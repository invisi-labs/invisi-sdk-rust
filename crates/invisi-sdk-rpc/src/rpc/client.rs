use super::*;
use crate::protocol::InvisiProtocol;
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolCall;
use serde_json::{json, Value};
use std::collections::HashMap;

pub trait CanonicalChain: Send + Sync {
    fn chain_id(&self) -> Result<u64>;
    fn block(&self, number: u64) -> Result<CanonicalBlock>;
    fn code_at(&self, address: Address, block: Option<u64>) -> Result<Vec<u8>>;
    fn call(&self, address: Address, data: &[u8], block: u64) -> Result<Vec<u8>>;
}
pub struct EthereumChain<T: RpcTransport> {
    rpc: JsonRpc<T>,
}
impl<T: RpcTransport> EthereumChain<T> {
    pub fn new(transport: T) -> Self {
        Self {
            rpc: JsonRpc::new(transport),
        }
    }
}
fn quantity(v: &Value) -> Result<u64> {
    let s = v
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or(Error::Invalid("Ethereum quantity required"))?;
    if s.is_empty()
        || s.len() > 1 && s.starts_with('0')
        || !s.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::Invalid("noncanonical Ethereum quantity"));
    }
    u64::from_str_radix(s, 16).map_err(|_| Error::Invalid("Ethereum quantity overflow"))
}
impl<T: RpcTransport> CanonicalChain for EthereumChain<T> {
    fn chain_id(&self) -> Result<u64> {
        quantity(&self.rpc.call("eth_chainId", json!([]))?)
    }
    fn block(&self, number: u64) -> Result<CanonicalBlock> {
        let v = self.rpc.call(
            "eth_getBlockByNumber",
            json!([format!("0x{number:x}"), false]),
        )?;
        let out = CanonicalBlock {
            number: quantity(&v["number"])?,
            timestamp: quantity(&v["timestamp"])?,
            hash: hash(&v["hash"])?,
            parent_hash: hash(&v["parentHash"])?,
        };
        if out.number != number {
            return Err(Error::Invalid("incorrect canonical block number"));
        }
        Ok(out)
    }
    fn code_at(&self, address: Address, block: Option<u64>) -> Result<Vec<u8>> {
        bytes(
            &self.rpc.call(
                "eth_getCode",
                json!([
                    address,
                    block
                        .map(|n| format!("0x{n:x}"))
                        .unwrap_or_else(|| "latest".into())
                ]),
            )?,
            0,
            32 << 20,
        )
    }
    fn call(&self, address: Address, data: &[u8], block: u64) -> Result<Vec<u8>> {
        bytes(&self.rpc.call("eth_call",json!([{"to":address,"data":format!("0x{}",hex::encode(data))},format!("0x{block:x}")]))?,0,32<<20)
    }
}
pub struct ProtocolRpcClient<T: RpcTransport, C: CanonicalChain> {
    rpc: JsonRpc<T>,
    pub chain: C,
    deployment: ProtocolDeployment,
}
impl<T: RpcTransport, C: CanonicalChain> ProtocolRpcClient<T, C> {
    pub fn new(transport: T, chain: C, deployment: ProtocolDeployment) -> Result<Self> {
        deployment.validate()?;
        Ok(Self {
            rpc: JsonRpc::new(transport),
            chain,
            deployment,
        })
    }
    pub fn deployment(&self) -> &ProtocolDeployment {
        &self.deployment
    }
    pub fn get_deployment(&self) -> Result<ProtocolDeployment> {
        let value = self.rpc.call("invisi_getDeployment", json!([]))?;
        self.versions(&value)?;
        let d = ProtocolDeployment::parse(&value["deployment"])?;
        if d != self.deployment {
            return Err(Error::Invalid("deployment pins mismatch"));
        }
        Ok(d)
    }
    fn versions(&self, v: &Value) -> Result<()> {
        if v["apiVersion"] != "v1" || v["protocolVersion"] != "1" {
            return Err(Error::Invalid("unsupported service version"));
        }
        Ok(())
    }
    fn canonical(&self, block: &CanonicalBlock) -> Result<()> {
        if self.chain.chain_id()? != self.deployment.chain_id()? {
            return Err(Error::Invalid("provider chain mismatch"));
        }
        if block.number > MAX_SAFE_INTEGER || self.chain.block(block.number)? != *block {
            return Err(Error::Invalid("canonical block mismatch"));
        }
        Ok(())
    }
    pub fn validate_deployment(&self) -> Result<()> {
        if self.chain.chain_id()? != self.deployment.chain_id()? {
            return Err(Error::Invalid("provider chain mismatch"));
        }
        for contract in [
            Some(&self.deployment.protocol),
            self.deployment.registry.as_ref(),
            self.deployment.broadcaster_registry.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if keccak256(self.chain.code_at(contract.address, None)?) != contract.runtime_code_hash
            {
                return Err(Error::Invalid("deployment runtime code mismatch"));
            }
        }
        Ok(())
    }
    pub fn get_status(&self) -> Result<ProtocolStatus> {
        let status = self.read_status_metadata()?;
        if let Some(head) = &status.indexed_head {
            self.canonical(head)?;
        }
        Ok(status)
    }
    fn read_status_metadata(&self) -> Result<ProtocolStatus> {
        if self.chain.chain_id()? != self.deployment.chain_id()? {
            return Err(Error::Invalid("provider chain mismatch"));
        }
        let v = self.rpc.call("invisi_getStatus", json!([]))?;
        self.versions(&v)?;
        if ProtocolDeployment::parse(&v["deployment"])? != self.deployment {
            return Err(Error::Invalid("indexed deployment mismatch"));
        }
        if v.get("indexedHead").is_none() {
            return Err(Error::Invalid("indexed head required"));
        }
        let head = if v["indexedHead"].is_null() {
            None
        } else {
            Some(CanonicalBlock::parse(&v["indexedHead"])?)
        };
        if let Some(block) = &head {
            if block.number < self.deployment.protocol.from_block {
                return Err(Error::Invalid("index predates deployment"));
            }
        }
        let bits = uint(&v["checkedBits"], 8)? as u8;
        if !(1..=24).contains(&bits) {
            return Err(Error::Invalid("invalid detection precision"));
        }
        Ok(ProtocolStatus {
            indexed_head: head,
            detection_enabled: v["detectionEnabled"]
                .as_bool()
                .ok_or(Error::Invalid("detection flag required"))?,
            checked_bits: bits,
        })
    }
    fn read_at(&self, block: &CanonicalBlock) -> Result<()> {
        self.read_status_metadata()?;
        if block.number < self.deployment.protocol.from_block {
            return Err(Error::Invalid("query predates deployment"));
        }
        self.canonical(block)
    }
    pub fn contract_read<S: SolCall>(
        &self,
        address: Address,
        call: &S,
        block: &CanonicalBlock,
    ) -> Result<S::Return> {
        self.canonical(block)?;
        let bytes = self.chain.call(address, &call.abi_encode(), block.number)?;
        let result = S::abi_decode_returns(&bytes, true)
            .map_err(|_| Error::Invalid("invalid ABI return"))?;
        self.canonical(block)?;
        Ok(result)
    }
    pub fn get_membership(
        &self,
        input: &MembershipInput,
        block: &CanonicalBlock,
    ) -> Result<Membership> {
        if input.tree_id == 0
            || input.tree_id > MAX_SAFE_INTEGER
            || input.leaf_index >= 1 << TREE_DEPTH
        {
            return Err(Error::Invalid("invalid membership position"));
        }
        field(input.commitment)?;
        if let Some(root) = input.root {
            field(root)?;
        }
        self.get_status()?;
        self.canonical(block)?;
        if block.number < self.deployment.protocol.from_block {
            return Err(Error::Invalid("membership predates deployment"));
        }
        let roots = self.rpc.call("invisi_getRoots", json!([input.tree_id]))?;
        let mut roots = roots
            .as_array()
            .ok_or(Error::Invalid("root list required"))?
            .iter()
            .map(RootAnchor::parse)
            .collect::<Result<Vec<_>>>()?;
        roots.sort_by_key(|r| std::cmp::Reverse((r.block.number, r.leaf_count)));
        let mut selected = None;
        for root in roots {
            if root.tree_id != input.tree_id || root.leaf_count > 1 << TREE_DEPTH {
                return Err(Error::Invalid("invalid root metadata"));
            }
            if root.block.number > block.number
                || root.block.number < self.deployment.protocol.from_block
                || root.leaf_count <= input.leaf_index
                || input.root.is_some_and(|r| r != root.root)
            {
                continue;
            }
            field(root.root)?;
            self.canonical(&root.block)?;
            let known = self.contract_read(
                self.deployment.protocol.address,
                &InvisiProtocol::rootHistoryCall {
                    _0: U256::from(input.tree_id),
                    _1: root.root,
                },
                block,
            )?;
            if known._0 {
                selected = Some(root);
                break;
            }
        }
        let root = selected.ok_or(Error::Invalid("no chain-known indexed root"))?;
        let v = self.rpc.call(
            "invisi_getMembership",
            json!([input.tree_id, input.leaf_index, root.root]),
        )?;
        if RootAnchor::parse(&v["anchor"])? != root
            || uint(&v["leafIndex"], 32)? != input.leaf_index as u64
            || hash(&v["commitment"])? != input.commitment
        {
            return Err(Error::Invalid("membership binding mismatch"));
        }
        let path = v["siblings"]
            .as_array()
            .ok_or(Error::Invalid("membership siblings required"))?
            .iter()
            .map(hash)
            .collect::<Result<Vec<_>>>()?;
        if path.len() != TREE_DEPTH {
            return Err(Error::Invalid("invalid Merkle depth"));
        }
        let mut current = crate::field::bytes_to_field(input.commitment.as_slice());
        for (level, sibling) in path.iter().enumerate() {
            field(*sibling)?;
            let sibling = crate::field::bytes_to_field(sibling.as_slice());
            current = if input.leaf_index >> level & 1 == 0 {
                crate::poseidon::hash(&[current, sibling])
            } else {
                crate::poseidon::hash(&[sibling, current])
            };
        }
        if crate::field::field_to_bytes_be(current).as_slice() != root.root.as_slice() {
            return Err(Error::Invalid("invalid Merkle path"));
        }
        self.canonical(block)?;
        Ok(Membership {
            tree_id: input.tree_id,
            leaf_index: input.leaf_index,
            leaf: input.commitment,
            root: root.root,
            path,
            block: block.clone(),
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct RootAnchor {
    tree_id: u64,
    root: B256,
    leaf_count: u32,
    block: CanonicalBlock,
}
impl RootAnchor {
    fn parse(v: &Value) -> Result<Self> {
        let root = hash(&v["root"])?;
        field(root)?;
        Ok(Self {
            tree_id: uint(&v["treeId"], 64)?,
            root,
            leaf_count: uint(&v["leafCount"], 32)? as u32,
            block: CanonicalBlock::parse(&v["block"])?,
        })
    }
}
impl<T: RpcTransport, C: CanonicalChain> ProtocolRpcClient<T, C> {
    fn update_page(
        &self,
        from: u64,
        to: u64,
        method: &str,
        detection_key: Option<&[u8; 32]>,
    ) -> Result<(CanonicalBlock, Value)> {
        if from < self.deployment.protocol.from_block
            || to < from
            || to - from >= MAX_UPDATE_BLOCKS
            || to > MAX_SAFE_INTEGER
        {
            return Err(Error::Invalid(
                "updates require at most 10000 deployment blocks",
            ));
        }
        if let Some(key) = detection_key {
            if key.iter().all(|byte| *byte == 0) {
                return Err(Error::Invalid("invalid detection key"));
            }
            decaf377_fmd::DetectionKey::from_bytes(*key)
                .map_err(|_| Error::Invalid("invalid detection key"))?;
        }
        let status = self.read_status_metadata()?;
        let head = status
            .indexed_head
            .ok_or(Error::Invalid("index has no head"))?;
        if head.number < to {
            return Err(Error::Invalid("index is behind requested range"));
        }
        let block = self.chain.block(to)?;
        if block.number != to {
            return Err(Error::Invalid("incorrect update anchor number"));
        }
        if head.number == block.number && head != block {
            return Err(Error::Invalid(
                "indexed head disagrees with requested canonical block",
            ));
        }
        let mut params = vec![json!({"fromBlock":from,"toBlock":to,"blockHash":block.hash})];
        if let Some(key) = detection_key {
            if !status.detection_enabled {
                return Err(Error::Invalid("delegated detection disabled"));
            }
            params.push(json!(format!("0x{}", hex::encode(key))));
        }
        let v = self.rpc.call(method, Value::Array(params))?;
        if method != "invisi_getCreditTransitions" {
            if hash(&v["blockHash"])? != block.hash {
                return Err(Error::Invalid("update anchor mismatch"));
            }
            if detection_key.is_some() && uint(&v["checkedBits"], 8)? != status.checked_bits as u64
            {
                return Err(Error::Invalid("detection precision mismatch"));
            }
        }
        self.canonical(&block)?;
        Ok((block, v))
    }
    fn leaf_rows<A: Clone + PartialEq>(
        &self,
        rows: &[Value],
        from: u64,
        to: u64,
        parse: fn(&Value) -> Result<A>,
    ) -> Result<Vec<A>> {
        let mut positions = HashMap::new();
        let mut commitments = HashMap::new();
        let mut out = Vec::new();
        for row in rows {
            let leaf = LeafMetadata::parse(row)?;
            if leaf.block.number < from || leaf.block.number > to {
                return Err(Error::Invalid("output outside requested range"));
            }
            self.canonical(&leaf.block)?;
            let position = (leaf.tree_id, leaf.leaf_index);
            let fingerprint = parse(row)?;
            if positions.get(&position).is_some_and(|s| s != &fingerprint)
                || commitments
                    .get(&leaf.commitment)
                    .is_some_and(|s| s != &fingerprint)
            {
                return Err(Error::Invalid("conflicting indexed output"));
            }
            if !positions.contains_key(&position) {
                out.push(fingerprint.clone());
            }
            positions.insert(position, fingerprint.clone());
            commitments.insert(leaf.commitment, fingerprint);
        }
        Ok(out)
    }
    fn transitions(&self, rows: &[Value], from: u64, to: u64) -> Result<Vec<CreditTransition>> {
        let mut seen = HashMap::new();
        let mut out = Vec::new();
        for row in rows {
            let item = CreditTransition::parse(row)?;
            if item.block.number < from || item.block.number > to {
                return Err(Error::Invalid("transition outside requested range"));
            }
            self.canonical(&item.block)?;
            let key = (item.block.number, item.log_index);
            if let Some(previous) = seen.get(&key) {
                if previous != &item {
                    return Err(Error::Invalid("conflicting Credit transition"));
                }
            } else {
                out.push(item.clone());
                seen.insert(key, item);
            }
        }
        Ok(out)
    }
    pub fn get_note_updates(&self, from: u64, to: u64) -> Result<UpdatePage<NoteOutput>> {
        let (block, v) = self.update_page(from, to, "invisi_getNoteUpdates", None)?;
        let rows = list_or_null(v.get("notes").ok_or(Error::Invalid("Note list required"))?)?;
        let items = self.leaf_rows(rows, from, to, NoteOutput::parse)?;
        self.canonical(&block)?;
        Ok(UpdatePage { block, items })
    }
    pub fn detect_notes(
        &self,
        from: u64,
        to: u64,
        key: &[u8; 32],
    ) -> Result<UpdatePage<NoteOutput>> {
        let (block, v) = self.update_page(from, to, "invisi_detectNotes", Some(key))?;
        let rows = detected_rows(&v, "note")?;
        let items = self.leaf_rows(&rows, from, to, NoteOutput::parse)?;
        self.canonical(&block)?;
        Ok(UpdatePage { block, items })
    }
    pub fn get_credit_transitions(
        &self,
        from: u64,
        to: u64,
    ) -> Result<UpdatePage<CreditTransition>> {
        let (block, v) = self.update_page(from, to, "invisi_getCreditTransitions", None)?;
        let rows = list_or_null(&v)?;
        let items = self.transitions(rows, from, to)?;
        self.canonical(&block)?;
        Ok(UpdatePage { block, items })
    }
    pub fn detect_credit_states(
        &self,
        from: u64,
        to: u64,
        key: &[u8; 32],
    ) -> Result<UpdatePage<IndexedCreditState>> {
        let (block, v) = self.update_page(from, to, "invisi_detectCreditStates", Some(key))?;
        let rows = detected_rows(&v, "state")?;
        let items = self.leaf_rows(&rows, from, to, IndexedCreditState::parse)?;
        self.canonical(&block)?;
        Ok(UpdatePage { block, items })
    }
    pub fn get_note(
        &self,
        commitment: B256,
        block: &CanonicalBlock,
    ) -> Result<Option<IndexedLookup<NoteOutput>>> {
        self.lookup(commitment, block, false, NoteOutput::parse)
    }
    pub fn get_credit_state(
        &self,
        commitment: B256,
        block: &CanonicalBlock,
    ) -> Result<Option<IndexedLookup<IndexedCreditState>>> {
        self.lookup(commitment, block, true, IndexedCreditState::parse)
    }
    fn lookup<A>(
        &self,
        commitment: B256,
        block: &CanonicalBlock,
        credit: bool,
        parse: fn(&Value) -> Result<A>,
    ) -> Result<Option<IndexedLookup<A>>> {
        if commitment == B256::ZERO {
            return Err(Error::Invalid("nonzero commitment required"));
        }
        field(commitment)?;
        self.read_at(block)?;
        let v = self.rpc.call(
            if credit {
                "invisi_getCreditState"
            } else {
                "invisi_getNote"
            },
            json!([commitment, block.number]),
        )?;
        if v.is_null() {
            return Ok(None);
        }
        let raw = &v[if credit { "state" } else { "output" }];
        let leaf = LeafMetadata::parse(raw)?;
        if leaf.commitment != commitment
            || leaf.block.number < self.deployment.protocol.from_block
            || leaf.block.number > block.number
        {
            return Err(Error::Invalid("lookup binding mismatch"));
        }
        self.canonical(&leaf.block)?;
        let anchor = RootAnchor::parse(&v["membership"]["anchor"])?;
        self.canonical(&anchor.block)?;
        if anchor.block.number > block.number
            || anchor.tree_id != leaf.tree_id
            || anchor.leaf_count <= leaf.leaf_index
            || anchor.leaf_count > 1 << TREE_DEPTH
        {
            return Err(Error::Invalid("lookup anchor mismatch"));
        }
        let membership = self.get_membership(
            &MembershipInput {
                tree_id: leaf.tree_id,
                leaf_index: leaf.leaf_index,
                commitment,
                root: Some(anchor.root),
            },
            block,
        )?;
        let proof = &v["membership"];
        if uint(&proof["leafIndex"], 32)? != leaf.leaf_index as u64
            || hash(&proof["commitment"])? != commitment
        {
            return Err(Error::Invalid("lookup proof binding mismatch"));
        }
        let path = proof["siblings"]
            .as_array()
            .ok_or(Error::Invalid("lookup path required"))?
            .iter()
            .map(hash)
            .collect::<Result<Vec<_>>>()?;
        if path != membership.path {
            return Err(Error::Invalid("lookup membership mismatch"));
        }
        self.canonical(block)?;
        Ok(Some(IndexedLookup {
            output: parse(raw)?,
            membership,
        }))
    }
    pub fn get_credit_allocation(
        &self,
        owner: Address,
        token: Address,
        block: &CanonicalBlock,
    ) -> Result<CreditAllocation> {
        if owner == Address::ZERO || token == Address::ZERO {
            return Err(Error::Invalid("nonzero owner and token required"));
        }
        self.read_at(block)?;
        let v = self.rpc.call(
            "invisi_getCreditAllocation",
            json!([owner, token, block.number]),
        )?;
        if CanonicalBlock::parse(&v["block"])? != *block {
            return Err(Error::Invalid("allocation block mismatch"));
        }
        let shard = uint(&v["shard"], 64)?;
        if shard == 0 {
            return Err(Error::Invalid("zero Credit shard"));
        }
        let slot = uint(&v["slot"], 16)? as u16;
        self.canonical(block)?;
        Ok(CreditAllocation {
            block: block.clone(),
            shard,
            slot,
        })
    }
    pub fn get_credit_revocation_bitmap(
        &self,
        owner: Address,
        token: Address,
        shard: u64,
        word: u8,
        block: &CanonicalBlock,
    ) -> Result<U256> {
        if owner == Address::ZERO || token == Address::ZERO || shard == 0 {
            return Err(Error::Invalid("invalid grant location"));
        }
        self.read_at(block)?;
        let v = self.rpc.call(
            "invisi_getCreditRevocationBitmap",
            json!([owner, token, shard.to_string(), word, block.number]),
        )?;
        if CanonicalBlock::parse(&v["block"])? != *block {
            return Err(Error::Invalid("revocation block mismatch"));
        }
        let bitmap = decimal(&v["bitmap"])?;
        self.canonical(block)?;
        Ok(bitmap)
    }
    fn consumption(&self, nullifier: B256, block: &CanonicalBlock, credit: bool) -> Result<bool> {
        if nullifier == B256::ZERO {
            return Err(Error::Invalid("nonzero nullifier required"));
        }
        field(nullifier)?;
        self.read_at(block)?;
        let value = self
            .rpc
            .call(
                if credit {
                    "invisi_isCreditConsumed"
                } else {
                    "invisi_isNoteSpent"
                },
                json!([nullifier, block.number]),
            )?
            .as_bool()
            .ok_or(Error::Invalid("boolean consumption observation required"))?;
        self.canonical(block)?;
        Ok(value)
    }
    pub fn is_note_spent(&self, nullifier: B256, block: &CanonicalBlock) -> Result<bool> {
        self.consumption(nullifier, block, false)
    }
    pub fn is_credit_consumed(&self, nullifier: B256, block: &CanonicalBlock) -> Result<bool> {
        self.consumption(nullifier, block, true)
    }
}
fn detected_rows(v: &Value, field: &str) -> Result<Vec<Value>> {
    list_or_null(
        v.get("candidates")
            .ok_or(Error::Invalid("detection candidates required"))?,
    )?
    .iter()
    .map(|row| {
        if !row["fallback"].is_boolean() || !row[field].is_object() {
            return Err(Error::Invalid("invalid detection candidate"));
        }
        Ok(row[field].clone())
    })
    .collect()
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedLookup<A> {
    pub output: A,
    pub membership: Membership,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreditAllocation {
    pub block: CanonicalBlock,
    pub shard: u64,
    pub slot: u16,
}
impl<T: RpcTransport, C: CanonicalChain> ProtocolRpcClient<T, C> {
    pub fn get_transaction_note_updates(
        &self,
        transaction: B256,
    ) -> Result<Availability<Vec<NoteOutput>>> {
        self.transaction_updates(transaction, false, |this, v, block| {
            this.leaf_rows(
                v["notes"]
                    .as_array()
                    .ok_or(Error::Invalid("Note array required"))?,
                block.number,
                block.number,
                NoteOutput::parse,
            )
        })
    }
    pub fn get_transaction_credit_updates(
        &self,
        transaction: B256,
    ) -> Result<Availability<CreditTransactionUpdates>> {
        self.transaction_updates(transaction, true, |this, v, block| {
            Ok(CreditTransactionUpdates {
                states: this.leaf_rows(
                    v["states"]
                        .as_array()
                        .ok_or(Error::Invalid("Credit state array required"))?,
                    block.number,
                    block.number,
                    IndexedCreditState::parse,
                )?,
                transitions: this.transitions(
                    v["transitions"]
                        .as_array()
                        .ok_or(Error::Invalid("Credit transition array required"))?,
                    block.number,
                    block.number,
                )?,
            })
        })
    }
    fn transaction_updates<A>(
        &self,
        transaction: B256,
        credit: bool,
        parse: impl FnOnce(&Self, &Value, &CanonicalBlock) -> Result<A>,
    ) -> Result<Availability<A>> {
        if transaction == B256::ZERO {
            return Err(Error::Invalid("nonzero transaction hash required"));
        }
        self.read_status_metadata()?;
        let v = self.rpc.call(
            if credit {
                "invisi_getTransactionCreditUpdates"
            } else {
                "invisi_getTransactionNoteUpdates"
            },
            json!([transaction]),
        )?;
        if hash(&v["transactionHash"])? != transaction || v.get("indexedHead").is_none() {
            return Err(Error::Invalid("transaction identity mismatch"));
        }
        if v.get("indexedHead").is_none() {
            return Err(Error::Invalid("indexed head required"));
        }
        let head = if v["indexedHead"].is_null() {
            None
        } else {
            Some(CanonicalBlock::parse(&v["indexedHead"])?)
        };
        let fields: &[&str] = if credit {
            &["states", "transitions"]
        } else {
            &["notes"]
        };
        match v["status"].as_str() {
            Some("not_found") => {
                if ["blockNumber", "blockHash", "receiptStatus"]
                    .iter()
                    .any(|name| v.get(*name).is_some())
                    || fields.iter().any(|name| v.get(*name) != Some(&Value::Null))
                {
                    return Err(Error::Invalid("invalid not_found transaction"));
                }
                Ok(Availability::NotFound { indexed_head: head })
            }
            Some("pending_index") | Some("indexed") => {
                let number = uint(&v["blockNumber"], 64)?;
                let start = [
                    Some(&self.deployment.protocol),
                    self.deployment.registry.as_ref(),
                    self.deployment.broadcaster_registry.as_ref(),
                ]
                .into_iter()
                .flatten()
                .map(|d| d.from_block)
                .min()
                .unwrap();
                if number < start || number > MAX_SAFE_INTEGER {
                    return Err(Error::Invalid("transaction outside deployment history"));
                }
                let block = self.chain.block(number)?;
                if block.number != number {
                    return Err(Error::Invalid("incorrect transaction block number"));
                }
                if hash(&v["blockHash"])? != block.hash {
                    return Err(Error::Invalid("transaction block mismatch"));
                }
                let receipt_status = uint(&v["receiptStatus"], 1)? == 1;
                if v["status"] == "pending_index" {
                    if fields.iter().any(|name| v.get(*name) != Some(&Value::Null)) {
                        return Err(Error::Invalid(
                            "pending transaction must not contain updates",
                        ));
                    }
                    return Ok(Availability::PendingIndex {
                        indexed_head: head,
                        block,
                        receipt_status,
                    });
                }
                let head =
                    head.ok_or(Error::Invalid("indexed transaction requires indexed head"))?;
                self.canonical(&head)?;
                if head.number < number {
                    return Err(Error::Invalid("transaction exceeds indexed head"));
                }
                for field in fields {
                    let rows = v[*field]
                        .as_array()
                        .ok_or(Error::Invalid("indexed transaction requires arrays"))?;
                    if !receipt_status && !rows.is_empty() {
                        return Err(Error::Invalid("reverted transaction contains outputs"));
                    }
                    for row in rows {
                        if hash(&row["transactionHash"])? != transaction {
                            return Err(Error::Invalid("different transaction in indexed outputs"));
                        }
                    }
                }
                let items = parse(self, &v, &block)?;
                self.canonical(&block)?;
                Ok(Availability::Indexed {
                    indexed_head: head,
                    block,
                    receipt_status,
                    items,
                })
            }
            _ => Err(Error::Invalid("invalid transaction availability status")),
        }
    }
    pub fn get_receiving_address(
        &self,
        owner: Address,
    ) -> Result<Option<RegisteredReceivingAddress>> {
        if owner == Address::ZERO {
            return Err(Error::Invalid("nonzero owner required"));
        }
        let registry = self
            .deployment
            .registry
            .as_ref()
            .ok_or(Error::Invalid("deployment has no receiving registry"))?;
        let v = self
            .rpc
            .call("invisi_getReceivingAddress", json!([owner]))?;
        if v.is_null() {
            return Ok(None);
        }
        if address(&v["ownerAddress"])? != owner {
            return Err(Error::Invalid("receiving identity mismatch"));
        }
        let viewing_public_key = bytes(&v["viewingPublicKey"], 33, 33)?;
        k256::PublicKey::from_sec1_bytes(&viewing_public_key)
            .map_err(|_| Error::Invalid("invalid viewing public key"))?;
        let clue_key = bytes(&v["clueKey"], 32, 32)?;
        decaf377_fmd::ClueKey(
            clue_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::Invalid("invalid clue key"))?,
        )
        .expand()
        .map_err(|_| Error::Invalid("invalid clue key"))?;
        let receiving_address = crate::address::ReceivingAddress::from_keys(
            U256::from_be_slice(owner.as_slice()),
            crate::address::ReceivingKeys {
                viewing_public_key: viewing_public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Invalid("invalid viewing key"))?,
                clue_key: clue_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Invalid("invalid clue key"))?,
            },
        )
        .and_then(|value| value.encode())
        .map_err(|_| Error::Invalid("invalid receiving keys"))?;
        let block = CanonicalBlock::parse(&v["block"])?;
        if block.number < registry.from_block {
            return Err(Error::Invalid("receiving registration predates deployment"));
        }
        self.canonical(&block)?;
        Ok(Some(RegisteredReceivingAddress {
            receiving_address,
            owner,
            viewing_public_key,
            clue_key,
            nonce: uint(&v["nonce"], 64)?,
            block,
        }))
    }
    pub fn get_broadcasters(&self, query: &BroadcasterQuery) -> Result<BroadcasterPage> {
        let registry = self
            .deployment
            .broadcaster_registry
            .as_ref()
            .ok_or(Error::Invalid("deployment has no broadcaster registry"))?;
        if query.limit == 0
            || query.limit > 100
            || query.after.is_some_and(|a| a == Address::ZERO)
            || query.after.is_some() && query.block.is_none()
        {
            return Err(Error::Invalid("invalid broadcaster query"));
        }
        if let Some(block) = &query.block {
            if block.number < registry.from_block {
                return Err(Error::Invalid("broadcaster anchor predates deployment"));
            }
            self.canonical(block)?;
        }
        let mut params = json!({"limit":query.limit});
        if let Some(enabled) = query.enabled {
            params["enabled"] = json!(enabled);
        }
        if let Some(after) = query.after {
            params["after"] = json!(after);
        }
        if let Some(block) = &query.block {
            params["block"] = json!(block);
        }
        let v = self.rpc.call("invisi_getBroadcasters", json!([params]))?;
        let page_block = CanonicalBlock::parse(&v["block"])?;
        if page_block.number < registry.from_block
            || query.block.as_ref().is_some_and(|b| b != &page_block)
        {
            return Err(Error::Invalid("broadcaster page anchor mismatch"));
        }
        self.canonical(&page_block)?;
        let rows = v["broadcasters"]
            .as_array()
            .ok_or(Error::Invalid("broadcaster list required"))?;
        if rows.len() > query.limit {
            return Err(Error::Invalid("broadcaster page exceeds limit"));
        }
        let mut previous = query.after.unwrap_or(Address::ZERO);
        let mut broadcasters = Vec::new();
        for row in rows {
            let operator = address(&row["operator"])?;
            let quote_signer = address(&row["quoteSigner"])?;
            let fee_recipient = address(&row["feeRecipient"])?;
            let enabled = row["enabled"]
                .as_bool()
                .ok_or(Error::Invalid("broadcaster enabled flag required"))?;
            if operator <= previous
                || quote_signer == Address::ZERO
                || fee_recipient == Address::ZERO
                || query.enabled.is_some_and(|filter| filter != enabled)
            {
                return Err(Error::Invalid("invalid broadcaster registration"));
            }
            let endpoint = row["endpoint"]
                .as_str()
                .ok_or(Error::Invalid("endpoint required"))?;
            let metadata_uri = row["metadataURI"]
                .as_str()
                .ok_or(Error::Invalid("metadataURI required"))?;
            for text in [endpoint, metadata_uri] {
                if text.len() > 2048 || !text.bytes().all(|b| (32..=126).contains(&b)) {
                    return Err(Error::Invalid("invalid broadcaster URI"));
                }
            }
            // Discovery preserves contract-valid declarations; contact validates the selected URL.
            if !endpoint.starts_with("https://") || endpoint.len() <= 8 {
                return Err(Error::Invalid("invalid broadcaster endpoint declaration"));
            }
            let block = CanonicalBlock::parse(&row["block"])?;
            if block.number < registry.from_block || block.number > page_block.number {
                return Err(Error::Invalid("broadcaster registration anchor mismatch"));
            }
            self.canonical(&block)?;
            broadcasters.push(RegisteredBroadcaster {
                operator,
                endpoint: endpoint.into(),
                metadata_uri: metadata_uri.into(),
                quote_signer,
                fee_recipient,
                enabled,
                block,
            });
            previous = operator;
        }
        let next = match v.get("next") {
            None => None,
            Some(value) => {
                let next = address(value)?;
                if next != previous || next == Address::ZERO || broadcasters.len() != query.limit {
                    return Err(Error::Invalid("invalid broadcaster cursor"));
                }
                Some(next)
            }
        };
        self.canonical(&page_block)?;
        Ok(BroadcasterPage {
            block: page_block,
            broadcasters,
            next,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredReceivingAddress {
    pub receiving_address: String,
    pub owner: Address,
    pub viewing_public_key: Vec<u8>,
    pub clue_key: Vec<u8>,
    pub nonce: u64,
    pub block: CanonicalBlock,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredBroadcaster {
    pub operator: Address,
    pub endpoint: String,
    pub metadata_uri: String,
    pub quote_signer: Address,
    pub fee_recipient: Address,
    pub enabled: bool,
    pub block: CanonicalBlock,
}
#[derive(Clone, Debug)]
pub struct BroadcasterQuery {
    pub enabled: Option<bool>,
    pub after: Option<Address>,
    pub limit: usize,
    pub block: Option<CanonicalBlock>,
}
impl Default for BroadcasterQuery {
    fn default() -> Self {
        Self {
            enabled: None,
            after: None,
            limit: 100,
            block: None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BroadcasterPage {
    pub block: CanonicalBlock,
    pub broadcasters: Vec<RegisteredBroadcaster>,
    pub next: Option<Address>,
}

/// Canonical receipt access is separate from indexed service metadata.
pub trait ChainReceipts: CanonicalChain {
    fn receipt(&self, transaction: B256) -> Result<Option<CanonicalReceipt>>;
}

impl<T: RpcTransport> ChainReceipts for EthereumChain<T> {
    fn receipt(&self, transaction: B256) -> Result<Option<CanonicalReceipt>> {
        if transaction == B256::ZERO {
            return Err(Error::Invalid("nonzero transaction hash required"));
        }
        let value = self
            .rpc
            .call("eth_getTransactionReceipt", json!([transaction]))?;
        if value.is_null() {
            return Ok(None);
        }
        if hash(&value["transactionHash"])? != transaction {
            return Err(Error::Invalid("receipt transaction mismatch"));
        }
        let block_number = quantity(&value["blockNumber"])?;
        let block_hash = hash(&value["blockHash"])?;
        let block = self.block(block_number)?;
        if block.hash != block_hash {
            return Err(Error::Invalid("receipt block is not canonical"));
        }
        let status = quantity(&value["status"])?;
        if status > 1 {
            return Err(Error::Invalid("invalid receipt status"));
        }
        let rows = value["logs"]
            .as_array()
            .ok_or(Error::Invalid("receipt logs required"))?;
        let mut logs = Vec::with_capacity(rows.len());
        let mut previous = None;
        for row in rows {
            if row
                .get("removed")
                .is_some_and(|v| v.as_bool() != Some(false))
                || hash(&row["transactionHash"])? != transaction
                || hash(&row["blockHash"])? != block_hash
                || quantity(&row["blockNumber"])? != block_number
            {
                return Err(Error::Invalid("receipt log binding mismatch"));
            }
            let log_index = u32::try_from(quantity(&row["logIndex"])?)
                .map_err(|_| Error::Invalid("log index overflow"))?;
            if previous.is_some_and(|last| last >= log_index) {
                return Err(Error::Invalid("receipt logs out of order"));
            }
            let topics = row["topics"]
                .as_array()
                .ok_or(Error::Invalid("log topics required"))?;
            if topics.len() > 4 {
                return Err(Error::Invalid("too many EVM log topics"));
            }
            logs.push(CanonicalLog {
                address: address(&row["address"])?,
                topics: topics.iter().map(hash).collect::<Result<_>>()?,
                data: bytes(&row["data"], 0, 32 << 20)?,
                log_index,
            });
            previous = Some(log_index);
        }
        if self.block(block_number)? != block {
            return Err(Error::Invalid("canonical receipt changed during read"));
        }
        Ok(Some(CanonicalReceipt {
            transaction_hash: transaction,
            block,
            success: status == 1,
            logs,
        }))
    }
}

pub trait ChainTransactions: CanonicalChain {
    fn transaction(&self, hash: B256) -> Result<Option<CanonicalTransaction>>;
}

impl<T: RpcTransport> ChainTransactions for EthereumChain<T> {
    fn transaction(&self, transaction: B256) -> Result<Option<CanonicalTransaction>> {
        if transaction == B256::ZERO {
            return Err(Error::Invalid("nonzero transaction hash required"));
        }
        let value = self
            .rpc
            .call("eth_getTransactionByHash", json!([transaction]))?;
        if value.is_null() {
            return Ok(None);
        }
        if hash(&value["hash"])? != transaction {
            return Err(Error::Invalid("transaction identity mismatch"));
        }
        let chain_id = quantity(&value["chainId"])?;
        if chain_id != self.chain_id()? {
            return Err(Error::Invalid("transaction chain mismatch"));
        }
        let block = match (&value["blockNumber"], &value["blockHash"]) {
            (Value::Null, Value::Null) => None,
            (number, block_hash) if !number.is_null() && !block_hash.is_null() => {
                let block = self.block(quantity(number)?)?;
                if block.hash != hash(block_hash)? {
                    return Err(Error::Invalid("transaction block is not canonical"));
                }
                Some(block)
            }
            _ => return Err(Error::Invalid("inconsistent transaction block binding")),
        };
        let amount = value["value"]
            .as_str()
            .and_then(|v| v.strip_prefix("0x"))
            .ok_or(Error::Invalid("transaction value required"))?;
        if amount.is_empty()
            || amount.len() > 64
            || amount.len() > 1 && amount.starts_with('0')
            || !amount.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(Error::Invalid("noncanonical transaction value"));
        }
        let out = CanonicalTransaction {
            hash: transaction,
            to: if value["to"].is_null() {
                None
            } else {
                Some(address(&value["to"])?)
            },
            input: bytes(&value["input"], 0, 32 << 20)?,
            value: U256::from_str_radix(amount, 16)
                .map_err(|_| Error::Invalid("transaction value overflow"))?,
            chain_id,
            block,
        };
        if let Some(block) = &out.block {
            if self.block(block.number)? != *block {
                return Err(Error::Invalid("canonical transaction changed during read"));
            }
        }
        Ok(Some(out))
    }
}

pub trait CanonicalHead: CanonicalChain {
    fn head(&self) -> Result<CanonicalBlock>;
}
impl<T: RpcTransport> CanonicalHead for EthereumChain<T> {
    fn head(&self) -> Result<CanonicalBlock> {
        self.block(quantity(&self.rpc.call("eth_blockNumber", json!([]))?)?)
    }
}

/// Final calldata estimation and signed transaction relay; key custody stays with the caller.
pub trait ChainGas: CanonicalChain {
    fn estimate_gas(
        &self,
        expected_chain_id: u64,
        from: Address,
        call: &crate::protocol::TransactionCall,
    ) -> Result<U256>;
    fn gas_price(&self) -> Result<U256>;
    fn pending_nonce(&self, address: Address) -> Result<u64>;
    fn send_raw_transaction(
        &self,
        expected_chain_id: u64,
        signed_transaction: &[u8],
    ) -> Result<B256>;
}
fn quantity_u256(value: &Value) -> Result<U256> {
    let text = value
        .as_str()
        .and_then(|v| v.strip_prefix("0x"))
        .ok_or(Error::Invalid("Ethereum quantity required"))?;
    if text.is_empty()
        || text.len() > 64
        || text.len() > 1 && text.starts_with('0')
        || !text.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::Invalid("noncanonical Ethereum quantity"));
    }
    U256::from_str_radix(text, 16).map_err(|_| Error::Invalid("Ethereum quantity overflow"))
}
impl<T: RpcTransport> ChainGas for EthereumChain<T> {
    fn estimate_gas(
        &self,
        expected_chain_id: u64,
        from: Address,
        call: &crate::protocol::TransactionCall,
    ) -> Result<U256> {
        if expected_chain_id == 0 || self.chain_id()? != expected_chain_id {
            return Err(Error::Invalid("gas estimation chain mismatch"));
        }
        if from == Address::ZERO || call.to == Address::ZERO {
            return Err(Error::Invalid(
                "real caller and destination required for gas estimation",
            ));
        }
        let result=quantity_u256(&self.rpc.call("eth_estimateGas",json!([{"from":from,"to":call.to,"data":format!("0x{}",hex::encode(&call.data)),"value":format!("{:#x}",call.value)}]))?)?;
        if result == U256::ZERO {
            return Err(Error::Invalid("zero gas estimate"));
        }
        Ok(result)
    }
    fn gas_price(&self) -> Result<U256> {
        quantity_u256(&self.rpc.call("eth_gasPrice", json!([]))?)
    }
    fn pending_nonce(&self, address: Address) -> Result<u64> {
        if address == Address::ZERO {
            return Err(Error::Invalid("nonzero account required"));
        }
        quantity(
            &self
                .rpc
                .call("eth_getTransactionCount", json!([address, "pending"]))?,
        )
    }
    fn send_raw_transaction(
        &self,
        expected_chain_id: u64,
        signed_transaction: &[u8],
    ) -> Result<B256> {
        if expected_chain_id == 0 || self.chain_id()? != expected_chain_id {
            return Err(Error::Invalid("transaction relay chain mismatch"));
        }
        if signed_transaction.is_empty() || signed_transaction.len() > 32 << 20 {
            return Err(Error::Invalid("invalid signed transaction length"));
        }
        let expected = keccak256(signed_transaction);
        let result = hash(&self.rpc.call(
            "eth_sendRawTransaction",
            json!([format!("0x{}", hex::encode(signed_transaction))]),
        )?)?;
        if result != expected {
            return Err(Error::Invalid(
                "transaction relay returned a different hash",
            ));
        }
        Ok(result)
    }
}

fn list_or_null(value: &Value) -> Result<&[Value]> {
    match value {
        Value::Null => Ok(&[]),
        Value::Array(values) => Ok(values),
        _ => Err(Error::Invalid("array or explicit null required")),
    }
}
