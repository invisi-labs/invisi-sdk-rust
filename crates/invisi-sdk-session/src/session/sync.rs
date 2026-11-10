use super::*;
use crate::{
    protocol::{self, InvisiProtocol as P},
    rpc::{
        self, CanonicalHead, CanonicalReceipt, CanonicalTransaction, ChainReceipts,
        ChainTransactions, Membership, MembershipInput, ProtocolRpcClient, RpcTransport,
    },
};
use std::{collections::BTreeSet, sync::Mutex};

/// Indexed discovery chooses candidates; receipts and membership come from independent canonical reads.
pub trait SessionSource: Send + Sync {
    fn context(&self) -> ProtocolContext;
    fn deployment_start(&self) -> u64;
    fn indexed_head(&self) -> Result<CanonicalBlock>;
    fn block(&self, number: u64) -> Result<CanonicalBlock>;
    fn discover(&self, from: u64, to: u64) -> Result<Vec<B256>>;
    fn receipt(&self, hash: B256) -> Result<Option<CanonicalReceipt>>;
    fn transaction(&self, hash: B256) -> Result<Option<CanonicalTransaction>>;
    fn membership(&self, input: &MembershipInput, block: &CanonicalBlock) -> Result<Membership>;
}
impl<T: RpcTransport, C: CanonicalHead + ChainReceipts + ChainTransactions> SessionSource
    for ProtocolRpcClient<T, C>
{
    fn context(&self) -> ProtocolContext {
        ProtocolContext {
            chain_id: self.deployment().chain_id().expect("validated deployment"),
            protocol_address: sdk::address_word(self.deployment().protocol.address),
        }
    }
    fn deployment_start(&self) -> u64 {
        self.deployment().protocol.from_block
    }
    fn indexed_head(&self) -> Result<CanonicalBlock> {
        self.get_status()
            .map_err(|e| e.to_string())?
            .indexed_head
            .ok_or_else(|| "Protocol RPC has no indexed head".into())
    }
    fn block(&self, number: u64) -> Result<CanonicalBlock> {
        self.chain.block(number).map_err(|e| e.to_string())
    }
    fn discover(&self, from: u64, to: u64) -> Result<Vec<B256>> {
        let notes = self.get_note_updates(from, to).map_err(|e| e.to_string())?;
        let credits = self
            .get_credit_transitions(from, to)
            .map_err(|e| e.to_string())?;
        if notes.block != credits.block {
            return Err("indexed discovery anchor mismatch".into());
        }
        Ok(notes
            .items
            .into_iter()
            .map(|v| v.leaf.transaction_hash)
            .chain(credits.items.into_iter().map(|v| v.transaction_hash))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }
    fn receipt(&self, hash: B256) -> Result<Option<CanonicalReceipt>> {
        self.chain.receipt(hash).map_err(|e| e.to_string())
    }
    fn transaction(&self, hash: B256) -> Result<Option<CanonicalTransaction>> {
        self.chain.transaction(hash).map_err(|e| e.to_string())
    }
    fn membership(&self, input: &MembershipInput, block: &CanonicalBlock) -> Result<Membership> {
        self.get_membership(input, block).map_err(|e| e.to_string())
    }
}
#[derive(Clone, Debug)]
pub struct RefreshOptions {
    pub from_block: u64,
    pub to_block: Option<u64>,
    pub page_size: u64,
    pub reset: bool,
}
impl RefreshOptions {
    pub fn from_block(from_block: u64) -> Self {
        Self {
            from_block,
            to_block: None,
            page_size: 10000,
            reset: false,
        }
    }
}
#[derive(Clone, Debug)]
pub struct RefreshResult {
    pub block: CanonicalBlock,
    pub notes: usize,
    pub credits: usize,
    pub revision: u64,
}
#[derive(Clone)]
enum Candidate {
    Note(rpc::NoteOutput),
    Credit(rpc::IndexedCreditState, CreditRole),
}
#[derive(Clone)]
enum Decoded {
    Note(crate::note::Note),
    Credit(CreditDeliveryState),
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ApplyState {
    Pending,
    Applying,
    Applied,
}
pub struct PendingWalletRefresh {
    session: WalletSession,
    base: WalletState,
    anchor: CanonicalBlock,
    receipts: Vec<CanonicalReceipt>,
    candidates: BTreeMap<String, Candidate>,
    options: RefreshOptions,
    apply_state: Mutex<ApplyState>,
    pub(crate) completion: Option<Vec<(String, u64, bool)>>,
}
impl std::fmt::Debug for PendingWalletRefresh {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingWalletRefresh")
            .field("block", &self.anchor)
            .field("candidate_count", &self.candidates.len())
            .finish_non_exhaustive()
    }
}
impl WalletSession {
    pub fn refresh(&self, options: RefreshOptions) -> Result<PendingWalletRefresh> {
        let base = self.snapshot()?;
        if base.invalidated && !options.reset {
            return Err("wallet requires canonical resync".into());
        }
        if options.from_block < self.source.deployment_start()
            || options.page_size == 0
            || options.page_size > rpc::MAX_UPDATE_BLOCKS
        {
            return Err("invalid refresh range or page size".into());
        }
        let head = self.source.indexed_head()?;
        let to = options.to_block.unwrap_or(head.number);
        if to < options.from_block || to > head.number {
            return Err("refresh outside indexed history".into());
        }
        let anchor = self.source.block(to)?;
        if anchor.number != to {
            return Err("wrong refresh block".into());
        }
        self.invisi.chain.canonical(&anchor)?;
        if !options.reset {
            if let Some(previous) = &base.observed_through {
                self.invisi.chain.canonical(previous)?;
                if previous.number > anchor.number {
                    return Err("refresh cannot regress checked inventory".into());
                }
            }
        }
        let mut transactions = BTreeSet::new();
        let mut start = options.from_block;
        loop {
            let end = start.saturating_add(options.page_size - 1).min(to);
            transactions.extend(self.source.discover(start, end)?);
            if end == to {
                break;
            }
            start = end.checked_add(1).ok_or("refresh range overflow")?;
        }
        let mut receipts = Vec::new();
        for hash in transactions {
            if hash == B256::ZERO {
                return Err("zero discovery transaction hash".into());
            }
            let receipt = self
                .source
                .receipt(hash)?
                .ok_or("missing canonical candidate receipt")?;
            if receipt.transaction_hash != hash
                || !receipt.success
                || receipt.block.number < options.from_block
                || receipt.block.number > to
            {
                return Err("candidate receipt outside selected canonical range".into());
            }
            self.invisi.chain.canonical(&receipt.block)?;
            receipts.push(receipt);
        }
        receipts.sort_by_key(|r| (r.block.number, r.logs.first().map_or(0, |l| l.log_index)));
        self.stage_refresh(base, anchor, receipts, options, None)
    }
    pub(crate) fn stage_refresh(
        &self,
        base: WalletState,
        anchor: CanonicalBlock,
        receipts: Vec<CanonicalReceipt>,
        options: RefreshOptions,
        completion: Option<Vec<(String, u64, bool)>>,
    ) -> Result<PendingWalletRefresh> {
        let mut candidates = BTreeMap::new();
        let mut keys = BTreeSet::new();
        let protocol = sdk::word_address(self.scope.context.protocol_address)?;
        for receipt in &receipts {
            if !receipt.success {
                continue;
            }
            let decoded = protocol::decode_receipt_outputs(protocol, receipt)?;
            for note in decoded.notes {
                if note.delivery.ciphertext.is_empty() {
                    continue;
                }
                let key = format!(
                    "{}:{}:{}:funds",
                    receipt.transaction_hash, note.leaf.tree_id, note.leaf.leaf_index
                );
                if !keys.insert(key.clone()) {
                    continue;
                }
                candidates.insert(key, Candidate::Note(note));
            }
            for credit in decoded.credits {
                for role in [CreditRole::Owner, CreditRole::Spender] {
                    let key = format!(
                        "{}:{}:{}:{role:?}",
                        receipt.transaction_hash, credit.leaf.tree_id, credit.leaf.leaf_index
                    );
                    if !keys.insert(key.clone()) {
                        continue;
                    }
                    candidates.insert(key, Candidate::Credit(credit.clone(), role));
                }
            }
        }
        Ok(PendingWalletRefresh {
            session: self.clone(),
            base,
            anchor,
            receipts,
            candidates,
            options,
            apply_state: Mutex::new(ApplyState::Pending),
            completion,
        })
    }
    pub(crate) fn verified_membership(
        &self,
        leaf: &rpc::LeafMetadata,
        anchor: &CanonicalBlock,
    ) -> Result<(U256, [U256; 16])> {
        let input = MembershipInput {
            tree_id: leaf.tree_id,
            leaf_index: leaf.leaf_index,
            commitment: leaf.commitment,
            root: None,
        };
        let proof = self.source.membership(&input, anchor)?;
        if proof.block != *anchor
            || proof.tree_id != leaf.tree_id
            || proof.leaf_index != leaf.leaf_index
            || proof.leaf != leaf.commitment
            || proof.path.len() != 16
        {
            return Err("membership response binding mismatch".into());
        }
        let root = U256::from_be_slice(proof.root.as_slice());
        let path: Vec<U256> = proof
            .path
            .iter()
            .map(|v| U256::from_be_slice(v.as_slice()))
            .collect();
        let path: [U256; 16] = path.try_into().map_err(|_| "membership depth mismatch")?;
        if sdk::merkle_root(
            U256::from_be_slice(leaf.commitment.as_slice()),
            u16::try_from(leaf.leaf_index).map_err(|_| "leaf index overflow")?,
            &path,
        )? != root
            || !self
                .invisi
                .chain
                .known_root(leaf.tree_id, proof.root, anchor)?
        {
            return Err("membership proof or canonical root mismatch".into());
        }
        Ok((root, path))
    }
}
impl PendingWalletRefresh {
    pub fn block(&self) -> &CanonicalBlock {
        &self.anchor
    }
    pub fn decrypt(
        &self,
        decryptor: &dyn crate::delivery::DeliveryDecryptor,
    ) -> Result<RefreshResult> {
        {
            let mut status = self
                .apply_state
                .lock()
                .map_err(|_| "refresh lock poisoned")?;
            if *status != ApplyState::Pending {
                return Err("wallet refresh already applying or applied".into());
            }
            *status = ApplyState::Applying;
        }
        let result = self.apply(decryptor);
        let mut status = self
            .apply_state
            .lock()
            .map_err(|_| "refresh lock poisoned")?;
        *status = if result.is_ok() {
            ApplyState::Applied
        } else {
            ApplyState::Pending
        };
        result
    }
    fn apply(&self, decryptor: &dyn crate::delivery::DeliveryDecryptor) -> Result<RefreshResult> {
        let session = &self.session;
        if session.snapshot()?.revision != self.base.revision {
            return Err("wallet changed; prepare refresh again".into());
        }
        let mut decoded = Vec::new();
        for candidate in self.candidates.values() {
            let leaf = match candidate {
                Candidate::Note(v) => &v.leaf,
                Candidate::Credit(v, _) => &v.leaf,
            };
            let context = crate::delivery::DeliveryContext {
                context: session.scope.context,
                token_address: sdk::address_word(leaf.token),
                output_commitment: U256::from_be_slice(leaf.commitment.as_slice()),
            };
            let value = match candidate {
                Candidate::Note(note) => match session.wallet.decrypt_note(
                    decryptor,
                    &note.delivery.ciphertext,
                    &context,
                )? {
                    Some(note) => Decoded::Note(note),
                    None => continue,
                },
                Candidate::Credit(credit, role) => {
                    let index = if *role == CreditRole::Owner { 0 } else { 1 };
                    match session.wallet.decrypt_credit(
                        decryptor,
                        &credit.deliveries[index].ciphertext,
                        &context,
                        *role,
                    )? {
                        Some(state) => Decoded::Credit(state),
                        None => continue,
                    }
                }
            };
            decoded.push((candidate.clone(), value));
        }
        if session.source.context() != session.scope.context
            || session.source.block(self.anchor.number)? != self.anchor
        {
            return Err("canonical refresh anchor changed".into());
        }
        session.invisi.chain.canonical(&self.anchor)?;
        for receipt in &self.receipts {
            if session.source.receipt(receipt.transaction_hash)?.as_ref() != Some(receipt) {
                return Err("canonical candidate receipt changed".into());
            }
            session.invisi.chain.canonical(&receipt.block)?;
        }
        let mut next = self.base.clone();
        if self.options.reset {
            next.notes.clear();
            next.credits.clear();
            next.invalidated = false;
            next.observed_through = None;
            next.discovery_through = None;
            for record in next.operations.values_mut() {
                if !session.terminal_is_canonical(record) {
                    record.status = OperationStatus::Reorged;
                    record.generation = record
                        .generation
                        .checked_add(1)
                        .ok_or("operation generation exhausted")?;
                    record.resolved_at = None;
                }
            }
        }
        let mut note_count = 0;
        let mut credit_count = 0;
        for (candidate, value) in decoded {
            match (candidate, value) {
                (Candidate::Note(output), Decoded::Note(note)) => {
                    if note.context != session.scope.context
                        || note.token_address != sdk::address_word(output.leaf.token)
                        || sdk::field_word(note.commitment().map_err(|e| e.to_string())?)
                            != output.leaf.commitment
                    {
                        return Err("decoded Note receipt context mismatch".into());
                    }
                    let (root, path) = session.verified_membership(&output.leaf, &self.anchor)?;
                    let nullifier = sdk::field_word(note.nullifier().map_err(|e| e.to_string())?);
                    let reserved_by =
                        reservation_for(&next, &format!("note:{}", output.leaf.commitment));
                    if let Some(previous) = next.notes.get(&output.leaf.commitment) {
                        if previous.input.note != note
                            || previous.input.tree_id != output.leaf.tree_id
                            || previous.input.leaf_index as u32 != output.leaf.leaf_index
                            || previous.transaction_hash != output.leaf.transaction_hash
                        {
                            return Err("conflicting canonical Note identity".into());
                        }
                    }
                    next.notes.insert(
                        output.leaf.commitment,
                        StoredNote {
                            input: NoteInput {
                                note,
                                tree_id: output.leaf.tree_id,
                                leaf_index: u16::try_from(output.leaf.leaf_index)
                                    .map_err(|_| "leaf index overflow")?,
                                path,
                                root,
                            },
                            commitment: output.leaf.commitment,
                            nullifier,
                            block: output.leaf.block,
                            transaction_hash: output.leaf.transaction_hash,
                            spent: false,
                            reserved_by,
                        },
                    );
                    note_count += 1;
                }
                (Candidate::Credit(output, role), Decoded::Credit(delivery)) => {
                    insert_credit(
                        session,
                        &mut next,
                        &output.leaf,
                        delivery,
                        role,
                        &self.anchor,
                    )?;
                    credit_count += 1;
                }
                _ => return Err("decoded wallet result mismatch".into()),
            }
        }
        // A canonical draw can recover an owned successor using its authenticated predecessor shared key.
        for receipt in &self.receipts {
            if !receipt.success {
                continue;
            }
            let records = protocol::decode_receipt_outputs(
                sdk::word_address(session.scope.context.protocol_address)?,
                receipt,
            )?;
            for (_, event) in records.events {
                if let P::InvisiProtocolEvents::CreditDraw(event) = event {
                    for (i, nullifier) in event.params.nullifiers.iter().enumerate() {
                        let predecessors = next
                            .credits
                            .values()
                            .filter(|record| record.nullifier == *nullifier)
                            .cloned()
                            .collect::<Vec<_>>();
                        for previous in predecessors {
                            let commitment = event.params.creditCommitments[i];
                            let key = credit_key(commitment, previous.role);
                            if next.credits.contains_key(&key) {
                                continue;
                            }
                            let recovered = crate::credit::recover_credit_state(
                                session.scope.context,
                                &previous.delivery.note,
                                &crate::credit::CreditStateRecovery {
                                    timestamp: receipt.block.timestamp,
                                    credit_nullifier: U256::from_be_slice(nullifier.as_slice()),
                                    state_commitment: U256::from_be_slice(commitment.as_slice()),
                                    recovery_amount: U256::from_be_slice(
                                        event.params.recoveryAmounts[i].as_slice(),
                                    ),
                                },
                            )
                            .map_err(|e| e.to_string())?;
                            let leaf = rpc::LeafMetadata {
                                block: receipt.block.clone(),
                                tree_id: u64::try_from(event.outputTreeId)
                                    .map_err(|_| "Credit tree overflow")?,
                                leaf_index: event.leafIndices[i],
                                commitment,
                                token: event.params.token,
                                transaction_hash: receipt.transaction_hash,
                                log_index: receipt.logs.first().map_or(0, |v| v.log_index),
                                kind: "CreditDraw".into(),
                            };
                            insert_credit(
                                session,
                                &mut next,
                                &leaf,
                                CreditDeliveryState {
                                    note: recovered,
                                    owner_receiving_keys: previous.delivery.owner_receiving_keys,
                                    spender_receiving_keys: previous
                                        .delivery
                                        .spender_receiving_keys,
                                },
                                previous.role,
                                &self.anchor,
                            )?;
                            credit_count += 1;
                        }
                    }
                }
            }
        }
        for note in next.notes.values_mut() {
            note.spent = session
                .invisi
                .chain
                .nullifier_spent(note.nullifier, &self.anchor)?;
        }
        for credit in next.credits.values_mut() {
            credit.consumed = session
                .invisi
                .chain
                .nullifier_spent(credit.nullifier, &self.anchor)?;
            let state = &credit.delivery.note;
            credit.revoked = session.invisi.chain.credit_revoked(
                sdk::word_address(state.owner_wallet_identity)?,
                sdk::word_address(state.token_address)?,
                state.revocation_shard,
                state.revocation_slot,
                &self.anchor,
            )?;
        }
        if let Some(completions) = &self.completion {
            for (id, generation, success) in completions {
                let record = next
                    .operations
                    .get_mut(id)
                    .ok_or("operation journal disappeared")?;
                if record.generation != *generation {
                    return Err("stale operation reconciliation".into());
                }
                let hash = record
                    .transaction_hash
                    .ok_or("operation transaction hash missing")?;
                let transaction = session
                    .source
                    .transaction(hash)?
                    .ok_or("canonical transaction missing")?;
                let call = record.call.as_ref().ok_or("operation calldata missing")?;
                if transaction.hash != hash
                    || transaction.chain_id != session.scope.context.chain_id
                    || transaction.to != Some(call.to)
                    || transaction.input != call.data
                    || transaction.value != call.value
                    || transaction
                        .block
                        .as_ref()
                        .is_none_or(|block| self.receipts.iter().all(|r| r.block != *block))
                {
                    return Err("reconciliation transaction differs from exported call".into());
                }
                record.status = if *success {
                    OperationStatus::Confirmed
                } else {
                    OperationStatus::Reverted
                };
                record.resolved_at = Some(self.anchor.clone());
                record.generation = record
                    .generation
                    .checked_add(1)
                    .ok_or("operation generation exhausted")?;
                release_inputs(&mut next, id);
            }
        }
        next.observed_through = Some(self.anchor.clone());
        let start = next
            .discovery_through
            .as_ref()
            .map_or(session.source.deployment_start(), |b| {
                b.number.saturating_add(1)
            });
        if self.completion.is_none() && self.options.from_block <= start {
            next.discovery_through = Some(self.anchor.clone());
        }
        session.invisi.chain.canonical(&self.anchor)?;
        let expected = next.revision;
        session.commit(next)?;
        Ok(RefreshResult {
            block: self.anchor.clone(),
            notes: note_count,
            credits: credit_count,
            revision: expected + 1,
        })
    }
}
fn reservation_for(state: &WalletState, input: &str) -> Option<String> {
    state
        .operations
        .values()
        .find(|op| !op.status.terminal() && op.inputs.iter().any(|value| value == input))
        .map(|op| op.id.clone())
}
pub(crate) fn release_inputs(state: &mut WalletState, id: &str) {
    for note in state.notes.values_mut() {
        if note.reserved_by.as_deref() == Some(id) {
            note.reserved_by = None;
        }
    }
    for credit in state.credits.values_mut() {
        if credit.reserved_by.as_deref() == Some(id) {
            credit.reserved_by = None;
        }
    }
}
fn insert_credit(
    session: &WalletSession,
    state: &mut WalletState,
    leaf: &rpc::LeafMetadata,
    delivery: CreditDeliveryState,
    role: CreditRole,
    anchor: &CanonicalBlock,
) -> Result<()> {
    delivery.validate().map_err(|e| e.to_string())?;
    let identity = if role == CreditRole::Owner {
        delivery.note.owner_wallet_identity
    } else {
        delivery.note.spender_wallet_identity
    };
    if identity != sdk::address_word(session.wallet.owner_address())
        || delivery.note.context != session.scope.context
        || delivery.note.token_address != sdk::address_word(leaf.token)
        || sdk::field_word(delivery.note.commitment().map_err(|e| e.to_string())?)
            != leaf.commitment
    {
        return Err("Credit receipt owner or context mismatch".into());
    }
    let (root, path) = session.verified_membership(leaf, anchor)?;
    let key = credit_key(leaf.commitment, role);
    if let Some(previous) = state.credits.get(&key) {
        if previous.tree_id != leaf.tree_id
            || previous.leaf_index as u32 != leaf.leaf_index
            || previous
                .delivery
                .note
                .commitment()
                .map_err(|e| e.to_string())?
                != delivery.note.commitment().map_err(|e| e.to_string())?
        {
            return Err("conflicting canonical Credit identity".into());
        }
    }
    let nullifier = sdk::field_word(delivery.note.nullifier().map_err(|e| e.to_string())?);
    let reserved_by = reservation_for(state, &format!("credit:{}", leaf.commitment));
    state.credits.insert(
        key,
        StoredCredit {
            delivery,
            commitment: leaf.commitment,
            nullifier,
            tree_id: leaf.tree_id,
            leaf_index: u16::try_from(leaf.leaf_index).map_err(|_| "Credit index overflow")?,
            path,
            root,
            block: leaf.block.clone(),
            transaction_hash: leaf.transaction_hash,
            role,
            consumed: false,
            revoked: false,
            reserved_by,
        },
    );
    Ok(())
}
