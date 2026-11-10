//! Stateless Note/Credit preparation and a public-only, host-executed wallet boundary.
use crate::{
    address::{ReceivingAddress, ReceivingKeys},
    delivery::{CreditDeliveryState, CreditRole, DeliveryContext},
    note::{Note, ProtocolContext},
    protocol::{self, IInvisiProtocol as abi, InvisiProtocol, TransactionCall},
    prover::{self, ProofBundle, Prover},
    rpc::{CanonicalBlock, CanonicalHead, ProtocolDeployment},
};
use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_sol_types::{SolCall, SolValue};
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
pub type Result<T> = std::result::Result<T, String>;
pub fn address_word(a: Address) -> U256 {
    U256::from_be_slice(a.as_slice())
}
pub fn word_address(a: U256) -> Result<Address> {
    crate::note::positive_address(a, "address").map_err(|e| e.to_string())?;
    Ok(Address::from_slice(&a.to_be_bytes::<32>()[12..]))
}
pub fn field_word(n: U256) -> B256 {
    B256::from(n.to_be_bytes::<32>())
}
fn model<T>(r: crate::note::ModelResult<T>) -> Result<T> {
    r.map_err(|e| e.to_string())
}
fn hex_bytes(s: &str, n: Option<usize>) -> Result<Vec<u8>> {
    let v = model(crate::note::decode_hex(s))?;
    if n.is_some_and(|n| n != v.len()) {
        return Err("invalid byte length".into());
    }
    Ok(v)
}
fn hex(v: &[u8]) -> String {
    format!("0x{}", hex::encode(v))
}
fn decimal(v: &Value) -> Result<U256> {
    let s = v.as_str().ok_or("canonical decimal string required")?;
    if s.is_empty()
        || s.len() > 78
        || s.len() > 1 && s.starts_with('0')
        || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("noncanonical decimal".into());
    }
    U256::from_str_radix(s, 10).map_err(|_| "decimal overflow".into())
}
fn protocol_context(v: &Value) -> Result<ProtocolContext> {
    let chain_id = u64::try_from(decimal(&v["chainId"])?).map_err(|_| "chain id overflow")?;
    let c = ProtocolContext {
        chain_id,
        protocol_address: decimal(&v["protocolAddress"])?,
    };
    model(c.validate())?;
    Ok(c)
}
fn context_value(c: ProtocolContext) -> Value {
    json!({"chainId":c.chain_id.to_string(),"protocolAddress":c.protocol_address.to_string()})
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WalletRequest {
    pub version: u32,
    pub id: String,
    pub owner_address: String,
    pub method: String,
    pub params: Value,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletError {
    pub code: String,
}
impl WalletError {
    fn validate(&self) -> Result<()> {
        if !self
            .code
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_uppercase)
            || self.code.len() > 128
            || !self
                .code
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err("invalid wallet error code".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum WalletOutcome {
    Result { result: Value },
    Error { error: WalletError },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletResponse {
    pub version: u32,
    pub id: String,
    pub owner_address: String,
    pub method: String,
    #[serde(flatten)]
    pub outcome: WalletOutcome,
}
impl<'de> Deserialize<'de> for WalletResponse {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let object = value
            .as_object()
            .ok_or_else(|| serde::de::Error::custom("wallet response object required"))?;
        let result = object.contains_key("result");
        let expected = [
            "version",
            "id",
            "ownerAddress",
            "method",
            if result { "result" } else { "error" },
        ];
        if object.len() != 5 || expected.iter().any(|k| !object.contains_key(*k)) {
            return Err(serde::de::Error::custom(
                "wallet response requires exactly one result or error",
            ));
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Envelope {
            version: u32,
            id: String,
            owner_address: String,
            method: String,
        }
        let envelope: Envelope =
            serde_json::from_value(value.clone()).map_err(serde::de::Error::custom)?;
        let outcome = if result {
            WalletOutcome::Result {
                result: value["result"].clone(),
            }
        } else {
            let error: WalletError =
                serde_json::from_value(value["error"].clone()).map_err(serde::de::Error::custom)?;
            error.validate().map_err(serde::de::Error::custom)?;
            WalletOutcome::Error { error }
        };
        Ok(Self {
            version: envelope.version,
            id: envelope.id,
            owner_address: envelope.owner_address,
            method: envelope.method,
            outcome,
        })
    }
}
impl WalletResponse {
    pub fn result(&self) -> Result<&Value> {
        match &self.outcome {
            WalletOutcome::Result { result } => Ok(result),
            WalletOutcome::Error { error } => {
                error.validate()?;
                Err(error.code.clone())
            }
        }
    }
    pub fn result_mut(&mut self) -> Result<&mut Value> {
        match &mut self.outcome {
            WalletOutcome::Result { result } => Ok(result),
            WalletOutcome::Error { error } => {
                error.validate()?;
                Err(error.code.clone())
            }
        }
    }
}
impl WalletRequest {
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.id.is_empty()
            || self.id.len() > 128
            || !self.id.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err("invalid wallet request identity".into());
        }
        let owner = hex_bytes(&self.owner_address, Some(20))?;
        if owner == [0; 20]
            || !self.params.is_object()
            || ![
                "wallet.public",
                "wallet.detect",
                "wallet.decryptNote",
                "wallet.decryptCredit",
                "wallet.authorize",
            ]
            .contains(&self.method.as_str())
        {
            return Err("invalid wallet request".into());
        }
        crate::wallet::validate_wire(&self.as_value())
    }
    pub fn as_value(&self) -> Value {
        serde_json::to_value(self).expect("serializable wallet request")
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletAuthorization {
    pub spending_public_key: [u8; 65],
    pub signature: [u8; 64],
    pub digest: B256,
}
pub enum WalletResult {
    Public(ReceivingKeys),
    Detected(Vec<bool>),
    Note(Note),
    Credit(CreditDeliveryState),
    Authorized(WalletAuthorization),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wallet {
    owner: Address,
    receiving_keys: Option<ReceivingKeys>,
}
impl Wallet {
    pub fn from_owner(owner: Address) -> Result<Self> {
        if owner == Address::ZERO {
            return Err("nonzero wallet owner required".into());
        }
        Ok(Self {
            owner,
            receiving_keys: None,
        })
    }
    pub fn from_address(address: &str) -> Result<Self> {
        let parsed = model(ReceivingAddress::parse(address))?;
        Ok(Self {
            owner: word_address(parsed.owner_address)?,
            receiving_keys: parsed.keys,
        })
    }
    pub fn from_keys(owner: Address, keys: ReceivingKeys) -> Result<Self> {
        let mut w = Self::from_owner(owner)?;
        model(keys.validate())?;
        w.receiving_keys = Some(keys);
        Ok(w)
    }
    pub fn owner_address(&self) -> Address {
        self.owner
    }
    pub fn receiving_keys(&self) -> Option<&ReceivingKeys> {
        self.receiving_keys.as_ref()
    }
    pub fn address(&self) -> Result<String> {
        model(
            ReceivingAddress {
                owner_address: address_word(self.owner),
                keys: self.receiving_keys.clone(),
            }
            .encode(),
        )
    }
    pub fn prepare_request(
        &self,
        id: impl Into<String>,
        method: &str,
        params: Value,
    ) -> Result<WalletRequest> {
        let q = WalletRequest {
            version: 1,
            id: id.into(),
            owner_address: hex(self.owner.as_slice()),
            method: method.into(),
            params,
        };
        q.validate()?;
        Ok(q)
    }
    pub fn from_response(q: &WalletRequest, r: &WalletResponse) -> Result<Self> {
        if q.method != "wallet.public" {
            return Err("public material response required".into());
        }
        let w = Self::from_owner(Address::from_slice(&hex_bytes(&q.owner_address, Some(20))?))?;
        match w.accept_response(q, r)? {
            WalletResult::Public(keys) => Self::from_keys(w.owner, keys),
            _ => Err("public response required".into()),
        }
    }
    /// Validate all envelopes and return responses in request order without trusting their results.
    pub fn validate_batch<'a>(
        &self,
        requests: &[WalletRequest],
        responses: &'a [WalletResponse],
    ) -> Result<Vec<&'a WalletResponse>> {
        if requests.len() > crate::wallet::MAX_WALLET_BATCH_ITEMS
            || requests.len() != responses.len()
            || serde_json::to_vec(requests)
                .map_err(|e| e.to_string())?
                .len()
                > crate::wallet::MAX_WALLET_BATCH_JSON_BYTES
            || serde_json::to_vec(responses)
                .map_err(|e| e.to_string())?
                .len()
                > crate::wallet::MAX_WALLET_BATCH_JSON_BYTES
        {
            return Err("wallet batch limit or response count mismatch".into());
        }
        let mut expected = BTreeMap::new();
        for request in requests {
            request.validate()?;
            if request.owner_address != hex(self.owner.as_slice())
                || expected.insert(request.id.as_str(), request).is_some()
            {
                return Err("wallet batch owner or duplicate request id".into());
            }
        }
        let mut actual = BTreeMap::new();
        for response in responses {
            if let WalletOutcome::Error { error } = &response.outcome {
                error.validate()?;
            }
            let request = expected
                .get(response.id.as_str())
                .ok_or("unknown wallet response id")?;
            if response.version != request.version
                || response.owner_address != request.owner_address
                || response.method != request.method
                || actual.insert(response.id.as_str(), response).is_some()
            {
                return Err("wallet response request binding mismatch".into());
            }
        }
        requests
            .iter()
            .map(|request| {
                actual
                    .get(request.id.as_str())
                    .copied()
                    .ok_or_else(|| "missing wallet response id".into())
            })
            .collect()
    }
    /// Independently decode and validate successful members, retaining explicit host errors.
    pub fn accept_batch(
        &self,
        requests: &[WalletRequest],
        responses: &[WalletResponse],
    ) -> Result<Vec<std::result::Result<WalletResult, WalletError>>> {
        let responses = self.validate_batch(requests, responses)?;
        requests
            .iter()
            .zip(responses)
            .map(|(request, response)| match &response.outcome {
                WalletOutcome::Error { error } => Ok(Err(error.clone())),
                WalletOutcome::Result { .. } => self.accept_response(request, response).map(Ok),
            })
            .collect()
    }
    /// Validate App plaintext against this wallet and the canonical output context.
    pub fn decrypt_note(
        &self,
        decryptor: &dyn crate::delivery::DeliveryDecryptor,
        envelope: &[u8],
        context: &crate::delivery::DeliveryContext,
    ) -> Result<Option<Note>> {
        model(crate::delivery::validate_envelope(envelope, false))?;
        let Some(plain) = decryptor.decrypt_note(envelope, context, address_word(self.owner))?
        else {
            return Ok(None);
        };
        if plain.len() + 78 > crate::delivery::MAX_CIPHERTEXT_BYTES {
            return Err("plaintext exceeds resource bound".into());
        }
        let note = model(crate::delivery::decode_note(&plain, context))?;
        if note.owner_address != address_word(self.owner) {
            return Err("note recipient mismatch".into());
        }
        Ok(Some(note))
    }
    pub fn decrypt_credit(
        &self,
        decryptor: &dyn crate::delivery::DeliveryDecryptor,
        envelope: &[u8],
        context: &crate::delivery::DeliveryContext,
        role: crate::delivery::CreditRole,
    ) -> Result<Option<crate::delivery::CreditDeliveryState>> {
        model(crate::delivery::validate_envelope(envelope, true))?;
        let Some(plain) =
            decryptor.decrypt_credit(envelope, context, role, address_word(self.owner))?
        else {
            return Ok(None);
        };
        if plain.len() + 78 > crate::delivery::MAX_CIPHERTEXT_BYTES {
            return Err("plaintext exceeds resource bound".into());
        }
        let state = model(crate::delivery::decode_credit(&plain, context))?;
        let (identity, keys) = match role {
            crate::delivery::CreditRole::Owner => (
                state.note.owner_wallet_identity,
                &state.owner_receiving_keys,
            ),
            crate::delivery::CreditRole::Spender => (
                state.note.spender_wallet_identity,
                &state.spender_receiving_keys,
            ),
        };
        if identity != address_word(self.owner)
            || self
                .receiving_keys
                .as_ref()
                .is_none_or(|existing| existing.viewing_public_key != keys.viewing_public_key)
        {
            return Err("Credit recipient or receiving snapshot mismatch".into());
        }
        Ok(Some(state))
    }

    pub fn accept_response(&self, q: &WalletRequest, r: &WalletResponse) -> Result<WalletResult> {
        q.validate()?;
        if q.owner_address != hex(self.owner.as_slice())
            || r.version != q.version
            || r.id != q.id
            || r.owner_address != q.owner_address
            || r.method != q.method
        {
            return Err("wallet response request binding mismatch".into());
        }
        let result = r.result()?;
        if !result.is_object() {
            return Err("wallet result object required".into());
        }
        fn exact(value: &Value, keys: &[&str]) -> Result<()> {
            let o = value.as_object().ok_or("wallet object required")?;
            if o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)) {
                return Err("wallet object fields mismatch".into());
            }
            Ok(())
        }
        match q.method.as_str() {
            "wallet.public" => {
                exact(&q.params, &[])?;
                exact(
                    result,
                    &["viewingPublicKey", "spendingPublicKey", "clueKey"],
                )?;
                let public = hex_bytes(
                    result["spendingPublicKey"]
                        .as_str()
                        .ok_or("public key required")?,
                    Some(65),
                )?;
                validate_spending_key(self.owner, &public)?;
                let keys = ReceivingKeys {
                    viewing_public_key: hex_bytes(
                        result["viewingPublicKey"]
                            .as_str()
                            .ok_or("viewing key required")?,
                        Some(33),
                    )?
                    .try_into()
                    .map_err(|_| "invalid viewing key")?,
                    clue_key: hex_bytes(
                        result["clueKey"].as_str().ok_or("clue key required")?,
                        Some(32),
                    )?
                    .try_into()
                    .map_err(|_| "invalid clue key")?,
                };
                model(keys.validate())?;
                if self
                    .receiving_keys
                    .as_ref()
                    .is_some_and(|existing| existing != &keys)
                {
                    return Err("resolved receiving keys mismatch".into());
                }
                Ok(WalletResult::Public(keys))
            }
            "wallet.detect" => {
                exact(&q.params, &["clues"])?;
                exact(result, &["matches"])?;
                let clues = q.params["clues"].as_array().ok_or("clues required")?;
                for clue in clues {
                    hex_bytes(clue.as_str().ok_or("clue required")?, Some(68))?;
                }
                let matches: Vec<bool> = serde_json::from_value(result["matches"].clone())
                    .map_err(|_| "boolean detection results required")?;
                if matches.len() != clues.len() {
                    return Err("detection length mismatch".into());
                }
                Ok(WalletResult::Detected(matches))
            }
            "wallet.authorize" => {
                exact(&q.params, &["operation", "capacity", "context", "words"])?;
                exact(&q.params["context"], &["chainId", "protocolAddress"])?;
                protocol_context(&q.params["context"])?;
                for v in q.params["words"]
                    .as_array()
                    .ok_or("public words required")?
                {
                    model(crate::note::field(decimal(v)?, "authorization field"))?;
                }
                exact(result, &["spendingPublicKey", "signature", "digest"])?;
                let public = hex_bytes(
                    result["spendingPublicKey"]
                        .as_str()
                        .ok_or("public key required")?,
                    Some(65),
                )?;
                validate_spending_key(self.owner, &public)?;
                let signature = hex_bytes(
                    result["signature"].as_str().ok_or("signature required")?,
                    Some(64),
                )?;
                let digest = crate::wallet::authorization_digest(&q.params)?;
                if hex_bytes(
                    result["digest"].as_str().ok_or("digest required")?,
                    Some(32),
                )? != digest
                {
                    return Err("authorization digest mismatch".into());
                }
                let sig =
                    Signature::from_slice(&signature).map_err(|_| "invalid wallet signature")?;
                if sig.normalize_s().is_some() {
                    return Err("noncanonical wallet signature".into());
                }
                VerifyingKey::from_sec1_bytes(&public)
                    .map_err(|_| "invalid spending key")?
                    .verify_prehash(&digest, &sig)
                    .map_err(|_| "wallet signature mismatch")?;
                Ok(WalletResult::Authorized(WalletAuthorization {
                    spending_public_key: public.try_into().map_err(|_| "invalid key length")?,
                    signature: signature
                        .try_into()
                        .map_err(|_| "invalid signature length")?,
                    digest: B256::from(digest),
                }))
            }
            "wallet.decryptNote" | "wallet.decryptCredit" => {
                exact(&q.params, &["envelope", "context"])?;
                exact(result, &["plaintext"])?;
                let credit = q.method == "wallet.decryptCredit";
                exact(
                    &q.params["context"],
                    if credit {
                        &[
                            "chainId",
                            "protocolAddress",
                            "tokenAddress",
                            "outputCommitment",
                            "role",
                        ]
                    } else {
                        &[
                            "chainId",
                            "protocolAddress",
                            "tokenAddress",
                            "outputCommitment",
                        ]
                    },
                )?;
                let context = DeliveryContext {
                    context: protocol_context(&q.params["context"])?,
                    token_address: decimal(&q.params["context"]["tokenAddress"])?,
                    output_commitment: U256::from_be_slice(&hex_bytes(
                        q.params["context"]["outputCommitment"]
                            .as_str()
                            .ok_or("commitment required")?,
                        Some(32),
                    )?),
                };
                model(context.validate())?;
                let envelope = hex_bytes(
                    q.params["envelope"].as_str().ok_or("envelope required")?,
                    None,
                )?;
                model(crate::delivery::validate_envelope(&envelope, credit))?;
                let plain = hex_bytes(
                    result["plaintext"].as_str().ok_or("plaintext required")?,
                    None,
                )?;
                if plain.len() > 4096 {
                    return Err("wallet plaintext exceeds bound".into());
                }
                if !credit {
                    let note = model(crate::delivery::decode_note(&plain, &context))?;
                    if note.owner_address != address_word(self.owner) {
                        return Err("note recipient mismatch".into());
                    }
                    Ok(WalletResult::Note(note))
                } else {
                    let state = model(crate::delivery::decode_credit(&plain, &context))?;
                    let (identity, keys) = match q.params["context"]["role"].as_str() {
                        Some("owner") => (
                            state.note.owner_wallet_identity,
                            &state.owner_receiving_keys,
                        ),
                        Some("spender") => (
                            state.note.spender_wallet_identity,
                            &state.spender_receiving_keys,
                        ),
                        _ => return Err("invalid Credit role".into()),
                    };
                    if identity != address_word(self.owner)
                        || self.receiving_keys.as_ref().is_none_or(|existing| {
                            existing.viewing_public_key != keys.viewing_public_key
                        })
                    {
                        return Err("Credit recipient or receiving snapshot mismatch".into());
                    }
                    Ok(WalletResult::Credit(state))
                }
            }
            _ => Err("unsupported wallet method".into()),
        }
    }
}
fn validate_spending_key(owner: Address, public: &[u8]) -> Result<()> {
    if public.len() != 65 || public[0] != 4 {
        return Err("uncompressed spending key required".into());
    }
    VerifyingKey::from_sec1_bytes(public).map_err(|_| "invalid spending key")?;
    if &keccak256(&public[1..]).as_slice()[12..] != owner.as_slice() {
        return Err("spending identity mismatch".into());
    }
    Ok(())
}

pub trait ChainState: Send + Sync {
    fn context(&self) -> ProtocolContext;
    fn snapshot(&self) -> Result<CanonicalBlock>;
    fn canonical(&self, block: &CanonicalBlock) -> Result<()>;
    fn known_root(&self, tree_id: u64, root: B256, block: &CanonicalBlock) -> Result<bool>;
    fn nullifier_spent(&self, nullifier: B256, block: &CanonicalBlock) -> Result<bool>;
    fn credit_revoked(
        &self,
        owner: Address,
        token: Address,
        shard: u64,
        slot: u16,
        block: &CanonicalBlock,
    ) -> Result<bool>;
    fn token_balance_allowance(
        &self,
        owner: Address,
        token: Address,
        block: &CanonicalBlock,
    ) -> Result<(U256, U256)>;
    fn credit_allocation(
        &self,
        owner: Address,
        token: Address,
        block: &CanonicalBlock,
    ) -> Result<(u64, u16)>;
    fn funding_nonce(&self, _owner: Address, _block: &CanonicalBlock) -> Result<U256> {
        Err("funding nonce reader required".into())
    }
    fn public_signature_valid(
        &self,
        owner: Address,
        digest: B256,
        signature: &[u8],
        _block: &CanonicalBlock,
    ) -> Result<bool> {
        Ok(verify_eoa_signature(owner, digest, signature))
    }
}
pub struct RpcChainState<C: CanonicalHead> {
    pub chain: C,
    pub deployment: ProtocolDeployment,
}
impl<C: CanonicalHead> RpcChainState<C> {
    pub fn new(chain: C, deployment: ProtocolDeployment) -> Result<Self> {
        deployment.validate().map_err(|e| e.to_string())?;
        if chain.chain_id().map_err(|e| e.to_string())?
            != deployment.chain_id().map_err(|e| e.to_string())?
        {
            return Err("chain deployment mismatch".into());
        }
        let s = Self { chain, deployment };
        s.snapshot()?;
        Ok(s)
    }
    fn read(
        &self,
        address: Address,
        signature: &str,
        args: &[U256],
        block: &CanonicalBlock,
    ) -> Result<Vec<u8>> {
        let mut bytes = keccak256(signature.as_bytes()).as_slice()[..4].to_vec();
        for arg in args {
            bytes.extend_from_slice(&arg.to_be_bytes::<32>());
        }
        self.chain
            .call(address, &bytes, block.number)
            .map_err(|e| e.to_string())
    }
    fn uint_read(
        &self,
        address: Address,
        signature: &str,
        args: &[U256],
        block: &CanonicalBlock,
    ) -> Result<U256> {
        let bytes = self.read(address, signature, args, block)?;
        if bytes.len() != 32 {
            return Err("invalid contract read width".into());
        }
        Ok(U256::from_be_slice(&bytes))
    }
}
impl<C: CanonicalHead> ChainState for RpcChainState<C> {
    fn context(&self) -> ProtocolContext {
        ProtocolContext {
            chain_id: self.deployment.chain_id().expect("validated deployment"),
            protocol_address: address_word(self.deployment.protocol.address),
        }
    }
    fn snapshot(&self) -> Result<CanonicalBlock> {
        let block = self.chain.head().map_err(|e| e.to_string())?;
        if block.number < self.deployment.protocol.from_block {
            return Err("chain head predates deployment".into());
        }
        if self.chain.chain_id().map_err(|e| e.to_string())? != self.context().chain_id {
            return Err("chain identity changed".into());
        }
        let code = self
            .chain
            .code_at(self.deployment.protocol.address, Some(block.number))
            .map_err(|e| e.to_string())?;
        if keccak256(&code) != self.deployment.protocol.runtime_code_hash {
            return Err("protocol runtime code mismatch".into());
        }
        self.canonical(&block)?;
        Ok(block)
    }
    fn canonical(&self, block: &CanonicalBlock) -> Result<()> {
        if self
            .chain
            .block(block.number)
            .map_err(|e| e.to_string())?
            .hash
            != block.hash
        {
            return Err("chain reorganization".into());
        }
        Ok(())
    }
    fn known_root(&self, tree: u64, root: B256, b: &CanonicalBlock) -> Result<bool> {
        let n = self.uint_read(
            self.deployment.protocol.address,
            "rootHistory(uint256,bytes32)",
            &[U256::from(tree), U256::from_be_slice(root.as_slice())],
            b,
        )?;
        if n > U256::from(1) {
            return Err("noncanonical contract boolean".into());
        }
        Ok(n == U256::from(1))
    }
    fn nullifier_spent(&self, n: B256, b: &CanonicalBlock) -> Result<bool> {
        let n = self.uint_read(
            self.deployment.protocol.address,
            "isNullifierSpent(bytes32)",
            &[U256::from_be_slice(n.as_slice())],
            b,
        )?;
        if n > U256::from(1) {
            return Err("noncanonical contract boolean".into());
        }
        Ok(n == U256::from(1))
    }
    fn credit_revoked(
        &self,
        owner: Address,
        token: Address,
        shard: u64,
        slot: u16,
        b: &CanonicalBlock,
    ) -> Result<bool> {
        let bits = self.uint_read(
            self.deployment.protocol.address,
            "creditRevocationBitmap(address,address,uint64,uint8)",
            &[
                address_word(owner),
                address_word(token),
                U256::from(shard),
                U256::from(slot / 256),
            ],
            b,
        )?;
        Ok(bits.bit((slot % 256) as usize))
    }
    fn token_balance_allowance(
        &self,
        owner: Address,
        token: Address,
        b: &CanonicalBlock,
    ) -> Result<(U256, U256)> {
        Ok((
            self.uint_read(token, "balanceOf(address)", &[address_word(owner)], b)?,
            self.uint_read(
                token,
                "allowance(address,address)",
                &[
                    address_word(owner),
                    address_word(self.deployment.protocol.address),
                ],
                b,
            )?,
        ))
    }
    fn funding_nonce(&self, owner: Address, b: &CanonicalBlock) -> Result<U256> {
        self.uint_read(
            self.deployment.protocol.address,
            "nonces(address)",
            &[address_word(owner)],
            b,
        )
    }
    fn public_signature_valid(
        &self,
        owner: Address,
        digest: B256,
        signature: &[u8],
        b: &CanonicalBlock,
    ) -> Result<bool> {
        if verify_eoa_signature(owner, digest, signature) {
            self.canonical(b)?;
            return Ok(true);
        }
        if self
            .chain
            .code_at(owner, Some(b.number))
            .map_err(|e| e.to_string())?
            .is_empty()
        {
            return Ok(false);
        }
        let mut data = keccak256("isValidSignature(bytes32,bytes)").as_slice()[..4].to_vec();
        data.extend((digest, Bytes::copy_from_slice(signature)).abi_encode_params());
        let result = match self.chain.call(owner, &data, b.number) {
            Ok(result) => result,
            Err(e) if e.to_string().contains("execution reverted") => return Ok(false),
            Err(e) => return Err(e.to_string()),
        };
        self.canonical(b)?;
        let mut magic = [0; 32];
        magic[..4].copy_from_slice(&[0x16, 0x26, 0xba, 0x7e]);
        Ok(result.len() >= 32 && result[..32] == magic)
    }
    fn credit_allocation(
        &self,
        owner: Address,
        token: Address,
        b: &CanonicalBlock,
    ) -> Result<(u64, u16)> {
        let raw = self.read(
            self.deployment.protocol.address,
            "creditAllocation(address,address)",
            &[address_word(owner), address_word(token)],
            b,
        )?;
        if raw.len() != 64 {
            return Err("invalid Credit allocation result".into());
        }
        Ok((
            u64::try_from(U256::from_be_slice(&raw[..32]))
                .map_err(|_| "allocation shard overflow")?,
            u16::try_from(U256::from_be_slice(&raw[32..]))
                .map_err(|_| "allocation slot overflow")?,
        ))
    }
}

pub fn merkle_root(mut leaf: U256, index: u16, path: &[U256; 16]) -> Result<U256> {
    for (i, sibling) in path.iter().enumerate() {
        let pair = if (index >> i) & 1 == 0 {
            [leaf, *sibling]
        } else {
            [*sibling, leaf]
        };
        leaf = model(crate::note::hash_fields(&pair))?;
    }
    Ok(leaf)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteInput {
    pub note: Note,
    pub tree_id: u64,
    pub leaf_index: u16,
    pub path: [U256; 16],
    pub root: U256,
}
impl NoteInput {
    pub fn validate(&self, owner: Address, context: ProtocolContext, token: Address) -> Result<()> {
        model(self.note.validate())?;
        if self.tree_id == 0
            || self.note.context != context
            || self.note.owner_address != address_word(owner)
            || self.note.token_address != address_word(token)
            || merkle_root(model(self.note.commitment())?, self.leaf_index, &self.path)?
                != self.root
        {
            return Err("Note input ownership, deployment or membership mismatch".into());
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct NoteOutput {
    context: ProtocolContext,
    token: Address,
    identity: U256,
    amount: U256,
    commitment: B256,
    note: Option<Note>,
    delivery: abi::Delivery,
}
fn nonce() -> U256 {
    loop {
        let mut bytes = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let value = U256::from_be_slice(&bytes);
        if value != U256::ZERO && value < crate::note::field_modulus() {
            return value;
        }
    }
}
impl NoteOutput {
    pub fn for_recipient(
        context: ProtocolContext,
        token: Address,
        recipient: &Wallet,
        amount: U256,
        payload: Vec<u8>,
    ) -> Result<Self> {
        let note = Note {
            context,
            owner_address: address_word(recipient.owner),
            token_address: address_word(token),
            amount,
            nonce: nonce(),
            payload,
        };
        Self::from_note(note, recipient.receiving_keys.as_ref())
    }
    pub fn from_note(note: Note, keys: Option<&ReceivingKeys>) -> Result<Self> {
        let context = note.context;
        let token = word_address(note.token_address)?;
        let identity = model(note.identity())?;
        let commitment = field_word(model(note.commitment())?);
        let delivery = if let Some(keys) = keys {
            model(keys.validate())?;
            let c = DeliveryContext {
                context,
                token_address: note.token_address,
                output_commitment: U256::from_be_slice(commitment.as_slice()),
            };
            abi::Delivery {
                ciphertext: model(crate::delivery::encrypt_note(
                    &keys.viewing_public_key,
                    &note,
                    &c,
                ))?
                .into(),
                clue: model(crate::fmd::create_clue(&keys.clue_key))?.into(),
            }
        } else {
            abi::Delivery {
                ciphertext: Bytes::new(),
                clue: Bytes::new(),
            }
        };
        Ok(Self {
            context,
            token,
            identity,
            amount: note.amount,
            commitment,
            note: Some(note),
            delivery,
        })
    }
    pub fn identity(
        context: ProtocolContext,
        token: Address,
        identity: U256,
        amount: U256,
    ) -> Result<Self> {
        model(context.validate())?;
        if identity == U256::ZERO {
            return Err("zero output identity".into());
        }
        let commitment = field_word(model(crate::note::compute_note_commitment(
            context.chain_id,
            context.protocol_address,
            identity,
            address_word(token),
            amount,
        ))?);
        Ok(Self {
            context,
            token,
            identity,
            amount,
            commitment,
            note: None,
            delivery: abi::Delivery {
                ciphertext: Bytes::new(),
                clue: Bytes::new(),
            },
        })
    }
    pub fn context(&self) -> ProtocolContext {
        self.context
    }
    pub fn token(&self) -> Address {
        self.token
    }
    pub fn identity_value(&self) -> U256 {
        self.identity
    }
    pub fn commitment(&self) -> B256 {
        self.commitment
    }
    pub fn amount(&self) -> U256 {
        self.amount
    }
    pub fn note(&self) -> Option<&Note> {
        self.note.as_ref()
    }
    pub fn delivery(&self) -> &abi::Delivery {
        &self.delivery
    }
}
#[derive(Clone, Debug, Default)]
pub struct Fee {
    pub recipient: Address,
    pub amount: U256,
}
impl Fee {
    fn validate(&self) -> Result<()> {
        model(crate::note::uint(self.amount, 128, "fee"))?;
        if (self.amount == U256::ZERO) != (self.recipient == Address::ZERO) {
            return Err("fee amount/recipient mismatch".into());
        }
        Ok(())
    }
}
#[derive(Clone)]
pub struct TransferPreparation {
    pub token: Address,
    pub inputs: Vec<NoteInput>,
    pub outputs: Vec<NoteOutput>,
    pub withdrawal: Option<(Address, U256)>,
    pub funding: abi::FundingParams,
    pub fee: Fee,
    pub deadline: u64,
    pub automatic_change: bool,
}
#[derive(Clone)]
pub struct ShieldPreparation {
    pub token: Address,
    pub outputs: Vec<NoteOutput>,
    pub funding: abi::FundingParams,
    pub fee: Fee,
    pub deadline: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Prepared,
    Authorized,
    Proved,
    Ready,
    Exported,
}
#[derive(Clone)]
pub(crate) enum Plan {
    Shield {
        params: abi::ShieldParams,
        outputs: Vec<NoteOutput>,
        funding: abi::FundingParams,
    },
    Transfer {
        params: abi::CrossTreeTransactParams,
        inputs: Vec<NoteInput>,
        outputs: Vec<NoteOutput>,
        funding: abi::FundingParams,
        capacity: usize,
    },
}
#[derive(Clone)]
pub struct PreparedTransaction {
    pub(crate) wallet: Wallet,
    pub(crate) context: ProtocolContext,
    pub(crate) token: Address,
    pub(crate) anchor: CanonicalBlock,
    pub(crate) plan: Plan,
    pub(crate) phase: Phase,
    pub(crate) authorization: Option<WalletAuthorization>,
    pub(crate) proof: Option<ProofBundle>,
    pub(crate) needs_authorization: bool,
    pub(crate) target: String,
    pub(crate) provenance: Option<Arc<PreparedProvenance>>,
    pub(crate) provenance_data: Option<Vec<u8>>,
    pub(crate) provenance_packet: Arc<std::sync::Mutex<Option<ProvenanceProof>>>,
    pub(crate) broadcaster: Option<PreparedBroadcasterState>,
    pub(crate) reprice: Option<RepriceTemplate>,
}
impl std::fmt::Debug for PreparedTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedTransaction")
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}
#[derive(Clone)]
pub struct Invisi {
    pub chain: Arc<dyn ChainState>,
    pub provenance: Option<Arc<PreparedProvenance>>,
}
fn sum(mut values: impl Iterator<Item = U256>) -> Result<U256> {
    values.try_fold(U256::ZERO, |a, b| {
        a.checked_add(b).ok_or_else(|| "amount overflow".into())
    })
}
fn validate_funding(f: &abi::FundingParams) -> Result<()> {
    model(crate::note::uint(f.amount, 128, "funding amount"))?;
    if (f.amount == U256::ZERO) != (f.payer == Address::ZERO) {
        return Err("funding amount/payer mismatch".into());
    }
    if f.amount == U256::ZERO
        && (f.sigNonce != U256::ZERO
            || f.deadline != U256::ZERO
            || !f.signature.is_empty()
            || f.permit.deadline != U256::ZERO
            || f.permit.v != 0
            || f.permit.r != B256::ZERO
            || f.permit.s != B256::ZERO)
    {
        return Err("empty funding must be canonical".into());
    }
    Ok(())
}
fn validate_outputs(
    outputs: &[NoteOutput],
    context: ProtocolContext,
    token: Address,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for out in outputs {
        if out.context != context
            || out.token != token
            || out.commitment == B256::ZERO
            || !seen.insert(out.commitment)
        {
            return Err("output context, zero or duplicate commitment".into());
        }
    }
    Ok(())
}
fn capacity(n: usize, m: usize) -> Result<usize> {
    if n + m == 0 || n + m > 190 || n == 0 && m < 2 {
        return Err("unsupported transact shape".into());
    }
    ([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        .into_iter()
        .chain((20..=190).step_by(10)))
    .find(|c| *c >= n + m)
    .ok_or_else(|| "unsupported capacity".into())
}
fn sorted_sources(inputs: &[NoteInput]) -> Result<Vec<abi::InputSource>> {
    let mut sources = BTreeMap::new();
    for input in inputs {
        if sources
            .insert(input.tree_id, input.root)
            .is_some_and(|r| r != input.root)
        {
            return Err("one root required per input tree".into());
        }
    }
    Ok(sources
        .into_iter()
        .map(|(tree, root)| abi::InputSource {
            treeId: U256::from(tree),
            merkleRoot: field_word(root),
        })
        .collect())
}
impl Invisi {
    pub fn new(chain: Arc<dyn ChainState>) -> Self {
        Self {
            chain,
            provenance: None,
        }
    }
    pub fn prepare_shield(
        &self,
        wallet: &Wallet,
        p: ShieldPreparation,
    ) -> Result<PreparedTransaction> {
        let template = RepriceTemplate::Shield(p.clone());
        let anchor = self.chain.snapshot()?;
        let context = self.chain.context();
        p.fee.validate()?;
        validate_funding(&p.funding)?;
        validate_outputs(&p.outputs, context, p.token)?;
        if p.deadline < anchor.timestamp
            || p.outputs.is_empty()
            || p.outputs.len() > 10
            || sum(p.outputs.iter().map(|o| o.amount))?.checked_add(p.fee.amount)
                != Some(p.funding.amount)
        {
            return Err("invalid shield deadline, count or funding balance".into());
        }
        let params = abi::ShieldParams {
            token: p.token,
            noteCommitments: p.outputs.iter().map(|o| o.commitment).collect(),
            deadline: U256::from(p.deadline),
            feeRecipient: p.fee.recipient,
            feeAmount: p.fee.amount,
        };
        self.chain.canonical(&anchor)?;
        Ok(PreparedTransaction {
            wallet: wallet.clone(),
            context,
            token: p.token,
            anchor,
            plan: Plan::Shield {
                params,
                outputs: p.outputs,
                funding: p.funding,
            },
            phase: Phase::Prepared,
            authorization: None,
            proof: None,
            needs_authorization: false,
            target: "evm".into(),
            provenance: self.provenance.clone(),
            provenance_data: None,
            provenance_packet: Default::default(),
            broadcaster: None,
            reprice: Some(template),
        })
    }
    pub fn prepare_transfer(
        &self,
        wallet: &Wallet,
        mut p: TransferPreparation,
    ) -> Result<PreparedTransaction> {
        let template = RepriceTemplate::Transfer(p.clone());
        let anchor = self.chain.snapshot()?;
        let context = self.chain.context();
        p.fee.validate()?;
        validate_funding(&p.funding)?;
        validate_outputs(&p.outputs, context, p.token)?;
        if p.deadline < anchor.timestamp {
            return Err("deadline expired".into());
        }
        let mut seen = BTreeSet::new();
        for input in &p.inputs {
            input.validate(wallet.owner, context, p.token)?;
            let n = field_word(model(input.note.nullifier())?);
            if !seen.insert(n)
                || !self
                    .chain
                    .known_root(input.tree_id, field_word(input.root), &anchor)?
                || self.chain.nullifier_spent(n, &anchor)?
            {
                return Err("duplicate, unknown or spent Note input".into());
            }
        }
        let (withdrawal_address, withdrawal_amount) =
            p.withdrawal.unwrap_or((Address::ZERO, U256::ZERO));
        model(crate::note::uint(withdrawal_amount, 128, "withdrawal"))?;
        if (withdrawal_amount == U256::ZERO) != (withdrawal_address == Address::ZERO) {
            return Err("withdrawal amount/address mismatch".into());
        }
        if p.inputs.is_empty()
            && (p.funding.amount == U256::ZERO || withdrawal_amount != U256::ZERO)
        {
            return Err("empty inputs require funding and no withdrawal".into());
        }
        let available = sum(p.inputs.iter().map(|i| i.note.amount))?
            .checked_add(p.funding.amount)
            .ok_or("amount overflow")?;
        let requested = sum(p.outputs.iter().map(|o| o.amount))?
            .checked_add(withdrawal_amount)
            .and_then(|a| a.checked_add(p.fee.amount))
            .ok_or("amount overflow")?;
        if requested > available {
            return Err("insufficient Note balance".into());
        }
        if requested < available {
            if !p.automatic_change {
                return Err("explicit outputs must balance inputs/funding".into());
            }
            if wallet.receiving_keys.is_none() {
                return Err("resolved receiving keys required for change".into());
            }
            p.outputs.push(NoteOutput::for_recipient(
                context,
                p.token,
                wallet,
                available - requested,
                Vec::new(),
            )?);
        }
        validate_outputs(&p.outputs, context, p.token)?;
        let c = capacity(p.inputs.len(), p.outputs.len())?;
        let sources = sorted_sources(&p.inputs)?;
        let nullifiers = p
            .inputs
            .iter()
            .map(|i| model(i.note.nullifier()).map(field_word))
            .collect::<Result<Vec<_>>>()?;
        let params = abi::CrossTreeTransactParams {
            token: p.token,
            sources,
            nullifiers,
            noteCommitments: p.outputs.iter().map(|o| o.commitment).collect(),
            withdrawalAddress: withdrawal_address,
            withdrawalAmount: withdrawal_amount,
            deadline: U256::from(p.deadline),
            feeRecipient: p.fee.recipient,
            feeAmount: p.fee.amount,
        };
        let needs_authorization = !p.inputs.is_empty()
            && !(withdrawal_address == wallet.owner
                && withdrawal_amount == available
                && p.outputs.is_empty()
                && p.funding.amount == U256::ZERO
                && p.fee.amount == U256::ZERO);
        self.chain.canonical(&anchor)?;
        Ok(PreparedTransaction {
            wallet: wallet.clone(),
            context,
            token: p.token,
            anchor,
            plan: Plan::Transfer {
                params,
                inputs: p.inputs,
                outputs: p.outputs,
                funding: p.funding,
                capacity: c,
            },
            phase: Phase::Prepared,
            authorization: None,
            proof: None,
            needs_authorization,
            target: "evm".into(),
            provenance: self.provenance.clone(),
            provenance_data: None,
            provenance_packet: Default::default(),
            broadcaster: None,
            reprice: Some(template),
        })
    }
}
fn hash_deliveries(deliveries: &[abi::Delivery]) -> B256 {
    keccak256((deliveries.to_vec(),).abi_encode_params())
}
fn split(h: B256) -> [U256; 2] {
    [
        U256::from_be_slice(&h.as_slice()[..16]),
        U256::from_be_slice(&h.as_slice()[16..]),
    ]
}
fn authorization_params(
    context: ProtocolContext,
    operation: &str,
    capacity: usize,
    words: &[U256],
) -> Value {
    json!({"operation":operation,"capacity":capacity,"context":context_value(context),"words":words.iter().map(U256::to_string).collect::<Vec<_>>()})
}
pub(crate) fn wallet_authorization_request(
    context: ProtocolContext,
    operation: &str,
    capacity: usize,
    words: &[U256],
) -> Result<EvmSigningRequest> {
    let digest = B256::from(crate::wallet::authorization_digest(&authorization_params(
        context, operation, capacity, words,
    ))?);
    let name = match operation {
        "transact" => "Invisi.Transact.v1",
        "create-credit" => "Invisi.CreateCredit.v4",
        "credit-draw" => "Invisi.CreditDraw.v4",
        "update-credit" => "Invisi.UpdateCredit.v4",
        _ => return Err("unsupported wallet authorization operation".into()),
    };
    let statement_hash = keccak256((U256::from(capacity), words.to_vec()).abi_encode_params());
    Ok(EvmSigningRequest {
        digest,
        typed_data: typed_data(
            context,
            "WalletAuthorization",
            json!([{"name":"operation","type":"bytes32"},{"name":"statementHash","type":"bytes32"}]),
            json!({"operation":keccak256(name),"statementHash":statement_hash}),
        ),
    })
}
pub(crate) fn accept_wallet_signature(
    owner: Address,
    request: &EvmSigningRequest,
    signature: &[u8],
) -> Result<WalletAuthorization> {
    if !verify_eoa_signature(owner, request.digest, signature) {
        return Err(
            "wallet authorization signature does not match owner or frozen statement".into(),
        );
    }
    let mut raw = signature.to_vec();
    if raw.len() == 64 {
        let parity = raw[32] >> 7;
        raw[32] &= 0x7f;
        raw.push(parity)
    }
    let parity = if raw[64] >= 27 { raw[64] - 27 } else { raw[64] };
    let id = k256::ecdsa::RecoveryId::try_from(parity).map_err(|_| "invalid wallet recovery ID")?;
    let sig = Signature::from_slice(&raw[..64]).map_err(|_| "invalid wallet signature")?;
    let key = VerifyingKey::recover_from_prehash(request.digest.as_slice(), &sig, id)
        .map_err(|_| "wallet signature recovery failed")?;
    Ok(WalletAuthorization {
        digest: request.digest,
        signature: raw[..64]
            .try_into()
            .map_err(|_| "invalid signature length")?,
        spending_public_key: key
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .map_err(|_| "invalid public key length")?,
    })
}

fn auth_words(
    context: ProtocolContext,
    operation: &str,
    capacity: usize,
    mut words: Vec<U256>,
) -> Result<Vec<U256>> {
    let digest = B256::from(crate::wallet::authorization_digest(&authorization_params(
        context, operation, capacity, &words,
    ))?);
    words.extend(split(digest));
    Ok(words)
}
impl PreparedTransaction {
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn needs_authorization(&self) -> bool {
        self.needs_authorization
    }
    pub fn wallet(&self) -> &Wallet {
        &self.wallet
    }
    pub fn anchor(&self) -> &CanonicalBlock {
        &self.anchor
    }
    pub(crate) fn inputs(&self) -> &[NoteInput] {
        match &self.plan {
            Plan::Transfer { inputs, .. } => inputs,
            _ => &[],
        }
    }
    pub fn outputs(&self) -> &[NoteOutput] {
        match &self.plan {
            Plan::Shield { outputs, .. } | Plan::Transfer { outputs, .. } => outputs,
        }
    }
    pub fn public_inputs(&self) -> Result<Vec<U256>> {
        match &self.plan {
            Plan::Shield { .. } => Err("shield has no proof statement".into()),
            Plan::Transfer {
                params,
                outputs,
                funding,
                capacity,
                ..
            } => {
                let c = *capacity;
                let mut words = vec![
                    U256::from(self.context.chain_id),
                    self.context.protocol_address,
                    address_word(params.token),
                    U256::from(params.nullifiers.len()),
                    U256::from(params.noteCommitments.len()),
                    U256::from(params.sources.len()),
                ];
                let mut ids = vec![U256::ZERO; c];
                let mut roots = vec![U256::ZERO; c];
                for (i, s) in params.sources.iter().enumerate() {
                    ids[i] = s.treeId;
                    roots[i] = U256::from_be_slice(s.merkleRoot.as_slice());
                }
                words.extend(ids);
                words.extend(roots);
                let mut slots = vec![U256::ZERO; c];
                for (i, v) in params
                    .nullifiers
                    .iter()
                    .chain(&params.noteCommitments)
                    .enumerate()
                {
                    slots[i] = U256::from_be_slice(v.as_slice());
                }
                words.extend(slots);
                words.extend(split(hash_deliveries(
                    &outputs
                        .iter()
                        .map(|o| o.delivery.clone())
                        .collect::<Vec<_>>(),
                )));
                words.extend([
                    address_word(params.withdrawalAddress),
                    params.withdrawalAmount,
                    params.deadline,
                    funding.amount,
                    address_word(funding.payer),
                    address_word(params.feeRecipient),
                    params.feeAmount,
                ]);
                auth_words(self.context, "transact", c, words)
            }
        }
    }
    pub fn export_wallet_authorization(&self) -> Result<EvmSigningRequest> {
        if !self.needs_authorization || ![Phase::Prepared, Phase::Authorized].contains(&self.phase)
        {
            return Err("operation is not awaiting wallet authorization".into());
        }
        let Plan::Transfer { capacity, .. } = &self.plan else {
            return Err("no wallet authorization".into());
        };
        let words = self.public_inputs()?;
        wallet_authorization_request(
            self.context,
            "transact",
            *capacity,
            &words[..words.len() - 2],
        )
    }
    pub fn with_wallet_signature(mut self, signature: &[u8]) -> Result<Self> {
        self.authorization = Some(accept_wallet_signature(
            self.wallet.owner,
            &self.export_wallet_authorization()?,
            signature,
        )?);
        self.phase = Phase::Authorized;
        Ok(self)
    }
    pub fn export_wallet_request(&self, id: impl Into<String>) -> Result<WalletRequest> {
        if !self.needs_authorization || ![Phase::Prepared, Phase::Authorized].contains(&self.phase)
        {
            return Err("operation is not awaiting wallet authorization".into());
        }
        let words = self.public_inputs()?;
        let c = match self.plan {
            Plan::Transfer { capacity, .. } => capacity,
            _ => return Err("no wallet authorization".into()),
        };
        self.wallet.prepare_request(
            id,
            "wallet.authorize",
            authorization_params(self.context, "transact", c, &words[..words.len() - 2]),
        )
    }
    pub fn with_wallet_response(mut self, q: &WalletRequest, r: &WalletResponse) -> Result<Self> {
        let current = self.export_wallet_request(q.id.clone())?;
        if current.params != q.params {
            return Err("wallet response differs from frozen statement".into());
        }
        match self.wallet.accept_response(q, r)? {
            WalletResult::Authorized(auth) => self.authorization = Some(auth),
            _ => return Err("wallet authorization response required".into()),
        }
        self.phase = Phase::Authorized;
        Ok(self)
    }
    pub fn prove(mut self, backend: &dyn Prover, recursive: bool) -> Result<Self> {
        if ![Phase::Prepared, Phase::Authorized].contains(&self.phase)
            || self.needs_authorization && self.authorization.is_none()
        {
            return Err("authorize prepared operation before proving".into());
        }
        let Plan::Transfer {
            params,
            inputs,
            outputs,
            capacity,
            ..
        } = &self.plan
        else {
            return Err("shield uses ready without a proof".into());
        };
        if recursive && *capacity > 10 {
            return Err("recursive execution requires native C1..C10".into());
        }
        let c = *capacity;
        let mut private = json!({"input_owner_address":inputs.first().map(|i|i.note.owner_address.to_string()).unwrap_or_else(||"0".into()),"public_key_x":vec![0u8;32],"public_key_y":vec![0u8;32],"signature":vec![0u8;64]});
        if let Some(a) = &self.authorization {
            private["public_key_x"] = json!(a.spending_public_key[1..33].to_vec());
            private["public_key_y"] = json!(a.spending_public_key[33..].to_vec());
            private["signature"] = json!(a.signature.to_vec());
        }
        let mut identities = vec!["0".to_string(); c];
        let mut amounts = identities.clone();
        let mut nonces = identities.clone();
        let mut indices = identities.clone();
        let mut source_indices = identities.clone();
        let mut paths = vec![vec!["0".to_string(); 16]; c];
        for (i, input) in inputs.iter().enumerate() {
            amounts[i] = input.note.amount.to_string();
            nonces[i] = input.note.nonce.to_string();
            indices[i] = input.leaf_index.to_string();
            source_indices[i] = params
                .sources
                .iter()
                .position(|s| s.treeId == U256::from(input.tree_id))
                .ok_or("input source missing")?
                .to_string();
            paths[i] = input.path.iter().map(U256::to_string).collect();
        }
        for (i, out) in outputs.iter().enumerate() {
            identities[inputs.len() + i] = out.identity.to_string();
            amounts[inputs.len() + i] = out.amount.to_string();
        }
        private["output_identities"] = json!(identities);
        private["amounts"] = json!(amounts);
        private["nonces"] = json!(nonces);
        private["leaf_indices"] = json!(indices);
        private["input_source_indices"] = json!(source_indices);
        private["merkle_paths"] = json!(paths);
        self.target = if recursive { "noir-recursive" } else { "evm" }.into();
        let inputs = self.public_inputs()?.into_iter().map(field_word).collect();
        let request = prover::request(
            &format!("transact_user_slots{c}"),
            &self.target,
            private,
            inputs,
        )?;
        let bundle = backend.prove(&request)?;
        prover::assert_bundle(&bundle, &request.statement)?;
        if !backend.verify(&bundle, &request.statement)? {
            return Err("independent proof verification failed".into());
        }
        self.proof = Some(bundle);
        self.authorization = None;
        self.phase = Phase::Proved;
        Ok(self)
    }
    pub fn ready(mut self) -> Result<Self> {
        if !matches!(self.plan, Plan::Shield { .. }) || self.phase != Phase::Prepared {
            return Err("ready requires a prepared shield".into());
        }
        self.phase = Phase::Ready;
        Ok(self)
    }
    pub fn proof(&self) -> Option<&ProofBundle> {
        self.proof.as_ref()
    }
    pub fn calldata(&self, chain: &dyn ChainState, caller: Address) -> Result<TransactionCall> {
        let anchor = chain.snapshot()?;
        if chain.context() != self.context {
            return Err("submission deployment mismatch".into());
        }
        chain.canonical(&self.anchor)?;
        for input in self.inputs() {
            if !chain.known_root(input.tree_id, field_word(input.root), &anchor)?
                || chain.nullifier_spent(field_word(model(input.note.nullifier())?), &anchor)?
            {
                return Err("Note input no longer spendable".into());
            }
        }
        self.validate_public_funding(chain, &anchor)?;
        let contract =
            protocol::ProtocolContract::new(word_address(self.context.protocol_address)?)?;
        match &self.plan {
            Plan::Shield {
                params,
                outputs,
                funding,
            } => {
                if self.phase != Phase::Ready {
                    return Err("shield must be ready".into());
                }
                validate_submission(funding, caller, anchor.timestamp, params.deadline)?;
                Ok(contract.call(&InvisiProtocol::shieldCall {
                    p: params.clone(),
                    _1: outputs
                        .iter()
                        .map(|o| abi::ShieldOutput {
                            identity: field_word(o.identity),
                            amount: o.amount,
                        })
                        .collect(),
                    _2: outputs.iter().map(|o| o.delivery.clone()).collect(),
                    _3: funding.clone(),
                }))
            }
            Plan::Transfer {
                params,
                outputs,
                funding,
                ..
            } => {
                if self.phase != Phase::Proved || self.target != "evm" {
                    return Err(
                        "verified EVM proof required; recursive members require aggregate export"
                            .into(),
                    );
                }
                validate_submission(funding, caller, anchor.timestamp, params.deadline)?;
                let proof = self.proof.as_ref().ok_or("proof required")?;
                let s = prover::statement(
                    &proof.circuit_name,
                    "evm",
                    self.public_inputs()?.into_iter().map(field_word).collect(),
                )?;
                prover::assert_bundle(proof, &s)?;
                Ok(contract.call(&InvisiProtocol::transact_0Call {
                    _0: proof.proof.clone().into(),
                    r: abi::TransactRequest {
                        params: params.clone(),
                        deliveries: outputs.iter().map(|o| o.delivery.clone()).collect(),
                        funding: funding.clone(),
                    },
                }))
            }
        }
    }
}
fn validate_submission(
    f: &abi::FundingParams,
    caller: Address,
    now: u64,
    deadline: U256,
) -> Result<()> {
    validate_funding(f)?;
    if deadline < U256::from(now) {
        return Err("transaction expired".into());
    }
    if f.signature.is_empty() {
        if f.sigNonce != U256::ZERO
            || f.deadline != U256::ZERO
            || f.amount != U256::ZERO && f.payer != caller
        {
            return Err("direct funding requires payer caller and zero nonce/deadline".into());
        }
    } else if f.deadline < U256::from(now) {
        return Err("funding authorization expired".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_zero_wallet_owner() {
        assert!(Wallet::from_owner(Address::ZERO).is_err());
    }
}

impl std::fmt::Debug for NoteOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoteOutput")
            .field("commitment", &self.commitment)
            .finish_non_exhaustive()
    }
}

pub fn empty_funding() -> abi::FundingParams {
    abi::FundingParams {
        amount: U256::ZERO,
        payer: Address::ZERO,
        sigNonce: U256::ZERO,
        deadline: U256::ZERO,
        signature: Bytes::new(),
        permit: protocol::IMetaTx::TokenPermit {
            deadline: U256::ZERO,
            v: 0,
            r: B256::ZERO,
            s: B256::ZERO,
        },
    }
}
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::Mutex;
    pub struct FixtureChain {
        pub context: ProtocolContext,
        pub block: Mutex<CanonicalBlock>,
        pub spent: Mutex<BTreeSet<B256>>,
    }
    impl ChainState for FixtureChain {
        fn context(&self) -> ProtocolContext {
            self.context
        }
        fn snapshot(&self) -> Result<CanonicalBlock> {
            Ok(self.block.lock().unwrap().clone())
        }
        fn canonical(&self, b: &CanonicalBlock) -> Result<()> {
            if self.block.lock().unwrap().hash != b.hash {
                return Err("chain reorganization".into());
            }
            Ok(())
        }
        fn known_root(&self, _: u64, _: B256, _: &CanonicalBlock) -> Result<bool> {
            Ok(true)
        }
        fn nullifier_spent(&self, n: B256, _: &CanonicalBlock) -> Result<bool> {
            Ok(self.spent.lock().unwrap().contains(&n))
        }
        fn credit_revoked(
            &self,
            _: Address,
            _: Address,
            _: u64,
            _: u16,
            _: &CanonicalBlock,
        ) -> Result<bool> {
            Ok(false)
        }
        fn token_balance_allowance(
            &self,
            _: Address,
            _: Address,
            _: &CanonicalBlock,
        ) -> Result<(U256, U256)> {
            Ok((U256::MAX, U256::MAX))
        }
        fn funding_nonce(&self, _: Address, _: &CanonicalBlock) -> Result<U256> {
            Ok(U256::ZERO)
        }
        fn credit_allocation(
            &self,
            _: Address,
            _: Address,
            _: &CanonicalBlock,
        ) -> Result<(u64, u16)> {
            Ok((1, 0))
        }
    }
    pub fn note_fixture() -> (Arc<FixtureChain>, Wallet, TransferPreparation, Vec<B256>) {
        note_fixture_label("note1a")
    }
    pub fn note_fixture_label(
        label: &str,
    ) -> (Arc<FixtureChain>, Wallet, TransferPreparation, Vec<B256>) {
        let all: Value = serde_json::from_str(include_str!(
            "../assets/prover/testdata/current-proving.json"
        ))
        .unwrap();
        let f = all["fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["label"] == label)
            .unwrap();
        let w = &f["witness"];
        let d = |key: &str| decimal(&w[key]).unwrap();
        let context = ProtocolContext {
            chain_id: d("chain_id").to::<u64>(),
            protocol_address: d("protocol_address"),
        };
        let owner = word_address(d("input_owner_address")).unwrap();
        let token = word_address(d("token_address")).unwrap();
        let note = Note {
            context,
            owner_address: address_word(owner),
            token_address: address_word(token),
            amount: decimal(&w["amounts"][0]).unwrap(),
            nonce: decimal(&w["nonces"][0]).unwrap(),
            payload: Vec::new(),
        };
        let path: [U256; 16] = w["merkle_paths"][0]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| decimal(v).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let index = decimal(&w["leaf_indices"][0]).unwrap().to::<u16>();
        let root = merkle_root(note.commitment().unwrap(), index, &path).unwrap();
        let input = NoteInput {
            note,
            tree_id: decimal(&w["input_tree_ids"][0]).unwrap().to::<u64>(),
            leaf_index: index,
            path,
            root,
        };
        let chain = Arc::new(FixtureChain {
            context,
            block: Mutex::new(CanonicalBlock {
                number: 10,
                hash: B256::from([1; 32]),
                parent_hash: B256::ZERO,
                timestamp: 1,
            }),
            spent: Mutex::new(BTreeSet::new()),
        });
        let wallet = Wallet::from_owner(owner).unwrap();
        let mut outputs = Vec::new();
        for i in 0..d("output_count").to::<usize>() {
            outputs.push(
                NoteOutput::identity(
                    context,
                    token,
                    decimal(&w["output_identities"][1 + i]).unwrap(),
                    decimal(&w["amounts"][1 + i]).unwrap(),
                )
                .unwrap(),
            );
        }
        let withdrawal = if d("withdrawal_amount") == U256::ZERO {
            None
        } else {
            Some((
                word_address(d("withdrawal_address")).unwrap(),
                d("withdrawal_amount"),
            ))
        };
        let p = TransferPreparation {
            token,
            inputs: vec![input],
            outputs,
            withdrawal,
            funding: empty_funding(),
            fee: Fee::default(),
            deadline: d("deadline").to::<u64>(),
            automatic_change: false,
        };
        let expected = serde_json::from_value(f["publicInputs"].clone()).unwrap();
        (chain, wallet, p, expected)
    }
}
#[cfg(test)]
mod statement_tests {
    use super::*;
    #[test]
    fn c1_public_statement_matches_independent_protocol_fixture() {
        let (chain, wallet, p, expected) = test_support::note_fixture();
        let prepared = Invisi::new(chain).prepare_transfer(&wallet, p).unwrap();
        assert!(!prepared.needs_authorization());
        assert_eq!(
            prepared
                .public_inputs()
                .unwrap()
                .into_iter()
                .map(field_word)
                .collect::<Vec<_>>(),
            expected
        );
    }
    #[test]
    fn rejects_duplicate_note_inputs() {
        let (chain, wallet, mut p, _) = test_support::note_fixture();
        p.inputs.push(p.inputs[0].clone());
        assert!(Invisi::new(chain).prepare_transfer(&wallet, p).is_err());
    }
}

pub mod credit;
pub use credit::*;

pub fn verify_eoa_signature(owner: Address, digest: B256, signature: &[u8]) -> bool {
    let mut raw = signature.to_vec();
    if raw.len() == 64 {
        let parity = raw[32] >> 7;
        raw[32] &= 0x7f;
        raw.push(parity);
    }
    if raw.len() != 65 {
        return false;
    }
    let parity = if raw[64] >= 27 { raw[64] - 27 } else { raw[64] };
    let Ok(id) = k256::ecdsa::RecoveryId::try_from(parity) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(&raw[..64]) else {
        return false;
    };
    if sig.normalize_s().is_some() {
        return false;
    }
    let Ok(key) = VerifyingKey::recover_from_prehash(digest.as_slice(), &sig, id) else {
        return false;
    };
    let public = key.to_encoded_point(false);
    &keccak256(&public.as_bytes()[1..]).as_slice()[12..] == owner.as_slice()
}
impl NoteOutput {
    pub(crate) fn restore(
        context: ProtocolContext,
        token: Address,
        identity: U256,
        amount: U256,
        commitment: B256,
        note: Option<Note>,
        delivery: abi::Delivery,
    ) -> Result<Self> {
        model(context.validate())?;
        if identity == U256::ZERO
            || field_word(model(crate::note::compute_note_commitment(
                context.chain_id,
                context.protocol_address,
                identity,
                address_word(token),
                amount,
            ))?) != commitment
        {
            return Err("saved output commitment mismatch".into());
        }
        if let Some(note) = &note {
            if note.context != context
                || note.token_address != address_word(token)
                || model(note.identity())? != identity
                || note.amount != amount
                || field_word(model(note.commitment())?) != commitment
            {
                return Err("saved output opening mismatch".into());
            }
        }
        if delivery.ciphertext.is_empty() {
            if !delivery.clue.is_empty() {
                return Err("omitted envelope cannot retain clue".into());
            }
        } else {
            if note.is_none() || delivery.clue.len() != 68 || delivery.clue[64] != 24 {
                return Err("invalid saved Note delivery".into());
            }
            model(crate::delivery::validate_envelope(
                &delivery.ciphertext,
                false,
            ))?;
        }
        Ok(Self {
            context,
            token,
            identity,
            amount,
            commitment,
            note,
            delivery,
        })
    }
}

#[cfg(test)]
mod wallet_wire_tests {
    use super::*;
    #[test]
    fn accepts_all_five_shared_native_wire_results() {
        let f: Value =
            serde_json::from_str(include_str!("../tests/fixtures/wallet-wire-vectors.json"))
                .unwrap();
        let cases = f["cases"].as_array().unwrap();
        let q: WalletRequest = serde_json::from_value(cases[0]["request"].clone()).unwrap();
        let r: WalletResponse = serde_json::from_value(cases[0]["response"].clone()).unwrap();
        let wallet = Wallet::from_response(&q, &r).unwrap();
        for c in cases {
            let q: WalletRequest = serde_json::from_value(c["request"].clone()).unwrap();
            let r: WalletResponse = serde_json::from_value(c["response"].clone()).unwrap();
            assert!(wallet.accept_response(&q, &r).is_ok(), "{}", q.method);
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmSigningRequest {
    pub typed_data: Value,
    pub digest: B256,
}
pub(crate) fn eip712_domain(context: ProtocolContext) -> B256 {
    keccak256((keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),keccak256("InvisibleProtocol"),keccak256("1"),U256::from(context.chain_id),word_address(context.protocol_address).expect("validated protocol context")).abi_encode())
}
pub(crate) fn eip712_digest(context: ProtocolContext, structure: B256) -> B256 {
    let mut bytes = vec![0x19, 0x01];
    bytes.extend_from_slice(eip712_domain(context).as_slice());
    bytes.extend_from_slice(structure.as_slice());
    keccak256(bytes)
}
pub(crate) fn typed_data(
    context: ProtocolContext,
    primary: &str,
    fields: Value,
    message: Value,
) -> Value {
    let mut types = json!({"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}]});
    types[primary] = fields;
    json!({"types":types,"primaryType":primary,"domain":{"name":"InvisibleProtocol","version":"1","chainId":context.chain_id.to_string(),"verifyingContract":hex(&context.protocol_address.to_be_bytes::<32>()[12..])},"message":message})
}
pub fn shield_funding_request_hash(
    params: &abi::ShieldParams,
    outputs: &[abi::ShieldOutput],
    deliveries: &[abi::Delivery],
) -> B256 {
    let outputs_hash = keccak256((outputs.to_vec(),).abi_encode_params());
    keccak256(
        (
            keccak256("InvisiShield"),
            params.clone(),
            outputs_hash,
            hash_deliveries(deliveries),
        )
            .abi_encode_params(),
    )
}
pub fn transact_funding_request_hash(
    proof: &[u8],
    params: &abi::CrossTreeTransactParams,
    deliveries: &[abi::Delivery],
) -> B256 {
    if params.sources.len() > 1 {
        return keccak256(
            (
                keccak256("InvisiCrossTreeTransact"),
                keccak256(proof),
                params.clone(),
                hash_deliveries(deliveries),
            )
                .abi_encode_params(),
        );
    }
    let (root, tree) = params
        .sources
        .first()
        .map(|s| (s.merkleRoot, s.treeId))
        .unwrap_or((B256::ZERO, U256::ZERO));
    let single = (
        params.token,
        root,
        params.nullifiers.clone(),
        params.noteCommitments.clone(),
        tree,
        params.withdrawalAddress,
        params.withdrawalAmount,
        params.deadline,
        params.feeRecipient,
        params.feeAmount,
    );
    keccak256((keccak256(proof), single, hash_deliveries(deliveries)).abi_encode_params())
}
fn funding_signing_request(
    context: ProtocolContext,
    primary: &str,
    request_hash: B256,
    f: &abi::FundingParams,
) -> Result<EvmSigningRequest> {
    validate_funding(f)?;
    if f.amount == U256::ZERO {
        return Err("positive funding required for authorization".into());
    }
    let hash=keccak256((keccak256(format!("{primary}(bytes32 requestHash,address payer,uint256 amount,uint256 sigNonce,uint256 deadline)")),request_hash,f.payer,f.amount,f.sigNonce,f.deadline).abi_encode());
    let data = typed_data(
        context,
        primary,
        json!([{"name":"requestHash","type":"bytes32"},{"name":"payer","type":"address"},{"name":"amount","type":"uint256"},{"name":"sigNonce","type":"uint256"},{"name":"deadline","type":"uint256"}]),
        json!({"requestHash":request_hash,"payer":hex(f.payer.as_slice()),"amount":f.amount.to_string(),"sigNonce":f.sigNonce.to_string(),"deadline":f.deadline.to_string()}),
    );
    Ok(EvmSigningRequest {
        typed_data: data,
        digest: eip712_digest(context, hash),
    })
}
impl PreparedTransaction {
    pub fn token(&self) -> Address {
        self.token
    }
    pub(crate) fn funding(&self) -> &abi::FundingParams {
        match &self.plan {
            Plan::Shield { funding, .. } | Plan::Transfer { funding, .. } => funding,
        }
    }
    fn funding_mut(&mut self) -> &mut abi::FundingParams {
        match &mut self.plan {
            Plan::Shield { funding, .. } | Plan::Transfer { funding, .. } => funding,
        }
    }
    fn funding_request_hash(&self) -> Result<(&'static str, B256)> {
        match &self.plan {
            Plan::Shield {
                params, outputs, ..
            } => Ok((
                "FundShield",
                shield_funding_request_hash(
                    params,
                    &outputs
                        .iter()
                        .map(|o| abi::ShieldOutput {
                            identity: field_word(o.identity),
                            amount: o.amount,
                        })
                        .collect::<Vec<_>>(),
                    &outputs
                        .iter()
                        .map(|o| o.delivery.clone())
                        .collect::<Vec<_>>(),
                ),
            )),
            Plan::Transfer {
                params,
                outputs,
                capacity,
                ..
            } => {
                let words = self.public_inputs()?;
                let hash = if self.target == "noir-recursive" {
                    keccak256(
                        (
                            keccak256("InvisiAtomicBatchMemberV1"),
                            U256::from(*capacity),
                            words[..words.len() - 2]
                                .iter()
                                .copied()
                                .map(field_word)
                                .collect::<Vec<_>>(),
                        )
                            .abi_encode_params(),
                    )
                } else {
                    let proof = self
                        .proof
                        .as_ref()
                        .ok_or("proof must precede funding authorization")?;
                    transact_funding_request_hash(
                        &proof.proof,
                        params,
                        &outputs
                            .iter()
                            .map(|o| o.delivery.clone())
                            .collect::<Vec<_>>(),
                    )
                };
                Ok(("FundTransact", hash))
            }
        }
    }
    pub fn with_funding_terms(mut self, chain: &dyn ChainState, deadline: u64) -> Result<Self> {
        if self.phase == Phase::Exported || self.funding().amount == U256::ZERO {
            return Err("operation has no pending public funding".into());
        }
        if self.broadcaster.is_some() {
            return Err("funding terms frozen by broadcaster quote".into());
        }
        let block = chain.snapshot()?;
        if chain.context() != self.context || deadline < block.timestamp {
            return Err("funding context or deadline mismatch".into());
        }
        let nonce = chain.funding_nonce(self.funding().payer, &block)?;
        let f = self.funding_mut();
        f.sigNonce = nonce;
        f.deadline = U256::from(deadline);
        f.signature = Bytes::new();
        chain.canonical(&block)?;
        Ok(self)
    }
    pub fn export_funding_authorization(
        &self,
        chain: &dyn ChainState,
    ) -> Result<EvmSigningRequest> {
        if !matches!(self.plan, Plan::Shield { .. }) && self.phase != Phase::Proved {
            return Err("proof must precede funding authorization".into());
        }
        let block = chain.snapshot()?;
        let f = self.funding();
        if chain.context() != self.context
            || f.deadline < U256::from(block.timestamp)
            || chain.funding_nonce(f.payer, &block)? != f.sigNonce
        {
            return Err("funding context, deadline or nonce stale".into());
        }
        let (primary, hash) = self.funding_request_hash()?;
        let request = funding_signing_request(self.context, primary, hash, f)?;
        chain.canonical(&block)?;
        Ok(request)
    }
    pub fn with_funding_signature(
        mut self,
        chain: &dyn ChainState,
        signature: Vec<u8>,
    ) -> Result<Self> {
        let request = self.export_funding_authorization(chain)?;
        let block = chain.snapshot()?;
        if signature.is_empty()
            || !chain.public_signature_valid(
                self.funding().payer,
                request.digest,
                &signature,
                &block,
            )?
        {
            return Err("public funding signature invalid".into());
        }
        self.funding_mut().signature = signature.into();
        chain.canonical(&block)?;
        Ok(self)
    }
    fn validate_public_funding(
        &self,
        chain: &dyn ChainState,
        block: &CanonicalBlock,
    ) -> Result<()> {
        let f = self.funding();
        if f.amount != U256::ZERO {
            let (balance, allowance) = chain.token_balance_allowance(f.payer, self.token, block)?;
            if balance < f.amount || allowance < f.amount && f.permit.deadline == U256::ZERO {
                return Err("ERC20 funding balance or Protocol allowance insufficient".into());
            }
            if f.permit.deadline != U256::ZERO
                && (f.permit.deadline < U256::from(block.timestamp)
                    || f.permit.r == B256::ZERO
                    || f.permit.s == B256::ZERO)
            {
                return Err("token permit malformed or expired".into());
            }
        }
        if !f.signature.is_empty() {
            let request = self.export_funding_authorization(chain)?;
            if !chain.public_signature_valid(f.payer, request.digest, &f.signature, block)? {
                return Err("public funding signature invalid".into());
            }
        }
        Ok(())
    }
    pub fn export_aggregate_member(&self) -> Result<prover::AggregateMember> {
        if self.phase != Phase::Proved || self.target != "noir-recursive" {
            return Err("verified recursive transfer required".into());
        }
        let proof = self.proof.as_ref().ok_or("recursive proof required")?;
        let expected = prover::statement(
            &proof.circuit_name,
            "noir-recursive",
            self.public_inputs()?.into_iter().map(field_word).collect(),
        )?;
        prover::assert_bundle(proof, &expected)?;
        Ok(prover::AggregateMember {
            bundle: proof.clone(),
            statement: expected,
        })
    }
}
pub struct PreparedAggregate {
    members: Vec<PreparedTransaction>,
    proof: ProofBundle,
    context: ProtocolContext,
}
impl std::fmt::Debug for PreparedAggregate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedAggregate")
            .field("members", &self.members.len())
            .finish_non_exhaustive()
    }
}
impl Invisi {
    pub fn aggregate(
        &self,
        backend: &dyn Prover,
        members: Vec<PreparedTransaction>,
    ) -> Result<PreparedAggregate> {
        if members.is_empty() || members.iter().any(|m| m.context != self.chain.context()) {
            return Err("aggregate context mismatch or no members".into());
        }
        let exports = members
            .iter()
            .map(PreparedTransaction::export_aggregate_member)
            .collect::<Result<Vec<_>>>()?;
        let proof = prover::aggregate(backend, &exports)?;
        Ok(PreparedAggregate {
            members,
            proof,
            context: self.chain.context(),
        })
    }
}
impl PreparedAggregate {
    pub fn proof(&self) -> &ProofBundle {
        &self.proof
    }
    pub fn members(&self) -> &[PreparedTransaction] {
        &self.members
    }
    pub fn calldata(&self, chain: &dyn ChainState, caller: Address) -> Result<TransactionCall> {
        let block = chain.snapshot()?;
        if chain.context() != self.context {
            return Err("aggregate deployment mismatch".into());
        }
        let mut requests = Vec::new();
        let mut nullifiers = BTreeSet::new();
        let mut commitments = BTreeSet::new();
        for member in &self.members {
            chain.canonical(&member.anchor)?;
            member.validate_public_funding(chain, &block)?;
            let Plan::Transfer {
                params,
                outputs,
                funding,
                ..
            } = &member.plan
            else {
                return Err("aggregate member must be transfer".into());
            };
            validate_submission(funding, caller, block.timestamp, params.deadline)?;
            for input in member.inputs() {
                if !chain.known_root(input.tree_id, field_word(input.root), &block)?
                    || chain.nullifier_spent(field_word(model(input.note.nullifier())?), &block)?
                {
                    return Err("aggregate input no longer spendable".into());
                }
            }
            for n in &params.nullifiers {
                if !nullifiers.insert(*n) {
                    return Err("duplicate aggregate nullifier".into());
                }
            }
            for n in &params.noteCommitments {
                if !commitments.insert(*n) {
                    return Err("duplicate aggregate output".into());
                }
            }
            requests.push(abi::TransactRequest {
                params: params.clone(),
                deliveries: outputs.iter().map(|o| o.delivery.clone()).collect(),
                funding: funding.clone(),
            });
        }
        let exports = self
            .members
            .iter()
            .map(PreparedTransaction::export_aggregate_member)
            .collect::<Result<Vec<_>>>()?;
        let capacities = exports
            .iter()
            .map(|e| {
                e.statement
                    .circuit_name
                    .strip_prefix("transact_user_slots")
                    .ok_or("invalid aggregate member")
                    .and_then(|v| v.parse::<usize>().map_err(|_| "invalid member capacity"))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let dedicated =
            capacities.iter().all(|c| *c == capacities[0]) && [1, 2, 5].contains(&capacities.len());
        let name = if dedicated {
            format!("transact_aggregate_{}_{}", capacities[0], capacities.len())
        } else {
            format!("transact_aggregate_mixed_1_5_{}", capacities.len())
        };
        if self.proof.circuit_name != name || self.proof.target != "evm" {
            return Err("aggregate proof route mismatch".into());
        }
        let expected = prover::statement(&name, "evm", self.proof.public_inputs.clone())?;
        prover::assert_bundle(&self.proof, &expected)?;
        chain.canonical(&block)?;
        Ok(
            protocol::ProtocolContract::new(word_address(self.context.protocol_address)?)?.call(
                &InvisiProtocol::transact_1Call {
                    _0: self.proof.proof.clone().into(),
                    requests,
                },
            ),
        )
    }
}

#[cfg(test)]
mod actual_witness_tests {
    use super::*;
    use std::{path::PathBuf, time::Duration};
    fn backend() -> prover::NativeProver {
        prover::NativeProver {
            bb_binary: std::env::var_os("INVISI_BB")
                .expect("explicit BB6 required")
                .into(),
            timeout: Duration::from_secs(600),
            threads: 4,
            assets: Arc::new(prover::DirectoryAssets {
                directory: std::env::var_os("INVISI_PROVER_ASSETS")
                    .expect("explicit pinned assets required")
                    .into(),
            }),
            witness_executor: Arc::new(prover::NoirCli {
                binary: PathBuf::from(
                    std::env::var_os("INVISI_NOIR_EXECUTE")
                        .expect("explicit local Noir executor required"),
                ),
                timeout: Duration::from_secs(180),
            }),
        }
    }
    #[test]
    fn c5_public_statement_matches_independent_protocol_fixture() {
        let (chain, wallet, p, expected) =
            test_support::note_fixture_label("note5_omitted_deliveries");
        let prepared = Invisi::new(chain).prepare_transfer(&wallet, p).unwrap();
        assert_eq!(
            prepared
                .public_inputs()
                .unwrap()
                .into_iter()
                .map(field_word)
                .collect::<Vec<_>>(),
            expected
        );
    }
    #[test]
    #[ignore = "requires explicit local Noir executor, BB6 and pinned assets"]
    fn real_sdk_note_witnesses_and_mixed_aggregate() {
        let backend = backend();
        let mut members = Vec::new();
        let mut shared_chain = None;
        for label in ["note1a", "note1b", "note5_omitted_deliveries"] {
            let (chain, wallet, p, expected) = test_support::note_fixture_label(label);
            let invisi = Invisi::new(chain.clone());
            let mut prepared = invisi.prepare_transfer(&wallet, p).unwrap();
            assert_eq!(
                prepared
                    .public_inputs()
                    .unwrap()
                    .into_iter()
                    .map(field_word)
                    .collect::<Vec<_>>(),
                expected
            );
            if prepared.needs_authorization() {
                let request = prepared.export_wallet_request(label).unwrap();
                let mut key = [0u8; 32];
                key[31] = 1;
                let response: WalletResponse = serde_json::from_value(
                    crate::wallet::execute(&key, &request.as_value()).unwrap(),
                )
                .unwrap();
                prepared = prepared.with_wallet_response(&request, &response).unwrap();
            }
            let prepared = prepared.prove(&backend, true).unwrap();
            assert_eq!(prepared.phase(), Phase::Proved);
            members.push(prepared);
            shared_chain = Some(chain);
        }
        let exports = members
            .iter()
            .map(PreparedTransaction::export_aggregate_member)
            .collect::<Result<Vec<_>>>()
            .unwrap();
        let dedicated = prover::aggregate(&backend, &exports[..2]).unwrap();
        assert_eq!(dedicated.circuit_name, "transact_aggregate_1_2");
        let mut members = members.into_iter();
        let first = members.next().unwrap();
        let _second = members.next().unwrap();
        let third = members.next().unwrap();
        let chain = shared_chain.unwrap();
        let aggregate = Invisi::new(chain.clone())
            .aggregate(&backend, vec![first, third])
            .unwrap();
        assert_eq!(
            aggregate.proof().circuit_name,
            "transact_aggregate_mixed_1_5_2"
        );
        let call = aggregate.calldata(&*chain, Address::ZERO).unwrap();
        assert!(matches!(
            protocol::ProtocolContract::decode_call(&call.data).unwrap(),
            InvisiProtocol::InvisiProtocolCalls::transact_1(_)
        ));
    }
}

#[cfg(test)]
mod funding_tests {
    use super::*;
    #[test]
    fn funding_hashes_and_eip712_match_current_go_protocol() {
        let all: Value = serde_json::from_str(include_str!(
            "../assets/prover/testdata/funding-hashes.json"
        ))
        .unwrap();
        let context = ProtocolContext {
            chain_id: 31337,
            protocol_address: U256::from_str_radix("1111111111111111111111111111111111111111", 16)
                .unwrap(),
        };
        for case in all["cases"].as_array().unwrap() {
            let data = hex_bytes(case["calldata"].as_str().unwrap(), None).unwrap();
            let (name, hash) = match protocol::ProtocolContract::decode_call(&data).unwrap() {
                InvisiProtocol::InvisiProtocolCalls::shield(call) => (
                    "FundShield",
                    shield_funding_request_hash(&call.p, &call._1, &call._2),
                ),
                InvisiProtocol::InvisiProtocolCalls::transact_0(call) => (
                    "FundTransact",
                    transact_funding_request_hash(&call._0, &call.r.params, &call.r.deliveries),
                ),
                _ => panic!("unsupported funding fixture"),
            };
            assert_eq!(
                format!("{hash:#x}"),
                case["expectedHash"].as_str().unwrap(),
                "{}",
                case["name"]
            );
            let mut funding = empty_funding();
            funding.amount = decimal(&case["fundingAmount"]).unwrap();
            funding.payer = case["fundingPayer"].as_str().unwrap().parse().unwrap();
            funding.sigNonce = U256::from(2);
            funding.deadline = U256::from(2000);
            let request = funding_signing_request(context, name, hash, &funding).unwrap();
            assert_eq!(
                format!("{:#x}", request.digest),
                case["fundingDigest"].as_str().unwrap(),
                "{}",
                case["name"]
            );
        }
    }
}

#[derive(Clone)]
pub struct SweepPreparation {
    pub token: Address,
    pub inputs: Vec<NoteInput>,
    pub deadline: u64,
    /// The current unsigned circuit requires zero; paid withdrawals need owner authorization.
    pub fee: Fee,
}
#[derive(Clone)]
pub struct WithdrawalPreparation {
    pub token: Address,
    pub inputs: Vec<NoteInput>,
    pub to: Address,
    pub amount: U256,
    pub fee: Fee,
    pub deadline: u64,
    pub automatic_change: bool,
}
impl Invisi {
    /// A disclosed opening permits only a full, fee-free payout to its original owner.
    pub fn prepare_sweep(&self, p: SweepPreparation) -> Result<PreparedTransaction> {
        if p.fee.amount != U256::ZERO || p.fee.recipient != Address::ZERO {
            return Err(
                "unsigned sweep requires zero fee; use an authorized withdrawal for paid routing"
                    .into(),
            );
        }
        let owner = word_address(
            p.inputs
                .first()
                .ok_or("sweep requires Note inputs")?
                .note
                .owner_address,
        )?;
        if p.inputs
            .iter()
            .any(|i| i.note.owner_address != address_word(owner))
        {
            return Err("sweep inputs must share one owner".into());
        }
        let amount = sum(p.inputs.iter().map(|i| i.note.amount))?;
        let wallet = Wallet::from_owner(owner)?;
        self.prepare_transfer(
            &wallet,
            TransferPreparation {
                token: p.token,
                inputs: p.inputs,
                outputs: Vec::new(),
                withdrawal: Some((owner, amount)),
                funding: empty_funding(),
                fee: Fee::default(),
                deadline: p.deadline,
                automatic_change: false,
            },
        )
    }
    pub fn prepare_withdrawal(
        &self,
        wallet: &Wallet,
        p: WithdrawalPreparation,
    ) -> Result<PreparedTransaction> {
        self.prepare_transfer(
            wallet,
            TransferPreparation {
                token: p.token,
                inputs: p.inputs,
                outputs: Vec::new(),
                withdrawal: Some((p.to, p.amount)),
                funding: empty_funding(),
                fee: p.fee,
                deadline: p.deadline,
                automatic_change: p.automatic_change,
            },
        )
    }
}
#[cfg(test)]
mod sweep_tests {
    use super::*;
    #[test]
    fn explicit_sweep_binds_original_owner_without_private_wallet() {
        let (chain, _wallet, p, _) = test_support::note_fixture();
        let owner = p.inputs[0].note.owner_address;
        let sweep = Invisi::new(chain)
            .prepare_sweep(SweepPreparation {
                token: p.token,
                inputs: p.inputs,
                deadline: p.deadline,
                fee: Fee::default(),
            })
            .unwrap();
        assert!(!sweep.needs_authorization());
        assert_eq!(address_word(sweep.wallet().owner_address()), owner);
        let Plan::Transfer { params, .. } = &sweep.plan else {
            panic!("not sweep")
        };
        assert_eq!(address_word(params.withdrawalAddress), owner);
        assert_eq!(params.feeAmount, U256::ZERO);
    }
    #[test]
    fn generic_transfer_cannot_spend_disclosed_other_owner() {
        let (chain, _, mut p, _) = test_support::note_fixture();
        let other = Wallet::from_owner(Address::from([9; 20])).unwrap();
        p.withdrawal = Some((other.owner_address(), p.inputs[0].note.amount));
        assert!(Invisi::new(chain).prepare_transfer(&other, p).is_err());
    }
}

#[cfg(test)]
mod sweep_fee_tests {
    use super::*;
    #[test]
    fn unsigned_sweep_rejects_any_nonzero_fee() {
        let (chain, _, p, _) = test_support::note_fixture();
        assert!(Invisi::new(chain)
            .prepare_sweep(SweepPreparation {
                token: p.token,
                inputs: p.inputs,
                deadline: p.deadline,
                fee: Fee {
                    recipient: Address::from([7; 20]),
                    amount: U256::from(1)
                }
            })
            .is_err());
    }
}

pub trait ReceivingKeyResolver {
    fn resolve(
        &self,
        owner: Address,
        context: ProtocolContext,
        lookup: crate::payment_request::AddressLookup,
    ) -> Result<ReceivingKeys>;
}
pub struct RpcReceivingKeyResolver<T: crate::rpc::RpcTransport, C: CanonicalHead> {
    pub client: crate::rpc::ProtocolRpcClient<T, C>,
}
impl<T: crate::rpc::RpcTransport, C: CanonicalHead> ReceivingKeyResolver
    for RpcReceivingKeyResolver<T, C>
{
    fn resolve(
        &self,
        owner: Address,
        context: ProtocolContext,
        lookup: crate::payment_request::AddressLookup,
    ) -> Result<ReceivingKeys> {
        if self.client.chain.chain_id().map_err(|e| e.to_string())? != context.chain_id {
            return Err("receiving lookup chain mismatch".into());
        }
        let deployment = self.client.deployment();
        if deployment.chain_id().map_err(|e| e.to_string())? != context.chain_id
            || address_word(deployment.protocol.address) != context.protocol_address
        {
            return Err("receiving lookup deployment mismatch".into());
        }
        let registry = deployment
            .registry
            .as_ref()
            .ok_or("receiving registry deployment required")?;
        let block = self.client.chain.head().map_err(|e| e.to_string())?;
        if block.number < registry.from_block
            || keccak256(
                self.client
                    .chain
                    .code_at(registry.address, Some(block.number))
                    .map_err(|e| e.to_string())?,
            ) != registry.runtime_code_hash
        {
            return Err("receiving registry runtime mismatch".into());
        }
        let call = protocol::InvisiAddressRegistry::receivingKeysOfCall {
            walletIdentity: field_word(address_word(owner)),
        };
        let raw = self
            .client
            .chain
            .call(registry.address, &call.abi_encode(), block.number)
            .map_err(|e| e.to_string())?;
        let registered =
            protocol::InvisiAddressRegistry::receivingKeysOfCall::abi_decode_returns(&raw, true)
                .map_err(|_| "invalid receiving registry response")?;
        let keys = ReceivingKeys {
            viewing_public_key: registered
                .keys
                .viewingPublicKey
                .as_ref()
                .try_into()
                .map_err(|_| "receiving keys not registered")?,
            clue_key: registered
                .keys
                .clueKey
                .as_slice()
                .try_into()
                .map_err(|_| "invalid clue key")?,
        };
        model(keys.validate())?;
        if lookup == crate::payment_request::AddressLookup::ProtocolRpc {
            let indexed = self
                .client
                .get_receiving_address(owner)
                .map_err(|e| e.to_string())?
                .ok_or("receiving keys not indexed")?;
            if indexed.viewing_public_key.as_slice() != keys.viewing_public_key
                || indexed.clue_key.as_slice() != keys.clue_key
                || indexed.nonce != registered.nonce
            {
                return Err("indexed receiving keys differ from chain registry".into());
            }
        }
        if self
            .client
            .chain
            .block(block.number)
            .map_err(|e| e.to_string())?
            .hash
            != block.hash
        {
            return Err("receiving registry canonical block changed".into());
        }
        Ok(keys)
    }
}
pub trait PaymentRequestOutputExt {
    fn prepare_output(
        &self,
        options: &crate::payment_request::ExecutionOptions,
        resolver: Option<&dyn ReceivingKeyResolver>,
    ) -> Result<NoteOutput>;
    fn assert_matches_output(&self, output: &NoteOutput) -> Result<()>;
}
impl PaymentRequestOutputExt for crate::payment_request::PaymentRequest {
    fn prepare_output(
        &self,
        options: &crate::payment_request::ExecutionOptions,
        resolver: Option<&dyn ReceivingKeyResolver>,
    ) -> Result<NoteOutput> {
        use crate::payment_request::{AddressLookup, NoteOutputRecipient};
        let q = model(crate::payment_request::apply_execution_options(
            self, options,
        ))?;
        let context = ProtocolContext {
            chain_id: q.chain_id,
            protocol_address: q.protocol_address,
        };
        let token = Address::from_slice(&q.token_address.to_be_bytes::<32>()[12..]);
        match &q.recipient {
            NoteOutputRecipient::Identity { identity } => {
                NoteOutput::identity(context, token, *identity, q.amount)
            }
            NoteOutputRecipient::Invisi {
                address,
                nonce: fixed,
            } => {
                let address = model(ReceivingAddress::parse(address))?;
                let note = Note {
                    context,
                    owner_address: address.owner_address,
                    token_address: q.token_address,
                    amount: q.amount,
                    nonce: fixed.unwrap_or_else(nonce),
                    payload: q.payload.clone().unwrap_or_default(),
                };
                NoteOutput::from_note(note, address.keys.as_ref())
            }
            NoteOutputRecipient::Evm {
                address,
                envelope,
                nonce: fixed,
                address_lookup,
            } => {
                let owner = model(ReceivingAddress::parse(address))?.owner_address;
                let keys = if *envelope {
                    Some(
                        resolver
                            .ok_or("registered receiving key resolver required")?
                            .resolve(
                                word_address(owner)?,
                                context,
                                address_lookup.unwrap_or(AddressLookup::ProtocolRpc),
                            )?,
                    )
                } else {
                    None
                };
                let note = Note {
                    context,
                    owner_address: owner,
                    token_address: q.token_address,
                    amount: q.amount,
                    nonce: fixed.unwrap_or_else(nonce),
                    payload: q.payload.clone().unwrap_or_default(),
                };
                NoteOutput::from_note(note, keys.as_ref())
            }
        }
    }
    fn assert_matches_output(&self, output: &NoteOutput) -> Result<()> {
        use crate::payment_request::NoteOutputRecipient;
        model(self.validate())?;
        if output.context.chain_id != self.chain_id
            || output.context.protocol_address != self.protocol_address
            || address_word(output.token) != self.token_address
            || output.amount != self.amount
        {
            return Err("payment request context, asset or amount mismatch".into());
        }
        match &self.recipient {
            NoteOutputRecipient::Identity { identity } => {
                if output.identity != *identity || !output.delivery.ciphertext.is_empty() {
                    return Err("identity recipient mismatch".into());
                }
            }
            NoteOutputRecipient::Invisi { address, nonce } => {
                let recipient = model(ReceivingAddress::parse(address))?;
                let note = output.note.as_ref().ok_or("receiving opening required")?;
                if note.owner_address != recipient.owner_address
                    || nonce.is_some_and(|n| n != note.nonce)
                    || output.delivery.ciphertext.is_empty()
                {
                    return Err("Invisi recipient, fixed nonce or delivery mismatch".into());
                }
            }
            NoteOutputRecipient::Evm {
                address,
                envelope,
                nonce,
                ..
            } => {
                let owner = model(ReceivingAddress::parse(address))?.owner_address;
                let note = output.note.as_ref().ok_or("receiving opening required")?;
                if note.owner_address != owner
                    || nonce.is_some_and(|n| n != note.nonce)
                    || *envelope == output.delivery.ciphertext.is_empty()
                {
                    return Err("EVM recipient, fixed nonce or delivery mismatch".into());
                }
            }
        }
        if output
            .note
            .as_ref()
            .map_or(&[][..], |n| n.payload.as_slice())
            != self.payload.as_deref().unwrap_or_default()
        {
            return Err("payment request payload mismatch".into());
        }
        Ok(())
    }
}
impl PreparedTransaction {
    /// Export final unsigned fee-bearing intent for an external registered broadcaster quote.
    pub fn broadcaster_intent(&self) -> Result<TransactionCall> {
        if self.phase != Phase::Prepared || self.target == "noir-recursive" {
            return Err("select broadcaster before authorization or proving".into());
        }
        let contract =
            protocol::ProtocolContract::new(word_address(self.context.protocol_address)?)?;
        match &self.plan {
            Plan::Shield {
                params,
                outputs,
                funding,
            } => {
                let mut funding = funding.clone();
                funding.signature = Bytes::new();
                Ok(contract.call(&InvisiProtocol::shieldCall {
                    p: params.clone(),
                    _1: outputs
                        .iter()
                        .map(|o| abi::ShieldOutput {
                            identity: field_word(o.identity),
                            amount: o.amount,
                        })
                        .collect(),
                    _2: outputs.iter().map(|o| o.delivery.clone()).collect(),
                    _3: funding,
                }))
            }
            Plan::Transfer {
                params,
                outputs,
                funding,
                ..
            } => {
                let mut funding = funding.clone();
                funding.signature = Bytes::new();
                Ok(contract.call(&InvisiProtocol::transact_0Call {
                    _0: Bytes::new(),
                    r: abi::TransactRequest {
                        params: params.clone(),
                        deliveries: outputs.iter().map(|o| o.delivery.clone()).collect(),
                        funding,
                    },
                }))
            }
        }
    }
    pub fn estimate_gas<G: crate::rpc::ChainGas>(
        &self,
        chain: &dyn ChainState,
        gas: &G,
        caller: Address,
    ) -> Result<U256> {
        let call = self.calldata(chain, caller)?;
        gas.estimate_gas(self.context.chain_id, caller, &call)
            .map_err(|e| e.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequirement {
    pub token: Address,
    pub payer: Address,
    pub amount: U256,
}
impl PreparedTransaction {
    pub fn approval_requirements(&self) -> Vec<ApprovalRequirement> {
        let f = self.funding();
        if f.amount == U256::ZERO {
            Vec::new()
        } else {
            vec![ApprovalRequirement {
                token: self.token,
                payer: f.payer,
                amount: f.amount,
            }]
        }
    }
    pub fn documented_gas_reference(
        &self,
        scenario: &str,
    ) -> Result<crate::gas::DocumentedGasReference> {
        let query = match &self.plan {
            Plan::Shield { outputs, .. } => {
                json!({"kind":"shield","noteOutputs":outputs.len(),"scenario":scenario})
            }
            Plan::Transfer {
                params,
                inputs,
                outputs,
                capacity,
                ..
            } => {
                let ciphertext_bytes = outputs
                    .iter()
                    .map(|o| o.delivery.ciphertext.len())
                    .max()
                    .unwrap_or(160);
                let clues = outputs
                    .iter()
                    .map(|o| o.delivery.clue.len())
                    .max()
                    .unwrap_or(68);
                json!({"kind":"transact","capacity":capacity,"noteInputs":inputs.len(),"noteOutputs":outputs.len(),"sourceTrees":params.sources.len(),"noteCiphertextBytes":ciphertext_bytes,"clueBytes":clues,"scenario":scenario})
            }
        };
        model(crate::gas::get_documented_gas_reference(
            query.as_object().ok_or("invalid gas shape")?,
        ))
    }
}
#[cfg(test)]
mod request_factory_tests {
    use super::*;
    #[test]
    fn ipr_output_preserves_fixed_nonce_payload_and_rejects_changes() {
        use crate::payment_request::{ExecutionOptions, NoteOutputRecipient, PaymentRequest};
        let all: Value =
            serde_json::from_str(include_str!("../tests/fixtures/wallet-wire-vectors.json"))
                .unwrap();
        let q: WalletRequest = serde_json::from_value(all["cases"][0]["request"].clone()).unwrap();
        let r: WalletResponse =
            serde_json::from_value(all["cases"][0]["response"].clone()).unwrap();
        let wallet = Wallet::from_response(&q, &r).unwrap();
        let mut request = PaymentRequest {
            chain_id: 1,
            protocol_address: U256::from(17),
            token_address: U256::from(34),
            amount: U256::from(7),
            recipient: NoteOutputRecipient::Invisi {
                address: wallet.address().unwrap(),
                nonce: Some(U256::from(123)),
            },
            payload: Some(b"invoice".to_vec()),
        };
        let output = request
            .prepare_output(&ExecutionOptions::default(), None)
            .unwrap();
        assert_eq!(output.note().unwrap().nonce, U256::from(123));
        request.assert_matches_output(&output).unwrap();
        request.amount += U256::from(1);
        assert!(request.assert_matches_output(&output).is_err());
    }
}
pub mod journal;
pub use journal::{ManagedPrepared, PreparedSnapshot};

impl NoteOutput {
    pub fn from_payment_request(
        request: &crate::payment_request::PaymentRequest,
        options: &crate::payment_request::ExecutionOptions,
        resolver: Option<&dyn ReceivingKeyResolver>,
    ) -> Result<Self> {
        request.prepare_output(options, resolver)
    }
    pub fn assert_matches_request(
        &self,
        request: &crate::payment_request::PaymentRequest,
    ) -> Result<()> {
        request.assert_matches_output(self)
    }
}
pub mod prelude {
    pub use super::{
        Fee, Invisi, NoteInput, NoteOutput, PaymentRequestOutputExt, PreparedAggregate,
        PreparedCredit, PreparedTransaction, ReceivingKeyResolver, ShieldPreparation,
        SweepPreparation, TransferPreparation, Wallet, WalletRequest, WalletResponse,
        WithdrawalPreparation,
    };
}

#[cfg(test)]
mod lookup_chain_tests {
    use super::*;
    use crate::rpc::{CanonicalChain, ContractDeployment, RpcTransport};
    struct NoTransport;
    impl RpcTransport for NoTransport {
        fn send(&self, _: &Value) -> crate::rpc::Result<Value> {
            panic!("wrong-chain lookup must not access indexed records")
        }
    }
    struct WrongChain;
    impl CanonicalChain for WrongChain {
        fn chain_id(&self) -> crate::rpc::Result<u64> {
            Ok(2)
        }
        fn block(&self, _: u64) -> crate::rpc::Result<CanonicalBlock> {
            panic!("wrong-chain lookup must stop before block reads")
        }
        fn code_at(&self, _: Address, _: Option<u64>) -> crate::rpc::Result<Vec<u8>> {
            panic!("wrong-chain lookup must stop before code reads")
        }
        fn call(&self, _: Address, _: &[u8], _: u64) -> crate::rpc::Result<Vec<u8>> {
            panic!("wrong-chain lookup must stop before registry reads")
        }
    }
    impl CanonicalHead for WrongChain {
        fn head(&self) -> crate::rpc::Result<CanonicalBlock> {
            panic!("wrong-chain lookup must stop before head reads")
        }
    }
    #[test]
    fn rejects_wrong_chain_before_receiving_key_lookup() {
        let context = ProtocolContext {
            chain_id: 1,
            protocol_address: U256::from(17),
        };
        let deployment = ProtocolDeployment {
            chain_id: "1".into(),
            protocol: ContractDeployment {
                address: word_address(context.protocol_address).unwrap(),
                runtime_code_hash: B256::from([1; 32]),
                from_block: 0,
            },
            registry: Some(ContractDeployment {
                address: Address::from([2; 20]),
                runtime_code_hash: B256::from([3; 32]),
                from_block: 0,
            }),
            broadcaster_registry: None,
        };
        let client =
            crate::rpc::ProtocolRpcClient::new(NoTransport, WrongChain, deployment).unwrap();
        let resolver = RpcReceivingKeyResolver { client };
        assert!(resolver
            .resolve(
                Address::from([4; 20]),
                context,
                crate::payment_request::AddressLookup::Chain
            )
            .is_err());
    }
}

#[cfg(test)]
mod public_funding_tests {
    use super::*;
    fn signing_key(last: u8) -> k256::ecdsa::SigningKey {
        let mut raw = [0u8; 32];
        raw[31] = last;
        k256::ecdsa::SigningKey::from_bytes((&raw).into()).unwrap()
    }
    fn signer_address(key: &k256::ecdsa::SigningKey) -> Address {
        let public = key.verifying_key().to_encoded_point(false);
        Address::from_slice(&keccak256(&public.as_bytes()[1..]).as_slice()[12..])
    }
    fn sign(key: &k256::ecdsa::SigningKey, digest: B256) -> Vec<u8> {
        let (signature, id) = key.sign_prehash_recoverable(digest.as_slice()).unwrap();
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(id.to_byte());
        bytes
    }
    #[test]
    fn shield_public_funding_keeps_payer_wallet_and_gas_caller_separate() {
        let (chain, wallet, note, _) = test_support::note_fixture();
        let payer_key = signing_key(2);
        let payer = signer_address(&payer_key);
        assert_ne!(payer, wallet.owner_address());
        let gas_caller = Address::from([9; 20]);
        let output =
            NoteOutput::identity(chain.context(), note.token, U256::from(9), U256::from(7))
                .unwrap();
        let build = || {
            let mut funding = empty_funding();
            funding.amount = U256::from(7);
            funding.payer = payer;
            funding.sigNonce = U256::from(1);
            funding.deadline = U256::from(1000);
            Invisi::new(chain.clone())
                .prepare_shield(
                    &wallet,
                    ShieldPreparation {
                        token: note.token,
                        outputs: vec![output.clone()],
                        funding,
                        fee: Fee::default(),
                        deadline: 2000,
                    },
                )
                .unwrap()
        };
        assert!(
            build().export_funding_authorization(&*chain).is_err(),
            "stale funding nonce accepted"
        );
        let prepared = build().with_funding_terms(&*chain, 1000).unwrap();
        let request = prepared.export_funding_authorization(&*chain).unwrap();
        let foreign = sign(&signing_key(3), request.digest);
        assert!(
            build()
                .with_funding_terms(&*chain, 1000)
                .unwrap()
                .with_funding_signature(&*chain, foreign)
                .is_err(),
            "foreign payer signature accepted"
        );
        let signature = sign(&payer_key, request.digest);
        let ready = prepared
            .with_funding_signature(&*chain, signature.clone())
            .unwrap()
            .ready()
            .unwrap();
        let call = ready.calldata(&*chain, gas_caller).unwrap();
        let InvisiProtocol::InvisiProtocolCalls::shield(decoded) =
            protocol::ProtocolContract::decode_call(&call.data).unwrap()
        else {
            panic!("not shield")
        };
        assert_eq!(decoded._3.payer, payer);
        assert_eq!(decoded._3.signature.as_ref(), signature);
        assert_eq!(decoded._3.amount, U256::from(7));
    }
}

pub mod prepared_broadcaster;
pub use prepared_broadcaster::*;

mod prepared_credit_broadcaster;

#[cfg(test)]
mod conventional_wallet_signature_tests {
    use super::*;
    fn sign(scalar: u8, digest: B256) -> Vec<u8> {
        let mut bytes = [0u8; 32];
        bytes[31] = scalar;
        let key = k256::ecdsa::SigningKey::from_slice(&bytes).unwrap();
        let (signature, id) = key.sign_prehash_recoverable(digest.as_slice()).unwrap();
        let mut out = signature.to_bytes().to_vec();
        out.push(id.to_byte() + 27);
        out
    }
    #[test]
    fn direct_signature_binds_owner_and_final_note_statement() {
        let (chain, wallet, plan, _) = test_support::note_fixture_label("note5_omitted_deliveries");
        let prepared = Invisi::new(chain).prepare_transfer(&wallet, plan).unwrap();
        let request = prepared.export_wallet_authorization().unwrap();
        assert_eq!(request.typed_data["primaryType"], "WalletAuthorization");
        let signature = sign(1, request.digest);
        let wrong = sign(2, request.digest);
        assert!(accept_wallet_signature(wallet.owner, &request, &wrong).is_err());
        let (other_chain, other_wallet, other_plan, _) =
            test_support::note_fixture_label("note5_omitted_deliveries");
        let other = Invisi::new(other_chain)
            .prepare_transfer(&other_wallet, other_plan)
            .unwrap();
        assert!(other.with_wallet_signature(&wrong).is_err());
        let (changed_chain, changed_wallet, changed_plan, _) =
            test_support::note_fixture_label("note5_omitted_deliveries");
        let mut changed_prepared = Invisi::new(changed_chain)
            .prepare_transfer(&changed_wallet, changed_plan)
            .unwrap();
        let Plan::Transfer { params, .. } = &mut changed_prepared.plan else {
            panic!("transfer required")
        };
        params.feeAmount += U256::from(1);
        assert!(changed_prepared.with_wallet_signature(&signature).is_err());

        let mut changed = request.clone();
        changed.digest = keccak256("different frozen statement");
        assert!(accept_wallet_signature(wallet.owner, &changed, &signature).is_err());
        let prepared = prepared.with_wallet_signature(&signature).unwrap();
        assert_eq!(prepared.phase, Phase::Authorized);
        assert_eq!(
            prepared.authorization.as_ref().unwrap().digest,
            request.digest
        );
        let Plan::Transfer { capacity, .. } = &prepared.plan else {
            panic!("transfer required")
        };
        let words = prepared.public_inputs().unwrap();
        let statement = keccak256(
            (U256::from(*capacity), words[..words.len() - 2].to_vec()).abi_encode_params(),
        );
        assert_eq!(
            request.typed_data["message"]["statementHash"],
            serde_json::to_value(statement).unwrap()
        );
        assert_eq!(
            eip712_digest(
                prepared.context,
                keccak256(
                    (
                        keccak256("WalletAuthorization(bytes32 operation,bytes32 statementHash)"),
                        keccak256("Invisi.Transact.v1"),
                        statement
                    )
                        .abi_encode()
                )
            ),
            request.digest
        );
    }
}

pub use crate::provenance::{ProofContext, ProvenanceProof};
pub fn validate_provenance_proof(
    packet: &ProvenanceProof,
    trust: &crate::provenance::TrustContext,
) -> Result<()> {
    invisi_sdk_rpc::provenance_packet::validate_provenance_proof(packet, trust)
}
pub fn submit_provenance_proof(
    client: &invisi_sdk_rpc::provenance_client::ProvenanceClient,
    packet: &ProvenanceProof,
) -> Result<Value> {
    invisi_sdk_rpc::provenance_packet::submit_provenance_proof(client, packet)
}
