//! Encrypted recovery for public provenance evidence, separate from wallet inventory and signing.
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use alloy_primitives::{keccak256, U256};
use invisi_sdk_protocol::provenance::{
    input_digest, parse_integer, validate_proof_bundle, ProofBundle, ProofSidecar, TrustContext,
};
use invisi_sdk_rpc::provenance_tracking::{
    preflight_tracking, tracking_from_result, STALE_TRACKING,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, String>;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenProvenanceIntent {
    pub chain_id: String,
    pub protocol_address: String,
    pub token_address: String,
    pub operation_index: String,
    pub operation_digest: String,
    pub input_nullifiers: Vec<String>,
    pub calldata: String,
    pub calldata_hash: String,
    pub signed_request_hash: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecoveryRecord {
    pub delivery_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tracking_id: Option<String>,
    pub format: String,
    pub revision: u64,
    pub id: String,
    pub intent: FrozenProvenanceIntent,
    pub manifest_sha256: String,
    pub chain_generation: String,
    pub sidecar: ProofSidecar,
    pub idempotency_key: String,
    pub state: String,
    #[serde(default)]
    pub transaction_hash: Option<String>,
    #[serde(default)]
    pub locator: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub job_id: Option<String>,
    #[serde(default)]
    pub proof_valid: bool,
    #[serde(default)]
    pub proof_job_status: Option<String>,
    #[serde(default)]
    pub source_state: Option<String>,
    #[serde(default)]
    pub reason_code: Option<String>,
    #[serde(default)]
    pub checkpoint_sequence: Option<String>,
}
#[derive(Clone)]
pub struct RecoveryCiphertext {
    pub revision: u64,
    pub data: Vec<u8>,
}
/// Host KV adapters atomically fence revisions and persist only ciphertext in a separate purpose namespace.
pub trait AtomicRecoveryRecords: Send + Sync {
    fn read(&self, key: &str) -> Result<Option<RecoveryCiphertext>>;
    fn compare_and_swap(&self, key: &str, old: u64, next: &RecoveryCiphertext) -> Result<bool>;
}
pub trait RecoveryAtomicStore: Send + Sync {
    fn load(&self, id: &str) -> Result<Option<RecoveryRecord>>;
    fn compare_and_swap(&self, id: &str, old: u64, next: &RecoveryRecord) -> Result<bool>;
}
pub struct EncryptedRecoveryStore {
    records: Arc<dyn AtomicRecoveryRecords>,
    key: Zeroizing<[u8; 32]>,
}
impl EncryptedRecoveryStore {
    pub fn new(records: Arc<dyn AtomicRecoveryRecords>, key: [u8; 32]) -> Self {
        Self {
            records,
            key: Zeroizing::new(key),
        }
    }
    fn storage_key(id: &str) -> Result<String> {
        if id.is_empty() || id.len() > 256 {
            return Err("invalid recovery id".into());
        }
        Ok(format!("Invisi.Provenance.Recovery.v1:{id}"))
    }
    fn aad(key: &str, revision: u64) -> Vec<u8> {
        format!("Invisi.Provenance.RecoveryRecord.v1\0{revision}\0{key}").into_bytes()
    }
}
impl RecoveryAtomicStore for EncryptedRecoveryStore {
    fn load(&self, id: &str) -> Result<Option<RecoveryRecord>> {
        let key = Self::storage_key(id)?;
        let Some(record) = self.records.read(&key)? else {
            return Ok(None);
        };
        if record.revision > 9007199254740991
            || record.revision == 0
            || record.data.len() < 29
            || record.data[0] != 1
        {
            return Err("invalid recovery ciphertext".into());
        }
        let cipher = Aes256Gcm::new_from_slice(&*self.key).map_err(|_| "invalid encryption key")?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&record.data[1..13]),
                    Payload {
                        msg: &record.data[13..],
                        aad: &Self::aad(&key, record.revision),
                    },
                )
                .map_err(|_| "recovery authentication failed")?,
        );
        let out: RecoveryRecord = serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
        if out.revision != record.revision {
            return Err("recovery revision mismatch".into());
        }
        Ok(Some(out))
    }
    fn compare_and_swap(&self, id: &str, old: u64, next: &RecoveryRecord) -> Result<bool> {
        if next.locator.as_ref().is_some_and(|locator| {
            locator
                .keys()
                .any(|key| !["blockHash", "txHash", "operationIndex"].contains(&key.as_str()))
        }) {
            return Err("unknown recovery locator field".into());
        }
        if old >= 9007199254740991 || old.checked_add(1) != Some(next.revision) {
            return Err("invalid next recovery revision".into());
        }
        let key = Self::storage_key(id)?;
        let plain = Zeroizing::new(serde_json::to_vec(next).map_err(|e| e.to_string())?);
        let mut nonce = [0; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new_from_slice(&*self.key).map_err(|_| "invalid encryption key")?;
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &Self::aad(&key, next.revision),
                },
            )
            .map_err(|_| "recovery encryption failed")?;
        let mut data = vec![1];
        data.extend(nonce);
        data.extend(sealed);
        self.records.compare_and_swap(
            &key,
            old,
            &RecoveryCiphertext {
                revision: next.revision,
                data,
            },
        )
    }
}
#[derive(Clone)]
pub struct RecoveryReconciliation {
    pub status: String,
    pub calldata_hash: String,
    pub signed_request_hash: String,
    pub chain_generation: String,
    pub transaction_hash: Option<String>,
    pub locator: Option<BTreeMap<String, String>>,
}
/// These capabilities authenticate frozen public transactions and verify proofs locally; private openings stay in host-encrypted storage.
pub trait RecoveryHost {
    fn verify_frozen_statement(
        &self,
        intent: &FrozenProvenanceIntent,
        sidecar: &ProofSidecar,
    ) -> Result<()>;
    fn reconcile_frozen_transaction(
        &self,
        record: &RecoveryRecord,
    ) -> Result<RecoveryReconciliation>;
    fn local_reprove(
        &self,
        _record: &RecoveryRecord,
        _generation: &str,
        _cancelled: &AtomicBool,
    ) -> Result<ProofSidecar> {
        Err("local reproof capability unavailable".into())
    }
}
pub trait RecoveryService {
    fn evaluate(&self, data: &str, sidecars: &[ProofSidecar]) -> Result<Value>;
    /// Deliver replacement evidence for an authenticated, confirmed frozen transaction.
    /// Adapters must support the historical Source path; pre-send evaluation is not a fallback.
    fn submit_source_proof(&self, _data: &str, _sidecars: &[ProofSidecar]) -> Result<Value> {
        Err("historical Source proof delivery capability unavailable".into())
    }
    fn tracking(&self, id: &str) -> Result<Value>;
    fn submit(
        &self,
        locator: &BTreeMap<String, String>,
        bundle: &ProofBundle,
        key: &str,
    ) -> Result<Value>;
    fn job(&self, id: &str) -> Result<Value>;
    fn operation_recognition(&self, locator: &BTreeMap<String, String>) -> Result<Value>;
}
impl RecoveryService for invisi_sdk_rpc::provenance_client::ProvenanceClient {
    fn evaluate(&self, data: &str, sidecars: &[ProofSidecar]) -> Result<Value> {
        self.evaluate_transaction(json!(data), sidecars)
    }
    fn submit_source_proof(&self, data: &str, sidecars: &[ProofSidecar]) -> Result<Value> {
        invisi_sdk_rpc::provenance_client::ProvenanceClient::submit_source_proof(
            self,
            json!(data),
            sidecars,
        )
    }
    fn tracking(&self, id: &str) -> Result<Value> {
        self.get_tracking(id)
    }
    fn submit(
        &self,
        locator: &BTreeMap<String, String>,
        bundle: &ProofBundle,
        key: &str,
    ) -> Result<Value> {
        self.submit_proof(json!(locator), bundle, key)
    }
    fn job(&self, id: &str) -> Result<Value> {
        self.get_proof_job(id)
    }
    fn operation_recognition(&self, locator: &BTreeMap<String, String>) -> Result<Value> {
        self.get_operation_recognition(json!(locator))
    }
}
pub fn recovery_submission_key(base: &str, sidecar: &ProofSidecar) -> Result<String> {
    if base.starts_with("internal/") {
        return Err("reserved idempotency key prefix".into());
    }
    if base.is_empty() || base.len() > 63 || !base.bytes().all(|b| (33..=126).contains(&b)) {
        return Err("invalid recovery idempotency key".into());
    }
    let value = serde_json::to_value(&sidecar.proof_bundle).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    Ok(format!("{}:{}", base, hex::encode(Sha256::digest(bytes))))
}
pub struct RecoveryCoordinator<'a> {
    pub store: &'a dyn RecoveryAtomicStore,
    pub trust: &'a TrustContext,
    pub service: &'a dyn RecoveryService,
    pub host: &'a dyn RecoveryHost,
}
fn number(v: &str, bits: usize) -> Result<U256> {
    parse_integer(v, bits).map_err(|e| e.to_string())
}
fn cancelled(flag: &AtomicBool) -> Result<()> {
    if flag.load(Ordering::SeqCst) {
        Err("local recovery cancelled; broadcast remains active".into())
    } else {
        Ok(())
    }
}
impl RecoveryCoordinator<'_> {
    fn validate(&self, r: &RecoveryRecord) -> Result<()> {
        if r.format != "invisi-provenance-recovery-v1"
            || r.id.is_empty()
            || r.idempotency_key.is_empty()
            || r.idempotency_key.len() > 63
        {
            return Err("invalid recovery record".into());
        }
        if !["tracked", "direct"].contains(&r.delivery_mode.as_str())
            || (r.revision > 0
                && r.delivery_mode == "tracked"
                && r.tracking_id.is_none()
                && r.state != "needs_reproof")
        {
            return Err("recovery tracking mode/identity missing".into());
        }
        recovery_submission_key(&r.idempotency_key, &r.sidecar)?;
        let i = &r.intent;
        let t = self.trust;
        if number(&i.chain_id, 64)? != U256::from(t.scope.chain_id)
            || number(&i.protocol_address, 160)? != t.scope.protocol_address
            || r.manifest_sha256 != t.manifest_sha256
        {
            return Err("recovery scope mismatch".into());
        }
        let bytes = hex::decode(
            i.calldata
                .strip_prefix("0x")
                .ok_or("invalid frozen calldata")?,
        )
        .map_err(|e| e.to_string())?;
        if format!("{:#x}", keccak256(bytes)) != i.calldata_hash
            || i.signed_request_hash.len() != 66
            || !i.signed_request_hash.starts_with("0x")
        {
            return Err("frozen recovery intent mismatch".into());
        }
        number(&i.signed_request_hash, 256)?;
        if number(&r.sidecar.operation_index, 32)? != number(&i.operation_index, 32)? {
            return Err("recovery operation index mismatch".into());
        }
        let p = &r.sidecar.proof_bundle.public_inputs;
        if p.len() != 11
            || number(&p[2], 160)? != number(&i.token_address, 160)?
            || ((number(&p[7], 128)? << 128) | number(&p[8], 128)?)
                != number(&i.operation_digest, 256)?
            || number(&p[6], 32)? != U256::from(i.input_nullifiers.len())
        {
            return Err("recovery statement mismatch".into());
        }

        let mut seen = std::collections::BTreeSet::new();
        for n in &i.input_nullifiers {
            if !seen.insert(number(n, 256)?) {
                return Err("duplicate recovery nullifier".into());
            }
        }
        let ns = i
            .input_nullifiers
            .iter()
            .map(|n| number(n, 256))
            .collect::<Result<Vec<_>>>()?;
        if input_digest(&ns).map_err(|e| e.to_string())? != number(&p[9], 254)? {
            return Err("recovery nullifiers digest mismatch".into());
        }
        let mut trust = self.trust.clone();
        trust.chain_generation = number(&r.chain_generation, 64)?.to::<u64>();
        validate_proof_bundle(&r.sidecar.proof_bundle, &trust).map_err(|e| e.to_string())?;
        self.host.verify_frozen_statement(i, &r.sidecar)
    }
    fn save(&self, mut record: RecoveryRecord, old: u64) -> Result<RecoveryRecord> {
        if old >= 9007199254740991 {
            return Err("recovery revision exhausted".into());
        }
        record.revision = old.checked_add(1).ok_or("recovery revision exhausted")?;
        if !self.store.compare_and_swap(&record.id, old, &record)? {
            return Err("recovery CAS conflict".into());
        }
        Ok(record)
    }
    pub fn prepare(
        &self,
        id: &str,
        intent: FrozenProvenanceIntent,
        sidecar: ProofSidecar,
        key: &str,
    ) -> Result<RecoveryRecord> {
        self.prepare_mode(id, intent, sidecar, key, "tracked")
    }
    pub fn prepare_direct(
        &self,
        id: &str,
        intent: FrozenProvenanceIntent,
        sidecar: ProofSidecar,
        key: &str,
    ) -> Result<RecoveryRecord> {
        self.prepare_mode(id, intent, sidecar, key, "direct")
    }
    fn prepare_mode(
        &self,
        id: &str,
        intent: FrozenProvenanceIntent,
        sidecar: ProofSidecar,
        key: &str,
        mode: &str,
    ) -> Result<RecoveryRecord> {
        let mut r = RecoveryRecord {
            delivery_mode: mode.into(),
            tracking_id: None,
            format: "invisi-provenance-recovery-v1".into(),
            revision: 0,
            id: id.into(),
            intent,
            manifest_sha256: self.trust.manifest_sha256.clone(),
            chain_generation: self.trust.chain_generation.to_string(),
            sidecar,
            idempotency_key: key.into(),
            state: "broadcast_possible".into(),
            transaction_hash: None,
            locator: None,
            job_id: None,
            proof_valid: false,
            proof_job_status: None,
            source_state: None,
            reason_code: None,
            checkpoint_sequence: None,
        };
        self.validate(&r)?;
        if self.store.load(id)?.is_some() {
            return Err("recovery id already exists".into());
        }
        if mode == "tracked" {
            let evaluated = self
                .service
                .evaluate(&r.intent.calldata, &[r.sidecar.clone()])?;
            r.tracking_id = Some(
                preflight_tracking(
                    &evaluated,
                    &r.intent.operation_index,
                    &r.intent.operation_digest,
                )?
                .id,
            );
        }
        self.save(r, 0)
    }
    fn required(&self, id: &str) -> Result<RecoveryRecord> {
        let r = self.store.load(id)?.ok_or("missing recovery record")?;
        if r.id != id {
            return Err("recovery id mismatch".into());
        }
        self.validate(&r)?;
        Ok(r)
    }
    pub fn mark_broadcast(&self, id: &str, tx: &str) -> Result<RecoveryRecord> {
        let mut r = self.required(id)?;
        if tx.len() != 66 || !tx.starts_with("0x") {
            return Err("invalid transaction hash".into());
        }
        number(tx, 256)?;
        if r.transaction_hash.as_ref().is_some_and(|old| old != tx) {
            return Err("frozen transaction hash mismatch".into());
        }
        r.transaction_hash = Some(tx.into());
        if r.state == "broadcast_possible" {
            r.state = "broadcast".into()
        }
        let old = r.revision;
        self.save(r, old)
    }
    pub fn resume(&self, id: &str, reprove: bool, stop: &AtomicBool) -> Result<RecoveryRecord> {
        cancelled(stop)?;
        let mut r = self.required(id)?;
        let fact = self.host.reconcile_frozen_transaction(&r)?;
        cancelled(stop)?;
        if fact.calldata_hash != r.intent.calldata_hash
            || fact.signed_request_hash != r.intent.signed_request_hash
            || (r.transaction_hash.is_some() && r.transaction_hash != fact.transaction_hash)
        {
            return Err("reconciled frozen transaction mismatch".into());
        }
        if !["unseen", "pending", "confirmed", "reorged"].contains(&fact.status.as_str()) {
            return Err("invalid reconciliation status".into());
        }
        number(&fact.chain_generation, 64)?;
        if fact.status == "confirmed" {
            let locator = fact
                .locator
                .as_ref()
                .ok_or("missing authenticated mined locator")?;
            let tx = fact
                .transaction_hash
                .as_ref()
                .ok_or("missing transaction hash")?;
            if tx.len() != 66 || !tx.starts_with("0x") {
                return Err("invalid transaction hash".into());
            }
            number(tx, 256)?;
            if locator
                .keys()
                .any(|k| !["blockHash", "txHash", "operationIndex"].contains(&k.as_str()))
                || locator.get("txHash") != Some(tx)
                || number(
                    locator
                        .get("operationIndex")
                        .ok_or("missing operation index")?,
                    32,
                )? != number(&r.intent.operation_index, 32)?
            {
                return Err("invalid authenticated locator".into());
            }
            let block = locator.get("blockHash").ok_or("missing block hash")?;
            if block.len() != 66 || !block.starts_with("0x") {
                return Err("invalid block hash".into());
            }
            number(block, 256)?;
        }
        let mut old = r.revision;
        if r.chain_generation != fact.chain_generation
            || number(&fact.chain_generation, 64)? != U256::from(self.trust.chain_generation)
            || fact.status == "reorged"
            || r.state == "needs_reproof"
            || (reprove && r.state == "proof_rejected")
        {
            r.state = "needs_reproof".into();
            r.tracking_id = None;
            r.job_id = None;
            r.locator = None;
            r.proof_valid = false;
            r.proof_job_status = None;
            r.reason_code = None;
            r.source_state = None;
            r.checkpoint_sequence = None;
            if !reprove
                || fact.status != "confirmed"
                || number(&fact.chain_generation, 64)? != U256::from(self.trust.chain_generation)
            {
                return self.save(r, old);
            }
            r.sidecar = self.host.local_reprove(&r, &fact.chain_generation, stop)?;
            cancelled(stop)?;
            r.chain_generation = fact.chain_generation.clone();
            let mut check = r.clone();
            check.revision = 0;
            self.validate(&check)?;
            if r.delivery_mode == "tracked" {
                let delivered = self
                    .service
                    .submit_source_proof(&r.intent.calldata, &[r.sidecar.clone()])?;
                let tracking = preflight_tracking(
                    &delivered,
                    &r.intent.operation_index,
                    &r.intent.operation_digest,
                )?;
                if let Some(matched) = &tracking.matched {
                    let locator = fact
                        .locator
                        .as_ref()
                        .ok_or("missing authenticated locator")?;
                    if Some(&matched.tx_hash) != fact.transaction_hash.as_ref()
                        || Some(&matched.block_hash) != locator.get("blockHash")
                        || Some(&matched.operation_index) != locator.get("operationIndex")
                    {
                        return Err("historical tracking matched another transaction".into());
                    }
                }
                r.tracking_id = Some(tracking.id);
                // Persist the accepted replacement before any fallible tracking/recognition read.
                r.state = "pending".into();
                r.transaction_hash = fact.transaction_hash.clone();
                r.locator = fact.locator.clone();
                r = self.save(r, old)?;
                old = r.revision;
            }
            r.state = "pending".into()
        }
        if fact.status == "confirmed" {
            r.transaction_hash = fact.transaction_hash.clone();
            r.locator = fact.locator.clone();
        }
        if r.delivery_mode == "tracked" {
            let id = r
                .tracking_id
                .as_deref()
                .ok_or("recovery tracking id required")?;
            let result = match self.service.tracking(id) {
                Ok(value) => value,
                Err(error) if error == STALE_TRACKING => {
                    r.state = "needs_reproof".into();
                    return self.save(r, old);
                }
                Err(error) => return Err(error),
            };
            let tracking = tracking_from_result(&result, Some(id))?;
            if number(&tracking.operation_digest, 256)? != number(&r.intent.operation_digest, 256)?
            {
                return Err("tracking statement mismatch".into());
            }
            r.reason_code = tracking.reason_code.clone();
            if ["expired", "superseded"].contains(&tracking.status.as_str()) {
                r.state = format!("tracking_{}", tracking.status);
                r.reason_code = tracking.reason_code;
                return self.save(r, old);
            }
            if fact.status != "confirmed" || tracking.status == "pending_confirmation" {
                r.state = "pending".into();
                return self.save(r, old);
            }
            let matched = tracking.matched.ok_or("tracking locator required")?;
            let locator = fact
                .locator
                .as_ref()
                .ok_or("missing authenticated locator")?;
            if Some(&matched.tx_hash) != fact.transaction_hash.as_ref()
                || Some(&matched.block_hash) != locator.get("blockHash")
                || Some(&matched.operation_index) != locator.get("operationIndex")
            {
                return Err("tracking matched another transaction".into());
            }
            if tracking.status == "pending_source" {
                r.state = "pending_source".into();
                r.source_state = Some("pending_source".into());
                r.transaction_hash = fact.transaction_hash;
                r.locator = fact.locator;
                return self.save(r, old);
            }
        }
        if fact.status != "confirmed" {
            return Ok(r);
        }
        let locator = fact.locator.ok_or("missing authenticated mined locator")?;
        if locator.is_empty() || fact.transaction_hash.is_none() {
            return Err("missing authenticated mined locator".into());
        }
        if locator
            .keys()
            .any(|k| !["blockHash", "txHash", "operationIndex"].contains(&k.as_str()))
            || locator.get("txHash") != fact.transaction_hash.as_ref()
            || number(
                locator
                    .get("operationIndex")
                    .ok_or("missing operation index")?,
                32,
            )? != number(&r.intent.operation_index, 32)?
        {
            return Err("invalid authenticated locator".into());
        }
        let block = locator.get("blockHash").ok_or("missing block hash")?;
        if block.len() != 66 || !block.starts_with("0x") {
            return Err("invalid authenticated block hash".into());
        }
        number(block, 256)?;
        r.locator = Some(locator.clone());
        r.transaction_hash = fact.transaction_hash;
        if ["recognized", "proof_rejected"].contains(&r.state.as_str()) {
            return Ok(r);
        }
        if r.delivery_mode == "direct" && r.job_id.is_none() {
            r = self.save(r, old)?;
            cancelled(stop)?;
            let response = self.service.submit(
                &locator,
                &r.sidecar.proof_bundle,
                &recovery_submission_key(&r.idempotency_key, &r.sidecar)?,
            )?;
            r.job_id = Some(
                response["jobId"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or("missing recovery job id")?
                    .into(),
            );
            r.state = "pending".into();
            let old = r.revision;
            r = self.save(r, old)?;
        }
        cancelled(stop)?;
        if r.delivery_mode == "direct" && !r.proof_valid {
            let job = self
                .service
                .job(r.job_id.as_deref().ok_or("missing job")?)?;
            let status = job["status"].as_str().ok_or("missing proof job status")?;
            r.proof_job_status = Some(status.into());
            r.reason_code = job["reasonCode"].as_str().map(str::to_owned);
            match status {
                "invalid" => r.state = "proof_rejected".into(),
                "valid" => {
                    r.proof_valid = true;
                    r.state = "pending_source".into()
                }
                "stale_generation" => r.state = "needs_reproof".into(),
                "queued" | "verifying" | "retryable_error" => r.state = "pending".into(),
                _ => return Err("unsupported proof job status".into()),
            }

            let old = r.revision;
            r = self.save(r, old)?;
        }
        if r.proof_valid || r.delivery_mode == "tracked" {
            let recognition = self.service.operation_recognition(&locator)?;
            let state = recognition["recognitionState"]
                .as_str()
                .ok_or("missing operation recognition state")?;
            let operation = &recognition["operation"];
            if operation["canonical"] != true || operation["success"] != true {
                return Err("missing canonical recognized operation".into());
            }
            for key in ["blockHash", "txHash", "operationIndex"] {
                if operation[key].as_str() != locator.get(key).map(String::as_str) {
                    return Err("recognition locator mismatch".into());
                }
            }
            for (key, expected) in [
                ("chainId", &r.intent.chain_id),
                ("protocolAddress", &r.intent.protocol_address),
                ("tokenAddress", &r.intent.token_address),
                ("operationDigest", &r.intent.operation_digest),
            ] {
                if number(
                    operation[key]
                        .as_str()
                        .ok_or("missing recognition statement")?,
                    256,
                )? != number(expected, 256)?
                {
                    return Err("recognition statement mismatch".into());
                }
            }
            let nullifiers = operation["noteNullifiers"]
                .as_array()
                .ok_or("missing recognition nullifiers")?;
            if nullifiers.len() != r.intent.input_nullifiers.len() {
                return Err("recognition nullifiers mismatch".into());
            }
            for (actual, expected) in nullifiers.iter().zip(&r.intent.input_nullifiers) {
                if number(actual.as_str().ok_or("invalid nullifier")?, 256)?
                    != number(expected, 256)?
                {
                    return Err("recognition nullifiers mismatch".into());
                }
            }
            r.source_state = Some(state.into());
            r.reason_code = recognition["recognition"]["reasonCode"]
                .as_str()
                .map(str::to_owned);
            r.checkpoint_sequence = recognition["recognition"]["checkpointSequence"]
                .as_str()
                .map(str::to_owned);
            if state == "recognized"
                && r.checkpoint_sequence.as_ref().map_or(true, |seq| {
                    number(seq, 64).map_or(true, |n| n == U256::ZERO)
                })
            {
                return Err("missing recognition checkpoint".into());
            }
            r.state = match state {
                "recognized" => "recognized",
                "source_rejected" => "source_rejected",
                _ => "pending_source",
            }
            .into();
        }
        let old = r.revision;
        self.save(r, old)
    }
    pub fn run(
        &self,
        id: &str,
        reprove: bool,
        stop: &AtomicBool,
        poll: Duration,
        max_polls: usize,
    ) -> Result<RecoveryRecord> {
        if poll.is_zero() || max_polls == 0 {
            return Err("invalid polling limits".into());
        }
        for _ in 0..max_polls {
            let r = self.resume(id, reprove, stop)?;
            if ![
                "broadcast_possible",
                "broadcast",
                "pending",
                "pending_source",
            ]
            .contains(&r.state.as_str())
            {
                return Ok(r);
            }
            let start = std::time::Instant::now();
            while start.elapsed() < poll {
                cancelled(stop)?;
                std::thread::sleep(Duration::from_millis(20).min(poll - start.elapsed().min(poll)));
            }
        }
        Err("recovery polling limit reached; resume remains available".into())
    }
}

/// Local membership filtering is independent of protocol spendability and makes no per-note requests.
pub fn filter_recognized_commitments(
    scope: &invisi_sdk_protocol::provenance::Scope,
    tree: &invisi_sdk_protocol::provenance::RecognizedTree,
    commitments: &[U256],
) -> Result<Vec<U256>> {
    let mut out = Vec::new();
    for commitment in commitments {
        if tree
            .membership_for_commitment(scope, *commitment)
            .map_err(|e| e.to_string())?
            .is_some()
        {
            out.push(*commitment)
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        sync::Mutex,
    };
    #[derive(Default)]
    struct Memory {
        values: Mutex<BTreeMap<String, RecoveryCiphertext>>,
        reject: AtomicBool,
    }
    impl AtomicRecoveryRecords for Memory {
        fn read(&self, key: &str) -> Result<Option<RecoveryCiphertext>> {
            Ok(self.values.lock().unwrap().get(key).cloned())
        }
        fn compare_and_swap(&self, key: &str, old: u64, next: &RecoveryCiphertext) -> Result<bool> {
            let mut values = self.values.lock().unwrap();
            if self.reject.load(Ordering::SeqCst)
                || values.get(key).map_or(0, |v| v.revision) != old
            {
                return Ok(false);
            }
            values.insert(key.into(), next.clone());
            Ok(true)
        }
    }
    struct Host {
        pending_first: Cell<bool>,
        intent: FrozenProvenanceIntent,
        fact: RefCell<RecoveryReconciliation>,
        next: RefCell<ProofSidecar>,
        reconciles: Cell<usize>,
    }
    impl RecoveryHost for Host {
        fn verify_frozen_statement(
            &self,
            intent: &FrozenProvenanceIntent,
            _: &ProofSidecar,
        ) -> Result<()> {
            if intent != &self.intent {
                return Err("host statement mismatch".into());
            }
            Ok(())
        }
        fn reconcile_frozen_transaction(
            &self,
            _: &RecoveryRecord,
        ) -> Result<RecoveryReconciliation> {
            self.reconciles.set(self.reconciles.get() + 1);
            let mut fact = self.fact.borrow().clone();
            if self.pending_first.replace(false) {
                fact.status = "pending".into();
            }
            Ok(fact)
        }
        fn local_reprove(
            &self,
            _: &RecoveryRecord,
            _: &str,
            _: &AtomicBool,
        ) -> Result<ProofSidecar> {
            Ok(self.next.borrow().clone())
        }
    }
    struct Service {
        job_status: RefCell<String>,
        recognition_outage: Cell<bool>,
        source_rejected: Cell<bool>,
        intent: FrozenProvenanceIntent,
        interrupt: Cell<bool>,
        submits: Cell<usize>,
        keys: RefCell<Vec<String>>,
        recognized: Cell<bool>,
    }
    impl RecoveryService for Service {
        fn evaluate(&self, _: &str, _: &[ProofSidecar]) -> Result<Value> {
            Err("direct fixture has no preflight".into())
        }
        fn tracking(&self, _: &str) -> Result<Value> {
            Err("direct fixture has no tracking".into())
        }
        fn submit(
            &self,
            _: &BTreeMap<String, String>,
            _: &ProofBundle,
            key: &str,
        ) -> Result<Value> {
            self.submits.set(self.submits.get() + 1);
            self.keys.borrow_mut().push(key.into());
            if self.interrupt.replace(false) {
                return Err("network interrupted after accepted".into());
            }
            Ok(json!({"jobId":"job1"}))
        }
        fn job(&self, _: &str) -> Result<Value> {
            Ok(json!({"status":self.job_status.borrow().clone()}))
        }
        fn operation_recognition(&self, locator: &BTreeMap<String, String>) -> Result<Value> {
            if self.recognition_outage.replace(false) {
                return Err("provider outage".into());
            }
            let mut operation = serde_json::to_value(&self.intent).unwrap();
            for (k, v) in locator {
                operation[k] = json!(v)
            }
            operation["noteNullifiers"] = json!(self.intent.input_nullifiers);
            operation["canonical"] = json!(true);
            operation["success"] = json!(true);
            Ok(
                json!({"operation":operation,"recognitionState":if self.source_rejected.get(){"source_rejected"}else if self.recognized.get(){"recognized"}else{"pending_source"},"recognition":{"reasonCode":"DEPENDENCIES_PENDING","checkpointSequence":"3"}}),
            )
        }
    }
    fn fixture() -> (
        FrozenProvenanceIntent,
        Vec<ProofSidecar>,
        TrustContext,
        Host,
        Service,
    ) {
        let v: Value =
            serde_json::from_str(include_str!("../testdata/provenance-recovery.json")).unwrap();
        let intent: FrozenProvenanceIntent = serde_json::from_value(v["intent"].clone()).unwrap();
        let sidecars: Vec<ProofSidecar> = serde_json::from_value(v["sidecars"].clone()).unwrap();
        let public: [u8; 32] =
            hex::decode(v["publicKey"].as_str().unwrap().trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap();
        let trust = TrustContext {
            scope: invisi_sdk_protocol::provenance::Scope {
                chain_id: number(&intent.chain_id, 64).unwrap().to(),
                protocol_address: number(&intent.protocol_address, 160).unwrap(),
            },
            chain_generation: 1,
            provider_id: number(v["providerId"].as_str().unwrap(), 256).unwrap(),
            signing_keys: BTreeMap::from([(
                number(v["signingKeyId"].as_str().unwrap(), 256).unwrap(),
                public,
            )]),
            signing_key_validity: BTreeMap::new(),
            manifest_sha256: v["manifestSha256"].as_str().unwrap().into(),
        };
        let tx = format!("0x{}", "ab".repeat(32));
        let host = Host {
            pending_first: Cell::new(false),
            intent: intent.clone(),
            fact: RefCell::new(RecoveryReconciliation {
                status: "confirmed".into(),
                calldata_hash: intent.calldata_hash.clone(),
                signed_request_hash: intent.signed_request_hash.clone(),
                chain_generation: "1".into(),
                transaction_hash: Some(tx.clone()),
                locator: Some(BTreeMap::from([
                    ("txHash".into(), tx),
                    ("blockHash".into(), format!("0x{}", "cd".repeat(32))),
                    ("operationIndex".into(), "0".into()),
                ])),
            }),
            next: RefCell::new(sidecars[1].clone()),
            reconciles: Cell::new(0),
        };
        let service = Service {
            job_status: RefCell::new("valid".into()),
            recognition_outage: Cell::new(false),
            source_rejected: Cell::new(false),
            intent: intent.clone(),
            interrupt: Cell::new(false),
            submits: Cell::new(0),
            keys: RefCell::new(vec![]),
            recognized: Cell::new(false),
        };
        (intent, sidecars, trust, host, service)
    }
    #[test]
    fn canonical_submission_keys_match_shared_vectors() {
        let fixture: Value =
            serde_json::from_str(include_str!("../testdata/provenance-recovery.json")).unwrap();
        let (_, sidecars, _, _, _) = self::fixture();
        for (i, sidecar) in sidecars.iter().enumerate() {
            assert_eq!(
                recovery_submission_key("stable", sidecar).unwrap(),
                fixture["submissionKeys"][i].as_str().unwrap()
            );
        }
    }
    #[test]
    fn waits_after_permit_crash_without_mark_broadcast() {
        let (intent, sidecars, trust, host, service) = fixture();
        let kv = Arc::new(Memory::default());
        let store = EncryptedRecoveryStore::new(kv, [7; 32]);
        let c = RecoveryCoordinator {
            store: &store,
            trust: &trust,
            host: &host,
            service: &service,
        };
        c.prepare_direct("possible", intent, sidecars[0].clone(), "stable")
            .unwrap();
        host.pending_first.set(true);
        service.recognized.set(true);
        let result = c
            .run(
                "possible",
                false,
                &AtomicBool::new(false),
                Duration::from_millis(1),
                2,
            )
            .unwrap();
        assert_eq!(result.state, "recognized");
        assert_eq!(host.reconciles.get(), 2);
        assert_eq!(service.submits.get(), 1);
        assert_eq!(result.transaction_hash, host.fact.borrow().transaction_hash);
    }
    #[test]
    fn idempotency_boundary_is_checked_before_broadcast_permit() {
        let (intent, sidecars, trust, host, service) = fixture();
        let store = EncryptedRecoveryStore::new(Arc::new(Memory::default()), [7; 32]);
        let c = RecoveryCoordinator {
            store: &store,
            trust: &trust,
            host: &host,
            service: &service,
        };
        let max = "a".repeat(63);
        assert_eq!(
            recovery_submission_key(&max, &sidecars[0]).unwrap().len(),
            128
        );
        let vector: Value =
            serde_json::from_str(include_str!("../testdata/provenance-recovery.json")).unwrap();
        assert_eq!(
            recovery_submission_key(&max, &sidecars[0]).unwrap(),
            vector["idempotencyLimits"]["maxBaseSubmissionKey"]
                .as_str()
                .unwrap()
        );
        c.prepare_direct("max", intent.clone(), sidecars[0].clone(), &max)
            .unwrap();
        for base in ["a".repeat(64), "a".repeat(128), "é".into(), " ".into()] {
            assert!(c
                .prepare_direct("blocked", intent.clone(), sidecars[0].clone(), &base)
                .is_err());
            assert!(store.load("blocked").unwrap().is_none());
        }
    }
    #[test]
    fn proof_valid_source_outage_and_changed_source_decision_resume() {
        let (intent, sidecars, trust, host, service) = fixture();
        let store = EncryptedRecoveryStore::new(Arc::new(Memory::default()), [7; 32]);
        let c = RecoveryCoordinator {
            store: &store,
            trust: &trust,
            host: &host,
            service: &service,
        };
        let stop = AtomicBool::new(false);
        c.prepare_direct("pending", intent, sidecars[0].clone(), "stable")
            .unwrap();
        service.recognition_outage.set(true);
        assert!(c.resume("pending", false, &stop).is_err());
        let saved = store.load("pending").unwrap().unwrap();
        assert!(saved.proof_valid);
        assert_eq!(saved.state, "pending_source");
        service.source_rejected.set(true);
        assert_eq!(
            c.resume("pending", false, &stop).unwrap().state,
            "source_rejected"
        );
        service.source_rejected.set(false);
        service.recognized.set(true);
        assert_eq!(
            c.resume("pending", false, &stop).unwrap().state,
            "recognized"
        );
        assert_eq!(service.submits.get(), 1);
    }
    #[test]
    fn same_generation_replacement_bundle_gets_new_key() {
        let (_, mut sidecars, _, _, _) = fixture();
        let old = recovery_submission_key("stable", &sidecars[0]).unwrap();
        sidecars[0].proof_bundle.proof = "0x02".into();
        assert_ne!(
            old,
            recovery_submission_key("stable", &sidecars[0]).unwrap()
        );
    }
    #[test]
    fn actual_job_wire_states_invalid_retryable_and_stale() {
        let (intent, sidecars, trust, host, service) = fixture();
        let store = EncryptedRecoveryStore::new(Arc::new(Memory::default()), [7; 32]);
        let c = RecoveryCoordinator {
            store: &store,
            trust: &trust,
            host: &host,
            service: &service,
        };
        let stop = AtomicBool::new(false);
        c.prepare_direct("invalid", intent.clone(), sidecars[0].clone(), "stable")
            .unwrap();
        *service.job_status.borrow_mut() = "invalid".into();
        assert_eq!(
            c.resume("invalid", false, &stop).unwrap().state,
            "proof_rejected"
        );
        let mut replacement = sidecars[0].clone();
        replacement.proof_bundle.proof = "0x02".into();
        *host.next.borrow_mut() = replacement;
        *service.job_status.borrow_mut() = "valid".into();
        service.recognized.set(true);
        let fixed = c.resume("invalid", true, &stop).unwrap();
        assert_eq!(fixed.state, "recognized");
        assert_eq!(fixed.intent, intent);
        assert_eq!(service.keys.borrow().len(), 2);
        assert_ne!(service.keys.borrow()[0], service.keys.borrow()[1]);
        for status in ["retryable_error", "stale_generation"] {
            c.prepare_direct(status, intent.clone(), sidecars[0].clone(), "stable")
                .unwrap();
            *service.job_status.borrow_mut() = status.into();
            let result = c.resume(status, false, &stop).unwrap();
            assert_eq!(
                result.state,
                if status == "retryable_error" {
                    "pending"
                } else {
                    "needs_reproof"
                }
            );
            assert!(!result.proof_valid);
        }
    }
    struct TrackedService<'a> {
        inner: &'a Service,
        tracking: Value,
        evaluations: Cell<usize>,
        queries: Cell<usize>,
        missing: Cell<bool>,
    }
    impl RecoveryService for TrackedService<'_> {
        fn evaluate(&self, data: &str, sidecars: &[ProofSidecar]) -> Result<Value> {
            assert_eq!(data, self.inner.intent.calldata);
            assert_eq!(sidecars.len(), 1);
            self.evaluations.set(self.evaluations.get() + 1);
            let mut result = json!({"broadcastDecision":"allow","operationDigest":self.inner.intent.operation_digest});
            if !self.missing.get() {
                result["tracking"] = self.tracking.clone()
            }
            Ok(result)
        }
        fn tracking(&self, id: &str) -> Result<Value> {
            assert_eq!(id, self.tracking["id"].as_str().unwrap());
            self.queries.set(self.queries.get() + 1);
            Ok(json!({"tracking":self.tracking}))
        }
        fn submit(&self, _: &BTreeMap<String, String>, _: &ProofBundle, _: &str) -> Result<Value> {
            panic!("tracked recovery must not submit")
        }
        fn job(&self, _: &str) -> Result<Value> {
            panic!("tracked recovery must not fetch proof job")
        }
        fn operation_recognition(&self, locator: &BTreeMap<String, String>) -> Result<Value> {
            self.inner.operation_recognition(locator)
        }
    }
    #[test]
    fn default_recovery_persists_preflight_tracking_without_direct_submission() {
        let (intent, sidecars, trust, host, service) = fixture();
        let store = EncryptedRecoveryStore::new(Arc::new(Memory::default()), [7; 32]);
        service.recognized.set(true);
        let tracking = json!({"id":"a".repeat(48),"status":"recognized","expiresAt":"1","operationDigest":format!("0x{:064x}",number(&intent.operation_digest,256).unwrap()),"matched":host.fact.borrow().locator});
        let tracked = TrackedService {
            inner: &service,
            tracking,
            evaluations: Cell::new(0),
            queries: Cell::new(0),
            missing: Cell::new(false),
        };
        let c = RecoveryCoordinator {
            store: &store,
            trust: &trust,
            host: &host,
            service: &tracked,
        };
        let prepared = c
            .prepare("tracked", intent.clone(), sidecars[0].clone(), "stable")
            .unwrap();
        assert_eq!(prepared.delivery_mode, "tracked");
        assert_eq!(
            store.load("tracked").unwrap().unwrap().tracking_id,
            Some("a".repeat(48))
        );
        let result = c
            .run(
                "tracked",
                false,
                &AtomicBool::new(false),
                Duration::from_millis(1),
                2,
            )
            .unwrap();
        assert_eq!(result.state, "recognized");
        assert_eq!(tracked.evaluations.get(), 1);
        assert_eq!(tracked.queries.get(), 1);
        assert_eq!(service.submits.get(), 0);
        tracked.missing.set(true);
        assert!(c
            .prepare("missing", intent, sidecars[0].clone(), "stable")
            .is_err());
        assert!(store.load("missing").unwrap().is_none());
    }
    #[test]
    fn terminal_tracking_cannot_return_recovery_permit() {
        for status in ["expired", "superseded"] {
            let (intent, sidecars, trust, host, service) = fixture();
            let store = EncryptedRecoveryStore::new(Arc::new(Memory::default()), [7; 32]);
            let tracked = TrackedService {
                inner: &service,
                tracking: json!({"id":"a".repeat(48),"status":status,"expiresAt":"1","operationDigest":format!("0x{:064x}",number(&intent.operation_digest,256).unwrap())}),
                evaluations: Cell::new(0),
                queries: Cell::new(0),
                missing: Cell::new(false),
            };
            let c = RecoveryCoordinator {
                store: &store,
                trust: &trust,
                host: &host,
                service: &tracked,
            };
            assert!(c
                .prepare("terminal", intent, sidecars[0].clone(), "stable")
                .is_err());
            assert!(store.load("terminal").unwrap().is_none());
            assert_eq!(service.submits.get(), 0);
        }
    }
    // Keep the real public client, signed proof fixtures and encrypted store in this
    // regression; only the Source service boundary is supplied locally.
    struct DeadlineSource {
        trust: TrustContext,
        intent: FrozenProvenanceIntent,
        locator: BTreeMap<String, String>,
        expired: bool,
        fail_tracking: AtomicBool,
        historical_failure: Option<&'static str>,
        cas_conflict: Option<(Arc<Memory>, RecoveryRecord)>,
        requests: Arc<Mutex<Vec<Value>>>,
    }
    impl invisi_sdk_rpc::rpc::RpcTransport for DeadlineSource {
        fn send(&self, q: &Value) -> invisi_sdk_rpc::rpc::Result<Value> {
            self.requests.lock().unwrap().push(q.clone());
            let method = q["method"].as_str().unwrap();
            if self.expired && method == "provenance_evaluateTransaction" {
                return Ok(
                    json!({"jsonrpc":"2.0","id":q["id"],"error":{"code":-32602,"data":{"code":"INVALID_ARGUMENT"}}}),
                );
            }
            if method == "provenance_getTracking"
                && self.fail_tracking.swap(false, Ordering::SeqCst)
            {
                return Err(invisi_sdk_rpc::rpc::Error::Invalid(
                    "fixture tracking outage",
                ));
            }
            if method == "provenance_submitSourceProof" && self.historical_failure == Some("remote")
            {
                return Ok(
                    json!({"jsonrpc":"2.0","id":q["id"],"error":{"code":-32603,"data":{"code":"UNAVAILABLE"}}}),
                );
            }
            let t = &self.trust;
            let digest = format!(
                "0x{:064x}",
                number(&self.intent.operation_digest, 256).unwrap()
            );
            let id = if t.chain_generation == 1 { "a" } else { "b" }.repeat(48);
            let mut result = json!({
                "scope":{"chainId":t.scope.chain_id.to_string(),"protocolAddress":t.scope.protocol_address.to_string()},
                "chainGeneration":t.chain_generation.to_string(),"providerId":t.provider_id.to_string(),
                "signingKeyId":t.signing_keys.keys().next().unwrap().to_string(),"manifestSha256":t.manifest_sha256
            });
            match method {
                "provenance_evaluateTransaction" | "provenance_submitSourceProof" => {
                    assert_eq!(q["params"][0]["data"], self.intent.calldata);
                    let sidecars: Vec<ProofSidecar> =
                        serde_json::from_value(q["params"][0]["proofSidecars"].clone()).unwrap();
                    assert_eq!(sidecars.len(), 1);
                    assert_eq!(
                        number(
                            &sidecars[0].proof_bundle.root_certificates[0].chain_generation,
                            64
                        )
                        .unwrap(),
                        U256::from(t.chain_generation)
                    );
                    result["broadcastDecision"] = json!("allow");
                    result["operationDigest"] = json!(digest);
                    result["tracking"] = json!({"id":id,"status":"pending_confirmation","expiresAt":"2000000000","operationDigest":digest});
                }
                "provenance_getTracking" => {
                    assert_eq!(q["params"][0]["trackingId"], id);
                    result["tracking"] = json!({"id":id,"status":"recognized","expiresAt":"2000000000","operationDigest":digest,"matched":self.locator});
                }
                "provenance_submitProof" => result["jobId"] = json!("job1"),
                "provenance_getProofJob" => result["status"] = json!("valid"),
                "provenance_getOperationRecognition" => {
                    let mut operation = serde_json::to_value(&self.intent).unwrap();
                    for (k, v) in &self.locator {
                        operation[k] = json!(v);
                    }
                    operation["noteNullifiers"] = json!(self.intent.input_nullifiers);
                    operation["canonical"] = json!(true);
                    operation["success"] = json!(true);
                    result["operation"] = operation;
                    result["recognitionState"] = json!("recognized");
                    result["recognition"] = json!({"checkpointSequence":"3"});
                }
                _ => panic!("unexpected Source call {method}"),
            }
            if method == "provenance_submitSourceProof" {
                if self.historical_failure == Some("invalid_ack") {
                    result["tracking"] = Value::Null;
                }
                if self.historical_failure == Some("wrong_matched") {
                    result["tracking"]["status"] = json!("recognized");
                    let mut mismatched = self.locator.clone();
                    mismatched.insert("txHash".into(), format!("0x{}", "ef".repeat(32)));
                    result["tracking"]["matched"] = json!(mismatched);
                }
                if let Some((records, previous)) = &self.cas_conflict {
                    let store = EncryptedRecoveryStore::new(records.clone(), [7; 32]);
                    let mut concurrent = previous.clone();
                    concurrent.revision += 1;
                    concurrent.state = "broadcast".into();
                    assert!(store
                        .compare_and_swap(&previous.id, previous.revision, &concurrent)
                        .unwrap());
                }
            }
            Ok(json!({"jsonrpc":"2.0","id":q["id"],"result":result}))
        }
    }
    fn deadline_client(
        trust: &TrustContext,
        host: &Host,
        expired: bool,
        requests: &Arc<Mutex<Vec<Value>>>,
    ) -> invisi_sdk_rpc::provenance_client::ProvenanceClient {
        invisi_sdk_rpc::provenance_client::ProvenanceClient::with_transport(
            trust.clone(),
            Arc::new(DeadlineSource {
                trust: trust.clone(),
                intent: host.intent.clone(),
                locator: host.fact.borrow().locator.clone().unwrap(),
                expired,
                fail_tracking: AtomicBool::new(false),
                historical_failure: None,
                cas_conflict: None,
                requests: requests.clone(),
            }),
        )
    }
    #[test]
    fn confirmed_tracked_reproof_uses_historical_delivery_after_native_deadline() {
        let (intent, sidecars, trust, host, _) = fixture();
        let records = Arc::new(Memory::default());
        let store = EncryptedRecoveryStore::new(records.clone(), [7; 32]);
        let requests = Arc::new(Mutex::new(vec![]));
        let initial = deadline_client(&trust, &host, false, &requests);
        let c = RecoveryCoordinator {
            store: &store,
            trust: &trust,
            host: &host,
            service: &initial,
        };
        let prepared = c
            .prepare("late", intent.clone(), sidecars[0].clone(), "stable")
            .unwrap();
        assert_eq!(prepared.tracking_id, Some("a".repeat(48)));
        c.mark_broadcast(
            "late",
            host.fact.borrow().transaction_hash.as_deref().unwrap(),
        )
        .unwrap();
        host.fact.borrow_mut().chain_generation = "2".into();
        let mut current = trust.clone();
        current.chain_generation = 2;
        let source = deadline_client(&current, &host, true, &requests);
        let restart_store = EncryptedRecoveryStore::new(records, [7; 32]);
        let restart = RecoveryCoordinator {
            store: &restart_store,
            trust: &current,
            host: &host,
            service: &source,
        };
        let result = restart
            .resume("late", true, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(result.state, "recognized");
        assert_eq!(result.tracking_id, Some("b".repeat(48)));
        assert_eq!(result.intent, intent);
        assert_eq!(result.delivery_mode, "tracked");
        assert_eq!(result.idempotency_key, "stable");
        assert_eq!(
            serde_json::to_value(&result.sidecar).unwrap(),
            serde_json::to_value(&sidecars[1]).unwrap()
        );
        assert_eq!(
            restart_store.load("late").unwrap().unwrap().state,
            "recognized"
        );
        let methods: Vec<_> = requests
            .lock()
            .unwrap()
            .iter()
            .map(|q| q["method"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            methods,
            [
                "provenance_evaluateTransaction",
                "provenance_submitSourceProof",
                "provenance_getTracking",
                "provenance_getOperationRecognition"
            ]
        );
    }
    #[test]
    fn historical_ack_survives_tracking_outage_and_encrypted_restart() {
        let (intent, sidecars, trust, host, _) = fixture();
        let records = Arc::new(Memory::default());
        let store = EncryptedRecoveryStore::new(records.clone(), [7; 32]);
        let requests = Arc::new(Mutex::new(vec![]));
        let initial = deadline_client(&trust, &host, false, &requests);
        RecoveryCoordinator {
            store: &store,
            trust: &trust,
            host: &host,
            service: &initial,
        }
        .prepare("ack", intent.clone(), sidecars[0].clone(), "stable")
        .unwrap();
        host.fact.borrow_mut().chain_generation = "2".into();
        let mut current = trust.clone();
        current.chain_generation = 2;
        let source = invisi_sdk_rpc::provenance_client::ProvenanceClient::with_transport(
            current.clone(),
            Arc::new(DeadlineSource {
                trust: current.clone(),
                intent: intent.clone(),
                locator: host.fact.borrow().locator.clone().unwrap(),
                expired: true,
                fail_tracking: AtomicBool::new(true),
                historical_failure: None,
                cas_conflict: None,
                requests: requests.clone(),
            }),
        );
        let c = RecoveryCoordinator {
            store: &store,
            trust: &current,
            host: &host,
            service: &source,
        };
        assert!(c
            .resume("ack", true, &AtomicBool::new(false))
            .unwrap_err()
            .contains("fixture tracking outage"));
        let acknowledged = store.load("ack").unwrap().unwrap();
        assert_eq!(acknowledged.state, "pending");
        assert_eq!(acknowledged.chain_generation, "2");
        assert_eq!(acknowledged.tracking_id, Some("b".repeat(48)));
        assert_eq!(acknowledged.locator, host.fact.borrow().locator);
        assert_eq!(
            acknowledged.transaction_hash,
            host.fact.borrow().transaction_hash
        );
        assert_eq!(
            serde_json::to_value(&acknowledged.sidecar).unwrap(),
            serde_json::to_value(&sidecars[1]).unwrap()
        );
        let reopened = EncryptedRecoveryStore::new(records, [7; 32]);
        let result = RecoveryCoordinator {
            store: &reopened,
            trust: &current,
            host: &host,
            service: &source,
        }
        .resume("ack", false, &AtomicBool::new(false))
        .unwrap();
        assert_eq!(result.state, "recognized");
        assert_eq!(result.intent, intent);
        assert_eq!(result.idempotency_key, "stable");
        let methods: Vec<_> = requests
            .lock()
            .unwrap()
            .iter()
            .map(|q| q["method"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            methods,
            [
                "provenance_evaluateTransaction",
                "provenance_submitSourceProof",
                "provenance_getTracking",
                "provenance_getTracking",
                "provenance_getOperationRecognition"
            ]
        );
    }
    #[test]
    fn historical_ack_cas_conflict_blocks_poll_and_preserves_concurrent_worker() {
        let (intent, sidecars, trust, host, _) = fixture();
        let records = Arc::new(Memory::default());
        let store = EncryptedRecoveryStore::new(records.clone(), [7; 32]);
        let requests = Arc::new(Mutex::new(vec![]));
        let initial = deadline_client(&trust, &host, false, &requests);
        let previous = RecoveryCoordinator {
            store: &store,
            trust: &trust,
            host: &host,
            service: &initial,
        }
        .prepare("race", intent.clone(), sidecars[0].clone(), "stable")
        .unwrap();
        host.fact.borrow_mut().chain_generation = "2".into();
        let mut current = trust.clone();
        current.chain_generation = 2;
        let source = invisi_sdk_rpc::provenance_client::ProvenanceClient::with_transport(
            current.clone(),
            Arc::new(DeadlineSource {
                trust: current.clone(),
                intent,
                locator: host.fact.borrow().locator.clone().unwrap(),
                expired: true,
                fail_tracking: AtomicBool::new(false),
                historical_failure: None,
                cas_conflict: Some((records, previous.clone())),
                requests: requests.clone(),
            }),
        );
        assert_eq!(
            RecoveryCoordinator {
                store: &store,
                trust: &current,
                host: &host,
                service: &source
            }
            .resume("race", true, &AtomicBool::new(false))
            .unwrap_err(),
            "recovery CAS conflict"
        );
        let concurrent = store.load("race").unwrap().unwrap();
        assert_eq!(concurrent.revision, previous.revision + 1);
        assert_eq!(concurrent.state, "broadcast");
        assert_eq!(concurrent.chain_generation, "1");
        assert_eq!(concurrent.tracking_id, previous.tracking_id);
        let methods: Vec<_> = requests
            .lock()
            .unwrap()
            .iter()
            .map(|q| q["method"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            methods,
            [
                "provenance_evaluateTransaction",
                "provenance_submitSourceProof"
            ]
        );
    }
    #[test]
    fn failed_historical_submission_preserves_original_encrypted_record() {
        for failure in ["remote", "invalid_ack", "wrong_matched"] {
            let (intent, sidecars, trust, host, _) = fixture();
            let records = Arc::new(Memory::default());
            let store = EncryptedRecoveryStore::new(records, [7; 32]);
            let requests = Arc::new(Mutex::new(vec![]));
            let initial = deadline_client(&trust, &host, false, &requests);
            let previous = RecoveryCoordinator {
                store: &store,
                trust: &trust,
                host: &host,
                service: &initial,
            }
            .prepare("failure", intent.clone(), sidecars[0].clone(), "stable")
            .unwrap();
            host.fact.borrow_mut().chain_generation = "2".into();
            let mut current = trust.clone();
            current.chain_generation = 2;
            let source = invisi_sdk_rpc::provenance_client::ProvenanceClient::with_transport(
                current.clone(),
                Arc::new(DeadlineSource {
                    trust: current.clone(),
                    intent,
                    locator: host.fact.borrow().locator.clone().unwrap(),
                    expired: true,
                    fail_tracking: AtomicBool::new(false),
                    historical_failure: Some(failure),
                    cas_conflict: None,
                    requests: requests.clone(),
                }),
            );
            assert!(RecoveryCoordinator {
                store: &store,
                trust: &current,
                host: &host,
                service: &source
            }
            .resume("failure", true, &AtomicBool::new(false))
            .is_err());
            assert_eq!(
                serde_json::to_value(store.load("failure").unwrap().unwrap()).unwrap(),
                serde_json::to_value(previous).unwrap()
            );
            assert_eq!(requests.lock().unwrap().len(), 2);
        }
    }
    #[test]
    fn historical_delivery_requires_confirmed_authenticated_locator() {
        for status in [
            "unseen",
            "pending",
            "reorged",
            "missing_locator",
            "missing_tx",
            "wrong_tx",
            "wrong_index",
            "bad_block",
            "extra_field",
        ] {
            let (intent, sidecars, trust, host, _) = fixture();
            let store = EncryptedRecoveryStore::new(Arc::new(Memory::default()), [7; 32]);
            let requests = Arc::new(Mutex::new(vec![]));
            let initial = deadline_client(&trust, &host, false, &requests);
            RecoveryCoordinator {
                store: &store,
                trust: &trust,
                host: &host,
                service: &initial,
            }
            .prepare("guard", intent, sidecars[0].clone(), "stable")
            .unwrap();
            host.fact.borrow_mut().chain_generation = "2".into();
            let mut current = trust.clone();
            current.chain_generation = 2;
            let source = deadline_client(&current, &host, true, &requests);
            {
                let mut fact = host.fact.borrow_mut();
                match status {
                    "unseen" | "pending" | "reorged" => fact.status = status.into(),
                    "missing_locator" => fact.locator = None,
                    "missing_tx" => fact.transaction_hash = None,
                    "wrong_tx" => {
                        fact.locator
                            .as_mut()
                            .unwrap()
                            .insert("txHash".into(), format!("0x{}", "ef".repeat(32)));
                    }
                    "wrong_index" => {
                        fact.locator
                            .as_mut()
                            .unwrap()
                            .insert("operationIndex".into(), "1".into());
                    }
                    "bad_block" => {
                        fact.locator
                            .as_mut()
                            .unwrap()
                            .insert("blockHash".into(), "0x12".into());
                    }
                    "extra_field" => {
                        fact.locator
                            .as_mut()
                            .unwrap()
                            .insert("other".into(), "value".into());
                    }
                    _ => unreachable!(),
                }
            }
            let result = RecoveryCoordinator {
                store: &store,
                trust: &current,
                host: &host,
                service: &source,
            }
            .resume("guard", true, &AtomicBool::new(false));
            if ["unseen", "pending", "reorged"].contains(&status) {
                assert_eq!(result.unwrap().state, "needs_reproof");
            } else {
                assert!(result.is_err(), "{status}");
            }
            assert_eq!(
                requests.lock().unwrap().len(),
                1,
                "no Source write for {status}"
            );
        }
    }
    #[test]
    fn expired_initial_prepare_stays_strict_and_direct_reproof_keeps_delivery_mode() {
        let (intent, sidecars, trust, host, _) = fixture();
        let store = EncryptedRecoveryStore::new(Arc::new(Memory::default()), [7; 32]);
        let requests = Arc::new(Mutex::new(vec![]));
        let initial = deadline_client(&trust, &host, true, &requests);
        let c = RecoveryCoordinator {
            store: &store,
            trust: &trust,
            host: &host,
            service: &initial,
        };
        assert!(c
            .prepare("expired", intent.clone(), sidecars[0].clone(), "stable")
            .is_err());
        assert!(store.load("expired").unwrap().is_none());
        c.prepare_direct("direct", intent.clone(), sidecars[0].clone(), "stable")
            .unwrap();
        host.fact.borrow_mut().chain_generation = "2".into();
        let mut current = trust.clone();
        current.chain_generation = 2;
        let source = deadline_client(&current, &host, true, &requests);
        let result = RecoveryCoordinator {
            store: &store,
            trust: &current,
            host: &host,
            service: &source,
        }
        .resume("direct", true, &AtomicBool::new(false))
        .unwrap();
        assert_eq!(result.state, "recognized");
        assert_eq!(result.delivery_mode, "direct");
        assert_eq!(result.intent, intent);
        assert_eq!(result.idempotency_key, "stable");
        let methods: Vec<_> = requests
            .lock()
            .unwrap()
            .iter()
            .map(|q| q["method"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            methods,
            [
                "provenance_evaluateTransaction",
                "provenance_submitProof",
                "provenance_getProofJob",
                "provenance_getOperationRecognition"
            ]
        );
    }
    #[test]
    fn reserved_idempotency_prefix_is_rejected_before_permit() {
        let (intent, sidecars, trust, host, service) = fixture();
        let store = EncryptedRecoveryStore::new(Arc::new(Memory::default()), [7; 32]);
        let c = RecoveryCoordinator {
            store: &store,
            trust: &trust,
            host: &host,
            service: &service,
        };
        assert!(c
            .prepare_direct("reserved", intent, sidecars[0].clone(), "internal/test")
            .unwrap_err()
            .contains("reserved"));
        assert!(store.load("reserved").unwrap().is_none());
    }
    #[test]
    fn reserved_idempotency_prefix_is_rejected_before_http() {
        use std::io::Write;
        use std::sync::atomic::AtomicUsize;
        let (_, sidecars, trust, _, _) = fixture();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let task = std::thread::spawn(move || {
            for _ in 0..40 {
                if let Ok((mut stream, _)) = listener.accept() {
                    observed.fetch_add(1, Ordering::SeqCst);
                    let _=stream.write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        let client =
            invisi_sdk_rpc::provenance_client::ProvenanceClient::new(&endpoint, trust).unwrap();
        let error = client
            .submit_proof(json!({}), &sidecars[0].proof_bundle, "internal/test")
            .unwrap_err();
        task.join().unwrap();
        assert!(error.contains("reserved"), "{error}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn encrypted_recovery_authentication_and_cas() {
        let (intent, sidecars, trust, host, service) = fixture();
        let kv = Arc::new(Memory::default());
        let store = EncryptedRecoveryStore::new(kv.clone(), [7; 32]);
        let c = RecoveryCoordinator {
            store: &store,
            trust: &trust,
            service: &service,
            host: &host,
        };
        let record = c
            .prepare_direct("one", intent, sidecars[0].clone(), "stable")
            .unwrap();
        assert_eq!(record.state, "broadcast_possible");
        let key = "Invisi.Provenance.Recovery.v1:one";
        let cipher = kv.values.lock().unwrap()[key].clone();
        assert!(!cipher.data.windows(6).any(|v| v == b"0x1234"));
        assert_eq!(
            store.load("one").unwrap().unwrap().intent.calldata,
            "0x1234"
        );
        assert!(!store.compare_and_swap("one", 0, &record).unwrap());
        let wrong = EncryptedRecoveryStore::new(kv.clone(), [8; 32]);
        assert!(wrong.load("one").is_err());
        kv.values
            .lock()
            .unwrap()
            .insert("Invisi.Provenance.Recovery.v1:two".into(), cipher.clone());
        assert!(store.load("two").is_err());
        kv.values.lock().unwrap().get_mut(key).unwrap().revision = 2;
        assert!(store.load("one").is_err());
    }
    #[test]
    fn restart_preserves_idempotency_and_waits_for_operation_recognition() {
        let (intent, sidecars, trust, host, service) = fixture();
        let kv = Arc::new(Memory::default());
        let store = EncryptedRecoveryStore::new(kv, [7; 32]);
        let stop = AtomicBool::new(false);
        let c = RecoveryCoordinator {
            store: &store,
            trust: &trust,
            service: &service,
            host: &host,
        };
        c.prepare_direct("send", intent.clone(), sidecars[0].clone(), "stable")
            .unwrap();
        c.mark_broadcast(
            "send",
            host.fact.borrow().transaction_hash.as_deref().unwrap(),
        )
        .unwrap();
        service.interrupt.set(true);
        assert!(c.resume("send", false, &stop).is_err());
        let restart = RecoveryCoordinator {
            store: &store,
            trust: &trust,
            service: &service,
            host: &host,
        };
        let pending = restart.resume("send", false, &stop).unwrap();
        assert_eq!(pending.state, "pending_source");
        assert!(pending.proof_valid);
        let expected = recovery_submission_key("stable", &sidecars[0]).unwrap();
        assert_eq!(*service.keys.borrow(), vec![expected.clone(), expected]);
        service.recognized.set(true);
        let recognized = restart
            .run("send", false, &stop, Duration::from_millis(1), 2)
            .unwrap();
        assert_eq!(recognized.state, "recognized");
        assert_eq!(recognized.checkpoint_sequence.as_deref(), Some("3"));
        assert_eq!(recognized.intent, intent);
        assert_eq!(service.submits.get(), 2);
    }
    #[test]
    fn cancellation_generation_reconciliation_and_statement_fences() {
        let (intent, sidecars, trust, host, service) = fixture();
        let kv = Arc::new(Memory::default());
        let store = EncryptedRecoveryStore::new(kv.clone(), [7; 32]);
        let stop = AtomicBool::new(false);
        let c = RecoveryCoordinator {
            store: &store,
            trust: &trust,
            service: &service,
            host: &host,
        };
        kv.reject.store(true, Ordering::SeqCst);
        assert!(c
            .prepare_direct("blocked", intent.clone(), sidecars[0].clone(), "stable")
            .is_err());
        assert!(store.load("blocked").unwrap().is_none());
        kv.reject.store(false, Ordering::SeqCst);
        c.prepare_direct("send", intent.clone(), sidecars[0].clone(), "stable")
            .unwrap();
        c.mark_broadcast(
            "send",
            host.fact.borrow().transaction_hash.as_deref().unwrap(),
        )
        .unwrap();
        stop.store(true, Ordering::SeqCst);
        assert!(c.resume("send", false, &stop).is_err());
        assert_eq!(store.load("send").unwrap().unwrap().state, "broadcast");
        assert_eq!(service.submits.get(), 0);
        stop.store(false, Ordering::SeqCst);
        host.fact.borrow_mut().chain_generation = "2".into();
        let old = c.resume("send", false, &stop).unwrap();
        assert_eq!(old.state, "needs_reproof");
        assert_eq!(host.reconciles.get(), 1);
        assert_eq!(service.submits.get(), 0);
        let mut next_trust = trust.clone();
        next_trust.chain_generation = 2;
        let current = RecoveryCoordinator {
            store: &store,
            trust: &next_trust,
            service: &service,
            host: &host,
        };
        host.next.borrow_mut().proof_bundle.public_inputs[2] = format!("0x{:064x}", 3);
        assert!(current.resume("send", true, &stop).is_err());
        assert_eq!(store.load("send").unwrap().unwrap().chain_generation, "1");
        assert_eq!(service.submits.get(), 0);
        *host.next.borrow_mut() = sidecars[1].clone();
        service.recognized.set(true);
        let reproved = current.resume("send", true, &stop).unwrap();
        assert_eq!(reproved.state, "recognized");
        assert_eq!(reproved.intent, intent);
        assert_eq!(
            *service.keys.borrow(),
            vec![recovery_submission_key("stable", &sidecars[1]).unwrap()]
        );
        let mut bad = intent;
        bad.operation_digest = "5".into();
        assert!(current
            .prepare_direct("bad", bad, sidecars[1].clone(), "stable")
            .is_err());
    }
}
