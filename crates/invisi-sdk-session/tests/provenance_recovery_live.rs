#![cfg(feature = "sqlite")]
use alloy_primitives::{keccak256, U256};
use invisi_sdk::{
    provenance::*,
    provenance_client::ProvenanceClient,
    rpc::{HttpTransport, RpcTransport},
};
use invisi_sdk_session::provenance_recovery::*;
use invisi_sdk_session::provenance_store::SessionRecoveryRecords;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
const LIVE_MANIFEST_SHA256: &str =
    "6107789c5c0d24c4130bff05da6d389336feb5ccb247c4030eae5198ab05d762";
fn current_source_release() -> ManifestIdentity {
    let identity = authenticate_manifest(
        include_bytes!("../testdata/source-manifest.json"),
        LIVE_MANIFEST_SHA256,
    )
    .unwrap();
    assert_eq!(identity.manifest.public_inputs, PUBLIC_INPUTS);
    assert_eq!(identity.manifest.public_inputs.len(), 11);
    assert_eq!(
        identity
            .manifest
            .circuits
            .iter()
            .map(|entry| entry.capacity)
            .collect::<Vec<_>>(),
        [10, 20, 40, 80, 120, 160, 190]
    );
    identity
}
#[test]
fn live_manifest_matches_current_packaged_release() {
    current_source_release();
}
fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap()
}
fn n(value: &str) -> U256 {
    parse_integer(value, 256).unwrap()
}
fn bytes32(value: &str) -> [u8; 32] {
    hex::decode(value.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap()
}
struct Host {
    transport: HttpTransport,
    fixture: Value,
    recovery: Value,
    intent: FrozenProvenanceIntent,
    bb: PathBuf,
    vk: PathBuf,
    calls: Cell<usize>,
    native: Cell<usize>,
}
impl Host {
    fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        self.calls.set(self.calls.get() + 1);
        let id = self.calls.get();
        let envelope = self
            .transport
            .send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .map_err(|e| e.to_string())?;
        if !envelope["error"].is_null() || envelope["id"] != id {
            return Err("primary RPC correlation/error".into());
        }
        Ok(envelope["result"].clone())
    }
    fn fact(&self) -> Result<RecoveryReconciliation, String> {
        let chain = self.rpc("eth_chainId", json!([]))?;
        if n(chain.as_str().ok_or("missing primary chain")?)
            != n(text(&self.fixture["scope"], "chainId"))
        {
            return Err("primary chain mismatch".into());
        }
        let txhash = text(&self.recovery, "transactionHash");
        let tx = self.rpc("eth_getTransactionByHash", json!([txhash]))?;
        let receipt = self.rpc("eth_getTransactionReceipt", json!([txhash]))?;
        let protocol = format!(
            "0x{:040x}",
            n(text(&self.fixture["scope"], "protocolAddress"))
        );
        if tx["hash"] != txhash
            || tx["to"].as_str().map(str::to_lowercase) != Some(protocol)
            || tx["input"] != self.recovery["calldata"]
            || receipt["transactionHash"] != txhash
            || n(receipt["status"].as_str().ok_or("missing receipt status")?) != U256::from(1)
            || receipt["blockHash"] != self.recovery["blockHash"]
        {
            return Err("primary frozen transaction/receipt mismatch".into());
        }
        let header = self.rpc(
            "eth_getBlockByNumber",
            json!([receipt["blockNumber"], false]),
        )?;
        if header["hash"] != receipt["blockHash"] || tx["blockHash"] != header["hash"] {
            return Err("primary canonical block mismatch".into());
        }
        let calldata =
            hex::decode(text(&tx, "input").trim_start_matches("0x")).map_err(|e| e.to_string())?;
        Ok(RecoveryReconciliation {
            status: "confirmed".into(),
            calldata_hash: format!("{:#x}", keccak256(calldata)),
            signed_request_hash: text(&tx, "hash").into(),
            chain_generation: text(&self.fixture, "chainGeneration").into(),
            transaction_hash: Some(text(&tx, "hash").into()),
            locator: Some(BTreeMap::from([
                ("txHash".into(), text(&tx, "hash").into()),
                ("blockHash".into(), text(&header, "hash").into()),
                (
                    "operationIndex".into(),
                    text(&self.recovery, "operationIndex").into(),
                ),
            ])),
        })
    }
    fn verify(&self, sidecar: &ProofSidecar) -> Result<(), String> {
        let directory =
            std::env::temp_dir().join(format!("invisi-recovery-bb-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).map_err(|e| e.to_string())?;
        let result = (|| {
            let proof = hex::decode(sidecar.proof_bundle.proof.trim_start_matches("0x"))
                .map_err(|e| e.to_string())?;
            std::fs::write(directory.join("proof"), proof).map_err(|e| e.to_string())?;
            let mut inputs = Vec::new();
            for p in &sidecar.proof_bundle.public_inputs {
                inputs.extend(bytes32(p));
            }
            std::fs::write(directory.join("inputs"), inputs).map_err(|e| e.to_string())?;
            let output = Command::new(&self.bb)
                .args(["verify", "-t", "evm", "-k"])
                .arg(&self.vk)
                .arg("-p")
                .arg(directory.join("proof"))
                .arg("-i")
                .arg(directory.join("inputs"))
                .env("HARDWARE_CONCURRENCY", "4")
                .output()
                .map_err(|e| e.to_string())?;
            let message = String::from_utf8_lossy(&output.stdout).to_string()
                + &String::from_utf8_lossy(&output.stderr);
            if !output.status.success() || !message.contains("Proof verified successfully") {
                return Err("native proof verification rejected".into());
            }
            self.native.set(self.native.get() + 1);
            Ok(())
        })();
        let _ = std::fs::remove_dir_all(directory);
        result
    }
}
impl RecoveryHost for Host {
    fn verify_frozen_statement(
        &self,
        intent: &FrozenProvenanceIntent,
        sidecar: &ProofSidecar,
    ) -> Result<(), String> {
        if intent != &self.intent {
            return Err("frozen intent changed".into());
        }
        self.fact()?;
        self.verify(sidecar)
    }
    fn reconcile_frozen_transaction(
        &self,
        _: &RecoveryRecord,
    ) -> Result<RecoveryReconciliation, String> {
        self.fact()
    }
    fn local_reprove(
        &self,
        _: &RecoveryRecord,
        _: &str,
        _: &AtomicBool,
    ) -> Result<ProofSidecar, String> {
        serde_json::from_value(self.recovery["sidecar"].clone()).map_err(|e| e.to_string())
    }
}
struct TrackingOnly<'a>(&'a ProvenanceClient);
impl RecoveryService for TrackingOnly<'_> {
    fn evaluate(&self, data: &str, sidecars: &[ProofSidecar]) -> Result<Value, String> {
        self.0.evaluate_transaction(json!(data), sidecars)
    }
    fn tracking(&self, id: &str) -> Result<Value, String> {
        self.0.get_tracking(id)
    }
    fn submit(
        &self,
        _: &BTreeMap<String, String>,
        _: &ProofBundle,
        _: &str,
    ) -> Result<Value, String> {
        Err("tracked recovery must not submit proof".into())
    }
    fn job(&self, _: &str) -> Result<Value, String> {
        Err("tracked recovery must not fetch proof job".into())
    }
    fn operation_recognition(&self, locator: &BTreeMap<String, String>) -> Result<Value, String> {
        self.0.get_operation_recognition(json!(locator))
    }
}
#[test]
fn provenance_recovery_live() {
    if std::env::var("INVISI_PROVENANCE_RECOVERY_LIVE").as_deref() != Ok("1") {
        eprintln!("SKIP explicit recovery live opt-in required");
        return;
    }
    let release = current_source_release();
    let path = PathBuf::from(std::env::var("INVISI_PROVENANCE_TRUST").unwrap());
    let fixture: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let recovery = fixture["recovery"].clone();
    let pin = LIVE_MANIFEST_SHA256;
    assert_eq!(fixture["manifestSha256"], pin);
    for endpoint in [text(&fixture, "endpoint"), text(&recovery, "primaryRPC")] {
        assert!(["http://127.0.0.1:", "http://localhost:", "http://[::1]:"]
            .iter()
            .any(|prefix| endpoint.starts_with(prefix)));
    }
    let genesis = bytes32(text(&fixture, "initialSigningPublicKey"));
    assert_eq!(
        format!("0x{}", hex::encode(Sha256::digest(genesis))),
        text(&fixture, "initialSigningKeyId")
    );
    let rotations: Vec<RotationRecord> =
        serde_json::from_value(fixture["keyRotations"].clone()).unwrap();
    let ring = verify_rotation_chain(
        RotationCheckpoint {
            provider_id: n(text(&fixture, "providerId")),
            keys: BTreeMap::from([(n(text(&fixture, "initialSigningKeyId")), genesis)]),
            validity: BTreeMap::new(),
            previous_rotation_hash: [0; 32],
            last_activated_at: 0,
            now: n(text(&fixture, "checkedAt")).to(),
        },
        &rotations,
    )
    .unwrap();
    assert_eq!(
        ring.keys[&n(text(&fixture, "currentSigningKeyId"))],
        bytes32(text(&fixture, "currentSigningPublicKey"))
    );
    let scope = &fixture["scope"];
    let trust = TrustContext {
        scope: Scope {
            chain_id: n(text(scope, "chainId")).to(),
            protocol_address: n(text(scope, "protocolAddress")),
        },
        chain_generation: n(text(&fixture, "chainGeneration")).to(),
        provider_id: n(text(&fixture, "providerId")),
        signing_keys: BTreeMap::new(),
        signing_key_validity: BTreeMap::new(),
        manifest_sha256: pin.into(),
    }
    .with_rotation_history(ring)
    .unwrap();
    let client = ProvenanceClient::new(text(&fixture, "endpoint"), trust.clone()).unwrap();
    let version = client.get_version().unwrap();
    assert_eq!(
        version["publicInputCount"],
        release.manifest.public_inputs.len().to_string()
    );
    client.get_status().unwrap();
    let calldata = text(&recovery, "calldata");
    let intent = FrozenProvenanceIntent {
        chain_id: text(scope, "chainId").into(),
        protocol_address: text(scope, "protocolAddress").into(),

        token_address: text(&recovery, "tokenAddress").into(),
        operation_index: text(&recovery, "operationIndex").into(),
        operation_digest: text(&recovery, "operationDigest").into(),
        input_nullifiers: serde_json::from_value(recovery["inputNullifiers"].clone()).unwrap(),
        calldata: calldata.into(),
        calldata_hash: format!(
            "{:#x}",
            keccak256(hex::decode(calldata.trim_start_matches("0x")).unwrap())
        ),
        signed_request_hash: text(&recovery, "transactionHash").into(),
    };
    if let Some(raw) = recovery["signedTransaction"].as_str() {
        assert_eq!(
            format!(
                "{:#x}",
                keccak256(hex::decode(raw.trim_start_matches("0x")).unwrap())
            ),
            intent.signed_request_hash
        );
    }
    let sidecar: ProofSidecar = serde_json::from_value(recovery["sidecar"].clone()).unwrap();
    assert_eq!(
        sidecar.proof_bundle.public_inputs.len(),
        PUBLIC_INPUTS.len()
    );
    validate_proof_bundle(&sidecar.proof_bundle, &trust).unwrap();
    let root = Path::new(text(&recovery, "protocolRoot"));
    let manifest = std::fs::read(root.join("circuits/provenance/manifest.json")).unwrap();
    authenticate_manifest(&manifest, pin).unwrap();
    assert_eq!(manifest, include_bytes!("../testdata/source-manifest.json"));
    let raw: Value = serde_json::from_slice(&manifest).unwrap();
    let capacity: usize = sidecar
        .proof_bundle
        .circuit_id
        .trim_start_matches("provenance_k")
        .parse()
        .unwrap();
    let entry = raw["circuits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["capacity"] == capacity)
        .unwrap();
    let vk = root.join(text(entry, "vk"));
    assert_eq!(
        hex::encode(Sha256::digest(std::fs::read(&vk).unwrap())),
        text(entry, "vkSha256")
    );
    let bb = root.join(".tools/bb/bb");
    assert_eq!(
        String::from_utf8(Command::new(&bb).arg("--version").output().unwrap().stdout)
            .unwrap()
            .trim(),
        "6.0.0"
    );
    let host = Host {
        transport: HttpTransport::new(text(&recovery, "primaryRPC")).unwrap(),
        fixture: fixture.clone(),
        recovery: recovery.clone(),
        intent: intent.clone(),
        bb,
        vk,
        calls: Cell::new(0),
        native: Cell::new(0),
    };
    let db_path = std::env::temp_dir().join(format!(
        "invisi-recovery-live-{}.sqlite",
        uuid::Uuid::new_v4()
    ));
    let records =
        Arc::new(invisi_sdk_session::session::sqlite::SQLiteRecords::open(&db_path).unwrap());
    let adapter = Arc::new(SessionRecoveryRecords::new(records));
    let store = EncryptedRecoveryStore::new(adapter, [23; 32]);
    let coordinator = RecoveryCoordinator {
        store: &store,
        trust: &trust,
        service: &client,
        host: &host,
    };
    let stop = AtomicBool::new(false);
    let mut bad = sidecar.clone();
    let mut proof = hex::decode(bad.proof_bundle.proof.trim_start_matches("0x")).unwrap();
    let last = proof.len() - 1;
    proof[last] ^= 1;
    bad.proof_bundle.proof = format!("0x{}", hex::encode(proof));
    assert!(coordinator
        .prepare_direct("bad-local", intent.clone(), bad, "rust-bad-local")
        .is_err());
    assert!(store.load("bad-local").unwrap().is_none());
    let id = "rust-recovery-live";
    let base = format!("rust-recovery-{}", uuid::Uuid::new_v4());
    coordinator
        .prepare_direct(id, intent.clone(), sidecar, &base)
        .unwrap();
    let invalid = recovery["invalidJobId"].as_str().filter(|s| !s.is_empty());
    if let Some(job) = invalid {
        let mut saved = store.load(id).unwrap().unwrap();
        let fact = host.fact().unwrap();
        let old = saved.revision;
        saved.revision += 1;
        saved.job_id = Some(job.into());
        saved.locator = fact.locator;
        saved.transaction_hash = fact.transaction_hash;
        saved.state = "pending".into();
        assert!(store.compare_and_swap(id, old, &saved).unwrap());
        let rejected = coordinator.resume(id, false, &stop).unwrap();
        assert_eq!(rejected.state, "proof_rejected");
        assert_eq!(rejected.proof_job_status.as_deref(), Some("invalid"));
        assert_eq!(rejected.reason_code.as_deref(), Some("PROOF_INVALID"));
    }
    let records =
        Arc::new(invisi_sdk_session::session::sqlite::SQLiteRecords::open(&db_path).unwrap());
    let reopened =
        EncryptedRecoveryStore::new(Arc::new(SessionRecoveryRecords::new(records)), [23; 32]);
    let restart = RecoveryCoordinator {
        store: &reopened,
        trust: &trust,
        service: &client,
        host: &host,
    };
    let result = restart
        .run(
            id,
            invalid.is_some(),
            &stop,
            Duration::from_millis(100),
            300,
        )
        .unwrap();
    assert_eq!(result.state, "recognized");
    assert_ne!(result.reason_code.as_deref(), Some("PROOF_INVALID"));
    assert!(result.proof_valid);
    assert_eq!(result.intent, intent);
    assert!(result.checkpoint_sequence.is_some());
    let tracked_service = TrackingOnly(&client);
    let automatic = RecoveryCoordinator {
        store: &reopened,
        trust: &trust,
        service: &tracked_service,
        host: &host,
    };
    let permit = automatic
        .prepare(
            "rust-tracked-live",
            intent.clone(),
            serde_json::from_value(recovery["sidecar"].clone()).unwrap(),
            &format!("rust-tracked-{}", uuid::Uuid::new_v4()),
        )
        .unwrap();
    assert_eq!(
        permit.tracking_id.as_deref(),
        Some(text(&recovery, "trackingId"))
    );
    let tracked_result = automatic
        .run(
            "rust-tracked-live",
            false,
            &stop,
            Duration::from_millis(100),
            300,
        )
        .unwrap();
    assert_eq!(tracked_result.state, "recognized");
    assert_eq!(tracked_result.intent, intent);
    let report = json!({"sdk":"rust","manifestSha256":pin,"realPrimaryHTTP":true,"primaryCalls":host.calls.get(),"realNativeVerification":true,"nativeVerifications":host.native.get(),"encryptedRestart":true,"trackedRecovery":true,"trackingId":tracked_result.tracking_id,"badLocalProofRejected":true,"reasonCode":result.reason_code,"invalidJobImported":invalid.is_some(),"jobStatus":result.proof_job_status,"state":result.state,"jobId":result.job_id,"checkpointSequence":result.checkpoint_sequence,"frozenTransactionHash":result.transaction_hash,"mocks":false});
    std::fs::write(
        path.parent()
            .unwrap()
            .join("sdk-recovery-rust-validation.json"),
        serde_json::to_string_pretty(&report).unwrap() + "\n",
    )
    .unwrap();
    drop(reopened);
    drop(store);
    let _ = std::fs::remove_file(db_path);
}
