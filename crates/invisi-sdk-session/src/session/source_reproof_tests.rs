use super::*;
use invisi_sdk_core::provenance as p;
use invisi_sdk_rpc::provenance_client::ProvenanceClient;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::sync::atomic::AtomicUsize;

struct LocalSource {
    endpoint: String,
    generation: Arc<AtomicUsize>,
    hits: Arc<AtomicUsize>,
    offline: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl LocalSource {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let generation = Arc::new(AtomicUsize::new(1));
        let hits = Arc::new(AtomicUsize::new(0));
        let offline = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let (g, h, off, done) = (
            generation.clone(),
            hits.clone(),
            offline.clone(),
            stop.clone(),
        );
        let thread = std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                    .unwrap();
                let mut bytes = Vec::new();
                let header_end = loop {
                    let mut buf = [0u8; 4096];
                    let count = stream.read(&mut buf).unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buf[..count]);
                    if let Some(i) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                        break i + 4;
                    }
                };
                let headers = String::from_utf8_lossy(&bytes[..header_end]);
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse().unwrap())
                    })
                    .unwrap();
                while bytes.len() < header_end + length {
                    let mut buf = [0u8; 4096];
                    let count = stream.read(&mut buf).unwrap();
                    assert!(count > 0);
                    bytes.extend_from_slice(&buf[..count]);
                }
                let request: Value =
                    serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap();
                h.fetch_add(1, Ordering::SeqCst);
                let gen = g.load(Ordering::SeqCst);
                let fixture: Value =
                    serde_json::from_str(include_str!("../../testdata/source-reproof.json"))
                        .unwrap();
                let cert = fixture["generations"][gen - 1]["certificate"].clone();
                let scope = json!({"chainId":"31337","protocolAddress":"4660"});
                let mut result =
                    json!({"scope":scope,"chainGeneration":gen.to_string(),"providerId":"1"});
                match request["method"].as_str().unwrap() {
                    "provenance_getStatus" => result["checkpointSequence"] = json!("1"),
                    "provenance_getRoot" => {
                        result["certificate"] = cert;
                        result["allowedForNewProof"] = json!(true);
                    }
                    "provenance_getLeaves" => {
                        let scope = p::Scope {
                            chain_id: 31337,
                            protocol_address: U256::from(4660),
                        };
                        let commitments = [
                            fixture["commitment"]
                                .as_str()
                                .unwrap()
                                .parse::<U256>()
                                .unwrap(),
                            U256::from(100),
                        ];
                        let items = commitments[..gen].iter().enumerate().map(|(index, commitment)| json!({
                            "scope":{"chainId":"31337","protocolAddress":"4660"},
                            "chainGeneration":gen.to_string(),"treeId":"1","leafIndex":index.to_string(),"checkpointSequence":"1",
                            "noteCommitment":commitment.to_string(),"leaf":p::recognized_leaf(p::scope_hash(&scope).unwrap(),*commitment).unwrap().to_string()
                        })).collect::<Vec<_>>();
                        result["certificate"] = cert;
                        result["rootId"] = json!(format!("{gen}:1"));
                        result["items"] = json!(items);
                        result["nextIndex"] = json!(gen.to_string());
                    }
                    method => panic!("unexpected Source method: {method}"),
                }
                let response = if off.load(Ordering::SeqCst) {
                    json!({"jsonrpc":"2.0","id":request["id"],"error":{"data":{"code":"offline"}}})
                } else {
                    json!({"jsonrpc":"2.0","id":request["id"],"result":result})
                };
                let body = response.to_string();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
            }
        });
        Self {
            endpoint,
            generation,
            hits,
            offline,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for LocalSource {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let result = self.thread.take().unwrap().join();
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}
struct SourceProver {
    calls: Arc<AtomicUsize>,
    cancel: Arc<AtomicBool>,
}
impl p::OfflineProver for SourceProver {
    fn prove(
        &self,
        _: &str,
        _: usize,
        _: &p::Witness,
        expected: &[String],
    ) -> crate::note::ModelResult<(Vec<String>, Vec<u8>)> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.cancel.load(Ordering::SeqCst) {
            return Err(crate::note::ModelError::Invalid("prover canceled"));
        }
        Ok((expected.to_vec(), vec![1, 2, 3]))
    }
}
fn capability(
    source: &LocalSource,
    generation: usize,
    calls: Arc<AtomicUsize>,
    cancel: Arc<AtomicBool>,
) -> Arc<sdk::PreparedProvenance> {
    let fixture: Value =
        serde_json::from_str(include_str!("../../testdata/source-reproof.json")).unwrap();
    let current = &fixture["generations"][generation - 1];
    let key: [u8; 32] = hex::decode(
        current["publicKey"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap()
    .try_into()
    .unwrap();
    let key_id = current["certificate"]["signingKeyId"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let manifest = p::authenticate_manifest(
        include_bytes!("../../testdata/source-manifest.json"),
        "6107789c5c0d24c4130bff05da6d389336feb5ccb247c4030eae5198ab05d762",
    )
    .unwrap();
    let trust = p::TrustContext {
        scope: p::Scope {
            chain_id: 31337,
            protocol_address: U256::from(4660),
        },
        chain_generation: generation as u64,
        provider_id: U256::from(1),
        signing_keys: BTreeMap::from([(key_id, key)]),
        signing_key_validity: BTreeMap::new(),
        manifest_sha256: manifest.sha256.clone(),
    };
    Arc::new(sdk::PreparedProvenance {
        client: Arc::new(ProvenanceClient::new(&source.endpoint, trust).unwrap()),
        manifest,
        prover: Arc::new(SourceProver { calls, cancel }),
        budgets: sdk::SourceReplayBudgets::default(),
    })
}
fn without_evidence(mut state: Value) -> Value {
    state.as_object_mut().unwrap().remove("revision");
    for record in state["operations"].as_object_mut().unwrap().values_mut() {
        record["snapshot"]
            .as_object_mut()
            .unwrap()
            .remove("provenancePacket");
    }
    state
}

#[test]
fn terminal_source_reproof_rotates_generation_after_restart_without_changing_payment() {
    let source = LocalSource::start();
    let calls = Arc::new(AtomicUsize::new(0));
    let cancel = Arc::new(AtomicBool::new(false));
    let mut h = synced();
    h.chain.source_anchors.store(true, Ordering::SeqCst);
    h.session.invisi = Invisi::new(h.chain.clone())
        .with_provenance(capability(&source, 1, calls.clone(), cancel.clone()))
        .unwrap();
    let mut operation = h
        .session
        .prepare_transfer(transfer(&h))
        .unwrap()
        .prove(&Backend, false)
        .unwrap();
    let packet = operation.prove_provenance().unwrap();
    let id = operation.id().to_owned();
    let call = operation
        .calldata(h.session.wallet.owner_address())
        .unwrap();
    operation
        .track_transaction(B256::with_last_byte(8))
        .unwrap();
    let mut state = h.session.snapshot().unwrap();
    let record = state.operations.get_mut(&id).unwrap();
    record.status = OperationStatus::Confirmed;
    record.resolved_at = Some(block(10));
    let note = state.notes.get_mut(&h.commitment).unwrap();
    note.spent = true;
    note.reserved_by = None;
    h.chain.spent.lock().unwrap().insert(note.nullifier);
    h.session.commit(state).unwrap();
    let before_terminal_refresh = serde_json::to_value(h.session.snapshot().unwrap()).unwrap();
    assert_eq!(operation.reprove_provenance().unwrap().data, packet.data);
    let terminal = serde_json::to_value(h.session.snapshot().unwrap()).unwrap();
    assert_eq!(
        without_evidence(terminal.clone()),
        without_evidence(before_terminal_refresh)
    );
    assert_eq!(
        terminal["operations"][&id]["call"]["data"],
        format!("0x{}", hex::encode(&call.data))
    );
    source.offline.store(true, Ordering::SeqCst);
    h.chain.reorg.store(true, Ordering::SeqCst);
    let hits = source.hits.load(Ordering::SeqCst);
    let mut restarted = WalletSession::connect(
        Invisi::new(h.chain.clone())
            .with_provenance(Arc::new(sdk::PreparedProvenance::client_only(
                h.session.invisi.provenance.as_ref().unwrap().client.clone(),
            )))
            .unwrap(),
        h.session.wallet.clone(),
        h.store.clone(),
        h.source.clone(),
        "test",
    )
    .unwrap();
    let restored = restarted.snapshot().unwrap().operations[&id]
        .snapshot
        .restore(restarted.wallet(), None)
        .unwrap();
    assert_eq!(restored.phase(), sdk::Phase::Prepared);
    let restored = match restored {
        ManagedPrepared::Funds(value) => ManagedPrepared::Funds(
            value
                .reattach_provenance(capability(&source, 1, calls.clone(), cancel.clone()))
                .unwrap(),
        ),
        _ => panic!("private Note required"),
    };
    assert!(!terminal["operations"][&id]["snapshot"]["proof"].is_null());
    assert!(serde_json::to_value(restored.snapshot().unwrap()).unwrap()["proof"].is_null());
    assert!(restarted.resume(&id, None).is_err());
    assert_eq!(
        restarted
            .recover_provenance_proof(&id)
            .unwrap()
            .unwrap()
            .data,
        packet.data
    );
    assert_eq!(operation.prove_provenance().unwrap().data, packet.data);
    assert_eq!(source.hits.load(Ordering::SeqCst), hits);
    assert!(restarted
        .reprove_provenance_proof(&id)
        .unwrap_err()
        .contains("local provenance proving resources"));
    assert_eq!(source.hits.load(Ordering::SeqCst), hits);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    h.chain.reorg.store(false, Ordering::SeqCst);
    source.offline.store(false, Ordering::SeqCst);
    source.generation.store(2, Ordering::SeqCst);
    restarted.invisi = Invisi::new(h.chain.clone())
        .with_provenance(capability(&source, 2, calls.clone(), cancel.clone()))
        .unwrap();
    assert!(restarted.recover_provenance_proof(&id).is_err());
    cancel.store(true, Ordering::SeqCst);
    assert!(restarted
        .reprove_provenance_proof(&id)
        .unwrap_err()
        .contains("prover canceled"));
    assert_eq!(
        serde_json::to_value(restarted.snapshot().unwrap()).unwrap(),
        terminal
    );
    cancel.store(false, Ordering::SeqCst);
    let renewed = restarted.reprove_provenance_proof(&id).unwrap();
    assert_eq!(renewed.data, packet.data);
    assert_eq!(renewed.public_inputs, packet.public_inputs);
    assert_eq!(renewed.operation_digest, packet.operation_digest);
    assert_ne!(
        serde_json::to_value(&renewed.sidecars).unwrap(),
        serde_json::to_value(&packet.sidecars).unwrap()
    );
    assert_eq!(
        renewed.sidecars[0].proof_bundle.root_certificates[0].chain_generation,
        "2"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    let after = serde_json::to_value(restarted.snapshot().unwrap()).unwrap();
    assert_eq!(without_evidence(after.clone()), without_evidence(terminal));
    source.offline.store(true, Ordering::SeqCst);
    h.chain.reorg.store(true, Ordering::SeqCst);
    let final_hits = source.hits.load(Ordering::SeqCst);
    assert_eq!(
        restarted
            .recover_provenance_proof(&id)
            .unwrap()
            .unwrap()
            .data,
        packet.data
    );
    assert_eq!(
        after,
        serde_json::to_value(restarted.snapshot().unwrap()).unwrap()
    );
    assert_eq!(source.hits.load(Ordering::SeqCst), final_hits);
    assert_eq!(calls.load(Ordering::SeqCst), 4);
}

#[test]
fn first_source_proof_after_terminal_restart_binds_authoritative_main_proof_bytes() {
    use alloy_sol_types::SolCall;
    let source = LocalSource::start();
    let calls = Arc::new(AtomicUsize::new(0));
    let cancel = Arc::new(AtomicBool::new(false));
    let mut h = synced();
    h.chain.source_anchors.store(true, Ordering::SeqCst);
    h.session.invisi = Invisi::new(h.chain.clone())
        .with_provenance(capability(&source, 1, calls.clone(), cancel.clone()))
        .unwrap();
    let mut operation = h
        .session
        .prepare_transfer(transfer(&h))
        .unwrap()
        .prove(&Backend, false)
        .unwrap();
    let id = operation.id().to_owned();
    let call = operation
        .calldata(h.session.wallet.owner_address())
        .unwrap();
    operation
        .track_transaction(B256::with_last_byte(8))
        .unwrap();
    let mut state = h.session.snapshot().unwrap();
    state.operations.get_mut(&id).unwrap().status = OperationStatus::Confirmed;
    let note = state.notes.get_mut(&h.commitment).unwrap();
    note.spent = true;
    note.reserved_by = None;
    h.chain.spent.lock().unwrap().insert(note.nullifier);
    h.session.commit(state).unwrap();
    let restarted = WalletSession::connect(
        h.session.invisi.clone(),
        h.session.wallet.clone(),
        h.store.clone(),
        h.source.clone(),
        "test",
    )
    .unwrap();
    assert!(restarted.recover_provenance_proof(&id).unwrap().is_none());
    let before = serde_json::to_value(restarted.snapshot().unwrap()).unwrap();
    let packet = restarted.reprove_provenance_proof(&id).unwrap();
    assert_eq!(packet.data, format!("0x{}", hex::encode(&call.data)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let after = serde_json::to_value(restarted.snapshot().unwrap()).unwrap();
    assert_eq!(without_evidence(before), without_evidence(after));
    let mut state = restarted.snapshot().unwrap();
    let record = state.operations.get_mut(&id).unwrap();
    let mut saved = serde_json::to_value(&record.snapshot).unwrap();
    let mut changed = P::transact_0Call::abi_decode(&call.data, true).unwrap();
    changed._0 = vec![9, 9, 9].into();
    saved["provenancePacket"]["data"] = json!(format!("0x{}", hex::encode(changed.abi_encode())));
    record.snapshot = serde_json::from_value(saved).unwrap();
    restarted.commit(state).unwrap();
    source.offline.store(true, Ordering::SeqCst);
    let hits = source.hits.load(Ordering::SeqCst);
    assert!(restarted
        .recover_provenance_proof(&id)
        .unwrap_err()
        .contains("final calldata mismatch"));
    assert_eq!(source.hits.load(Ordering::SeqCst), hits);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
