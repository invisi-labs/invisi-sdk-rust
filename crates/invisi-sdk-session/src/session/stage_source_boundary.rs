//! Local Source HTTP, authenticated roots and counted fixture provers. No external transactions.
use super::*;
use crate::broadcaster::{self as relay, Configuration, Fee, Status, Trust, VerifiedQuote};
use sdk::PreparedBroadcaster;

struct StageRelay {
    inner: SessionCreditRelay,
    lookups: AtomicUsize,
}

impl PreparedBroadcaster for StageRelay {
    fn configuration(&self) -> Configuration {
        self.inner.configuration()
    }
    fn provenance_mode(&self) -> Option<()> {
        Some(())
    }
    fn submission_requirements(&self, q: &VerifiedQuote) -> Result<bool> {
        Ok(q.signed().provenance_required == Some(true))
    }
    fn fee(&self, token: Address, data: Option<&[u8]>) -> Result<Fee> {
        self.inner.fee(token, data).map(|mut f| {
            f.fee_amount = "5".into();
            f
        })
    }
    fn quote(
        &self,
        data: &[u8],
        chain_id: u64,
        protocol: Address,
        now: u64,
        sidecars: &[p::ProofSidecar],
    ) -> Result<VerifiedQuote> {
        let mut signed = self
            .inner
            .quote(data, chain_id, protocol, now, sidecars)?
            .signed()
            .clone();
        let trust = Trust {
            chain_id,
            protocol,
            signer: self.configuration().quote_signer,
        };
        signed.quote.request_hash =
            B256::from(p::provenance_intent_hash(signed.quote.request_hash.0));
        signed.request_hash_format = Some(relay::REQUEST_HASH_FORMAT.into());
        signed.provenance_required = Some(true);
        let (signature, recovery) = k256::ecdsa::SigningKey::from_slice(&key(1))
            .unwrap()
            .sign_prehash_recoverable(
                relay::quote_digest(&signed.quote, &trust)
                    .unwrap()
                    .as_slice(),
            )
            .unwrap();
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery.to_byte());
        signed.signature = format!("0x{}", hex::encode(bytes));
        VerifiedQuote::authenticate(signed, trust, data, now, Some(())).map_err(|e| e.to_string())
    }
    fn submit(
        &self,
        data: &[u8],
        q: &VerifiedQuote,
        sidecars: &[p::ProofSidecar],
    ) -> Result<Status> {
        assert_eq!(sidecars.len(), 1);
        let mut wires = self.inner.requests.lock().unwrap();
        let packet = json!({"data":hex::encode(data),"signed":q.signed(),"sidecars":sidecars});
        if let Some(first) = wires.first() {
            assert_eq!(first, &packet);
        }
        wires.push(packet);
        if wires.len() == 1 {
            return Err("uncertain fixture response after wire".into());
        }
        self.inner
            .lookup_status("private-stage")?
            .ok_or("missing fixture status".into())
    }
    fn lookup_status(&self, id: &str) -> Result<Option<Status>> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        self.inner.lookup_status(id)
    }
}
struct MainProver(AtomicUsize);
impl Prover for MainProver {
    fn prove(&self, request: &ProvingRequest) -> Result<ProofBundle> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Backend.prove(request)
    }
    fn verify(&self, bundle: &ProofBundle, statement: &ProofStatement) -> Result<bool> {
        Backend.verify(bundle, statement)
    }
}

#[test]
fn private_source_stage_boundaries_and_exact_recovery() {
    run_private_case(false);
}
#[test]
fn mixed_funding_waits_for_explicit_source_finalization() {
    run_private_case(true);
}
fn run_private_case(mixed: bool) {
    let started = std::time::Instant::now();
    let inject_failure = std::env::var("INVISI_STAGE_NO_READY_FAILURE").as_deref() != Ok("1");
    let expected_calls = if inject_failure { 2 } else { 1 };
    let baseline = std::env::var("INVISI_STAGE_BASELINE").as_deref() == Ok("1");
    let source = LocalSource::start_with_fixture(include_str!("../../testdata/stage-source.json"));
    let calls = Arc::new(AtomicUsize::new(0));
    let cancel = Arc::new(AtomicBool::new(false));
    let backend = MainProver(0.into());
    let mut h = harness_for_note_amount(context(), 100);
    h.session
        .refresh(RefreshOptions::from_block(0))
        .unwrap()
        .decrypt(&AppDecryptor::default())
        .unwrap();
    h.chain.source_anchors.store(true, Ordering::SeqCst);
    if mixed {
        h.chain.preparation_enabled.store(true, Ordering::SeqCst);
    }
    h.session.invisi = Invisi::new(h.chain.clone())
        .with_provenance(capability(&source, 1, calls.clone(), cancel.clone()))
        .unwrap();
    let relay = Arc::new(StageRelay {
        inner: SessionCreditRelay {
            requests: Mutex::new(vec![]),
            lookup_mode: 0.into(),
            attempts: 0.into(),
        },
        lookups: 0.into(),
    });
    let mut stages = Vec::new();
    let mut last_http = 0;
    let mut last_micros = 0;
    let mut checkpoint = |name: &str| {
        let micros = started.elapsed().as_micros();
        let requests = source.requests.lock().unwrap();
        let methods = requests[last_http..]
            .iter()
            .map(|r| r["method"].clone())
            .collect::<Vec<_>>();
        stages.push(json!({
            "stage":name,
            "elapsedMicrosSinceStart":micros,
            "elapsedMicros":micros-last_micros,
            "sourceMethods":methods,
            "chainSnapshot":h.chain.snapshot_reads.load(Ordering::SeqCst),
            "chainNonce":h.chain.nonce_reads.load(Ordering::SeqCst),
            "chainRoot":h.chain.root_reads.load(Ordering::SeqCst),
            "chainNullifier":h.chain.nullifier_reads.load(Ordering::SeqCst),
            "mainProver":backend.0.load(Ordering::SeqCst),
            "sourceProver":calls.load(Ordering::SeqCst),
            "sourceHttp":requests.len(),
            "relayWire":relay.inner.requests.lock().unwrap().len(),
            "status":relay.lookups.load(Ordering::SeqCst)
        }));
        last_http = requests.len();
        last_micros = micros;
    };
    checkpoint("initialize");
    let mut payment = transfer(&h);
    payment.withdrawal = None;
    payment.outputs =
        vec![
            sdk::NoteOutput::identity(context(), payment.token, U256::from(716), U256::from(30))
                .unwrap(),
        ];
    payment.automatic_change = true;
    if mixed {
        payment.funding.amount = U256::from(10);
        payment.funding.payer = h.session.wallet.owner_address();
    }
    let mut op = h.session.prepare_transfer(payment).unwrap();
    if mixed {
        op = op.with_funding_terms(2_000_000_100).unwrap();
    }
    checkpoint("prepare");
    let chain_counts = || {
        [
            h.chain.snapshot_reads.load(Ordering::SeqCst),
            h.chain.nonce_reads.load(Ordering::SeqCst),
            h.chain.root_reads.load(Ordering::SeqCst),
            h.chain.nullifier_reads.load(Ordering::SeqCst),
        ]
    };
    let prequote = chain_counts();
    op.quote_for_broadcaster(
        relay.clone(),
        &sdk::BroadcasterOptions {
            fee_source: Some(sdk::BroadcasterFeeSource::PrivateInputs),
            max_fee_amount: Some(U256::from(10)),
            ..Default::default()
        },
    )
    .unwrap();
    if !baseline {
        assert_eq!(chain_counts(), prequote);
    }
    checkpoint("quote");
    let req = op.export_wallet_request("stage-private").unwrap();
    let resp =
        serde_json::from_value(crate::wallet::execute(&key(1), &req.as_value()).unwrap()).unwrap();
    let mut op = op
        .with_wallet_response(&resp)
        .unwrap()
        .prove(&backend, false)
        .unwrap();
    let id = op.id().to_owned();
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    checkpoint("prove");
    let mut verified_signature = None;
    if mixed {
        let saved = serde_json::to_value(h.session.snapshot().unwrap()).unwrap();
        assert!(op.ready().is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            serde_json::to_value(h.session.snapshot().unwrap()).unwrap(),
            saved
        );
        op = h.session.resume(&id, Some(&backend)).unwrap();
        let digest = op.export_funding_authorization().unwrap().digest;
        let (sig, rec) = k256::ecdsa::SigningKey::from_slice(&key(1))
            .unwrap()
            .sign_prehash_recoverable(digest.as_ref())
            .unwrap();
        let mut bytes = sig.to_bytes().to_vec();
        bytes.push(rec.to_byte());
        verified_signature = Some(bytes.clone());
        op = op.with_funding_signature(bytes).unwrap();
        assert_eq!(op.phase(), sdk::Phase::Proved);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(op.broadcaster_state().unwrap().submitted_data.is_empty());
        checkpoint("fundingSignature");
    }
    if inject_failure {
        cancel.store(true, Ordering::SeqCst);
        let before = h.session.snapshot().unwrap();
        if baseline {
            assert!(op
                .submit_for_broadcaster(relay.as_ref())
                .unwrap_err()
                .contains("canceled"));
        } else {
            assert!(op
                .submit_for_broadcaster(relay.as_ref())
                .unwrap_err()
                .contains("FINALIZATION_REQUIRED"));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(op.ready().unwrap_err().contains("canceled"));
        }
        let after = h.session.snapshot().unwrap();
        assert_eq!(
            serde_json::to_value(&before).unwrap(),
            serde_json::to_value(&after).unwrap()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        checkpoint("injectedFailure");
        cancel.store(false, Ordering::SeqCst);
        op = h.session.resume(&id, Some(&backend)).unwrap();
        if !baseline {
            let before = h.session.snapshot().unwrap();
            assert!(op
                .submit_for_broadcaster(relay.as_ref())
                .unwrap_err()
                .starts_with("FINALIZATION_REQUIRED"));
            assert!(relay.inner.requests.lock().unwrap().is_empty());
            assert_eq!(h.session.snapshot().unwrap().revision, before.revision);
        }
    }
    if !baseline {
        op = op.ready().unwrap();
        assert_eq!(op.broadcaster_state().unwrap().sidecars.len(), 1);
        if let Some(sig) = verified_signature {
            use alloy_sol_types::SolCall;
            let final_tx = P::transact_0Call::abi_decode_validate(
                &op.broadcaster_state().unwrap().submitted_data,
            )
            .unwrap();
            assert_eq!(final_tx.r.funding.signature.as_ref(), sig);
        }
        if inject_failure {
            op = op.ready().unwrap();
        }
        assert_eq!(calls.load(Ordering::SeqCst), expected_calls);
        source.offline.store(true, Ordering::SeqCst);
    }
    checkpoint("ready");
    assert!(op
        .submit_for_broadcaster(relay.as_ref())
        .unwrap_err()
        .contains("uncertain fixture"));
    checkpoint("firstSubmit");
    source.offline.store(true, Ordering::SeqCst);
    if !baseline {
        h.session.invisi.provenance = None;
        h.session.invisi.provenance_factory =
            Some(Arc::new(|_| Err("Source offline during recovery".into())));
    }
    let mut resumed = h.session.resume(&id, None).unwrap();
    resumed.submit_for_broadcaster(relay.as_ref()).unwrap();
    checkpoint("unknownIdReplay");
    resumed.submit_for_broadcaster(relay.as_ref()).unwrap();
    checkpoint("knownIdStatus");
    assert_eq!(relay.lookups.load(Ordering::SeqCst), 1);
    assert_eq!(relay.inner.requests.lock().unwrap().len(), 2);
    assert_eq!(calls.load(Ordering::SeqCst), expected_calls);
    if let Ok(path) = std::env::var("INVISI_STAGE_SOURCE_TRACE") {
        std::fs::write(path,serde_json::to_vec_pretty(&json!({"proofBackend":"counted fixture proofs","stages":stages,"sourceRequests":*source.requests.lock().unwrap(),"relayRequests":*relay.inner.requests.lock().unwrap()})).unwrap()).unwrap();
    }
}
