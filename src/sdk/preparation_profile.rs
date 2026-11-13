// Public synthetic fixtures, controlled ChainState latency, real signatures, stub main proof.
struct LatencyChain {
    inner: Arc<super::super::test_support::FixtureChain>,
    calls: std::sync::atomic::AtomicUsize,
    active: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
}
impl LatencyChain {
    fn wait(&self) {
        use std::sync::atomic::Ordering;
        self.calls.fetch_add(1, Ordering::SeqCst);
        let n = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(n, Ordering::SeqCst);
        std::thread::sleep(std::time::Duration::from_millis(100));
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}
impl ChainState for LatencyChain {
    fn context(&self) -> ProtocolContext {
        self.inner.context()
    }
    fn snapshot(&self) -> Result<CanonicalBlock> {
        self.wait();
        self.inner.snapshot()
    }
    fn canonical(&self, b: &CanonicalBlock) -> Result<()> {
        self.wait();
        self.inner.canonical(b)
    }
    fn known_root(&self, t: u64, r: B256, b: &CanonicalBlock) -> Result<bool> {
        self.wait();
        self.inner.known_root(t, r, b)
    }
    fn nullifier_spent(&self, n: B256, b: &CanonicalBlock) -> Result<bool> {
        self.wait();
        self.inner.nullifier_spent(n, b)
    }
    fn credit_revoked(
        &self,
        o: Address,
        t: Address,
        s: u64,
        l: u16,
        b: &CanonicalBlock,
    ) -> Result<bool> {
        self.wait();
        self.inner.credit_revoked(o, t, s, l, b)
    }
    fn credit_allocation(&self, o: Address, t: Address, b: &CanonicalBlock) -> Result<(u64, u16)> {
        self.wait();
        self.inner.credit_allocation(o, t, b)
    }
    fn token_balance_allowance(
        &self,
        o: Address,
        t: Address,
        b: &CanonicalBlock,
    ) -> Result<(U256, U256)> {
        self.wait();
        self.inner.token_balance_allowance(o, t, b)
    }
    fn funding_nonce(&self, o: Address, b: &CanonicalBlock) -> Result<U256> {
        self.wait();
        self.inner.funding_nonce(o, b)
    }
}
struct ProfileProof;
impl Prover for ProfileProof {
    fn prove(&self, r: &prover::ProvingRequest) -> Result<ProofBundle> {
        let s = &r.statement;
        let proof = vec![0; 32];
        Ok(ProofBundle {
            format_version: 1,
            circuit_name: s.circuit_name.clone(),
            target: s.target.clone(),
            bb_version: "6.0.0".into(),
            artifact_sha256: s.artifact_sha256.clone(),
            vk_sha256: s.vk_sha256.clone(),
            proof_sha256: prover::sha256(&proof),
            proof,
            public_inputs: s.expected_public_inputs.clone(),
        })
    }
    fn verify(&self, _: &ProofBundle, _: &prover::ProofStatement) -> Result<bool> {
        Ok(true)
    }
}
fn profile_signature(key: &k256::ecdsa::SigningKey, request: &EvmSigningRequest) -> Vec<u8> {
    let (signature, recovery) = key
        .sign_prehash_recoverable(request.digest.as_slice())
        .unwrap();
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(recovery.to_byte());
    bytes
}
#[test]
fn preparation_latency_10x10_profile() {
    if std::env::var_os("INVISI_PREPARATION_PROFILE").is_none() {
        return;
    }
    for _round in 0..3 {
        let (inner, old_wallet, base, _) = note_fixture();
        let key = k256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        let public = key.verifying_key().to_encoded_point(false);
        let owner = Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]);
        let wallet = Wallet::from_keys(owner, old_wallet.receiving_keys().clone()).unwrap();
        let mut inputs = Vec::new();
        for i in 0..10 {
            let note = Note {
                context: inner.context(),
                owner_address: address_word(owner),
                token_address: address_word(base.token),
                amount: U256::from(100),
                nonce: U256::from(1000 + i),
                payload: vec![],
            };
            let path = [U256::ZERO; 16];
            let root = merkle_root(note.commitment().unwrap(), 0, &path).unwrap();
            inputs.push(NoteInput {
                note,
                tree_id: i + 1,
                leaf_index: 0,
                path,
                root,
            });
        }
        let chain = Arc::new(LatencyChain {
            inner,
            calls: 0.into(),
            active: 0.into(),
            peak: 0.into(),
        });
        let runtime = Invisi::new(chain.clone());
        let mut times = BTreeMap::new();
        let start = std::time::Instant::now();
        let outputs = (0..9)
            .map(|_| {
                NoteOutput::for_recipient(
                    chain.context(),
                    base.token,
                    &wallet,
                    U256::from(200),
                    vec![],
                )
                .unwrap()
            })
            .collect();
        times.insert("outputs", start.elapsed().as_millis());
        let start = std::time::Instant::now();
        let prepared = runtime
            .prepare_transfer(
                &wallet,
                TransferPreparation {
                    token: base.token,
                    inputs,
                    outputs,
                    withdrawal: None,
                    funding: abi::FundingParams {
                        payer: owner,
                        amount: U256::from(1000),
                        deadline: U256::from(100),
                        ..empty_funding()
                    },
                    fee: Fee::default(),
                    deadline: 100,
                    automatic_change: true,
                },
            )
            .unwrap();
        times.insert("prepare", start.elapsed().as_millis());
        assert_eq!(prepared.inputs().len(), 10);
        assert_eq!(prepared.outputs().len(), 10);
        let start = std::time::Instant::now();
        prepared.estimate_gas().unwrap();
        times.insert("estimate", start.elapsed().as_millis());
        let start = std::time::Instant::now();
        let request = prepared.export_wallet_authorization().unwrap();
        times.insert("wallet_export", start.elapsed().as_millis());
        let start = std::time::Instant::now();
        let signature = profile_signature(&key, &request);
        times.insert("wallet_sign", start.elapsed().as_millis());
        let start = std::time::Instant::now();
        let authorized = prepared.clone().with_wallet_signature(&signature).unwrap();
        times.insert("wallet_attach", start.elapsed().as_millis());
        let start = std::time::Instant::now();
        let proved = authorized.prove(&ProfileProof, None).unwrap();
        times.insert("prove_stub", start.elapsed().as_millis());
        let start = std::time::Instant::now();
        let funding = proved.export_funding_authorization(chain.as_ref()).unwrap();
        times.insert("funding_export", start.elapsed().as_millis());
        let start = std::time::Instant::now();
        let signature = profile_signature(&key, &funding);
        times.insert("funding_sign", start.elapsed().as_millis());
        let start = std::time::Instant::now();
        let ready = proved
            .with_funding_signature(chain.as_ref(), signature)
            .unwrap();
        times.insert("funding_attach", start.elapsed().as_millis());
        let start = std::time::Instant::now();
        ready.calldata(chain.as_ref(), owner).unwrap();
        times.insert("transaction_export", start.elapsed().as_millis());
        let start = std::time::Instant::now();
        prepared
            .quote_for_broadcaster(
                chain.clone(),
                Arc::new(SignedRelay {
                    fees: 0.into(),
                    quotes: 0.into(),
                }),
                &BroadcasterOptions {
                    max_fee_amount: Some(U256::from(100)),
                    ..Default::default()
                },
            )
            .unwrap();
        times.insert("quote", start.elapsed().as_millis());
        times.insert(
            "provider_calls",
            chain.calls.load(std::sync::atomic::Ordering::SeqCst) as u128,
        );
        times.insert(
            "peak_concurrency",
            chain.peak.load(std::sync::atomic::Ordering::SeqCst) as u128,
        );
        println!("PROFILE {}", serde_json::to_string(&times).unwrap());
    }
}
