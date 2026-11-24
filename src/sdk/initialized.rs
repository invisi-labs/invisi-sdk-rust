//! Explicit initialization for native transports whose endpoint cannot change.
use super::*;
use crate::rpc::{EthereumChain, HttpTransport, TrustedProvider};
use std::sync::atomic::{AtomicBool, Ordering};

/// Owns a fixed native reader and its validated immutable deployment receipt.
/// Mutable chain facts are always live. Invalidating (or any read failure) retires
/// the receipt permanently; later reads use the full legacy validation path.
/// Dropping this object disposes the receipt and owned HTTP transport.
pub struct InitializedRpcChainState<C: CanonicalHead> {
    state: RpcChainState<C>,
    valid: AtomicBool,
    anchor: CanonicalBlock,
}
impl InitializedRpcChainState<EthereumChain<HttpTransport>> {
    pub fn ethereum(
        chain: EthereumChain<HttpTransport>,
        deployment: ProtocolDeployment,
    ) -> Result<Self> {
        Self::initialize(chain, deployment)
    }
}
impl InitializedRpcChainState<TrustedProvider<HttpTransport>> {
    pub fn trusted(
        chain: TrustedProvider<HttpTransport>,
        deployment: ProtocolDeployment,
    ) -> Result<Self> {
        Self::initialize(chain, deployment)
    }
}
impl<C: CanonicalHead> InitializedRpcChainState<C> {
    fn initialize(chain: C, deployment: ProtocolDeployment) -> Result<Self> {
        deployment.validate().map_err(|e| e.to_string())?;
        let state = RpcChainState { chain, deployment };
        let anchor = state.snapshot()?;
        Ok(Self {
            state,
            anchor,
            valid: AtomicBool::new(true),
        })
    }
    pub fn invalidate(&self) {
        self.valid.store(false, Ordering::SeqCst);
    }
    pub fn deployment_receipt_valid(&self) -> bool {
        self.valid.load(Ordering::SeqCst)
    }
    fn checked<T>(&self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.invalidate();
        }
        result
    }
    fn receipt_result<T>(&self, result: Result<T>) -> Result<T> {
        match result {
            Err(error) => {
                self.invalidate();
                Err(error)
            }
            Ok(value) if self.deployment_receipt_valid() => Ok(value),
            Ok(_) => Err("deployment receipt invalidated during read".into()),
        }
    }
    fn live_snapshot(&self) -> Result<CanonicalBlock> {
        if !self.deployment_receipt_valid() {
            return self.state.snapshot();
        }
        let block = self.state.chain.head().map_err(|e| e.to_string())?;
        if block.number < self.state.deployment.protocol.from_block {
            return Err("chain head predates deployment".into());
        }
        if self.state.chain.chain_id().map_err(|e| e.to_string())? != self.context().chain_id {
            return Err("chain identity changed".into());
        }
        self.state.canonical(&block)?;
        Ok(block)
    }
}
impl<C: CanonicalHead> ChainState for InitializedRpcChainState<C> {
    fn invalidate_initialization(&self) {
        self.invalidate();
    }

    fn self_contained_preparation_anchor(&self) -> Option<CanonicalBlock> {
        self.deployment_receipt_valid().then(|| self.anchor.clone())
    }

    fn preparation_deployment(&self) -> Option<ProtocolDeployment> {
        self.state.preparation_deployment()
    }
    fn context(&self) -> ProtocolContext {
        self.state.context()
    }
    fn snapshot(&self) -> Result<CanonicalBlock> {
        let initialized = self.deployment_receipt_valid();
        let result = self.live_snapshot();
        if initialized {
            self.receipt_result(result)
        } else {
            self.checked(result)
        }
    }
    fn submission_timestamp(&self) -> Result<u64> {
        self.snapshot().map(|b| b.timestamp)
    }
    fn canonical(&self, b: &CanonicalBlock) -> Result<()> {
        self.checked(self.state.canonical(b))
    }
    fn canonical_anchor(&self, n: u64, h: B256) -> Result<()> {
        self.checked(self.state.canonical_anchor(n, h))
    }
    fn known_root(&self, t: u64, r: B256, b: &CanonicalBlock) -> Result<bool> {
        self.checked(self.state.known_root(t, r, b))
    }
    fn nullifier_spent(&self, n: B256, b: &CanonicalBlock) -> Result<bool> {
        self.checked(self.state.nullifier_spent(n, b))
    }
    fn credit_status(&self, o: Address, t: Address, g: u128, b: &CanonicalBlock) -> Result<u8> {
        self.checked(self.state.credit_status(o, t, g, b))
    }
    fn token_balance_allowance(
        &self,
        o: Address,
        t: Address,
        b: &CanonicalBlock,
    ) -> Result<(U256, U256)> {
        self.checked(self.state.token_balance_allowance(o, t, b))
    }
    fn funding_nonce(&self, o: Address, b: &CanonicalBlock) -> Result<U256> {
        self.checked(self.state.funding_nonce(o, b))
    }
    fn public_signature_valid(
        &self,
        o: Address,
        d: B256,
        s: &[u8],
        b: &CanonicalBlock,
    ) -> Result<bool> {
        self.checked(self.state.public_signature_valid(o, d, s, b))
    }
    fn finality(&self) -> crate::rpc::ChainFinality {
        self.state.finality()
    }
    fn transaction_confirmation(&self, h: B256) -> Result<crate::rpc::TransactionConfirmation> {
        self.snapshot()?;
        self.checked(self.state.transaction_confirmation(h))
    }
    fn validate_submission_network(&self) -> Result<()> {
        if self.deployment_receipt_valid() {
            self.receipt_result(self.state.validate_submission_network())
        } else {
            self.state.validate_submission_network()
        }
    }
    fn delegated_network_fence(&self) -> Option<Result<()>> {
        if !self.deployment_receipt_valid() {
            return None;
        }
        Some(self.receipt_result(self.state.validate_submission_network()))
    }
    fn fresh_funding_nonce(&self, owner: Address) -> Option<Result<FreshFundingNonce>> {
        if !self.deployment_receipt_valid() {
            return None;
        }
        let mut data = keccak256("nonces(address)").as_slice()[..4].to_vec();
        data.extend_from_slice(&address_word(owner).to_be_bytes::<32>());
        let result = self
            .state
            .chain
            .latest_call(self.state.deployment.protocol.address, &data)?;
        Some(self.receipt_result((|| {
            let bytes = result.map_err(|e| e.to_string())?;
            if bytes.len() != 32 {
                return Err("invalid contract read width".into());
            }
            if self.state.chain.chain_id().map_err(|e| e.to_string())? != self.context().chain_id {
                return Err("chain identity changed".into());
            }
            Ok(FreshFundingNonce {
                context: self.context(),
                owner,
                nonce: U256::from_be_slice(&bytes),
            })
        })()))
    }
    fn self_contained_shield_capability(&self) -> Option<SelfContainedShieldCapability> {
        self.deployment_receipt_valid()
            .then(|| SelfContainedShieldCapability {
                context: self.context(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{CanonicalChain, ContractDeployment};
    use std::sync::atomic::{AtomicU64, AtomicUsize};
    struct Chain {
        id: AtomicU64,
        code: AtomicUsize,
        calls: AtomicUsize,
        nonce_base: AtomicUsize,
        hook: std::sync::Mutex<Option<Box<dyn Fn() + Send>>>,
    }
    fn block() -> CanonicalBlock {
        CanonicalBlock {
            number: 10,
            timestamp: 100,
            hash: B256::repeat_byte(10),
            parent_hash: B256::repeat_byte(9),
        }
    }
    impl CanonicalChain for Chain {
        fn latest_call(&self, a: Address, d: &[u8]) -> Option<crate::rpc::Result<Vec<u8>>> {
            Some(self.call(a, d, 10))
        }
        fn chain_id(&self) -> crate::rpc::Result<u64> {
            if let Some(hook) = self.hook.lock().unwrap().take() {
                hook();
            }
            Ok(self.id.load(Ordering::SeqCst))
        }
        fn block(&self, _: u64) -> crate::rpc::Result<CanonicalBlock> {
            Ok(block())
        }
        fn code_at(&self, _: Address, _: Option<u64>) -> crate::rpc::Result<Vec<u8>> {
            self.code.fetch_add(1, Ordering::SeqCst);
            Ok(vec![1])
        }
        fn call(&self, _: Address, _: &[u8], _: u64) -> crate::rpc::Result<Vec<u8>> {
            Ok(U256::from(
                self.nonce_base.load(Ordering::SeqCst) + self.calls.fetch_add(1, Ordering::SeqCst),
            )
            .to_be_bytes::<32>()
            .to_vec())
        }
    }
    impl CanonicalHead for Chain {
        fn head(&self) -> crate::rpc::Result<CanonicalBlock> {
            Ok(block())
        }
    }
    fn initialized() -> InitializedRpcChainState<Chain> {
        InitializedRpcChainState::initialize(
            Chain {
                id: 31337.into(),
                code: 0.into(),
                calls: 0.into(),
                nonce_base: 0.into(),
                hook: Default::default(),
            },
            ProtocolDeployment {
                chain_id: "31337".into(),
                protocol: ContractDeployment {
                    address: Address::repeat_byte(1),
                    runtime_code_hash: keccak256([1]),
                    from_block: 1,
                },
                registry: None,
                broadcaster_registry: None,
            },
        )
        .unwrap()
    }
    #[test]
    fn initialized_broadcasters_reuse_support_only_for_bound_reader_token_and_receipt() {
        struct SupportTransport {
            calls: Arc<AtomicUsize>,
            retire: Option<std::sync::Weak<InitializedRpcChainState<Chain>>>,
        }
        impl crate::rpc::RpcTransport for SupportTransport {
            fn send(&self, request: &Value) -> crate::rpc::Result<Value> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if let Some(state) = self.retire.as_ref().and_then(std::sync::Weak::upgrade) {
                    state.invalidate();
                }
                assert_eq!(request["method"], "broadcaster_getTokenSupport");
                Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":{
                    "apiVersion":"v1","protocolVersion":"1","chainId":"31337","protocol":Address::repeat_byte(1),"sender":Address::repeat_byte(3),"feeRecipient":Address::repeat_byte(4),
                    "tokenAddress":request["params"][0]["tokenAddress"],"supported":true,"submissionHalted":false,"provenance":{"enabled":false}
                }}))
            }
        }
        let state = Arc::new(initialized());
        let chain: Arc<dyn ChainState> = state.clone();
        let token = Address::repeat_byte(2);
        let calls = Arc::new(AtomicUsize::new(0));
        let client = invisi_sdk_rpc::broadcaster::BroadcasterClient::new(
            invisi_sdk_rpc::broadcaster::Configuration {
                endpoint: "https://relay.example".into(),
                quote_signer: Address::repeat_byte(3),
                fee_recipient: Address::repeat_byte(4),
            },
            SupportTransport {
                calls: calls.clone(),
                retire: None,
            },
        )
        .unwrap();
        let pool = InitializedBroadcasters::configured(client, chain.clone(), token).unwrap();
        assert_eq!(pool.clients_for(&chain, token).unwrap().len(), 1);
        assert_eq!(pool.clients_for(&chain, token).unwrap().len(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(pool.clients_for(&chain, Address::repeat_byte(9)).is_none());
        let foreign: Arc<dyn ChainState> = Arc::new(initialized());
        assert!(pool.clients_for(&foreign, token).is_none());
        state.invalidate();
        assert!(pool.clients_for(&chain, token).is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let state = Arc::new(initialized());
        let chain: Arc<dyn ChainState> = state.clone();
        let client = invisi_sdk_rpc::broadcaster::BroadcasterClient::new(
            invisi_sdk_rpc::broadcaster::Configuration {
                endpoint: "https://relay.example".into(),
                quote_signer: Address::repeat_byte(3),
                fee_recipient: Address::repeat_byte(4),
            },
            SupportTransport {
                calls: calls.clone(),
                retire: Some(Arc::downgrade(&state)),
            },
        )
        .unwrap();
        assert!(
            InitializedBroadcasters::configured(client, chain, token).is_err(),
            "retired support probe must not publish"
        );
    }
    #[test]
    fn unquoted_manual_authorization_keeps_current_nonce_validation() {
        let state = Arc::new(initialized());
        let wallet = Wallet::from_keys(Address::repeat_byte(2), test_receiving_keys()).unwrap();
        let token = Address::repeat_byte(3);
        let output =
            NoteOutput::for_recipient(state.context(), token, &wallet, U256::from(30), Vec::new())
                .unwrap();
        let prepared = Invisi::new(state.clone())
            .prepare_shield(
                &wallet,
                ShieldPreparation {
                    token,
                    outputs: vec![output],
                    funding: abi::FundingParams {
                        payer: wallet.owner_address(),
                        amount: U256::from(30),
                        deadline: U256::from(200),
                        ..empty_funding()
                    },
                    fee: Fee::default(),
                    deadline: 200,
                },
            )
            .unwrap();
        assert_eq!(state.state.chain.calls.load(Ordering::SeqCst), 0);
        prepared
            .export_funding_authorization(state.as_ref())
            .unwrap();
        assert_eq!(state.state.chain.calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn in_flight_network_nonce_and_snapshot_reads_reject_retired_receipt() {
        for mode in ["network", "nonce", "snapshot"] {
            let state = Arc::new(initialized());
            let weak = Arc::downgrade(&state);
            *state.state.chain.hook.lock().unwrap() =
                Some(Box::new(move || weak.upgrade().unwrap().invalidate()));
            let error = match mode {
                "network" => state.delegated_network_fence().unwrap().unwrap_err(),
                "nonce" => state
                    .fresh_funding_nonce(Address::repeat_byte(2))
                    .unwrap()
                    .unwrap_err(),
                _ => state.snapshot().unwrap_err(),
            };
            assert!(error.contains("invalidated during read"), "{mode}: {error}");
            assert!(!state.deployment_receipt_valid());
            state.snapshot().unwrap(); // A subsequent operation uses full validation.
        }
    }
    use invisi_sdk_rpc::broadcaster::{
        Configuration, Execution, Fee as RelayFee, Quote, SignedQuote, Trust,
    };
    #[derive(Default)]
    struct QuoteTransport {
        requests: Arc<std::sync::Mutex<Vec<Value>>>,
        submissions: Arc<AtomicUsize>,
        lose_first_submit: bool,
    }
    fn config() -> Configuration {
        let key = k256::ecdsa::SigningKey::from_slice(&[17; 32]).unwrap();
        let public = key.verifying_key().to_encoded_point(false);
        Configuration {
            endpoint: "https://relay.example".into(),
            quote_signer: Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]),
            fee_recipient: Address::repeat_byte(4),
        }
    }
    impl crate::rpc::RpcTransport for QuoteTransport {
        fn send(&self, request: &Value) -> crate::rpc::Result<Value> {
            self.requests.lock().unwrap().push(request.clone());
            let result = if request["method"] == "broadcaster_estimateQuote" {
                json!(RelayFee {
                    fee_recipient: config().fee_recipient,
                    fee_amount: "2".into(),
                    max_gas: "100000".into()
                })
            } else if request["method"] == "broadcaster_getTokenSupport"
                || request["method"] == "broadcaster_getStatus"
            {
                json!({"apiVersion":"v1","protocolVersion":"1","chainId":"31337","protocol":Address::repeat_byte(1),"sender":config().quote_signer,"feeRecipient":config().fee_recipient,"tokenAddress":request["params"][0]["tokenAddress"],"supported":true,"submissionHalted":false,"provenance":{"enabled":false}})
            } else if request["method"] == "broadcaster_submitTransaction" {
                let attempt = self.submissions.fetch_add(1, Ordering::SeqCst);
                if self.lose_first_submit && attempt == 0 {
                    return Err(crate::rpc::Error::Transport(
                        "lost synthetic relay response".into(),
                    ));
                }
                json!({"id":"pool-frozen","state":"pending"})
            } else if request["method"] == "broadcaster_getTransactionStatus" {
                json!({"id":"pool-frozen","state":"pending"})
            } else {
                assert_eq!(request["method"], "broadcaster_getQuote");
                let data = hex_bytes(request["params"][0]["data"].as_str().unwrap(), None).unwrap();
                let intent = invisi_sdk_rpc::broadcaster::decode_intent(&data).unwrap();
                let quote = Quote {
                    schedule: None,
                    execution: Execution::Direct,
                    token: intent.token,
                    fee_recipient: intent.fee_recipient,
                    fee_amount: intent.fee_amount.to_string(),
                    deadline: intent.deadline.to_string(),
                    max_gas: "100000".into(),
                    request_hash: invisi_sdk_rpc::broadcaster::request_hash(&data).unwrap(),
                };
                let trust = Trust {
                    chain_id: 31337,
                    protocol: Address::repeat_byte(1),
                    signer: config().quote_signer,
                };
                let key = k256::ecdsa::SigningKey::from_slice(&[17; 32]).unwrap();
                let (sig, r) = key
                    .sign_prehash_recoverable(
                        invisi_sdk_rpc::broadcaster::quote_digest(&quote, &trust)
                            .unwrap()
                            .as_slice(),
                    )
                    .unwrap();
                let mut signature = sig.to_bytes().to_vec();
                signature.push(r.to_byte());
                json!(SignedQuote {
                    quote,
                    signature: hex(&signature),
                    request_hash_format: None,
                    provenance_required: None
                })
            };
            Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
        }
    }
    #[test]
    fn signature_prepare_selects_current_nonce_and_explicit_prerequisite_is_payer_bound() {
        let state = Arc::new(initialized());
        state.state.chain.nonce_base.store(7, Ordering::SeqCst);
        let chain: Arc<dyn ChainState> = state.clone();
        let wallet = Wallet::from_keys(Address::repeat_byte(2), test_receiving_keys()).unwrap();
        let token = Address::repeat_byte(3);
        let deadline = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let output =
            NoteOutput::for_recipient(state.context(), token, &wallet, U256::from(30), Vec::new())
                .unwrap();
        let prepared = Invisi::new(chain.clone())
            .prepare_shield_with_signature_funding(
                &wallet,
                ShieldPreparation {
                    token,
                    outputs: vec![output],
                    funding: abi::FundingParams {
                        payer: wallet.owner_address(),
                        amount: U256::from(30),
                        deadline: U256::from(deadline),
                        ..empty_funding()
                    },
                    fee: Fee::default(),
                    deadline,
                },
                SignatureFundingNonce::Current,
            )
            .unwrap();
        assert_eq!(
            prepared.funding().sigNonce,
            U256::from(7),
            "nonce is selected before quote"
        );
        let relay = Arc::new(
            invisi_sdk_rpc::broadcaster::BroadcasterClient::new(
                config(),
                QuoteTransport::default(),
            )
            .unwrap(),
        );
        let options = BroadcasterOptions {
            max_fee_amount: Some(U256::from(10)),
            ..Default::default()
        };
        let quoted = prepared
            .quote_for_broadcaster(chain.clone(), relay.clone(), &options)
            .unwrap();
        assert_eq!(
            quoted.funding().sigNonce,
            U256::from(7),
            "legacy nonzero deadline/default nonce must still select current nonce"
        );
        assert_eq!(state.state.chain.calls.load(Ordering::SeqCst), 1);
        let fresh = state
            .fresh_funding_nonce(wallet.owner_address())
            .unwrap()
            .unwrap();
        let selected = prepared
            .clone()
            .with_fresh_funding_nonce(fresh, deadline)
            .unwrap();
        let calls = state.state.chain.calls.load(Ordering::SeqCst);
        let quoted = selected
            .quote_for_broadcaster(chain.clone(), relay.clone(), &options)
            .unwrap();
        assert_eq!(quoted.funding().sigNonce, U256::from(8));
        assert_eq!(
            state.state.chain.calls.load(Ordering::SeqCst),
            calls,
            "explicit prerequisite must not be reread while quoting"
        );
        let permitted = prepared
            .clone()
            .quote_for_broadcaster(
                chain,
                relay,
                &BroadcasterOptions {
                    funding_permit: Some(Arc::new(move |_| {
                        Ok(crate::protocol::IMetaTx::TokenPermit {
                            deadline: U256::from(deadline),
                            v: 27,
                            r: B256::repeat_byte(1),
                            s: B256::repeat_byte(2),
                        })
                    })),
                    ..options.clone()
                },
            )
            .unwrap();
        assert!(
            permitted.selected_funding_terms && !permitted.self_contained_shield(),
            "permit must retain conservative authorization policy"
        );
        let snapshot = ManagedPrepared::snapshot_funds(&permitted)
            .snapshot()
            .unwrap();
        snapshot
            .restore(&wallet, None)
            .expect("permit fallback must retain normal journal restoration");
        let wrong = state
            .fresh_funding_nonce(Address::repeat_byte(9))
            .unwrap()
            .unwrap();
        assert!(prepared.with_fresh_funding_nonce(wrong, deadline).is_err());
    }
    #[test]
    fn current_exact_zero_and_caller_funding_are_distinct() {
        let state = Arc::new(initialized());
        let chain: Arc<dyn ChainState> = state.clone();
        let runtime = Invisi::new(chain.clone());
        let wallet = Wallet::from_keys(Address::repeat_byte(2), test_receiving_keys()).unwrap();
        let token = Address::repeat_byte(3);
        let deadline = preparation::QuoteClock::wall_seconds().unwrap() + 3600;
        let options = ShieldPreparation {
            token,
            outputs: vec![NoteOutput::for_recipient(
                state.context(),
                token,
                &wallet,
                U256::from(30),
                vec![],
            )
            .unwrap()],
            funding: abi::FundingParams {
                payer: wallet.owner_address(),
                amount: U256::from(30),
                ..empty_funding()
            },
            fee: Fee::default(),
            deadline,
        };
        let raw = runtime.prepare_shield(&wallet, options.clone()).unwrap();
        let relay = Arc::new(
            invisi_sdk_rpc::broadcaster::BroadcasterClient::new(
                config(),
                QuoteTransport::default(),
            )
            .unwrap(),
        );
        assert!(raw
            .quote_for_broadcaster(
                chain,
                relay,
                &BroadcasterOptions {
                    max_fee_amount: Some(U256::from(10)),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .starts_with(NEEDS_REPREPARATION));
        assert_eq!(state.state.chain.calls.load(Ordering::SeqCst), 0);
        let exact = runtime
            .prepare_shield_with_signature_funding(
                &wallet,
                options.clone(),
                SignatureFundingNonce::Exact(U256::ZERO),
            )
            .unwrap();
        assert_eq!(exact.funding().sigNonce, U256::ZERO);
        state.state.chain.nonce_base.store(6, Ordering::SeqCst);
        assert!(runtime
            .prepare_shield_with_signature_funding(
                &wallet,
                options.clone(),
                SignatureFundingNonce::Exact(U256::ZERO)
            )
            .is_err());
        for _ in 0..2 {
            let before = state.state.chain.calls.load(Ordering::SeqCst);
            let current = runtime
                .prepare_shield_with_signature_funding(
                    &wallet,
                    options.clone(),
                    SignatureFundingNonce::Current,
                )
                .unwrap();
            assert_eq!(current.funding().sigNonce, U256::from(6 + before));
            assert_eq!(state.state.chain.calls.load(Ordering::SeqCst), before + 1);
        }
    }
    #[test]
    fn retired_pool_preserves_authenticated_unknown_replay_and_known_status_only() {
        let state = Arc::new(initialized());
        let chain: Arc<dyn ChainState> = state.clone();
        let key = k256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        let public = key.verifying_key().to_encoded_point(false);
        let owner = Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]);
        let wallet = Wallet::from_keys(owner, test_receiving_keys()).unwrap();
        let token = Address::repeat_byte(3);
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let rpc = invisi_sdk_rpc::broadcaster::BroadcasterClient::new(
            config(),
            QuoteTransport {
                requests: requests.clone(),
                lose_first_submit: true,
                ..Default::default()
            },
        )
        .unwrap();
        let pool = InitializedBroadcasters::configured(rpc, chain.clone(), token).unwrap();
        let deadline = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let output =
            NoteOutput::for_recipient(state.context(), token, &wallet, U256::from(30), Vec::new())
                .unwrap();
        let mut target = Invisi::new(chain.clone())
            .prepare_shield_with_signature_funding(
                &wallet,
                ShieldPreparation {
                    token,
                    outputs: vec![output],
                    funding: abi::FundingParams {
                        payer: owner,
                        amount: U256::from(30),
                        ..empty_funding()
                    },
                    fee: Fee::default(),
                    deadline,
                },
                SignatureFundingNonce::Current,
            )
            .unwrap();
        pool.quote(
            &mut target,
            chain.clone(),
            &BroadcasterOptions {
                max_fee_amount: Some(U256::from(10)),
                ..Default::default()
            },
        )
        .unwrap();
        let request = target.export_funding_authorization(chain.as_ref()).unwrap();
        let (sig, r) = key
            .sign_prehash_recoverable(request.digest.as_slice())
            .unwrap();
        let mut signature = sig.to_bytes().to_vec();
        signature.push(r.to_byte());
        target = target
            .with_funding_signature(chain.as_ref(), signature)
            .unwrap()
            .ready()
            .unwrap();
        let mut fresh = target.clone();
        fresh.export_transaction().unwrap();
        assert!(pool
            .submit(&mut target, chain.as_ref())
            .unwrap_err()
            .contains("lost synthetic relay response"));
        let first = requests
            .lock()
            .unwrap()
            .iter()
            .find(|r| r["method"] == "broadcaster_submitTransaction")
            .unwrap()["params"]
            .clone();
        pool.invalidate();
        state.state.chain.id.store(1, Ordering::SeqCst);
        *state.state.chain.hook.lock().unwrap() =
            Some(Box::new(|| panic!("frozen retry must not read network")));
        let before = requests.lock().unwrap().len();
        assert!(pool
            .submit(&mut fresh, chain.as_ref())
            .unwrap_err()
            .contains("retired"));
        assert_eq!(
            requests.lock().unwrap().len(),
            before,
            "ordinary export is not frozen relay authority"
        );
        assert_eq!(
            pool.submit(&mut target, chain.as_ref()).unwrap().id,
            "pool-frozen"
        );
        let sent = requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r["method"] == "broadcaster_submitTransaction")
            .map(|r| r["params"].clone())
            .collect::<Vec<_>>();
        assert_eq!(sent, vec![first.clone(), first]);
        let before = requests.lock().unwrap().len();
        assert_eq!(
            pool.submit(&mut target, chain.as_ref()).unwrap().id,
            "pool-frozen"
        );
        let after = requests.lock().unwrap();
        assert_eq!(after.len(), before + 1);
        assert_eq!(
            after.last().unwrap()["method"],
            "broadcaster_getTransactionStatus"
        );
        drop(after);
        let before = requests.lock().unwrap().len();
        let mut wrong_endpoint = target.clone();
        wrong_endpoint.broadcaster.as_mut().unwrap().endpoint = "https://foreign.example".into();
        assert!(pool
            .submit(&mut wrong_endpoint, chain.as_ref())
            .unwrap_err()
            .contains("not owned"));
        let mut changed = target.clone();
        let mut signature = changed.funding().signature.to_vec();
        signature[0] ^= 1;
        changed.funding_mut().signature = signature.into();
        assert!(pool.submit(&mut changed, chain.as_ref()).is_err());
        assert_eq!(requests.lock().unwrap().len(), before);
        assert!(state.state.chain.hook.lock().unwrap().is_some());
    }
    #[test]
    fn submission_binding_rejects_retired_receipt_even_if_full_validation_succeeds() {
        let state = initialized();
        let original = SubmissionNetworkBinding::capture(&state, state.context()).unwrap();
        state.invalidate();
        state.snapshot().unwrap();
        assert!(original
            .check(&state)
            .unwrap_err()
            .contains("receipt invalidated"));
    }
    #[test]
    fn entry_and_final_network_fences_reject_wrong_network_and_retire_receipt() {
        for wrong_at_entry in [true, false] {
            let state = initialized();
            if !wrong_at_entry {
                state.delegated_network_fence().unwrap().unwrap();
            }
            state.state.chain.id.store(1, Ordering::SeqCst);
            assert!(state
                .delegated_network_fence()
                .unwrap()
                .unwrap_err()
                .contains("identity changed"));
            assert!(state.delegated_network_fence().is_none());
            assert!(!state.deployment_receipt_valid());
        }
    }
    #[test]
    fn immutable_receipt_reuses_code_but_invalidation_restores_full_validation() {
        let state = initialized();
        assert_eq!(state.state.chain.code.load(Ordering::SeqCst), 1);
        state.snapshot().unwrap();
        state.snapshot().unwrap();
        assert_eq!(state.state.chain.code.load(Ordering::SeqCst), 1);
        state.invalidate();
        assert!(state.self_contained_shield_capability().is_none());
        assert!(state.fresh_funding_nonce(Address::repeat_byte(2)).is_none());
        state.snapshot().unwrap();
        state.snapshot().unwrap();
        assert_eq!(state.state.chain.code.load(Ordering::SeqCst), 3);
    }
    #[test]
    fn wrong_network_retires_receipt_even_if_network_returns() {
        let state = initialized();
        state.state.chain.id.store(1, Ordering::SeqCst);
        assert!(state.snapshot().unwrap_err().contains("identity changed"));
        assert!(!state.deployment_receipt_valid());
        state.state.chain.id.store(31337, Ordering::SeqCst);
        state.snapshot().unwrap();
        assert_eq!(state.state.chain.code.load(Ordering::SeqCst), 2);
    }
    #[test]
    fn authorization_nonce_is_live_and_network_bound() {
        let state = initialized();
        let payer = Address::repeat_byte(2);
        let first = state.fresh_funding_nonce(payer).unwrap().unwrap();
        let second = state.fresh_funding_nonce(payer).unwrap().unwrap();
        assert_eq!(first.nonce, U256::ZERO);
        assert_eq!(second.nonce, U256::from(1));
        assert_eq!(second.context, state.context());
        state.state.chain.id.store(1, Ordering::SeqCst);
        assert!(state.fresh_funding_nonce(payer).unwrap().is_err());
        assert!(state.fresh_funding_nonce(payer).is_none());
    }
}
