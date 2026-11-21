use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{SolCall, SolValue};
use invisi_sdk_payment_router::*;
use invisi_sdk_protocol::protocol::TransactionCall;
use serde_json::Value;
use std::sync::{Arc, Mutex};
fn a(n: u8) -> Address {
    Address::repeat_byte(n)
}
fn dep() -> PaymentRouterDeployment {
    PaymentRouterDeployment {
        chain_id: 31337,
        core_address: a(0x11),
        router_address: a(0x33),
        weth_address: a(0x44),
        uniswap_router_address: a(0x55),
        runtime_code_hash: None,
        zero_ex: Some(ZeroExDeployment {
            allowance_holder_address: a(0x77),
            settler_registry_address: a(0x88),
        }),
    }
}
#[derive(Default)]
struct State {
    now: u64,
    chain_id: Option<u64>,
    quoter_inputs: Vec<Option<U256>>,
    settler: Option<Address>,
    core: Option<Address>,
    reorg: bool,
    missing_code: bool,
    fail: bool,
    spent: Option<U256>,
    expected_sender: Option<Address>,
    account_payer: Option<Address>,
    wrong_delegation: bool,
    revoked_delegation: bool,
    eoa_nonce: u64,
    calls: Vec<(TransactionCall, Option<Address>, u64)>,
}
struct Provider(Mutex<State>);
impl Provider {
    fn new() -> Arc<Self> {
        Arc::new(Self(Mutex::new(State {
            now: 1000,
            ..Default::default()
        })))
    }
}
impl RouterProvider for Provider {
    fn nonce_at(&self, target: Address, block: u64) -> BoxFuture<'_, Result<u64>> {
        Box::pin(async move {
            let state = self.0.lock().unwrap();
            assert_eq!(Some(target), state.account_payer);
            assert_eq!(block, 10);
            Ok(state.eoa_nonce)
        })
    }

    fn call_authorized<'a>(
        &'a self,
        call: TransactionCall,
        from: Address,
        block: u64,
        _auth: &'a [canonical::SignedAuthorization],
    ) -> BoxFuture<'a, Result<Vec<u8>>> {
        self.call(call, Some(from), block)
    }
    fn estimate_gas_authorized<'a>(
        &'a self,
        call: TransactionCall,
        from: Address,
        block: u64,
        _auth: &'a [canonical::SignedAuthorization],
    ) -> BoxFuture<'a, Result<U256>> {
        self.estimate_gas(call, from, block)
    }

    fn storage_at(&self, target: Address, slot: B256, block: u64) -> BoxFuture<'_, Result<B256>> {
        Box::pin(async move {
            assert_eq!(Some(target), self.0.lock().unwrap().account_payer);
            assert_eq!(block, 10);
            let expected = U256::from_be_slice(
                alloy_primitives::keccak256("invisi.payment-router.account.storage.v1").as_slice(),
            ) - U256::from(1);
            assert_eq!(slot, B256::from(expected.to_be_bytes::<32>()));
            Ok(B256::from(U256::from(9).to_be_bytes::<32>()))
        })
    }

    fn chain_id(&self) -> BoxFuture<'_, Result<u64>> {
        Box::pin(async { Ok(self.0.lock().unwrap().chain_id.unwrap_or(31337)) })
    }
    fn block(&self, n: Option<u64>) -> BoxFuture<'_, Result<RouterBlock>> {
        Box::pin(async move {
            let s = self.0.lock().unwrap();
            Ok(RouterBlock {
                number: 10,
                timestamp: s.now,
                hash: B256::repeat_byte(if n.is_some() && s.reorg { 1 } else { 0xab }),
            })
        })
    }
    fn code(&self, target: Address, b: u64) -> BoxFuture<'_, Result<Vec<u8>>> {
        Box::pin(async move {
            assert_eq!(b, 10);
            let state = self.0.lock().unwrap();
            if state.account_payer == Some(target) {
                if state.revoked_delegation {
                    return Ok(vec![]);
                }
                let mut code = vec![0xef, 0x01, 0x00];
                code.extend_from_slice(
                    a(if state.wrong_delegation { 0xdd } else { 0xcc }).as_slice(),
                );
                return Ok(code);
            }
            Ok(if state.missing_code {
                vec![]
            } else {
                vec![0x60, 0]
            })
        })
    }
    fn call(
        &self,
        c: TransactionCall,
        from: Option<Address>,
        b: u64,
    ) -> BoxFuture<'_, Result<Vec<u8>>> {
        Box::pin(async move {
            assert_eq!(b, 10);
            let mut s = self.0.lock().unwrap();
            s.calls.push((c.clone(), from, b));
            let selector = &c.data[..4];
            for (name, value) in [
                ("core()", s.core.unwrap_or(a(0x11))),
                ("dex()", a(0x55)),
                ("weth()", a(0x44)),
                ("allowanceHolder()", a(0x77)),
                ("settlerRegistry()", a(0x88)),
                ("ownerOf(uint256)", s.settler.unwrap_or(a(0x66))),
            ] {
                if selector == &alloy_primitives::keccak256(name)[..4] {
                    return Ok((value,).abi_encode_params());
                }
            }
            if s.account_payer.is_some() {
                if selector == &alloy_primitives::keccak256("implementation()")[..4] {
                    return Ok(a(0xcc).abi_encode());
                }
                if selector == &alloy_primitives::keccak256("router()")[..4] {
                    return Ok(a(0x33).abi_encode());
                }
                if selector == &alloy_primitives::keccak256("routerCodeHash()")[..4] {
                    return Ok(alloy_primitives::keccak256([0x60, 0]).abi_encode());
                }
                if selector == &alloy_primitives::keccak256("nonce()")[..4] {
                    return Ok(U256::from(3).abi_encode());
                }
            }
            if selector == &alloy_primitives::keccak256("nonces(address)")[..4] {
                return Ok(U256::from(7).abi_encode());
            }
            if selector == &alloy_primitives::keccak256("CHAIN_ID()")[..4] {
                return Ok((U256::from(31337),).abi_encode_params());
            }
            if selector == abi::quoteExactOutputCall::SELECTOR {
                let amount = if s.quoter_inputs.is_empty() {
                    U256::from(60)
                } else {
                    s.quoter_inputs
                        .remove(0)
                        .ok_or(Error::Provider("route reverted".into()))?
                };
                return Ok((
                    amount,
                    Vec::<alloy_primitives::aliases::U160>::new(),
                    Vec::<u32>::new(),
                    U256::from(80000),
                )
                    .abi_encode_params());
            }
            if s.fail {
                return Err(Error::Provider("payment reverted".into()));
            }
            Ok((s.spent.unwrap_or(U256::from(60)),).abi_encode_params())
        })
    }
    fn estimate_gas(
        &self,
        c: TransactionCall,
        from: Address,
        b: u64,
    ) -> BoxFuture<'_, Result<U256>> {
        Box::pin(async move {
            assert_eq!(
                from,
                self.0.lock().unwrap().expected_sender.unwrap_or(a(0xaa))
            );
            assert_eq!(b, 10);
            assert_eq!(
                c.to,
                self.0.lock().unwrap().account_payer.unwrap_or(a(0x33))
            );
            Ok(U256::from(123456))
        })
    }
}
fn vector() -> Value {
    serde_json::from_str(include_str!("fixtures/payment-router-vectors.json")).unwrap()
}
fn addr(v: &Value) -> Address {
    v.as_str().unwrap().parse().unwrap()
}
fn num(v: &Value) -> U256 {
    U256::from_str_radix(v.as_str().unwrap(), 10).unwrap()
}
fn data(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
}
fn quote(v: &Value) -> SwapQuote {
    SwapQuote {
        chain_id: 31337,
        router_address: addr(&v["routerAddress"]),
        token_out: addr(&v["tokenOut"]),
        amount_out: num(&v["amountOut"]),
        estimated_input: num(&v["estimatedInput"]),
        max_input: num(&v["maxInput"]),
        deadline: v["deadline"].as_str().unwrap().parse().unwrap(),
        route: if v["channel"] == "uniswap-v3" {
            SwapRoute::UniswapV3 {
                reverse_path: data(&v["reversePath"]),
            }
        } else {
            SwapRoute::ZeroEx {
                target: addr(&v["target"]),
                data: data(&v["data"]),
                settler_address: addr(&v["settlerAddress"]),
            }
        },
    }
}
fn payment(v: &Value) -> TransactionCall {
    TransactionCall {
        to: addr(&v["to"]),
        data: data(&v["data"]),
        value: num(&v["value"]),
    }
}
fn opts() -> QuoteParameters {
    QuoteParameters {
        token_out: a(0x22),
        amount_out: U256::from(10),
        max_input: U256::from(101),
        deadline: 1100,
        slippage_bps: Some(100),
        cancellation: None,
    }
}
#[tokio::test]
async fn shared_full_calls_build_and_simulate_exactly() {
    let v = vector();
    let p = Provider::new();
    let c = PaymentRouterClient::new(dep(), p.clone()).unwrap();
    for case in v["payments"].as_array().unwrap() {
        let call = c
            .build_payment_transaction(payment(&v["corePayment"]), quote(&case["quote"]), a(0xaa))
            .await
            .unwrap();
        assert_eq!(call, payment(&case["expected"]), "{}", case["name"]);
        let result = c.simulate_payment(call.clone(), a(0xaa)).await.unwrap();
        assert_eq!(result.eth_spent, num(&case["simulation"]["ethSpent"]));
        assert_eq!(result.eth_refunded, num(&case["simulation"]["ethRefunded"]));
        assert_eq!(result.gas_estimate, num(&case["simulation"]["gasEstimate"]));
        assert!(p
            .0
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|(x, from, block)| x == &call && *from == Some(a(0xaa)) && *block == 10));
    }
}
#[tokio::test]
async fn builder_rejects_funding_shapes_deadlines_deployment_and_refunds() {
    let v = vector();
    let p = Provider::new();
    let c = PaymentRouterClient::new(dep(), p.clone()).unwrap();
    let q = quote(&v["payments"][0]["quote"]);
    let pay = payment(&v["corePayment"]);
    for n in 0..13 {
        let mut call = pay.clone();
        let mut raw =
            invisi_sdk_protocol::protocol::InvisiCore::transact_0Call::abi_decode_validate(
                &call.data,
            )
            .unwrap();
        match n {
            0 => raw.r.funding.payer = a(0xaa),
            1 => raw.r.funding.amount = U256::from(11),
            2 => raw.r.funding.sigNonce = U256::from(1),
            3 => raw.r.funding.permit.v = 1,
            4 => raw.r.params.noteCommitments.pop().map(|_| ()).unwrap(),
            5 => raw.r.params.noteCommitments[1] = raw.r.params.noteCommitments[0],
            6 => {
                raw.r.deliveries.pop();
            }
            7 => raw.r.params.feeAmount = U256::from(1),
            8 => raw.r.params.deadline = U256::from(1099),
            9 => raw.r.params.withdrawalAmount = U256::from(1),
            10 => raw._0 = vec![].into(),
            11 => raw.r.funding.amount = U256::from(1) << 128,
            12 => raw.r.deliveries[0].clue = vec![0; 68].into(),
            _ => unreachable!(),
        }
        call.data = raw.abi_encode();
        assert!(
            c.build_payment_transaction(call, q.clone(), a(0xaa))
                .await
                .is_err(),
            "case {n}"
        );
    }
    for recipient in [Address::ZERO, dep().router_address] {
        assert!(c
            .build_payment_transaction(pay.clone(), q.clone(), recipient)
            .await
            .is_err());
    }
    p.0.lock().unwrap().core = Some(a(0x55));
    assert!(c
        .build_payment_transaction(pay.clone(), q.clone(), a(0xaa))
        .await
        .is_err());
    p.0.lock().unwrap().core = None;
    p.0.lock().unwrap().reorg = true;
    assert!(c
        .build_payment_transaction(pay.clone(), q.clone(), a(0xaa))
        .await
        .is_err());
    p.0.lock().unwrap().reorg = false;
    p.0.lock().unwrap().missing_code = true;
    assert!(c.build_payment_transaction(pay, q, a(0xaa)).await.is_err());
}
#[tokio::test]
async fn v3_rounding_and_full_simulation_revert_budget_and_sender() {
    let p = Provider::new();
    let c = PaymentRouterClient::new(dep(), p.clone()).unwrap();
    let adapter = UniswapV3Adapter::new(
        p.clone(),
        a(0x99),
        vec![V3Route {
            tokens: vec![a(0x44), a(0x22)],
            fees: vec![3000],
        }],
    )
    .unwrap();
    let q = c.quote(&adapter, opts()).await.unwrap();
    assert_eq!(q.max_input, U256::from(61));
    let mut low = opts();
    low.max_input = U256::from(60);
    assert!(c.quote(&adapter, low).await.is_err());
    let call = c
        .build_payment_transaction(payment(&vector()["corePayment"]), q, a(0xaa))
        .await
        .unwrap();
    assert!(c
        .simulate_payment(call.clone(), Address::ZERO)
        .await
        .is_err());
    p.0.lock().unwrap().fail = true;
    assert!(c
        .simulate_payment(call.clone(), a(0xaa))
        .await
        .unwrap_err()
        .to_string()
        .contains("reverted"));
    p.0.lock().unwrap().fail = false;
    p.0.lock().unwrap().spent = Some(U256::from(62));
    assert!(c.simulate_payment(call, a(0xaa)).await.is_err());
}
#[tokio::test]
async fn async_quote_rejects_rotation_expiry_cancellation_and_callback_budget_changes() {
    for mode in 0..4 {
        let p = Provider::new();
        let c = PaymentRouterClient::new(dep(), p.clone()).unwrap();
        let token = CancellationToken::default();
        let t = token.clone();
        let chain = p.clone();
        let v = vector();
        let q = quote(&v["payments"][1]["quote"]);
        let adapter = ZeroExAdapter::new(move |r: SwapQuoteRequest| {
            let p = chain.clone();
            let t = t.clone();
            let mut q = q.clone();
            Box::pin(async move {
                let mut r = r;
                match mode {
                    0 => p.0.lock().unwrap().settler = Some(a(0x55)),
                    1 => p.0.lock().unwrap().now = 1101,
                    2 => t.cancel(),
                    3 => {
                        r.parameters.max_input = U256::from(1000);
                        q.max_input = r.parameters.max_input;
                    }
                    _ => (),
                };
                Ok(
                    serde_json::json!({"liquidityAvailable":true,"buyToken":q.token_out,"buyAmount":"10","sellToken":NATIVE_TOKEN,"maxSellAmount":q.max_input.to_string(),"sellAmount":"60","transaction":{"to":a(0x66),"value":q.max_input.to_string(),"data":format!("0x{}",hex::encode(match q.route {SwapRoute::ZeroEx {data,..}=>data,_=>unreachable!()}))}}),
                )
            })
        });
        let mut options = opts();
        options.cancellation = Some(token);
        assert!(c.quote(&adapter, options).await.is_err(), "mode {mode}");
    }
}

struct PreparationChain;
impl invisi_sdk::sdk::ChainState for PreparationChain {
    fn context(&self) -> invisi_sdk::note::ProtocolContext {
        invisi_sdk::note::ProtocolContext {
            chain_id: 31337,
            protocol_address: invisi_sdk::sdk::address_word(a(0x11)),
        }
    }
    fn snapshot(
        &self,
    ) -> std::result::Result<invisi_sdk_protocol::interfaces::CanonicalBlock, String> {
        Ok(invisi_sdk_protocol::interfaces::CanonicalBlock {
            number: 10,
            hash: B256::repeat_byte(0xab),
            parent_hash: B256::ZERO,
            timestamp: 1000,
        })
    }
    fn canonical(
        &self,
        _: &invisi_sdk_protocol::interfaces::CanonicalBlock,
    ) -> std::result::Result<(), String> {
        Ok(())
    }
    fn known_root(
        &self,
        _: u64,
        _: B256,
        _: &invisi_sdk_protocol::interfaces::CanonicalBlock,
    ) -> std::result::Result<bool, String> {
        panic!("pure funding has no root reads")
    }
    fn nullifier_spent(
        &self,
        _: B256,
        _: &invisi_sdk_protocol::interfaces::CanonicalBlock,
    ) -> std::result::Result<bool, String> {
        panic!("pure funding has no nullifier reads")
    }
    fn credit_revoked(
        &self,
        _: Address,
        _: Address,
        _: u64,
        _: u16,
        _: &invisi_sdk_protocol::interfaces::CanonicalBlock,
    ) -> std::result::Result<bool, String> {
        panic!("pure funding has no credit reads")
    }
    fn token_balance_allowance(
        &self,
        _: Address,
        _: Address,
        _: &invisi_sdk_protocol::interfaces::CanonicalBlock,
    ) -> std::result::Result<(U256, U256), String> {
        Ok((U256::ZERO, U256::ZERO))
    }
    fn credit_allocation(
        &self,
        _: Address,
        _: Address,
        _: &invisi_sdk_protocol::interfaces::CanonicalBlock,
    ) -> std::result::Result<(u64, u16), String> {
        panic!("pure funding has no allocation reads")
    }
}
// Only the cryptographic backend is a test double. SDK witness/statement/proof binding is real.
struct ProofBackend;
impl invisi_sdk::prover::Prover for ProofBackend {
    fn prove(
        &self,
        r: &invisi_sdk::prover::ProvingRequest,
    ) -> std::result::Result<invisi_sdk::prover::ProofBundle, String> {
        Ok(invisi_sdk::prover::ProofBundle {
            format_version: 1,
            circuit_name: r.statement.circuit_name.clone(),
            target: r.statement.target.clone(),
            bb_version: "6.0.0".into(),
            artifact_sha256: r.statement.artifact_sha256.clone(),
            vk_sha256: r.statement.vk_sha256.clone(),
            proof: vec![0x12; 32],
            proof_sha256: invisi_sdk::prover::sha256(&[0x12; 32]),
            public_inputs: r.statement.expected_public_inputs.clone(),
        })
    }
    fn verify(
        &self,
        b: &invisi_sdk::prover::ProofBundle,
        s: &invisi_sdk::prover::ProofStatement,
    ) -> std::result::Result<bool, String> {
        invisi_sdk::prover::assert_bundle(b, s)?;
        Ok(true)
    }
}
#[tokio::test]
async fn actual_sdk_pure_funding_preparation_proof_and_router_export() {
    use invisi_sdk::sdk::{ChainState, Fee, Invisi, NoteOutput, Wallet};
    let chain = Arc::new(PreparationChain);
    let sdk = Invisi::new(chain.clone());
    // A bare receiving address retains host ownership and requires no spending key for funding.
    let wallet_data: Value =
        serde_json::from_str(include_str!("fixtures/current-address.json")).unwrap();
    let wallet = Wallet::from_address(wallet_data["longAddress"].as_str().unwrap()).unwrap();
    let outputs = [3u64, 5]
        .into_iter()
        .enumerate()
        .map(|(i, n)| {
            NoteOutput::identity(chain.context(), a(0x22), U256::from(100 + i), U256::from(n))
                .unwrap()
        })
        .collect::<Vec<_>>();
    let options = RouterPaymentPreparation {
        token: a(0x22),
        outputs: outputs.clone(),
        fee: Fee {
            recipient: a(0xaa),
            amount: U256::from(2),
        },
        deadline: 1500,
    };
    let c = PaymentRouterClient::new(dep(), Provider::new()).unwrap();
    let prepared = c
        .prepare_payment(&sdk, &wallet, options.clone())
        .await
        .unwrap();
    assert!(!prepared.needs_authorization());
    assert!(prepared.export_transaction().is_err());
    assert_eq!(
        prepared
            .outputs()
            .iter()
            .map(|o| o.commitment())
            .collect::<Vec<_>>(),
        outputs.iter().map(|o| o.commitment()).collect::<Vec<_>>()
    );
    let ready = prepared.prove(&ProofBackend, false).unwrap();
    assert!(ready
        .calldata(chain.as_ref(), dep().router_address)
        .unwrap_err()
        .contains("funding balance or Protocol allowance insufficient"));
    let q = quote(&vector()["payments"][0]["quote"]);
    let call = c
        .build_prepared_payment_transaction(&ready, q, a(0xaa))
        .await
        .unwrap();
    let decoded = abi::Router::payCall::abi_decode_validate(&call.data).unwrap();
    assert_eq!(decoded.request.funding.payer, dep().router_address);
    assert_eq!(decoded.request.funding.amount, U256::from(10));
    assert_eq!(decoded.request.params.feeAmount, U256::from(2));
    assert!(decoded.request.params.nullifiers.is_empty());
    assert_eq!(decoded.proof.as_ref(), &[0x12; 32]);
    let mut one = options.clone();
    one.outputs.truncate(1);
    assert!(c.prepare_payment(&sdk, &wallet, one).await.is_err());
    let mut weth = options;
    weth.token = dep().weth_address;
    assert!(c.prepare_payment(&sdk, &wallet, weth).await.is_err());
}

#[tokio::test]
async fn deployment_pins_deadline_refresh_and_extreme_v3_arithmetic() {
    let p = Provider::new();
    let mut d = dep();
    d.chain_id = 0;
    assert!(PaymentRouterClient::new(d, p.clone()).is_err());
    let mut d = dep();
    d.weth_address = d.core_address;
    assert!(PaymentRouterClient::new(d, p.clone()).is_err());
    let mut d = dep();
    d.runtime_code_hash = Some(B256::ZERO);
    let c = PaymentRouterClient::new(d, p.clone()).unwrap();
    assert!(c.frame(false).await.is_err());
    let c = PaymentRouterClient::new(dep(), p.clone()).unwrap();
    p.0.lock().unwrap().chain_id = Some(1);
    assert!(c.frame(false).await.is_err());
    p.0.lock().unwrap().chain_id = None;
    let routes = vec![
        V3Route {
            tokens: vec![a(0x44), a(0x22)],
            fees: vec![3000],
        },
        V3Route {
            tokens: vec![a(0x44), a(0x55), a(0x22)],
            fees: vec![500, 100],
        },
    ];
    let adapter = UniswapV3Adapter::new(p.clone(), a(0x99), routes).unwrap();
    p.0.lock().unwrap().quoter_inputs = vec![None, Some(U256::from(59))];
    let q = c.quote(&adapter, opts()).await.unwrap();
    assert_eq!(q.estimated_input, U256::from(59));
    p.0.lock().unwrap().quoter_inputs = vec![Some(U256::from(65)), Some(U256::from(55))];
    assert_eq!(
        c.quote(&adapter, opts()).await.unwrap().estimated_input,
        U256::from(55)
    );
    p.0.lock().unwrap().now = 1100;
    assert!(c.quote(&adapter, opts()).await.is_ok());
    p.0.lock().unwrap().now = 1110;
    let mut fresh = opts();
    fresh.deadline = 1200;
    let q = c.quote(&adapter, fresh).await.unwrap();
    let original = payment(&vector()["corePayment"]);
    c.build_payment_transaction(original.clone(), q, a(0xaa))
        .await
        .unwrap();
    assert_eq!(original, payment(&vector()["corePayment"]));
    p.0.lock().unwrap().now = 1000;
    p.0.lock().unwrap().quoter_inputs = vec![Some(U256::MAX), None];
    let mut maximum = opts();
    maximum.max_input = U256::MAX;
    maximum.slippage_bps = Some(0);
    assert_eq!(
        c.quote(&adapter, maximum.clone()).await.unwrap().max_input,
        U256::MAX
    );
    p.0.lock().unwrap().quoter_inputs = vec![Some(U256::MAX), None];
    maximum.slippage_bps = Some(1);
    assert!(c.quote(&adapter, maximum).await.is_err());
}

#[tokio::test]
async fn canonical_modes_nonce_sender_route_and_outer_simulation() {
    use invisi_sdk_payment_router::canonical::*;
    let v: Value = serde_json::from_str(include_str!("fixtures/intent.json")).unwrap();
    for c in v["cases"].as_array().unwrap().iter().take(3) {
        let provider = Provider::new();
        let client = PaymentRouterClient::new(dep(), provider.clone()).unwrap();
        let call = TransactionCall {
            to: a(0x33),
            data: data(&c["call"]["data"]),
            value: num(&c["call"]["value"]),
        };
        let (intent, route) = match c["method"].as_str().unwrap() {
            "payNative" => {
                let x = PaymentRouter::payNativeCall::abi_decode_validate(&call.data).unwrap();
                (x.i, x.route)
            }
            "payToken" => {
                let x = PaymentRouter::payTokenCall::abi_decode_validate(&call.data).unwrap();
                (x.i, x.route)
            }
            _ => {
                let x = PaymentRouter::payTokenForCall::abi_decode_validate(&call.data).unwrap();
                (x.i, x.route)
            }
        };
        let core = TransactionCall {
            to: a(0x11),
            data: data(&c["coreCalldata"]),
            value: U256::ZERO,
        };
        let p = client
            .prepare_canonical(core.clone(), intent.clone(), route.clone())
            .await
            .unwrap();
        let sender = if intent.mode == RELAYED_TOKEN {
            intent.relayer
        } else {
            intent.payer
        };
        provider.0.lock().unwrap().expected_sender = Some(sender);
        let simulated = client
            .simulate_canonical(&p, call.clone(), sender, &[], None)
            .await
            .unwrap();
        assert_eq!(simulated.input_spent, U256::from(60));
        assert!(provider
            .0
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|(actual, from, _)| actual.data == call.data && *from == Some(sender)));
        assert!(client
            .simulate_canonical(&p, call.clone(), a(0xfe), &[], None)
            .await
            .is_err());
        let mut wrong = call.clone();
        wrong.value = call.value + U256::from(1);
        assert!(client
            .simulate_canonical(&p, wrong, sender, &[], None)
            .await
            .is_err());
        let mut stale = intent.clone();
        stale.nonce += U256::from(1);
        assert!(client
            .prepare_canonical(core.clone(), stale, route.clone())
            .await
            .is_err());
        let mut malformed = route.clone();
        malformed.channel = 9;
        assert!(client
            .prepare_canonical(core.clone(), intent.clone(), malformed)
            .await
            .is_err());
    }
}

#[tokio::test]
async fn sponsored_account_signature_delegation_and_outer_simulation() {
    use invisi_sdk_payment_router::canonical::*;
    use k256::ecdsa::SigningKey;
    let key = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
    let payer = Address::from_slice(
        &alloy_primitives::keccak256(&key.verifying_key().to_encoded_point(false).as_bytes()[1..])
            [12..],
    );
    let provider = Provider::new();
    {
        let mut s = provider.0.lock().unwrap();
        s.account_payer = Some(payer);
        s.expected_sender = Some(a(0xbb));
    }
    let client = PaymentRouterClient::new(dep(), provider.clone()).unwrap();
    let v: Value = serde_json::from_str(include_str!("fixtures/intent.json")).unwrap();
    let c = &v["cases"][3];
    let x = PaymentRouter::payNativeCall::abi_decode_validate(&data(&c["call"]["data"])).unwrap();
    let mut i = x.i;
    i.payer = payer;
    let p = client
        .prepare_canonical(
            TransactionCall {
                to: a(0x11),
                data: data(&c["coreCalldata"]),
                value: U256::ZERO,
            },
            i,
            x.route,
        )
        .await
        .unwrap();
    let d = AccountDeployment {
        implementation: a(0xcc),
        runtime_code_hash: alloy_primitives::keccak256([0x60, 0]),
    };
    let n = client
        .prepare_native_account(&p, &d, p.intent().deadline, false)
        .await
        .unwrap();
    let (sig, id) = key
        .sign_prehash_recoverable(n.digest(31337).as_slice())
        .unwrap();
    let mut bytes = sig.to_bytes().to_vec();
    bytes.push(id.to_byte() + 27);
    let call = n.account_call(bytes.into()).unwrap();
    assert_eq!(call.to, payer);
    assert_eq!(call.value, U256::ZERO);
    client
        .simulate_canonical(&p, call.clone(), a(0xbb), &[], Some(&d))
        .await
        .unwrap();
    // An installed implementation would keep executing if the EVM silently skipped stale
    // authorization. SDK preflight must reject the stale EOA nonce before simulation.
    let authorization = |nonce: u64| {
        let request = AuthorizationRequest {
            chain_id: 31337,
            implementation: a(0xcc),
            nonce,
        };
        let (sig, id) = key
            .sign_prehash_recoverable(request.digest().unwrap().as_slice())
            .unwrap();
        let raw = sig.to_bytes();
        SignedAuthorization {
            chain_id: U256::from(31337),
            address: a(0xcc),
            nonce: alloy_primitives::U64::from(nonce),
            y_parity: alloy_primitives::U8::from(id.to_byte()),
            r: U256::from_be_slice(&raw[..32]),
            s: U256::from_be_slice(&raw[32..]),
        }
    };
    provider.0.lock().unwrap().eoa_nonce = 5;
    let error = client
        .simulate_canonical(&p, call.clone(), a(0xbb), &[authorization(4)], Some(&d))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        Error::Invalid("stale EIP-7702 authorization nonce")
    ));
    client
        .simulate_canonical(&p, call.clone(), a(0xbb), &[authorization(5)], Some(&d))
        .await
        .unwrap();
    let mut bad = call.clone();
    let mut action =
        PaymentRouterAccount::executeNativePaymentCall::abi_decode_validate(&bad.data).unwrap();
    action.nonce_ += U256::from(1);
    bad.data = action.abi_encode();
    assert!(client
        .simulate_canonical(&p, bad, a(0xbb), &[], Some(&d))
        .await
        .is_err());
    provider.0.lock().unwrap().wrong_delegation = true;
    assert!(client
        .simulate_canonical(&p, call, a(0xbb), &[], Some(&d))
        .await
        .is_err());
    assert!(client
        .prepare_native_account(&p, &d, p.intent().deadline, true)
        .await
        .is_err());
    {
        let mut state = provider.0.lock().unwrap();
        state.wrong_delegation = false;
        state.revoked_delegation = true;
    }
    assert!(client
        .prepare_native_account(&p, &d, p.intent().deadline, false)
        .await
        .is_err());
    let pending = client
        .prepare_native_account(&p, &d, p.intent().deadline, true)
        .await
        .unwrap();
    let call = pending
        .account_call(alloy_primitives::Bytes::from(vec![1; 65]))
        .unwrap();
    assert_eq!(
        PaymentRouterAccount::executeNativePaymentCall::abi_decode_validate(&call.data)
            .unwrap()
            .nonce_,
        U256::from(9)
    );
}

#[tokio::test]
async fn canonical_erc20_quotes_bind_input_output_cap_and_registry() {
    use invisi_sdk_payment_router::canonical::*;
    use serde_json::json;
    let provider = Provider::new();
    let client = PaymentRouterClient::new(dep(), provider.clone()).unwrap();
    let v: Value = serde_json::from_str(include_str!("fixtures/intent.json")).unwrap();
    let c = &v["cases"][1];
    let x = PaymentRouter::payTokenCall::abi_decode_validate(&data(&c["call"]["data"])).unwrap();
    let mut i = x.i;
    i.tokenIn = a(0x44);
    let core = TransactionCall {
        to: a(0x11),
        data: data(&c["coreCalldata"]),
        value: U256::ZERO,
    };
    let inner = abi::executeCall {
        slippage: abi::Slippage {
            recipient: a(0x33),
            buyToken: a(0x22),
            minAmountOut: U256::from(100200000),
        },
        actions: vec![],
        zid: B256::ZERO,
    }
    .abi_encode();
    let outer = abi::execCall {
        operator: a(0x66),
        token: i.tokenIn,
        amount: i.amountInMaximum,
        target: a(0x66),
        data: inner.into(),
    }
    .abi_encode();
    let body = json!({"liquidityAvailable":true,"chainId":31337,"sellToken":i.tokenIn,"buyToken":a(0x22),"buyAmount":"100200000","maxSellAmount":i.amountInMaximum.to_string(),"transaction":{"to":a(0x77),"value":"0","data":format!("0x{}",hex::encode(outer))}});
    client
        .prepare_canonical_zeroex_quote(core.clone(), i.clone(), &body)
        .await
        .unwrap();
    let mut bad = body.clone();
    bad["buyAmount"] = json!("1");
    assert!(client
        .prepare_canonical_zeroex_quote(core.clone(), i.clone(), &bad)
        .await
        .is_err());
    bad = body.clone();
    bad["sellToken"] = json!(a(0xaa));
    assert!(client
        .prepare_canonical_zeroex_quote(core.clone(), i.clone(), &bad)
        .await
        .is_err());
    bad = body.clone();
    bad["transaction"]["value"] = json!("1");
    assert!(client
        .prepare_canonical_zeroex_quote(core.clone(), i.clone(), &bad)
        .await
        .is_err());
    provider.0.lock().unwrap().settler = Some(a(0xfe));
    assert!(client
        .prepare_canonical_zeroex_quote(core.clone(), i.clone(), &body)
        .await
        .is_err());
    let path = encode_v3_exact_output_path(&[a(0xaa), a(0x22)], &[3000]).unwrap();
    assert_eq!(
        client
            .quote_canonical_v3(a(0x99), path.into(), a(0xaa), a(0x22), U256::from(10))
            .await
            .unwrap(),
        U256::from(60)
    );
}
