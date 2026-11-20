use alloy_primitives::{Address, U256};
use invisi_sdk_payment_router::*;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
struct Http {
    mode: u8,
    seen: Arc<Mutex<bool>>,
}
impl ZeroExHttpBackend for Http {
    fn execute(&self, request: reqwest::Request) -> BoxFuture<'_, Result<ZeroExHttpResponse>> {
        Box::pin(async move {
            assert_eq!(request.headers()["0x-api-key"], "explicit-test-secret");
            assert_eq!(request.headers()["0x-version"], "v2");
            let query = request
                .url()
                .query_pairs()
                .collect::<std::collections::BTreeMap<_, _>>();
            assert_eq!(query["buyAmount"], "10");
            assert!(!query.contains_key("sellAmount"));
            assert_eq!(query["taker"], query["recipient"]);
            *self.seen.lock().unwrap() = true;
            match self.mode {
                0 => Ok(ZeroExHttpResponse {
                    status: 200,
                    body: br#"{"ok":true}"#.to_vec(),
                }),
                1 => Ok(ZeroExHttpResponse {
                    status: 401,
                    body: b"explicit-test-secret".to_vec(),
                }),
                2 => Ok(ZeroExHttpResponse {
                    status: 200,
                    body: b"explicit-test-secret".to_vec(),
                }),
                _ => Err(Error::Provider("explicit-test-secret".into())),
            }
        })
    }
}
fn request() -> SwapQuoteRequest {
    let a = |n| Address::repeat_byte(n);
    SwapQuoteRequest {
        parameters: QuoteParameters {
            token_out: a(0x22),
            amount_out: U256::from(10),
            max_input: U256::from(100),
            deadline: 1100,
            slippage_bps: None,
            cancellation: None,
        },
        deployment: PaymentRouterDeployment {
            chain_id: 31337,
            router_address: a(0x33),
            core_address: a(0x11),
            weth_address: a(0x44),
            uniswap_router_address: a(0x55),
            runtime_code_hash: None,
            zero_ex: Some(ZeroExDeployment {
                allowance_holder_address: a(0x77),
                settler_registry_address: a(0x88),
            }),
        },
        now: 1000,
        block_number: 10,
        settler_address: Some(a(0x66)),
    }
}
#[tokio::test]
async fn http_exact_buy_headers_errors_and_json_are_explicit_and_sanitized() {
    for mode in 0..4 {
        let seen = Arc::new(Mutex::new(false));
        let h = ZeroExHttpTransport::with_backend(
            "explicit-test-secret",
            None,
            Arc::new(Http {
                mode,
                seen: seen.clone(),
            }),
        )
        .unwrap();
        let result = h.fetch(request()).await;
        assert!(*seen.lock().unwrap());
        if mode == 0 {
            assert_eq!(result.unwrap(), json!({"ok":true}));
        } else {
            let error = result.unwrap_err().to_string();
            assert!(!error.contains("explicit-test-secret"));
            if mode == 1 {
                assert!(error.contains("401"));
            }
        }
    }
}
#[tokio::test]
async fn http_rejects_endpoint_aliases_and_pre_cancelled_requests() {
    for url in [
        "http://api.0x.org/quote",
        "https://x:y@api.0x.org/quote",
        "https://api.0x.org/quote?key=x",
        "https://api.0x.org/quote#x",
    ] {
        assert!(ZeroExHttpTransport::new("key", Some(url)).is_err());
    }
    assert!(ZeroExHttpTransport::new("  ", None).is_err());
    let seen = Arc::new(Mutex::new(false));
    let h = ZeroExHttpTransport::with_backend(
        "explicit-test-secret",
        None,
        Arc::new(Http {
            mode: 0,
            seen: seen.clone(),
        }),
    )
    .unwrap();
    let mut r = request();
    let token = CancellationToken::default();
    token.cancel();
    r.parameters.cancellation = Some(token);
    assert!(matches!(h.fetch(r).await, Err(Error::Cancelled)));
    assert!(!*seen.lock().unwrap());
}
#[tokio::test]
async fn zeroex_metadata_and_integer_boundaries_are_rejected_before_use() {
    for mutate in 0..9 {
        let adapter = ZeroExAdapter::new(move |_r: SwapQuoteRequest| async move {
            let v: Value =
                serde_json::from_str(include_str!("fixtures/payment-router-vectors.json")).unwrap();
            let q = &v["payments"][1]["quote"];
            let mut body = json!({"liquidityAvailable":true,"buyToken":q["tokenOut"],"buyAmount":"10","sellToken":NATIVE_TOKEN,"sellAmount":"60","maxSellAmount":"100","transaction":{"to":q["target"],"data":q["data"],"value":"100"}});
            match mutate {
                0 => body["buyAmount"] = json!("11"),
                1 => body["sellToken"] = json!(Address::repeat_byte(0x44)),
                2 => body["liquidityAvailable"] = json!(false),
                3 => body["transaction"]["value"] = json!("99"),
                4 => body["sellAmount"] = json!("101"),
                5 => body["maxSellAmount"] = json!("0100"),
                6 => body["chainId"] = json!(1),
                7 => body["recipient"] = json!(Address::repeat_byte(0xaa)),
                8 => body["buyAmount"] = json!((U256::from(1) << 128usize).to_string()),
                _ => (),
            };
            Ok(body)
        });
        assert!(adapter.quote(request()).await.is_err(), "metadata {mutate}");
    }
    let calls = Arc::new(Mutex::new(0));
    let count = calls.clone();
    let adapter = ZeroExAdapter::new(move |_r: SwapQuoteRequest| {
        *count.lock().unwrap() += 1;
        async { Ok(json!({})) }
    });
    for (amount, budget, bps) in [
        (U256::ZERO, U256::from(100), 50),
        (U256::from(1) << 128, U256::from(100), 50),
        (U256::from(10), U256::ZERO, 50),
        (U256::from(10), U256::from(100), 10001),
    ] {
        let mut r = request();
        r.parameters.amount_out = amount;
        r.parameters.max_input = budget;
        r.parameters.slippage_bps = Some(bps);
        assert!(adapter.quote(r).await.is_err());
    }
    assert_eq!(*calls.lock().unwrap(), 0);
}

#[tokio::test]
async fn zeroex_accepts_safe_integer_json_chain_numbers() {
    let adapter = ZeroExAdapter::new(|_r: SwapQuoteRequest| async {
        let v: Value =
            serde_json::from_str(include_str!("fixtures/payment-router-vectors.json")).unwrap();
        let q = &v["payments"][1]["quote"];
        Ok(
            json!({"liquidityAvailable":true,"buyToken":q["tokenOut"],"buyAmount":"10","sellToken":NATIVE_TOKEN,"chainId":31337.0,"maxSellAmount":"100","transaction":{"to":q["target"],"data":q["data"],"value":"100","chainId":31337.0}}),
        )
    });
    assert_eq!(
        adapter.quote(request()).await.unwrap().max_input,
        U256::from(100)
    );
}
