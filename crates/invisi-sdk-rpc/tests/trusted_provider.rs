use alloy_primitives::{Address, B256};
use invisi_sdk_rpc::rpc::*;
use serde_json::{json, Value};
struct Reject;
impl RpcTransport for Reject {
    fn send(&self, request: &Value) -> Result<Value> {
        assert_eq!(request["method"], "invisi_readChainState");
        Ok(
            json!({"jsonrpc":"2.0","id":request["id"],"result":{"apiVersion":"v0","protocolVersion":"1"}}),
        )
    }
}
#[test]
fn trusted_provider_requires_valid_pins_and_checks_every_envelope() {
    let deployment = ProtocolDeployment {
        chain_id: "31337".into(),
        protocol: ContractDeployment {
            address: Address::with_last_byte(1),
            runtime_code_hash: B256::with_last_byte(1),
            from_block: 0,
        },
        registry: None,
        broadcaster_registry: None,
    };
    let provider = TrustedProvider::new(Reject, deployment.clone()).unwrap();
    assert!(provider.head().is_err());
    assert!(provider.code_at(deployment.protocol.address, None).is_err());
    assert!(provider.receipt(B256::with_last_byte(1)).is_err());
    assert!(provider.transaction(B256::with_last_byte(1)).is_err());
    let mut bad = deployment;
    bad.chain_id = "0".into();
    assert!(TrustedProvider::new(Reject, bad).is_err());
}

#[derive(Clone)]
struct Facts {
    deployment: ProtocolDeployment,
    tamper: &'static str,
}
impl Facts {
    fn header(&self) -> alloy_consensus::Header {
        alloy_consensus::Header {
            number: 10,
            timestamp: 20,
            ..Default::default()
        }
    }
}
impl RpcTransport for Facts {
    fn send(&self, request: &Value) -> Result<Value> {
        assert_eq!(request["method"], "invisi_readChainState");
        let p = &request["params"][0];
        let h = self.header();
        let mut result =
            json!({"apiVersion":"v1","protocolVersion":"1","deployment":self.deployment});
        match p["kind"].as_str().unwrap() {
            "header" => {
                result["header"] = json!(h);
                result["headerHash"] = json!(h.hash_slow());
            }
            "code" | "call" => result["data"] = json!("0x1234"),
            "receipt" => {
                result["receipt"] = json!({"transactionHash":p["transactionHash"],"blockNumber":"0xa","blockHash":h.hash_slow(),"status":"0x1","logs":[]})
            }
            "transaction" => {
                if self.tamper.starts_with("tx") {
                    let mut tx = signed_transaction();
                    if self.tamper == "tx-forged" {
                        tx["input"] = json!("0xff");
                    }
                    result["transaction"] = tx;
                    result["pending"] = json!(true);
                } else {
                    result["transaction"] = Value::Null;
                    result["pending"] = json!(false);
                }
            }
            _ => panic!("unexpected trusted read"),
        }
        match self.tamper {
            "hash" => result["headerHash"] = json!(B256::ZERO),
            "receipt" => result["receipt"]["blockHash"] = json!(B256::ZERO),
            "deployment" => result["deployment"]["protocol"]["fromBlock"] = json!(1),
            "version" => result["protocolVersion"] = json!("2"),
            _ => {}
        }
        Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
    }
}
fn facts(tamper: &'static str) -> Facts {
    Facts {
        deployment: ProtocolDeployment {
            chain_id: "31337".into(),
            protocol: ContractDeployment {
                address: Address::with_last_byte(1),
                runtime_code_hash: B256::with_last_byte(1),
                from_block: 0,
            },
            registry: None,
            broadcaster_registry: None,
        },
        tamper,
    }
}
#[test]
fn trusted_reads_bind_header_number_hash_and_receipts() {
    let f = facts("");
    let p = TrustedProvider::new(f.clone(), f.deployment.clone()).unwrap();
    assert_eq!(p.chain_id().unwrap(), 31337);
    assert_eq!(p.head().unwrap().number, 10);
    assert_eq!(p.block(10).unwrap().hash, f.header().hash_slow());
    assert!(p.block(9).is_err());
    assert_eq!(
        p.code_at(Address::with_last_byte(1), None).unwrap(),
        vec![0x12, 0x34]
    );
    assert_eq!(
        p.call(Address::with_last_byte(1), &[1, 2, 3, 4], 10)
            .unwrap(),
        vec![0x12, 0x34]
    );
    assert!(p.receipt(B256::with_last_byte(1)).unwrap().unwrap().success);
    assert!(p.transaction(B256::with_last_byte(1)).unwrap().is_none());
    assert_eq!(
        p.block_by_tag(FinalityTag::Safe).unwrap().unwrap().number,
        10
    );
    for bad in ["hash", "deployment", "version"] {
        let f = facts(bad);
        assert!(TrustedProvider::new(f.clone(), f.deployment.clone())
            .unwrap()
            .head()
            .is_err());
    }
    let f = facts("receipt");
    assert!(TrustedProvider::new(f.clone(), f.deployment.clone())
        .unwrap()
        .receipt(B256::with_last_byte(1))
        .is_err());
}

fn signed_transaction() -> Value {
    use alloy_eips::eip2718::Encodable2718;
    let mut tx = json!({"type":"0x2","chainId":"0x7a69","nonce":"0x1","gas":"0x5208","maxFeePerGas":"0xa","maxPriorityFeePerGas":"0x1","to":Address::with_last_byte(2),"value":"0x0","input":"0x","accessList":[],"yParity":"0x0","r":"0x1","s":"0x2","hash":B256::ZERO});
    let decoded: alloy_consensus::TxEnvelope = serde_json::from_value(tx.clone()).unwrap();
    tx["hash"] = json!(alloy_primitives::keccak256(decoded.encoded_2718()));
    tx
}
#[test]
fn trusted_transactions_recompute_signed_hash() {
    let hash: B256 = serde_json::from_value(signed_transaction()["hash"].clone()).unwrap();
    let f = facts("tx");
    let p = TrustedProvider::new(f.clone(), f.deployment.clone()).unwrap();
    let tx = p.transaction(hash).unwrap().unwrap();
    assert_eq!(tx.hash, hash);
    assert!(tx.block.is_none());
    let f = facts("tx-forged");
    assert!(TrustedProvider::new(f.clone(), f.deployment.clone())
        .unwrap()
        .transaction(hash)
        .is_err());
}

#[derive(Clone)]
struct BatchFacts {
    facts: Facts,
    corrupt: &'static str,
    calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}
impl RpcTransport for BatchFacts {
    fn send(&self, request: &Value) -> Result<Value> {
        if request["method"] == "invisi_getBlockHeaders" {
            return Ok(
                json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":-32601,"message":"unsupported"}}),
            );
        }
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let single = !request.is_array();
        let requests = request
            .as_array()
            .cloned()
            .unwrap_or_else(|| vec![request.clone()]);
        assert!(requests.len() <= 20);
        let mut responses = requests.iter().map(|r| {
            let n = u64::from_str_radix(r["params"][0]["block"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
            let h = alloy_consensus::Header { number: n, timestamp: n + 1, ..Default::default() };
            json!({"jsonrpc":"2.0","id":r["id"],"result":{"apiVersion":"v1","protocolVersion":"1","deployment":self.facts.deployment,"header":h,"headerHash":h.hash_slow()}})
        }).collect::<Vec<_>>();
        responses.reverse(); // Response order is independent of request order.
        match self.corrupt {
            "missing" => {
                responses.pop();
            }
            "duplicate" => responses[0] = responses[1].clone(),
            "extra" => responses.push(responses[0].clone()),
            "id" => responses[0]["id"] = json!(u64::MAX),
            "hash" => responses[0]["result"]["headerHash"] = json!(B256::ZERO),
            "number" => {
                let h = alloy_consensus::Header {
                    number: 0,
                    timestamp: 1,
                    ..Default::default()
                };
                responses[0]["result"]["header"] = json!(h);
                responses[0]["result"]["headerHash"] = json!(h.hash_slow());
            }
            "deployment" => responses[0]["result"]["deployment"]["chainId"] = json!("1"),
            "ambiguous" => responses[0]["error"] = json!({"code":-1,"message":"failed"}),
            "error" => {
                responses[0].as_object_mut().unwrap().remove("result");
                responses[0]["error"] =
                    json!({"code":-1,"message":"failed","data":{"retryAfterMs":100}});
            }
            "null-error" | "missing-message" | "missing-code" | "missing-result" => {
                responses[0].as_object_mut().unwrap().remove("result");
                responses[0]["error"] = match self.corrupt {
                    "null-error" => Value::Null,
                    "missing-message" => json!({"code":-1}),
                    "missing-code" => json!({"message":"failed"}),
                    _ => {
                        responses[0].as_object_mut().unwrap().remove("error");
                        Value::Null
                    }
                };
                if self.corrupt == "missing-result" {
                    responses[0].as_object_mut().unwrap().remove("error");
                }
            }
            _ => {}
        }
        if single {
            Ok(responses.remove(0))
        } else {
            Ok(json!(responses))
        }
    }
}
#[test]
fn trusted_header_batches_are_bounded_ordered_and_fail_closed() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let numbers = (1..=45).collect::<Vec<_>>();
    for corrupt in [
        "",
        "missing",
        "duplicate",
        "extra",
        "id",
        "hash",
        "number",
        "deployment",
        "ambiguous",
        "error",
        "null-error",
        "missing-message",
        "missing-code",
        "missing-result",
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let f = facts("");
        let p = TrustedProvider::new(
            BatchFacts {
                facts: f.clone(),
                corrupt,
                calls: calls.clone(),
            },
            f.deployment,
        )
        .unwrap();
        let result = p
            .blocks(&numbers)
            .expect("TrustedProvider batch capability");
        if corrupt.is_empty() {
            let headers = result.unwrap();
            assert_eq!(
                headers.iter().map(|b| b.number).collect::<Vec<_>>(),
                numbers
            );
            assert_eq!(calls.load(Ordering::SeqCst), 3);
        } else if corrupt == "error" {
            match result {
                Err(Error::Remote {
                    code,
                    message,
                    data,
                }) => {
                    assert_eq!(code, -1);
                    assert_eq!(message, "failed");
                    assert_eq!(data, Some(json!({"retryAfterMs":100})));
                }
                other => panic!("remote RPC error lost its typed code/message/data: {other:?}"),
            }
        } else {
            assert!(
                matches!(result, Err(Error::Invalid(_))),
                "accepted or misclassified {corrupt}: {result:?}"
            );
        }
    }
}

#[test]
#[ignore = "controlled transport-latency benchmark; run explicitly with --ignored --nocapture"]
fn benchmark_trusted_header_batch() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    struct Delayed(BatchFacts);
    impl RpcTransport for Delayed {
        fn send(&self, request: &Value) -> Result<Value> {
            std::thread::sleep(std::time::Duration::from_millis(2));
            self.0.send(request)
        }
    }
    let numbers = (1..=256).collect::<Vec<_>>();
    let f = facts("");
    let calls = Arc::new(AtomicUsize::new(0));
    let p = TrustedProvider::new(
        Delayed(BatchFacts {
            facts: f.clone(),
            corrupt: "",
            calls: calls.clone(),
        }),
        f.deployment,
    )
    .unwrap();
    let start = std::time::Instant::now();
    let baseline = numbers
        .iter()
        .map(|n| p.block(*n).unwrap())
        .collect::<Vec<_>>();
    let single_us = start.elapsed().as_micros();
    let single_calls = calls.swap(0, Ordering::SeqCst);
    let start = std::time::Instant::now();
    let batched = p.blocks(&numbers).unwrap().unwrap();
    let batch_us = start.elapsed().as_micros();
    assert_eq!(baseline, batched);
    assert_eq!(single_calls, 256);
    assert_eq!(calls.load(Ordering::SeqCst), 13);
    println!("trusted_header_batch single_us={single_us} batch_us={batch_us} single_requests={single_calls} batch_requests={}",calls.load(Ordering::SeqCst));
}

#[derive(Clone)]
struct RangeFacts {
    mode: &'static str,
    requests: std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
    headers: Vec<alloy_consensus::Header>,
}
impl RangeFacts {
    fn new(mode: &'static str) -> Self {
        let mut parent_hash = B256::ZERO;
        let headers = (0..=520)
            .map(|number| {
                let h = alloy_consensus::Header {
                    number,
                    timestamp: number + 100,
                    parent_hash,
                    state_root: B256::with_last_byte(11),
                    transactions_root: B256::with_last_byte(12),
                    receipts_root: B256::with_last_byte(13),
                    gas_limit: 30_000_000,
                    gas_used: 123,
                    extra_data: vec![1, 2, 3, 4].into(),
                    mix_hash: B256::with_last_byte(14),
                    nonce: alloy_primitives::B64::with_last_byte(15),
                    base_fee_per_gas: Some(0),
                    withdrawals_root: Some(B256::with_last_byte(8)),
                    blob_gas_used: Some(0),
                    excess_blob_gas: Some(0),
                    parent_beacon_block_root: Some(B256::with_last_byte(9)),
                    requests_hash: Some(B256::with_last_byte(10)),
                    ..Default::default()
                };
                parent_hash = h.hash_slow();
                h
            })
            .collect();
        Self {
            mode,
            requests: Default::default(),
            headers,
        }
    }
    fn provider(&self) -> TrustedProvider<Self> {
        TrustedProvider::new(self.clone(), facts("").deployment).unwrap()
    }
}
impl RpcTransport for RangeFacts {
    fn send(&self, request: &Value) -> Result<Value> {
        self.requests.lock().unwrap().push(request.clone());
        if request["method"] != "invisi_getBlockHeaders" {
            let live = BatchFacts {
                facts: facts(""),
                corrupt: "",
                calls: Default::default(),
            };
            return live.send(request);
        }
        if matches!(self.mode, "unsupported" | "unavailable" | "remote") {
            let code = match self.mode {
                "unsupported" => -32601,
                "unavailable" => -32004,
                _ => -32000,
            };
            return Ok(
                json!({"jsonrpc":"2.0","id":request["id"],"error":{"code":code,"message":"history unavailable"}}),
            );
        }
        let from = request["params"][0]["fromBlock"].as_u64().unwrap();
        let to = request["params"][0]["toBlock"].as_u64().unwrap();
        assert!(to >= from && to - from < 256);
        let rows = self.headers[from as usize..=to as usize]
            .iter()
            .map(|h| json!({"header":h,"headerHash":h.hash_slow()}))
            .collect::<Vec<_>>();
        let mut result = json!({"apiVersion":"v1","protocolVersion":"1","deployment":facts("").deployment,"range":{"fromBlock":from,"toBlock":to,"blockHash":self.headers[to as usize].hash_slow()},"headers":rows});
        if self.mode.starts_with("omit-") || self.mode.starts_with("null-") {
            let (kind, field) = self.mode.split_once('-').unwrap();
            let header = result["headers"][0]["header"].as_object_mut().unwrap();
            if kind == "omit" {
                header.remove(field);
            } else {
                header.insert(field.into(), Value::Null);
            }
            // A matching hash cannot make an incomplete fork-field prefix valid.
            let decoded: alloy_consensus::Header =
                serde_json::from_value(result["headers"][0]["header"].clone()).unwrap();
            result["headers"][0]["headerHash"] = json!(decoded.hash_slow());
            result["range"]["blockHash"] = json!(decoded.hash_slow());
        }
        match self.mode {
            "slot" => result["headers"][0]["header"]["slotNumber"] = json!("0x0"),
            "hash" => result["headers"][0]["headerHash"] = json!(B256::ZERO),
            "optional-hash" => {
                result["headers"][0]["header"]
                    .as_object_mut()
                    .unwrap()
                    .remove("withdrawalsRoot");
            }
            "incomplete" => {
                result["headers"][0]["header"]
                    .as_object_mut()
                    .unwrap()
                    .remove("stateRoot");
            }
            "parent" | "boundary-parent" if self.mode == "parent" || from == 257 => {
                let index = if self.mode == "parent" { 1 } else { 0 };
                let mut h = self.headers[from as usize + index].clone();
                h.parent_hash = B256::ZERO;
                result["headers"][index] = json!({"header":h,"headerHash":h.hash_slow()});
            }
            "anchor" => result["range"]["blockHash"] = json!(B256::ZERO),
            "range" => result["range"]["fromBlock"] = json!(from + 1),
            "string-range" => result["range"]["toBlock"] = json!(to.to_string()),
            "version" => result["apiVersion"] = json!("v2"),
            "protocol-version" => result["protocolVersion"] = json!("2"),
            "deployment" => result["deployment"]["protocol"]["fromBlock"] = json!(1),
            "count" => {
                result["headers"].as_array_mut().unwrap().pop();
            }
            "order" => result["headers"].as_array_mut().unwrap().reverse(),
            "ambiguous" => {
                return Ok(
                    json!({"jsonrpc":"2.0","id":request["id"],"result":result,"error":{"code":-32004,"message":"unavailable"}}),
                )
            }
            "id" => return Ok(json!({"jsonrpc":"2.0","id":99999,"result":result})),
            _ => {}
        }
        Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
    }
}
#[test]
fn historical_headers_use_inclusive_ranges_and_chunk_at_256() {
    let f = RangeFacts::new("");
    let numbers = (1..=513).collect::<Vec<_>>();
    let blocks = f.provider().blocks(&numbers).unwrap().unwrap();
    assert_eq!(blocks.iter().map(|b| b.number).collect::<Vec<_>>(), numbers);
    assert_eq!(blocks[0].hash, f.headers[1].hash_slow());
    assert_eq!(blocks[512].hash, f.headers[513].hash_slow());
    let requests = f.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    for (request, (from, to)) in requests.iter().zip([(1, 256), (257, 512), (513, 513)]) {
        assert_eq!(request["method"], "invisi_getBlockHeaders");
        assert_eq!(request["params"], json!([{"fromBlock":from,"toBlock":to}]));
    }
}
#[test]
fn historical_headers_fail_closed_without_live_fallback() {
    for mode in [
        "hash",
        "optional-hash",
        "incomplete",
        "parent",
        "boundary-parent",
        "anchor",
        "range",
        "string-range",
        "version",
        "protocol-version",
        "deployment",
        "count",
        "order",
        "ambiguous",
        "id",
        "remote",
    ] {
        let f = RangeFacts::new(mode);
        let numbers = if mode == "boundary-parent" {
            (1..=257).collect::<Vec<_>>()
        } else {
            vec![1, 2]
        };
        assert!(
            f.provider().blocks(&numbers).unwrap().is_err(),
            "accepted {mode}"
        );
        assert!(
            f.requests
                .lock()
                .unwrap()
                .iter()
                .all(|r| r["method"] == "invisi_getBlockHeaders"),
            "fell back for {mode}"
        );
    }
}
#[test]
fn historical_headers_only_fallback_for_explicit_compatibility_errors() {
    for mode in ["unsupported", "unavailable"] {
        let f = RangeFacts::new(mode);
        let blocks = f.provider().blocks(&[1, 2]).unwrap().unwrap();
        assert_eq!(blocks[1].number, 2);
        let requests = f.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0]["method"], "invisi_getBlockHeaders");
        assert!(requests[1].is_array());
    }
}
#[test]
fn historical_headers_preserve_sparse_live_reads_and_validate_before_network() {
    let f = RangeFacts::new("");
    let p = f.provider();
    assert!(p.blocks(&[]).unwrap().is_err());
    assert!(p.blocks(&[1, i64::MAX as u64 + 1]).unwrap().is_err());
    assert!(f.requests.lock().unwrap().is_empty());
    assert_eq!(
        p.blocks(&[3, 1, 3])
            .unwrap()
            .unwrap()
            .iter()
            .map(|b| b.number)
            .collect::<Vec<_>>(),
        vec![3, 1, 3]
    );
    assert!(f.requests.lock().unwrap()[0].is_array());
    let historical = p.blocks(&[10]).unwrap().unwrap().remove(0);
    let live = p.block(10).unwrap();
    assert_ne!(
        historical.hash, live.hash,
        "single canonical fence must observe live reorg"
    );
    assert_eq!(
        f.requests.lock().unwrap().last().unwrap()["method"],
        "invisi_readChainState"
    );
}

#[test]
#[ignore = "controlled transport-latency benchmark; run explicitly with --ignored --nocapture"]
fn benchmark_historical_header_range() {
    struct Delayed(RangeFacts);
    impl RpcTransport for Delayed {
        fn send(&self, request: &Value) -> Result<Value> {
            std::thread::sleep(std::time::Duration::from_millis(2));
            self.0.send(request)
        }
    }
    let numbers = (1..=256).collect::<Vec<_>>();
    let mut timings = Vec::new();
    for mode in ["unsupported", ""] {
        let facts = RangeFacts::new(mode);
        let p = TrustedProvider::new(Delayed(facts.clone()), self::facts("").deployment).unwrap();
        let start = std::time::Instant::now();
        let blocks = p.blocks(&numbers).unwrap().unwrap();
        let elapsed = start.elapsed().as_micros();
        assert_eq!(blocks.iter().map(|b| b.number).collect::<Vec<_>>(), numbers);
        let requests = facts.requests.lock().unwrap().len();
        timings.push((elapsed, requests));
    }
    assert_eq!(timings[0].1, 14); // unsupported probe + thirteen live batches
    assert_eq!(timings[1].1, 1);
    println!("historical_header_range blocks=256 live_batch_us={} historical_us={} live_batch_requests={} historical_requests={}", timings[0].0, timings[1].0, timings[0].1, timings[1].1);
}

#[test]
fn historical_headers_reject_incomplete_fork_prefix_even_with_matching_hash() {
    for mode in [
        "omit-baseFeePerGas",
        "null-baseFeePerGas",
        "omit-withdrawalsRoot",
        "null-withdrawalsRoot",
        "omit-blobGasUsed",
        "null-blobGasUsed",
        "omit-excessBlobGas",
        "null-excessBlobGas",
        "omit-parentBeaconBlockRoot",
        "null-parentBeaconBlockRoot",
        "slot",
    ] {
        let f = RangeFacts::new(mode);
        assert!(
            f.provider().blocks(&[1]).unwrap().is_err(),
            "accepted incomplete or mismatched fork fields: {mode}"
        );
        assert_eq!(f.requests.lock().unwrap().len(), 1, "fell back for {mode}");
    }
}

// Independently computed with go-ethereum v1.17.2 types.Header.Hash.
// Slot 10 also matches the TypeScript rich-header regression fixture.
const RICH_NO_SLOT: &str = "0xa014a56477175712d2382e4209021ef9e81b6c1932db0bd2db766b52235a792d";
const RICH_SLOT_ZERO: &str = "0x29ea1a71dd4785587fab04a663b53953ec654620f415ab0fe13b0180ad473d2a";
const RICH_SLOT_TEN: &str = "0x1840a20a2da071d939eb5142302d6e1a0b0ab4533a60168569ecb682734967d7";
const RICH_SLOT_MAX: &str = "0x3813da2e8c8585fcd52407f10dbb2472b7197013db0ae1f76bf8f5fabdf13f1b";
#[derive(Clone)]
struct RichHeaders {
    current: std::sync::Arc<std::sync::Mutex<(Value, &'static str)>>,
    requests: std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
}
impl RichHeaders {
    fn new(slot: Option<Value>, hash: &'static str) -> Self {
        let word = |n| format!("0x{n:064x}");
        let mut header = json!({
            "parentHash":word(0), "sha3Uncles":word(2),
            "miner":"0x1111111111111111111111111111111111111111",
            "stateRoot":word(3), "transactionsRoot":word(4), "receiptsRoot":word(5),
            "logsBloom":format!("0x{}", "00".repeat(256)),
            "difficulty":"0x0", "number":"0x1", "gasLimit":"0x100", "gasUsed":"0x0",
            "timestamp":"0x7b", "extraData":"0x", "mixHash":word(6),
            "nonce":"0x0000000000000000", "baseFeePerGas":"0x0",
            "withdrawalsRoot":word(7), "blobGasUsed":"0x0", "excessBlobGas":"0x0",
            "parentBeaconBlockRoot":word(8), "requestsHash":word(9),
        });
        if let Some(slot) = slot {
            header["slotNumber"] = slot;
        }
        Self {
            current: std::sync::Arc::new(std::sync::Mutex::new((header, hash))),
            requests: Default::default(),
        }
    }
    fn provider(&self) -> TrustedProvider<Self> {
        TrustedProvider::new(self.clone(), facts("").deployment).unwrap()
    }
}
impl RpcTransport for RichHeaders {
    fn send(&self, request: &Value) -> Result<Value> {
        self.requests.lock().unwrap().push(request.clone());
        let (header, hash) = self.current.lock().unwrap().clone();
        let mut result =
            json!({"apiVersion":"v1","protocolVersion":"1","deployment":facts("").deployment});
        if request["method"] == "invisi_getBlockHeaders" {
            assert_eq!(request["params"], json!([{"fromBlock":1,"toBlock":1}]));
            result["range"] = json!({"fromBlock":1,"toBlock":1,"blockHash":hash});
            result["headers"] = json!([{"header":header,"headerHash":hash}]);
        } else {
            assert_eq!(request["method"], "invisi_readChainState");
            assert_eq!(request["params"][0]["kind"], "header");
            result["header"] = header;
            result["headerHash"] = json!(hash);
        }
        Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
    }
}
#[test]
fn rich_slot_headers_match_independent_hashes_in_historical_and_live_reads() {
    for (slot, expected) in [
        (None, RICH_NO_SLOT),
        (Some(Value::Null), RICH_NO_SLOT),
        (Some(json!("0x0")), RICH_SLOT_ZERO),
        (Some(json!("0xa")), RICH_SLOT_TEN),
        (Some(json!("0xffffffffffffffff")), RICH_SLOT_MAX),
    ] {
        let f = RichHeaders::new(slot, expected);
        let p = f.provider();
        let historical = p.blocks(&[1]).unwrap().unwrap().remove(0);
        assert_eq!(historical.hash.to_string(), expected);
        assert_eq!(p.block(1).unwrap(), historical);
        assert_eq!(
            p.block_by_tag(FinalityTag::Finalized).unwrap().unwrap(),
            historical
        );
        assert_eq!(f.requests.lock().unwrap().len(), 3);
    }
}
#[test]
fn slot_headers_reject_invalid_quantities_hashes_and_fork_gaps_without_fallback() {
    for slot in [
        json!("0x10000000000000000"),
        json!("0x00"),
        json!("0x"),
        json!("-1"),
        json!(0),
        json!(-1),
        json!("0xb"),
    ] {
        let f = RichHeaders::new(Some(slot), RICH_SLOT_TEN);
        let p = f.provider();
        assert!(p.blocks(&[1]).unwrap().is_err());
        assert_eq!(f.requests.lock().unwrap().len(), 1);
        assert!(p.block(1).is_err());
    }
    for field in [
        "baseFeePerGas",
        "withdrawalsRoot",
        "blobGasUsed",
        "excessBlobGas",
        "parentBeaconBlockRoot",
        "requestsHash",
    ] {
        for missing in [true, false] {
            let f = RichHeaders::new(Some(json!("0xa")), RICH_SLOT_TEN);
            {
                let mut current = f.current.lock().unwrap();
                if missing {
                    current.0.as_object_mut().unwrap().remove(field);
                } else {
                    current.0[field] = Value::Null;
                }
            }
            let p = f.provider();
            assert!(
                p.blocks(&[1]).unwrap().is_err(),
                "historical accepted gap: {field}"
            );
            assert_eq!(f.requests.lock().unwrap().len(), 1);
            assert!(p.block(1).is_err(), "live accepted gap: {field}");
        }
    }
}
#[test]
fn slot_header_canonical_fences_observe_fresh_live_fork_changes() {
    let f = RichHeaders::new(Some(json!("0xa")), RICH_SLOT_TEN);
    let p = f.provider();
    let historical = p.blocks(&[1]).unwrap().unwrap().remove(0);
    {
        let mut current = f.current.lock().unwrap();
        current.0["slotNumber"] = json!("0x0");
        current.1 = RICH_SLOT_ZERO;
    }
    let live = p.block(1).unwrap();
    assert_ne!(historical.hash, live.hash);
    assert_eq!(live.hash.to_string(), RICH_SLOT_ZERO);
    assert_eq!(p.head().unwrap(), live);
    assert_eq!(
        f.requests
            .lock()
            .unwrap()
            .iter()
            .map(|r| r["method"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "invisi_getBlockHeaders",
            "invisi_readChainState",
            "invisi_readChainState"
        ]
    );
}
