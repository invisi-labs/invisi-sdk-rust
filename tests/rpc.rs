use alloy_primitives::{keccak256, Address, B256};
use invisi_sdk::rpc::*;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

#[derive(Clone)]
struct Chain {
    reorg: Arc<AtomicBool>,
}
fn block(number: u64) -> CanonicalBlock {
    CanonicalBlock {
        number,
        hash: B256::with_last_byte(number as u8),
        parent_hash: B256::with_last_byte(number.saturating_sub(1) as u8),
        timestamp: 100 + number,
    }
}
impl CanonicalChain for Chain {
    fn chain_id(&self) -> Result<u64> {
        Ok(31337)
    }
    fn block(&self, number: u64) -> Result<CanonicalBlock> {
        let mut b = block(number);
        if self.reorg.load(Ordering::SeqCst) {
            b.hash = B256::repeat_byte(99);
        }
        Ok(b)
    }
    fn code_at(&self, _: Address, _: Option<u64>) -> Result<Vec<u8>> {
        Ok(vec![1])
    }
    fn call(&self, _: Address, _: &[u8], _: u64) -> Result<Vec<u8>> {
        let mut out = vec![0; 32];
        out[31] = 1;
        Ok(out)
    }
}
struct Transport {
    handler: Box<dyn Fn(&Value) -> Result<Value> + Send + Sync>,
}
impl RpcTransport for Transport {
    fn send(&self, r: &Value) -> Result<Value> {
        (self.handler)(r)
    }
}
fn deployment() -> ProtocolDeployment {
    ProtocolDeployment {
        chain_id: "31337".into(),
        protocol: ContractDeployment {
            address: Address::repeat_byte(1),
            runtime_code_hash: keccak256([1]),
            from_block: 1,
        },
        registry: None,
        broadcaster_registry: None,
    }
}
fn status() -> Value {
    json!({"apiVersion":"v1","protocolVersion":"1","deployment":deployment(),"indexedHead":block(10)})
}
fn client(
    handler: impl Fn(&str, &Value) -> Value + Send + Sync + 'static,
) -> ProtocolRpcClient<Transport, Chain> {
    ProtocolRpcClient::new(Transport{handler:Box::new(move|request|Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":handler(request["method"].as_str().unwrap(),&request["params"])})))},Chain{reorg:Arc::new(AtomicBool::new(false))},deployment()).unwrap()
}
fn note() -> Value {
    json!({"block":block(10),"treeId":"1","leafIndex":7,"commitment":B256::with_last_byte(3),"token":Address::repeat_byte(2),"transactionHash":B256::with_last_byte(4),"logIndex":1,"kind":"NoteOutputs","ciphertext":"0x","clue":"0x"})
}
#[test]
fn transport_rejects_substituted_envelopes_and_preserves_remote_errors() {
    let bad = JsonRpc::new(Transport {
        handler: Box::new(|_| Ok(json!({"jsonrpc":"2.0","id":999,"result":[]}))),
    });
    assert!(bad.call("method", json!([])).is_err());
    let remote = JsonRpc::new(Transport {
        handler: Box::new(|r| {
            Ok(
                json!({"jsonrpc":"2.0","id":r["id"],"error":{"code":-32000,"message":"not ready","data":{"retry":true}}}),
            )
        }),
    });
    assert!(matches!(
        remote.call("method", json!([])),
        Err(Error::Remote { code: -32000, .. })
    ));
    assert!(HttpTransport::protocol("https://rpc.example/v1", 31337).is_ok());
    assert!(HttpTransport::protocol("https://rpc.example/v1/chains/1", 31337).is_err());
    assert!(HttpTransport::new("https://user:pass@rpc.example/v1").is_err());
}
#[test]
fn pinned_status_and_update_anchor_are_independently_checked() {
    let good = client(|method, _| {
        if method == "invisi_getStatus" {
            status()
        } else {
            json!({"blockHash":block(10).hash,"notes":[note()]})
        }
    });
    good.validate_deployment().unwrap();
    assert_eq!(
        good.get_note_updates(1, 10).unwrap().items[0]
            .leaf
            .leaf_index,
        7
    );
    assert!(good.get_note_updates(1, 10001).is_err());
    let wrong = client(|method, _| {
        if method == "invisi_getStatus" {
            status()
        } else {
            json!({"blockHash":B256::ZERO,"notes":[]})
        }
    });
    assert!(wrong.get_note_updates(1, 10).is_err());
    good.chain.reorg.store(true, Ordering::SeqCst);
    assert!(good.get_status().is_err());
}
#[test]
fn note_and_credit_collections_cannot_be_interchanged() {
    let mut authority = note();
    authority["kind"] = json!("CreditCreated");
    authority["deliveries"] = json!(vec![
        json!({"ciphertext":"0x82","clue":format!("0x{}","00".repeat(68))});
        2
    ]);
    assert!(NoteOutput::parse(&authority).is_err());
    assert!(IndexedCreditState::parse(&authority).is_ok());
    assert!(IndexedCreditState::parse(&note()).is_err());
    let mut unpaired = note();
    unpaired["clue"] = json!(format!("0x{}", "00".repeat(68)));
    assert!(NoteOutput::parse(&unpaired).is_err());
    let wrong = client(move |method, _| {
        if method == "invisi_getStatus" {
            status()
        } else {
            json!({"blockHash":block(10).hash,"notes":[authority.clone()]})
        }
    });
    assert!(wrong.get_note_updates(1, 10).is_err());
}
#[test]
fn canonical_integers_and_fields_reject_aliases_and_overflow() {
    for value in [
        json!("01"),
        json!("-1"),
        json!("0x01"),
        json!(9007199254740992u64),
    ] {
        assert!(uint(&value, 64).is_err());
    }
    assert!(field(B256::repeat_byte(255)).is_err());
    assert!(decimal(&json!("00")).is_err());
    let mut bad = note();
    bad["leafIndex"] = json!(65536);
    assert!(NoteOutput::parse(&bad).is_err());
}
#[test]
fn transaction_index_availability_never_confuses_unknown_with_empty() {
    let transaction = B256::with_last_byte(4);
    let not_found = client(move |method, _| {
        if method == "invisi_getStatus" {
            status()
        } else {
            json!({"transactionHash":transaction,"status":"not_found","indexedHead":block(10),"notes":null})
        }
    });
    assert!(matches!(
        not_found.get_transaction_note_updates(transaction).unwrap(),
        Availability::NotFound { .. }
    ));
    let pending = client(move |method, _| {
        if method == "invisi_getStatus" {
            status()
        } else {
            json!({"transactionHash":transaction,"status":"pending_index","indexedHead":block(10),"blockNumber":10,"blockHash":block(10).hash,"receiptStatus":1,"notes":[]})
        }
    });
    assert!(pending.get_transaction_note_updates(transaction).is_err());
    let indexed = client(move |method, _| {
        if method == "invisi_getStatus" {
            status()
        } else {
            json!({"transactionHash":transaction,"status":"indexed","indexedHead":block(10),"blockNumber":10,"blockHash":block(10).hash,"receiptStatus":1,"notes":[note()]})
        }
    });
    assert!(
        matches!(indexed.get_transaction_note_updates(transaction).unwrap(),Availability::Indexed{items,..}if items.len()==1)
    );
}
#[test]
fn membership_is_bound_to_chain_known_root_and_exact_poseidon_path() {
    let leaf = B256::with_last_byte(3);
    let siblings = vec![B256::ZERO; 16];
    let mut current = invisi_sdk::field::bytes_to_field(leaf.as_slice());
    for sibling in &siblings {
        current = invisi_sdk::poseidon::hash(&[
            current,
            invisi_sdk::field::bytes_to_field(sibling.as_slice()),
        ]);
    }
    let root = B256::from(invisi_sdk::field::field_to_bytes_be(current));
    let anchor = json!({"treeId":1,"root":root,"leafCount":1,"block":block(10)});
    let good = client(move |method, _| match method {
        "invisi_getStatus" => status(),
        "invisi_getRoots" => json!([anchor.clone()]),
        "invisi_getMembership" => {
            json!({"anchor":anchor,"leafIndex":0,"commitment":leaf,"siblings":siblings})
        }
        _ => panic!("unexpected method {method}"),
    });
    let input = MembershipInput {
        tree_id: 1,
        leaf_index: 0,
        commitment: leaf,
        root: None,
    };
    assert_eq!(good.get_membership(&input, &block(10)).unwrap().root, root);
    let wrong = MembershipInput {
        commitment: B256::with_last_byte(5),
        ..input
    };
    assert!(good.get_membership(&wrong, &block(10)).is_err());
}

#[test]
fn ethereum_receipts_require_canonical_blocks_and_bound_ordered_logs() {
    let transaction = B256::with_last_byte(4);
    let chain = EthereumChain::new(Transport {
        handler: Box::new(move |request| {
            let result = match request["method"].as_str().unwrap() {
                "eth_getBlockByNumber" => {
                    json!({"number":"0xa","timestamp":"0x6e","hash":block(10).hash,"parentHash":block(10).parent_hash})
                }
                "eth_getTransactionReceipt" => {
                    json!({"transactionHash":transaction,"blockNumber":"0xa","blockHash":block(10).hash,"status":"0x1","logs":[{"address":Address::repeat_byte(1),"transactionHash":transaction,"blockNumber":"0xa","blockHash":block(10).hash,"logIndex":"0x2","topics":[B256::repeat_byte(3)],"data":"0x","removed":false}]})
                }
                _ => panic!("unexpected method"),
            };
            Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
        }),
    });
    let receipt = chain.receipt(transaction).unwrap().unwrap();
    assert!(receipt.success);
    assert_eq!(receipt.logs[0].log_index, 2);
}

#[test]
fn http_transport_maps_service_chain_paths_and_reports_retry_after() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for expected in ["GET /v1 ", "POST /v1/chains/31337 "] {
            let (mut socket, _) = listener.accept().unwrap();
            let mut data = Vec::new();
            let mut byte = [0; 1];
            while !data.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                data.push(byte[0]);
            }
            let header = String::from_utf8(data).unwrap();
            assert!(header.starts_with(expected));
            if expected.starts_with("GET") {
                let body = r#"{"apiVersion":"v1","chains":[{"chainId":"31337","protocolVersion":"1","rpcPath":"/v1/chains/31337"}]}"#;
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .unwrap();
            } else {
                write!(socket,"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nRetry-After: 3\r\nConnection: close\r\n\r\n").unwrap();
            }
        }
    });
    let endpoint = format!("http://{address}/v1");
    let discovery = HttpTransport::new(&endpoint).unwrap();
    assert_eq!(discovery.discover_chains().unwrap()[0].chain_id, 31337);
    let rpc = JsonRpc::new(HttpTransport::protocol(&endpoint, 31337).unwrap());
    assert!(
        matches!(rpc.call("invisi_getStatus",json!([])),Err(Error::Http{status:429,retry_after:Some(value)})if value=="3")
    );
    server.join().unwrap();
}

#[test]
fn signed_relay_binds_chain_nonce_price_and_hash() {
    use alloy_primitives::U256;
    let raw = vec![1, 2, 3];
    let expected = keccak256(&raw);
    let chain = EthereumChain::new(Transport {
        handler: Box::new(move |r| {
            let result = match r["method"].as_str().unwrap() {
                "eth_chainId" => json!("0x7a69"),
                "eth_getTransactionCount" => {
                    assert_eq!(r["params"][1], "pending");
                    json!("0x2")
                }
                "eth_gasPrice" => json!("0x3b9aca00"),
                "eth_sendRawTransaction" => {
                    assert_eq!(r["params"][0], "0x010203");
                    json!(expected)
                }
                _ => panic!("unexpected Ethereum method"),
            };
            Ok(json!({"jsonrpc":"2.0","id":r["id"],"result":result}))
        }),
    });
    assert_eq!(chain.pending_nonce(Address::repeat_byte(3)).unwrap(), 2);
    assert_eq!(chain.gas_price().unwrap(), U256::from(1_000_000_000));
    assert_eq!(chain.send_raw_transaction(31337, &raw).unwrap(), expected);
}

#[test]
fn ethereum_transaction_reads_bind_hash_chain_calldata_and_canonical_block() {
    let transaction = B256::with_last_byte(4);
    let chain = EthereumChain::new(Transport {
        handler: Box::new(move |request| {
            let result = match request["method"].as_str().unwrap() {
                "eth_chainId" => json!("0x7a69"),
                "eth_blockNumber" => json!("0xa"),
                "eth_getBlockByNumber" => {
                    json!({"number":"0xa","timestamp":"0x6e","hash":block(10).hash,"parentHash":block(10).parent_hash})
                }
                "eth_getTransactionByHash" => {
                    json!({"hash":transaction,"chainId":"0x7a69","to":Address::repeat_byte(1),"input":"0x010203","value":"0x7","blockNumber":"0xa","blockHash":block(10).hash})
                }
                _ => panic!("unexpected Ethereum method"),
            };
            Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
        }),
    });
    let value = chain.transaction(transaction).unwrap().unwrap();
    assert_eq!(value.input, vec![1, 2, 3]);
    assert_eq!(value.to, Some(Address::repeat_byte(1)));
    assert_eq!(value.chain_id, 31337);
    assert_eq!(value.block, Some(block(10)));
    assert_eq!(chain.head().unwrap(), block(10));
}

#[test]
fn membership_rejects_noncanonical_roots_even_when_outside_selected_history() {
    let leaf = B256::with_last_byte(3);
    let path = vec![B256::ZERO; 16];
    let mut current = invisi_sdk::field::bytes_to_field(leaf.as_slice());
    for sibling in &path {
        current = invisi_sdk::poseidon::hash(&[
            current,
            invisi_sdk::field::bytes_to_field(sibling.as_slice()),
        ]);
    }
    let root = B256::from(invisi_sdk::field::field_to_bytes_be(current));
    let anchor = json!({"treeId":1,"root":root,"leafCount":1,"block":block(10)});
    let rpc = client(move |method, _| match method {
        "invisi_getStatus" => status(),
        "invisi_getRoots" => {
            json!([{"treeId":1,"root":B256::repeat_byte(255),"leafCount":1,"block":block(11)},anchor.clone()])
        }
        "invisi_getMembership" => {
            json!({"anchor":anchor,"leafIndex":0,"commitment":leaf,"siblings":path})
        }
        _ => panic!("unexpected method"),
    });
    assert!(rpc
        .get_membership(
            &MembershipInput {
                tree_id: 1,
                leaf_index: 0,
                commitment: leaf,
                root: None
            },
            &block(10)
        )
        .is_err());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = calls.clone();
    let rpc = client(move |_, _| {
        count.fetch_add(1, Ordering::SeqCst);
        status()
    });
    assert!(rpc
        .get_membership(
            &MembershipInput {
                tree_id: 1,
                leaf_index: 0,
                commitment: leaf,
                root: Some(B256::repeat_byte(255))
            },
            &block(10)
        )
        .is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn broadcaster_discovery_preserves_unselected_contract_declarations() {
    let mut pinned = deployment();
    pinned.broadcaster_registry = Some(pinned.protocol.clone());
    let endpoint = "https://bad host";
    let rpc=ProtocolRpcClient::new(Transport{handler:Box::new(move|r|Ok(json!({"jsonrpc":"2.0","id":r["id"],"result":{"block":block(10),"broadcasters":[{"operator":Address::repeat_byte(3),"endpoint":endpoint,"metadataURI":"","quoteSigner":Address::repeat_byte(4),"feeRecipient":Address::repeat_byte(5),"enabled":false,"block":block(10)}]}})))},Chain{reorg:Arc::new(AtomicBool::new(false))},pinned).unwrap();
    let page = rpc.get_broadcasters(&BroadcasterQuery::default()).unwrap();
    assert_eq!(page.broadcasters[0].endpoint, endpoint);
    let configuration = invisi_sdk::broadcaster::Configuration {
        endpoint: endpoint.into(),
        quote_signer: Address::repeat_byte(4),
        fee_recipient: Address::repeat_byte(5),
    };
    assert!(configuration.validate().is_err());
}

#[test]
fn stale_untrusted_heads_do_not_block_pending_transactions_or_older_canonical_ranges() {
    let mut stale = status();
    stale["indexedHead"]["hash"] = json!(B256::repeat_byte(99));
    let head = stale["indexedHead"].clone();
    let transaction = B256::with_last_byte(4);
    let rpc = client(move |method, _| match method {
        "invisi_getStatus" => stale.clone(),
        "invisi_getTransactionNoteUpdates" => {
            json!({"transactionHash":transaction,"status":"pending_index","indexedHead":head,"blockNumber":9,"blockHash":block(9).hash,"receiptStatus":1,"notes":null})
        }
        "invisi_getNoteUpdates" => json!({"blockHash":block(9).hash,"notes":[]}),
        _ => panic!("unexpected method"),
    });
    assert!(rpc.get_status().is_err());
    assert!(matches!(
        rpc.get_transaction_note_updates(transaction).unwrap(),
        Availability::PendingIndex { .. }
    ));
    assert!(rpc.get_note_updates(1, 9).unwrap().items.is_empty());
    assert!(rpc.get_note_updates(1, 10).is_err());
}

#[test]
fn empty_range_null_collections_match_current_service_encoding() {
    let rpc = client(move |method, _| match method {
        "invisi_getStatus" => status(),
        "invisi_getNoteUpdates" => json!({"blockHash":block(10).hash,"notes":null}),
        "invisi_getCreditTransitions" => Value::Null,
        _ => panic!("unexpected method"),
    });
    assert!(rpc.get_note_updates(1, 10).unwrap().items.is_empty());
    assert!(rpc.get_credit_transitions(1, 10).unwrap().items.is_empty());
}

#[test]
fn indexed_duplicate_aliases_are_compared_after_typed_normalization() {
    let first = note();
    let mut duplicate = first.clone();
    duplicate["treeId"] = json!(1);
    duplicate["block"]["hash"] = json!(format!("0x{}", hex::encode(block(10).hash).to_uppercase()));
    duplicate["futureMetadata"] = json!("ignored");
    let rpc = client(move |method, _| {
        if method == "invisi_getStatus" {
            status()
        } else {
            json!({"blockHash":block(10).hash,"notes":[first.clone(),duplicate.clone()]})
        }
    });
    assert_eq!(rpc.get_note_updates(1, 10).unwrap().items.len(), 1);
}

#[test]
fn token_discovery_pins_pages_and_skips_incompatible_operators() {
    use invisi_sdk::broadcaster::Configuration;
    let mut pins = deployment();
    pins.broadcaster_registry = Some(pins.protocol.clone());
    let token = Address::repeat_byte(9);
    let pages = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let page_calls = pages.clone();
    let rpc = ProtocolRpcClient::new(
        Transport { handler: Box::new(move |r| {
            page_calls.fetch_add(1,Ordering::SeqCst);
            assert_eq!(r["method"], "invisi_getBroadcasters");
            assert!(r["params"][0].get("tokenAddress").is_none());
            assert_eq!(r["params"][0]["enabled"], true);
            let second = r["params"][0].get("after").is_some();
            if second { assert_eq!(r["params"][0]["block"], serde_json::to_value(block(10)).unwrap()); }
            let ids: Vec<u8> = if second { vec![101,102] } else { (1..=100).collect() };
            let rows: Vec<_> = ids.into_iter().map(|id| json!({"operator":Address::repeat_byte(id),"endpoint":format!("https://relay{id}.example"),"metadataURI":"","quoteSigner":Address::repeat_byte(id+10),"feeRecipient":Address::repeat_byte(id+20),"enabled":true,"block":block(10)})).collect();
            let mut result=json!({"block":block(10),"broadcasters":rows});
            if !second {result["next"]=json!(Address::repeat_byte(100));}
            Ok(json!({"jsonrpc":"2.0","id":r["id"],"result":result}))
        }) },
        Chain { reorg: Arc::new(AtomicBool::new(false)) }, pins,
    ).unwrap();
    let selected = rpc.discover_broadcasters_with_transport(token, |configuration: &Configuration| {
        let cfg=configuration.clone();
        Ok(Transport { handler: Box::new(move |r| {
            assert_eq!(r["method"],"broadcaster_getTokenSupport");
            assert_eq!(r["params"][0]["tokenAddress"],json!(token));
            if cfg.endpoint.contains("relay3") { return Err(Error::Transport("offline".into())); }
            Ok(json!({"jsonrpc":"2.0","id":r["id"],"result":{"apiVersion":"v1","protocolVersion":"1","chainId":if cfg.endpoint.contains("relay4") {"2"} else {"31337"},"protocol":Address::repeat_byte(1),"sender":cfg.quote_signer,"feeRecipient":cfg.fee_recipient,"tokenAddress":if cfg.endpoint.contains("relay5") {Address::repeat_byte(8)}else{token},"supported":cfg.endpoint=="https://relay1.example","submissionHalted":false,"provenance":{"enabled":false}}}))
        }) })
    }).unwrap();
    assert_eq!(pages.load(Ordering::SeqCst), 2);
    assert_eq!(selected.len(), 1);
    assert_eq!(
        selected[0].configuration().endpoint,
        "https://relay1.example"
    );
    assert!(rpc
        .discover_broadcasters_with_transport(Address::ZERO, |_| -> Result<Transport> {
            panic!("zero token reached network")
        })
        .is_err());
}
