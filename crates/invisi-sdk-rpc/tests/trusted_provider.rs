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
