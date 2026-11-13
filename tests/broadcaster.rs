use alloy_primitives::{Address, B256};
use invisi_sdk::broadcaster::{quote_digest, request_hash, verify_quote, SignedQuote, Trust};
#[test]
fn six_current_quote_and_request_hash_vectors_match_independent_typescript_reference() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/broadcaster-vectors.json")).unwrap();
    for row in rows.as_array().unwrap() {
        let data = hex::decode(row["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        let unsigned = hex::decode(
            row["unsignedVariant"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let expected: B256 = row["requestHash"].as_str().unwrap().parse().unwrap();
        assert_eq!(request_hash(&data).unwrap(), expected);
        assert_eq!(request_hash(&unsigned).unwrap(), expected);
        let trust = Trust {
            chain_id: row["trust"]["chainId"].as_str().unwrap().parse().unwrap(),
            protocol: row["trust"]["protocol"]
                .as_str()
                .unwrap()
                .parse::<Address>()
                .unwrap(),
            signer: row["trust"]["signer"].as_str().unwrap().parse().unwrap(),
        };
        let signed: SignedQuote = serde_json::from_value(
            serde_json::json!({"quote":row["quote"],"signature":row["signature"]}),
        )
        .unwrap();
        assert_eq!(
            quote_digest(&signed.quote, &trust).unwrap(),
            row["quoteDigest"]
                .as_str()
                .unwrap()
                .parse::<B256>()
                .unwrap()
        );
        verify_quote(&signed, &trust, &data, 0).unwrap();
        let mut changed = signed.clone();
        changed.quote.fee_amount = "999".into();
        assert!(verify_quote(&changed, &trust, &data, 0).is_err());
    }
}

#[test]
fn quotes_reject_different_context_expiry_and_noncanonical_calldata() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/broadcaster-vectors.json")).unwrap();
    let row = &rows[0];
    let mut data = hex::decode(row["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let trust = Trust {
        chain_id: 56,
        protocol: row["trust"]["protocol"].as_str().unwrap().parse().unwrap(),
        signer: row["trust"]["signer"].as_str().unwrap().parse().unwrap(),
    };
    let signed: SignedQuote = serde_json::from_value(
        serde_json::json!({"quote":row["quote"],"signature":row["signature"]}),
    )
    .unwrap();
    let mut changed = trust.clone();
    changed.chain_id += 1;
    assert!(verify_quote(&signed, &changed, &data, 0).is_err());
    changed = trust.clone();
    changed.protocol = Address::repeat_byte(9);
    assert!(verify_quote(&signed, &changed, &data, 0).is_err());
    changed = trust.clone();
    changed.signer = Address::repeat_byte(9);
    assert!(verify_quote(&signed, &changed, &data, 0).is_err());
    assert!(verify_quote(&signed, &trust, &data, u64::MAX).is_err());
    data.extend([0; 32]);
    assert!(request_hash(&data).is_err());
}
#[test]
fn client_verifies_registered_quote_and_submit_status_correlation() {
    use invisi_sdk_rpc::{
        broadcaster::{BroadcasterClient, Configuration},
        rpc::{Result, RpcTransport},
    };
    use serde_json::{json, Value};
    struct Transport {
        signed: Value,
        service: Value,
        submission: Option<Value>,
    }
    impl RpcTransport for Transport {
        fn send(&self, r: &Value) -> Result<Value> {
            let result = match r["method"].as_str().unwrap() {
                "broadcaster_getQuote" => self.signed.clone(),
                "broadcaster_getStatus" => self.service.clone(),
                "broadcaster_getTokenSupport" => {
                    let mut v = self.service.clone();
                    v["tokenAddress"] = r["params"][0]["tokenAddress"].clone();
                    v["supported"] = json!(true);
                    v
                }
                "broadcaster_estimateQuote" => {
                    json!({"feeRecipient":self.signed["quote"]["feeRecipient"],"feeAmount":"1","maxGas":"21000"})
                }
                "broadcaster_submitTransaction" => {
                    assert!(r["params"][0].get("idempotencyKey").is_none());
                    self.submission
                        .clone()
                        .unwrap_or_else(|| json!({"id":"server-owned","state":"pending"}))
                }
                "broadcaster_getTransactionStatus" => {
                    json!({"id":"substituted","state":"confirmed"})
                }
                _ => panic!("unexpected broadcaster method"),
            };
            Ok(json!({"jsonrpc":"2.0","id":r["id"],"result":result}))
        }
    }
    let rows: Value =
        serde_json::from_str(include_str!("fixtures/broadcaster-vectors.json")).unwrap();
    let row = &rows[0];
    let data = hex::decode(row["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let configuration = Configuration {
        endpoint: "https://relay.example/rpc".into(),
        quote_signer: row["trust"]["signer"].as_str().unwrap().parse().unwrap(),
        fee_recipient: row["quote"]["feeRecipient"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    };
    let service = json!({"apiVersion":"v1","protocolVersion":"1","chainId":"56","protocol":row["trust"]["protocol"],"sender":configuration.quote_signer,"feeRecipient":configuration.fee_recipient,"submissionHalted":false,"provenance":{"enabled":false}});
    let client = BroadcasterClient::new(
        configuration.clone(),
        Transport {
            submission: None,
            signed: json!({"quote":row["quote"],"signature":row["signature"]}),
            service: service.clone(),
        },
    )
    .unwrap();
    let protocol = row["trust"]["protocol"].as_str().unwrap().parse().unwrap();
    let verified = client.quote(&data, 56, protocol, 0).unwrap();
    assert!(!client.submission_requirements(&verified).unwrap());
    assert!(client
        .supports_token(verified.signed().quote.token, 56, protocol)
        .unwrap());
    for (field, value) in [
        ("chainId", json!("57")),
        ("sender", json!(Address::ZERO)),
        ("submissionHalted", json!(true)),
        (
            "provenance",
            json!({"enabled":true,"requestHashFormat":"invisi-broadcaster-provenance-intent-v1","trackingRequired":true,"trackingSupported":true}),
        ),
    ] {
        let mut bad = service.clone();
        bad[field] = value;
        let changed = BroadcasterClient::new(
            configuration.clone(),
            Transport {
                submission: None,
                signed: json!({"quote":row["quote"],"signature":row["signature"]}),
                service: bad,
            },
        )
        .unwrap();
        assert!(changed.submission_requirements(&verified).is_err());
        if field != "provenance" {
            assert!(
                changed
                    .supports_token(verified.signed().quote.token, 56, protocol)
                    .is_err()
                    || !changed
                        .supports_token(verified.signed().quote.token, 56, protocol)
                        .unwrap()
            );
        }
    }
    assert_eq!(client.estimate_quote(&data).unwrap().fee_amount, "1");
    assert_eq!(
        client.submit_transaction(&data, &verified).unwrap().id,
        "server-owned"
    );
    assert!(client.status("operation-1").is_err());
    for state in ["queued", "proving", "confirmed"] {
        let malformed=BroadcasterClient::new(configuration.clone(),Transport{signed:json!({"quote":row["quote"],"signature":row["signature"]}),service:service.clone(),submission:Some(json!({"id":"server-owned","state":state,"confirmation":{"level":"finalized","status":"available","block":{"number":"10","hash":B256::repeat_byte(1),"timestamp":123}}}))}).unwrap();
        assert!(
            malformed.submit_transaction(&data, &verified).is_err(),
            "accepted impossible submit confirmation context"
        );
    }
}

#[test]
fn execution_is_mandatory_and_bound_to_signature() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/broadcaster-vectors.json")).unwrap();
    let row = &rows[0];
    let mut quote = row["quote"].clone();
    quote.as_object_mut().unwrap().remove("execution");
    assert!(serde_json::from_value::<invisi_sdk::broadcaster::Quote>(quote).is_err());
    let mut signed: SignedQuote = serde_json::from_value(
        serde_json::json!({"quote":row["quote"],"signature":row["signature"]}),
    )
    .unwrap();
    let trust = Trust {
        chain_id: 56,
        protocol: row["trust"]["protocol"].as_str().unwrap().parse().unwrap(),
        signer: row["trust"]["signer"].as_str().unwrap().parse().unwrap(),
    };
    let data = hex::decode(row["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    signed.quote.execution = invisi_sdk::broadcaster::Execution::Aggregate;
    assert!(verify_quote(&signed, &trust, &data, 0).is_err());
}

#[test]
fn aggregate_admission_and_lifecycle_states_match_wire_contract() {
    use invisi_sdk::broadcaster::{aggregate_member_capacity, Status};
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/broadcaster-vectors.json")).unwrap();
    for row in rows.as_array().unwrap() {
        let data = hex::decode(row["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        assert!(
            aggregate_member_capacity(&data).is_err(),
            "existing vectors have funding or non-Note methods"
        );
    }
    for state in ["queued", "proving", "rejected", "expired"] {
        let status: Status =
            serde_json::from_value(serde_json::json!({"id":"relay-id","state":state})).unwrap();
        assert_eq!(serde_json::to_value(status).unwrap()["state"], state);
    }
}

#[test]
fn recursive_member_wire_rejects_an_evm_bundle_before_transport() {
    use invisi_sdk::broadcaster::{validate_member_proof, MemberProof};
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/broadcaster-vectors.json")).unwrap();
    let data = hex::decode(rows[0]["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let proof: MemberProof = serde_json::from_value(serde_json::json!({"formatVersion":1,"circuitName":"transact_user_slots1","target":"evm","bbVersion":"6.0.0","artifactSha256":"00".repeat(32),"vkSha256":"00".repeat(32),"proofHex":"0x00","proofSha256":"00".repeat(32),"publicInputs":[]})).unwrap();
    assert!(validate_member_proof(&data, &proof).is_err());
}

#[test]
fn broadcaster_aggregate_confirmation_matches_business_member_exactly_once() {
    use alloy_sol_types::SolCall;
    use invisi_sdk_rpc::{
        broadcaster::{matches_execution_transaction, Execution},
        protocol::InvisiProtocol as P,
    };
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/broadcaster-vectors.json")).unwrap();
    let data = hex::decode(rows[0]["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let mut member = P::transact_0Call::abi_decode(&data, true).unwrap();
    member.r.funding.amount = alloy_primitives::U256::ZERO;
    let member_data = member.abi_encode();
    let mut outer = P::transact_1Call {
        _0: vec![1; 32].into(),
        requests: vec![member.r.clone()],
    };
    assert!(matches_execution_transaction(
        &member_data,
        Execution::Aggregate,
        &outer.abi_encode()
    ));
    assert!(!matches_execution_transaction(
        &member_data,
        Execution::Aggregate,
        &member_data
    ));
    outer.requests.push(member.r.clone());
    assert!(!matches_execution_transaction(
        &member_data,
        Execution::Aggregate,
        &outer.abi_encode()
    ));
    outer.requests.clear();
    assert!(!matches_execution_transaction(
        &member_data,
        Execution::Aggregate,
        &outer.abi_encode()
    ));
    outer.requests.push(member.r.clone());
    outer.requests[0].params.deadline += alloy_primitives::U256::from(1);
    assert!(!matches_execution_transaction(
        &member_data,
        Execution::Aggregate,
        &outer.abi_encode()
    ));
    assert!(matches_execution_transaction(
        &member_data,
        Execution::Direct,
        &member_data
    ));
}

#[test]
fn aggregate_rpc_sends_the_public_member_and_checks_nested_capability() {
    use alloy_primitives::U256;
    use alloy_sol_types::SolCall;
    use invisi_sdk_rpc::{
        broadcaster::{
            BroadcasterClient, Configuration, Execution, MemberProof, Quote, VerifiedQuote,
        },
        protocol::InvisiProtocol as P,
        rpc::{Result, RpcTransport},
    };
    use serde_json::{json, Value};
    struct Transport {
        service: Value,
        member: Value,
        data: String,
    }
    impl RpcTransport for Transport {
        fn send(&self, request: &Value) -> Result<Value> {
            let result = match request["method"].as_str().unwrap() {
                "broadcaster_getStatus" => self.service.clone(),
                "broadcaster_submitTransaction" => {
                    let body = &request["params"][0];
                    assert_eq!(body["data"], self.data);
                    assert_eq!(body["memberProof"], self.member);
                    assert_eq!(body["quote"]["execution"], "aggregate");
                    assert_eq!(body["proofSidecars"], json!([]));
                    json!({"id":"aggregate-id","state":"queued"})
                }
                method => panic!("unexpected method {method}"),
            };
            Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
        }
    }
    let rows: Value =
        serde_json::from_str(include_str!("fixtures/broadcaster-vectors.json")).unwrap();
    let row = &rows[0];
    let mut call = P::transact_0Call::abi_decode(
        &hex::decode(row["data"].as_str().unwrap().trim_start_matches("0x")).unwrap(),
        true,
    )
    .unwrap();
    call.r.funding = invisi_sdk::sdk::empty_funding();
    let capacity = call.r.params.nullifiers.len() + call.r.params.noteCommitments.len();
    call._0 = vec![0; 458 * 32].into();
    let data = call.abi_encode();
    let mut inputs = vec![B256::ZERO; 17 + 3 * capacity];
    inputs[3] = B256::from(U256::from(call.r.params.nullifiers.len()).to_be_bytes::<32>());
    inputs[4] = B256::from(U256::from(call.r.params.noteCommitments.len()).to_be_bytes::<32>());
    let statement = invisi_sdk::prover::statement(
        &format!("transact_user_slots{capacity}"),
        "noir-recursive",
        inputs.clone(),
    )
    .unwrap();
    let member = MemberProof {
        format_version: 1,
        circuit_name: statement.circuit_name,
        target: statement.target,
        bb_version: "6.0.0".into(),
        artifact_sha256: statement.artifact_sha256,
        vk_sha256: statement.vk_sha256,
        proof_hex: format!("0x{}", hex::encode(&call._0)),
        proof_sha256: invisi_sdk::prover::sha256(&call._0),
        public_inputs: inputs,
    };
    let trust = Trust {
        chain_id: 56,
        protocol: row["trust"]["protocol"].as_str().unwrap().parse().unwrap(),
        signer: row["trust"]["signer"].as_str().unwrap().parse().unwrap(),
    };
    let mut quote: Quote = serde_json::from_value(row["quote"].clone()).unwrap();
    quote.execution = Execution::Aggregate;
    quote.request_hash = request_hash(&data).unwrap();
    let mut key = [0; 32];
    key[31] = 7;
    let (signature, recovery) = k256::ecdsa::SigningKey::from_slice(&key)
        .unwrap()
        .sign_prehash_recoverable(quote_digest(&quote, &trust).unwrap().as_slice())
        .unwrap();
    let mut signature = signature.to_bytes().to_vec();
    signature.push(recovery.to_byte());
    let verified = VerifiedQuote::authenticate(
        SignedQuote {
            quote,
            signature: format!("0x{}", hex::encode(signature)),
            request_hash_format: None,
            provenance_required: None,
        },
        trust.clone(),
        &data,
        0,
        None,
    )
    .unwrap();
    let config = Configuration {
        endpoint: "https://relay.example".into(),
        quote_signer: trust.signer,
        fee_recipient: verified.signed().quote.fee_recipient,
    };
    for supported in [false, true] {
        let service = json!({"apiVersion":"v1","protocolVersion":"1","chainId":"56","protocol":trust.protocol,"sender":trust.signer,"feeRecipient":config.fee_recipient,"submissionHalted":false,"aggregateSupported":true,"provenance":{"enabled":false,"aggregateSupported":supported}});
        let client = BroadcasterClient::new(
            config.clone(),
            Transport {
                service,
                member: serde_json::to_value(&member).unwrap(),
                data: format!("0x{}", hex::encode(&data)),
            },
        )
        .unwrap();
        assert_eq!(client.submission_requirements(&verified).is_ok(), supported);
        assert!(client.submit_transaction(&data, &verified).is_err());
        assert_eq!(
            client
                .submit_with_member_proof(&data, &verified, &[], Some(&member))
                .unwrap()
                .id,
            "aggregate-id"
        );
        let mut altered = member.clone();
        altered.proof_hex = "0x00".into();
        assert!(client
            .submit_with_member_proof(&data, &verified, &[], Some(&altered))
            .is_err());
    }
}
