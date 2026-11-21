use alloy_primitives::{Address, U256};
use alloy_sol_types::{SolCall, SolInterface};
use invisi_sdk::protocol::{InvisiCore, ProtocolContract};
#[test]
fn current_typescript_go_calldata_roundtrips_without_abi_drift() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/protocol-vectors.json")).unwrap();
    let mut count = 0;
    for (name, fixture) in vectors["fixtures"].as_object().unwrap() {
        if let Some(data) = fixture["calldata"].as_str() {
            let bytes = hex::decode(data.trim_start_matches("0x")).unwrap();
            let encoded = InvisiCore::InvisiCoreCalls::abi_decode_validate(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"))
                .abi_encode();
            assert_eq!(encoded, bytes, "{name}");
            count += 1;
        }
    }
    assert!(count >= 10);
}
#[test]
fn typed_reads_and_writes_have_explicit_destination_and_value() {
    let contract = ProtocolContract::new(Address::repeat_byte(1)).unwrap();
    let call = InvisiCore::isNullifierSpentCall {
        nullifier: [2u8; 32].into(),
    };
    let transaction = contract.call(&call);
    assert_eq!(transaction.to, contract.address());
    assert_eq!(transaction.value, U256::ZERO);
    assert_eq!(transaction.data, call.abi_encode());
    assert!(ProtocolContract::new(Address::ZERO).is_err());
}

#[test]
fn typed_returns_reject_invalid_boolean_padding() {
    let mut encoded = [0u8; 32];
    encoded[31] = 1;
    assert!(ProtocolContract::decode_return::<InvisiCore::isNullifierSpentCall>(&encoded).unwrap());
    encoded[31] = 0;
    assert!(
        !ProtocolContract::decode_return::<InvisiCore::isNullifierSpentCall>(&encoded).unwrap()
    );
    encoded[0] = 1;
    assert!(ProtocolContract::decode_return::<InvisiCore::isNullifierSpentCall>(&encoded).is_err());
}

fn log<E: alloy_sol_types::SolEvent>(event: &E, index: u32) -> invisi_sdk::rpc::CanonicalLog {
    let data = event.encode_log_data();
    invisi_sdk::rpc::CanonicalLog {
        address: Address::repeat_byte(1),
        topics: data.topics().to_vec(),
        data: data.data.to_vec(),
        log_index: index,
    }
}
fn receipt(logs: Vec<invisi_sdk::rpc::CanonicalLog>) -> invisi_sdk::rpc::CanonicalReceipt {
    invisi_sdk::rpc::CanonicalReceipt {
        transaction_hash: alloy_primitives::B256::repeat_byte(7),
        block: invisi_sdk::rpc::CanonicalBlock {
            number: 10,
            hash: alloy_primitives::B256::repeat_byte(1),
            parent_hash: alloy_primitives::B256::repeat_byte(2),
            timestamp: 100,
        },
        success: true,
        logs,
    }
}
#[test]
fn canonical_receipts_preserve_omitted_note_positions_and_reject_unpaired_outputs() {
    use alloy_primitives::B256;
    use invisi_sdk::protocol::decode_receipt_outputs;
    let id = B256::with_last_byte(9);
    let operation = InvisiCore::NoteOperation {
        operationId: id,
        token: Address::repeat_byte(2),
        kind: 1,
        outputCount: U256::from(1),
        deadline: U256::from(900),
        feeRecipient: Address::ZERO,
        feeAmount: U256::ZERO,
    };
    let insertion = InvisiCore::CommitmentsInserted {
        treeId: U256::from(1),
        startLeafIndex: 7,
        commitments: vec![B256::with_last_byte(3)],
    };
    let outputs = InvisiCore::NoteOutputs {
        operationId: id,
        treeId: U256::from(1),
        startLeafIndex: 7,
        packedDeliveries: vec![0, 0].into(),
    };
    let deposit = InvisiCore::PublicDeposit {
        operationId: id,
        token: operation.token,
        payer: Address::repeat_byte(3),
        amount: U256::from(1),
    };
    let decoded = decode_receipt_outputs(
        Address::repeat_byte(1),
        &receipt(vec![
            log(&operation, 0),
            log(&insertion, 1),
            log(&outputs, 2),
            log(&deposit, 3),
        ]),
    )
    .unwrap();
    assert_eq!(decoded.notes[0].leaf.leaf_index, 7);
    assert!(decoded.notes[0].delivery.ciphertext.is_empty());
    assert!(decode_receipt_outputs(
        Address::repeat_byte(1),
        &receipt(vec![log(&operation, 0), log(&outputs, 2)])
    )
    .is_err());
}
fn real_receipt(value: &serde_json::Value) -> invisi_sdk::rpc::CanonicalReceipt {
    let r = &value["receipt"];
    let uint = |v: &serde_json::Value| {
        u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    };
    invisi_sdk::rpc::CanonicalReceipt {
        transaction_hash: r["transactionHash"].as_str().unwrap().parse().unwrap(),
        block: invisi_sdk::rpc::CanonicalBlock {
            number: uint(&r["blockNumber"]),
            hash: r["blockHash"].as_str().unwrap().parse().unwrap(),
            parent_hash: alloy_primitives::B256::repeat_byte(1),
            timestamp: value["context"]["timestamp"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        },
        success: r["status"] == "0x1",
        logs: r["logs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|log| invisi_sdk::rpc::CanonicalLog {
                address: log["address"].as_str().unwrap().parse().unwrap(),
                topics: log["topics"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|t| t.as_str().unwrap().parse().unwrap())
                    .collect(),
                data: hex::decode(log["data"].as_str().unwrap().trim_start_matches("0x")).unwrap(),
                log_index: uint(&log["logIndex"]) as u32,
            })
            .collect(),
    }
}
#[test]
fn real_core_receipts_keep_note_credit_and_nullifier_counts() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/parity-receipts.json")).unwrap();
    let shared: serde_json::Value =
        serde_json::from_str(include_str!("../testdata/unified-note-receipt.json")).unwrap();
    assert_eq!(
        corpus["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "note-shield")
            .unwrap()["receipt"],
        shared["receipt"]
    );
    for case in corpus["cases"].as_array().unwrap() {
        let context = invisi_sdk::note::ProtocolContext {
            chain_id: case["context"]["chainId"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
            protocol_address: case["context"]["protocolAddress"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        };
        let output =
            invisi_sdk::protocol::decode_receipt_outputs_with_context(context, &real_receipt(case))
                .unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
        assert_eq!(
            output.notes.len() as u64,
            case["expected"]["ordinaryNotes"].as_u64().unwrap(),
            "{}",
            case["name"]
        );
        assert_eq!(
            output.credits.len() as u64,
            case["expected"]["creditStates"].as_u64().unwrap(),
            "{}",
            case["name"]
        );
        assert_eq!(
            (output.nullifiers.len() + output.credit_nullifiers.len()) as u64,
            case["expected"]["nullifiers"].as_u64().unwrap(),
            "{}",
            case["name"]
        );
    }
}
