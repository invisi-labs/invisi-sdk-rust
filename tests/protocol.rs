use alloy_primitives::{Address, U256};
use alloy_sol_types::{SolCall, SolInterface};
use invisi_sdk::protocol::{InvisiProtocol, ProtocolContract};
#[test]
fn current_typescript_go_calldata_roundtrips_without_abi_drift() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/protocol-vectors.json")).unwrap();
    let mut count = 0;
    for (name, fixture) in vectors["fixtures"].as_object().unwrap() {
        if let Some(data) = fixture["calldata"].as_str() {
            let bytes = hex::decode(data.trim_start_matches("0x")).unwrap();
            let call = InvisiProtocol::InvisiProtocolCalls::abi_decode(&bytes, true)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(call.abi_encode(), bytes, "{name}");
            count += 1;
        }
    }
    assert!(count >= 10);
}
#[test]
fn typed_reads_and_writes_have_explicit_destination_and_value() {
    let contract = ProtocolContract::new(Address::repeat_byte(1)).unwrap();
    let call = InvisiProtocol::isNullifierSpentCall {
        nullifier: [2u8; 32].into(),
    };
    let transaction = contract.call(&call);
    assert_eq!(transaction.to, contract.address());
    assert_eq!(transaction.value, U256::ZERO);
    assert_eq!(transaction.data, call.abi_encode());
    assert!(ProtocolContract::new(Address::ZERO).is_err());
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
    use invisi_sdk::protocol::{decode_receipt_outputs, IInvisiProtocol::Delivery};
    let insertion = InvisiProtocol::CommitmentsInserted {
        treeId: U256::from(1),
        startLeafIndex: 7,
        commitments: vec![B256::with_last_byte(3)],
    };
    let shield = InvisiProtocol::Shield {
        token: Address::repeat_byte(2),
        payer: Address::repeat_byte(3),
        amount: U256::from(1),
        treeId: U256::from(1),
        startLeafIndex: 7,
        deliveries: vec![Delivery {
            ciphertext: vec![].into(),
            clue: vec![].into(),
        }],
        deadline: U256::from(900),
    };
    let data = receipt(vec![log(&insertion, 1), log(&shield, 2)]);
    let decoded = decode_receipt_outputs(Address::repeat_byte(1), &data).unwrap();
    assert_eq!(decoded.notes[0].leaf.leaf_index, 7);
    assert!(decoded.notes[0].delivery.ciphertext.is_empty());
    assert!(
        decode_receipt_outputs(Address::repeat_byte(1), &receipt(vec![log(&shield, 2)])).is_err()
    );
    let mut spoofed = log(&shield, 2);
    spoofed.address = Address::repeat_byte(9);
    assert!(decode_receipt_outputs(
        Address::repeat_byte(1),
        &receipt(vec![log(&insertion, 1), spoofed])
    )
    .unwrap()
    .notes
    .is_empty());
}
#[test]
fn current_credit_draw_receipt_keeps_authority_separate_from_recipient_note() {
    use invisi_sdk::protocol::decode_receipt_outputs;
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/protocol-vectors.json")).unwrap();
    let data = hex::decode(
        vectors["fixtures"]["draw1"]["calldata"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
    )
    .unwrap();
    let call = match ProtocolContract::decode_call(&data).unwrap() {
        InvisiProtocol::InvisiProtocolCalls::creditDraw(call) => call,
        _ => panic!("wrong golden fixture"),
    };
    let mut commitments = call.p.creditCommitments.clone();
    commitments.push(call.p.noteCommitment);
    let insertion = InvisiProtocol::CommitmentsInserted {
        treeId: U256::from(1),
        startLeafIndex: 0,
        commitments,
    };
    let event = InvisiProtocol::CreditDraw {
        outputTreeId: U256::from(1),
        params: call.p,
        leafIndices: vec![0, 1],
        deliveries: call._2,
    };
    let data = receipt(vec![log(&insertion, 1), log(&event, 2)]);
    let output = decode_receipt_outputs(Address::repeat_byte(1), &data).unwrap();
    assert_eq!(output.credits.len(), 1);
    assert_eq!(output.credits[0].deliveries.len(), 2);
    assert_eq!(output.notes.len(), 1);
    assert_eq!(output.notes[0].leaf.leaf_index, 1);
    let mut invalid = event;
    invalid.leafIndices[1] = 2;
    assert!(decode_receipt_outputs(
        Address::repeat_byte(1),
        &receipt(vec![log(&insertion, 1), log(&invalid, 2)])
    )
    .is_err());
}
