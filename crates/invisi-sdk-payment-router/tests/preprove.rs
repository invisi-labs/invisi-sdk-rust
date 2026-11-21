use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{SolCall, SolValue};
use invisi_sdk_payment_router::{canonical::*, *};
use invisi_sdk_protocol::protocol::{InvisiCore, TransactionCall};
use serde_json::{json, Value};
fn fixture(proof: &[u8]) -> Payment {
    let v: Value = serde_json::from_str(include_str!("fixtures/intent.json")).unwrap();
    let c = &v["cases"][2];
    let data = hex::decode(c["call"]["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let call = PaymentRouter::payTokenForCall::abi_decode_validate(&data).unwrap();
    let d = PaymentRouterDeployment {
        chain_id: 31337,
        core_address: Address::repeat_byte(0x11),
        router_address: Address::repeat_byte(0x33),
        weth_address: Address::repeat_byte(0x44),
        uniswap_router_address: Address::repeat_byte(0x55),
        runtime_code_hash: None,
        zero_ex: None,
    };
    let core = InvisiCore::transact_0Call {
        _0: Bytes::copy_from_slice(proof),
        r: invisi_sdk_protocol::protocol::IInvisiCore::TransactRequest::abi_decode_validate(
            &call.r.abi_encode(),
        )
        .unwrap(),
    };
    Payment::prepare_draft(
        &d,
        TransactionCall {
            to: d.core_address,
            data: core.abi_encode(),
            value: U256::ZERO,
        },
        call.i,
        call.route,
        1000,
        None,
    )
    .unwrap()
}
#[test]
fn model_conservative_and_unknown_zeroex() {
    let input: RouterGasInput = serde_json::from_value(json!({"coreGasUnits":100000,"mode":2,"channel":1,"hopCount":2,"routeBytes":43,"permit":true,"authorizationCount":0})).unwrap();
    let estimate = estimate_router_gas(&input).unwrap();
    assert_eq!(estimate["gasUnits"], 460688);
    assert_eq!(estimate["source"], "model");
    let mut unknown = input.clone();
    unknown.channel = 2;
    unknown.hop_count = 0;
    assert_eq!(
        estimate_router_gas(&unknown).unwrap()["reason"],
        "zeroex-route-gas-unavailable"
    );
    unknown.core_gas_units = 9_007_199_254_740_992;
    assert_eq!(
        estimate_router_gas(&unknown).unwrap()["reason"],
        "invalid-router-gas-input"
    );
}
#[test]
fn draft_and_final_semantic_identity() {
    let draft = fixture(&[]);
    let final_payment = fixture(&[1, 2, 3]);
    let a = draft.draft_relay_envelope(Permit::default()).unwrap();
    let b = final_payment
        .relay_envelope(Permit::default(), Bytes::from(vec![7; 65]))
        .unwrap();
    let core = draft.core().to;
    assert_eq!(
        router_intent_hash(31337, core, &a).unwrap(),
        router_intent_hash(31337, core, &b).unwrap()
    );
    assert_ne!(
        envelope_hash(31337, core, &a).unwrap(),
        envelope_hash(31337, core, &b).unwrap()
    );
    assert!(draft.check_final_envelope(&a).is_err());
    assert!(final_payment.check_final_envelope(&b).is_ok());
    assert!(draft.estimate_gas(false, 0, None).unwrap()["available"]
        .as_bool()
        .unwrap());
    let mut changed = b.clone();
    let mut call = PaymentRouter::payTokenForCall::abi_decode_validate(&b.data).unwrap();
    call.i.amountInMaximum += U256::from(1);
    changed.data = call.abi_encode().into();
    assert_ne!(
        router_intent_hash(31337, core, &a).unwrap(),
        router_intent_hash(31337, core, &changed).unwrap()
    );
    call.i.coreRequestHash = Default::default();
    changed.data = call.abi_encode().into();
    assert!(router_intent_hash(31337, core, &changed).is_err());
}
#[test]
fn shared_model_vectors() {
    let vectors: Value =
        serde_json::from_str(include_str!("fixtures/gas-model-vectors.json")).unwrap();
    for v in vectors.as_array().unwrap() {
        let input: RouterGasInput = serde_json::from_value(v["input"].clone()).unwrap();
        assert_eq!(estimate_router_gas(&input).unwrap(), v["output"]);
    }
}
#[test]
fn shared_semantic_vectors() {
    let vectors: Value =
        serde_json::from_str(include_str!("fixtures/preprove-intent-vectors.json")).unwrap();
    for v in vectors.as_array().unwrap() {
        let core: Address = v["core"].as_str().unwrap().parse().unwrap();
        let chain = v["chainId"].as_str().unwrap().parse().unwrap();
        for key in ["draftEnvelope", "finalEnvelope"] {
            let e: RouterEnvelope = serde_json::from_value(v[key].clone()).unwrap();
            assert_eq!(
                router_intent_hash(chain, core, &e).unwrap().to_string(),
                v["intentHash"].as_str().unwrap()
            );
        }
    }
}

#[test]
fn token_business_fields_and_permit_deadline_remain_bound() {
    let p = fixture(&[]);
    let e = p.draft_relay_envelope(Permit::default()).unwrap();
    let original = router_intent_hash(31337, p.core().to, &e).unwrap();
    let call = PaymentRouter::payTokenForCall::abi_decode_validate(&e.data).unwrap();
    for field in 0..13 {
        let mut c = call.clone();
        match field {
            0 => c.i.nonce += U256::from(1),
            1 => c.i.deadline -= U256::from(1),
            2 => c.i.amountInMaximum += U256::from(1),
            3 => c.i.refundRecipient = Address::repeat_byte(0x91),
            4 => c.i.payer = Address::repeat_byte(0x92),
            5 => c.i.relayer = Address::repeat_byte(0x93),
            6 => c.r.params.feeAmount += U256::from(1),
            7 => c.r.funding.amount += U256::from(1),
            8 => c.r.params.deadline -= U256::from(1),
            9 => c.r.params.noteCommitments[0] = alloy_primitives::B256::repeat_byte(0x01),
            10 => c.r.deliveries[0].ciphertext = Bytes::from(vec![4]),
            11 => c.permit.deadline = U256::from(99),
            12 => c.r.funding.sigNonce += U256::from(1),
            _ => unreachable!(),
        }
        c.i.coreRequestHash = core_request_hash(&c.proof, &c.r);
        let mut changed = e.clone();
        changed.data = c.abi_encode().into();
        assert_ne!(
            original,
            router_intent_hash(31337, p.core().to, &changed).unwrap(),
            "field {field}"
        );
    }
    let mut c = call;
    c.signature = Bytes::from(vec![5; 65]);
    c.permit.v = 28;
    c.permit.r = alloy_primitives::B256::repeat_byte(1);
    c.permit.s = alloy_primitives::B256::repeat_byte(2);
    let mut changed = e.clone();
    changed.data = c.abi_encode().into();
    assert_eq!(
        original,
        router_intent_hash(31337, p.core().to, &changed).unwrap()
    );
    let mut noncanonical = changed.data.to_vec();
    noncanonical.push(0);
    changed.data = noncanonical.into();
    assert!(router_intent_hash(31337, p.core().to, &changed).is_err());
}
#[test]
fn native_action_and_authorization_metadata_remain_bound() {
    let vectors: Value =
        serde_json::from_str(include_str!("fixtures/preprove-intent-vectors.json")).unwrap();
    let v = vectors
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["draftEnvelope"]["authorizationList"].is_array())
        .unwrap();
    let e: RouterEnvelope = serde_json::from_value(v["draftEnvelope"].clone()).unwrap();
    let core: Address = v["core"].as_str().unwrap().parse().unwrap();
    let original = router_intent_hash(31337, core, &e).unwrap();
    for field in 0..5 {
        let mut changed = e.clone();
        let mut c =
            PaymentRouterAccount::executeNativePaymentCall::abi_decode_validate(&e.data).unwrap();
        match field {
            0 => {
                c.nonce_ += U256::from(1);
                changed.data = c.abi_encode().into();
            }
            1 => {
                c.deadline -= U256::from(1);
                changed.data = c.abi_encode().into();
            }
            2 => changed.authorization_list[0].nonce += alloy_primitives::U64::from(1),
            3 => changed.authorization_list[0].chain_id += U256::from(1),
            4 => changed.authorization_list[0].address = Address::repeat_byte(0x98),
            _ => unreachable!(),
        }
        assert_ne!(
            original,
            router_intent_hash(31337, core, &changed).unwrap(),
            "field {field}"
        );
    }
    let mut changed = e.clone();
    changed.authorization_list[0].r = U256::from(22);
    changed.authorization_list[0].s = U256::from(33);
    changed.authorization_list[0].y_parity = alloy_primitives::U8::from(1);
    let mut c =
        PaymentRouterAccount::executeNativePaymentCall::abi_decode_validate(&e.data).unwrap();
    c.signature = Bytes::from(vec![9; 65]);
    changed.data = c.abi_encode().into();
    assert_eq!(original, router_intent_hash(31337, core, &changed).unwrap());
}

#[test]
fn final_native_builder_requires_proof_while_draft_builder_accepts_empty_proof() {
    let vectors: Value =
        serde_json::from_str(include_str!("fixtures/preprove-intent-vectors.json")).unwrap();
    let v = &vectors[1];
    let deployment = PaymentRouterDeployment {
        chain_id: 31337,
        core_address: Address::repeat_byte(0x11),
        router_address: Address::repeat_byte(0x33),
        weth_address: Address::repeat_byte(0x44),
        uniswap_router_address: Address::repeat_byte(0x55),
        runtime_code_hash: None,
        zero_ex: None,
    };
    for prefix in ["draft", "final"] {
        let envelope: RouterEnvelope =
            serde_json::from_value(v[format!("{prefix}Envelope")].clone()).unwrap();
        let action =
            PaymentRouterAccount::executeNativePaymentCall::abi_decode_validate(&envelope.data)
                .unwrap();
        let inner =
            PaymentRouter::payNativeCall::abi_decode_validate(&action.routerCalldata).unwrap();
        let core = TransactionCall {
            to: deployment.core_address,
            data: hex::decode(
                v[format!("{prefix}CoreData")]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
            )
            .unwrap(),
            value: U256::ZERO,
        };
        let payment =
            Payment::prepare_draft(&deployment, core, inner.i, inner.route, 1000, None).unwrap();
        let native = NativePayment::prepare(
            &payment,
            Address::repeat_byte(0xcc),
            alloy_primitives::B256::repeat_byte(1),
            action.nonce_,
            action.deadline,
        )
        .unwrap();
        assert!(native.draft_account_call(Bytes::new()).is_ok());
        assert!(native.draft_envelope(vec![]).is_ok());
        let signature = Bytes::from(vec![7; 65]);
        assert_eq!(
            native.account_call(signature.clone()).is_ok(),
            prefix == "final"
        );
        assert_eq!(
            native.envelope(signature, vec![]).is_ok(),
            prefix == "final"
        );
    }
}
