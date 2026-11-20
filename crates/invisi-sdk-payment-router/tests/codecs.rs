use alloy_primitives::{Address, U256};
use invisi_sdk_payment_router::*;
fn a(n: u8) -> Address {
    Address::repeat_byte(n)
}
#[test]
fn reversed_paths_validate_fees_tokens_and_endpoints() {
    let path = encode_v3_exact_output_path(&[a(4), a(5), a(2)], &[500, 100]).unwrap();
    assert_eq!(
        hex::encode(&path),
        format!(
            "{}000064{}0001f4{}",
            hex::encode(a(2)),
            hex::encode(a(5)),
            hex::encode(a(4))
        )
    );
    validate_v3_path(&path, a(4), a(2)).unwrap();
    assert!(validate_v3_path(&path, a(2), a(4)).is_err());
    for (tokens, fees) in [
        (vec![a(4)], vec![]),
        (vec![a(4), a(4)], vec![3000]),
        (vec![a(4), a(2)], vec![0]),
        (vec![a(4), Address::ZERO], vec![3000]),
        (vec![a(4), a(2)], vec![1_000_000]),
    ] {
        assert!(encode_v3_exact_output_path(&tokens, &fees).is_err());
    }
}
#[test]
fn zeroex_requires_exact_output_single_guard_and_current_settler() {
    use alloy_sol_types::SolCall;
    let guard = abi::NATIVE_CHECKCall {
        deadline: U256::from(1100),
        msgValue: U256::from(100),
    }
    .abi_encode();
    let envelope = abi::executeCall {
        slippage: abi::Slippage {
            recipient: a(3),
            buyToken: a(2),
            minAmountOut: U256::from(10),
        },
        actions: vec![guard.into()],
        zid: Default::default(),
    };
    let mut options = ZeroExPayloadOptions {
        target: a(6),
        data: envelope.abi_encode(),
        router_address: a(3),
        token_out: a(2),
        amount_out: U256::from(10),
        max_input: U256::from(100),
        settler_address: a(6),
        allowance_holder_address: a(7),
        now: 1000,
    };
    assert_eq!(
        validate_zeroex_payload(&options).unwrap().native_deadline,
        U256::from(1100)
    );
    options.amount_out = U256::from(9);
    assert!(validate_zeroex_payload(&options).is_err());
    options.amount_out = U256::from(10);
    let mut duplicate = envelope.clone();
    duplicate.actions.push(duplicate.actions[0].clone());
    options.data = duplicate.abi_encode();
    assert!(validate_zeroex_payload(&options).is_err());
    let wrapper = abi::execCall {
        operator: a(6),
        token: NATIVE_TOKEN,
        amount: U256::ZERO,
        target: a(6),
        data: envelope.abi_encode().into(),
    };
    options.target = a(7);
    options.data = wrapper.abi_encode();
    assert!(validate_zeroex_payload(&options).is_ok());
    options.settler_address = a(5);
    assert!(validate_zeroex_payload(&options).is_err());
}

#[test]
fn all_shared_typescript_paths_and_native_payloads() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/payment-router-vectors.json")).unwrap();
    let address = |v: &serde_json::Value| v.as_str().unwrap().parse::<Address>().unwrap();
    let bytes = |v: &serde_json::Value| {
        hex::decode(v.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
    };
    let number = |v: &serde_json::Value| U256::from_str_radix(v.as_str().unwrap(), 10).unwrap();
    for case in v["pathCases"].as_array().unwrap() {
        let tokens = case["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .map(address)
            .collect::<Vec<_>>();
        let fees = case["fees"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u32)
            .collect::<Vec<_>>();
        assert_eq!(
            encode_v3_exact_output_path(&tokens, &fees).unwrap(),
            bytes(&case["expected"])
        );
    }
    for case in v["zeroExPayloads"].as_array().unwrap() {
        let o = &case["input"];
        let options = ZeroExPayloadOptions {
            target: address(&o["target"]),
            data: bytes(&o["data"]),
            router_address: address(&o["routerAddress"]),
            token_out: address(&o["tokenOut"]),
            amount_out: number(&o["amountOut"]),
            max_input: number(&o["maxInput"]),
            settler_address: address(&o["settlerAddress"]),
            allowance_holder_address: address(&o["allowanceHolderAddress"]),
            now: o["now"].as_str().unwrap().parse().unwrap(),
        };
        let result = validate_zeroex_payload(&options);
        if case["valid"] == true {
            let checked = result.unwrap();
            assert_eq!(
                checked.data,
                bytes(&case["expected"]["data"]),
                "{}",
                case["name"]
            );
            assert_eq!(
                checked.native_deadline,
                number(&case["expected"]["nativeDeadline"])
            );
        } else {
            assert!(result.is_err(), "{}", case["name"]);
        }
    }
}

#[test]
fn zeroex_canonicalization_strips_appended_sender_bytes() {
    use alloy_sol_types::SolCall;
    let guard = abi::NATIVE_CHECKCall {
        deadline: U256::from(1100),
        msgValue: U256::from(100),
    }
    .abi_encode();
    let canonical = abi::executeCall {
        slippage: abi::Slippage {
            recipient: a(3),
            buyToken: a(2),
            minAmountOut: U256::from(10),
        },
        actions: vec![guard.into()],
        zid: Default::default(),
    }
    .abi_encode();
    let mut original = canonical.clone();
    original.extend_from_slice(a(9).as_slice());
    let options = ZeroExPayloadOptions {
        target: a(6),
        data: original,
        router_address: a(3),
        token_out: a(2),
        amount_out: U256::from(10),
        max_input: U256::from(100),
        settler_address: a(6),
        allowance_holder_address: a(7),
        now: 1000,
    };
    assert_eq!(validate_zeroex_payload(&options).unwrap().data, canonical);
}
