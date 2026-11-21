use alloy_primitives::{Address, Bytes, B256, U256};
use alloy_sol_types::SolCall;
use invisi_sdk_payment_router::{canonical::*, *};
use invisi_sdk_protocol::protocol::TransactionCall;
use serde_json::Value;
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn addr(v: &Value) -> Address {
    v.as_str().unwrap().parse().unwrap()
}
fn num(v: &Value) -> U256 {
    v.as_str().unwrap().parse().unwrap()
}
fn corpus() -> Value {
    serde_json::from_str(include_str!("fixtures/intent.json")).unwrap()
}
#[test]
fn all_shared_contract_vectors() {
    let v = corpus();
    let a = &v["addresses"];
    let d = PaymentRouterDeployment {
        chain_id: 31337,
        router_address: addr(&a["router"]),
        core_address: addr(&a["core"]),
        weth_address: addr(&a["weth"]),
        uniswap_router_address: addr(&a["dex"]),
        runtime_code_hash: None,
        zero_ex: None,
    };
    for c in v["cases"].as_array().unwrap() {
        let data = bytes(&c["call"]["data"]);
        let (i, route) = match c["method"].as_str().unwrap() {
            "payNative" => {
                let x = PaymentRouter::payNativeCall::abi_decode_validate(&data).unwrap();
                (x.i, x.route)
            }
            "payToken" => {
                let x = PaymentRouter::payTokenCall::abi_decode_validate(&data).unwrap();
                (x.i, x.route)
            }
            _ => {
                let x = PaymentRouter::payTokenForCall::abi_decode_validate(&data).unwrap();
                (x.i, x.route)
            }
        };
        assert_eq!(
            format!("{}", intent_digest(31337, d.router_address, &i)),
            c["intentDigest"].as_str().unwrap(),
            "{}",
            c["name"]
        );
        assert_eq!(route_hash(&route), i.routeHash);
        assert_eq!(
            recover_signer(
                intent_digest(31337, d.router_address, &i),
                &bytes(&c["signature"])
            )
            .unwrap(),
            i.payer
        );
        let p = Payment::prepare(
            &d,
            TransactionCall {
                to: d.core_address,
                data: bytes(&c["coreCalldata"]),
                value: U256::ZERO,
            },
            i.clone(),
            route,
            1000,
            None,
        )
        .unwrap();
        assert_eq!(
            format!("{}", p.intent().coreRequestHash),
            v["coreRequestHash"].as_str().unwrap()
        );
        let sig = if i.mode == RELAYED_TOKEN {
            bytes(&c["signature"])
        } else {
            vec![]
        };
        let built = p.router_call(Permit::default(), sig.into()).unwrap();
        assert_eq!(built.data, data);
        assert_eq!(built.value, num(&c["call"]["value"]));
        if i.mode == SPONSORED_NATIVE {
            let a = &c["account"];
            let n = NativePayment::prepare(
                &p,
                addr(&a["implementation"]),
                a["routerCodeHash"].as_str().unwrap().parse().unwrap(),
                num(&a["payment"]["nonce"]),
                num(&a["payment"]["deadline"]),
            )
            .unwrap();
            assert_eq!(
                format!("{}", n.digest(31337)),
                a["digest"].as_str().unwrap()
            );
            let account = n.account_call(bytes(&a["signature"]).into()).unwrap();
            assert_eq!(account.data, bytes(&a["call"]["data"]));
            assert_eq!(account.to, i.payer);
            assert!(account.value.is_zero());
        }
    }
}
#[test]
fn relay_hash_binds_all_fields_and_wire_shape() {
    let e = RouterEnvelope {
        to: Address::repeat_byte(3),
        data: Bytes::from(vec![1, 2, 3, 4]),
        value: "0".into(),
        authorization_list: vec![],
    };
    let h = envelope_hash(31337, Address::repeat_byte(1), &e).unwrap();
    let mut changed = e.clone();
    changed.data = Bytes::from(vec![1, 2, 3, 4, 5]);
    assert_ne!(
        h,
        envelope_hash(31337, Address::repeat_byte(1), &changed).unwrap()
    );
    changed = e.clone();
    changed.value = "1".into();
    assert!(envelope_hash(31337, Address::repeat_byte(1), &changed).is_err());
    let wire = serde_json::to_value(&e).unwrap();
    assert_eq!(wire["value"], "0");
    assert_eq!(wire["data"], "0x01020304");
    assert!(wire.get("authorizationList").is_none());
    assert!(recover_signer(B256::ZERO, &[0; 65]).is_err());
}
#[test]
fn shared_go_envelope_hashes_include_signed_authorization() {
    let v: Value = serde_json::from_str(include_str!("fixtures/envelope.json")).unwrap();
    for c in v.as_array().unwrap() {
        let e: RouterEnvelope = serde_json::from_value(c["envelope"].clone()).unwrap();
        assert_eq!(
            format!("{}", envelope_hash(31337, addr(&c["core"]), &e).unwrap()),
            c["hash"].as_str().unwrap(),
            "{}",
            c["name"]
        );
        if !e.authorization_list.is_empty() {
            let a = &e.authorization_list[0];
            validate_authorizations(31337, e.to, a.address, &e.authorization_list).unwrap();
            assert!(validate_authorizations(1, e.to, a.address, &e.authorization_list).is_err());
            assert!(validate_authorizations(
                31337,
                Address::repeat_byte(0xfe),
                a.address,
                &e.authorization_list
            )
            .is_err());
            let mut bad = e.clone();
            bad.authorization_list[0].nonce += alloy_primitives::U64::from(1);
            assert_ne!(
                envelope_hash(31337, addr(&c["core"]), &e).unwrap(),
                envelope_hash(31337, addr(&c["core"]), &bad).unwrap()
            );
        }
    }
}
#[test]
fn same_token_wrap_and_erc20_zeroex_routes_and_rejections() {
    use invisi_sdk_protocol::protocol::InvisiCore;
    let v = corpus();
    let a = &v["addresses"];
    let c = &v["cases"][1];
    let d = PaymentRouterDeployment {
        chain_id: 31337,
        router_address: addr(&a["router"]),
        core_address: addr(&a["core"]),
        weth_address: addr(&a["weth"]),
        uniswap_router_address: addr(&a["dex"]),
        runtime_code_hash: None,
        zero_ex: Some(ZeroExDeployment {
            allowance_holder_address: addr(&a["holder"]),
            settler_registry_address: addr(&a["registry"]),
        }),
    };
    let decoded =
        PaymentRouter::payTokenCall::abi_decode_validate(&bytes(&c["call"]["data"])).unwrap();
    let core = TransactionCall {
        to: d.core_address,
        data: bytes(&c["coreCalldata"]),
        value: U256::ZERO,
    };
    let p = Payment::prepare(
        &d,
        core.clone(),
        decoded.i.clone(),
        decoded.route.clone(),
        1000,
        None,
    )
    .unwrap();
    let mut bad = p.intent().clone();
    bad.refundRecipient = d.router_address;
    assert!(Payment::prepare(&d, core.clone(), bad, decoded.route.clone(), 1000, None).is_err());
    bad = p.intent().clone();
    bad.deadline = U256::from(999);
    assert!(Payment::prepare(&d, core.clone(), bad, decoded.route.clone(), 1000, None).is_err());
    bad = p.intent().clone();
    bad.tokenIn = Address::ZERO;
    assert!(Payment::prepare(&d, core.clone(), bad, decoded.route.clone(), 1000, None).is_err());
    // Direct token same-token flow is channel None; no DEX or native value.
    let same = decoded.route.clone();
    assert_eq!(same.channel, 0);
    assert!(p
        .router_call(Permit::default(), Bytes::new())
        .unwrap()
        .value
        .is_zero());
    // Wrap-only native flow supplies precisely the funding amount and needs no swap.
    let mut native = InvisiCore::transact_0Call::abi_decode_validate(&core.data).unwrap();
    native.r.params.token = d.weth_address;
    let wrapped = TransactionCall {
        to: d.core_address,
        data: native.abi_encode(),
        value: U256::ZERO,
    };
    let mut i = p.intent().clone();
    i.mode = DIRECT_NATIVE;
    i.tokenIn = Address::ZERO;
    let wrap = Payment::prepare(&d, wrapped, i, same.clone(), 1000, None).unwrap();
    assert_eq!(
        wrap.router_call(Permit::default(), Bytes::new())
            .unwrap()
            .value,
        wrap.intent().amountInMaximum
    );
    // ERC20 0x envelope binds current Holder/Settler, exact output, input cap and recipient.
    let inner = invisi_sdk_payment_router::abi::executeCall {
        slippage: invisi_sdk_payment_router::abi::Slippage {
            recipient: d.router_address,
            buyToken: p.request().params.token,
            minAmountOut: p.request().funding.amount,
        },
        actions: vec![],
        zid: B256::ZERO,
    }
    .abi_encode();
    let mut i = p.intent().clone();
    i.tokenIn = d.weth_address;
    let outer = invisi_sdk_payment_router::abi::execCall {
        operator: addr(&a["settler"]),
        token: i.tokenIn,
        amount: i.amountInMaximum,
        target: addr(&a["settler"]),
        data: inner.into(),
    }
    .abi_encode();
    let route = Route {
        channel: 2,
        path: Bytes::new(),
        target: addr(&a["holder"]),
        data: outer.into(),
    };
    Payment::prepare(
        &d,
        core.clone(),
        i.clone(),
        route.clone(),
        1000,
        Some(addr(&a["settler"])),
    )
    .unwrap();
    assert!(Payment::prepare(
        &d,
        core.clone(),
        i.clone(),
        route.clone(),
        1000,
        Some(Address::repeat_byte(0xfd))
    )
    .is_err());
    let mut invalid = route.clone();
    let mut trailing = invalid.data.to_vec();
    trailing.push(0);
    invalid.data = trailing.into();
    assert!(Payment::prepare(&d, core, i, invalid, 1000, Some(addr(&a["settler"]))).is_err());
}
