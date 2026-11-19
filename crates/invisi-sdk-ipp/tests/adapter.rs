#![cfg(feature = "invisi")]
use invisi_sdk_ipp::*;
#[test]
fn adapter_refuses_expired_and_wrong_deployment_before_preparing() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/ipp-wire-vectors.json")).unwrap();
    let raw = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "payment-request")
        .unwrap();
    let request = parse_payment_request(
        parse_json(raw["json"].as_str().unwrap().as_bytes()).unwrap(),
        None,
    )
    .unwrap();
    let trusted = invisi_sdk::note::ProtocolContext {
        chain_id: 1,
        protocol_address: alloy_primitives::U256::from(1),
    };
    assert!(matches!(
        validate_preparation(&request, trusted, 0),
        Err(Error::DeploymentMismatch)
    ));
    assert!(matches!(
        validate_preparation(&request, trusted, i64::MAX),
        Err(Error::ExecutionNotAllowed)
    ));
}
#[test]
fn callback_boundary_preserves_exact_terms_without_executing_a_wallet() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/ipp-wire-vectors.json")).unwrap();
    for name in ["payment-request", "credit-request"] {
        let raw = corpus["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap();
        let value = parse_json(raw["json"].as_str().unwrap().as_bytes()).unwrap();
        let mode = value["mode"].as_str().unwrap();
        let details = &value[mode];
        let context = invisi_sdk::note::ProtocolContext {
            chain_id: 8453,
            protocol_address: details["protocolAddress"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap(),
        };
        let request = parse_payment_request(value.clone(), None).unwrap();
        let result = prepare_invisi_request_with(
            &request,
            context,
            0,
            invisi_sdk::sdk::Fee::default(),
            |p| {
                assert_eq!(
                    p.token.to_string().to_lowercase(),
                    details["tokenAddress"].as_str().unwrap()
                );
                assert_eq!(
                    p.output.amount().to_string(),
                    details["amount"].as_str().unwrap()
                );
                assert_eq!(
                    p.output.identity_value(),
                    details["recipient"]["identity"]
                        .as_str()
                        .unwrap()
                        .parse::<alloy_primitives::U256>()
                        .unwrap()
                );
                assert_eq!(p.deadline, timestamp(&value["expiresAt"]).unwrap() as u64);
                Ok("payment")
            },
            |c| {
                assert_eq!(
                    c.credit_shared_key,
                    Some(
                        details["creditSharedKey"]
                            .as_str()
                            .unwrap()
                            .parse()
                            .unwrap()
                    )
                );
                assert_eq!(c.spender, details["spender"].as_str().unwrap());
                assert_eq!(
                    c.available_credit.to_string(),
                    details["availableCredit"].as_str().unwrap()
                );
                assert_eq!(c.expiry, timestamp(&details["expiresAt"]).unwrap() as u64);
                Ok("credit")
            },
        )
        .unwrap();
        assert_eq!(result, mode);
    }
}

#[test]
fn initial_payment_adapter_adds_actual_fee_and_rejects_invalid_fee_or_overflow() {
    use alloy_primitives::{Address, U256};
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/ipp-wire-vectors.json")).unwrap();
    let raw = corpus["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "credit-request")
        .unwrap();
    let mut value = parse_json(raw["json"].as_str().unwrap().as_bytes()).unwrap();
    value["credit"]["initialPayment"] = serde_json::json!({"amount":"5"});
    let context = invisi_sdk::note::ProtocolContext {
        chain_id: 8453,
        protocol_address: value["credit"]["protocolAddress"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    };
    let request = parse_payment_request(value, None).unwrap();
    let prepare = |fee| {
        prepare_invisi_request_with(
            &request,
            context,
            0,
            fee,
            |_| panic!("payment"),
            |c| {
                let payment = c.initial_payment.unwrap();
                assert_eq!(payment.net_amount, Some(U256::from(5)));
                Ok(payment.amount)
            },
        )
    };
    assert_eq!(
        prepare(invisi_sdk::sdk::Fee::default()).unwrap(),
        U256::from(5)
    );
    assert_eq!(
        prepare(invisi_sdk::sdk::Fee {
            recipient: Address::repeat_byte(4),
            amount: U256::from(2)
        })
        .unwrap(),
        U256::from(7)
    );
    assert!(prepare(invisi_sdk::sdk::Fee {
        recipient: Address::ZERO,
        amount: U256::from(2)
    })
    .is_err());
    assert!(prepare(invisi_sdk::sdk::Fee {
        recipient: Address::repeat_byte(4),
        amount: (U256::from(1) << 126) - U256::from(5)
    })
    .is_err());
}
