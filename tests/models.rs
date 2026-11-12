use alloy_primitives::U256;
use invisi_sdk::{credit::*, note::*};
fn n(s: &str) -> U256 {
    if let Some(s) = s.strip_prefix("0x") {
        U256::from_str_radix(s, 16).unwrap()
    } else {
        U256::from_str_radix(s, 10).unwrap()
    }
}
fn current() -> CreditState {
    CreditState {
        context: ProtocolContext {
            chain_id: 31337,
            protocol_address: n("0x1111111111111111111111111111111111111111"),
        },
        token_address: n("0x2222222222222222222222222222222222222222"),
        spender_wallet_identity: n("3"),
        owner_wallet_identity: n("4"),
        revocation_shard: 1,
        revocation_slot: 0,
        nonce: n("5"),
        expiry: 2050000000,
        credit_shared_key: n("6"),
        policy: CreditPolicy {
            single_limit: n("1000"),
            daily_limit: n("10000"),
            monthly_limit: n("100000"),
        },
        usage: CreditUsage::default(),
        available_credit: n("1000000"),
        unlimited: false,
        payload: vec![],
    }
}
#[test]
fn current_credit_matches_ts_draw_recovery_update() {
    let vector: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/current-credit.json")).unwrap();
    let old = current();
    assert_eq!(
        old.commitment().unwrap(),
        n(vector["commitment"].as_str().unwrap())
    );
    let draw = derive_credit_state(&old, n("7"), 2000000000).unwrap();
    assert_eq!(
        draw.nullifier,
        n(vector["draw"]["nullifier"].as_str().unwrap())
    );
    assert_eq!(
        draw.state_commitment,
        n(vector["draw"]["stateCommitment"].as_str().unwrap())
    );
    assert_eq!(
        draw.recovery_amount,
        n(vector["draw"]["recoveryAmount"].as_str().unwrap())
    );
    assert_eq!(draw.state.available_credit, n("999993"));
    assert_eq!(
        recover_credit_state(
            old.context,
            &old,
            &CreditStateRecovery {
                timestamp: 2000000000,
                credit_nullifier: draw.nullifier,
                state_commitment: draw.state_commitment,
                recovery_amount: draw.recovery_amount
            }
        )
        .unwrap(),
        draw.state
    );
    let update = derive_credit_update(
        &draw.state,
        &CreditUpdateChanges {
            single_limit: Some(n("10")),
            daily_limit: Some(n("40")),
            monthly_limit: Some(n("60")),
            expiry: Some(2060000000),
            decrease_available_credit: n("100"),
            ..Default::default()
        },
        2000000001,
    )
    .unwrap();
    assert_eq!(
        update.state_commitment,
        n(vector["update"]["stateCommitment"].as_str().unwrap())
    );
    assert_eq!(update.state.usage, draw.state.usage);
}
#[test]
fn rejects_invalid_financial_state_and_period_rollback() {
    let mut state = current();
    state.unlimited = true;
    assert!(state.validate().is_err());
    let mut state = current();
    state.usage.last_day = 999999;
    assert!(apply_credit_draw_usage(&state, n("1"), 2000000000).is_err());
    assert!(apply_credit_draw_usage(&current(), n("1001"), 2000000000).is_err());
}
#[test]
fn current_note_matches_ts_identity_commitment_nullifier() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/current-note.json")).unwrap();
    let note = Note {
        context: ProtocolContext {
            chain_id: 31337,
            protocol_address: n("4660"),
        },
        owner_address: n(v["note"]["ownerAddress"].as_str().unwrap()),
        token_address: n("22136"),
        amount: n("70"),
        nonce: n("123"),
        payload: vec![],
    };
    assert_eq!(
        note.identity().unwrap(),
        n(v["note"]["identity"].as_str().unwrap())
    );
    assert_eq!(
        note.commitment().unwrap(),
        n(v["note"]["commitment"].as_str().unwrap())
    );
    assert_eq!(
        note.nullifier().unwrap(),
        n(v["note"]["nullifier"].as_str().unwrap())
    );
}
#[test]
fn receiving_address_matches_ts_and_resolves_only_explicitly() {
    use invisi_sdk::address::*;
    let v: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/current-address.json")).unwrap();
    let owner = n(v["ownerAddress"].as_str().unwrap());
    let decode = |s: &str| hex::decode(s.trim_start_matches("0x")).unwrap();
    let keys = ReceivingKeys {
        viewing_public_key: decode(v["viewingPublicKey"].as_str().unwrap())
            .try_into()
            .unwrap(),
        clue_key: decode(v["clueKey"].as_str().unwrap()).try_into().unwrap(),
    };
    let long = ReceivingAddress::from_keys(owner, keys.clone()).unwrap();
    let text = long.encode().unwrap();
    assert_eq!(text.len(), 138);
    assert_eq!(text, v["longAddress"].as_str().unwrap());
    assert_eq!(ReceivingAddress::parse(&text).unwrap(), long);
    let short = ReceivingAddress::from_identity(owner).unwrap();
    assert_eq!(short.encode().unwrap(), v["shortAddress"].as_str().unwrap());
    assert_eq!(short.resolve(|_| Ok(Some(keys))).unwrap(), long);
    assert_eq!(
        ReceivingAddress::parse(&short.encode().unwrap()).unwrap(),
        short
    );
    let mut corrupted = text.as_bytes().to_vec();
    let i = corrupted
        .iter()
        .enumerate()
        .skip(2)
        .find(|(_, b)| b.is_ascii_alphabetic())
        .unwrap()
        .0;
    corrupted[i] = if corrupted[i].is_ascii_uppercase() {
        corrupted[i].to_ascii_lowercase()
    } else {
        corrupted[i].to_ascii_uppercase()
    };
    assert!(ReceivingAddress::parse(std::str::from_utf8(&corrupted).unwrap()).is_err());
}
#[test]
fn financial_models_use_flat_canonical_json() {
    let state = current();
    let json = serde_json::to_value(&state).unwrap();
    assert_eq!(json["chainId"], "31337");
    assert_eq!(json["availableCredit"], "1000000");
    assert_eq!(
        json["ownerWalletIdentity"],
        "0x0000000000000000000000000000000000000004"
    );
    assert!(json.get("context").is_none());
    assert_eq!(
        serde_json::from_value::<CreditState>(json.clone()).unwrap(),
        state
    );
    let mut bad = json.clone();
    bad["availableCredit"] = serde_json::json!("010");
    assert!(serde_json::from_value::<CreditState>(bad).is_err());
    let mut bad = json;
    bad["lifetimeLimit"] = serde_json::json!("100");
    assert!(serde_json::from_value::<CreditState>(bad).is_err());
}
#[test]
fn current_credit_financial_boundaries() {
    let state = current();
    let draw = derive_credit_state(&state, n("7"), 2000000000).unwrap();
    let mut recovery = CreditStateRecovery {
        timestamp: 2000000000,
        credit_nullifier: draw.nullifier,
        state_commitment: draw.state_commitment,
        recovery_amount: draw.recovery_amount,
    };
    recovery.recovery_amount += U256::from(1);
    assert!(recover_credit_state(state.context, &state, &recovery).is_err());
    let mut unlimited = state.clone();
    unlimited.unlimited = true;
    unlimited.available_credit = U256::ZERO;
    let drawn = derive_credit_state(&unlimited, n("7"), 2000000000).unwrap();
    assert_eq!(drawn.state.available_credit, U256::ZERO);
    assert_eq!(drawn.state.usage.total_spent, n("7"));
    let mut exhausted = state.clone();
    exhausted.available_credit = n("6");
    assert!(derive_credit_state(&exhausted, n("7"), 2000000000).is_err());
    assert!(derive_credit_update(
        &state,
        &CreditUpdateChanges {
            increase_available_credit: n("1"),
            decrease_available_credit: n("1"),
            ..Default::default()
        },
        2000000000
    )
    .is_err());
    assert_eq!(credit_periods(0), (1, 1));
    assert_eq!(credit_periods(u64::MAX).0, u64::MAX / 86400 + 1);
}
#[test]
fn securely_generated_current_secrets_are_canonical() {
    for _ in 0..8 {
        assert!(generate_nonce() < field_modulus());
        let key = generate_credit_shared_key();
        assert!(key > U256::ZERO && key < field_modulus());
    }
}
#[test]
fn omitted_optional_policy_and_usage_normalize_to_zero() {
    let mut value = serde_json::to_value(current()).unwrap();
    for key in [
        "singleLimit",
        "dailyLimit",
        "monthlyLimit",
        "lastDay",
        "dailySpent",
        "lastMonth",
        "monthlySpent",
        "totalSpent",
    ] {
        value.as_object_mut().unwrap().remove(key);
    }
    let state: CreditState = serde_json::from_value(value).unwrap();
    assert_eq!(state.policy, CreditPolicy::default());
    assert_eq!(state.usage, CreditUsage::default());
}

#[test]
fn note_hashes_bind_protocol_instance() {
    let mut note = Note {
        context: ProtocolContext {
            chain_id: 31337,
            protocol_address: n("0x1234"),
        },
        owner_address: n("0x1111"),
        token_address: n("0x5678"),
        amount: n("70"),
        nonce: n("123"),
        payload: vec![],
    };
    let first = note.commitment().unwrap();
    let nullifier = note.nullifier().unwrap();
    note.context.protocol_address = n("0x1235");
    assert_ne!(first, note.commitment().unwrap());
    assert_ne!(nullifier, note.nullifier().unwrap());
    assert_ne!(
        compute_note_nullifier(31337, n("0x1234"), note.nonce, first).unwrap(),
        compute_note_nullifier(31337, n("0x1235"), note.nonce, first).unwrap()
    );
    assert!(compute_note_commitment(
        31337,
        U256::ZERO,
        note.identity().unwrap(),
        note.token_address,
        note.amount
    )
    .is_err());
    assert!(compute_note_nullifier(31337, U256::from(1) << 160, note.nonce, first).is_err());
}

#[test]
fn credit_update_payload_absent_preserves_and_empty_clears() {
    let changes: invisi_sdk::credit::CreditUpdateChanges =
        serde_json::from_value(serde_json::json!({"payload":"0x"})).unwrap();
    assert_eq!(changes.payload, Some(Vec::new()));
    assert!(invisi_sdk::credit::CreditUpdateChanges::default()
        .payload
        .is_none());
    let mut previous = current();
    previous.payload = vec![1, 2];
    let preserved =
        derive_credit_update(&previous, &CreditUpdateChanges::default(), 2000000001).unwrap();
    assert_eq!(preserved.state.payload, vec![1, 2]);
    let cleared = derive_credit_update(&previous, &changes, 2000000001).unwrap();
    assert!(cleared.state.payload.is_empty());
    assert_eq!(preserved.state_commitment, cleared.state_commitment);
}
