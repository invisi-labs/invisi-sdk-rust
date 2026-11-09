use invisi_sdk::wallet::{authorization_digest, detection_key, execute, viewing_key};
use serde_json::{json, Value};
fn key() -> [u8; 32] {
    let mut k = [0; 32];
    k[31] = 1;
    k
}
fn fixtures(name: &str) -> Value {
    serde_json::from_str(match name {
        "kdf" => include_str!("fixtures/wallet-kdf-vectors.json"),
        "note" => include_str!("fixtures/wallet-note-vectors.json"),
        _ => include_str!("fixtures/wallet-authorization-vectors.json"),
    })
    .unwrap()
}
#[test]
fn independent_key_derivation_vectors() {
    for v in fixtures("kdf")["vectors"].as_array().unwrap() {
        let k = hex::decode(v["privateKey"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(
            hex::encode(&*viewing_key(&k).unwrap()),
            v["viewingPrivateKey"]
        );
        assert_eq!(hex::encode(&*detection_key(&k).unwrap()), v["detectionKey"]);
    }
    assert!(viewing_key(&[0; 32]).is_err());
}
#[test]
fn current_authorization_vectors() {
    for row in fixtures("authorization")["rows"].as_array().unwrap() {
        assert_eq!(
            format!("0x{}", hex::encode(authorization_digest(row).unwrap())),
            row["digest"]
        );
    }
}
#[test]
fn public_response_never_exports_private_material() {
    let request = json!({"version":1,"id":"public-1","ownerAddress":"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf","method":"wallet.public","params":{}});
    let response = execute(&key(), &request).unwrap();
    assert_eq!(response["id"], request["id"]);
    assert_eq!(response["ownerAddress"], request["ownerAddress"]);
    assert!(response["result"]["detectionKey"].is_null());
    assert_eq!(response["result"]["clueKey"].as_str().unwrap().len(), 66);
    let mut wrong = request.clone();
    wrong["ownerAddress"] = json!("0x0000000000000000000000000000000000000001");
    assert!(execute(&key(), &wrong).is_err());
    let mut version = request.clone();
    version["version"] = json!(2);
    assert!(execute(&key(), &version).is_err());
}
#[test]
fn decrypt_current_note_and_credit_and_bind_context() {
    let f = fixtures("note");
    for (section, role, field, k) in [
        ("note", "funds", "ciphertext", key()),
        ("credit", "owner", "ownerCiphertext", key()),
        ("credit", "spender", "spenderCiphertext", {
            let mut k = key();
            k[31] = 2;
            k
        }),
    ] {
        let mut ctx = f["context"].clone();
        ctx["outputCommitment"] = f[section]["commitment"].clone();
        ctx.as_object_mut().unwrap().remove("timestamp");
        for name in ["protocolAddress", "tokenAddress"] {
            let n = u64::from_str_radix(ctx[name].as_str().unwrap().trim_start_matches("0x"), 16)
                .unwrap();
            ctx[name] = json!(n.to_string());
        }
        if section == "credit" {
            ctx["role"] = json!(role);
        }
        let req = json!({"version":1,"id":"decrypt-1","ownerAddress":if role=="spender"{"0x2b5ad5c4795c026514f8317c7a215e218dccd6cf"}else{"0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"},"method":if section=="note"{"wallet.decryptNote"}else{"wallet.decryptCredit"},"params":{"envelope":f[section][field],"context":ctx}});
        assert!(execute(&k, &req).is_ok(), "{}", role);
        for name in [
            "chainId",
            "protocolAddress",
            "tokenAddress",
            "outputCommitment",
        ] {
            let mut bad = req.clone();
            bad["params"]["context"][name] = json!("2");
            assert!(execute(&k, &bad).is_err());
        }
    }
}

#[test]
fn portable_wire_vectors_match_typescript() {
    let f: Value = serde_json::from_str(include_str!("fixtures/wallet-wire-vectors.json")).unwrap();
    for case in f["cases"].as_array().unwrap() {
        assert_eq!(
            execute(&key(), &case["request"]).unwrap(),
            case["response"],
            "{}",
            case["request"]["method"]
        );
    }
}
#[test]
fn malformed_requests_do_not_authorize_arbitrary_hashes() {
    let f: Value = serde_json::from_str(include_str!("fixtures/wallet-wire-vectors.json")).unwrap();
    let r = f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["request"]["method"] == "wallet.authorize")
        .unwrap()["request"]
        .clone();
    for (field, value) in [
        ("operation", json!("cancel-credit")),
        ("capacity", json!(14)),
        (
            "words",
            json!([
                "31337",
                "4660",
                "21888242871839275222246405745257275088548364400416034343698204186575808495617"
            ]),
        ),
    ] {
        let mut bad = r.clone();
        bad["params"][field] = value;
        assert!(execute(&key(), &bad).is_err());
    }
    let mut bare = r.clone();
    bare["params"] = json!({"digest":"0x00"});
    assert!(execute(&key(), &bare).is_err());
}
#[test]
fn plaintext_financial_commitments_are_independently_checked() {
    use invisi_sdk::wallet::validate_delivery_plaintext;
    let f: Value = serde_json::from_str(include_str!("fixtures/wallet-wire-vectors.json")).unwrap();
    for case in f["cases"].as_array().unwrap() {
        let method = case["request"]["method"].as_str().unwrap();
        if method != "wallet.decryptNote" && method != "wallet.decryptCredit" {
            continue;
        }
        let plain = hex::decode(
            case["response"]["result"]["plaintext"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let ctx = &case["request"]["params"]["context"];
        let role = if method == "wallet.decryptNote" {
            "funds"
        } else {
            "owner"
        };
        assert!(validate_delivery_plaintext(&plain, ctx, role).is_ok());
        let mut framing = plain.clone();
        let end = framing.len() - 1;
        framing[end] = 1;
        assert!(validate_delivery_plaintext(&framing, ctx, role).is_err());
        let mut altered = plain.clone();
        altered[47] ^= 1;
        assert!(validate_delivery_plaintext(&altered, ctx, role).is_err());
    }
}

#[test]
fn account_key_encoding_is_exactly_32_bytes() {
    assert!(viewing_key(&[1u8; 31]).is_err());
    assert!(detection_key(&[1u8; 31]).is_err());
}
