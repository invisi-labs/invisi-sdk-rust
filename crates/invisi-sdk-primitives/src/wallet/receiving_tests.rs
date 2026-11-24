use super::*;
use crate::{
    delivery::{decrypt_note, encode_note, encrypt_note, DeliveryContext},
    fmd::{create_clue_from_seed, detect_clue},
    note::{Note, ProtocolContext},
    wallet::{authorization_digest, decode, detection_key, execute, hex_value, viewing_key},
};
use k256::ecdsa::signature::hazmat::{PrehashVerifier, RandomizedPrehashSigner};
use rand::{rngs::StdRng, SeedableRng};
use serde_json::{json, Value};

fn vectors() -> Vec<Value> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../testdata/receiving-signature-v1-vectors.json"
    ))
    .unwrap();
    fixture["vectors"].as_array().unwrap().clone()
}

fn bytes(vector: &Value, name: &str) -> Vec<u8> {
    decode(vector[name].as_str().unwrap()).unwrap()
}

#[test]
fn local_wallet_receiving_keys_match_v1_vectors() {
    for vector in vectors() {
        let key = bytes(&vector, "privateKey");
        assert_eq!(
            &viewing_key(&key).unwrap()[..],
            bytes(&vector, "viewingPrivateKey")
        );
        assert_eq!(
            &detection_key(&key).unwrap()[..],
            bytes(&vector, "detectionKey")
        );
        let request = json!({
            "version": 1, "id": "public", "ownerAddress": vector["ownerAddress"],
            "method": "wallet.public", "params": {}
        });
        assert_eq!(
            execute(&key, &request).unwrap()["result"],
            json!({
                "spendingPublicKey": vector["spendingPublicKey"],
                "viewingPublicKey": vector["viewingPublicKey"],
                "clueKey": vector["clueKey"]
            })
        );
    }
}

#[test]
fn equivalent_signatures_produce_all_v1_vector_material() {
    for vector in vectors() {
        let owner = vector["ownerAddress"].as_str().unwrap();
        let address = parse_owner(owner).unwrap();
        let message = build_receiving_key_message(owner).unwrap();
        let digest = eip191_hash_message(&message);
        assert_eq!(message, vector["message"]);
        assert_eq!(message.as_bytes(), bytes(&vector, "messageHex"));
        assert_eq!(digest.as_slice(), bytes(&vector, "digest"));
        let upper = format!("0x{}", owner[2..].to_ascii_uppercase());
        let checksum = address.to_checksum(None);
        for owner in [upper.as_str(), checksum.as_str()] {
            assert_eq!(build_receiving_key_message(owner).unwrap(), message);
        }
        let signer = SigningKey::from_slice(&bytes(&vector, "privateKey")).unwrap();
        assert_eq!(
            &sign_receiving_message(&signer, address).unwrap()[..],
            bytes(&vector, "signature")
        );

        for encoding in [
            "signature",
            "signatureV0",
            "signatureHighS",
            "signatureCompact",
        ] {
            let signature = bytes(&vector, encoding);
            let canonical = canonical_material(address, &signature).unwrap();
            assert_eq!(&canonical[..], bytes(&vector, "receivingKeyMaterial"));
            let root = receiving_root(address, &canonical[..]).unwrap();
            assert_eq!(&root[..], bytes(&vector, "invisiRootKey"));
            let seed = detection_seed(&root).unwrap();
            assert_eq!(&seed[..], bytes(&vector, "detectionSeed"));

            let receiving = derive_receiving_keys_from_signature(&checksum, &signature).unwrap();
            assert_eq!(receiving.owner_address(), address);
            assert_eq!(
                receiving.viewing_private_key(),
                bytes(&vector, "viewingPrivateKey").as_slice()
            );
            assert_eq!(
                receiving.detection_key(),
                bytes(&vector, "detectionKey").as_slice()
            );
            assert_eq!(
                receiving.public_keys().viewing_public_key.as_slice(),
                bytes(&vector, "viewingPublicKey")
            );
            assert_eq!(
                receiving.public_keys().clue_key.as_slice(),
                bytes(&vector, "clueKey")
            );
            assert_eq!(
                receiving.receiving_address().encode().unwrap(),
                vector["receivingAddress"]
            );
            let debug = format!("{receiving:?}");
            assert!(!debug.contains("viewing_private_key"));
            assert!(!debug.contains("detection_key"));
        }
    }
}

#[test]
fn rejects_wrong_owner_wrong_digest_and_invalid_signature_scalars() {
    let fixture = vectors();
    let vector = &fixture[0];
    let owner = vector["ownerAddress"].as_str().unwrap();
    let message = vector["message"].as_str().unwrap();
    let signature = bytes(vector, "signature");
    for invalid_owner in [
        fixture[1]["ownerAddress"].as_str().unwrap(),
        "0x0000000000000000000000000000000000000000",
        "0x7E5f4552091a69125d5dfcb7b8c2659029395bdf",
        vector["receivingAddress"].as_str().unwrap(),
        "0x1234",
    ] {
        assert!(derive_receiving_keys_from_signature(invalid_owner, &signature).is_err());
    }
    for length in [0, 32, 63, 66] {
        let bad = vec![1; length];
        assert!(derive_receiving_keys_from_signature(owner, &bad).is_err());
    }
    let modulus =
        hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
    let mut invalid = signature.clone();
    for offset in [0, 32] {
        for scalar in [&[0; 32][..], modulus.as_slice()] {
            invalid.copy_from_slice(&signature);
            invalid[offset..offset + 32].copy_from_slice(scalar);
            assert!(derive_receiving_keys_from_signature(owner, &invalid).is_err());
        }
    }
    for v in [1, 26, 28, 29, 35, 255] {
        invalid.copy_from_slice(&signature);
        invalid[64] = v;
        assert!(derive_receiving_keys_from_signature(owner, &invalid).is_err());
    }
    let signer = SigningKey::from_slice(&bytes(vector, "privateKey")).unwrap();
    for wrong_message in [
        format!("{message}\n"),
        format!("\x19Ethereum Signed Message:\n{}{message}", message.len()),
        vector["messageHex"].as_str().unwrap().into(),
    ] {
        let (sig, recid) = signer
            .sign_prehash_recoverable(eip191_hash_message(wrong_message).as_slice())
            .unwrap();
        let mut encoded = sig.to_bytes().to_vec();
        encoded.push(recid.to_byte());
        assert!(derive_receiving_keys_from_signature(owner, &encoded).is_err());
    }
}

#[test]
fn different_valid_nonces_change_receiving_material() {
    let vector = &vectors()[0];
    let owner = vector["ownerAddress"].as_str().unwrap();
    let signature = bytes(vector, "signature");
    let expected = derive_receiving_keys_from_signature(owner, &signature).unwrap();
    let digest = bytes(vector, "digest");
    let signer = SigningKey::from_slice(&bytes(vector, "privateKey")).unwrap();
    let other: Signature = signer
        .sign_prehash_with_rng(&mut StdRng::seed_from_u64(13), &digest)
        .unwrap();
    let id =
        RecoveryId::trial_recovery_from_prehash(signer.verifying_key(), &digest, &other).unwrap();
    let mut encoded = other.to_bytes().to_vec();
    encoded.push(id.to_byte());
    let different = derive_receiving_keys_from_signature(owner, &encoded).unwrap();
    assert_eq!(different.owner_address(), expected.owner_address());
    assert_ne!(different.receiving_address(), expected.receiving_address());
}

#[test]
fn external_receiving_and_local_spending_use_the_same_note_owner() {
    let vector = &vectors()[0];
    let owner = vector["ownerAddress"].as_str().unwrap();
    let receiving =
        derive_receiving_keys_from_signature(owner, &bytes(vector, "signatureCompact")).unwrap();
    let account_key = bytes(vector, "privateKey");
    let note = Note {
        context: ProtocolContext {
            chain_id: 31337,
            protocol_address: U256::from(4660),
        },
        owner_address: receiving.receiving_address().owner_address,
        token_address: U256::from(22136),
        amount: U256::from(42),
        nonce: U256::from(123),
        payload: b"receiving v1".to_vec(),
    };
    let context = DeliveryContext {
        context: note.context,
        token_address: note.token_address,
        output_commitment: note.commitment().unwrap(),
    };
    let envelope =
        encrypt_note(&receiving.public_keys().viewing_public_key, &note, &context).unwrap();
    assert_eq!(
        decrypt_note(
            receiving.viewing_private_key(),
            &envelope,
            &context,
            note.owner_address
        )
        .unwrap(),
        note
    );
    let request = |method, params| json!({ "version": 1, "id": method, "ownerAddress": owner, "method": method, "params": params });
    let response = execute(
        &account_key,
        &request(
            "wallet.decryptNote",
            json!({
                "envelope": hex_value(&envelope), "context": context
            }),
        ),
    )
    .unwrap();
    assert_eq!(
        response["result"]["plaintext"],
        hex_value(&encode_note(&note).unwrap())
    );

    let clue = create_clue_from_seed(&receiving.public_keys().clue_key, &[42; 32]).unwrap();
    assert!(detect_clue(receiving.detection_key(), &clue).unwrap());
    let detected = execute(
        &account_key,
        &request("wallet.detect", json!({"clues": [hex_value(&clue)]})),
    )
    .unwrap();
    assert_eq!(detected["result"]["matches"], json!([true]));

    let authorization = json!({
        "operation": "transact", "capacity": 1,
        "words": ["31337", "4660", note.commitment().unwrap().to_string()],
        "context": {"chainId": "31337", "protocolAddress": "4660"}
    });
    let digest = authorization_digest(&authorization).unwrap();
    let signed = execute(&account_key, &request("wallet.authorize", authorization)).unwrap();
    let public = bytes(&signed["result"], "spendingPublicKey");
    assert_eq!(public, bytes(vector, "spendingPublicKey"));
    let spending = VerifyingKey::from_sec1_bytes(&public).unwrap();
    assert_eq!(owner_for_key(&spending), receiving.owner_address());
    assert_eq!(bytes(&signed["result"], "digest"), digest);
    let signature = Signature::from_slice(&bytes(&signed["result"], "signature")).unwrap();
    spending.verify_prehash(&digest, &signature).unwrap();
    let viewing =
        VerifyingKey::from_sec1_bytes(&receiving.public_keys().viewing_public_key).unwrap();
    assert!(viewing.verify_prehash(&digest, &signature).is_err());
}

#[test]
fn receiving_signatures_reduce_the_nonce_digest_modulo_the_curve_order() {
    let mut one = [0; 32];
    one[31] = 1;
    let order_plus_one: [u8; 32] =
        hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142")
            .unwrap()
            .try_into()
            .unwrap();
    let signer = SigningKey::from_slice(&one).unwrap();
    let expected = sign_receiving_digest(&signer, &one).unwrap();
    let encoded = sign_receiving_digest(&signer, &order_plus_one).unwrap();
    let signature = Signature::from_slice(&encoded[..64]).unwrap();
    let recovery = RecoveryId::from_byte(encoded[64] - 27).unwrap();
    let recovered =
        VerifyingKey::recover_from_prehash(&order_plus_one, &signature, recovery).unwrap();
    assert_eq!(&recovered, signer.verifying_key());
    assert_eq!(&encoded[..], &expected[..]);
}
