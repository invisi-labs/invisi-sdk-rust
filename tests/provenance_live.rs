use alloy_primitives::U256;
use invisi_sdk::provenance::*;
use invisi_sdk::provenance_client::ProvenanceClient;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, time::Duration};
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LiveScope {
    chain_id: String,
    protocol_address: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LiveTrust {
    #[serde(default, rename = "recovery")]
    _recovery: Option<Value>,
    format: String,
    endpoint: String,
    scope: LiveScope,
    chain_generation: String,
    provider_id: String,
    initial_signing_public_key: String,
    initial_signing_key_id: String,
    current_signing_public_key: String,
    current_signing_key_id: String,
    manifest_sha256: String,
    key_rotations: Vec<RotationRecord>,
    checked_at: String,
    root_id: String,
    commitment: String,
    #[serde(default, rename = "jobId")]
    _job_id: Option<String>,
    tracking_id: String,
}
fn bytes32(value: &str) -> [u8; 32] {
    assert!(value.starts_with("0x"));
    hex::decode(&value[2..]).unwrap().try_into().unwrap()
}
fn n(value: &str) -> U256 {
    parse_integer(value, 256).unwrap()
}
fn identity(r: &Value, f: &LiveTrust) {
    assert_eq!(
        n(r["scope"]["chainId"].as_str().unwrap()),
        n(&f.scope.chain_id)
    );
    assert_eq!(
        n(r["scope"]["protocolAddress"].as_str().unwrap()),
        n(&f.scope.protocol_address)
    );
    assert_eq!(r["chainGeneration"], f.chain_generation);
    assert_eq!(r["providerId"], f.provider_id);
    assert_eq!(r["signingKeyId"], f.current_signing_key_id);
    assert_eq!(r["manifestSha256"], f.manifest_sha256);
}
#[test]
fn provenance_live_service() {
    if std::env::var("INVISI_PROVENANCE_LIVE").as_deref() != Ok("1") {
        eprintln!(
            "SKIP live opt-in: INVISI_PROVENANCE_LIVE=1 and public operator trust file required"
        );
        return;
    }
    let file = std::env::var("INVISI_PROVENANCE_TRUST").expect("explicit trust file required");
    let f: LiveTrust = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
    assert_eq!(f.format, "invisi-provenance-sdk-live-v1");
    assert_eq!(
        f.manifest_sha256,
        "f90f2ce43218de158c6392fa19e6517dda703c35823a4aa5bfc20b50788ad282"
    );
    assert!(
        f.endpoint.starts_with("http://127.0.0.1:")
            || f.endpoint.starts_with("http://localhost:")
            || f.endpoint.starts_with("http://[::1]:")
    );
    let genesis = bytes32(&f.initial_signing_public_key);
    let current = bytes32(&f.current_signing_public_key);
    assert_eq!(
        format!("0x{}", hex::encode(Sha256::digest(genesis))),
        f.initial_signing_key_id
    );
    assert_eq!(
        format!("0x{}", hex::encode(Sha256::digest(current))),
        f.current_signing_key_id
    );
    let ring = verify_rotation_chain(
        RotationCheckpoint {
            provider_id: n(&f.provider_id),
            keys: BTreeMap::from([(n(&f.initial_signing_key_id), genesis)]),
            validity: BTreeMap::new(),
            previous_rotation_hash: [0; 32],
            last_activated_at: 0,
            now: parse_integer(&f.checked_at, 64).unwrap().to(),
        },
        &f.key_rotations,
    )
    .unwrap();
    assert_eq!(ring.keys[&n(&f.current_signing_key_id)], current);
    let trust = TrustContext {
        scope: Scope {
            chain_id: parse_integer(&f.scope.chain_id, 64).unwrap().to(),
            protocol_address: n(&f.scope.protocol_address),
        },
        chain_generation: parse_integer(&f.chain_generation, 64).unwrap().to(),
        provider_id: n(&f.provider_id),
        signing_keys: BTreeMap::new(),
        signing_key_validity: BTreeMap::new(),
        manifest_sha256: f.manifest_sha256.clone(),
    }
    .with_rotation_history(ring.clone())
    .unwrap();
    let c = ProvenanceClient::new(&f.endpoint, trust.clone()).unwrap();
    let version = c.get_version().unwrap();
    identity(&version, &f);
    assert_eq!(version["apiVersion"], "v1");
    assert_eq!(version["protocolVersion"], "1");
    assert_eq!(version["publicInputCount"], "13");
    assert_eq!(version["proofFormat"], "invisi-provenance-proof-v1");
    let status = c.get_status().unwrap();
    identity(&status, &f);
    assert_eq!(status["workerAvailable"], true);
    let policy = c.get_rules().unwrap();
    identity(&policy, &f);
    assert_eq!(
        policy["initialSigningPublicKey"],
        f.initial_signing_public_key
    );
    let rotations = if policy["keyRotations"].is_null() {
        json!([])
    } else {
        policy["keyRotations"].clone()
    };
    assert_eq!(rotations, serde_json::to_value(&f.key_rotations).unwrap());
    for (id, pubkey) in &ring.keys {
        assert_eq!(
            policy["providerKeys"][format!("0x{}", hex::encode(id.to_be_bytes::<32>()))],
            format!("0x{}", hex::encode(pubkey))
        );
    }
    let mut cursor = None;
    let mut found = false;
    for page in 0..20 {
        let roots = c
            .get_roots(match cursor {
                Some(ref v) => json!({"cursor":v,"limit":"1"}),
                None => json!({"after":"0","limit":"1"}),
            })
            .unwrap();
        identity(&roots, &f);
        for raw in roots["items"].as_array().unwrap() {
            let cert: RootCertificate = serde_json::from_value(raw.clone()).unwrap();
            assert_certificate_trust(&cert, &trust).unwrap();
            if format!("{}:{}", cert.chain_generation, cert.root_sequence) == f.root_id {
                found = true;
            }
        }
        cursor = roots["nextCursor"].as_str().map(String::from);
        if cursor.is_none() {
            break;
        }
        assert!(page < 19, "unbounded root history");
    }
    assert!(found, "fixed published root absent");
    let root = c.get_root(&f.root_id).unwrap();
    identity(&root, &f);
    assert_eq!(root["allowedForNewProof"], true);
    let cert: RootCertificate = serde_json::from_value(root["certificate"].clone()).unwrap();
    assert_certificate_trust(&cert, &trust).unwrap();
    let leaves = c.get_leaves(&f.root_id, 0, 1).unwrap();
    identity(&leaves, &f);
    assert_eq!(leaves["nextIndex"], "1");
    assert_eq!(leaves["items"].as_array().unwrap().len(), 1);
    let tree = c.sync_recognized_tree(&f.root_id, &cert, 10000).unwrap();
    assert_eq!(U256::from(tree.leaf_count()), n(&cert.leaf_count));
    let local = tree
        .membership_for_commitment(&trust.scope, n(&f.commitment))
        .unwrap()
        .expect("locally replayed commitment missing");
    assert_eq!(local.root, n(&cert.root));
    let remote = c
        .get_membership(n(&f.commitment), &f.root_id, true)
        .unwrap();
    identity(&remote, &f);
    assert_eq!(
        n(remote["leafIndex"].as_str().unwrap()),
        U256::from(local.leaf_index)
    );
    assert_eq!(
        remote["path"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| n(v.as_str().unwrap()))
            .collect::<Vec<_>>(),
        local.path
    );
    let note = c.get_note_recognition(n(&f.commitment)).unwrap();
    identity(&note, &f);
    assert_eq!(note["found"], true);
    assert_eq!(note["recognitionState"], "recognized");
    assert_eq!(note["note"]["noteCommitment"], f.commitment);
    assert_certificate_trust(
        &serde_json::from_value::<RootCertificate>(note["certificate"].clone()).unwrap(),
        &trust,
    )
    .unwrap();
    let tracked = c.get_tracking(&f.tracking_id).unwrap();
    identity(&tracked, &f);
    assert_eq!(tracked["tracking"]["status"], "recognized");
    let waited = c
        .wait_tracking(
            &f.tracking_id,
            Duration::from_millis(1),
            Duration::from_secs(3),
        )
        .unwrap();
    identity(&waited, &f);
    assert_eq!(waited["tracking"]["status"], "recognized");
    for kind in ["provider", "generation", "manifest", "key"] {
        let mut wrong = trust.clone();
        match kind {
            "provider" => wrong.provider_id = U256::ZERO,
            "generation" => wrong.chain_generation = 0,
            "manifest" => wrong.manifest_sha256 = "0".repeat(64),
            "key" => wrong.signing_keys.clear(),
            _ => unreachable!(),
        };
        assert!(
            ProvenanceClient::new(&f.endpoint, wrong)
                .unwrap()
                .get_tracking(&f.tracking_id)
                .is_err(),
            "wrong {kind} pin accepted actual response"
        );
    }
}
