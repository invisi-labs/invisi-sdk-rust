use super::*;

fn fixture(capacity: usize) -> Vec<u8> {
    fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "assets/prover/testdata/recursive/transact_user_slots{capacity}.vk"
    )))
    .unwrap()
}

#[test]
fn recursive_metadata_does_not_embed_full_keys() {
    let keys: Value = serde_json::from_str(RECURSIVE_KEYS).unwrap();
    assert_eq!(keys.as_object().unwrap().len(), 10);
    for key in keys.as_object().unwrap().values() {
        assert!(
            key.get("verificationKeyFields").is_none(),
            "recursive fields must be loaded from authenticated binary assets"
        );
        assert!(key["keyHash"].is_string());
        assert!(key["innerVkCommitment"].is_string());
    }
}

#[test]
fn real_recursive_binaries_match_all_ten_pinned_commitments() {
    let keys: Value = serde_json::from_str(RECURSIVE_KEYS).unwrap();
    for capacity in 1..=10 {
        let name = format!("transact_user_slots{capacity}");
        let expected =
            statement(&name, "noir-recursive", vec![B256::ZERO; 17 + 3 * capacity]).unwrap();
        let key = &keys[capacity.to_string()];
        let decoded =
            authenticate_recursive_key(&fixture(capacity), &expected.vk_sha256, key).unwrap();
        assert_eq!(decoded.fields.len(), 115);
        assert_eq!(decoded.hash, key["keyHash"]);
        assert_eq!(decoded.commitment, key["innerVkCommitment"]);
        assert_eq!(
            hex::decode(decoded.fields.concat().replace("0x", "")).unwrap(),
            fixture(capacity)
        );
    }
}

#[test]
fn rejects_recursive_corruption_width_noncanonical_and_commitment() {
    let keys: Value = serde_json::from_str(RECURSIVE_KEYS).unwrap();
    let key = &keys["1"];
    let bytes = fixture(1);
    let digest = sha256(&bytes);
    let mut wrong = bytes.clone();
    wrong[0] ^= 1;
    assert!(authenticate_recursive_key(&wrong, &digest, key)
        .unwrap_err()
        .contains("checksum"));
    for length in [0, 32, 114 * 32, 115 * 32 - 1, 115 * 32 + 1] {
        let wrong = vec![0; length];
        assert!(authenticate_recursive_key(&wrong, &sha256(&wrong), key)
            .unwrap_err()
            .contains("width"));
    }
    wrong = bytes.clone();
    wrong[..32].copy_from_slice(&invisi_sdk_primitives::note::field_modulus().to_be_bytes::<32>());
    assert!(authenticate_recursive_key(&wrong, &sha256(&wrong), key)
        .unwrap_err()
        .contains("canonical"));
    for field in ["keyHash", "innerVkCommitment"] {
        let mut wrong_key = key.clone();
        wrong_key[field] = json!(format!("{:#x}", B256::ZERO));
        assert!(authenticate_recursive_key(&bytes, &digest, &wrong_key)
            .unwrap_err()
            .contains("commitment"));
        wrong_key[field] = json!("0x01");
        assert!(authenticate_recursive_key(&bytes, &digest, &wrong_key)
            .unwrap_err()
            .contains("canonical"));
    }
}

fn bundle(expected: &ProofStatement) -> ProofBundle {
    let proof = vec![
        0;
        if expected.target == "noir-recursive" {
            458 * 32
        } else {
            32
        }
    ];
    ProofBundle {
        format_version: 1,
        circuit_name: expected.circuit_name.clone(),
        target: expected.target.clone(),
        bb_version: "6.0.0".into(),
        artifact_sha256: expected.artifact_sha256.clone(),
        vk_sha256: expected.vk_sha256.clone(),
        proof_sha256: sha256(&proof),
        proof,
        public_inputs: expected.expected_public_inputs.clone(),
    }
}
fn member(label: &str) -> AggregateMember {
    let fixtures: Value = serde_json::from_str(include_str!(
        "../../assets/prover/testdata/current-proving.json"
    ))
    .unwrap();
    let fixture = fixtures["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["label"] == label)
        .unwrap();
    let expected = statement(
        fixture["name"].as_str().unwrap(),
        "noir-recursive",
        serde_json::from_value(fixture["publicInputs"].clone()).unwrap(),
    )
    .unwrap();
    AggregateMember {
        bundle: bundle(&expected),
        statement: expected,
    }
}
#[derive(Default)]
struct Backend {
    loads: std::sync::Mutex<Vec<usize>>,
    verifications: std::sync::Mutex<Vec<String>>,
    reject_member: bool,
    reject_outer: bool,
    unsupported: bool,
}
impl Prover for Backend {
    fn load_verification_key(&self, name: &str, target: &str) -> Result<Vec<u8>> {
        if self.unsupported {
            return Err("unsupported key loader".into());
        }
        assert_eq!(target, "noir-recursive");
        let capacity = name
            .strip_prefix("transact_user_slots")
            .unwrap()
            .parse()
            .unwrap();
        self.loads.lock().unwrap().push(capacity);
        Ok(fixture(capacity))
    }
    // The expensive external prover is replaced here to inspect witness assembly;
    // the ignored native integration below proves and verifies actual BB6 proofs.
    fn prove(&self, request: &ProvingRequest) -> Result<ProofBundle> {
        request.witness.with_inputs(|inputs| {
            let keys: Vec<Value> = if inputs.get("verification_key").is_some() {
                vec![inputs["verification_key"].clone()]
            } else {
                inputs["verification_keys"].as_array().unwrap().clone()
            };
            for (fields, capacity) in keys.iter().zip(self.loads.lock().unwrap().iter()) {
                let expected: Vec<String> = fixture(*capacity)
                    .chunks_exact(32)
                    .map(|word| format!("0x{}", hex::encode(word)))
                    .collect();
                assert_eq!(fields, &json!(expected));
            }
            Ok(())
        })?;
        Ok(bundle(&request.statement))
    }
    fn verify(&self, proof: &ProofBundle, _: &ProofStatement) -> Result<bool> {
        self.verifications
            .lock()
            .unwrap()
            .push(proof.target.clone());
        Ok(if proof.target == "noir-recursive" {
            !self.reject_member
        } else {
            !self.reject_outer
        })
    }
}
#[test]
fn dedicated_and_mixed_aggregation_load_backend_keys_and_verify_members_and_outer() {
    for (members, expected_loads, expected_name) in [
        (vec![member("note1a")], vec![1], "transact_aggregate_1_1"),
        (
            vec![member("note1a"), member("note1b")],
            vec![1],
            "transact_aggregate_1_2",
        ),
        (
            vec![member("note1a"), member("note5")],
            vec![1, 2, 3, 4, 5],
            "transact_aggregate_mixed_1_5_2",
        ),
    ] {
        let backend = Backend::default();
        let result = aggregate(&backend, &members).unwrap();
        assert_eq!(result.circuit_name, expected_name);
        assert_eq!(*backend.loads.lock().unwrap(), expected_loads);
        let verified = backend.verifications.lock().unwrap();
        assert_eq!(
            &verified[..members.len()],
            vec!["noir-recursive"; members.len()]
        );
        assert_eq!(verified.last().unwrap(), "evm");
    }
    let backend = Backend {
        reject_member: true,
        ..Backend::default()
    };
    assert!(aggregate(&backend, &[member("note1a")])
        .unwrap_err()
        .contains("member verification"));
    assert!(backend.loads.lock().unwrap().is_empty());
    let backend = Backend {
        reject_outer: true,
        ..Backend::default()
    };
    assert!(aggregate(&backend, &[member("note1a")])
        .unwrap_err()
        .contains("aggregate proof verification"));
    let backend = Backend {
        unsupported: true,
        ..Backend::default()
    };
    assert!(aggregate(&backend, &[member("note1a")])
        .unwrap_err()
        .contains("unsupported key loader"));
}
#[test]
fn native_key_loader_uses_configured_key_only_provider_and_offline_cache() {
    struct NoExecution;
    impl WitnessExecutor for NoExecution {
        fn execute(&self, _: &[u8], _: &LocalWitness) -> Result<Zeroizing<Vec<u8>>> {
            panic!("key loading must not execute a witness")
        }
    }
    let temporary = PrivateDir::new().unwrap();
    let source = temporary.path("source");
    fs::create_dir(&source).unwrap();
    let bytes = fixture(1);
    let digest = sha256(&bytes);
    let index = serde_json::to_vec(&json!({"format":"invisi.prover-assets.v1", "noirVersion":"1.0.0", "bbVersion":"6.0.0", "files": {
        "circuits/transact_user_slots1.noir-recursive.vk": {"sha256":digest,"size":bytes.len()}
    }})).unwrap();
    fs::write(source.join("index.json"), &index).unwrap();
    fs::write(source.join(format!("{digest}.vk")), &bytes).unwrap();
    let options = ResourceOptions {
        source: source.to_string_lossy().into(),
        cache: temporary.path("cache"),
        index_sha256: sha256(&index),
        ..ResourceOptions::default()
    };
    let mut backend = NativeProver::new(temporary.path("missing-bb"), Arc::new(NoExecution));
    assert!(
        !options.cache.exists(),
        "constructing a native prover must not load resources"
    );
    backend.assets = Arc::new(ResourceProvider::new(options.clone()));
    assert_eq!(load_recursive_key(&backend, 1).unwrap().fields.len(), 115);
    fs::remove_dir_all(&source).unwrap();
    backend.assets = Arc::new(ResourceProvider::new(ResourceOptions {
        offline: true,
        ..options.clone()
    }));
    assert_eq!(load_recursive_key(&backend, 1).unwrap().fields.len(), 115);
    fs::write(
        options.cache.join(format!("{digest}.vk")),
        vec![0; 115 * 32],
    )
    .unwrap();
    assert!(load_recursive_key(&backend, 1).is_err());
    let directory = temporary.path("logical");
    fs::create_dir(&directory).unwrap();
    fs::write(
        directory.join("transact_user_slots1.noir-recursive.vk"),
        &bytes,
    )
    .unwrap();
    backend.assets = Arc::new(DirectoryAssets {
        directory: directory.clone(),
    });
    assert_eq!(load_recursive_key(&backend, 1).unwrap().fields.len(), 115);
    fs::write(
        directory.join("transact_user_slots1.noir-recursive.vk"),
        vec![0; 115 * 32],
    )
    .unwrap();
    assert!(load_recursive_key(&backend, 1).is_err());
}

#[test]
#[ignore = "requires explicit INVISI_BB, INVISI_NOIR_EXECUTE, and INVISI_PROVER_ASSETS"]
fn real_native_recursive_c1_aggregation_proves_and_verifies() {
    let fixtures: Value = serde_json::from_str(include_str!(
        "../../assets/prover/testdata/current-proving.json"
    ))
    .unwrap();
    let fixture = fixtures["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["label"] == "note1a")
        .unwrap();
    let expected = member("note1a").statement;
    let backend = NativeProver {
        bb_binary: std::env::var_os("INVISI_BB").unwrap().into(),
        timeout: Duration::from_secs(600),
        threads: 4,
        assets: Arc::new(ResourceProvider::new(ResourceOptions {
            directory: Some(std::env::var_os("INVISI_PROVER_ASSETS").unwrap().into()),
            offline: true,
            ..ResourceOptions::default()
        })),
        witness_executor: Arc::new(NoirCli {
            binary: std::env::var_os("INVISI_NOIR_EXECUTE").unwrap().into(),
            timeout: Duration::from_secs(120),
        }),
    };
    let inner = backend
        .prove(&ProvingRequest {
            statement: expected.clone(),
            witness: LocalWitness::new(fixture["witness"].clone()).unwrap(),
        })
        .unwrap();
    let outer = aggregate(
        &backend,
        &[AggregateMember {
            bundle: inner,
            statement: expected,
        }],
    )
    .unwrap();
    assert_eq!(outer.circuit_name, "transact_aggregate_1_1");
    assert_eq!(outer.target, "evm");
    let mut mixed_members = Vec::new();
    for label in ["note1a", "note5"] {
        let fixture = fixtures["fixtures"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["label"] == label)
            .unwrap();
        let expected = member(label).statement;
        let proof = backend
            .prove(&ProvingRequest {
                statement: expected.clone(),
                witness: LocalWitness::new(fixture["witness"].clone()).unwrap(),
            })
            .unwrap();
        mixed_members.push(AggregateMember {
            bundle: proof,
            statement: expected,
        });
    }
    let mixed = aggregate(&backend, &mixed_members).unwrap();
    assert_eq!(mixed.circuit_name, "transact_aggregate_mixed_1_5_2");
}

#[test]
fn configured_key_loader_also_authenticates_direct_evm_keys() {
    let temporary = PrivateDir::new().unwrap();
    let key = include_bytes!("../../assets/prover/testdata/transact_user_slots1.evm.vk");
    fs::write(temporary.path("transact_user_slots1.evm.vk"), key).unwrap();
    let assets = DirectoryAssets {
        directory: temporary.0.clone(),
    };
    assert_eq!(
        assets
            .load_verification_key("transact_user_slots1", "evm")
            .unwrap(),
        key
    );
    fs::write(
        temporary.path("transact_user_slots1.evm.vk"),
        vec![0; key.len()],
    )
    .unwrap();
    assert!(assets
        .load_verification_key("transact_user_slots1", "evm")
        .is_err());
}

#[test]
fn existing_custom_backends_fail_locally_without_a_key_capability() {
    struct ExistingBackend;
    impl Prover for ExistingBackend {
        fn prove(&self, _: &ProvingRequest) -> Result<ProofBundle> {
            panic!("unsupported aggregation must not prove")
        }
        fn verify(&self, _: &ProofBundle, _: &ProofStatement) -> Result<bool> {
            Ok(true)
        }
    }
    assert!(aggregate(&ExistingBackend, &[member("note1a")])
        .unwrap_err()
        .contains("support verification key loading"));
    struct ExistingAssets;
    impl Assets for ExistingAssets {
        fn load(&self, _: &ProofStatement) -> Result<(Vec<u8>, Vec<u8>)> {
            panic!("key loading must not load circuit artifacts")
        }
    }
    assert!(ExistingAssets
        .load_verification_key("transact_user_slots1", "noir-recursive")
        .unwrap_err()
        .contains("support verification key loading"));
}

#[test]
fn native_key_api_authenticates_even_custom_asset_bytes() {
    struct CustomAssets(Vec<u8>);
    impl Assets for CustomAssets {
        fn load(&self, _: &ProofStatement) -> Result<(Vec<u8>, Vec<u8>)> {
            panic!("key API must not load an artifact")
        }
        fn load_verification_key(&self, _: &str, _: &str) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }
    struct NoExecution;
    impl WitnessExecutor for NoExecution {
        fn execute(&self, _: &[u8], _: &LocalWitness) -> Result<Zeroizing<Vec<u8>>> {
            panic!("key API must not execute")
        }
    }
    let mut backend = NativeProver::new(PathBuf::from("missing-bb"), Arc::new(NoExecution));
    backend.assets = Arc::new(CustomAssets(vec![0; 1888]));
    assert!(
        backend
            .load_verification_key("transact_user_slots1", "evm")
            .is_err(),
        "native API must reject untrusted custom asset bytes"
    );
    let key = include_bytes!("../../assets/prover/testdata/transact_user_slots1.evm.vk");
    backend.assets = Arc::new(CustomAssets(key.to_vec()));
    assert_eq!(
        backend
            .load_verification_key("transact_user_slots1", "evm")
            .unwrap(),
        key
    );
    assert!(backend.load_verification_key("unknown", "evm").is_err());
    assert!(backend
        .load_verification_key("transact_user_slots1", "unknown")
        .is_err());
}
