//! Source proofs use their own manifest and verification keys, independently of the main release.
use super::*;
use invisi_sdk_primitives::note::{ModelError, ModelResult};

use crate::provenance::{authenticate_manifest, OfflineProver, Witness, PUBLIC_INPUTS};

pub struct NativeSourceProver {
    pub directory: PathBuf,
    pub manifest_sha256: String,
    pub bb_binary: PathBuf,
    pub timeout: Duration,
    pub threads: usize,
    pub witness_executor: Arc<dyn WitnessExecutor>,
}
impl OfflineProver for NativeSourceProver {
    fn prove(
        &self,
        pin: &str,
        capacity: usize,
        witness: &Witness,
        expected: &[String],
    ) -> ModelResult<(Vec<String>, Vec<u8>)> {
        self.prove_local(pin, capacity, witness, expected)
            .map_err(|_| ModelError::Invalid("local source proving"))
    }
}
impl NativeSourceProver {
    fn prove_local(
        &self,
        pin: &str,
        capacity: usize,
        witness: &Witness,
        expected: &[String],
    ) -> Result<(Vec<String>, Vec<u8>)> {
        if pin != self.manifest_sha256
            || expected.len() != PUBLIC_INPUTS.len()
            || self.timeout.is_zero()
            || self.threads == 0
        {
            return Err("source prover identity or options mismatch".into());
        }
        let bytes = fs::read(self.directory.join("manifest.json"))
            .map_err(|_| "source manifest unavailable")?;
        let identity = authenticate_manifest(&bytes, pin).map_err(|e| e.to_string())?;
        let entry = identity
            .manifest
            .circuits
            .iter()
            .find(|c| c.capacity == capacity)
            .ok_or("source capacity unavailable")?;
        let raw: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid source manifest")?;
        let paths = raw["circuits"]
            .as_array()
            .and_then(|items| items.iter().find(|c| c["capacity"] == capacity))
            .ok_or("source capacity unavailable")?;
        let load = |name: &str| -> Result<Vec<u8>> {
            let relative = Path::new(
                paths[name]
                    .as_str()
                    .ok_or("source asset path unavailable")?,
            );
            if relative.is_absolute()
                || relative
                    .components()
                    .any(|c| !matches!(c, std::path::Component::Normal(_)))
            {
                return Err("invalid source asset path".into());
            }
            fs::read(self.directory.join(relative)).map_err(|_| "source asset unavailable".into())
        };
        let artifact = load("artifact")?;
        let key = load("vk")?;
        if sha256(&artifact) != entry.artifact_sha256 || sha256(&key) != entry.vk_sha256 {
            return Err("source asset digest mismatch".into());
        }
        let local = LocalWitness {
            encoded: Zeroizing::new(
                serde_json::to_vec(witness).map_err(|_| "invalid source witness")?,
            ),
        };
        let acvm = self.witness_executor.execute(&artifact, &local)?;
        let dir = PrivateDir::new()?;
        for (name, bytes) in [
            ("circuit.json", artifact.as_slice()),
            ("vk", key.as_slice()),
            ("witness.gz", acvm.as_slice()),
        ] {
            write_private(&dir.path(name), bytes)?;
        }
        version(&self.bb_binary, &["--version"], "6.0.0", self.timeout)?;
        let mut prove = Command::new(&self.bb_binary);
        prove
            .env("HARDWARE_CONCURRENCY", self.threads.to_string())
            .env("BB_MSM_LEGACY", "1");
        run_local(
            prove
                .args(["prove", "-t", "evm", "-b"])
                .arg(dir.path("circuit.json"))
                .arg("-w")
                .arg(dir.path("witness.gz"))
                .arg("-k")
                .arg(dir.path("vk"))
                .arg("-o")
                .arg(&dir.0)
                .args(["--output_format", "json"])
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            self.timeout,
        )?;
        let read = |name: &str| -> Result<Value> {
            serde_json::from_slice(
                &fs::read(dir.path(name)).map_err(|_| "source proof output unavailable")?,
            )
            .map_err(|_| "invalid source proof output".into())
        };
        let public = read("public_inputs.json")?;
        let public = public["public_inputs"]
            .as_array()
            .ok_or("source public inputs unavailable")?;
        let public_words = public.iter().map(word).collect::<Result<Vec<_>>>()?;
        let expected_words = expected
            .iter()
            .map(|v| word(&json!(v)))
            .collect::<Result<Vec<_>>>()?;
        if public_words != expected_words {
            return Err("source prover statement mismatch".into());
        }
        let proof = read("proof.json")?;
        if proof["bb_version"] != "6.0.0" {
            return Err("source proof version mismatch".into());
        }
        let proof = proof["proof"]
            .as_array()
            .ok_or("source proof fields unavailable")?
            .iter()
            .map(word)
            .collect::<Result<Vec<_>>>()?
            .iter()
            .flat_map(|w| w.as_slice().to_vec())
            .collect::<Vec<_>>();
        if proof.is_empty() || proof.len() > 65536 {
            return Err("source proof size invalid".into());
        }
        let public_bytes = expected_words
            .iter()
            .flat_map(|w| w.as_slice().to_vec())
            .collect::<Vec<_>>();
        write_private(&dir.path("proof"), &proof)?;
        write_private(&dir.path("public_inputs"), &public_bytes)?;
        run_local(
            Command::new(&self.bb_binary)
                .args(["verify", "-t", "evm", "-k"])
                .arg(dir.path("vk"))
                .arg("-p")
                .arg(dir.path("proof"))
                .arg("-i")
                .arg(dir.path("public_inputs"))
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
            self.timeout,
        )?;
        Ok((expected.to_vec(), proof))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires pinned source assets and local Noir/BB executables"]
    fn real_local_source_proof_is_independently_verified() -> Result<()> {
        let root = PathBuf::from(
            std::env::var("INVISI_PROTOCOL_ROOT").map_err(|_| "protocol root required")?,
        );
        let golden: Value = serde_json::from_slice(
            &fs::read(root.join("circuits/provenance/golden-vectors.json")).unwrap(),
        )
        .unwrap();
        let prover = NativeSourceProver {
            directory: std::env::var("PROVENANCE_ASSETS").unwrap().into(),
            manifest_sha256: "6107789c5c0d24c4130bff05da6d389336feb5ccb247c4030eae5198ab05d762"
                .into(),
            bb_binary: std::env::var("BB_BINARY").unwrap().into(),
            timeout: Duration::from_secs(120),
            threads: 4,
            witness_executor: Arc::new(NoirCli {
                binary: std::env::var("NOIR_EXECUTOR").unwrap().into(),
                timeout: Duration::from_secs(120),
            }),
        };
        let manifest = fs::read(root.join("circuits/provenance/manifest.json"))
            .map_err(|_| "tracked Source manifest required")?;
        authenticate_manifest(&manifest, &prover.manifest_sha256).map_err(|e| e.to_string())?;
        assert_eq!(manifest, include_bytes!("../../provenance/manifest.json"));
        for key in ["witnessK10SingleInput", "witnessK10CrossTree"] {
            let witness = golden[key]
                .as_object()
                .ok_or("current Source K10 fixture required")?;
            let expected = PUBLIC_INPUTS
                .iter()
                .map(|k| Ok(format!("0x{}", hex::encode(word(&witness[*k])?.as_slice()))))
                .collect::<Result<Vec<_>>>()?;
            let (public, proof) = prover
                .prove(&prover.manifest_sha256, 10, witness, &expected)
                .map_err(|e| e.to_string())?;
            assert_eq!(public, expected);
            assert!(!proof.is_empty());
            let mut changed = expected.clone();
            changed[10] = "0x01".into();
            assert!(prover
                .prove(&prover.manifest_sha256, 10, witness, &changed)
                .is_err());
        }
        Ok(())
    }
}

/// Public resources inherited from the main prover; witness execution remains local.
#[derive(Clone)]
pub struct ProvenanceCapability {
    pub manifest: crate::provenance::ManifestIdentity,
    pub prover: Arc<dyn OfflineProver + Send + Sync>,
}
struct BundledSourceProver {
    assets: Arc<dyn Assets>,
    bb_binary: PathBuf,
    timeout: Duration,
    threads: usize,
    witness_executor: Arc<dyn WitnessExecutor>,
}
impl OfflineProver for BundledSourceProver {
    fn prove(
        &self,
        pin: &str,
        capacity: usize,
        witness: &Witness,
        expected: &[String],
    ) -> ModelResult<(Vec<String>, Vec<u8>)> {
        let run = || -> Result<(Vec<String>, Vec<u8>)> {
            let manifest = include_bytes!("../../provenance/manifest.json");
            let identity = authenticate_manifest(manifest, pin).map_err(|e| e.to_string())?;
            let entry = identity
                .manifest
                .circuits
                .iter()
                .find(|c| c.capacity == capacity)
                .ok_or("source capacity unavailable")?;
            let raw: Value =
                serde_json::from_slice(manifest).map_err(|_| "invalid bundled manifest")?;
            let paths = raw["circuits"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["capacity"] == capacity)
                .unwrap();
            let artifact = self.assets.load_provenance_resource(
                paths["artifact"]
                    .as_str()
                    .ok_or("invalid source asset path")?,
            )?;
            let vk = self
                .assets
                .load_provenance_resource(paths["vk"].as_str().ok_or("invalid source key path")?)?;
            if sha256(&artifact) != entry.artifact_sha256 || sha256(&vk) != entry.vk_sha256 {
                return Err("source asset digest mismatch".into());
            }
            let dir = PrivateDir::new()?;
            write_private(&dir.path("manifest.json"), manifest)?;
            for (key, bytes) in [("artifact", artifact.as_slice()), ("vk", vk.as_slice())] {
                let relative = Path::new(paths[key].as_str().ok_or("invalid bundled asset path")?);
                if relative.is_absolute()
                    || relative
                        .components()
                        .any(|c| !matches!(c, std::path::Component::Normal(_)))
                {
                    return Err("invalid bundled asset path".into());
                }
                let target = dir.0.join(relative);
                fs::create_dir_all(target.parent().unwrap())
                    .map_err(|_| "source resource directory unavailable")?;
                write_private(&target, bytes)?;
            }
            NativeSourceProver {
                directory: dir.0.clone(),
                manifest_sha256: pin.into(),
                bb_binary: self.bb_binary.clone(),
                timeout: self.timeout,
                threads: self.threads,
                witness_executor: self.witness_executor.clone(),
            }
            .prove_local(pin, capacity, witness, expected)
        };
        run().map_err(|_| ModelError::Invalid("local bundled source proving"))
    }
}
impl NativeProver {
    pub fn provenance_capability(&self) -> Result<ProvenanceCapability> {
        if self.timeout.is_zero() || self.threads == 0 {
            return Err("invalid native prover options".into());
        }
        let bytes = include_bytes!("../../provenance/manifest.json");
        let pin = "6107789c5c0d24c4130bff05da6d389336feb5ccb247c4030eae5198ab05d762";
        let manifest = authenticate_manifest(bytes, pin).map_err(|e| e.to_string())?;
        Ok(ProvenanceCapability {
            manifest,
            prover: Arc::new(BundledSourceProver {
                assets: self.assets.clone(),
                bb_binary: self.bb_binary.clone(),
                timeout: self.timeout,
                threads: self.threads,
                witness_executor: self.witness_executor.clone(),
            }),
        })
    }
}

#[cfg(test)]
mod bundled_tests {
    use super::*;
    struct NoIo;
    impl Assets for NoIo {
        fn load_provenance_resource(&self, _: &str) -> Result<Vec<u8>> {
            panic!("capability discovery must not load Source resources")
        }
        fn load(&self, _: &ProofStatement) -> Result<(Vec<u8>, Vec<u8>)> {
            panic!("capability discovery must not load main circuit assets")
        }
    }
    impl WitnessExecutor for NoIo {
        fn execute(&self, _: &[u8], _: &LocalWitness) -> Result<Zeroizing<Vec<u8>>> {
            panic!("capability discovery must not execute private witnesses")
        }
    }
    #[test]
    fn native_capability_authenticates_manifest_without_loading_resources() {
        let prover = NativeProver {
            bb_binary: "/nonexistent/bb".into(),
            timeout: Duration::from_secs(10),
            threads: 1,
            assets: Arc::new(NoIo),
            witness_executor: Arc::new(NoIo),
        };
        let capability = prover.get_provenance_capability().unwrap().unwrap();
        assert_eq!(capability.manifest.manifest.circuits.len(), 7);
        assert_eq!(
            capability.manifest.sha256,
            "6107789c5c0d24c4130bff05da6d389336feb5ccb247c4030eae5198ab05d762"
        );
    }
}

#[cfg(test)]
mod bundled_native_smoke {
    use super::*;
    struct NoMainAssets;
    impl Assets for NoMainAssets {
        fn load(&self, _: &ProofStatement) -> Result<(Vec<u8>, Vec<u8>)> {
            Err("main assets unavailable".into())
        }
    }
    #[test]
    #[ignore = "requires actual BB6 and Noir executables"]
    fn actual_bundled_source_k10_proves_and_independently_verifies() -> Result<()> {
        let timeout = Duration::from_secs(120);
        let prover = NativeProver {
            bb_binary: std::env::var("BB_BINARY")
                .map_err(|_| "BB_BINARY required")?
                .into(),
            timeout,
            threads: 4,
            assets: Arc::new(NoMainAssets),
            witness_executor: Arc::new(NoirCli {
                binary: std::env::var("NOIR_EXECUTOR")
                    .map_err(|_| "NOIR_EXECUTOR required")?
                    .into(),
                timeout,
            }),
        };
        let capability = prover.provenance_capability()?;
        let witness: Witness =
            serde_json::from_slice(include_bytes!("../../testdata/provenance-k10.json"))
                .map_err(|e| e.to_string())?;
        let expected = PUBLIC_INPUTS
            .iter()
            .map(|key| {
                Ok(format!(
                    "0x{}",
                    hex::encode(word(&witness[*key])?.as_slice())
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let (public, proof) = capability
            .prover
            .prove(&capability.manifest.sha256, 10, &witness, &expected)
            .map_err(|e| e.to_string())?;
        assert_eq!(public, expected);
        assert!(!proof.is_empty());
        let mut invalid = expected;
        invalid[10] = "0x01".into();
        assert!(capability
            .prover
            .prove(&capability.manifest.sha256, 10, &witness, &invalid)
            .is_err());
        Ok(())
    }
}
