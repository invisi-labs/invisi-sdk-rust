//! Source proofs use their own manifest and verification keys, independently of the main release.
use super::*;
use invisi_sdk_core::{
    note::{ModelError, ModelResult},
    provenance::{authenticate_manifest, OfflineProver, Witness, PUBLIC_INPUTS},
};

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
