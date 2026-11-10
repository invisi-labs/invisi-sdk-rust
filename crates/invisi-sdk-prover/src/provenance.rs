//! Local Source witness construction, authenticated assets and proof orchestration.
use alloy_primitives::U256;
use invisi_sdk_primitives::note::{field, hash_fields, ModelError, ModelResult};
pub use invisi_sdk_protocol::provenance::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
fn h(v: &[U256]) -> ModelResult<U256> {
    hash_fields(v)
}
#[derive(Debug, Clone)]
pub struct WitnessInput {
    pub opening: Opening,
    pub source_index: usize,
    pub leaf_index: u32,
    pub path: Vec<U256>,
}
pub struct WitnessRequest {
    pub scope: Scope,
    pub capacity: usize,
    pub token_address: U256,
    pub chain_generation: u64,
    pub operation_digest: U256,
    pub inputs: Vec<WitnessInput>,
    pub sources: Vec<Source>,
}
pub type Witness = serde_json::Map<String, serde_json::Value>;
fn values(v: Vec<U256>) -> serde_json::Value {
    serde_json::Value::Array(
        v.into_iter()
            .map(|n| serde_json::Value::String(n.to_string()))
            .collect(),
    )
}
pub fn build_witness(r: &WitnessRequest) -> ModelResult<Witness> {
    if !supported_capacity(r.capacity)
        || r.inputs.is_empty()
        || r.inputs.len() > r.capacity
        || r.sources.is_empty()
        || r.sources.len() > r.inputs.len()
    {
        return Err(ModelError::Invalid("provenance shape"));
    }
    let scope = scope_hash(&r.scope)?;
    let sd = sources_digest(r.chain_generation, &r.sources)?;
    let mut vectors: BTreeMap<&str, Vec<U256>> = BTreeMap::new();
    for k in [
        "owners",
        "nonces",
        "amounts",
        "source_indices",
        "leaf_indices",
        "tree_ids",
        "roots",
        "leaf_counts",
    ] {
        vectors.insert(k, Vec::new());
    }
    for s in &r.sources {
        vectors
            .get_mut("tree_ids")
            .unwrap()
            .push(U256::from(s.tree_id));
        vectors.get_mut("roots").unwrap().push(s.root);
        vectors
            .get_mut("leaf_counts")
            .unwrap()
            .push(U256::from(s.leaf_count));
    }
    let mut used = BTreeSet::new();
    let mut ns = Vec::new();
    let mut paths = Vec::new();
    for i in &r.inputs {
        let src = r
            .sources
            .get(i.source_index)
            .ok_or(ModelError::Invalid("source index"))?;
        if i.path.len() != 32 || i.leaf_index as u64 >= src.leaf_count {
            return Err(ModelError::Invalid("membership path"));
        }
        used.insert(i.source_index);
        let (c, n) = note_opening(&r.scope, r.token_address, &i.opening)?;
        let mut leaf = recognized_leaf(scope, c)?;
        for (l, p) in i.path.iter().enumerate() {
            leaf = if (i.leaf_index >> l) & 1 == 0 {
                h(&[leaf, *p])?
            } else {
                h(&[*p, leaf])?
            };
        }
        if leaf != src.root {
            return Err(ModelError::Mismatch("membership root"));
        }
        if ns.contains(&n) {
            return Err(ModelError::Invalid("duplicate input"));
        }
        ns.push(n);
        for (k, v) in [
            ("owners", i.opening.owner),
            ("nonces", i.opening.nonce),
            ("amounts", i.opening.amount),
            ("source_indices", U256::from(i.source_index)),
            ("leaf_indices", U256::from(i.leaf_index)),
        ] {
            vectors.get_mut(k).unwrap().push(v);
        }
        paths.push(values(i.path.clone()));
    }
    if used.len() != r.sources.len() {
        return Err(ModelError::Invalid("unused source"));
    }
    let id = input_digest(&ns)?;
    let binding = binding_digest(
        scope,
        r.token_address,
        r.chain_generation,
        r.sources.len(),
        sd,
        r.inputs.len(),
        r.operation_digest,
        id,
    )?;
    let [ohi, olo] = limbs(r.operation_digest);
    let pub_values = [
        U256::from(r.scope.chain_id),
        r.scope.protocol_address,
        r.token_address,
        U256::from(r.chain_generation),
        U256::from(r.sources.len()),
        sd,
        U256::from(r.inputs.len()),
        ohi,
        olo,
        id,
        binding,
    ];
    let mut w = Witness::new();
    for (k, n) in PUBLIC_INPUTS.iter().zip(pub_values) {
        field(n, "public input")?;
        w.insert(k.to_string(), serde_json::Value::String(n.to_string()));
    }
    for (k, mut v) in vectors {
        v.resize(r.capacity, U256::ZERO);
        w.insert(k.to_string(), values(v));
    }
    while paths.len() < r.capacity {
        paths.push(values(vec![U256::ZERO; 32]));
    }
    w.insert("paths".into(), serde_json::Value::Array(paths));
    Ok(w)
}
/// Private witnesses are consumed by an explicit local host capability, never a remote prover URL.
pub trait OfflineProver {
    fn prove(
        &self,
        manifest_sha256: &str,
        capacity: usize,
        witness: &Witness,
        expected_public_inputs: &[String],
    ) -> ModelResult<(Vec<String>, Vec<u8>)>;
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestEntry {
    pub capacity: usize,
    pub artifact_sha256: String,
    pub vk_sha256: String,
}
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub family: String,
    pub target: String,
    pub noir_version: String,
    pub bb_version: String,
    pub depth: usize,
    pub public_inputs: Vec<String>,
    pub circuits: Vec<ManifestEntry>,
}
#[derive(Debug, Clone)]
pub struct ManifestIdentity {
    pub manifest: Manifest,
    pub sha256: String,
}
pub fn authenticate_manifest(bytes: &[u8], expected: &str) -> ModelResult<ManifestIdentity> {
    if expected.len() != 64 || hex::encode(Sha256::digest(bytes)) != expected {
        return Err(ModelError::Mismatch("manifest hash"));
    }
    let m: Manifest = serde_json::from_slice(bytes).map_err(|_| ModelError::Invalid("manifest"))?;
    if m.family != "provenance"
        || m.target != "evm"
        || m.noir_version != "1.0.0"
        || m.bb_version != "6.0.0"
        || m.depth != 32
        || m.public_inputs != PUBLIC_INPUTS
        || m.circuits.len() != 7
    {
        return Err(ModelError::Invalid("manifest identity"));
    }
    let mut seen = BTreeSet::new();
    for c in &m.circuits {
        if !supported_capacity(c.capacity)
            || !seen.insert(c.capacity)
            || c.artifact_sha256.len() != 64
            || c.vk_sha256.len() != 64
        {
            return Err(ModelError::Invalid("manifest circuit"));
        }
    }
    Ok(ManifestIdentity {
        manifest: m,
        sha256: expected.to_string(),
    })
}
pub fn export_sidecar(
    r: &WitnessRequest,
    certificates: &[RootCertificate],
    trust: &TrustContext,
    identity: &ManifestIdentity,
    prover: &dyn OfflineProver,
    operation_index: u32,
) -> ModelResult<ProofSidecar> {
    if identity.sha256 != trust.manifest_sha256
        || certificates.len() != r.sources.len()
        || r.scope != trust.scope
        || r.chain_generation != trust.chain_generation
    {
        return Err(ModelError::Mismatch("provenance deployment"));
    }
    for (c, s) in certificates.iter().zip(&r.sources) {
        assert_certificate_trust(c, trust)?;
        for (raw, n) in [
            (&c.tree_id, U256::from(s.tree_id)),
            (&c.root, s.root),
            (&c.leaf_count, U256::from(s.leaf_count)),
        ] {
            if parse_integer(raw, 256)? != n {
                return Err(ModelError::Mismatch("certificate source"));
            }
        }
    }
    let witness = build_witness(r)?;
    let mut expected = Vec::new();
    for k in PUBLIC_INPUTS {
        let value = parse_integer(
            witness[k].as_str().ok_or(ModelError::Invalid("witness"))?,
            256,
        )?;
        expected.push(format!("0x{}", hex::encode(value.to_be_bytes::<32>())));
    }
    let (public, proof) = prover.prove(&identity.sha256, r.capacity, &witness, &expected)?;
    if public.len() != 11 || proof.is_empty() || proof.len() > 65536 {
        return Err(ModelError::Invalid("offline prover output"));
    }
    for (a, b) in public.iter().zip(&expected) {
        if parse_integer(a, 256)? != parse_integer(b, 256)? {
            return Err(ModelError::Mismatch("prover statement"));
        }
    }
    Ok(ProofSidecar {
        operation_index: operation_index.to_string(),
        proof_bundle: ProofBundle {
            format: "invisi-provenance-proof-v1".into(),
            circuit_id: format!("provenance_k{}", r.capacity),
            manifest_sha256: identity.sha256.clone(),
            target: "evm".into(),
            public_inputs: expected,
            proof: format!("0x{}", hex::encode(proof)),
            root_certificates: certificates
                .iter()
                .map(certificate_to_wire)
                .collect::<ModelResult<_>>()?,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    fn vectors() -> Value {
        serde_json::from_str(include_str!("provenance-testdata/golden-vectors.json")).unwrap()
    }
    fn n(v: &Value) -> U256 {
        parse_integer(
            &v.as_str()
                .map(String::from)
                .unwrap_or_else(|| v.to_string()),
            256,
        )
        .unwrap()
    }
    fn request(v: &Value) -> WitnessRequest {
        let count = n(&v["input_count"]).to::<usize>();
        let source_count = n(&v["source_count"]).to::<usize>();
        WitnessRequest {
            scope: Scope {
                chain_id: n(&v["chain_id"]).to(),
                protocol_address: n(&v["protocol_address"]),
            },
            capacity: v["owners"].as_array().unwrap().len(),
            token_address: n(&v["token_address"]),
            chain_generation: n(&v["chain_generation"]).to(),
            operation_digest: n(&v["operation_digest_lo"]),
            inputs: (0..count)
                .map(|i| WitnessInput {
                    opening: Opening {
                        owner: n(&v["owners"][i]),
                        nonce: n(&v["nonces"][i]),
                        amount: n(&v["amounts"][i]),
                    },
                    source_index: n(&v["source_indices"][i]).to(),
                    leaf_index: n(&v["leaf_indices"][i]).to(),
                    path: v["paths"][i].as_array().unwrap().iter().map(n).collect(),
                })
                .collect(),
            sources: (0..source_count)
                .map(|i| Source {
                    tree_id: n(&v["tree_ids"][i]).to(),
                    root: n(&v["roots"][i]),
                    leaf_count: n(&v["leaf_counts"][i]).to(),
                })
                .collect(),
        }
    }
    #[test]
    fn shared_primitives_and_evm_digest() {
        let v = vectors();
        let c = &v["note"]["context"];
        let s = Scope {
            chain_id: n(&c["chainId"]).to(),
            protocol_address: n(&c["protocolAddress"]),
        };
        let scope = scope_hash(&s).unwrap();
        assert_eq!(scope, n(&v["note"]["scope"]));
        let (commitment, nullifier) = note_opening(
            &s,
            n(&c["tokenAddress"]),
            &Opening {
                owner: n(&c["owner"]),
                nonce: n(&c["nonce"]),
                amount: n(&c["amount"]),
            },
        )
        .unwrap();
        assert_eq!(commitment, n(&v["note"]["commitment"]));
        assert_eq!(nullifier, n(&v["note"]["nullifier"]));
        assert_eq!(
            recognized_leaf(scope, commitment).unwrap(),
            n(&v["note"]["recognizedLeaf"])
        );
        let op = &v["operation"];
        let digest = operation_digest(
            &Scope {
                chain_id: n(&op["chainId"]).to(),
                protocol_address: n(&op["protocolAddress"]),
            },
            n(&op["mainCircuitCapacity"]).to(),
            &op["publicInputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(n)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(
            format!("0x{}", hex::encode(digest)),
            op["digest"].as_str().unwrap()
        );
    }
    #[test]
    fn full_witness_and_depth32_replay() {
        let v = vectors();
        for name in ["witnessK10SingleInput", "witnessK10CrossTree"] {
            let r = request(&v[name]);
            let w = build_witness(&r).unwrap();
            for k in PUBLIC_INPUTS {
                assert_eq!(w[k], v[name][k], "{name} {k}");
            }
            for k in [
                "owners",
                "nonces",
                "amounts",
                "source_indices",
                "leaf_indices",
                "tree_ids",
                "roots",
                "leaf_counts",
            ] {
                let expected: Vec<_> = v[name][k]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| n(v).to_string())
                    .collect();
                let actual: Vec<_> = w[k]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap().to_string())
                    .collect();
                assert_eq!(actual, expected);
            }
        }
        let mut t = RecognizedTree::default();
        t.append(n(&v["note"]["recognizedLeaf"])).unwrap();
        let (path, root) = t.path(0).unwrap();
        assert_eq!(
            t.membership_for_commitment(
                &request(&v["witnessK10SingleInput"]).scope,
                n(&v["note"]["commitment"])
            )
            .unwrap()
            .unwrap()
            .leaf_index,
            0
        );
        assert!(t
            .membership_for_commitment(&request(&v["witnessK10SingleInput"]).scope, U256::from(1))
            .unwrap()
            .is_none());
        assert_eq!(root, n(&v["witnessK10SingleInput"]["roots"][0]));
        assert_eq!(
            path,
            v["witnessK10SingleInput"]["paths"][0]
                .as_array()
                .unwrap()
                .iter()
                .map(n)
                .collect::<Vec<_>>()
        );
        let mut r = request(&v["witnessK10SingleInput"]);
        r.inputs[0].path[0] = U256::from(1);
        assert!(build_witness(&r).is_err());
    }
    #[test]
    fn fixed_certificate_and_strict_ed25519() {
        let v = vectors();
        let cv = &v["certificate"];
        let mut value = cv["fields"].clone();
        for (_, v) in value.as_object_mut().unwrap() {
            *v = Value::String(n(v).to_string());
        }
        value["signature"] = Value::String(format!("0x{}", cv["signatureHex"].as_str().unwrap()));
        let mut c: RootCertificate = serde_json::from_value(value).unwrap();
        let payload = root_certificate_payload(&c).unwrap();
        assert_eq!(payload.len(), 269);
        let mut empty = c.clone();
        empty.leaf_count = "0".into();
        assert_eq!(root_certificate_payload(&empty).unwrap().len(), 269);
        assert_eq!(hex::encode(payload), cv["payloadHex"].as_str().unwrap());
        assert_eq!(
            hex::encode(root_certificate_message(&c).unwrap()),
            cv["messageHex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(checkpoint_hash(&c).unwrap()),
            cv["checkpointHash"].as_str().unwrap()
        );
        let key = hex::decode(cv["publicKeySpkiHex"].as_str().unwrap()).unwrap();
        let key: [u8; 32] = key[key.len() - 32..].try_into().unwrap();
        assert!(verify_root_certificate(&c, &key).unwrap());
        c.root = "11".into();
        assert!(!verify_root_certificate(&c, &key).unwrap());
        c.signature = "0x00".into();
        assert!(verify_root_certificate(&c, &key).is_err());
    }
    #[test]
    fn canonical_and_capacity_rejections() {
        for s in ["-1", "01", "1.5", " 1", "0x"] {
            assert!(parse_integer(s, 256).is_err());
        }
        assert!(field(invisi_sdk_primitives::note::field_modulus(), "field").is_err());
        assert!(!supported_capacity(11));
        let v = vectors();
        let mut r = request(&v["witnessK10SingleInput"]);
        r.capacity = 2;
        r.inputs.push(r.inputs[0].clone());
        assert!(build_witness(&r).is_err());
    }
}
