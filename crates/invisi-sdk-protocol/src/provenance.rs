//! Pure Source recognition trees, public statements, digests and certificate contracts.
use alloy_primitives::{keccak256, U256};
use invisi_sdk_primitives::note::{
    field, field_modulus, hash_fields, positive_address, uint, ModelError, ModelResult,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const PUBLIC_INPUTS: [&str; 11] = [
    "chain_id",
    "protocol_address",
    "token_address",
    "chain_generation",
    "source_count",
    "sources_digest",
    "input_count",
    "operation_digest_hi",
    "operation_digest_lo",
    "input_digest",
    "binding",
];
pub fn supported_capacity(k: usize) -> bool {
    [10, 20, 40, 80, 120, 160, 190].contains(&k)
}
pub fn parse_integer(s: &str, bits: usize) -> ModelResult<U256> {
    let (digits, base) = if let Some(v) = s.strip_prefix("0x") {
        (v, 16)
    } else {
        if s.len() > 1 && s.starts_with('0') {
            return Err(ModelError::Invalid("integer encoding"));
        }
        (s, 10)
    };
    if digits.is_empty()
        || !digits.bytes().all(|b| {
            if base == 16 {
                b.is_ascii_hexdigit()
            } else {
                b.is_ascii_digit()
            }
        })
    {
        return Err(ModelError::Invalid("integer encoding"));
    }
    let n = U256::from_str_radix(digits, base).map_err(|_| ModelError::Invalid("integer"))?;
    uint(n, bits, "integer")?;
    Ok(n)
}
fn domain(name: &str) -> U256 {
    U256::from_be_bytes::<32>(
        Sha256::digest(format!("Invisi.Provenance.{name}.v1").as_bytes()).into(),
    ) % field_modulus()
}
fn h(v: &[U256]) -> ModelResult<U256> {
    hash_fields(v)
}
pub fn limbs(n: U256) -> [U256; 2] {
    [n >> 128, n & ((U256::from(1) << 128) - U256::from(1))]
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub chain_id: u64,
    pub protocol_address: U256,
}
pub fn scope_hash(s: &Scope) -> ModelResult<U256> {
    positive_address(s.protocol_address, "protocol")?;
    h(&[domain("Scope"), U256::from(s.chain_id), s.protocol_address])
}
pub fn recognized_leaf(scope: U256, commitment: U256) -> ModelResult<U256> {
    if commitment == U256::ZERO {
        return Err(ModelError::Invalid("zero commitment"));
    }
    h(&[domain("Note"), scope, commitment])
}
#[derive(Debug, Clone)]
pub struct Opening {
    pub owner: U256,
    pub nonce: U256,
    pub amount: U256,
}
pub fn note_opening(scope: &Scope, token: U256, o: &Opening) -> ModelResult<(U256, U256)> {
    positive_address(scope.protocol_address, "protocol")?;
    positive_address(o.owner, "owner")?;
    positive_address(token, "token")?;
    uint(o.amount, 128, "amount")?;
    if o.amount == U256::ZERO {
        return Err(ModelError::Invalid("amount"));
    }
    field(o.nonce, "nonce")?;
    let id = h(&[U256::from(2), o.owner, o.nonce])?;
    let c = h(&[
        U256::from(3),
        U256::from(scope.chain_id),
        scope.protocol_address,
        id,
        token,
        o.amount,
    ])?;
    Ok((
        c,
        h(&[
            U256::from(4),
            U256::from(scope.chain_id),
            scope.protocol_address,
            o.nonce,
            c,
        ])?,
    ))
}
pub fn input_digest(ns: &[U256]) -> ModelResult<U256> {
    let mut d = h(&[domain("Inputs"), U256::from(ns.len())])?;
    for n in ns {
        d = h(&[domain("Step"), d, *n])?;
    }
    Ok(d)
}
#[derive(Debug, Clone)]
pub struct Source {
    pub tree_id: u64,
    pub root: U256,
    pub leaf_count: u64,
}
pub fn sources_digest(generation: u64, sources: &[Source]) -> ModelResult<U256> {
    let mut d = h(&[
        domain("Sources"),
        U256::from(generation),
        U256::from(sources.len()),
    ])?;
    let mut previous = 0;
    for s in sources {
        if s.tree_id <= previous || s.leaf_count == 0 || s.leaf_count > 1u64 << 32 {
            return Err(ModelError::Invalid("source ordering or count"));
        }
        previous = s.tree_id;
        d = h(&[
            domain("SourceStep"),
            d,
            U256::from(s.tree_id),
            s.root,
            U256::from(s.leaf_count),
        ])?;
    }
    Ok(d)
}
pub fn binding_digest(
    scope: U256,
    token: U256,
    generation: u64,
    source_count: usize,
    sources_digest: U256,
    input_count: usize,
    operation_digest: U256,
    input_digest: U256,
) -> ModelResult<U256> {
    positive_address(token, "token")?;
    let [hi, lo] = limbs(operation_digest);
    h(&[
        domain("Bind"),
        scope,
        token,
        U256::from(generation),
        U256::from(source_count),
        sources_digest,
        U256::from(input_count),
        hi,
        lo,
        input_digest,
    ])
}
fn abi_word(n: U256) -> [u8; 32] {
    n.to_be_bytes()
}
pub fn operation_digest(s: &Scope, capacity: usize, public: &[U256]) -> ModelResult<[u8; 32]> {
    positive_address(s.protocol_address, "protocol")?;
    if capacity == 0 || capacity > 190 || public.len() != 17 + 3 * capacity {
        return Err(ModelError::Invalid("authenticated transact statement"));
    }
    for n in public {
        field(*n, "public input")?;
    }
    let text = b"Invisi.Provenance.Operation.v1";
    let mut encoded = Vec::new();
    for n in [
        U256::from(192),
        U256::from(s.chain_id),
        s.protocol_address,
        U256::from(2),
        U256::from(capacity),
        U256::from(256),
    ] {
        encoded.extend(abi_word(n));
    }
    encoded.extend(abi_word(U256::from(text.len())));
    encoded.extend(text);
    encoded.resize(256, 0);
    encoded.extend(abi_word(U256::from(public.len())));
    for n in public {
        encoded.extend(abi_word(*n));
    }
    Ok(keccak256(encoded).0)
}
pub fn provenance_intent_hash(original: [u8; 32]) -> [u8; 32] {
    let text = b"InvisiBroadcasterProvenanceIntentV1";
    let mut e = Vec::new();
    e.extend(abi_word(U256::from(64)));
    e.extend(original);
    e.extend(abi_word(U256::from(text.len())));
    e.extend(text);
    e.resize(160, 0);
    keccak256(e).0
}
const CERT_LAYOUT: [(&str, usize); 15] = [
    ("certificateVersion", 1),
    ("providerId", 32),
    ("signingKeyId", 32),
    ("chainId", 8),
    ("protocolAddress", 20),
    ("chainGeneration", 8),
    ("rootSequence", 8),
    ("treeId", 8),
    ("leafCount", 8),
    ("root", 32),
    ("confirmedBlockNumber", 8),
    ("confirmedBlockHash", 32),
    ("decisionLogHash", 32),
    ("previousCheckpointHash", 32),
    ("issuedAt", 8),
];
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RootCertificate {
    pub certificate_version: String,
    pub provider_id: String,
    pub signing_key_id: String,
    pub chain_id: String,
    pub protocol_address: String,
    pub chain_generation: String,
    pub root_sequence: String,
    pub tree_id: String,
    pub leaf_count: String,
    pub root: String,
    pub confirmed_block_number: String,
    pub confirmed_block_hash: String,
    pub decision_log_hash: String,
    pub previous_checkpoint_hash: String,
    pub issued_at: String,
    pub signature: String,
}
pub fn root_certificate_payload(c: &RootCertificate) -> ModelResult<Vec<u8>> {
    let value = serde_json::to_value(c).map_err(|_| ModelError::Invalid("certificate"))?;
    let mut out = Vec::new();
    for (name, width) in CERT_LAYOUT {
        let n = parse_integer(
            value[name]
                .as_str()
                .ok_or(ModelError::Invalid("certificate field"))?,
            width * 8,
        )?;
        match name {
            "certificateVersion" if n != U256::from(1) => {
                return Err(ModelError::Invalid("certificate version"))
            }
            "root" => field(n, "root")?,
            "treeId" if n == U256::ZERO => return Err(ModelError::Invalid("tree id")),
            "leafCount" if n > U256::from(1u64 << 32) => {
                return Err(ModelError::Invalid("leaf count"))
            }
            _ => {}
        }
        out.extend(&n.to_be_bytes::<32>()[32 - width..]);
    }
    Ok(out)
}
pub fn checkpoint_hash(c: &RootCertificate) -> ModelResult<[u8; 32]> {
    Ok(Sha256::digest(root_certificate_payload(c)?).into())
}
pub fn root_certificate_message(c: &RootCertificate) -> ModelResult<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(b"Invisi.Provenance.Root.v1");
    hash.update(root_certificate_payload(c)?);
    Ok(hash.finalize().into())
}
pub fn verify_root_certificate(c: &RootCertificate, key: &[u8; 32]) -> ModelResult<bool> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let raw = c
        .signature
        .strip_prefix("0x")
        .ok_or(ModelError::Invalid("signature encoding"))?;
    if raw.len() != 128 {
        return Err(ModelError::Invalid("signature length"));
    }
    let bytes = hex::decode(raw).map_err(|_| ModelError::Invalid("signature encoding"))?;
    let sig = Signature::from_slice(&bytes).map_err(|_| ModelError::Invalid("signature"))?;
    let key = VerifyingKey::from_bytes(key).map_err(|_| ModelError::Invalid("public key"))?;
    Ok(key
        .verify_strict(&root_certificate_message(c)?, &sig)
        .is_ok())
}
#[derive(Default)]
pub struct RecognizedTree {
    leaves: Vec<U256>,
}
impl RecognizedTree {
    pub fn leaf_count(&self) -> u64 {
        self.leaves.len() as u64
    }
    pub fn append(&mut self, leaf: U256) -> ModelResult<u32> {
        field(leaf, "leaf")?;
        if leaf == U256::ZERO || self.leaves.len() as u64 >= 1u64 << 32 {
            return Err(ModelError::Invalid("leaf or tree capacity"));
        }
        self.leaves.push(leaf);
        Ok((self.leaves.len() - 1) as u32)
    }
    pub fn path(&self, index: u32) -> ModelResult<(Vec<U256>, U256)> {
        if index as usize >= self.leaves.len() {
            return Err(ModelError::Invalid("leaf index"));
        }
        let mut nodes: BTreeMap<u64, U256> = self
            .leaves
            .iter()
            .enumerate()
            .map(|(i, v)| (i as u64, *v))
            .collect();
        let mut zero = U256::ZERO;
        let mut cursor = index as u64;
        let mut path = Vec::new();
        for _ in 0..32 {
            path.push(*nodes.get(&(cursor ^ 1)).unwrap_or(&zero));
            let mut next = BTreeMap::new();
            for i in nodes.keys() {
                let p = i / 2;
                if !next.contains_key(&p) {
                    next.insert(
                        p,
                        h(&[
                            *nodes.get(&(p * 2)).unwrap_or(&zero),
                            *nodes.get(&(p * 2 + 1)).unwrap_or(&zero),
                        ])?,
                    );
                }
            }
            zero = h(&[zero, zero])?;
            nodes = next;
            cursor /= 2;
        }
        Ok((path, *nodes.get(&0).unwrap_or(&zero)))
    }
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofBundle {
    pub format: String,
    pub circuit_id: String,
    pub manifest_sha256: String,
    pub target: String,
    pub public_inputs: Vec<String>,
    pub proof: String,
    pub root_certificates: Vec<RootCertificate>,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofSidecar {
    pub operation_index: String,
    pub proof_bundle: ProofBundle,
}
#[derive(Debug, Clone)]
pub struct TrustContext {
    pub scope: Scope,
    pub chain_generation: u64,
    pub provider_id: U256,
    pub signing_keys: BTreeMap<U256, [u8; 32]>,
    pub signing_key_validity: BTreeMap<U256, KeyValidity>,
    pub manifest_sha256: String,
}
pub fn assert_certificate_trust(c: &RootCertificate, t: &TrustContext) -> ModelResult<()> {
    for (raw, expected) in [
        (&c.chain_id, U256::from(t.scope.chain_id)),
        (&c.protocol_address, t.scope.protocol_address),
        (&c.chain_generation, U256::from(t.chain_generation)),
        (&c.provider_id, t.provider_id),
    ] {
        if parse_integer(raw, 256)? != expected {
            return Err(ModelError::Mismatch("certificate deployment"));
        }
    }
    let id = parse_integer(&c.signing_key_id, 256)?;
    if let Some(interval) = t.signing_key_validity.get(&id) {
        let issued = parse_integer(&c.issued_at, 64)?.to::<u64>();
        if issued < interval.activated_at
            || interval
                .retired_at
                .map(|end| issued >= end)
                .unwrap_or(false)
        {
            return Err(ModelError::Invalid("certificate key validity interval"));
        }
    }
    let key = t
        .signing_keys
        .get(&id)
        .ok_or(ModelError::Invalid("untrusted signing key"))?;
    if !verify_root_certificate(c, key)? {
        return Err(ModelError::Invalid("certificate signature"));
    }
    Ok(())
}
pub fn validate_proof_bundle(b: &ProofBundle, t: &TrustContext) -> ModelResult<()> {
    if b.format != "invisi-provenance-proof-v1"
        || b.target != "evm"
        || b.manifest_sha256 != t.manifest_sha256
    {
        return Err(ModelError::Invalid("proof identity"));
    }
    let proof = hex::decode(
        b.proof
            .strip_prefix("0x")
            .ok_or(ModelError::Invalid("proof encoding"))?,
    )
    .map_err(|_| ModelError::Invalid("proof encoding"))?;
    if proof.is_empty() || proof.len() > 65536 {
        return Err(ModelError::Invalid("proof size"));
    }
    let capacity = b
        .circuit_id
        .strip_prefix("provenance_k")
        .ok_or(ModelError::Invalid("circuit id"))?
        .parse::<usize>()
        .map_err(|_| ModelError::Invalid("capacity"))?;
    if !supported_capacity(capacity)
        || b.circuit_id != format!("provenance_k{capacity}")
        || b.public_inputs.len() != 11
    {
        return Err(ModelError::Invalid("circuit ABI"));
    }
    let p: Vec<U256> = b
        .public_inputs
        .iter()
        .map(|v| {
            if v.len() != 66 || !v.starts_with("0x") {
                return Err(ModelError::Invalid("public input encoding"));
            }
            let n = parse_integer(v, 256)?;
            field(n, "public input")?;
            Ok(n)
        })
        .collect::<ModelResult<_>>()?;
    if p[0] != U256::from(t.scope.chain_id)
        || p[1] != t.scope.protocol_address
        || p[3] != U256::from(t.chain_generation)
        || p[4] != U256::from(b.root_certificates.len())
        || p[6] == U256::ZERO
        || p[6] > U256::from(capacity)
        || p[4] == U256::ZERO
        || p[4] > p[6]
    {
        return Err(ModelError::Mismatch("proof scope or shape"));
    }
    uint(p[7], 128, "operation digest high")?;
    uint(p[8], 128, "operation digest low")?;
    let sources: Vec<Source> = b
        .root_certificates
        .iter()
        .map(|c| {
            assert_certificate_trust(c, t)?;
            Ok(Source {
                tree_id: parse_integer(&c.tree_id, 64)?.to(),
                root: parse_integer(&c.root, 256)?,
                leaf_count: parse_integer(&c.leaf_count, 64)?.to(),
            })
        })
        .collect::<ModelResult<_>>()?;
    let sd = sources_digest(t.chain_generation, &sources)?;
    if sd != p[5] {
        return Err(ModelError::Mismatch("proof sources digest"));
    }
    let binding = binding_digest(
        scope_hash(&t.scope)?,
        p[2],
        t.chain_generation,
        sources.len(),
        sd,
        p[6].to(),
        (p[7] << 128) | p[8],
        p[9],
    )?;
    if binding != p[10] {
        return Err(ModelError::Mismatch("proof binding"));
    }
    Ok(())
}
pub fn assert_public_submission(v: &serde_json::Value) -> ModelResult<()> {
    match v {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if [
                    "opening",
                    "openings",
                    "nonce",
                    "nonces",
                    "privatekey",
                    "private_key",
                    "ipn",
                    "witness",
                    "owners",
                    "amounts",
                    "paths",
                    "artifacturl",
                    "vkurl",
                    "verificationkey",
                ]
                .contains(&k.to_ascii_lowercase().as_str())
                {
                    return Err(ModelError::Invalid("private material in public submission"));
                }
                assert_public_submission(v)?;
            }
        }
        serde_json::Value::Array(items) => {
            for v in items {
                assert_public_submission(v)?;
            }
        }
        _ => {}
    }
    Ok(())
}
pub fn certificate_to_wire(c: &RootCertificate) -> ModelResult<RootCertificate> {
    root_certificate_payload(c)?;
    let mut value = serde_json::to_value(c).map_err(|_| ModelError::Invalid("certificate"))?;
    for (name, width) in CERT_LAYOUT {
        let n = parse_integer(
            value[name]
                .as_str()
                .ok_or(ModelError::Invalid("certificate field"))?,
            width * 8,
        )?;
        value[name] = serde_json::Value::String(if width == 32 || name == "protocolAddress" {
            format!("0x{}", hex::encode(&n.to_be_bytes::<32>()[32 - width..]))
        } else {
            n.to_string()
        });
    }
    serde_json::from_value(value).map_err(|_| ModelError::Invalid("certificate"))
}

impl RecognizedTree {
    pub fn root(&self) -> ModelResult<U256> {
        if self.leaf_count() > 0 {
            return Ok(self.path(0)?.1);
        }
        let mut zero = U256::ZERO;
        for _ in 0..32 {
            zero = h(&[zero, zero])?;
        }
        Ok(zero)
    }
}

pub use crate::provenance_rotation::{
    rotation_hash, rotation_message, rotation_payload, verify_rotation_chain, KeyValidity,
    RotationCheckpoint, RotationRecord, TrustedKeyring,
};

pub fn proof_bundle_to_wire(bundle: &ProofBundle) -> ModelResult<ProofBundle> {
    let mut result = bundle.clone();
    result.root_certificates = bundle
        .root_certificates
        .iter()
        .map(certificate_to_wire)
        .collect::<ModelResult<_>>()?;
    result.public_inputs = bundle
        .public_inputs
        .iter()
        .map(|v| {
            let n = parse_integer(v, 256)?;
            field(n, "public input")?;
            Ok(format!("0x{}", hex::encode(n.to_be_bytes::<32>())))
        })
        .collect::<ModelResult<_>>()?;
    Ok(result)
}
pub fn proof_sidecar_to_wire(sidecar: &ProofSidecar) -> ModelResult<ProofSidecar> {
    Ok(ProofSidecar {
        operation_index: parse_integer(&sidecar.operation_index, 32)?.to_string(),
        proof_bundle: proof_bundle_to_wire(&sidecar.proof_bundle)?,
    })
}

#[derive(Debug, Clone)]
pub struct Membership {
    pub leaf_index: u32,
    pub path: Vec<U256>,
    pub root: U256,
}
impl RecognizedTree {
    pub fn membership_for_commitment(
        &self,
        scope: &Scope,
        commitment: U256,
    ) -> ModelResult<Option<Membership>> {
        let expected = recognized_leaf(scope_hash(scope)?, commitment)?;
        if let Some(index) = self.leaves.iter().position(|value| *value == expected) {
            let (path, root) = self.path(index as u32)?;
            return Ok(Some(Membership {
                leaf_index: index as u32,
                path,
                root,
            }));
        }
        Ok(None)
    }
}

/// A public recovery packet contains no Note plaintext, private witness or local proving capability.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProvenanceProof {
    pub format: String,
    pub data: String,
    pub context: ProofContext,
    pub main_circuit_capacity: usize,
    pub public_inputs: Vec<String>,
    pub operation_digest: String,
    pub sidecars: Vec<ProofSidecar>,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofContext {
    pub chain_id: String,
    pub protocol_address: String,
    pub token_address: String,
}
