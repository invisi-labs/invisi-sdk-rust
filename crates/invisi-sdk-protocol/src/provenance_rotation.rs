//! Authenticated signing-key rotation and historical validity intervals.
use crate::provenance::{parse_integer, TrustContext};
use alloy_primitives::U256;
use invisi_sdk_primitives::note::{ModelError, ModelResult};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RotationRecord {
    pub version: String,
    pub provider_id: String,
    pub old_key_id: String,
    pub new_key_id: String,
    pub new_public_key: String,
    pub activated_at: String,
    pub previous_rotation_hash: String,
    pub signature: String,
}
#[derive(Debug, Clone)]
pub struct KeyValidity {
    pub activated_at: u64,
    pub retired_at: Option<u64>,
}
#[derive(Debug, Clone)]
pub struct RotationCheckpoint {
    pub provider_id: U256,
    pub keys: BTreeMap<U256, [u8; 32]>,
    pub validity: BTreeMap<U256, KeyValidity>,
    pub previous_rotation_hash: [u8; 32],
    pub last_activated_at: u64,
    pub now: u64,
}
#[derive(Debug, Clone)]
pub struct TrustedKeyring {
    pub provider_id: U256,
    pub keys: BTreeMap<U256, [u8; 32]>,
    pub validity: BTreeMap<U256, KeyValidity>,
    pub rotation_hash: [u8; 32],
    pub last_activated_at: u64,
}
fn fixed(v: &str, size: usize) -> ModelResult<Vec<u8>> {
    if v.len() != 2 + size * 2 {
        return Err(ModelError::Invalid("rotation hex width"));
    }
    hex::decode(
        v.strip_prefix("0x")
            .ok_or(ModelError::Invalid("rotation hex"))?,
    )
    .map_err(|_| ModelError::Invalid("rotation hex"))
}
fn at(v: &str) -> ModelResult<u64> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) || (v.len() > 1 && v.starts_with('0'))
    {
        return Err(ModelError::Invalid("rotation decimal time"));
    }
    Ok(parse_integer(v, 64)?.to())
}
pub fn rotation_payload(r: &RotationRecord) -> ModelResult<Vec<u8>> {
    if r.version != "1" {
        return Err(ModelError::Invalid("rotation version"));
    }
    let provider = fixed(&r.provider_id, 32)?;
    let old = fixed(&r.old_key_id, 32)?;
    let new = fixed(&r.new_key_id, 32)?;
    let public = fixed(&r.new_public_key, 32)?;
    if Sha256::digest(&public).as_slice() != new.as_slice() {
        return Err(ModelError::Mismatch("rotation key ID"));
    }
    let mut payload = vec![1];
    payload.extend(provider);
    payload.extend(old);
    payload.extend(new);
    payload.extend(public);
    payload.extend(at(&r.activated_at)?.to_be_bytes());
    payload.extend(fixed(&r.previous_rotation_hash, 32)?);
    Ok(payload)
}
pub fn rotation_message(r: &RotationRecord) -> ModelResult<[u8; 32]> {
    let mut h = Sha256::new();
    h.update(b"Invisi.Provenance.KeyRotation.v1");
    h.update(rotation_payload(r)?);
    Ok(h.finalize().into())
}
pub fn rotation_hash(r: &RotationRecord) -> ModelResult<[u8; 32]> {
    Ok(Sha256::digest(rotation_payload(r)?).into())
}
pub fn verify_rotation_chain(
    initial: RotationCheckpoint,
    records: &[RotationRecord],
) -> ModelResult<TrustedKeyring> {
    use ed25519_dalek::{Signature, VerifyingKey};
    if initial.last_activated_at > initial.now {
        return Err(ModelError::Invalid("rotation checkpoint time"));
    }
    let mut ring = TrustedKeyring {
        provider_id: initial.provider_id,
        keys: initial.keys,
        validity: initial.validity,
        rotation_hash: initial.previous_rotation_hash,
        last_activated_at: initial.last_activated_at,
    };
    for id in ring.keys.keys() {
        ring.validity.entry(*id).or_insert(KeyValidity {
            activated_at: 0,
            retired_at: None,
        });
    }
    for r in records {
        let message = rotation_message(r)?;
        let provider = parse_integer(&r.provider_id, 256)?;
        let old = parse_integer(&r.old_key_id, 256)?;
        let new = parse_integer(&r.new_key_id, 256)?;
        let time = at(&r.activated_at)?;
        let previous = fixed(&r.previous_rotation_hash, 32)?;
        let key = ring
            .keys
            .get(&old)
            .ok_or(ModelError::Invalid("untrusted rotation key"))?;
        let interval = ring
            .validity
            .get(&old)
            .ok_or(ModelError::Invalid("missing key interval"))?;
        if provider != ring.provider_id
            || previous.as_slice() != ring.rotation_hash
            || time <= ring.last_activated_at
            || time > initial.now
            || interval.retired_at.is_some()
            || time < interval.activated_at
            || ring.keys.contains_key(&new)
        {
            return Err(ModelError::Invalid("out-of-order rotation"));
        }
        let signature = Signature::from_slice(&fixed(&r.signature, 64)?)
            .map_err(|_| ModelError::Invalid("rotation signature"))?;
        let key = VerifyingKey::from_bytes(key)
            .map_err(|_| ModelError::Invalid("rotation public key"))?;
        key.verify_strict(&message, &signature)
            .map_err(|_| ModelError::Invalid("rotation signature"))?;
        ring.validity.get_mut(&old).unwrap().retired_at = Some(time);
        ring.keys.insert(
            new,
            fixed(&r.new_public_key, 32)?
                .try_into()
                .map_err(|_| ModelError::Invalid("public key width"))?,
        );
        ring.validity.insert(
            new,
            KeyValidity {
                activated_at: time,
                retired_at: None,
            },
        );
        ring.rotation_hash = rotation_hash(r)?;
        ring.last_activated_at = time;
    }
    Ok(ring)
}
impl TrustContext {
    pub fn with_rotation_history(mut self, ring: TrustedKeyring) -> ModelResult<Self> {
        if ring.provider_id != self.provider_id {
            return Err(ModelError::Mismatch("rotation provider"));
        }
        self.signing_keys = ring.keys;
        self.signing_key_validity = ring.validity;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::{
        assert_certificate_trust, root_certificate_message, RootCertificate, Scope,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::Value;
    fn raw(v: &str) -> [u8; 32] {
        fixed(v, 32).unwrap().try_into().unwrap()
    }
    #[test]
    fn shared_rotation_vector_and_historical_certificate_intervals() {
        let v: Value =
            serde_json::from_str(include_str!("provenance-testdata/rotation-vectors.json"))
                .unwrap();
        let r: RotationRecord = serde_json::from_value(v["rotation"].clone()).unwrap();
        assert_eq!(rotation_payload(&r).unwrap().len(), 169);
        assert_eq!(
            format!("0x{}", hex::encode(rotation_payload(&r).unwrap())),
            v["payload"].as_str().unwrap()
        );
        assert_eq!(
            format!("0x{}", hex::encode(rotation_message(&r).unwrap())),
            v["message"].as_str().unwrap()
        );
        assert_eq!(
            format!("0x{}", hex::encode(rotation_hash(&r).unwrap())),
            v["hash"].as_str().unwrap()
        );
        let old = parse_integer(&r.old_key_id, 256).unwrap();
        let new = parse_integer(&r.new_key_id, 256).unwrap();
        let initial = RotationCheckpoint {
            provider_id: parse_integer(&r.provider_id, 256).unwrap(),
            keys: BTreeMap::from([(old, raw(v["initialPublicKey"].as_str().unwrap()))]),
            validity: BTreeMap::new(),
            previous_rotation_hash: raw(&r.previous_rotation_hash),
            last_activated_at: 0,
            now: 300,
        };
        let ring = verify_rotation_chain(initial.clone(), &[r.clone()]).unwrap();
        assert_eq!(ring.keys[&new], raw(&r.new_public_key));
        assert_eq!(ring.validity[&old].retired_at, Some(200));
        let mut bad = initial.clone();
        bad.keys.clear();
        assert!(verify_rotation_chain(bad, &[r.clone()]).is_err());
        bad = initial.clone();
        bad.now = 199;
        assert!(verify_rotation_chain(bad, &[r.clone()]).is_err());
        assert!(verify_rotation_chain(initial.clone(), &[r.clone(), r.clone()]).is_err());
        let mut changed = r.clone();
        changed.new_key_id = r.old_key_id.clone();
        assert!(verify_rotation_chain(initial.clone(), &[changed]).is_err());
        changed = r.clone();
        changed.signature = format!("0x{}", hex::encode([0u8; 64]));
        assert!(verify_rotation_chain(initial.clone(), &[changed]).is_err());
        changed = r.clone();
        changed.previous_rotation_hash = format!("0x{}", hex::encode([1u8; 32]));
        assert!(verify_rotation_chain(initial, &[changed]).is_err());
        let notes: Value =
            serde_json::from_str(include_str!("provenance-testdata/golden-vectors.json")).unwrap();
        let mut fields = notes["certificate"]["fields"].clone();
        for (_, v) in fields.as_object_mut().unwrap() {
            *v = Value::String(v.to_string());
        }
        fields["providerId"] = Value::String(r.provider_id.clone());
        fields["signingKeyId"] = Value::String(r.old_key_id.clone());
        fields["issuedAt"] = Value::String("199".into());
        fields["signature"] = Value::String("0x".into());
        let mut cert: RootCertificate = serde_json::from_value(fields).unwrap();
        let trust = TrustContext {
            scope: Scope {
                chain_id: 4,
                protocol_address: U256::from(5),
            },
            chain_generation: 6,
            provider_id: parse_integer(&r.provider_id, 256).unwrap(),
            signing_keys: BTreeMap::new(),
            signing_key_validity: BTreeMap::new(),
            manifest_sha256: "a".repeat(64),
        }
        .with_rotation_history(ring)
        .unwrap();
        let sign = |mut c: RootCertificate, seed: &str| {
            let key = SigningKey::from_bytes(&raw(seed));
            c.signature = format!(
                "0x{}",
                hex::encode(key.sign(&root_certificate_message(&c).unwrap()).to_bytes())
            );
            c
        };
        assert_certificate_trust(&sign(cert.clone(), v["oldSeed"].as_str().unwrap()), &trust)
            .unwrap();
        cert.issued_at = "200".into();
        assert!(assert_certificate_trust(
            &sign(cert.clone(), v["oldSeed"].as_str().unwrap()),
            &trust
        )
        .is_err());
        cert.signing_key_id = r.new_key_id;
        assert_certificate_trust(&sign(cert.clone(), v["newSeed"].as_str().unwrap()), &trust)
            .unwrap();
        cert.issued_at = "199".into();
        assert!(
            assert_certificate_trust(&sign(cert, v["newSeed"].as_str().unwrap()), &trust).is_err()
        );
    }
    #[test]
    fn strict_provenance_zero_semantics() {
        use crate::provenance::{note_opening, recognized_leaf, Opening};
        assert!(recognized_leaf(U256::from(1), U256::ZERO).is_err());
        let s = Scope {
            chain_id: 1,
            protocol_address: U256::from(1),
        };
        assert!(note_opening(
            &s,
            U256::ZERO,
            &Opening {
                owner: U256::from(1),
                nonce: U256::from(1),
                amount: U256::from(1)
            }
        )
        .is_err());
    }
}
