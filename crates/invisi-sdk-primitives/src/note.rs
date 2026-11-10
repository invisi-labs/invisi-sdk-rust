//! Current deployment-scoped funds notes and canonical field hashing.
use alloy_primitives::U256;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ModelError {
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("{0} exceeded")]
    Exceeded(&'static str),
    #[error("{0} mismatch")]
    Mismatch(&'static str),
}
pub type ModelResult<T> = Result<T, ModelError>;
pub fn field_modulus() -> U256 {
    U256::from_str_radix(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    )
    .expect("fixed BN254 modulus")
}
pub fn field(value: U256, name: &'static str) -> ModelResult<()> {
    if value >= field_modulus() {
        return Err(ModelError::Invalid(name));
    }
    Ok(())
}
pub fn uint(value: U256, bits: usize, name: &'static str) -> ModelResult<()> {
    if bits > 256 {
        return Err(ModelError::Invalid(name));
    }
    if bits < 256 && value >= (U256::from(1) << bits) {
        return Err(ModelError::Invalid(name));
    }
    Ok(())
}
pub fn positive_address(value: U256, name: &'static str) -> ModelResult<()> {
    uint(value, 160, name)?;
    if value == U256::ZERO {
        return Err(ModelError::Invalid(name));
    }
    Ok(())
}
pub fn hash_fields(values: &[U256]) -> ModelResult<U256> {
    for value in values {
        field(*value, "field")?;
    }
    let fields: Vec<_> = values
        .iter()
        .map(|value| crate::field::bytes_to_field(&value.to_be_bytes::<32>()))
        .collect();
    Ok(U256::from_be_bytes(crate::field::field_to_bytes_be(
        crate::poseidon::hash(&fields),
    )))
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtocolContext {
    #[serde(with = "decimal_u64")]
    pub chain_id: u64,
    #[serde(with = "decimal")]
    pub protocol_address: U256,
}
impl ProtocolContext {
    pub fn validate(&self) -> ModelResult<()> {
        uint(self.protocol_address, 160, "protocol address")
    }
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Note {
    #[serde(flatten)]
    pub context: ProtocolContext,
    #[serde(with = "address_hex")]
    pub owner_address: U256,
    #[serde(with = "decimal")]
    pub token_address: U256,
    #[serde(with = "decimal")]
    pub amount: U256,
    #[serde(with = "decimal")]
    pub nonce: U256,
    #[serde(default, with = "bytes_hex")]
    pub payload: Vec<u8>,
}
impl Note {
    pub fn validate(&self) -> ModelResult<()> {
        self.context.validate()?;
        positive_address(self.owner_address, "owner address")?;
        uint(self.token_address, 160, "token address")?;
        uint(self.amount, 128, "note amount")?;
        if self.amount == U256::ZERO {
            return Err(ModelError::Invalid("note amount"));
        }
        field(self.nonce, "note nonce")
    }
    pub fn identity(&self) -> ModelResult<U256> {
        compute_note_identity(self.owner_address, self.nonce)
    }
    pub fn commitment(&self) -> ModelResult<U256> {
        self.validate()?;
        compute_note_commitment(
            self.context.chain_id,
            self.context.protocol_address,
            self.identity()?,
            self.token_address,
            self.amount,
        )
    }
    pub fn nullifier(&self) -> ModelResult<U256> {
        compute_note_nullifier(
            self.context.chain_id,
            self.context.protocol_address,
            self.nonce,
            self.commitment()?,
        )
    }
}
pub fn compute_note_identity(owner: U256, nonce: U256) -> ModelResult<U256> {
    positive_address(owner, "owner address")?;
    field(nonce, "note nonce")?;
    hash_fields(&[U256::from(2), owner, nonce])
}
pub fn compute_note_commitment(
    chain_id: u64,
    protocol_address: U256,
    identity: U256,
    token: U256,
    amount: U256,
) -> ModelResult<U256> {
    positive_address(protocol_address, "protocol address")?;
    field(identity, "note identity")?;
    uint(token, 160, "token address")?;
    uint(amount, 128, "note amount")?;
    if amount == U256::ZERO {
        return Err(ModelError::Invalid("note amount"));
    }
    hash_fields(&[
        U256::from(3),
        U256::from(chain_id),
        protocol_address,
        identity,
        token,
        amount,
    ])
}
pub fn compute_note_nullifier(
    chain_id: u64,
    protocol_address: U256,
    nonce: U256,
    commitment: U256,
) -> ModelResult<U256> {
    positive_address(protocol_address, "protocol address")?;
    field(nonce, "note nonce")?;
    field(commitment, "note commitment")?;
    hash_fields(&[
        U256::from(4),
        U256::from(chain_id),
        protocol_address,
        nonce,
        commitment,
    ])
}

pub mod decimal {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &U256, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<U256, D::Error> {
        let value = String::deserialize(d)?;
        if value.is_empty()
            || value.len() > 78
            || !value.bytes().all(|b| b.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(serde::de::Error::custom("noncanonical decimal integer"));
        }
        U256::from_str_radix(&value, 10).map_err(serde::de::Error::custom)
    }
}
pub mod decimal_u64 {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let n = super::decimal::deserialize(d)?;
        u64::try_from(n).map_err(serde::de::Error::custom)
    }
}
pub mod decimal_u16 {
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u16, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u16, D::Error> {
        let n = super::decimal::deserialize(d)?;
        u16::try_from(n).map_err(serde::de::Error::custom)
    }
}
pub mod address_hex {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &U256, s: S) -> Result<S::Ok, S::Error> {
        if *value >= U256::from(1) << 160 {
            return Err(serde::ser::Error::custom("address exceeds 160 bits"));
        }
        s.serialize_str(&format!(
            "0x{}",
            hex::encode(&value.to_be_bytes::<32>()[12..])
        ))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<U256, D::Error> {
        let value = String::deserialize(d)?;
        let bytes = decode_hex(&value).map_err(serde::de::Error::custom)?;
        if bytes.len() != 20 {
            return Err(serde::de::Error::custom("address must contain 20 bytes"));
        }
        Ok(U256::from_be_slice(&bytes))
    }
}
pub mod field_hex {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &U256, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(value.to_be_bytes::<32>())))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<U256, D::Error> {
        let value = String::deserialize(d)?;
        let bytes = decode_hex(&value).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("field must contain 32 bytes"));
        }
        let n = U256::from_be_slice(&bytes);
        field(n, "field").map_err(serde::de::Error::custom)?;
        Ok(n)
    }
}
pub fn decode_hex(value: &str) -> ModelResult<Vec<u8>> {
    let raw = value
        .strip_prefix("0x")
        .ok_or(ModelError::Invalid("hex encoding"))?;
    if raw.len() % 2 != 0
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ModelError::Invalid("canonical hex encoding"));
    }
    hex::decode(raw).map_err(|_| ModelError::Invalid("hex encoding"))
}
pub mod bytes_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(value)))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        super::decode_hex(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
pub mod array_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer, const N: usize>(
        value: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        super::bytes_hex::serialize(value, s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let bytes =
            super::decode_hex(&String::deserialize(d)?).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid fixed byte length"))
    }
}

/// Uniform BN254 nonce; zero is permitted by the current note format.
pub fn generate_nonce() -> U256 {
    sample_field(false)
}
/// Independent Credit shared secret, sampled without deriving it from an account key.
pub fn generate_credit_shared_key() -> U256 {
    sample_field(true)
}
fn sample_field(nonzero: bool) -> U256 {
    use rand::RngCore;
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    loop {
        rand::rngs::OsRng.fill_bytes(&mut *bytes);
        let candidate = U256::from_be_bytes(*bytes);
        if candidate < field_modulus() && (!nonzero || candidate != U256::ZERO) {
            return candidate;
        }
    }
}
