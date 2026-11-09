//! Offline receiving addresses with the protocol's case-checksummed Base32 encoding.
use crate::note::{positive_address, ModelError, ModelResult};
use alloy_primitives::{keccak256, U256};
const ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceivingKeys {
    #[serde(with = "crate::note::array_hex")]
    pub viewing_public_key: [u8; 33],
    #[serde(with = "crate::note::array_hex")]
    pub clue_key: [u8; 32],
}
impl ReceivingKeys {
    pub fn validate(&self) -> ModelResult<()> {
        if ![2, 3].contains(&self.viewing_public_key[0])
            || k256::PublicKey::from_sec1_bytes(&self.viewing_public_key).is_err()
        {
            return Err(ModelError::Invalid("viewing public key"));
        }
        if self.clue_key == [0u8; 32] || decaf377_fmd::ClueKey(self.clue_key).expand().is_err() {
            return Err(ModelError::Invalid("clue key"));
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceivingAddress {
    #[serde(with = "crate::note::address_hex")]
    pub owner_address: U256,
    pub keys: Option<ReceivingKeys>,
}
impl ReceivingAddress {
    pub fn from_identity(owner_address: U256) -> ModelResult<Self> {
        positive_address(owner_address, "owner address")?;
        Ok(Self {
            owner_address,
            keys: None,
        })
    }
    pub fn from_keys(owner_address: U256, keys: ReceivingKeys) -> ModelResult<Self> {
        positive_address(owner_address, "owner address")?;
        keys.validate()?;
        Ok(Self {
            owner_address,
            keys: Some(keys),
        })
    }
    pub fn encode(&self) -> ModelResult<String> {
        positive_address(self.owner_address, "owner address")?;
        let Some(keys) = &self.keys else {
            return Ok(evm_checksum(self.owner_address));
        };
        keys.validate()?;
        let mut payload = self.owner_address.to_be_bytes::<32>()[12..].to_vec();
        payload.extend_from_slice(&keys.viewing_public_key);
        payload.extend_from_slice(&keys.clue_key);
        let mut buffer = 0u32;
        let mut bits = 0;
        let mut data = String::new();
        for byte in payload {
            buffer = (buffer << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                data.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
            }
            buffer &= (1 << bits) - 1;
        }
        if bits > 0 {
            data.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
        }
        Ok(checked_text(&data))
    }
    pub fn parse(text: &str) -> ModelResult<Self> {
        if let Some(raw) = text.strip_prefix("0x") {
            if raw.len() != 40 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ModelError::Invalid("owner address encoding"));
            }
            let owner =
                U256::from_str_radix(raw, 16).map_err(|_| ModelError::Invalid("owner address"))?;
            if raw.bytes().any(|b| b.is_ascii_lowercase())
                && raw.bytes().any(|b| b.is_ascii_uppercase())
                && evm_checksum(owner) != text
            {
                return Err(ModelError::Invalid("owner address checksum"));
            }
            return Self::from_identity(owner);
        }
        if !text.starts_with("0i") || text.len() != 138 || !text.is_ascii() {
            return Err(ModelError::Invalid("receiving address encoding"));
        }
        let data = text[2..].to_ascii_lowercase();
        if checked_text(&data) != text {
            return Err(ModelError::Invalid("receiving address checksum"));
        }
        let mut buffer = 0u32;
        let mut bits = 0;
        let mut payload = vec![];
        for byte in data.bytes() {
            let value = ALPHABET
                .iter()
                .position(|b| *b == byte)
                .ok_or(ModelError::Invalid("receiving address alphabet"))?
                as u32;
            buffer = (buffer << 5) | value;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                payload.push(((buffer >> bits) & 255) as u8);
            }
            buffer &= (1 << bits) - 1;
        }
        if bits != 0 || buffer != 0 || payload.len() != 85 {
            return Err(ModelError::Invalid("receiving address padding"));
        }
        Self::from_keys(
            U256::from_be_slice(&payload[..20]),
            ReceivingKeys {
                viewing_public_key: payload[20..53].try_into().expect("fixed public key"),
                clue_key: payload[53..].try_into().expect("fixed clue key"),
            },
        )
    }
    pub fn resolve(
        &self,
        lookup: impl FnOnce(U256) -> ModelResult<Option<ReceivingKeys>>,
    ) -> ModelResult<Self> {
        if self.keys.is_some() {
            return Ok(self.clone());
        }
        Self::from_keys(
            self.owner_address,
            lookup(self.owner_address)?.ok_or(ModelError::Invalid("unregistered owner address"))?,
        )
    }
}
fn checked_text(data: &str) -> String {
    let digest = keccak256(format!("Invisi.AddressCaseChecksum.v1:0i{data}").as_bytes());
    let mut result = String::from("0i");
    for (i, byte) in data.bytes().enumerate() {
        result.push(if (digest[i >> 3] >> (7 - (i & 7))) & 1 == 1 {
            byte.to_ascii_uppercase()
        } else {
            byte
        } as char);
    }
    result
}
fn evm_checksum(owner: U256) -> String {
    let data = hex::encode(&owner.to_be_bytes::<32>()[12..]);
    let digest = keccak256(data.as_bytes());
    let mut out = String::from("0x");
    for (i, byte) in data.bytes().enumerate() {
        let nibble = if i % 2 == 0 {
            digest[i / 2] >> 4
        } else {
            digest[i / 2] & 15
        };
        out.push(if nibble >= 8 {
            byte.to_ascii_uppercase()
        } else {
            byte
        } as char);
    }
    out
}
