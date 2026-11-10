//! Canonical offline `ipr:` requests. Registry choices and payer nonces remain local overrides.
use crate::{
    address::{ReceivingAddress, ReceivingKeys},
    note::{self, ModelError, ModelResult},
};
use alloy_primitives::U256;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
pub const MAX_REQUEST_PAYLOAD_BYTES: usize = 3936;
const MAX_BINARY_BYTES: usize = 186 + MAX_REQUEST_PAYLOAD_BYTES;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AddressLookup {
    Chain,
    ProtocolRpc,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum NoteOutputRecipient {
    Evm {
        address: String,
        #[serde(default = "enabled")]
        envelope: bool,
        #[serde(
            default,
            with = "optional_decimal",
            skip_serializing_if = "Option::is_none"
        )]
        nonce: Option<U256>,
        #[serde(
            default,
            rename = "addressLookup",
            skip_serializing_if = "Option::is_none"
        )]
        address_lookup: Option<AddressLookup>,
    },
    Invisi {
        address: String,
        #[serde(
            default,
            with = "optional_decimal",
            skip_serializing_if = "Option::is_none"
        )]
        nonce: Option<U256>,
    },
    Identity {
        #[serde(with = "note::field_hex")]
        identity: U256,
    },
}
fn enabled() -> bool {
    true
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PaymentRequest {
    #[serde(with = "note::decimal_u64")]
    pub chain_id: u64,
    #[serde(with = "note::address_hex")]
    pub protocol_address: U256,
    #[serde(with = "note::address_hex")]
    pub token_address: U256,
    #[serde(with = "note::decimal")]
    pub amount: U256,
    pub recipient: NoteOutputRecipient,
    #[serde(
        default,
        with = "optional_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub payload: Option<Vec<u8>>,
}
impl PaymentRequest {
    pub fn validate(&self) -> ModelResult<()> {
        if self.chain_id == 0 {
            return Err(ModelError::Invalid("payment chain id"));
        }
        note::positive_address(self.protocol_address, "protocol address")?;
        note::uint(self.token_address, 160, "token address")?;
        note::uint(self.amount, 128, "payment amount")?;
        if self.amount == U256::ZERO {
            return Err(ModelError::Invalid("payment amount"));
        }
        let encrypted = match &self.recipient {
            NoteOutputRecipient::Identity { identity } => {
                note::field(*identity, "recipient identity")?;
                if *identity == U256::ZERO {
                    return Err(ModelError::Invalid("recipient identity"));
                }
                false
            }
            NoteOutputRecipient::Evm {
                address,
                envelope,
                nonce,
                ..
            } => {
                let parsed = ReceivingAddress::parse(address)?;
                if parsed.keys.is_some() {
                    return Err(ModelError::Invalid("EVM recipient address type"));
                }
                if let Some(nonce) = nonce {
                    note::field(*nonce, "recipient nonce")?;
                }
                *envelope
            }
            NoteOutputRecipient::Invisi { address, nonce } => {
                let parsed = ReceivingAddress::parse(address)?;
                if parsed.keys.is_none() {
                    return Err(ModelError::Invalid("Invisi recipient address type"));
                }
                if let Some(nonce) = nonce {
                    note::field(*nonce, "recipient nonce")?;
                }
                true
            }
        };
        if !encrypted && self.payload.is_some() {
            return Err(ModelError::Invalid("unencrypted payment payload"));
        }
        if self
            .payload
            .as_ref()
            .is_some_and(|p| p.len() > MAX_REQUEST_PAYLOAD_BYTES)
        {
            return Err(ModelError::Exceeded("payment payload"));
        }
        Ok(())
    }
}
fn push(bytes: &mut Vec<u8>, value: U256, size: usize) {
    bytes.extend_from_slice(&value.to_be_bytes::<32>()[32 - size..]);
}
pub fn encode_payment_request(request: &PaymentRequest) -> ModelResult<String> {
    request.validate()?;
    let kind = match request.recipient {
        NoteOutputRecipient::Evm { .. } => 1,
        NoteOutputRecipient::Invisi { .. } => 2,
        NoteOutputRecipient::Identity { .. } => 3,
    };
    let mut bytes = vec![1, kind];
    bytes.extend_from_slice(&request.chain_id.to_be_bytes());
    push(&mut bytes, request.protocol_address, 20);
    push(&mut bytes, request.token_address, 20);
    push(&mut bytes, request.amount, 16);
    match &request.recipient {
        NoteOutputRecipient::Identity { identity } => push(&mut bytes, *identity, 32),
        NoteOutputRecipient::Evm { address, nonce, .. }
        | NoteOutputRecipient::Invisi { address, nonce } => {
            let address = ReceivingAddress::parse(address)?;
            push(&mut bytes, address.owner_address, 20);
            let encrypted = if let Some(keys) = address.keys {
                bytes.extend_from_slice(&keys.viewing_public_key);
                bytes.extend_from_slice(&keys.clue_key);
                true
            } else {
                let NoteOutputRecipient::Evm { envelope, .. } = &request.recipient else {
                    return Err(ModelError::Invalid("recipient type"));
                };
                bytes.push(u8::from(*envelope));
                *envelope
            };
            bytes.push(u8::from(nonce.is_some()));
            if let Some(nonce) = nonce {
                push(&mut bytes, *nonce, 32);
            }
            if encrypted {
                let payload = request.payload.as_deref().unwrap_or_default();
                bytes.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                bytes.extend_from_slice(payload);
            }
        }
    }
    Ok(format!("ipr:{}", URL_SAFE_NO_PAD.encode(bytes)))
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> ModelResult<&'a [u8]> {
        let end = self
            .offset
            .checked_add(size)
            .ok_or(ModelError::Invalid("payment length"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(ModelError::Invalid("truncated payment request"))?;
        self.offset = end;
        Ok(bytes)
    }
    fn integer(&mut self, size: usize) -> ModelResult<U256> {
        Ok(U256::from_be_slice(self.take(size)?))
    }
    fn flag(&mut self) -> ModelResult<bool> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ModelError::Invalid("payment flag")),
        }
    }
}
pub fn decode_payment_request(encoded: &str) -> ModelResult<PaymentRequest> {
    if encoded.len() > 4 + (MAX_BINARY_BYTES * 8).div_ceil(6) {
        return Err(ModelError::Exceeded("payment request length"));
    }
    let text = encoded
        .strip_prefix("ipr:")
        .ok_or(ModelError::Invalid("payment prefix"))?;
    if text.is_empty()
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(ModelError::Invalid("payment Base64URL"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| ModelError::Invalid("canonical payment Base64URL"))?;
    if URL_SAFE_NO_PAD.encode(&bytes) != text {
        return Err(ModelError::Invalid("canonical payment Base64URL"));
    }
    let mut r = Reader {
        bytes: &bytes,
        offset: 0,
    };
    if r.take(1)?[0] != 1 {
        return Err(ModelError::Invalid("payment version"));
    }
    let kind = r.take(1)?[0];
    let chain_id = r.integer(8)?.to::<u64>();
    let protocol_address = r.integer(20)?;
    let token_address = r.integer(20)?;
    let amount = r.integer(16)?;
    let mut payload = None;
    let recipient = if kind == 3 {
        NoteOutputRecipient::Identity {
            identity: r.integer(32)?,
        }
    } else if kind == 1 || kind == 2 {
        let owner = r.integer(20)?;
        let (address, encrypted) = if kind == 2 {
            let keys = ReceivingKeys {
                viewing_public_key: r
                    .take(33)?
                    .try_into()
                    .map_err(|_| ModelError::Invalid("viewing key"))?,
                clue_key: r
                    .take(32)?
                    .try_into()
                    .map_err(|_| ModelError::Invalid("clue key"))?,
            };
            (ReceivingAddress::from_keys(owner, keys)?.encode()?, true)
        } else {
            (ReceivingAddress::from_identity(owner)?.encode()?, r.flag()?)
        };
        let nonce = if r.flag()? {
            Some(r.integer(32)?)
        } else {
            None
        };
        if encrypted {
            let len = r.integer(2)?.to::<usize>();
            if len > MAX_REQUEST_PAYLOAD_BYTES {
                return Err(ModelError::Exceeded("payment payload"));
            }
            if len != 0 {
                payload = Some(r.take(len)?.to_vec());
            }
        }
        if kind == 2 {
            NoteOutputRecipient::Invisi { address, nonce }
        } else {
            NoteOutputRecipient::Evm {
                address,
                envelope: encrypted,
                nonce,
                address_lookup: None,
            }
        }
    } else {
        return Err(ModelError::Invalid("recipient type"));
    };
    if r.offset != bytes.len() {
        return Err(ModelError::Invalid("trailing payment bytes"));
    }
    let request = PaymentRequest {
        chain_id,
        protocol_address,
        token_address,
        amount,
        recipient,
        payload,
    };
    request.validate()?;
    if encode_payment_request(&request)? != encoded {
        return Err(ModelError::Invalid("noncanonical payment request"));
    }
    Ok(request)
}
#[derive(Debug, Clone, Default)]
pub struct ExecutionOptions {
    pub nonce: Option<U256>,
    pub address_lookup: Option<AddressLookup>,
}
pub fn apply_execution_options(
    request: &PaymentRequest,
    options: &ExecutionOptions,
) -> ModelResult<PaymentRequest> {
    request.validate()?;
    let mut copy = request.clone();
    if let Some(value) = options.nonce {
        note::field(value, "execution nonce")?;
        let nonce = match &mut copy.recipient {
            NoteOutputRecipient::Evm { nonce, .. } | NoteOutputRecipient::Invisi { nonce, .. } => {
                nonce
            }
            _ => return Err(ModelError::Invalid("identity execution nonce")),
        };
        if nonce.is_some_and(|old| old != value) {
            return Err(ModelError::Mismatch("fixed payment nonce"));
        }
        *nonce = Some(value);
    }
    if let Some(lookup) = options.address_lookup {
        match &mut copy.recipient {
            NoteOutputRecipient::Evm {
                envelope: true,
                address_lookup,
                ..
            } => *address_lookup = Some(lookup),
            _ => return Err(ModelError::Invalid("unencrypted execution registry lookup")),
        }
    }
    Ok(copy)
}
mod optional_decimal {
    use super::*;
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &Option<U256>, s: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(n) => s.serialize_some(&n.to_string()),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<U256>, D::Error> {
        let value = Option::<String>::deserialize(d)?;
        value
            .map(|s| {
                if s.is_empty()
                    || s.len() > 78
                    || !s.bytes().all(|b| b.is_ascii_digit())
                    || (s.len() > 1 && s.starts_with('0'))
                {
                    return Err(serde::de::Error::custom("canonical decimal required"));
                }
                U256::from_str_radix(&s, 10).map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}
mod optional_bytes {
    use super::*;
    use serde::{Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => s.serialize_some(&format!("0x{}", hex::encode(bytes))),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| note::decode_hex(&s).map_err(serde::de::Error::custom))
            .transpose()
    }
}
