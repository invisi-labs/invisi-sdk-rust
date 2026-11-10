//! Optional memo application bytes, independently versioned from financial delivery envelopes.
use crate::note::{ModelError, ModelResult};
pub const MAX_MEMO_BYTES: usize = 256;
#[derive(Debug, Clone, Copy)]
pub enum Memo<'a> {
    Text(&'a str),
    Bytes(&'a [u8]),
}
pub fn encode_memo(memo: Option<Memo<'_>>) -> ModelResult<Vec<u8>> {
    let bytes = match memo {
        None => &[][..],
        Some(Memo::Text(text)) => text.as_bytes(),
        Some(Memo::Bytes(bytes)) => bytes,
    };
    if bytes.len() > MAX_MEMO_BYTES {
        return Err(ModelError::Exceeded("memo 256-byte limit"));
    }
    Ok(bytes.to_vec())
}
pub fn decode_memo_text(bytes: &[u8]) -> ModelResult<String> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| ModelError::Invalid("UTF-8 memo"))
}
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationDataV1 {
    #[serde(
        default,
        with = "crate::note::bytes_hex",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub memo: Vec<u8>,
}
pub type FundsDataV1 = ApplicationDataV1;
pub type CreditDataV1 = ApplicationDataV1;
fn encode(data: &ApplicationDataV1) -> ModelResult<Vec<u8>> {
    let memo = encode_memo(Some(Memo::Bytes(&data.memo)))?;
    let mut bytes = Vec::with_capacity(memo.len() + 1);
    bytes.push(1);
    bytes.extend_from_slice(&memo);
    Ok(bytes)
}
fn decode(bytes: &[u8]) -> ModelResult<ApplicationDataV1> {
    if bytes.first() != Some(&1) {
        return Err(ModelError::Invalid("application payload version"));
    }
    Ok(ApplicationDataV1 {
        memo: encode_memo(Some(Memo::Bytes(&bytes[1..])))?,
    })
}
pub fn encode_funds_v1(data: &FundsDataV1) -> ModelResult<Vec<u8>> {
    encode(data)
}
pub fn decode_funds_v1(bytes: &[u8]) -> ModelResult<FundsDataV1> {
    decode(bytes)
}
pub fn encode_credit_v1(data: &CreditDataV1) -> ModelResult<Vec<u8>> {
    encode(data)
}
pub fn decode_credit_v1(bytes: &[u8]) -> ModelResult<CreditDataV1> {
    decode(bytes)
}
