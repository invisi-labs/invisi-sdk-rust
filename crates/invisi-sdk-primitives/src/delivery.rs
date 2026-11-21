//! Current Note/Credit delivery codecs and context-bound secp256k1/HKDF/AES-GCM.
use crate::{
    address::ReceivingKeys,
    credit::{CreditPolicy, CreditState, CreditUsage},
    note::{ModelError, ModelResult, Note, ProtocolContext},
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use alloy_primitives::U256;
use hkdf::Hkdf;
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey, SecretKey};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Authentication ambiguity is retryable; operational failures remain errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecryptionOutcome {
    Plaintext(Vec<u8>),
    NonRecipient,
    AuthenticationFailed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DeliveryRole {
    Funds,
    Owner,
    Spender,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DetectionCandidate {
    pub clue: Vec<u8>,
    pub context: DeliveryContext,
    pub owner: U256,
    pub role: DeliveryRole,
}
/// App-owned decryption: only Ok(None) means a nonrecipient; all operational failures reject.
/// The App authenticates ciphertext and owns key storage, unlocking and consent.
pub trait DeliveryDecryptor: Send + Sync {
    fn decrypt_note(
        &self,
        envelope: &[u8],
        context: &DeliveryContext,
        owner: U256,
    ) -> Result<Option<Vec<u8>>, String>;
    fn decrypt_credit(
        &self,
        envelope: &[u8],
        context: &DeliveryContext,
        role: CreditRole,
        owner: U256,
    ) -> Result<Option<Vec<u8>>, String>;
    /// Native implementations own detection keys; false is an explicit nonrecipient.
    fn detect(&self, candidates: &[DetectionCandidate]) -> Result<Vec<bool>, String> {
        Ok(vec![true; candidates.len()])
    }
    fn decrypt_note_outcome(
        &self,
        envelope: &[u8],
        context: &DeliveryContext,
        owner: U256,
    ) -> Result<DecryptionOutcome, String> {
        Ok(match self.decrypt_note(envelope, context, owner)? {
            Some(p) => DecryptionOutcome::Plaintext(p),
            None => DecryptionOutcome::NonRecipient,
        })
    }
    fn decrypt_credit_outcome(
        &self,
        envelope: &[u8],
        context: &DeliveryContext,
        role: CreditRole,
        owner: U256,
    ) -> Result<DecryptionOutcome, String> {
        Ok(match self.decrypt_credit(envelope, context, role, owner)? {
            Some(p) => DecryptionOutcome::Plaintext(p),
            None => DecryptionOutcome::NonRecipient,
        })
    }
}

pub const MAX_CIPHERTEXT_BYTES: usize = 4096;
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CreditRole {
    Owner,
    Spender,
}
impl CreditRole {
    fn byte(self) -> u8 {
        if self == Self::Owner {
            1
        } else {
            2
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreditDeliveryState {
    pub note: CreditState,
    pub owner_receiving_keys: ReceivingKeys,
    pub spender_receiving_keys: ReceivingKeys,
}
impl CreditDeliveryState {
    pub fn validate(&self) -> ModelResult<()> {
        self.note.validate()?;
        self.owner_receiving_keys.validate()?;
        self.spender_receiving_keys.validate()
    }
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliveryContext {
    #[serde(flatten)]
    pub context: ProtocolContext,
    #[serde(with = "crate::note::decimal")]
    pub token_address: U256,
    #[serde(with = "crate::note::field_hex")]
    pub output_commitment: U256,
}
impl DeliveryContext {
    pub fn validate(&self) -> ModelResult<()> {
        crate::note::uint(self.context.protocol_address, 160, "protocol address")?;
        crate::note::uint(self.token_address, 160, "token address")?;
        crate::note::field(self.output_commitment, "output commitment")
    }
    fn wire(&self) -> serde_json::Value {
        serde_json::json!({"chainId":self.context.chain_id.to_string(),"protocolAddress":self.context.protocol_address.to_string(),"tokenAddress":self.token_address.to_string(),"outputCommitment":format!("0x{}",hex::encode(self.output_commitment.to_be_bytes::<32>()))})
    }
}
fn invalid() -> ModelError {
    ModelError::Invalid("delivery envelope")
}
fn push(out: &mut Vec<u8>, value: U256, size: usize) -> ModelResult<()> {
    if size < 32 {
        crate::note::uint(value, size * 8, "delivery integer")?;
    }
    out.extend_from_slice(&value.to_be_bytes::<32>()[32 - size..]);
    Ok(())
}
fn payload(out: &mut Vec<u8>, bytes: &[u8]) -> ModelResult<()> {
    if bytes.len() > u16::MAX as usize {
        return Err(ModelError::Invalid("payload length"));
    }
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn read(plain: &[u8], offset: &mut usize, size: usize) -> ModelResult<U256> {
    let data = plain.get(*offset..*offset + size).ok_or_else(invalid)?;
    *offset += size;
    Ok(U256::from_be_slice(data))
}
fn read_payload(plain: &[u8], offset: usize) -> ModelResult<Vec<u8>> {
    let len = plain.get(offset..offset + 2).ok_or_else(invalid)?;
    let len = u16::from_be_bytes([len[0], len[1]]) as usize;
    if plain.len() != offset + 2 + len {
        return Err(invalid());
    }
    Ok(plain[offset + 2..].to_vec())
}
pub fn encode_note(note: &Note) -> ModelResult<Zeroizing<Vec<u8>>> {
    note.validate()?;
    let mut p = Zeroizing::new(Vec::new());
    push(&mut p, note.owner_address, 32)?;
    push(&mut p, note.amount, 16)?;
    push(&mut p, note.nonce, 32)?;
    payload(&mut p, &note.payload)?;
    Ok(p)
}
pub fn decode_note(plain: &[u8], context: &DeliveryContext) -> ModelResult<Note> {
    let mut o = 0;
    let note = Note {
        context: context.context,
        token_address: context.token_address,
        owner_address: read(plain, &mut o, 32)?,
        amount: read(plain, &mut o, 16)?,
        nonce: read(plain, &mut o, 32)?,
        payload: read_payload(plain, o)?,
    };
    note.validate()?;
    if note.commitment() != Ok(context.output_commitment) {
        return Err(ModelError::Mismatch("note commitment"));
    }
    Ok(note)
}
// Fixed uint128 Credit plaintext fields; native-wallet preflight shares these offsets.
pub(crate) const CREDIT_OWNER_KEYS_OFFSET: usize =
    32 * 2 + 16 + 32 + 8 + 32 + 16 * 4 + 1 + 8 * 2 + 16 * 3;
pub(crate) const CREDIT_SPENDER_KEYS_OFFSET: usize = CREDIT_OWNER_KEYS_OFFSET + 33 + 32;
pub(crate) const CREDIT_PAYLOAD_LENGTH_OFFSET: usize = CREDIT_SPENDER_KEYS_OFFSET + 33 + 32;

pub fn encode_credit(state: &CreditDeliveryState) -> ModelResult<Zeroizing<Vec<u8>>> {
    state.validate()?;
    let n = &state.note;
    let mut p = Zeroizing::new(Vec::new());
    for (value, size) in [
        (n.spender_wallet_identity, 32),
        (n.owner_wallet_identity, 32),
        (U256::from(n.grant_id), 16),
        (n.nonce, 32),
        (U256::from(n.expiry), 8),
        (n.credit_shared_key, 32),
        (n.policy.single_limit, 16),
        (n.policy.daily_limit, 16),
        (n.policy.monthly_limit, 16),
        (n.available_credit, 16),
        (U256::from(n.unlimited as u8), 1),
        (U256::from(n.usage.last_day), 8),
        (n.usage.daily_spent, 16),
        (U256::from(n.usage.last_month), 8),
        (n.usage.monthly_spent, 16),
        (n.usage.total_spent, 16),
    ] {
        push(&mut p, value, size)?;
    }
    debug_assert_eq!(p.len(), CREDIT_OWNER_KEYS_OFFSET);
    for keys in [&state.owner_receiving_keys, &state.spender_receiving_keys] {
        p.extend_from_slice(&keys.viewing_public_key);
        p.extend_from_slice(&keys.clue_key);
    }
    debug_assert_eq!(p.len(), CREDIT_PAYLOAD_LENGTH_OFFSET);
    payload(&mut p, &n.payload)?;
    Ok(p)
}
pub fn decode_credit(plain: &[u8], context: &DeliveryContext) -> ModelResult<CreditDeliveryState> {
    let mut o = 0;
    let spender = read(plain, &mut o, 32)?;
    let owner = read(plain, &mut o, 32)?;
    let grant_id = read(plain, &mut o, 16)?.to::<u128>();
    let nonce = read(plain, &mut o, 32)?;
    let expiry = read(plain, &mut o, 8)?.to::<u64>();
    let key = read(plain, &mut o, 32)?;
    let policy = CreditPolicy {
        single_limit: read(plain, &mut o, 16)?,
        daily_limit: read(plain, &mut o, 16)?,
        monthly_limit: read(plain, &mut o, 16)?,
    };
    let available = read(plain, &mut o, 16)?;
    let flag = read(plain, &mut o, 1)?.to::<u8>();
    if flag > 1 {
        return Err(ModelError::Invalid("unlimited flag"));
    }
    let usage = CreditUsage {
        last_day: read(plain, &mut o, 8)?.to::<u64>(),
        daily_spent: read(plain, &mut o, 16)?,
        last_month: read(plain, &mut o, 8)?.to::<u64>(),
        monthly_spent: read(plain, &mut o, 16)?,
        total_spent: read(plain, &mut o, 16)?,
    };
    let mut keys = || -> ModelResult<ReceivingKeys> {
        let data = plain.get(o..o + 65).ok_or_else(invalid)?;
        o += 65;
        Ok(ReceivingKeys {
            viewing_public_key: data[..33].try_into().map_err(|_| invalid())?,
            clue_key: data[33..].try_into().map_err(|_| invalid())?,
        })
    };
    let owner_receiving_keys = keys()?;
    let spender_receiving_keys = keys()?;
    let state = CreditDeliveryState {
        note: CreditState {
            context: context.context,
            token_address: context.token_address,
            spender_wallet_identity: spender,
            owner_wallet_identity: owner,
            grant_id,
            nonce,
            expiry,
            credit_shared_key: key,
            policy,
            usage,
            available_credit: available,
            unlimited: flag == 1,
            payload: read_payload(plain, o)?,
        },
        owner_receiving_keys,
        spender_receiving_keys,
    };
    state.validate()?;
    if state.note.commitment() != Ok(context.output_commitment) {
        return Err(ModelError::Mismatch("credit commitment"));
    }
    Ok(state)
}
fn domain(header: u8) -> ModelResult<&'static [u8]> {
    match header {
        1 => Ok(b"Invisi.NoteDelivery.v1"),
        132 => Ok(b"Invisi.CreditDelivery.v4.GrantId.Uint128"),
        _ => Err(invalid()),
    }
}
pub fn validate_envelope(data: &[u8], credit: bool) -> ModelResult<()> {
    let minimum = if credit { 491 } else { 160 };
    if data.len() < minimum
        || data.len() > MAX_CIPHERTEXT_BYTES
        || data[0] != if credit { 132 } else { 1 }
    {
        return Err(invalid());
    }
    PublicKey::from_sec1_bytes(&data[1..34]).map_err(|_| invalid())?;
    Ok(())
}
fn aad(header: &[u8], context: &DeliveryContext, role: u8) -> ModelResult<Vec<u8>> {
    context.validate()?;
    let mut out = domain(header[0])?.to_vec();
    out.extend_from_slice(header);
    out.push(role);
    out.extend_from_slice(&context.context.chain_id.to_be_bytes());
    push(&mut out, context.context.protocol_address, 20)?;
    push(&mut out, context.token_address, 20)?;
    push(&mut out, context.output_commitment, 32)?;
    Ok(out)
}
fn derive(
    key: &SecretKey,
    peer: &PublicKey,
    header: &[u8],
    recipient: &[u8],
) -> ModelResult<Zeroizing<[u8; 32]>> {
    let shared = k256::ecdh::diffie_hellman(key.to_nonzero_scalar(), peer.as_affine());
    let mut info = domain(header[0])?.to_vec();
    info.extend_from_slice(&header[1..34]);
    info.extend_from_slice(recipient);
    let mut output = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(&header[34..50]), shared.raw_secret_bytes())
        .expand(&info, &mut *output)
        .map_err(|_| invalid())?;
    Ok(output)
}
fn seal(public: &[u8], plain: &[u8], context: &DeliveryContext, role: u8) -> ModelResult<Vec<u8>> {
    let recipient = PublicKey::from_sec1_bytes(public).map_err(|_| invalid())?;
    if public.len() != 33 {
        return Err(invalid());
    }
    let ephemeral = SecretKey::random(&mut OsRng);
    let mut header = vec![if role == 0 { 1 } else { 132 }];
    header.extend_from_slice(ephemeral.public_key().to_encoded_point(true).as_bytes());
    let mut salt_iv = [0; 28];
    OsRng.fill_bytes(&mut salt_iv);
    header.extend_from_slice(&salt_iv);
    let key = derive(&ephemeral, &recipient, &header, public)?;
    let cipher = Aes256Gcm::new_from_slice(&*key).map_err(|_| invalid())?;
    let encrypted = cipher
        .encrypt(
            Nonce::from_slice(&header[50..62]),
            Payload {
                msg: plain,
                aad: &aad(&header, context, role)?,
            },
        )
        .map_err(|_| invalid())?;
    header.extend_from_slice(&encrypted);
    validate_envelope(&header, role != 0)?;
    Ok(header)
}
pub fn payload_key(
    viewing_key: &[u8],
    envelope: &[u8],
    credit: bool,
) -> ModelResult<Zeroizing<[u8; 32]>> {
    validate_envelope(envelope, credit)?;
    if viewing_key.len() != 32 {
        return Err(ModelError::Invalid("viewing key length"));
    }
    let secret = SecretKey::from_slice(viewing_key).map_err(|_| invalid())?;
    let peer = PublicKey::from_sec1_bytes(&envelope[1..34]).map_err(|_| invalid())?;
    derive(
        &secret,
        &peer,
        &envelope[..62],
        secret.public_key().to_encoded_point(true).as_bytes(),
    )
}
pub fn open_payload(
    key: &[u8],
    envelope: &[u8],
    context: &DeliveryContext,
    role: u8,
) -> ModelResult<Zeroizing<Vec<u8>>> {
    validate_envelope(envelope, role != 0)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| invalid())?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&envelope[50..62]),
                Payload {
                    msg: &envelope[62..],
                    aad: &aad(&envelope[..62], context, role)?,
                },
            )
            .map_err(|_| ModelError::Invalid("delivery authentication"))?,
    );
    crate::wallet::validate_delivery_plaintext(
        &plain,
        &context.wire(),
        match role {
            0 => "funds",
            1 => "owner",
            2 => "spender",
            _ => return Err(invalid()),
        },
    )
    .map_err(|_| ModelError::Invalid("delivery financial commitment"))?;
    Ok(plain)
}
pub fn encrypt_note(public: &[u8], note: &Note, context: &DeliveryContext) -> ModelResult<Vec<u8>> {
    if note.context != context.context
        || note.token_address != context.token_address
        || note.commitment() != Ok(context.output_commitment)
    {
        return Err(ModelError::Mismatch("note context"));
    }
    seal(public, &encode_note(note)?, context, 0)
}
pub fn decrypt_note(
    viewing_key: &[u8],
    envelope: &[u8],
    context: &DeliveryContext,
    owner: U256,
) -> ModelResult<Note> {
    let key = payload_key(viewing_key, envelope, false)?;
    let note = decode_note(&open_payload(&*key, envelope, context, 0)?, context)?;
    if note.owner_address != owner {
        return Err(ModelError::Mismatch("note recipient"));
    }
    Ok(note)
}
pub fn encrypt_credit(
    public: &[u8],
    state: &CreditDeliveryState,
    context: &DeliveryContext,
    role: CreditRole,
) -> ModelResult<Vec<u8>> {
    let keys = if role == CreditRole::Owner {
        &state.owner_receiving_keys
    } else {
        &state.spender_receiving_keys
    };
    if public != keys.viewing_public_key
        || state.note.context != context.context
        || state.note.token_address != context.token_address
        || state.note.commitment() != Ok(context.output_commitment)
    {
        return Err(ModelError::Mismatch("credit context or receiving key"));
    }
    seal(public, &encode_credit(state)?, context, role.byte())
}
pub fn decrypt_credit(
    viewing_key: &[u8],
    envelope: &[u8],
    context: &DeliveryContext,
    role: CreditRole,
    owner: U256,
) -> ModelResult<CreditDeliveryState> {
    let key = payload_key(viewing_key, envelope, true)?;
    let state = decode_credit(
        &open_payload(&*key, envelope, context, role.byte())?,
        context,
    )?;
    let (identity, keys) = if role == CreditRole::Owner {
        (
            state.note.owner_wallet_identity,
            &state.owner_receiving_keys,
        )
    } else {
        (
            state.note.spender_wallet_identity,
            &state.spender_receiving_keys,
        )
    };
    let secret = SecretKey::from_slice(viewing_key).map_err(|_| invalid())?;
    if identity != owner
        || keys.viewing_public_key != secret.public_key().to_encoded_point(true).as_bytes()
    {
        return Err(ModelError::Mismatch("credit recipient"));
    }
    Ok(state)
}
