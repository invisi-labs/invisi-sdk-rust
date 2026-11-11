//! Host-executed wallet cryptography. Keys never belong in wire requests.
//! The host owns account storage, unlock policy, user approval, and key access.
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use alloy_primitives::{keccak256, U256};
use hkdf::Hkdf;
use k256::{
    ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey, SecretKey,
};
use serde_json::{json, Value};
use sha2::Sha256;
use zeroize::Zeroizing;

pub const MAX_WALLET_BATCH_ITEMS: usize = 1024;
pub const MAX_WALLET_BATCH_JSON_BYTES: usize = 16 * 1024 * 1024;

fn hkdf(key: &[u8], salt: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut output = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), key)
        .expand(info, &mut *output)
        .map_err(|_| "PRIVACY_KDF_FAILED")?;
    Ok(output)
}

fn root(key: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    if key.len() != 32 {
        return Err("WALLET_INVALID_ACCOUNT_KEY".into());
    }
    SecretKey::from_slice(key).map_err(|_| "PRIVACY_INVALID_ACCOUNT_KEY")?;
    hkdf(key, b"Invisi.WalletRoot.v1", b"")
}

pub fn viewing_key(key: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let root = root(key)?;
    for counter in 0u32..=u32::MAX {
        let candidate = hkdf(
            &*root,
            b"Invisi.WalletViewingKey.v1",
            &counter.to_be_bytes(),
        )?;
        if SecretKey::from_slice(&*candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err("PRIVACY_KDF_EXHAUSTED".into())
}

pub fn detection_key(key: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let root = root(key)?;
    let seed = hkdf(&*root, b"Invisi.WalletDetectionSeed.v1", b"")?;
    let modulus = U256::from_str_radix(
        "2111115437357092606062206234695386632838870926408408195193685246394721360383",
        10,
    )
    .unwrap();
    for counter in 0u32..=u32::MAX {
        let mut candidate = hkdf(
            &*seed,
            b"Invisi.WalletDetectionKey.v1",
            &counter.to_be_bytes(),
        )?;
        candidate[31] &= 7;
        let scalar = U256::from_le_slice(&*candidate);
        if scalar != U256::ZERO && scalar < modulus {
            return Ok(candidate);
        }
    }
    Err("PRIVACY_KDF_EXHAUSTED".into())
}

fn decode(value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value.strip_prefix("0x").ok_or("PRIVACY_INVALID_HEX")?)
        .map_err(|_| "PRIVACY_INVALID_HEX".into())
}
fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str, String> {
    value[name]
        .as_str()
        .ok_or_else(|| "PRIVACY_INVALID_REQUEST".into())
}
fn hex_value(value: &[u8]) -> String {
    format!("0x{}", hex::encode(value))
}
fn number(value: &str, length: usize) -> Result<Vec<u8>, String> {
    let n = if let Some(hex) = value.strip_prefix("0x") {
        U256::from_str_radix(hex, 16)
    } else {
        U256::from_str_radix(value, 10)
    }
    .map_err(|_| "PRIVACY_INVALID_INTEGER")?;
    let bytes = n.to_be_bytes::<32>();
    if length > 32 || bytes[..32 - length].iter().any(|b| *b != 0) {
        return Err("PRIVACY_INTEGER_RANGE".into());
    }
    Ok(bytes[32 - length..].to_vec())
}
fn public(key: &[u8], compressed: bool) -> Result<Vec<u8>, String> {
    Ok(SecretKey::from_slice(key)
        .map_err(|_| "PRIVACY_INVALID_ACCOUNT_KEY")?
        .public_key()
        .to_encoded_point(compressed)
        .as_bytes()
        .to_vec())
}
fn identity(key: &[u8]) -> Result<String, String> {
    Ok(hex_value(&keccak256(&public(key, false)?[1..])[12..]))
}

pub fn poseidon(fields: &[String]) -> Result<String, String> {
    if fields.len() > 4096 {
        return Err("PRIVACY_TOO_MANY_FIELDS".into());
    }
    let mut values = Vec::with_capacity(fields.len());
    for value in fields {
        let bytes = number(value, 32)?;
        let field = crate::field::bytes_to_field(&bytes);
        if crate::field::field_to_bytes_be(field).as_slice() != bytes.as_slice() {
            return Err("PRIVACY_NONCANONICAL_FIELD".into());
        }
        values.push(field);
    }
    Ok(hex_value(&crate::field::field_to_bytes_be(
        crate::poseidon::hash(&values),
    )))
}

pub fn open(key: &[u8], request: &Value) -> Result<Zeroizing<Vec<u8>>, String> {
    let data = decode(text(request, "envelope")?)?;
    let role = text(request, "role")?;
    let (header, role_byte, domain, minimum) = match role {
        "funds" => (1, 0, b"Invisi.NoteDelivery.v1".as_slice(), 160),
        "owner" => (130, 1, b"Invisi.CreditDelivery.v2".as_slice(), 485),
        "spender" => (130, 2, b"Invisi.CreditDelivery.v2".as_slice(), 485),
        _ => return Err("PRIVACY_INVALID_ROLE".into()),
    };
    if data.len() < minimum || data.len() > 4096 || data[0] != header {
        return Err("PRIVACY_INVALID_ENVELOPE".into());
    }
    let peer =
        PublicKey::from_sec1_bytes(&data[1..34]).map_err(|_| "PRIVACY_INVALID_EPHEMERAL_KEY")?;
    let viewing = viewing_key(key)?;
    let secret = SecretKey::from_slice(&*viewing).map_err(|_| "PRIVACY_INVALID_VIEWING_KEY")?;
    let shared = k256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    let mut info = domain.to_vec();
    info.extend_from_slice(&data[1..34]);
    info.extend_from_slice(&public(&*viewing, true)?);
    let aes_key = hkdf(shared.raw_secret_bytes(), &data[34..50], &info)?;
    let context = &request["context"];
    let mut aad = domain.to_vec();
    aad.extend_from_slice(&data[..62]);
    aad.push(role_byte);
    for (name, length) in [
        ("chainId", 8),
        ("protocolAddress", 20),
        ("tokenAddress", 20),
        ("outputCommitment", 32),
    ] {
        aad.extend_from_slice(&number(text(context, name)?, length)?);
    }
    let cipher = Aes256Gcm::new_from_slice(&*aes_key).map_err(|_| "PRIVACY_DECRYPT_FAILED")?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&data[50..62]),
                Payload {
                    msg: &data[62..],
                    aad: &aad,
                },
            )
            .map_err(|_| "PRIVACY_DECRYPT_FAILED")?,
    );
    let (identity_start, payload_offset) = match role {
        "funds" => (0, 80),
        "owner" => (32, 405),
        _ => (0, 405),
    };
    if plain.len() < payload_offset + 2 {
        return Err("PRIVACY_INVALID_PAYLOAD".into());
    }
    let expected = number(&identity(key)?, 32)?;
    if plain[identity_start..identity_start + 32] != expected {
        return Err("PRIVACY_RECIPIENT_MISMATCH".into());
    }
    let len = u16::from_be_bytes([plain[payload_offset], plain[payload_offset + 1]]) as usize;
    if plain.len() != payload_offset + 2 + len {
        return Err("PRIVACY_INVALID_PAYLOAD".into());
    }
    if role != "funds" {
        let start = if role == "owner" { 275 } else { 340 };
        if plain[start..start + 33] != public(&*viewing, true)? {
            return Err("PRIVACY_RECIPIENT_MISMATCH".into());
        }
    }
    validate_delivery_plaintext(&plain, context, role)?;
    Ok(plain)
}

pub fn authorization_digest(request: &Value) -> Result<[u8; 32], String> {
    let operation = text(request, "operation")?;
    let capacity = request["capacity"]
        .as_u64()
        .ok_or("PRIVACY_INVALID_AUTHORIZATION")?;
    let (name, capacities): (&str, &[u64]) = match operation {
        "transact" => (
            "Transact",
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130,
                140, 150, 160, 170, 180, 190,
            ],
        ),
        "create-credit" => ("CreateCredit", &[1]),
        "credit-draw" => (
            "CreditDraw",
            &[1, 2, 3, 4, 5, 10, 20, 30, 40, 50, 60, 70, 80],
        ),
        "update-credit" => ("UpdateCredit", &[1]),
        _ => return Err("PRIVACY_INVALID_AUTHORIZATION_OPERATION".into()),
    };
    if !capacities.contains(&capacity) {
        return Err("PRIVACY_INVALID_AUTHORIZATION_CAPACITY".into());
    }
    let chain = number(text(&request["context"], "chainId")?, 8)?;
    let protocol = number(text(&request["context"], "protocolAddress")?, 20)?;
    if protocol.iter().all(|byte| *byte == 0) {
        return Err("PRIVACY_INVALID_AUTHORIZATION_CONTEXT".into());
    }
    let words = request["words"]
        .as_array()
        .ok_or("PRIVACY_INVALID_AUTHORIZATION_WORDS")?;
    if words.len() < 2 || words.len() > 8192 {
        return Err("PRIVACY_INVALID_AUTHORIZATION_WORDS".into());
    }
    if number(
        words[0]
            .as_str()
            .ok_or("PRIVACY_INVALID_AUTHORIZATION_WORDS")?,
        8,
    )? != chain
        || number(
            words[1]
                .as_str()
                .ok_or("PRIVACY_INVALID_AUTHORIZATION_WORDS")?,
            20,
        )? != protocol
    {
        return Err("PRIVACY_INVALID_AUTHORIZATION_CONTEXT".into());
    }
    let mut encoded = Vec::new();
    for value in [capacity, 64, words.len() as u64] {
        encoded.extend_from_slice(&U256::from(value).to_be_bytes::<32>());
    }
    for word in words {
        let encoded_word = number(
            word.as_str().ok_or("PRIVACY_INVALID_AUTHORIZATION_WORDS")?,
            32,
        )?;
        if crate::field::field_to_bytes_be(crate::field::bytes_to_field(&encoded_word)).as_slice()
            != encoded_word.as_slice()
        {
            return Err("PRIVACY_NONCANONICAL_FIELD".into());
        }
        encoded.extend_from_slice(&encoded_word);
    }
    let mut domain = Vec::new();
    for item in [
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        "InvisibleProtocol",
        "1",
    ] {
        domain.extend_from_slice(keccak256(item.as_bytes()).as_slice());
    }
    domain.extend_from_slice(&number(text(&request["context"], "chainId")?, 32)?);
    domain.extend_from_slice(&number(text(&request["context"], "protocolAddress")?, 32)?);
    let mut structure =
        keccak256(b"WalletAuthorization(bytes32 operation,bytes32 statementHash)").to_vec();
    structure.extend_from_slice(
        keccak256(
            format!(
                "Invisi.{name}.{}",
                if operation == "transact" { "v1" } else { "v4" }
            )
            .as_bytes(),
        )
        .as_slice(),
    );
    structure.extend_from_slice(keccak256(&encoded).as_slice());
    let mut message = vec![0x19, 0x01];
    message.extend_from_slice(keccak256(&domain).as_slice());
    message.extend_from_slice(keccak256(&structure).as_slice());
    Ok(keccak256(message).into())
}

/// Execute a wallet request using a key supplied exclusively by the native host.
/// Request IDs correlate responses; hosts must enforce their own approval and replay policy.
pub fn execute(key: &[u8], request: &Value) -> Result<Value, String> {
    if key.len() != 32 {
        return Err("WALLET_INVALID_ACCOUNT_KEY".into());
    }
    validate_wire(request)?;
    if request["version"].as_u64() != Some(1) {
        return Err("WALLET_UNSUPPORTED_VERSION".into());
    }
    let id = text(request, "id")?;
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err("WALLET_INVALID_ID".into());
    }
    let owner = text(request, "ownerAddress")?;
    if owner.len() != 42 || identity(key)? != owner.to_lowercase() {
        return Err("WALLET_ACCOUNT_MISMATCH".into());
    }
    let params = &request["params"];
    if !params.is_object() {
        return Err("WALLET_INVALID_PARAMS".into());
    }
    let method = text(request, "method")?;
    let result = match method {
        "wallet.public" => {
            let detection = detection_key(key)?;
            let detector = decaf377_fmd::DetectionKey::from_bytes(*detection)
                .map_err(|_| "WALLET_INVALID_DETECTION_KEY")?;
            let clue = detector.clue_key().0;
            json!({"spendingPublicKey":hex_value(&public(key,false)?),"viewingPublicKey":hex_value(&public(&*viewing_key(key)?,true)?),"clueKey":hex_value(&clue)})
        }
        "wallet.detect" => {
            let clues = params["clues"].as_array().ok_or("WALLET_INVALID_CLUES")?;
            if clues.len() > 1024 {
                return Err("WALLET_TOO_MANY_CLUES".into());
            }
            let detection = detection_key(key)?;
            let detector = decaf377_fmd::DetectionKey::from_bytes(*detection)
                .map_err(|_| "WALLET_INVALID_DETECTION_KEY")?;
            let matches = clues
                .iter()
                .map(|c| {
                    let data = decode(c.as_str().ok_or("WALLET_INVALID_CLUE")?)?;
                    if data.len() != 68 {
                        return Err("WALLET_INVALID_CLUE".to_owned());
                    }
                    if data[64] != 24 {
                        return Ok(false);
                    }
                    let clue = decaf377_fmd::Clue::try_from(data.as_slice())
                        .map_err(|_| "WALLET_INVALID_CLUE")?;
                    Ok(detector.examine(&clue))
                })
                .collect::<Result<Vec<_>, String>>()?;
            json!({"matches":matches})
        }
        "wallet.decryptNote" | "wallet.decryptCredit" => {
            let mut input = params.clone();
            input["role"] = if method == "wallet.decryptNote" {
                json!("funds")
            } else {
                params["context"]["role"].clone()
            };
            let plain = open(key, &input)?;
            json!({"plaintext":hex_value(&plain)})
        }
        "wallet.authorize" => {
            let digest = authorization_digest(params)?;
            let signing = SigningKey::from_slice(key).map_err(|_| "WALLET_INVALID_ACCOUNT_KEY")?;
            let signature: Signature = signing
                .sign_prehash(&digest)
                .map_err(|_| "WALLET_SIGN_FAILED")?;
            json!({"digest":hex_value(&digest),"signature":hex_value(&signature.to_bytes()),"spendingPublicKey":hex_value(&public(key,false)?)})
        }
        _ => return Err("WALLET_UNSUPPORTED_METHOD".into()),
    };
    Ok(json!({"version":1,"id":id,"ownerAddress":owner,"method":method,"result":result}))
}

/// Execute an atomic envelope batch. Hosts approve the complete batch before calling this function.
pub fn execute_batch(key: &[u8], requests: &[Value]) -> Result<Vec<Value>, String> {
    if requests.len() > MAX_WALLET_BATCH_ITEMS
        || serde_json::to_vec(requests)
            .map_err(|_| "WALLET_INVALID_JSON")?
            .len()
            > MAX_WALLET_BATCH_JSON_BYTES
    {
        return Err("WALLET_BATCH_LIMIT".into());
    }
    if requests.is_empty() {
        return Ok(Vec::new());
    }
    let mut ids = std::collections::BTreeSet::new();
    let owner = text(&requests[0], "ownerAddress")?;
    for request in requests {
        validate_wire(request)?;
        if text(request, "ownerAddress")? != owner {
            return Err("WALLET_BATCH_OWNER_MISMATCH".into());
        }
        if !ids.insert(text(request, "id")?) {
            return Err("WALLET_DUPLICATE_ID".into());
        }
    }
    if key.len() != 32 || identity(key)? != owner {
        return Err("WALLET_ACCOUNT_MISMATCH".into());
    }
    let responses: Vec<Value> = requests.iter().map(|request| match execute(key, request) {
        Ok(response) => response,
        Err(code) => {
            let code = match code.as_str() {
                "PRIVACY_DECRYPT_FAILED" => "WALLET_AUTHENTICATION_FAILED",
                "PRIVACY_RECIPIENT_MISMATCH" => "WALLET_NOT_RECIPIENT",
                other if other.as_bytes().first().is_some_and(u8::is_ascii_uppercase) && other.len() <= 128 && other.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_') => other,
                _ => "WALLET_NATIVE_FAILURE",
            };
            json!({"version":request["version"],"id":request["id"],"ownerAddress":request["ownerAddress"],"method":request["method"],"error":{"code":code}})
        }
    }).collect();
    if serde_json::to_vec(&responses)
        .map_err(|_| "WALLET_INVALID_JSON")?
        .len()
        > MAX_WALLET_BATCH_JSON_BYTES
    {
        return Err("WALLET_BATCH_LIMIT".into());
    }
    Ok(responses)
}

fn exact_keys(value: &Value, keys: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("WALLET_INVALID_OBJECT")?;
    if object.len() != keys.len() || keys.iter().any(|k| !object.contains_key(*k)) {
        return Err("WALLET_UNEXPECTED_FIELDS".into());
    }
    Ok(())
}
fn decimal(value: &Value) -> Result<(), String> {
    let value = value.as_str().ok_or("WALLET_INVALID_INTEGER")?;
    if value.is_empty()
        || value.len() > 78
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("WALLET_INVALID_INTEGER".into());
    }
    number(value, 32)?;
    Ok(())
}
fn canonical_hex(value: &Value, length: Option<usize>) -> Result<(), String> {
    let text = value.as_str().ok_or("WALLET_INVALID_HEX")?;
    if text.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err("WALLET_INVALID_HEX".into());
    }
    let b = decode(text)?;
    if length.is_some_and(|n| b.len() != n) {
        return Err("WALLET_INVALID_HEX".into());
    }
    Ok(())
}
pub fn validate_wire(request: &Value) -> Result<(), String> {
    exact_keys(
        request,
        &["version", "id", "ownerAddress", "method", "params"],
    )?;
    if request["version"].as_u64() != Some(1) {
        return Err("WALLET_UNSUPPORTED_VERSION".into());
    }
    let id = text(request, "id")?;
    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err("WALLET_INVALID_ID".into());
    }
    canonical_hex(&request["ownerAddress"], Some(20))?;
    if decode(text(request, "ownerAddress")?)?
        .iter()
        .all(|b| *b == 0)
    {
        return Err("WALLET_INVALID_OWNER".into());
    }
    let params = &request["params"];
    match text(request, "method")? {
        "wallet.public" => exact_keys(params, &[])?,
        "wallet.detect" => {
            exact_keys(params, &["clues"])?;
            let clues = params["clues"].as_array().ok_or("WALLET_INVALID_CLUES")?;
            if clues.len() > 1024 {
                return Err("WALLET_TOO_MANY_CLUES".into());
            }
            for clue in clues {
                canonical_hex(clue, Some(68))?;
            }
        }
        "wallet.authorize" => {
            exact_keys(params, &["operation", "capacity", "words", "context"])?;
            exact_keys(&params["context"], &["chainId", "protocolAddress"])?;
            for name in ["chainId", "protocolAddress"] {
                decimal(&params["context"][name])?;
            }
            for word in params["words"].as_array().ok_or("WALLET_INVALID_WORDS")? {
                decimal(word)?;
            }
            authorization_digest(params)?;
        }
        "wallet.decryptNote" | "wallet.decryptCredit" => {
            exact_keys(params, &["envelope", "context"])?;
            let context = &params["context"];
            if request["method"] == "wallet.decryptCredit" {
                exact_keys(
                    context,
                    &[
                        "chainId",
                        "protocolAddress",
                        "tokenAddress",
                        "outputCommitment",
                        "role",
                    ],
                )?;
            } else {
                exact_keys(
                    context,
                    &[
                        "chainId",
                        "protocolAddress",
                        "tokenAddress",
                        "outputCommitment",
                    ],
                )?;
            }
            for name in ["chainId", "protocolAddress", "tokenAddress"] {
                decimal(&context[name])?;
            }
            canonical_hex(&context["outputCommitment"], Some(32))?;
            canonical_hex(&params["envelope"], None)?;
            let credit = request["method"] == "wallet.decryptCredit";
            if credit && !matches!(text(context, "role")?, "owner" | "spender") {
                return Err("WALLET_INVALID_ROLE".into());
            }
            number(text(context, "chainId")?, 8)?;
            number(text(context, "protocolAddress")?, 20)?;
            number(text(context, "tokenAddress")?, 20)?;
            let field = number(text(context, "outputCommitment")?, 32)?;
            if crate::field::field_to_bytes_be(crate::field::bytes_to_field(&field)).as_slice()
                != field.as_slice()
            {
                return Err("WALLET_NONCANONICAL_FIELD".into());
            }
            crate::delivery::validate_envelope(&decode(text(params, "envelope")?)?, credit)
                .map_err(|_| "WALLET_INVALID_ENVELOPE")?;
        }
        _ => return Err("WALLET_UNSUPPORTED_METHOD".into()),
    }
    Ok(())
}

/// Verify the financial preimage independently from envelope authentication.
/// Opaque application payload bytes are outside the financial commitment.
pub fn validate_delivery_plaintext(
    plain: &[u8],
    context: &Value,
    role: &str,
) -> Result<(), String> {
    let scoped = crate::delivery::DeliveryContext {
        context: crate::note::ProtocolContext {
            chain_id: u64::from_be_bytes(
                number(text(context, "chainId")?, 8)?
                    .try_into()
                    .map_err(|_| "WALLET_INVALID_CHAIN")?,
            ),
            protocol_address: U256::from_be_slice(&number(text(context, "protocolAddress")?, 20)?),
        },
        token_address: U256::from_be_slice(&number(text(context, "tokenAddress")?, 20)?),
        output_commitment: U256::from_be_slice(&number(text(context, "outputCommitment")?, 32)?),
    };
    match role {
        "funds" => crate::delivery::decode_note(plain, &scoped)
            .map(|_| ())
            .map_err(|_| "WALLET_INVALID_NOTE_PAYLOAD".into()),
        "owner" | "spender" => crate::delivery::decode_credit(plain, &scoped)
            .map(|_| ())
            .map_err(|_| "WALLET_INVALID_CREDIT_PAYLOAD".into()),
        _ => Err("WALLET_INVALID_ROLE".into()),
    }
}
