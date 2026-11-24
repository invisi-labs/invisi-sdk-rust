use super::{hex_value, hkdf};
use crate::address::{ReceivingAddress, ReceivingKeys};
use alloy_primitives::{eip191_hash_message, Address, U256};
use k256::{
    ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey},
    elliptic_curve::{ops::Reduce, sec1::ToEncodedPoint},
    FieldBytes, Scalar, SecretKey, U256 as CurveUint,
};
use std::{cell::OnceCell, fmt};
use zeroize::Zeroizing;

/// Viewing and detection capabilities for an EVM account's v1 receiving address.
/// Keep the private keys local or share each only with its intended delegate.
pub struct DerivedReceivingKeys {
    owner: Address,
    public_keys: ReceivingKeys,
    viewing_private_key: Zeroizing<[u8; 32]>,
    detection_key: Zeroizing<[u8; 32]>,
}

impl DerivedReceivingKeys {
    pub fn owner_address(&self) -> Address {
        self.owner
    }

    pub fn public_keys(&self) -> &ReceivingKeys {
        &self.public_keys
    }

    pub fn receiving_address(&self) -> ReceivingAddress {
        ReceivingAddress {
            owner_address: U256::from_be_slice(self.owner.as_slice()),
            keys: Some(self.public_keys.clone()),
        }
    }

    pub fn viewing_private_key(&self) -> &[u8; 32] {
        &self.viewing_private_key
    }

    pub fn detection_key(&self) -> &[u8; 32] {
        &self.detection_key
    }
}

impl fmt::Debug for DerivedReceivingKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedReceivingKeys")
            .field("owner_address", &self.owner)
            .field("public_keys", &self.public_keys)
            .finish_non_exhaustive()
    }
}

/// Build the fixed v1 message for EIP-191 personal signing.
pub fn build_receiving_key_message(owner: &str) -> Result<String, String> {
    Ok(message_for_owner(parse_owner(owner)?))
}

/// Verify a raw EIP-191 signature for `owner` and derive the v1 receiving capabilities.
/// Accepts 65-byte signatures with Ethereum recovery parity and 64-byte EIP-2098 signatures.
pub fn derive_receiving_keys_from_signature(
    owner: &str,
    signature: &[u8],
) -> Result<DerivedReceivingKeys, String> {
    let owner = parse_owner(owner)?;
    let material = canonical_material(owner, signature)?;
    let root = receiving_root(owner, &material[..])?;
    derive_receiving_keys(owner, &root)
}

fn parse_owner(owner: &str) -> Result<Address, String> {
    if !owner.starts_with("0x") {
        return Err("WALLET_INVALID_OWNER".into());
    }
    let short = ReceivingAddress::parse(owner).map_err(|_| "WALLET_INVALID_OWNER")?;
    Ok(Address::from_slice(
        &short.owner_address.to_be_bytes::<32>()[12..],
    ))
}

fn message_for_owner(owner: Address) -> String {
    format!(
        "Invisi Privacy Receiving Keys v1\nAccount: {}\nPurpose: derive viewing and detection keys only.",
        hex_value(owner.as_slice())
    )
}

fn canonical_material(owner: Address, signature: &[u8]) -> Result<Zeroizing<[u8; 64]>, String> {
    let mut material = Zeroizing::new([0; 64]);
    let mut parity = match signature.len() {
        65 => {
            material.copy_from_slice(&signature[..64]);
            match signature[64] {
                0 | 27 => false,
                1 | 28 => true,
                _ => return Err("WALLET_INVALID_RECEIVING_SIGNATURE".into()),
            }
        }
        64 => {
            material.copy_from_slice(signature);
            let parity = material[32] & 0x80 != 0;
            material[32] &= 0x7f;
            parity
        }
        _ => return Err("WALLET_INVALID_RECEIVING_SIGNATURE".into()),
    };
    let mut signature =
        Signature::from_slice(&material[..]).map_err(|_| "WALLET_INVALID_RECEIVING_SIGNATURE")?;
    if let Some(low_s) = signature.normalize_s() {
        signature = low_s;
        let normalized = Zeroizing::new(<[u8; 64]>::from(signature.to_bytes()));
        material.copy_from_slice(&normalized[..]);
        parity = !parity;
    }
    let digest = eip191_hash_message(message_for_owner(owner));
    let verifying = VerifyingKey::recover_from_prehash(
        digest.as_slice(),
        &signature,
        RecoveryId::new(parity, false),
    )
    .map_err(|_| "WALLET_INVALID_RECEIVING_SIGNATURE")?;
    if owner_for_key(&verifying) != owner {
        return Err("WALLET_ACCOUNT_MISMATCH".into());
    }
    Ok(material)
}

fn receiving_root(owner: Address, material: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    hkdf(material, b"Invisi.ReceivingRoot.v1", owner.as_slice())
}

pub(super) fn viewing_from_root(root: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, String> {
    for counter in 0u32..=u32::MAX {
        let candidate = hkdf(root, b"Invisi.WalletViewingKey.v1", &counter.to_be_bytes())?;
        if SecretKey::from_slice(&candidate[..]).is_ok() {
            return Ok(candidate);
        }
    }
    Err("PRIVACY_KDF_EXHAUSTED".into())
}

fn detection_seed(root: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, String> {
    hkdf(root, b"Invisi.WalletDetectionSeed.v1", b"")
}

pub(super) fn detection_from_root(root: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, String> {
    let seed = detection_seed(root)?;
    let modulus = U256::from_str_radix(
        "2111115437357092606062206234695386632838870926408408195193685246394721360383",
        10,
    )
    .expect("fixed Decaf377 scalar modulus")
    .to_le_bytes::<32>();
    for counter in 0u32..=u32::MAX {
        let mut candidate = hkdf(
            &seed[..],
            b"Invisi.WalletDetectionKey.v1",
            &counter.to_be_bytes(),
        )?;
        candidate[31] &= 7;
        if candidate.iter().any(|&byte| byte != 0)
            && candidate.iter().rev().cmp(modulus.iter().rev()).is_lt()
        {
            return Ok(candidate);
        }
    }
    Err("PRIVACY_KDF_EXHAUSTED".into())
}

pub(super) fn derive_receiving_keys(
    owner: Address,
    root: &[u8; 32],
) -> Result<DerivedReceivingKeys, String> {
    let viewing_private_key = viewing_from_root(root)?;
    let viewing = SecretKey::from_slice(&viewing_private_key[..])
        .map_err(|_| "PRIVACY_INVALID_VIEWING_KEY")?;
    let mut viewing_public_key = [0; 33];
    viewing_public_key.copy_from_slice(viewing.public_key().to_encoded_point(true).as_bytes());
    let detection_key = detection_from_root(root)?;
    let clue_key = crate::fmd::derive_clue_key(&detection_key[..])
        .map_err(|_| "WALLET_INVALID_DETECTION_KEY")?;
    Ok(DerivedReceivingKeys {
        owner,
        public_keys: ReceivingKeys {
            viewing_public_key,
            clue_key,
        },
        viewing_private_key,
        detection_key,
    })
}

fn owner_for_key(key: &VerifyingKey) -> Address {
    Address::from_raw_public_key(&key.to_encoded_point(false).as_bytes()[1..])
}

fn sign_receiving_message(key: &SigningKey, owner: Address) -> Result<Zeroizing<[u8; 65]>, String> {
    let digest = eip191_hash_message(message_for_owner(owner));
    sign_receiving_digest(key, &digest.0)
}

fn sign_receiving_digest(
    key: &SigningKey,
    digest: &[u8; 32],
) -> Result<Zeroizing<[u8; 65]>, String> {
    // k256 uses the supplied bytes for nonce generation. RFC6979 bits2octets
    // reduces the digest modulo the curve order before that step.
    let reduced =
        <Scalar as Reduce<CurveUint>>::reduce_bytes(&FieldBytes::from(*digest)).to_bytes();
    let (signature, recovery) = key
        .sign_prehash_recoverable(&reduced)
        .map_err(|_| "WALLET_SIGN_FAILED")?;
    if recovery.is_x_reduced() {
        return Err("WALLET_SIGN_FAILED".into());
    }
    let raw = Zeroizing::new(<[u8; 64]>::from(signature.to_bytes()));
    let mut encoded = Zeroizing::new([0; 65]);
    encoded[..64].copy_from_slice(&raw[..]);
    encoded[64] = recovery.to_byte() + 27;
    Ok(encoded)
}

pub(super) struct LocalWallet {
    pub(super) signing_key: SigningKey,
    pub(super) owner: Address,
    // Request batches may use the same receiving root for public material, detection, and opening.
    root: OnceCell<Result<Zeroizing<[u8; 32]>, String>>,
}

impl LocalWallet {
    pub(super) fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() != 32 {
            return Err("WALLET_INVALID_ACCOUNT_KEY".into());
        }
        let signing_key = SigningKey::from_slice(key).map_err(|_| "PRIVACY_INVALID_ACCOUNT_KEY")?;
        let owner = owner_for_key(signing_key.verifying_key());
        if owner == Address::ZERO {
            return Err("WALLET_INVALID_OWNER".into());
        }
        Ok(Self {
            signing_key,
            owner,
            root: OnceCell::new(),
        })
    }

    pub(super) fn root(&self) -> Result<&[u8; 32], String> {
        self.root
            .get_or_init(|| {
                let signature = sign_receiving_message(&self.signing_key, self.owner)?;
                // The signer itself supplied the owner and k256 already enforces low-s.
                receiving_root(self.owner, &signature[..64])
            })
            .as_deref()
            .map_err(Clone::clone)
    }
}

#[cfg(test)]
#[path = "receiving_tests.rs"]
mod tests;
