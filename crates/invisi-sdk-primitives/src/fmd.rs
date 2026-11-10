//! Fixed decaf377-fmd 2.1.1 profile: full 24-bit precision and 68-byte clues.
use crate::note::{ModelError, ModelResult};
use decaf377_fmd::{Clue, ClueKey, DetectionKey, Precision};
use rand::RngCore;
use zeroize::Zeroizing;
pub const CLUE_PRECISION: u8 = 24;
pub const CLUE_BYTES: usize = 68;
fn detection_key(key: &[u8]) -> ModelResult<DetectionKey> {
    let bytes: [u8; 32] = key
        .try_into()
        .map_err(|_| ModelError::Invalid("detection key length"))?;
    if bytes == [0u8; 32] {
        return Err(ModelError::Invalid("zero detection key"));
    }
    DetectionKey::from_bytes(bytes).map_err(|_| ModelError::Invalid("canonical detection key"))
}
pub fn derive_clue_key(key: &[u8]) -> ModelResult<[u8; 32]> {
    Ok(detection_key(key)?.clue_key().0)
}
pub fn validate_clue_key(key: &[u8]) -> ModelResult<()> {
    let bytes: [u8; 32] = key
        .try_into()
        .map_err(|_| ModelError::Invalid("clue key length"))?;
    if bytes == [0u8; 32] {
        return Err(ModelError::Invalid("identity clue key"));
    }
    ClueKey(bytes)
        .expand()
        .map_err(|_| ModelError::Invalid("canonical clue key"))?;
    Ok(())
}
/// Seed reuse links clues. Each production call must receive independently generated entropy.
pub fn create_clue_from_seed(key: &[u8], seed: &[u8]) -> ModelResult<Vec<u8>> {
    validate_clue_key(key)?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| ModelError::Invalid("clue seed length"))?;
    let key = ClueKey(
        key.try_into()
            .map_err(|_| ModelError::Invalid("clue key length"))?,
    );
    let expanded = key
        .expand()
        .map_err(|_| ModelError::Invalid("canonical clue key"))?;
    let precision = Precision::try_from(CLUE_PRECISION).expect("fixed supported precision");
    let clue = expanded
        .create_clue_deterministic(precision, seed)
        .map_err(|_| ModelError::Invalid("clue seed"))?;
    Ok(clue.into())
}
pub fn create_clue(key: &[u8]) -> ModelResult<Vec<u8>> {
    let mut seed = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *seed);
    create_clue_from_seed(key, &*seed)
}
pub fn detect_clue(key: &[u8], clue: &[u8]) -> ModelResult<bool> {
    let detector = detection_key(key)?;
    if clue.len() != CLUE_BYTES {
        return Err(ModelError::Invalid("clue length"));
    }
    if clue[64] != CLUE_PRECISION {
        return Ok(false);
    }
    let clue = Clue::try_from(clue).map_err(|_| ModelError::Invalid("clue length"))?;
    Ok(detector.examine(&clue))
}
