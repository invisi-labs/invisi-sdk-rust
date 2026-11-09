//! Random canonical 32-byte BN254 scalar-field nonces.
//! Matches TypeScript core generateNonce encoding.

use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand::rngs::OsRng;

use crate::field::field_to_bytes_be;

/// Sample a scalar uniformly and return its canonical 32-byte big-endian encoding.
pub fn generate_nonce() -> [u8; 32] {
    let fr = Fr::rand(&mut OsRng);
    field_to_bytes_be(fr)
}
