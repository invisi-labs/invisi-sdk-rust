//! BN254 scalar-field encoding. Reduction helpers must not be used to validate canonical wire inputs.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

pub fn bytes_to_field(b: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(b)
}

pub fn field_to_bytes_be(fr: Fr) -> [u8; 32] {
    let bigint = fr.into_bigint();
    // ark-ff 0.4 BigInteger only provides to_bytes_le; reverse for big-endian.
    let mut bytes = bigint.to_bytes_le();
    bytes.reverse();
    let mut out = [0u8; 32];
    let n = bytes.len();
    if n >= 32 {
        out.copy_from_slice(&bytes[n - 32..]);
    } else {
        out[32 - n..].copy_from_slice(&bytes);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_field_roundtrip() {
        let mut input = [0u8; 32];
        input[31] = 7;
        let f = bytes_to_field(&input);
        assert_eq!(field_to_bytes_be(f), input);
    }
}
