//! BN254 scalar field (fr) encoding helpers.
//!
//! 与 `../invisi-nexus/pkg/kms/field.go` 对应:
//!   bytesToField / int64ToField / uuidToField / addressToField
//!
//! 所有 field 元素用 `ark_bn254::Fr` 表示, modulus p ≈ 2^254 (BN254 scalar field).

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// 大端字节解码 → 模 p 归约. 用于 32-byte masterKey (其值可能 ≥ p).
///
/// 等价于 nexus bytesToField(b) = SetBytes(b) mod p.
pub fn bytes_to_field(b: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(b)
}

/// u64 → Fr. 用于 chain_id 和 domain tag (都 << p).
///
/// 等价于 nexus int64ToField(v).
pub fn u64_to_field(v: u64) -> Fr {
    Fr::from(v)
}

/// 16-byte UUID 大端解码 → Fr (128-bit < p, 不需要 mod).
///
/// 等价于 nexus uuidToField(u).
pub fn uuid_to_field(u: &[u8; 16]) -> Fr {
    Fr::from_be_bytes_mod_order(u)
}

/// 20-byte EVM 地址大端解码 → Fr (160-bit < p, 不需要 mod).
///
/// 等价于 nexus addressToField(a).
pub fn address_to_field(a: &[u8; 20]) -> Fr {
    Fr::from_be_bytes_mod_order(a)
}

/// Fr → 32 字节大端编码. 输出永远 32 字节 (即使前缀全零).
///
/// 等价于 nexus FieldToHex32 的字节版本 (不带 "0x" 前缀).
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
    fn u64_to_field_basic() {
        assert_eq!(u64_to_field(0), Fr::from(0u64));
        assert_eq!(u64_to_field(1), Fr::from(1u64));
        assert_eq!(u64_to_field(u64::MAX), Fr::from(u64::MAX));
    }

    #[test]
    fn bytes_field_roundtrip() {
        let mut input = [0u8; 32];
        input[31] = 7;
        let f = bytes_to_field(&input);
        assert_eq!(field_to_bytes_be(f), input);
    }

    #[test]
    fn uuid_field_basic() {
        let uuid = [0u8; 16];
        assert_eq!(uuid_to_field(&uuid), Fr::from(0u64));
        let mut uuid2 = [0u8; 16];
        uuid2[15] = 1;
        assert_eq!(uuid_to_field(&uuid2), Fr::from(1u64));
    }

    #[test]
    fn address_field_basic() {
        let addr = [0u8; 20];
        assert_eq!(address_to_field(&addr), Fr::from(0u64));
    }
}
