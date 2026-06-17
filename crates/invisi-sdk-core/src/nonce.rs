//! 随机 nonce 生成 — BN254 标量域内 32 字节 field element。
//! 对齐 invisi-sdk-ts `@invisi-labs/core` generateNonce。

use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand::rngs::OsRng;

use crate::field::field_to_bytes_be;

/// 生成一个落在 BN254 标量域内的随机 nonce，返回规范 32 字节大端编码。
pub fn generate_nonce() -> [u8; 32] {
    let fr = Fr::rand(&mut OsRng);
    field_to_bytes_be(fr)
}
