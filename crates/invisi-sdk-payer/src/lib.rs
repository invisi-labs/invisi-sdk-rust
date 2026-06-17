//! payer 侧 calldata 构建 — 对齐 @invisi-labs/payer build*Calldata。
//! ABI 编码用 alloy（Rust 版 viem）。

use alloy_sol_types::sol;

sol! {
    function approve(address spender, uint256 amount);
    function payOpen(bytes32 identityCommitment, uint256 amount, bytes32 nonce, uint256 treeId, bytes32 refundLink);
    function payBlind(bytes proof, bytes32 paymentCommitment, bytes32 changeCommitment, uint256 inputAmount, uint256 treeId, bytes32 refundLink);
}

use alloy_primitives::{Address, Bytes, FixedBytes, U256};
use alloy_sol_types::SolCall;

pub fn build_approve_calldata(spender: &[u8; 20], amount: &[u8; 32]) -> Vec<u8> {
    approveCall {
        spender: Address::from(*spender),
        amount: U256::from_be_bytes(*amount),
    }
    .abi_encode()
}

pub fn build_pay_open_calldata(
    identity_commitment: &[u8; 32],
    amount: &[u8; 32],
    nonce: &[u8; 32],
    tree_id: u64,
    refund_link: &[u8; 32],
) -> Vec<u8> {
    payOpenCall {
        identityCommitment: FixedBytes::from(*identity_commitment),
        amount: U256::from_be_bytes(*amount),
        nonce: FixedBytes::from(*nonce),
        treeId: U256::from(tree_id),
        refundLink: FixedBytes::from(*refund_link),
    }
    .abi_encode()
}

pub fn build_pay_blind_calldata(
    proof: &[u8],
    payment_commitment: &[u8; 32],
    change_commitment: &[u8; 32],
    input_amount: &[u8; 32],
    tree_id: u64,
    refund_link: &[u8; 32],
) -> Vec<u8> {
    payBlindCall {
        proof: Bytes::copy_from_slice(proof),
        paymentCommitment: FixedBytes::from(*payment_commitment),
        changeCommitment: FixedBytes::from(*change_commitment),
        inputAmount: U256::from_be_bytes(*input_amount),
        treeId: U256::from(tree_id),
        refundLink: FixedBytes::from(*refund_link),
    }
    .abi_encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approve_calldata_matches_known_vector() {
        // spender = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8, amount = 1000 (0x3e8)
        let spender = hex_lit::<20>("70997970c51812dc3a010c7d01b50e0d17dc79c8");
        let mut amount = [0u8; 32];
        amount[30] = 0x03; amount[31] = 0xe8;
        let got = build_approve_calldata(&spender, &amount);
        let expected = concat_hex(&[
            "095ea7b3",
            "00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c8",
            "00000000000000000000000000000000000000000000000000000000000003e8",
        ]);
        assert_eq!(got, expected);
    }

    #[test]
    fn pay_blind_calldata_matches_cast() {
        let proof = vec![0xde, 0xad, 0xbe, 0xef];
        let pc = [0x33u8; 32];
        let cc = [0x44u8; 32];
        let mut input = [0u8; 32]; input[30] = 0x07; input[31] = 0xd0; // 2000
        let refund = [0u8; 32];
        let got = build_pay_blind_calldata(&proof, &pc, &cc, &input, 1, &refund);
        const GOLDEN: &str = "82d33b9b00000000000000000000000000000000000000000000000000000000000000c03333333333333333333333333333333333333333333333333333333333333333444444444444444444444444444444444444444444444444444444444444444400000000000000000000000000000000000000000000000000000000000007d0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004deadbeef00000000000000000000000000000000000000000000000000000000";
        assert_eq!(got, decode_hex(GOLDEN));
    }

    #[test]
    fn pay_open_calldata_matches_cast() {
        let identity = [0x11u8; 32];
        let mut amount = [0u8; 32]; amount[30] = 0x03; amount[31] = 0xe8; // 1000
        let nonce = [0x22u8; 32];
        let refund = [0u8; 32];
        let got = build_pay_open_calldata(&identity, &amount, &nonce, 1, &refund);
        const GOLDEN: &str = "8cf55984111111111111111111111111111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000000003e8222222222222222222222222222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(got, decode_hex(GOLDEN));
    }

    // test helpers
    fn hex_lit<const N: usize>(s: &str) -> [u8; N] {
        let v = decode_hex(s);
        let mut o = [0u8; N];
        o.copy_from_slice(&v);
        o
    }
    fn concat_hex(parts: &[&str]) -> Vec<u8> {
        parts.iter().flat_map(|p| decode_hex(p)).collect()
    }
    fn decode_hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
    }
}
