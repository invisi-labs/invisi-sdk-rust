//! payer 侧 calldata 构建 — 对齐 @invisi-labs/payer build*Calldata。
//! ABI 编码用 alloy（Rust 版 viem）。

use alloy_sol_types::sol;

sol! {
    function approve(address spender, uint256 amount);
    function payOpen(bytes32 identityCommitment, uint256 amount, bytes32 nonce, uint256 treeId, bytes32 refundLink);
    function payBlind(bytes proof, bytes32 paymentCommitment, bytes32 changeCommitment, uint256 inputAmount, uint256 treeId, bytes32 refundLink);
}
