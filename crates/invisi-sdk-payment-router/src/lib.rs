#![doc = include_str!("../README.md")]
mod adapters;
mod client;
mod codecs;
mod provider;
mod types;
pub use adapters::*;
pub use client::*;
pub use codecs::*;
pub use provider::*;
pub use types::*;

/// Reviewed router ABI from invisi-periphery b246f29 and native 0x calls.
/// The core tuple matches InvisiCore exactly.
pub const PAYMENT_ROUTER_ABI: &str = include_str!("payment-router.abi.json");
pub const ZERO_EX_PAYMENT_ROUTER_ABI: &str = include_str!("router.abi.json");
pub mod abi {
    alloy_sol_types::sol!(
        #[sol(all_derives)]
        Router,
        "src/router.abi.json"
    );
    alloy_sol_types::sol! {
        #[sol(all_derives)]
        struct Slippage { address recipient; address buyToken; uint256 minAmountOut; }
        #[sol(all_derives)]
        function execute(Slippage slippage, bytes[] actions, bytes32 zid) payable returns(bool);
        #[sol(all_derives)]
        function exec(address operator,address token,uint256 amount,address target,bytes data) payable returns(bytes);
        #[sol(all_derives)]
        function NATIVE_CHECK(uint256 deadline,uint256 msgValue);
        #[sol(all_derives)]
        function ownerOf(uint256 id) view returns(address);
        #[sol(all_derives)]
        function quoteExactOutput(bytes path,uint256 amountOut) returns(uint256 amountIn,uint160[] sqrtPriceX96AfterList,uint32[] initializedTicksCrossedList,uint256 gasEstimate);
    }
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("invalid ABI: {0}")]
    Abi(#[from] alloy_sol_types::Error),
    #[error("provider: {0}")]
    Provider(String),
    #[error("SDK preparation: {0}")]
    Preparation(String),
    #[error("quote cancelled")]
    Cancelled,
    #[error("0x quote HTTP {0}")]
    Http(u16),
}
pub type Result<T> = std::result::Result<T, Error>;
fn ensure(ok: bool, message: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(message))
    }
}
fn nonzero(a: alloy_primitives::Address) -> Result<()> {
    ensure(!a.is_zero(), "address must be nonzero")
}
fn uint(
    value: alloy_primitives::U256,
    bits: usize,
    positive: bool,
    label: &'static str,
) -> Result<()> {
    ensure(
        (!positive || !value.is_zero())
            && (bits == 256 || value < (alloy_primitives::U256::from(1) << bits)),
        label,
    )
}
