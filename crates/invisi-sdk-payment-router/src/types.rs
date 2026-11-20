use crate::{ensure, nonzero, uint, Error, Result};
use alloy_primitives::{Address, B256, U256};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZeroExDeployment {
    pub allowance_holder_address: Address,
    pub settler_registry_address: Address,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentRouterDeployment {
    pub chain_id: u64,
    pub router_address: Address,
    pub core_address: Address,
    pub weth_address: Address,
    pub uniswap_router_address: Address,
    pub runtime_code_hash: Option<B256>,
    pub zero_ex: Option<ZeroExDeployment>,
}
impl PaymentRouterDeployment {
    pub fn validate(&self) -> Result<()> {
        ensure(self.chain_id > 0, "invalid chain ID")?;
        let mut addresses = vec![
            self.router_address,
            self.core_address,
            self.weth_address,
            self.uniswap_router_address,
        ];
        if let Some(z) = &self.zero_ex {
            addresses.extend([z.allowance_holder_address, z.settler_registry_address]);
        }
        let mut seen = std::collections::BTreeSet::new();
        for a in addresses {
            nonzero(a)?;
            ensure(seen.insert(a), "deployment addresses must be distinct")?;
        }
        Ok(())
    }
}
/// Explicit cancellation capability; cloning financial requests detaches their values.
#[derive(Clone, Default, Debug)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
}
impl CancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }
    pub fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::SeqCst) {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
    pub(crate) async fn cancelled(&self) {
        loop {
            let ready = self.notify.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            if self.check().is_err() {
                return;
            }
            ready.await;
        }
    }
}
#[derive(Clone, Debug)]
pub struct QuoteParameters {
    pub token_out: Address,
    pub amount_out: U256,
    pub max_input: U256,
    pub deadline: u64,
    pub slippage_bps: Option<u16>,
    pub cancellation: Option<CancellationToken>,
}
impl QuoteParameters {
    pub(crate) fn check(&self) -> Result<()> {
        if let Some(c) = &self.cancellation {
            c.check()?;
        }
        uint(self.amount_out, 128, true, "invalid funding amount")?;
        uint(self.max_input, 256, true, "invalid ETH budget")?;
        ensure(
            self.slippage_bps.unwrap_or(50) <= 10000,
            "invalid slippageBps",
        )
    }
}
#[derive(Clone, Debug)]
pub struct SwapQuoteRequest {
    pub parameters: QuoteParameters,
    pub deployment: PaymentRouterDeployment,
    pub now: u64,
    pub block_number: u64,
    pub settler_address: Option<Address>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapChannel {
    UniswapV3,
    ZeroEx,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SwapRoute {
    UniswapV3 {
        reverse_path: Vec<u8>,
    },
    ZeroEx {
        target: Address,
        data: Vec<u8>,
        settler_address: Address,
    },
}
impl SwapRoute {
    pub fn channel(&self) -> SwapChannel {
        match self {
            Self::UniswapV3 { .. } => SwapChannel::UniswapV3,
            Self::ZeroEx { .. } => SwapChannel::ZeroEx,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapQuote {
    pub chain_id: u64,
    pub router_address: Address,
    pub token_out: Address,
    pub amount_out: U256,
    pub estimated_input: U256,
    pub max_input: U256,
    pub deadline: u64,
    pub route: SwapRoute,
}
pub trait SwapQuoteAdapter: Send + Sync {
    fn channel(&self) -> SwapChannel;
    fn quote(&self, request: SwapQuoteRequest)
        -> crate::provider::BoxFuture<'_, Result<SwapQuote>>;
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterSimulation {
    pub gas_estimate: U256,
    pub eth_spent: U256,
    pub eth_refunded: U256,
}
