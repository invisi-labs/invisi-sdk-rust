//! Application-level quotation over the independent public RPC client.
use crate::rpc::{HttpTransport, RpcTransport};
use crate::sdk::{self, BroadcasterOptions, ChainState, PreparedBroadcaster};
pub use invisi_sdk_rpc::broadcaster::*;
use std::{ops::Deref, sync::Arc};

/// A quote target keeps its own authorization and persistence boundary.
pub trait BroadcasterQuoteTarget {
    #[doc(hidden)]
    fn apply_broadcaster_quote(
        &mut self,
        chain: Arc<dyn ChainState>,
        relay: Arc<dyn PreparedBroadcaster>,
        options: &BroadcasterOptions,
    ) -> sdk::Result<()>;
}

pub struct BroadcasterClient<T: RpcTransport> {
    rpc: Arc<invisi_sdk_rpc::broadcaster::BroadcasterClient<T>>,
}
impl BroadcasterClient<HttpTransport> {
    pub fn connect(configuration: Configuration) -> invisi_sdk_rpc::rpc::Result<Self> {
        invisi_sdk_rpc::broadcaster::BroadcasterClient::connect(configuration)
            .map(|rpc| Self { rpc: Arc::new(rpc) })
    }
}
impl<T: RpcTransport + 'static> BroadcasterClient<T> {
    pub fn new(configuration: Configuration, transport: T) -> invisi_sdk_rpc::rpc::Result<Self> {
        invisi_sdk_rpc::broadcaster::BroadcasterClient::new(configuration, transport)
            .map(|rpc| Self { rpc: Arc::new(rpc) })
    }
    pub fn from_rpc(rpc: invisi_sdk_rpc::broadcaster::BroadcasterClient<T>) -> Self {
        Self { rpc: Arc::new(rpc) }
    }
    pub fn rpc(&self) -> &invisi_sdk_rpc::broadcaster::BroadcasterClient<T> {
        &self.rpc
    }
    pub fn quote<Q: BroadcasterQuoteTarget>(
        &self,
        target: &mut Q,
        chain: Arc<dyn ChainState>,
        options: &BroadcasterOptions,
    ) -> sdk::Result<()> {
        target.apply_broadcaster_quote(chain, self.rpc.clone(), options)
    }
}
impl<T: RpcTransport> Deref for BroadcasterClient<T> {
    type Target = invisi_sdk_rpc::broadcaster::BroadcasterClient<T>;
    fn deref(&self) -> &Self::Target {
        &self.rpc
    }
}
impl BroadcasterQuoteTarget for sdk::PreparedTransaction {
    fn apply_broadcaster_quote(
        &mut self,
        chain: Arc<dyn ChainState>,
        relay: Arc<dyn PreparedBroadcaster>,
        options: &BroadcasterOptions,
    ) -> sdk::Result<()> {
        let quoted = self.quote_for_broadcaster(chain, relay, options)?;
        *self = quoted;
        Ok(())
    }
}
impl BroadcasterQuoteTarget for sdk::PreparedCredit {
    fn apply_broadcaster_quote(
        &mut self,
        chain: Arc<dyn ChainState>,
        relay: Arc<dyn PreparedBroadcaster>,
        options: &BroadcasterOptions,
    ) -> sdk::Result<()> {
        let quoted = self.quote_for_broadcaster(chain, relay, options)?;
        *self = quoted;
        Ok(())
    }
}
