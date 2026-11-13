//! Application-level Broadcaster lifecycle over the independent public RPC client.
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

/// Submission keeps the target's storage and lifecycle boundary.
pub trait BroadcasterSubmitTarget {
    #[doc(hidden)]
    fn submit_for_client(
        &mut self,
        chain: &dyn ChainState,
        relay: &dyn PreparedBroadcaster,
    ) -> sdk::Result<Status>;
}
/// Cancellation keeps reservation reconciliation inside the managed target.
pub trait BroadcasterCancelTarget {
    #[doc(hidden)]
    fn cancel_for_client(&mut self, relay: &dyn PreparedBroadcaster) -> sdk::Result<Status>;
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
    pub fn submit<Q: BroadcasterSubmitTarget>(
        &self,
        target: &mut Q,
        chain: &dyn ChainState,
    ) -> sdk::Result<Status> {
        target.submit_for_client(chain, self.rpc.as_ref())
    }
    pub fn cancel<Q: BroadcasterCancelTarget>(&self, target: &mut Q) -> sdk::Result<Status> {
        target.cancel_for_client(self.rpc.as_ref())
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

macro_rules! prepared_target {
    ($target:ty) => {
        impl BroadcasterSubmitTarget for $target {
            fn submit_for_client(&mut self, chain: &dyn ChainState, relay: &dyn PreparedBroadcaster) -> sdk::Result<Status> {
                self.submit_for_broadcaster(chain, relay)
            }
        }
        impl BroadcasterCancelTarget for $target {
            fn cancel_for_client(&mut self, relay: &dyn PreparedBroadcaster) -> sdk::Result<Status> {
                let saved = self.broadcaster_state().ok_or("saved broadcaster context required")?;
                let id = saved.submission_id.as_deref().ok_or("submission ID unknown; recover the previously attempted submission before cancellation")?;
                saved.cancel(relay, id)
            }
        }
    }
}
prepared_target!(sdk::PreparedTransaction);
prepared_target!(sdk::PreparedCredit);
