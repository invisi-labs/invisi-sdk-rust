//! Explicit initialized discovery/support receipts, scoped to one native reader.
use super::*;
use crate::rpc::{CanonicalChain, ProtocolRpcClient, RpcTransport};
use std::sync::atomic::{AtomicBool, Ordering};

/// Reuses initialized registry discovery and token support. This does not cache
/// current submission policy: stock clients still query service requirements.
/// A different reader/token or a retired deployment receipt never matches.
pub struct InitializedBroadcasters {
    chain: Arc<dyn ChainState>,
    deployment: ProtocolDeployment,
    token: Address,
    clients: Vec<Arc<dyn PreparedBroadcaster>>,
    valid: AtomicBool,
}
impl InitializedBroadcasters {
    fn binding(chain: &Arc<dyn ChainState>) -> Result<ProtocolDeployment> {
        chain
            .self_contained_shield_capability()
            .ok_or("initialized native deployment receipt required")?;
        chain
            .preparation_deployment()
            .ok_or_else(|| "deployment pins required".into())
    }
    /// A configured endpoint probes token support once, without registry discovery.
    pub fn configured<T: RpcTransport + 'static>(
        client: invisi_sdk_rpc::broadcaster::BroadcasterClient<T>,
        chain: Arc<dyn ChainState>,
        token: Address,
    ) -> Result<Self> {
        let deployment = Self::binding(&chain)?;
        if !client
            .supports_token(token, chain.context().chain_id, deployment.protocol.address)
            .map_err(|e| e.to_string())?
        {
            return Err("broadcaster does not support token".into());
        }
        if Self::binding(&chain)? != deployment {
            return Err("initialization binding changed during probe".into());
        }
        Ok(Self {
            chain,
            deployment,
            token,
            clients: vec![Arc::new(client)],
            valid: AtomicBool::new(true),
        })
    }
    /// Discover registered operators and authenticate their support exactly once.
    pub fn discover<T: RpcTransport, C: CanonicalChain>(
        protocol: &ProtocolRpcClient<T, C>,
        chain: Arc<dyn ChainState>,
        token: Address,
    ) -> Result<Self> {
        let deployment = Self::binding(&chain)?;
        if protocol.deployment() != &deployment {
            return Err("discovery deployment mismatch".into());
        }
        let clients = protocol
            .discover_broadcasters(token)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|client| Arc::new(client) as Arc<dyn PreparedBroadcaster>)
            .collect();
        if Self::binding(&chain)? != deployment {
            return Err("initialization binding changed during probe".into());
        }
        Ok(Self {
            chain,
            deployment,
            token,
            clients,
            valid: AtomicBool::new(true),
        })
    }
    pub fn invalidate(&self) {
        self.valid.store(false, Ordering::SeqCst);
        self.chain.invalidate_initialization();
    }
    /// None requests fresh discovery/support using the caller's current reader.
    pub fn clients_for(
        &self,
        chain: &Arc<dyn ChainState>,
        token: Address,
    ) -> Option<Vec<Arc<dyn PreparedBroadcaster>>> {
        if !self.valid.load(Ordering::SeqCst)
            || !Arc::ptr_eq(&self.chain, chain)
            || token != self.token
            || chain.self_contained_shield_capability().is_none()
            || chain.preparation_deployment().as_ref() != Some(&self.deployment)
        {
            return None;
        }
        let clients = self.clients.clone();
        (self.valid.load(Ordering::SeqCst) && chain.self_contained_shield_capability().is_some())
            .then_some(clients)
    }
    pub fn quote<Q: crate::broadcaster::BroadcasterQuoteTarget>(
        &self,
        target: &mut Q,
        chain: Arc<dyn ChainState>,
        options: &BroadcasterOptions,
    ) -> Result<()> {
        if crate::broadcaster::BroadcasterQuoteTarget::initialization_token(target)
            != Some(self.token)
        {
            return Err("initialized broadcaster target token mismatch".into());
        }
        let client = self
            .clients_for(&chain, self.token)
            .and_then(|clients| clients.into_iter().next())
            .ok_or("broadcaster initialization retired or empty; rediscover")?;
        target.apply_broadcaster_quote(chain, client, options)
    }
    pub fn submit<Q: crate::broadcaster::BroadcasterSubmitTarget>(
        &self,
        target: &mut Q,
        chain: &dyn ChainState,
    ) -> Result<invisi_sdk_rpc::broadcaster::Status> {
        if let Some(authority) =
            crate::broadcaster::BroadcasterSubmitTarget::frozen_broadcaster_authority(target)?
        {
            if authority.token != self.token || authority.context != self.chain.context() {
                return Err("frozen broadcaster pool scope mismatch".into());
            }
            let client = self
                .clients
                .iter()
                .find(|client| client.configuration() == authority.configuration)
                .ok_or("frozen broadcaster client is not owned by this pool")?;
            return target.submit_for_client(self.chain.as_ref(), client.as_ref());
        }
        if crate::broadcaster::BroadcasterSubmitTarget::initialization_token(target)
            != Some(self.token)
        {
            return Err("initialized broadcaster target token mismatch".into());
        }
        if !std::ptr::eq(Arc::as_ptr(&self.chain), chain)
            || self.clients_for(&self.chain, self.token).is_none()
        {
            return Err("broadcaster initialization retired; rediscover".into());
        }
        let client = self.clients.first().ok_or("no initialized broadcasters")?;
        target.submit_for_client(chain, client.as_ref())
    }
}
