use super::{
    BroadcasterQuery, CanonicalChain, Error, HttpTransport, ProtocolRpcClient, Result, RpcTransport,
};
use crate::broadcaster::{BroadcasterClient, Configuration};
use alloy_primitives::Address;
use std::collections::BTreeSet;

impl<T: RpcTransport, C: CanonicalChain> ProtocolRpcClient<T, C> {
    /// Discover registered operators that currently support this token, without quoting a transaction.
    pub fn discover_broadcasters(
        &self,
        token: Address,
    ) -> Result<Vec<BroadcasterClient<HttpTransport>>> {
        self.discover_broadcasters_with_transport(token, |configuration| {
            HttpTransport::new(&configuration.endpoint)?.with_response_limit(65536)
        })
    }

    /// App transports retain their own network policy; registry identity still pins every probe.
    pub fn discover_broadcasters_with_transport<R: RpcTransport>(
        &self,
        token: Address,
        mut transport: impl FnMut(&Configuration) -> Result<R>,
    ) -> Result<Vec<BroadcasterClient<R>>> {
        if token == Address::ZERO {
            return Err(Error::Invalid("nonzero broadcaster token required"));
        }
        let chain_id = self.deployment().chain_id()?;
        let protocol = self.deployment().protocol.address;
        let mut query = BroadcasterQuery {
            enabled: Some(true),
            ..Default::default()
        };
        let mut clients = Vec::new();
        let mut seen = BTreeSet::new();
        loop {
            let page = self.get_broadcasters(&query)?;
            query.block.get_or_insert(page.block);
            for entry in page.broadcasters {
                if !entry.enabled || !seen.insert(entry.operator) {
                    continue;
                }
                let configuration = Configuration {
                    endpoint: entry.endpoint,
                    quote_signer: entry.quote_signer,
                    fee_recipient: entry.fee_recipient,
                };
                let client = match configuration
                    .validate()
                    .and_then(|_| transport(&configuration))
                    .and_then(|transport| BroadcasterClient::new(configuration, transport))
                {
                    Ok(client) => client,
                    Err(_) => continue,
                };
                if client
                    .supports_token(token, chain_id, protocol)
                    .unwrap_or(false)
                {
                    clients.push(client);
                }
            }
            match page.next {
                None => return Ok(clients),
                Some(next) if query.after.is_some_and(|previous| next <= previous) => {
                    return Err(Error::Invalid("nonadvancing broadcaster cursor"))
                }
                Some(next) => query.after = Some(next),
            }
        }
    }
}
