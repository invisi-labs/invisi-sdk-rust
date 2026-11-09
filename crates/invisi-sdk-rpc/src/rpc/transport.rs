use super::{Error, Result};
use serde_json::{json, Value};
use std::{
    io::Read,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

/// A transport returns the complete JSON-RPC envelope, retaining request/response correlation.
pub trait RpcTransport: Send + Sync {
    fn send(&self, request: &Value) -> Result<Value>;
}
pub struct HttpTransport {
    client: reqwest::blocking::Client,
    endpoint: reqwest::Url,
    max_response_bytes: u64,
    headers: reqwest::header::HeaderMap,
}
impl HttpTransport {
    pub fn new(endpoint: &str) -> Result<Self> {
        let endpoint =
            reqwest::Url::parse(endpoint).map_err(|e| Error::Transport(e.to_string()))?;
        if !["http", "https"].contains(&endpoint.scheme())
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(Error::Invalid("invalid RPC URL"));
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(Self {
            client,
            endpoint,
            max_response_bytes: 32 << 20,
            headers: reqwest::header::HeaderMap::new(),
        })
    }
    /// Lower the transport response bound for services with smaller envelopes.
    pub fn with_response_limit(mut self, bytes: u64) -> Result<Self> {
        if bytes == 0 || bytes > self.max_response_bytes {
            return Err(Error::Invalid("invalid response bound"));
        }
        self.max_response_bytes = bytes;
        Ok(self)
    }
    pub fn with_headers(mut self, headers: reqwest::header::HeaderMap) -> Self {
        self.headers = headers;
        self
    }
    pub fn protocol(endpoint: &str, chain_id: u64) -> Result<Self> {
        if chain_id == 0 {
            return Err(Error::Invalid("zero chain id"));
        }
        let mut transport = Self::new(endpoint)?;
        let path = transport.endpoint.path().trim_end_matches('/');
        let target = format!("/v1/chains/{chain_id}");
        let path = if path.ends_with("/v1") {
            format!("{path}/chains/{chain_id}")
        } else if path.ends_with(&target) {
            path.to_owned()
        } else {
            return Err(Error::Invalid("Protocol RPC endpoint chain mismatch"));
        };
        transport.endpoint.set_path(&path);
        Ok(transport)
    }
}
impl RpcTransport for HttpTransport {
    fn send(&self, request: &Value) -> Result<Value> {
        let response = self
            .client
            .post(self.endpoint.clone())
            .headers(self.headers.clone())
            .json(request)
            .send()
            .map_err(|e| Error::Transport(e.to_string()))?;
        if !response.status().is_success() {
            return Err(Error::Http {
                status: response.status().as_u16(),
                retry_after: response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned),
            });
        }
        let mut bytes = Vec::new();
        response
            .take(self.max_response_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| Error::Transport(e.to_string()))?;
        if bytes.len() as u64 > self.max_response_bytes {
            return Err(Error::Invalid("RPC response too large"));
        }
        serde_json::from_slice(&bytes).map_err(|e| Error::Transport(e.to_string()))
    }
}
pub struct JsonRpc<T> {
    pub transport: T,
    sequence: AtomicU64,
}
impl<T: RpcTransport> JsonRpc<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            sequence: AtomicU64::new(0),
        }
    }
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let id = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| Error::Invalid("request id exhausted"))?
            + 1;
        let response = self
            .transport
            .send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?;
        if !response.is_object()
            || response["jsonrpc"] != "2.0"
            || response["id"].as_u64() != Some(id)
        {
            return Err(Error::Invalid("JSON-RPC response envelope mismatch"));
        }
        if response.get("error").is_some() && response.get("result").is_some() {
            return Err(Error::Invalid("ambiguous JSON-RPC response"));
        }
        if let Some(error) = response.get("error") {
            let code = error["code"]
                .as_i64()
                .ok_or(Error::Invalid("invalid RPC error"))?;
            let message = error["message"]
                .as_str()
                .ok_or(Error::Invalid("invalid RPC error"))?
                .to_owned();
            return Err(Error::Remote {
                code,
                message,
                data: error.get("data").cloned(),
            });
        }
        response
            .get("result")
            .cloned()
            .ok_or(Error::Invalid("missing JSON-RPC result"))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredChain {
    pub chain_id: u64,
    pub protocol_version: String,
    pub rpc_path: String,
    pub rpc_url: String,
}
impl HttpTransport {
    /// Discover chain endpoints from the service /v1 HTTP resource, preserving the origin.
    pub fn discover_chains(&self) -> Result<Vec<DiscoveredChain>> {
        if !self.endpoint.path().trim_end_matches('/').ends_with("/v1") {
            return Err(Error::Invalid("chain discovery requires service /v1 URL"));
        }
        let response = self
            .client
            .get(self.endpoint.clone())
            .headers(self.headers.clone())
            .send()
            .map_err(|e| Error::Transport(e.to_string()))?;
        if !response.status().is_success() {
            return Err(Error::Http {
                status: response.status().as_u16(),
                retry_after: response
                    .headers()
                    .get("retry-after")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned),
            });
        }
        let mut bytes = Vec::new();
        response
            .take(self.max_response_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| Error::Transport(e.to_string()))?;
        if bytes.len() as u64 > self.max_response_bytes {
            return Err(Error::Invalid("RPC response too large"));
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|e| Error::Transport(e.to_string()))?;
        if value["apiVersion"] != "v1" {
            return Err(Error::Invalid("unsupported service version"));
        }
        let mut seen = std::collections::HashSet::new();
        value["chains"]
            .as_array()
            .ok_or(Error::Invalid("chain list required"))?
            .iter()
            .map(|row| {
                let text = row["chainId"]
                    .as_str()
                    .ok_or(Error::Invalid("chain id required"))?;
                let chain_id = super::uint(&Value::String(text.into()), 64)?;
                let rpc_path = format!("/v1/chains/{chain_id}");
                if chain_id == 0
                    || !seen.insert(chain_id)
                    || row["protocolVersion"] != "1"
                    || row["rpcPath"] != rpc_path
                {
                    return Err(Error::Invalid("invalid chain discovery entry"));
                }
                let mut endpoint = self.endpoint.clone();
                endpoint.set_path(&format!(
                    "{}/chains/{chain_id}",
                    endpoint.path().trim_end_matches('/')
                ));
                Ok(DiscoveredChain {
                    chain_id,
                    protocol_version: "1".into(),
                    rpc_path,
                    rpc_url: endpoint.to_string(),
                })
            })
            .collect()
    }
}
