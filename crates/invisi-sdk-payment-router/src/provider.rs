use crate::{ensure, Error, Result};
use alloy_primitives::{Address, B256, U256};
use invisi_sdk_protocol::protocol::TransactionCall;
use serde_json::{json, Value};
use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
};
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouterBlock {
    pub number: u64,
    pub hash: B256,
    pub timestamp: u64,
}
/// All state reads, calls and gas estimates are explicitly pinned to the same block.
pub trait RouterProvider: Send + Sync {
    /// EOA transaction nonce at the exact preflight block, independent of account action nonce.
    fn nonce_at(&self, _target: Address, _block: u64) -> BoxFuture<'_, Result<u64>> {
        Box::pin(async { Err(Error::Invalid("provider does not support EOA nonce reads")) })
    }

    fn storage_at(
        &self,
        _target: Address,
        _slot: B256,
        _block: u64,
    ) -> BoxFuture<'_, Result<B256>> {
        Box::pin(async {
            Err(Error::Invalid(
                "provider does not support account storage reads",
            ))
        })
    }

    fn call_authorized<'a>(
        &'a self,
        call: TransactionCall,
        from: Address,
        block: u64,
        auth: &'a [crate::canonical::SignedAuthorization],
    ) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            ensure(
                auth.is_empty(),
                "provider does not support EIP-7702 simulation",
            )?;
            self.call(call, Some(from), block).await
        })
    }
    fn estimate_gas_authorized<'a>(
        &'a self,
        call: TransactionCall,
        from: Address,
        block: u64,
        auth: &'a [crate::canonical::SignedAuthorization],
    ) -> BoxFuture<'a, Result<U256>> {
        Box::pin(async move {
            ensure(
                auth.is_empty(),
                "provider does not support EIP-7702 simulation",
            )?;
            self.estimate_gas(call, from, block).await
        })
    }

    fn chain_id(&self) -> BoxFuture<'_, Result<u64>>;
    fn block(&self, number: Option<u64>) -> BoxFuture<'_, Result<RouterBlock>>;
    fn code(&self, target: Address, block: u64) -> BoxFuture<'_, Result<Vec<u8>>>;
    fn call(
        &self,
        call: TransactionCall,
        from: Option<Address>,
        block: u64,
    ) -> BoxFuture<'_, Result<Vec<u8>>>;
    fn estimate_gas(
        &self,
        call: TransactionCall,
        from: Address,
        block: u64,
    ) -> BoxFuture<'_, Result<U256>>;
}
/// Async JSON-RPC provider for an explicitly supplied Ethereum endpoint.
/// Errors intentionally exclude URLs, response bodies and transport credentials.
pub struct HttpRouterProvider {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    sequence: AtomicU64,
}
impl HttpRouterProvider {
    pub fn new(endpoint: &str) -> Result<Self> {
        let endpoint =
            reqwest::Url::parse(endpoint).map_err(|_| Error::Invalid("invalid RPC URL"))?;
        ensure(
            ["http", "https"].contains(&endpoint.scheme())
                && endpoint.host_str().is_some()
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.fragment().is_none(),
            "invalid RPC URL",
        )?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| Error::Invalid("RPC transport unavailable"))?;
        Ok(Self {
            client,
            endpoint,
            sequence: AtomicU64::new(0),
        })
    }
    async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let id = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Error::Invalid("RPC request ID exhausted"))?
            + 1;
        let response = self
            .client
            .post(self.endpoint.clone())
            .json(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .send()
            .await
            .map_err(|_| Error::Provider("RPC request failed".into()))?;
        ensure(response.status().is_success(), "RPC HTTP request failed")?;
        let value: Value = response
            .json()
            .await
            .map_err(|_| Error::Invalid("invalid RPC response"))?;
        ensure(
            value.is_object() && value["jsonrpc"] == "2.0" && value["id"].as_u64() == Some(id),
            "RPC response envelope mismatch",
        )?;
        ensure(value.get("error").is_none(), "RPC call failed")?;
        value
            .get("result")
            .cloned()
            .ok_or(Error::Invalid("missing RPC result"))
    }
}
fn quantity(v: &Value) -> Result<U256> {
    let s = v
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or(Error::Invalid("invalid RPC quantity"))?;
    ensure(
        !s.is_empty() && (s.len() == 1 || !s.starts_with('0')),
        "noncanonical RPC quantity",
    )?;
    U256::from_str_radix(s, 16).map_err(|_| Error::Invalid("invalid RPC quantity"))
}
fn u64_quantity(v: &Value) -> Result<u64> {
    u64::try_from(quantity(v)?).map_err(|_| Error::Invalid("RPC integer overflow"))
}
pub(crate) fn bytes(v: &Value) -> Result<Vec<u8>> {
    hex::decode(
        v.as_str()
            .and_then(|s| s.strip_prefix("0x"))
            .ok_or(Error::Invalid("invalid hex bytes"))?,
    )
    .map_err(|_| Error::Invalid("invalid hex bytes"))
}
fn transaction(call: TransactionCall, from: Option<Address>) -> Value {
    let mut v = json!({"to":call.to,"data":format!("0x{}",hex::encode(call.data)),"value":format!("{:#x}",call.value)});
    if let Some(a) = from {
        v["from"] = json!(a);
    }
    v
}
impl RouterProvider for HttpRouterProvider {
    fn nonce_at(&self, target: Address, block: u64) -> BoxFuture<'_, Result<u64>> {
        Box::pin(async move {
            u64_quantity(
                &self
                    .rpc(
                        "eth_getTransactionCount",
                        json!([target, format!("0x{block:x}")]),
                    )
                    .await?,
            )
        })
    }

    fn storage_at(&self, target: Address, slot: B256, block: u64) -> BoxFuture<'_, Result<B256>> {
        Box::pin(async move {
            let value = bytes(
                &self
                    .rpc(
                        "eth_getStorageAt",
                        json!([target, slot, format!("0x{block:x}")]),
                    )
                    .await?,
            )?;
            ensure(value.len() == 32, "invalid account storage word")?;
            Ok(B256::from_slice(&value))
        })
    }

    fn call_authorized<'a>(
        &'a self,
        call: TransactionCall,
        from: Address,
        block: u64,
        auth: &'a [crate::canonical::SignedAuthorization],
    ) -> BoxFuture<'a, Result<Vec<u8>>> {
        Box::pin(async move {
            let mut tx = transaction(call, Some(from));
            if !auth.is_empty() {
                tx["authorizationList"] = json!(auth);
                tx["type"] = json!("0x4");
            }
            bytes(
                &self
                    .rpc("eth_call", json!([tx, format!("0x{block:x}")]))
                    .await?,
            )
        })
    }
    fn estimate_gas_authorized<'a>(
        &'a self,
        call: TransactionCall,
        from: Address,
        block: u64,
        auth: &'a [crate::canonical::SignedAuthorization],
    ) -> BoxFuture<'a, Result<U256>> {
        Box::pin(async move {
            let mut tx = transaction(call, Some(from));
            if !auth.is_empty() {
                tx["authorizationList"] = json!(auth);
                tx["type"] = json!("0x4");
            }
            quantity(
                &self
                    .rpc("eth_estimateGas", json!([tx, format!("0x{block:x}")]))
                    .await?,
            )
        })
    }

    fn chain_id(&self) -> BoxFuture<'_, Result<u64>> {
        Box::pin(async { u64_quantity(&self.rpc("eth_chainId", json!([])).await?) })
    }
    fn block(&self, number: Option<u64>) -> BoxFuture<'_, Result<RouterBlock>> {
        Box::pin(async move {
            let block = self
                .rpc(
                    "eth_getBlockByNumber",
                    json!([
                        number
                            .map(|n| format!("0x{n:x}"))
                            .unwrap_or("latest".into()),
                        false
                    ]),
                )
                .await?;
            let hash = bytes(&block["hash"])?;
            ensure(hash.len() == 32, "missing canonical chain block")?;
            let result = RouterBlock {
                number: u64_quantity(&block["number"])?,
                timestamp: u64_quantity(&block["timestamp"])?,
                hash: B256::from_slice(&hash),
            };
            ensure(
                result.number < (1 << 53) && result.timestamp < (1 << 53),
                "unsafe canonical block integer",
            )?;
            Ok(result)
        })
    }
    fn code(&self, target: Address, block: u64) -> BoxFuture<'_, Result<Vec<u8>>> {
        Box::pin(async move {
            bytes(
                &self
                    .rpc("eth_getCode", json!([target, format!("0x{block:x}")]))
                    .await?,
            )
        })
    }
    fn call(
        &self,
        call: TransactionCall,
        from: Option<Address>,
        block: u64,
    ) -> BoxFuture<'_, Result<Vec<u8>>> {
        Box::pin(async move {
            bytes(
                &self
                    .rpc(
                        "eth_call",
                        json!([transaction(call, from), format!("0x{block:x}")]),
                    )
                    .await?,
            )
        })
    }
    fn estimate_gas(
        &self,
        call: TransactionCall,
        from: Address,
        block: u64,
    ) -> BoxFuture<'_, Result<U256>> {
        Box::pin(async move {
            quantity(
                &self
                    .rpc(
                        "eth_estimateGas",
                        json!([transaction(call, Some(from)), format!("0x{block:x}")]),
                    )
                    .await?,
            )
        })
    }
}
