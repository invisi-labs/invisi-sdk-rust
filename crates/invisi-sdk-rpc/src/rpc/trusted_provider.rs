//! Read-only Protocol RPC adapter. All chain facts are trusted service assertions.
use super::*;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256};
use serde_json::{json, Value};

/// A read-only provider that trusts Protocol RPC for chain facts and never contacts an Ethereum node.
/// Explicit deployment pins and v1/1 versions are checked on every service response. This is not
/// independent chain authentication. It implements the same read traits as `EthereumChain`.
pub struct TrustedProvider<T: RpcTransport> {
    ethereum: EthereumChain<TrustedTransport<T>>,
}
impl<T: RpcTransport> TrustedProvider<T> {
    pub fn new(transport: T, deployment: ProtocolDeployment) -> Result<Self> {
        deployment.validate()?;
        Ok(Self {
            ethereum: EthereumChain::new(TrustedTransport {
                rpc: JsonRpc::new(transport),
                deployment,
            }),
        })
    }
}
struct TrustedTransport<T: RpcTransport> {
    rpc: JsonRpc<T>,
    deployment: ProtocolDeployment,
}
impl<T: RpcTransport> TrustedTransport<T> {
    fn read(&self, request: Value) -> Result<Value> {
        let value = self.rpc.call("invisi_readChainState", json!([request]))?;
        if value["apiVersion"] != "v1"
            || value["protocolVersion"] != "1"
            || ProtocolDeployment::parse(&value["deployment"])? != self.deployment
        {
            return Err(Error::Invalid("trusted deployment or version mismatch"));
        }
        Ok(value)
    }
    fn header(&self, block: &Value) -> Result<Value> {
        let response = self.read(json!({"kind":"header", "block":block}))?;
        let value = response["header"].clone();
        if value.is_null() {
            return Err(Error::Invalid("trusted header missing"));
        }
        let header: alloy_consensus::Header = serde_json::from_value(value.clone())
            .map_err(|_| Error::Invalid("invalid trusted header"))?;
        let digest = header.hash_slow();
        if digest != invisi_sdk_protocol::interfaces::hash(&response["headerHash"])? {
            return Err(Error::Invalid("trusted header hash mismatch"));
        }
        if let Some(n) = block.as_str().filter(|s| s.starts_with("0x")) {
            if super::client::quantity(&Value::String(n.into()))? != header.number {
                return Err(Error::Invalid("trusted header number mismatch"));
            }
        }
        let mut value = value;
        value["hash"] = json!(digest);
        Ok(value)
    }
}
impl<T: RpcTransport> RpcTransport for TrustedTransport<T> {
    fn send(&self, request: &Value) -> Result<Value> {
        let p = &request["params"];
        let value = match request["method"].as_str() {
            Some("eth_chainId") => {
                self.header(&json!("latest"))?;
                json!(format!("0x{:x}", self.deployment.chain_id()?))
            }
            Some("eth_blockNumber") => self.header(&json!("latest"))?["number"].clone(),
            Some("eth_getBlockByNumber") => self.header(&p[0])?,
            Some("eth_getCode") => {
                self.read(json!({"kind":"code", "address":p[0], "block":p[1]}))?["data"].clone()
            }
            Some("eth_call") => self.read(
                json!({"kind":"call", "address":p[0]["to"], "data":p[0]["data"], "block":p[1]}),
            )?["data"]
                .clone(),
            Some("eth_getTransactionReceipt") => {
                self.read(json!({"kind":"receipt", "transactionHash":p[0]}))?["receipt"].clone()
            }
            Some("eth_getTransactionByHash") => {
                let response = self.read(json!({"kind":"transaction", "transactionHash":p[0]}))?;
                let mut tx = response["transaction"].clone();
                if !tx.is_null() {
                    let decoded: alloy_consensus::TxEnvelope =
                        serde_json::from_value(tx.clone())
                            .map_err(|_| Error::Invalid("invalid trusted transaction"))?;
                    let expected = invisi_sdk_protocol::interfaces::hash(&p[0])?;
                    if alloy_primitives::keccak256(decoded.encoded_2718()) != expected
                        || invisi_sdk_protocol::interfaces::hash(&tx["hash"])? != expected
                    {
                        return Err(Error::Invalid("trusted transaction hash mismatch"));
                    }
                    let pending = response["pending"]
                        .as_bool()
                        .ok_or(Error::Invalid("pending status required"))?;
                    if pending {
                        tx["blockNumber"] = Value::Null;
                        tx["blockHash"] = Value::Null;
                    } else {
                        let receipt = self
                            .read(json!({"kind":"receipt", "transactionHash":p[0]}))?["receipt"]
                            .clone();
                        if receipt.is_null() || receipt["transactionHash"] != p[0] {
                            return Err(Error::Invalid("trusted transaction receipt missing"));
                        }
                        tx["blockNumber"] = receipt["blockNumber"].clone();
                        tx["blockHash"] = receipt["blockHash"].clone();
                    }
                }
                tx
            }
            _ => return Err(Error::Invalid("unsupported trusted provider operation")),
        };
        Ok(json!({"jsonrpc":"2.0", "id":request["id"], "result":value}))
    }
}
impl<T: RpcTransport> CanonicalChain for TrustedProvider<T> {
    fn chain_id(&self) -> Result<u64> {
        self.ethereum.chain_id()
    }
    fn block(&self, number: u64) -> Result<CanonicalBlock> {
        self.ethereum.block(number)
    }
    fn code_at(&self, address: Address, block: Option<u64>) -> Result<Vec<u8>> {
        self.ethereum.code_at(address, block)
    }
    fn call(&self, address: Address, data: &[u8], block: u64) -> Result<Vec<u8>> {
        self.ethereum.call(address, data, block)
    }
    fn block_by_tag(&self, tag: FinalityTag) -> Result<Option<CanonicalBlock>> {
        self.ethereum.block_by_tag(tag)
    }
    fn confirmation_receipt(&self, hash: B256) -> Result<Option<CanonicalReceipt>> {
        self.receipt(hash)
    }
}
impl<T: RpcTransport> CanonicalHead for TrustedProvider<T> {
    fn head(&self) -> Result<CanonicalBlock> {
        self.ethereum
            .block_by_tag(FinalityTag::Latest)?
            .ok_or(Error::Invalid("trusted head missing"))
    }
}
impl<T: RpcTransport> ChainReceipts for TrustedProvider<T> {
    fn receipt(&self, hash: B256) -> Result<Option<CanonicalReceipt>> {
        self.ethereum.receipt(hash)
    }
}
impl<T: RpcTransport> ChainTransactions for TrustedProvider<T> {
    fn transaction(&self, hash: B256) -> Result<Option<CanonicalTransaction>> {
        self.ethereum.transaction(hash)
    }
}
