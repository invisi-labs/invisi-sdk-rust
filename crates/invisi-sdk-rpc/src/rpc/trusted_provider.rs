//! Read-only Protocol RPC adapter. All chain facts are trusted service assertions.
use super::*;
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256};
use alloy_rlp::Encodable;
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
/// Authenticate the original full header in both historical and live reads.
/// Pinned Alloy encodes fields through requestsHash; append slotNumber inside
/// that same RLP list without reconstructing or dropping any earlier fields.
fn decode_full_header(original: &Value) -> Result<(alloy_consensus::Header, B256)> {
    let fork_fields = [
        "baseFeePerGas",
        "withdrawalsRoot",
        "blobGasUsed",
        "excessBlobGas",
        "parentBeaconBlockRoot",
        "requestsHash",
        "slotNumber",
    ];
    if let Some(last) = fork_fields
        .iter()
        .rposition(|field| !original[field].is_null())
    {
        if fork_fields[..=last]
            .iter()
            .any(|field| original[field].is_null())
        {
            return Err(Error::Invalid("incomplete trusted header fork fields"));
        }
    }
    let header: alloy_consensus::Header = serde_json::from_value(original.clone())
        .map_err(|_| Error::Invalid("invalid trusted header"))?;
    let digest = if original["slotNumber"].is_null() {
        header.hash_slow()
    } else {
        let slot = super::client::quantity(&original["slotNumber"])?;
        let encoded = alloy_rlp::encode(&header);
        let mut payload = encoded.as_slice();
        alloy_rlp::Header::decode(&mut payload)
            .map_err(|_| Error::Invalid("invalid encoded trusted header"))?;
        let mut extended = Vec::with_capacity(encoded.len() + slot.length());
        alloy_rlp::Header {
            list: true,
            payload_length: payload.len() + slot.length(),
        }
        .encode(&mut extended);
        extended.extend_from_slice(payload);
        slot.encode(&mut extended);
        alloy_primitives::keccak256(extended)
    };
    Ok((header, digest))
}
struct TrustedTransport<T: RpcTransport> {
    rpc: JsonRpc<T>,
    deployment: ProtocolDeployment,
}
impl<T: RpcTransport> TrustedTransport<T> {
    fn read(&self, request: Value) -> Result<Value> {
        let value = self.rpc.call("invisi_readChainState", json!([request]))?;
        self.validate_read(&value)?;
        Ok(value)
    }
    fn validate_read(&self, value: &Value) -> Result<()> {
        if value["apiVersion"] != "v1"
            || value["protocolVersion"] != "1"
            || ProtocolDeployment::parse(&value["deployment"])? != self.deployment
        {
            return Err(Error::Invalid("trusted deployment or version mismatch"));
        }
        Ok(())
    }
    /// Historical storage is a bulk optimization only; single reads stay live.
    fn historical_headers(&self, from: u64, to: u64) -> Result<Vec<CanonicalBlock>> {
        let response = self.rpc.call(
            "invisi_getBlockHeaders",
            json!([{"fromBlock":from,"toBlock":to}]),
        )?;
        self.validate_read(&response)?;
        if response["range"]["fromBlock"].as_u64() != Some(from)
            || response["range"]["toBlock"].as_u64() != Some(to)
        {
            return Err(Error::Invalid("trusted historical range mismatch"));
        }
        let rows = response["headers"]
            .as_array()
            .filter(|rows| rows.len() as u64 == to - from + 1)
            .ok_or(Error::Invalid("trusted historical header count mismatch"))?;
        let mut headers: Vec<CanonicalBlock> = Vec::with_capacity(rows.len());
        for (offset, row) in rows.iter().enumerate() {
            // Deserialize the complete original Ethereum header, including fork fields,
            // and recompute its RLP hash rather than hashing a reduced canonical block.
            let (header, digest) = decode_full_header(&row["header"])?;
            if header.number != from + offset as u64
                || digest != invisi_sdk_protocol::interfaces::hash(&row["headerHash"])?
                || headers
                    .last()
                    .is_some_and(|previous| header.parent_hash != previous.hash)
            {
                return Err(Error::Invalid("trusted historical header binding mismatch"));
            }
            headers.push(CanonicalBlock {
                number: header.number,
                timestamp: header.timestamp,
                hash: digest,
                parent_hash: header.parent_hash,
            });
        }
        if headers.last().map(|h| h.hash)
            != Some(invisi_sdk_protocol::interfaces::hash(
                &response["range"]["blockHash"],
            )?)
        {
            return Err(Error::Invalid("trusted historical anchor mismatch"));
        }
        Ok(headers)
    }
    fn header(&self, block: &Value) -> Result<Value> {
        let response = self.read(json!({"kind":"header", "block":block}))?;
        self.validate_header(&response, block)
    }
    fn validate_header(&self, response: &Value, block: &Value) -> Result<Value> {
        self.validate_read(response)?;
        let value = response["header"].clone();
        if value.is_null() {
            return Err(Error::Invalid("trusted header missing"));
        }
        let (header, digest) = decode_full_header(&value)?;
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
    fn latest_call(&self, address: Address, data: &[u8]) -> Option<Result<Vec<u8>>> {
        self.ethereum.latest_call(address, data)
    }

    fn blocks(&self, numbers: &[u64]) -> Option<Result<Vec<CanonicalBlock>>> {
        Some((|| {
            if numbers.is_empty() || numbers.iter().any(|n| *n > i64::MAX as u64) {
                return Err(Error::Invalid(
                    "nonempty signed-64-bit header numbers required",
                ));
            }
            let transport = &self.ethereum.rpc.transport;
            let mut headers: Vec<CanonicalBlock> = Vec::with_capacity(numbers.len());
            if numbers
                .windows(2)
                .all(|pair| pair[0].checked_add(1) == Some(pair[1]))
            {
                let mut compatible = true;
                for chunk in numbers.chunks(256) {
                    match transport.historical_headers(chunk[0], chunk[chunk.len() - 1]) {
                        Ok(batch) => {
                            if headers
                                .last()
                                .is_some_and(|previous| batch[0].parent_hash != previous.hash)
                            {
                                return Err(Error::Invalid(
                                    "trusted historical chunk parent mismatch",
                                ));
                            }
                            headers.extend(batch);
                        }
                        Err(Error::Remote {
                            code: -32601 | -32004,
                            ..
                        }) => {
                            compatible = false;
                            break;
                        }
                        Err(error) => return Err(error),
                    }
                }
                if compatible {
                    return Ok(headers);
                }
                // Only explicit unsupported/unavailable history errors permit the
                // original live batched path. Never mix stored and live history.
                headers.clear();
            }
            for chunk in numbers.chunks(20) {
                let requests = chunk
                    .iter()
                    .map(|n| {
                        (
                            "invisi_readChainState",
                            json!([{"kind":"header","block":format!("0x{n:x}")}]),
                        )
                    })
                    .collect::<Vec<_>>();
                let responses = transport.rpc.batch(&requests)?;
                for (n, response) in chunk.iter().zip(responses) {
                    let v = transport.validate_header(&response, &json!(format!("0x{n:x}")))?;
                    headers.push(CanonicalBlock {
                        number: super::client::quantity(&v["number"])?,
                        timestamp: super::client::quantity(&v["timestamp"])?,
                        hash: invisi_sdk_protocol::interfaces::hash(&v["hash"])?,
                        parent_hash: invisi_sdk_protocol::interfaces::hash(&v["parentHash"])?,
                    });
                }
            }
            Ok(headers)
        })())
    }
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
