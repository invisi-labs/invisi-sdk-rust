use super::{Error, Result};
use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_SAFE_INTEGER: u64 = (1u64 << 53) - 1;
pub const TREE_DEPTH: usize = 16;
pub const MAX_UPDATE_BLOCKS: u64 = 10_000;
pub fn uint(value: &Value, bits: u32) -> Result<u64> {
    let string = match value {
        Value::String(s) => s.clone(),
        Value::Number(n) if n.as_u64().is_some_and(|n| n <= MAX_SAFE_INTEGER) => n.to_string(),
        _ => return Err(Error::Invalid("invalid wire integer")),
    };
    if string.is_empty()
        || (string.len() > 1 && string.starts_with('0'))
        || !string.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::Invalid("noncanonical wire integer"));
    }
    let number = string
        .parse::<u64>()
        .map_err(|_| Error::Invalid("wire integer overflow"))?;
    if bits < 64 && number >= (1u64 << bits) {
        return Err(Error::Invalid("wire integer out of range"));
    }
    Ok(number)
}
pub fn bytes(value: &Value, min: usize, max: usize) -> Result<Vec<u8>> {
    let text = value
        .as_str()
        .ok_or(Error::Invalid("hex string required"))?;
    let body = text
        .strip_prefix("0x")
        .ok_or(Error::Invalid("hex prefix required"))?;
    if body.len() > max.saturating_mul(2) {
        return Err(Error::Invalid("hex bytes exceed bound"));
    }
    let result = hex::decode(body).map_err(|_| Error::Invalid("invalid hex"))?;
    if result.len() < min || result.len() > max {
        return Err(Error::Invalid("invalid byte length"));
    }
    Ok(result)
}
pub fn hash(value: &Value) -> Result<B256> {
    Ok(B256::from_slice(&bytes(value, 32, 32)?))
}
pub fn address(value: &Value) -> Result<Address> {
    Ok(Address::from_slice(&bytes(value, 20, 20)?))
}
pub fn field(value: B256) -> Result<()> {
    let data = value.as_slice();
    if invisi_sdk_primitives::field::field_to_bytes_be(
        invisi_sdk_primitives::field::bytes_to_field(data),
    )
    .as_slice()
        != data
    {
        return Err(Error::Invalid("noncanonical field"));
    }
    Ok(())
}
pub fn decimal(value: &Value) -> Result<U256> {
    let text = value
        .as_str()
        .ok_or(Error::Invalid("decimal string required"))?;
    if text.is_empty()
        || text.len() > 78
        || text.len() > 1 && text.starts_with('0')
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Error::Invalid("noncanonical decimal"));
    }
    U256::from_str_radix(text, 10).map_err(|_| Error::Invalid("decimal overflow"))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalBlock {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    pub timestamp: u64,
}
impl CanonicalBlock {
    pub fn parse(value: &Value) -> Result<Self> {
        let block = Self {
            number: uint(&value["number"], 64)?,
            hash: hash(&value["hash"])?,
            parent_hash: hash(&value["parentHash"])?,
            timestamp: uint(&value["timestamp"], 64)?,
        };
        if block.number > MAX_SAFE_INTEGER || block.timestamp > MAX_SAFE_INTEGER {
            return Err(Error::Invalid("unsafe block integer"));
        }
        Ok(block)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractDeployment {
    pub address: Address,
    pub runtime_code_hash: B256,
    pub from_block: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolDeployment {
    pub chain_id: String,
    pub protocol: ContractDeployment,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<ContractDeployment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcaster_registry: Option<ContractDeployment>,
}
impl ProtocolDeployment {
    pub fn chain_id(&self) -> Result<u64> {
        let n = uint(&Value::String(self.chain_id.clone()), 64)?;
        if n == 0 {
            return Err(Error::Invalid("zero chain id"));
        }
        Ok(n)
    }
    pub fn validate(&self) -> Result<()> {
        self.chain_id()?;
        for item in [
            Some(&self.protocol),
            self.registry.as_ref(),
            self.broadcaster_registry.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if item.address == Address::ZERO
                || item.runtime_code_hash == B256::ZERO
                || item.from_block > MAX_SAFE_INTEGER
            {
                return Err(Error::Invalid("invalid contract deployment"));
            }
        }
        Ok(())
    }
    pub fn parse(value: &Value) -> Result<Self> {
        fn contract(v: &Value) -> Result<ContractDeployment> {
            Ok(ContractDeployment {
                address: address(&v["address"])?,
                runtime_code_hash: hash(&v["runtimeCodeHash"])?,
                from_block: uint(&v["fromBlock"], 64)?,
            })
        }
        let result = Self {
            chain_id: value["chainId"]
                .as_str()
                .ok_or(Error::Invalid("chain id required"))?
                .into(),
            protocol: contract(&value["protocol"])?,
            registry: value.get("registry").map(contract).transpose()?,
            broadcaster_registry: value.get("broadcasterRegistry").map(contract).transpose()?,
        };
        result.validate()?;
        Ok(result)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolStatus {
    pub finality: Option<crate::finality::ChainFinality>,
    pub indexed_head: Option<CanonicalBlock>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafMetadata {
    pub block: CanonicalBlock,
    pub tree_id: u64,
    pub leaf_index: u32,
    pub commitment: B256,
    pub token: Address,
    pub transaction_hash: B256,
    pub log_index: u32,
    pub kind: String,
}
impl LeafMetadata {
    pub fn parse(v: &Value) -> Result<Self> {
        let out = Self {
            block: CanonicalBlock::parse(&v["block"])?,
            tree_id: uint(&v["treeId"], 64)?,
            leaf_index: uint(&v["leafIndex"], 16)? as u32,
            commitment: hash(&v["commitment"])?,
            token: address(&v["token"])?,
            transaction_hash: hash(&v["transactionHash"])?,
            log_index: uint(&v["logIndex"], 32)? as u32,
            kind: v["kind"]
                .as_str()
                .ok_or(Error::Invalid("output kind required"))?
                .into(),
        };
        field(out.commitment)?;
        if out.tree_id == 0 || out.tree_id > MAX_SAFE_INTEGER || out.token == Address::ZERO {
            return Err(Error::Invalid("invalid output metadata"));
        }
        Ok(out)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedDelivery {
    pub ciphertext: Vec<u8>,
    pub clue: Vec<u8>,
}
impl IndexedDelivery {
    pub fn parse(v: &Value, omitted: bool) -> Result<Self> {
        let ciphertext = bytes(&v["ciphertext"], if omitted { 0 } else { 1 }, 4096)?;
        let size = if ciphertext.is_empty() { 0 } else { 68 };
        Ok(Self {
            ciphertext,
            clue: bytes(&v["clue"], size, size)?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteOutput {
    pub leaf: LeafMetadata,
    pub delivery: IndexedDelivery,
}
impl NoteOutput {
    pub fn parse(v: &Value) -> Result<Self> {
        let leaf = LeafMetadata::parse(v)?;
        if ![
            "Shield",
            "Transact",
            "CrossTreeTransact",
            "BatchOutputs",
            "CreditDraw",
        ]
        .contains(&leaf.kind.as_str())
        {
            return Err(Error::Invalid(
                "Credit authority cannot appear in Note results",
            ));
        }
        Ok(Self {
            leaf,
            delivery: IndexedDelivery::parse(v, true)?,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexedCreditState {
    pub leaf: LeafMetadata,
    pub deliveries: [IndexedDelivery; 2],
}
impl IndexedCreditState {
    pub fn parse(v: &Value) -> Result<Self> {
        let leaf = LeafMetadata::parse(v)?;
        if !["CreditCreated", "CreditDraw", "CreditUpdated"].contains(&leaf.kind.as_str()) {
            return Err(Error::Invalid("invalid Credit state event"));
        }
        let d = v["deliveries"]
            .as_array()
            .ok_or(Error::Invalid("Credit deliveries required"))?;
        if d.len() != 2 {
            return Err(Error::Invalid("two Credit role deliveries required"));
        }
        Ok(Self {
            leaf,
            deliveries: [
                IndexedDelivery::parse(&d[0], false)?,
                IndexedDelivery::parse(&d[1], false)?,
            ],
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreditTransition {
    pub block: CanonicalBlock,
    pub name: String,
    pub transaction_hash: B256,
    pub log_index: u32,
    pub data: Value,
}
impl CreditTransition {
    pub fn parse(v: &Value) -> Result<Self> {
        let name = v["name"]
            .as_str()
            .ok_or(Error::Invalid("transition name required"))?;
        if ![
            "CreditCreated",
            "CreditDraw",
            "CreditUpdated",
            "CreditRevoked",
        ]
        .contains(&name)
        {
            return Err(Error::Invalid("invalid Credit transition"));
        }
        if !v["data"].is_object() {
            return Err(Error::Invalid("transition data required"));
        }
        Ok(Self {
            block: CanonicalBlock::parse(&v["block"])?,
            name: name.into(),
            transaction_hash: hash(&v["transactionHash"])?,
            log_index: uint(&v["logIndex"], 32)? as u32,
            data: v["data"].clone(),
        })
    }
}
#[derive(Clone, Debug)]
pub struct MembershipInput {
    pub tree_id: u64,
    pub leaf_index: u32,
    pub commitment: B256,
    pub root: Option<B256>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Membership {
    pub tree_id: u64,
    pub leaf_index: u32,
    pub leaf: B256,
    pub root: B256,
    pub path: Vec<B256>,
    pub block: CanonicalBlock,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePage<T> {
    pub block: CanonicalBlock,
    pub items: Vec<T>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Availability<T> {
    NotFound {
        indexed_head: Option<CanonicalBlock>,
    },
    PendingIndex {
        indexed_head: Option<CanonicalBlock>,
        block: CanonicalBlock,
        receipt_status: bool,
    },
    Indexed {
        indexed_head: CanonicalBlock,
        block: CanonicalBlock,
        receipt_status: bool,
        items: T,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreditTransactionUpdates {
    pub states: Vec<IndexedCreditState>,
    pub transitions: Vec<CreditTransition>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
    pub log_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalReceipt {
    pub transaction_hash: B256,
    pub block: CanonicalBlock,
    pub success: bool,
    pub logs: Vec<CanonicalLog>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalTransaction {
    pub hash: B256,
    pub to: Option<Address>,
    pub input: Vec<u8>,
    pub value: U256,
    pub chain_id: u64,
    pub block: Option<CanonicalBlock>,
}
