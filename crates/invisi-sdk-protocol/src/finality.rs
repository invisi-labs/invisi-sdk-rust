//! Native chain finality DTOs; no depth or elapsed-time estimates.
use crate::{interfaces::CanonicalBlock, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FinalityTag {
    Latest,
    Safe,
    Finalized,
}
impl FinalityTag {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Latest => "latest",
            Self::Safe => "safe",
            Self::Finalized => "finalized",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FinalityStatus {
    Available,
    Unsupported,
    Unavailable,
    Inconsistent,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalityHead {
    pub status: FinalityStatus,
    pub block: Option<CanonicalBlock>,
}
impl FinalityHead {
    pub fn absent(status: FinalityStatus) -> Self {
        Self {
            status,
            block: None,
        }
    }
    pub fn parse(v: &Value) -> Result<Self> {
        if v.as_object()
            .is_none_or(|o| o.len() != 2 || !o.contains_key("status") || !o.contains_key("block"))
        {
            return Err(Error::Invalid("invalid finality head"));
        }
        let status: FinalityStatus = serde_json::from_value(v["status"].clone())
            .map_err(|_| Error::Invalid("invalid finality status"))?;
        let block = if v["block"].is_null() {
            None
        } else {
            Some(CanonicalBlock::parse(&v["block"])?)
        };
        if (status == FinalityStatus::Available) != block.is_some() {
            return Err(Error::Invalid("finality status/block mismatch"));
        }
        Ok(Self { status, block })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainFinality {
    pub latest: FinalityHead,
    pub safe: FinalityHead,
    pub finalized: FinalityHead,
}
impl ChainFinality {
    pub fn absent(status: FinalityStatus) -> Self {
        Self {
            latest: FinalityHead::absent(status),
            safe: FinalityHead::absent(status),
            finalized: FinalityHead::absent(status),
        }
    }
    pub fn ordered(&self) -> bool {
        let heads = [&self.finalized, &self.safe, &self.latest];
        (0..3).all(|i| {
            ((i + 1)..3).all(|j| match (&heads[i].block, &heads[j].block) {
                (Some(a), Some(b)) => a.number < b.number || (a.number == b.number && a == b),
                _ => true,
            })
        })
    }
    pub fn parse(v: &Value) -> Result<Self> {
        if v.as_object().is_none_or(|o| o.len() != 3) {
            return Err(Error::Invalid("invalid chain finality"));
        }
        let out = Self {
            latest: FinalityHead::parse(&v["latest"])?,
            safe: FinalityHead::parse(&v["safe"])?,
            finalized: FinalityHead::parse(&v["finalized"])?,
        };
        if !out.ordered() {
            return Err(Error::Invalid("incoherent chain finality"));
        }
        Ok(out)
    }
    pub fn head(&self, tag: FinalityTag) -> &FinalityHead {
        match tag {
            FinalityTag::Latest => &self.latest,
            FinalityTag::Safe => &self.safe,
            FinalityTag::Finalized => &self.finalized,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConfirmationLevel {
    Pending,
    Included,
    Safe,
    Finalized,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionConfirmation {
    pub level: ConfirmationLevel,
    pub status: FinalityStatus,
    pub block: Option<CanonicalBlock>,
}
