//! Exact documented gas workloads. These observations are neither gas limits nor RPC estimates.
use alloy_primitives::U256;
use invisi_sdk_primitives::note::{ModelError, ModelResult};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
const CATALOG: &str = include_str!("../assets/gas/documented-references.json");
pub const DOCUMENTED_CATALOG_SHA256: &str =
    "a74b8250ef45de20a3f3d54ca0b35fb54dff50db4c1066e9a76c5592124e8129";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnavailableReason {
    ShapeNotCovered,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnavailableReference {
    pub source: String,
    pub available: bool,
    pub reason: UnavailableReason,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AvailableReference {
    pub source: String,
    pub available: bool,
    #[serde(with = "invisi_sdk_primitives::note::decimal")]
    pub gas_units: U256,
    pub statistic: String,
    pub sample_count: u32,
    pub reference_id: String,
    pub document: String,
    pub source_sha256: String,
    pub docs_commit: String,
    pub conditions: String,
    pub assumptions: Vec<String>,
    pub release_identity: Value,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GasEstimate {
    Available(AvailableReference),
    Unavailable(UnavailableReference),
}
impl GasEstimate {
    pub fn available(&self) -> bool {
        matches!(self, Self::Available(_))
    }
    pub fn gas_units(&self) -> Option<U256> {
        match self {
            Self::Available(row) => Some(row.gas_units),
            _ => None,
        }
    }
}
fn unavailable(reason: UnavailableReason) -> GasEstimate {
    GasEstimate::Unavailable(UnavailableReference {
        source: "benchmark".into(),
        available: false,
        reason,
    })
}
fn invalid() -> ModelError {
    ModelError::Invalid("bundled documented gas catalog")
}
fn text<'a>(v: &'a Value, name: &str) -> ModelResult<&'a str> {
    v[name].as_str().ok_or_else(invalid)
}
/// Match every workload key exactly; measured release identity is provenance only.
fn documented_reference(query: &Map<String, Value>) -> ModelResult<GasEstimate> {
    if hex::encode(Sha256::digest(CATALOG.as_bytes())) != DOCUMENTED_CATALOG_SHA256 {
        return Err(invalid());
    }
    let catalog: Value = serde_json::from_str(CATALOG).map_err(|_| invalid())?;
    let row = catalog["references"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .find(|row| row["shape"].as_object() == Some(query));
    let Some(row) = row else {
        return Ok(unavailable(UnavailableReason::ShapeNotCovered));
    };
    let identity = &row["releaseIdentity"];
    let document = text(row, "source")?;
    let source = catalog["sources"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .find(|source| source["path"] == document)
        .ok_or_else(invalid)?;
    let gas_units = U256::from_str_radix(text(row, "gasUnits")?, 10).map_err(|_| invalid())?;
    let assumptions = catalog["assumptions"]
        .as_array()
        .ok_or_else(invalid)?
        .iter()
        .map(|v| v.as_str().map(str::to_owned).ok_or_else(invalid))
        .collect::<ModelResult<Vec<_>>>()?;
    Ok(GasEstimate::Available(AvailableReference {
        source: "benchmark".into(),
        available: true,
        gas_units,
        statistic: text(row, "statistic")?.into(),
        sample_count: row["sampleCount"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(invalid)?,
        reference_id: text(row, "id")?.into(),
        document: document.into(),
        source_sha256: text(source, "sha256")?.into(),
        docs_commit: text(&catalog, "docsCommit")?.into(),
        conditions: text(source, "conditions")?.into(),
        assumptions,
        release_identity: identity.clone(),
    }))
}

/// Estimate an exact prepared workload from bundled measurements without network access.
pub fn estimate_gas(shape: &Map<String, Value>) -> ModelResult<GasEstimate> {
    documented_reference(shape)
}
