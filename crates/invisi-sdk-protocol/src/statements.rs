//! Pinned public circuit statements and artifact identities.
use alloy_primitives::{B256, U256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub type Result<T> = std::result::Result<T, String>;
#[derive(Deserialize)]
struct Layout {
    #[serde(rename = "artifactSha256")]
    artifact_sha256: String,
    keys: BTreeMap<String, String>,
    #[serde(rename = "publicInputCount")]
    count: usize,
}
fn layouts() -> Result<BTreeMap<String, Layout>> {
    serde_json::from_str(include_str!("../assets/circuit-statements.json"))
        .map_err(|_| "invalid circuit statement catalog".into())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProofStatement {
    pub circuit_name: String,
    pub target: String,
    pub artifact_sha256: String,
    pub vk_sha256: String,
    pub expected_public_inputs: Vec<B256>,
}
/// Return the independently pinned binary verification-key digest without
/// requiring public inputs or loading circuit resources.
pub fn verification_key_sha256(name: &str, target: &str) -> Result<String> {
    layouts()?
        .get(name)
        .ok_or("unsupported circuit")?
        .keys
        .get(target)
        .cloned()
        .ok_or_else(|| "unsupported proving target".into())
}
pub fn statement(name: &str, target: &str, inputs: Vec<B256>) -> Result<ProofStatement> {
    for input in &inputs {
        invisi_sdk_primitives::note::field(U256::from_be_slice(input.as_slice()), "public field")
            .map_err(|e| e.to_string())?;
    }
    let all = layouts()?;
    let layout = all.get(name).ok_or("unsupported circuit")?;
    let key = layout
        .keys
        .get(target)
        .ok_or("unsupported proving target")?;
    if inputs.len() != layout.count {
        return Err("public statement width mismatch".into());
    }
    Ok(ProofStatement {
        circuit_name: name.into(),
        target: target.into(),
        artifact_sha256: layout.artifact_sha256.clone(),
        vk_sha256: key.clone(),
        expected_public_inputs: inputs,
    })
}
