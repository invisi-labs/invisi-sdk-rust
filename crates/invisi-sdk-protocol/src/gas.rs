//! Receipt-calibrated local gas previews for legal direct execution workloads.
use alloy_primitives::U256;
use invisi_sdk_primitives::note::{ModelError, ModelResult};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::OnceLock;
const MODEL: &str = include_str!("../assets/gas/measured-model.json");
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
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub docs_commit: String,
    pub protocol_commit: String,
    pub conditions: String,
    pub assumptions: Vec<String>,
    #[serde(skip_serializing_if = "Value::is_null", default)]
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
    ModelError::Invalid("unsupported gas shape")
}
fn model() -> &'static Value {
    static MODEL_VALUE: OnceLock<Value> = OnceLock::new();
    MODEL_VALUE.get_or_init(|| serde_json::from_str(MODEL).expect("bundled measured gas model"))
}
fn count(q: &Map<String, Value>, key: &str, fallback: Option<u64>) -> ModelResult<u64> {
    let n = match q.get(key) {
        Some(v) => v.as_u64().ok_or_else(invalid)?,
        None => fallback.ok_or_else(invalid)?,
    };
    if n > 9_007_199_254_740_991 {
        return Err(invalid());
    }
    Ok(n)
}
fn flag(q: &Map<String, Value>, key: &str, fallback: bool) -> bool {
    q.get(key).map_or(fallback, |v| v == true)
}
fn capacity(m: &Value, key: &str, n: u64, supplied: Option<&Value>) -> ModelResult<u64> {
    let c = m[key]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_u64)
        .find(|c| n > 0 && *c >= n)
        .ok_or_else(invalid)?;
    if supplied.is_some_and(|v| v.as_u64() != Some(c)) {
        return Err(invalid());
    }
    Ok(c)
}
fn matches(row: &Value, shape: &Map<String, Value>) -> bool {
    shape.iter().all(|(k, v)| row["shape"].get(k) == Some(v))
}
/// Local receipt-calibrated preview; this is not a transaction gas limit or RPC simulation.
pub fn estimate_gas(q: &Map<String, Value>) -> ModelResult<GasEstimate> {
    use serde_json::json;
    let m = model();
    let kind = q.get("kind").and_then(Value::as_str).unwrap_or("");
    if kind == "create-credit-initial-payment"
        || kind == "create-credit"
            && q.get("creationAbi").and_then(Value::as_str) == Some("initial-payment")
    {
        let data: Value = serde_json::from_str(include_str!(
            "../assets/gas/initial-payment-measurements.json"
        ))
        .map_err(|_| invalid())?;
        let fee = flag(q, "feeEnabled", flag(q, "fee", false));
        let row = data["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["kind"] == kind && r["feeEnabled"] == fee)
            .ok_or_else(invalid)?;
        let combined = kind == "create-credit-initial-payment";
        let extra = count(q, "extraDeliveryBytes", Some(0))?
            + 2 * count(q, "creditCiphertextBytes", Some(485))?.saturating_sub(485)
            + if combined {
                count(q, "noteCiphertextBytes", Some(160))?.saturating_sub(160)
            } else {
                0
            }
            + (if combined { 3 } else { 2 }) * count(q, "clueBytes", Some(68))?.saturating_sub(68);
        return Ok(GasEstimate::Available(AvailableReference {
            source:"benchmark".into(),available:true,gas_units:U256::from(row["gasUnits"].as_u64().unwrap())+U256::from(extra)*U256::from(32),
            statistic:if extra==0 {"median"} else {"estimate"}.into(),sample_count:if extra==0 {3} else {0},reference_id:"initial-payment-receipt-v1".into(),
            document:"scripts/benchmark-credit-initial-payment-gas.mjs".into(),source_sha256:data["sourceSha256"].as_str().unwrap().into(),protocol_commit:data["protocolCommit"].as_str().unwrap().into(),docs_commit:String::new(),
            release_identity:json!({"creditManifestVersion":7,"creditFormatVersion":8,"creditManifestSha256":data["creditManifestSha256"]}),conditions:data["conditions"].as_str().unwrap().into(),
            assumptions:vec!["Pre-signing local fee preview; not an RPC simulation or transaction gas limit.".into(),"Token behavior, storage warmth, tree cursor and rollover can change actual gas.".into(),"Additional source trees, authorization and delivery bytes use explicit benchmark-calibrated allowances.".into(),"Measured against the recorded working-tree source hash before commit.".into()],
        }));
    }

    if ![
        "shield",
        "transact",
        "draw-credit",
        "create-credit",
        "update-credit",
        "revoke-credit",
    ]
    .contains(&kind)
    {
        return Ok(unavailable(UnavailableReason::ShapeNotCovered));
    }
    let fee = flag(q, "feeEnabled", flag(q, "fee", false));
    let mut shape = json!({"kind":kind,"fee":fee});
    let rows = m["rows"].as_array().unwrap();
    let mut gas: f64;
    if kind == "shield" {
        let n = count(q, "noteOutputs", None)?;
        if !(1..=10).contains(&n) {
            return Err(invalid());
        }
        shape = json!({"kind":kind,"noteOutputs":n,"fee":fee});
        gas = rows
            .iter()
            .find(|r| matches(r, shape.as_object().unwrap()))
            .ok_or_else(invalid)?["gasUnits"]
            .as_f64()
            .unwrap();
    } else if kind == "transact" || kind == "draw-credit" {
        let draw = kind == "draw-credit";
        let n = count(q, if draw { "creditInputs" } else { "noteInputs" }, None)?;
        let o = if draw {
            0
        } else {
            count(q, "noteOutputs", None)?
        };
        let key = if draw {
            "creditCapacities"
        } else {
            "capacities"
        };
        let tier = capacity(
            m,
            key,
            n.checked_add(o).ok_or_else(invalid)?,
            q.get("capacity"),
        )?;
        let trees = count(q, "sourceTrees", Some(u64::from(n > 0)))?;
        if trees > n || (n > 0 && trees == 0) {
            return Err(invalid());
        }
        let mut features: Vec<f64> = m[key]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| f64::from(c.as_u64() == Some(tier)))
            .collect();
        if draw {
            let payers = count(q, "distinctPayers", Some(n))?;
            if payers == 0 || payers > n {
                return Err(invalid());
            }
            shape = json!({"kind":kind,"capacity":tier,"creditInputs":n,"distinctPayers":payers,"sourceTrees":trees,"fee":fee});
            features.extend([n as f64, payers as f64, f64::from(fee)]);
        } else {
            let scenario = q.get("scenario").and_then(Value::as_str).unwrap_or("");
            let deposit = flag(
                q,
                "deposit",
                ["public-funding", "mixed"].contains(&scenario),
            );
            let withdrawal = flag(q, "withdrawal", ["withdrawal", "mixed"].contains(&scenario));
            if (n == 0 && (o < 2 || !deposit)) || (o == 0 && !withdrawal && !fee) {
                return Err(invalid());
            }
            shape = json!({"kind":kind,"capacity":tier,"noteInputs":n,"noteOutputs":o,"sourceTrees":trees,"deposit":deposit,"withdrawal":withdrawal,"fee":fee});
            features.extend([
                n as f64,
                o as f64,
                f64::from(o > 0),
                f64::from(deposit),
                f64::from(withdrawal),
                f64::from(fee),
            ]);
        }
        gas = features
            .iter()
            .zip(
                m["coefficients"][if draw { "draw" } else { "transact" }]
                    .as_array()
                    .unwrap(),
            )
            .fold(0.0, |sum, (x, c)| sum + x * c.as_f64().unwrap())
            + trees.saturating_sub(1) as f64 * 10000.0;
    } else {
        if kind == "revoke-credit" {
            shape["authorization"] = q.get("authorization").cloned().unwrap_or(json!("unknown"));
            shape["bitmapWord"] = q.get("bitmapWord").cloned().unwrap_or(json!("empty"));
        }
        if let Some(row) = rows.iter().find(|r| matches(r, shape.as_object().unwrap())) {
            gas = row["gasUnits"].as_f64().unwrap();
        } else if kind == "revoke-credit" {
            let auth = shape["authorization"].as_str().ok_or_else(invalid)?;
            if !["direct", "eoa", "erc1271", "unknown"].contains(&auth)
                || !["empty", "nonempty"].contains(&shape["bitmapWord"].as_str().unwrap_or(""))
            {
                return Err(invalid());
            }
            let row = rows
                .iter()
                .find(|r| {
                    r["shape"]["kind"] == kind
                        && r["shape"]["fee"] == fee
                        && r["shape"]["authorization"]
                            == if auth == "direct" { "direct" } else { "eoa" }
                })
                .ok_or_else(invalid)?;
            gas = row["gasUnits"].as_f64().unwrap()
                + if ["erc1271", "unknown"].contains(&auth) {
                    60000.0
                } else {
                    0.0
                };
        } else {
            return Err(invalid());
        }
    }
    let notes = match kind {
        "draw-credit" => 1,
        "shield" | "transact" => count(q, "noteOutputs", None)?,
        _ => 0,
    };
    let credits = match kind {
        "draw-credit" => 2 * count(q, "creditInputs", None)?,
        "create-credit" | "update-credit" => 2,
        _ => 0,
    };
    let extra_bytes = count(q, "extraDeliveryBytes", Some(0))? as f64
        + notes as f64 * count(q, "noteCiphertextBytes", Some(160))?.saturating_sub(160) as f64
        + credits as f64 * count(q, "creditCiphertextBytes", Some(485))?.saturating_sub(485) as f64
        + (notes + credits) as f64 * count(q, "clueBytes", Some(68))?.saturating_sub(68) as f64;
    let extra = extra_bytes * 32.0
        + if flag(q, "permit", false) {
            70000.0
        } else {
            0.0
        }
        + if flag(q, "fundingSignature", false) {
            40000.0
        } else {
            0.0
        };
    let exact = rows
        .iter()
        .enumerate()
        .find(|(_, r)| matches(r, shape.as_object().unwrap()))
        .filter(|_| extra == 0.0);
    if let Some((_, r)) = exact {
        gas = r["gasUnits"].as_f64().unwrap();
    }
    gas += extra;
    if !gas.is_finite() || gas <= 0.0 {
        return Err(invalid());
    }
    Ok(GasEstimate::Available(AvailableReference {
        source: "benchmark".into(),
        available: true,
        gas_units: U256::from(gas.ceil() as u128),
        statistic: if exact.is_some() { "median" } else { "estimate" }.into(),
        sample_count: if exact.is_some() { 3 } else { 0 },
        reference_id: exact.map(|(i, _)| format!("receipt-{i}"))
            .unwrap_or_else(|| format!("{kind}-benchmark-estimate-v1")),
        document: if kind=="draw-credit" {"test-support/gas-benchmark/measure-credit.mjs"} else {"05-benchmarks/5.10-sdk-gas-estimation.md"}.into(),
        source_sha256: if kind=="draw-credit" {&m["creditDrawMeasurement"]["sourceSha256"]} else {&m["sourceSha256"]}.as_str().unwrap().into(),
        protocol_commit: if kind=="draw-credit" {&m["creditDrawMeasurement"]["protocolCommit"]} else {&m["protocolCommit"]}.as_str().unwrap().into(),
        docs_commit: String::new(),
        release_identity: Value::Null,
        conditions: if kind=="draw-credit" {m["creditDrawMeasurement"]["conditions"].as_str().unwrap()} else {"Local Anvil31337 / Prague, Solidity0.8.38 optimizer200, real verifiers, reference ERC20."}.into(),
        assumptions: vec![
            "Pre-signing local fee preview; not an RPC simulation or transaction gas limit.".into(),
            "Token behavior, storage warmth, tree cursor and rollover can change actual gas.".into(),
            "Additional source trees, authorization and delivery bytes use explicit benchmark-calibrated allowances.".into(),
        ].into_iter().chain((kind=="draw-credit").then(||"Unified CreditDraw / CreditStateTransition receipts; measured working-tree source hash before commit.".into())).collect(),
    }))
}
