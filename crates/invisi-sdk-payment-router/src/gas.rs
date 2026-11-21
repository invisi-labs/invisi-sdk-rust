//! Conservative pre-proof Router allowances over the existing Core gas preview.
use crate::{canonical::Payment, ensure, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::OnceLock;
fn profile() -> &'static Value {
    static PROFILE: OnceLock<Value> = OnceLock::new();
    PROFILE.get_or_init(|| {
        serde_json::from_str(ROUTER_GAS_PROFILE).expect("bundled Router gas profile")
    })
}
fn unavailable(reason: &str) -> Value {
    json!({"available":false,"source":"model","modelId":ROUTER_GAS_MODEL_ID,"reason":reason})
}
pub const ROUTER_GAS_PROFILE: &str = include_str!("gas-profile.json");
pub const ROUTER_GAS_MODEL_ID: &str = "payment-router-gas-v1";
const MAX_SAFE: u64 = 9_007_199_254_740_991;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouterGasInput {
    pub core_gas_units: u64,
    pub mode: u8,
    pub channel: u8,
    pub hop_count: u64,
    pub route_bytes: u64,
    pub permit: bool,
    pub authorization_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zero_ex_gas_units: Option<u64>,
}
/// Numeric inputs and totals must fit the cross-SDK safe integer range.
/// An opaque 0x route requires a trusted service-policy gas budget.
pub fn estimate_router_gas(input: &RouterGasInput) -> Result<Value> {
    let i = input;
    if !(i.core_gas_units > 0
        && i.core_gas_units <= MAX_SAFE
        && i.mode <= 3
        && i.channel <= 2
        && i.route_bytes <= 131072
        && i.authorization_count <= 1
        && (i.authorization_count == 0 || i.mode == 3)
        && i.zero_ex_gas_units.is_none_or(|n| n <= MAX_SAFE))
    {
        return Ok(unavailable("invalid-router-gas-input"));
    }
    if !(if i.channel == 1 {
        (1..=8).contains(&i.hop_count)
    } else {
        i.hop_count == 0
    }) {
        return Ok(unavailable("invalid-router-gas-input"));
    }
    if i.channel == 0 && i.route_bytes != 0 {
        return Ok(unavailable("invalid-router-gas-input"));
    }
    if i.channel == 2 && i.zero_ex_gas_units.unwrap_or(0) == 0 {
        return Ok(
            json!({"available":false,"source":"model","modelId":ROUTER_GAS_MODEL_ID,"reason":"zeroex-route-gas-unavailable"}),
        );
    }
    let p = profile();
    let mode = p["modeOverhead"][i.mode as usize].as_u64().unwrap();
    let route = match i.channel {
        1 => p["v3Base"].as_u64().unwrap() + p["v3PerHop"].as_u64().unwrap() * i.hop_count,
        2 => i.zero_ex_gas_units.unwrap(),
        _ => 0,
    };
    let permit = if i.permit {
        p["permit"].as_u64().unwrap()
    } else {
        0
    };
    let authorization = p["authorization"].as_u64().unwrap() * i.authorization_count;
    let route_bytes = p["routeByte"].as_u64().unwrap() * i.route_bytes;
    let gas = i
        .core_gas_units
        .checked_add(mode)
        .and_then(|n| n.checked_add(route))
        .and_then(|n| n.checked_add(permit))
        .and_then(|n| n.checked_add(authorization))
        .and_then(|n| n.checked_add(route_bytes))
        .filter(|n| *n <= MAX_SAFE);
    let Some(gas) = gas else {
        return Ok(unavailable("router-gas-overflow"));
    };
    Ok(
        json!({"available":true,"source":"model","modelId":ROUTER_GAS_MODEL_ID,"gasUnits":gas,"breakdown":{"core":i.core_gas_units,"router":mode,"swap":route,"permit":permit,"authorization":authorization,"routeCalldata":route_bytes}}),
    )
}
impl Payment {
    /// Local estimate from the finalized Core shape; proof and wallet signatures are unnecessary.
    /// Common Core transaction base is counted once. Final actual-call simulation is mandatory.
    pub fn estimate_gas(
        &self,
        permit: bool,
        authorization_count: u64,
        zero_ex_gas_units: Option<u64>,
    ) -> Result<Value> {
        let r = self.request();
        let extra: usize = r
            .deliveries
            .iter()
            .map(|d| d.ciphertext.len().saturating_sub(160) + d.clue.len().saturating_sub(68))
            .sum();
        let shape = json!({"kind":"transact","noteInputs":0,"noteOutputs":r.params.noteCommitments.len(),"deposit":true,"fee":!r.params.feeAmount.is_zero(),"extraDeliveryBytes":extra});
        let core = invisi_sdk_protocol::gas::estimate_gas(shape.as_object().unwrap())
            .map_err(|_| Error::Invalid("invalid Core gas shape"))?;
        let Some(core) = core.gas_units() else {
            return Ok(
                json!({"available":false,"source":"model","modelId":ROUTER_GAS_MODEL_ID,"reason":"core-gas-unavailable"}),
            );
        };
        ensure(
            core <= alloy_primitives::U256::from(MAX_SAFE),
            "invalid Core gas estimate",
        )?;
        let route = self.route();
        estimate_router_gas(&RouterGasInput {
            core_gas_units: core.to::<u64>(),
            mode: self.intent().mode,
            channel: route.channel,
            hop_count: if route.channel == 1 {
                (route.path.len().saturating_sub(20) / 23) as u64
            } else {
                0
            },
            route_bytes: (route.path.len() + route.data.len()) as u64,
            permit,
            authorization_count,
            zero_ex_gas_units,
        })
    }
}
