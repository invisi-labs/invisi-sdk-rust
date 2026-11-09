use alloy_primitives::U256;
use invisi_sdk::provenance::*;
use invisi_sdk::provenance_client::ProvenanceClient;
use invisi_sdk::rpc::{HttpTransport, JsonRpc};
use serde_json::{json, Value};
use std::{collections::BTreeMap, env, fs, time::Duration};
fn text(v: &Value) -> Result<&str, Box<dyn std::error::Error>> {
    Ok(v.as_str().ok_or("Expected string")?)
}
fn number(v: &Value) -> Result<U256, Box<dyn std::error::Error>> {
    Ok(parse_integer(text(v)?, 256)?)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !env::args().any(|a| a == "--execute") {
        println!("Pass --execute with TRANSACTION_HASH and the retained public record.");
        return Ok(());
    }
    let config: Value = serde_json::from_slice(&fs::read(env::var("PROVENANCE_CONFIG")?)?)?;
    let record: Value = serde_json::from_slice(&fs::read(env::var("PROVENANCE_RECORD")?)?)?;
    let trust = TrustContext {
        scope: Scope {
            chain_id: number(&config["chainId"])?.to(),
            protocol_address: number(&config["protocolAddress"])?,
            policy_id: number(&config["policyId"])?,
        },
        chain_generation: number(&config["generation"])?.to(),
        provider_id: number(&config["providerId"])?,
        manifest_sha256: "f90f2ce43218de158c6392fa19e6517dda703c35823a4aa5bfc20b50788ad282".into(),
        signing_keys: BTreeMap::from([(
            number(&config["signingKeyId"])?,
            hex::decode(text(&config["signingPublicKey"])?.trim_start_matches("0x"))?
                .try_into()
                .map_err(|_| "Signing key width")?,
        )]),
        signing_key_validity: BTreeMap::new(),
    };
    let sidecar: ProofSidecar = serde_json::from_value(record["sidecar"].clone())?;
    validate_proof_bundle(&sidecar.proof_bundle, &trust)?;
    let primary = JsonRpc::new(HttpTransport::new(text(&config["chainRpcUrl"])?)?);
    if number(&primary.call("eth_chainId", json!([]))?)? != U256::from(trust.scope.chain_id) {
        return Err("Primary chain mismatch".into());
    }
    let hash = env::var("TRANSACTION_HASH")?;
    if hash.len() != 66 {
        return Err("TRANSACTION_HASH required".into());
    }
    let receipt = primary.call("eth_getTransactionReceipt", json!([hash]))?;
    let tx = primary.call("eth_getTransactionByHash", json!([hash]))?;
    if receipt.is_null() || tx.is_null() || number(&receipt["status"])? != U256::from(1) {
        return Err("Successful receipt not yet available".into());
    }
    let block = primary.call(
        "eth_getBlockByNumber",
        json!([receipt["blockNumber"], false]),
    )?;
    if receipt["transactionHash"] != hash
        || tx["hash"] != hash
        || block["hash"] != receipt["blockHash"]
        || tx["blockHash"] != receipt["blockHash"]
        || !text(&tx["to"])?.eq_ignore_ascii_case(text(&config["protocolAddress"])?)
        || !text(&tx["input"])?.eq_ignore_ascii_case(text(&record["data"])?)
    {
        return Err("Canonical transaction mismatch".into());
    }
    let source = ProvenanceClient::new(text(&config["endpoint"])?, trust)?;
    let locator = json!({"txHash":hash,"blockHash":receipt["blockHash"],"operationIndex":"0"});
    let tracked = source.wait_tracking(
        text(&record["trackingId"])?,
        Duration::from_secs(2),
        Duration::from_secs(120),
    )?;
    let tracking = invisi_sdk::provenance_tracking::tracking_from_result(
        &tracked,
        Some(text(&record["trackingId"])?),
    )?;
    let matched = tracking.matched.ok_or("Tracking locator missing")?;
    if tracking.status != "recognized"
        || matched.tx_hash != hash
        || matched.block_hash != text(&receipt["blockHash"])?
        || matched.operation_index != "0"
        || n_digest(&tracking.operation_digest)? != number(&record["operationDigest"])?
    {
        return Err(
            "Tracking not recognized or matched another operation; retain original record".into(),
        );
    }
    let operation = source.get_operation_recognition(locator)?;
    if operation["recognitionState"] != "recognized" {
        return Err("Publication pending; retry the same tracking ID".into());
    }
    println!("Source service confirms operation recognition");
    Ok(())
}
fn n_digest(v: &str) -> Result<U256, Box<dyn std::error::Error>> {
    Ok(parse_integer(v, 256)?)
}
