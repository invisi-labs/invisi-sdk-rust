//! Read actual Source status without treating a successful receipt as recognition.
use alloy_primitives::{B256, U256};
use invisi_sdk::provenance_client::ProvenanceClient;
use serde_json::{json, Value};

/// Host supplies a trust-configured Source client, actual transaction hash and Note commitment.
/// This query reveals interest in public commitments; no opening or witness is uploaded.
pub fn query_router_output(
    source: &ProvenanceClient,
    transaction: B256,
    commitment: U256,
) -> Result<Value, String> {
    Ok(json!({
        "transaction": source.get_transaction_recognition(&format!("{transaction:#x}"))?,
        "note": source.get_note_recognition(commitment)?,
    }))
}
fn main() {
    println!("Host recipe: query_router_output accepts a pinned Source client and actual confirmed Router transaction/Note commitment. It returns service states and reasons unchanged. Main performs no network request. See examples/09-provenance/README.md.");
}
