//! Spend a previously recognized Note using the existing private transfer/Source APIs.
use alloy_primitives::B256;
use invisi_sdk::{
    protocol::TransactionCall,
    provenance_client::ProvenanceClient,
    prover::Prover,
    sdk::{self, ChainState, EvmSigningRequest, Invisi, TransferPreparation, Wallet},
};
use serde_json::{json, Value};

/// Inputs must be real discovered/decrypted, canonically authenticated unspent Notes.
/// Source proving replays recognition and verifies certificates/anchors; a caller's
/// status query alone cannot establish membership. Configure the SDK's native Source
/// capability as in 07-broadcaster before invoking this recipe.
#[allow(clippy::too_many_arguments)]
pub fn spend_recognized_note(
    sdk: &Invisi,
    chain: &dyn ChainState,
    wallet: &Wallet,
    source: &ProvenanceClient,
    prover: &dyn Prover,
    preparation: TransferPreparation,
    sign_wallet: impl FnOnce(&EvmSigningRequest) -> Result<Vec<u8>, String>,
    simulate_main: impl FnOnce(&TransactionCall) -> Result<(), String>,
    send_main: impl FnOnce(TransactionCall) -> Result<B256, String>,
) -> Result<Value, String> {
    if preparation.inputs.is_empty() {
        return Err("private Note inputs are required".into());
    }
    let prepared = sdk.prepare_transfer(wallet, preparation)?;
    let authorization = prepared.export_wallet_authorization()?;
    let signature = sign_wallet(&authorization)?;
    let ready = prepared
        .with_wallet_signature(&signature)?
        .prove(prover, false)?;
    let packet = ready.prove_provenance(chain)?;
    let evaluation = source.evaluate_transaction(json!(packet.data), &packet.sidecars)?;
    invisi_sdk::provenance_tracking::preflight_tracking(
        &evaluation,
        "0",
        &packet.operation_digest,
    )?;
    let call = ready.export_transaction()?;
    let packet_data = hex::decode(
        packet
            .data
            .strip_prefix("0x")
            .ok_or("0x Source calldata required")?,
    )
    .map_err(|error| error.to_string())?;
    if call.data != packet_data {
        return Err("main transaction does not match Provenance packet calldata".into());
    }
    simulate_main(&call)?;
    // SDK validates the public packet and submits it through submit_source_proof.
    // Source's public precheck/tracking is independent of canonical main execution.
    let accepted = sdk::submit_provenance_proof(source, &packet)?;
    // Recheck the submission acknowledgement: service state may have changed
    // since evaluation. A rejected, unavailable or mismatched operation cannot send.
    let tracking = invisi_sdk::provenance_tracking::preflight_tracking(
        &accepted,
        "0",
        &packet.operation_digest,
    )?;
    let hash = send_main(call)?;
    Ok(
        json!({"transactionHash": hash, "evaluation": evaluation, "sourceSubmission": accepted, "tracking": source.get_tracking(&tracking.id)?}),
    )
}
fn main() {
    println!("Host recipe: discover/authenticate recognized inputs, authorize private transfer, prove Core, prove Provenance, evaluate, submit public Source packet and send the same Core call. Main reads no files, keys or network. Source recognition remains asynchronous; inspect tracking instead of claiming immediate recognition.");
}
