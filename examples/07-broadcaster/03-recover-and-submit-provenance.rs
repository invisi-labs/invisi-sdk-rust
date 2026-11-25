//! Recover an encrypted payment journal and retained openings, then publish its Source proof.
mod support;
use invisi_sdk::sdk;
use std::{
    env,
    time::{Duration, Instant},
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let support::SessionRuntime {
        chain,
        session,
        source,
        ..
    } = support::session_runtime()?;
    let id = env::var("OPERATION_ID")?;
    let timeout = support::confirmation_timeout()?;
    let host_hash = env::var("HOST_TRANSACTION_HASH").ok();
    let until = Instant::now() + timeout;
    loop {
        match invisi_sdk_examples::recover_sent_operation(
            &session,
            chain.as_ref(),
            source.as_ref(),
            &id,
            Some("transfer"),
            host_hash.as_deref(),
        )? {
            Some(invisi_sdk_examples::Recovery::Confirmed(_)) => break,
            Some(invisi_sdk_examples::Recovery::Pending) => {
                if Instant::now() >= until {
                    return Err(
                        "canonical reconciliation timed out; retain the saved operation".into(),
                    );
                }
                std::thread::sleep(Duration::from_secs(2));
            }
            None => {
                return Err(
                    "saved operation has no sent transaction; recovery never submits a replacement"
                        .into(),
                )
            }
        }
    }
    if session.snapshot()?.operations[&id].status
        != invisi_sdk_session::session::OperationStatus::Confirmed
    {
        return Err("canonical payment execution did not succeed".into());
    }
    // Canonical reconciliation may finish the payment; retained openings remain available for Source.
    let packet = session.reprove_provenance_proof(&id)?;
    let source = support::source_client()?;
    let accepted = sdk::submit_provenance_proof(source.as_ref(), &packet)?;
    let tracking = invisi_sdk::provenance_tracking::tracking_from_result(&accepted, None)?;
    println!("Operation digest: {}", packet.operation_digest);
    println!("Source submission: {accepted}; tracking: {}", tracking.id);
    let recognition = source.wait_tracking(&tracking.id, Duration::from_secs(2), timeout)?;
    println!("Source recognition: {recognition}");
    Ok(())
}
