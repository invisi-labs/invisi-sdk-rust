//! Recover an encrypted payment journal and retained openings, then publish its Source proof.
mod support;
use invisi_sdk::sdk::{self, ChainState};
use invisi_sdk_session::session::Reconciliation;
use std::{
    env,
    time::{Duration, Instant},
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let support::SessionRuntime {
        chain,
        session,
        prover,
        ..
    } = support::session_runtime()?;
    let id = env::var("OPERATION_ID")?;
    let timeout = support::confirmation_timeout()?;
    let state = session.snapshot()?;
    let record = state.operations.get(&id).ok_or("operation not found")?;
    if record.status.terminal() {
        chain.canonical(
            record
                .resolved_at
                .as_ref()
                .ok_or("completed payment lacks canonical resolution")?,
        )?;
    } else {
        let mut operation = session.resume(&id, Some(prover.as_ref()))?;
        // Supply only the original sent hash when a crash prevented the host from recording it.
        if let Ok(hash) = env::var("HOST_TRANSACTION_HASH") {
            operation.track_transaction(hash.parse()?)?;
        }
        let until = Instant::now() + timeout;
        loop {
            match session.reconcile(&id)? {
                Reconciliation::Ready(pending) => {
                    pending.decrypt(&invisi_sdk_examples::AppDecryptor)?;
                    break;
                }
                Reconciliation::Pending => {
                    if Instant::now() >= until {
                        return Err(
                            "canonical reconciliation timed out; retain the saved operation".into(),
                        );
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
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
    let recognition = source.wait_tracking(&tracking.id, Duration::from_millis(500), timeout)?;
    println!("Source recognition: {recognition}");
    Ok(())
}
