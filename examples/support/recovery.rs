//! Recover the original exported intent before opening any signing or proving capability.
use invisi_sdk::{rpc::CanonicalBlock, sdk::ChainState};
use invisi_sdk_session::session::{Reconciliation, SessionSource, WalletSession};

#[derive(Debug, PartialEq, Eq)]
pub enum Recovery {
    Pending,
    Confirmed(CanonicalBlock),
}

pub fn recover_sent_operation(
    session: &WalletSession,
    chain: &dyn ChainState,
    source: &dyn SessionSource,
    id: &str,
    kind: Option<&str>,
    host_hash: Option<&str>,
) -> Result<Option<Recovery>, String> {
    use alloy_primitives::B256;
    use invisi_sdk_session::session::OperationStatus;
    let state = session.snapshot()?;
    if state.invalidated {
        return Err("wallet requires canonical resync".into());
    }
    if chain.context() != session.scope().context {
        return Err("chain deployment mismatch".into());
    }
    let record = state.operations.get(id).ok_or("operation not found")?;
    if kind.is_some_and(|kind| kind != record.kind) {
        return Err("OPERATION_ID belongs to a different operation kind".into());
    }
    if source.context() != session.scope().context {
        return Err("source deployment mismatch".into());
    }
    let supplied = host_hash
        .map(|value| {
            if value.len() != 66 || !value.starts_with("0x") {
                return Err("transaction hash must be 0x-prefixed 32-byte hex".to_owned());
            }
            let hash: B256 = value.parse().map_err(|_| "invalid transaction hash")?;
            if hash == B256::ZERO {
                return Err("nonzero transaction hash required".into());
            }
            Ok(hash)
        })
        .transpose()?;
    if supplied
        .zip(record.transaction_hash)
        .is_some_and(|(a, b)| a != b)
    {
        return Err("operation already tracks another transaction".into());
    }
    let hash = supplied.or(record.transaction_hash);
    if record.status.terminal() {
        if record.status != OperationStatus::Confirmed {
            return Err("saved operation did not confirm successfully".into());
        }
        let hash = hash.ok_or("confirmed operation lacks a transaction hash")?;
        if record.transaction_hash != Some(hash) || hash == B256::ZERO {
            return Err("confirmed operation lacks its original transaction hash".into());
        }
        let resolved = record
            .resolved_at
            .as_ref()
            .ok_or("confirmed operation lacks canonical resolution")?;
        let receipt = source
            .receipt(hash)?
            .ok_or("confirmed receipt no longer available")?;
        let transaction = source
            .transaction(hash)?
            .ok_or("confirmed transaction no longer available")?;
        let call = record
            .call
            .as_ref()
            .ok_or("exported calldata unavailable")?;
        let data_matches = if record.broadcaster_id.is_some() {
            record
                .snapshot
                .validate_broadcaster_submission(&call.data)?;
            record.snapshot.broadcaster_execution().map_or(
                transaction.input == call.data,
                |execution| {
                    invisi_sdk::broadcaster::matches_execution_transaction(
                        &call.data,
                        execution,
                        &transaction.input,
                    )
                },
            )
        } else {
            transaction.input == call.data
        };
        if !record.externalized
            || !receipt.success
            || receipt.transaction_hash != hash
            || receipt.block != *resolved
            || transaction.hash != hash
            || transaction.to != Some(call.to)
            || transaction.value != call.value
            || transaction.chain_id != session.scope().context.chain_id
            || transaction.block.as_ref() != Some(resolved)
            || !data_matches
            || chain.context() != session.scope().context
            || source.context() != session.scope().context
        {
            return Err("confirmed transaction differs from the original frozen operation".into());
        }
        chain.canonical(resolved)?;
        return Ok(Some(Recovery::Confirmed(resolved.clone())));
    }
    let Some(hash) = hash else {
        if record.externalized {
            return Err("exported transaction may have been sent; provide its original HOST_TRANSACTION_HASH; do not export or resend".into());
        }
        return Ok(None);
    };
    if record.transaction_hash.is_none() {
        // Restoring solely to attach a sent hash never authorizes or exports another call.
        session.resume(id, None)?.track_transaction(hash)?;
    }
    match session.reconcile(id)? {
        Reconciliation::Pending => Ok(Some(Recovery::Pending)),
        Reconciliation::Ready(pending) => {
            let applied = pending.decrypt(&super::AppDecryptor)?;
            if session.snapshot()?.operations[id].status != OperationStatus::Confirmed {
                return Err("canonical transaction execution did not succeed".into());
            }
            Ok(Some(Recovery::Confirmed(applied.block)))
        }
    }
}

#[cfg(test)]
mod tests;

/// Cancel only a saved attempted handoff; the explicit replay option can recover its remote ID.
pub fn cancel_saved_operation<T: invisi_sdk::rpc::RpcTransport + 'static>(
    session: &WalletSession,
    chain: &dyn ChainState,
    relay: &invisi_sdk::broadcaster::BroadcasterClient<T>,
    id: &str,
    recover_submit_id: bool,
) -> Result<(), String> {
    let state = session.snapshot()?;
    if state.invalidated {
        return Err("wallet requires canonical resync".into());
    }
    if chain.context() != session.scope().context {
        return Err("chain deployment mismatch".into());
    }
    let record = state.operations.get(id).ok_or("operation not found")?;
    if record.broadcaster_id.as_deref() != Some(id) || !record.externalized || record.call.is_none()
    {
        return Err(
            "saved Broadcaster attempt required; recovery never creates a new intent".into(),
        );
    }
    if record.status.terminal() {
        if record.status != invisi_sdk_session::session::OperationStatus::Failed
            || !record.broadcaster_cancelled
            || record.transaction_hash.is_some()
        {
            return Err("saved operation was not canonically cancelled".into());
        }
        chain.canonical(
            record
                .resolved_at
                .as_ref()
                .ok_or("cancelled operation lacks canonical resolution")?,
        )?;
        return Ok(());
    }
    if record.broadcaster_submission_id.is_none() && !recover_submit_id {
        return Err("submission ID unknown; pass --recover-submit-id to replay only the original frozen attempt before cancellation".into());
    }
    let mut recovered = session.resume(id, None)?;
    if record.broadcaster_submission_id.is_none() {
        // Explicit opt-in only: the SDK authenticates and replays the original frozen attempt.
        relay.submit(&mut recovered, chain)?;
    }
    // A durable acknowledgement bypasses relay IO while canonical cleanup is retried.
    let cancelled = relay.cancel(&mut recovered)?;
    if cancelled.state != invisi_sdk::broadcaster::StatusState::Cancelled
        || cancelled.transaction_hash.is_some()
    {
        return Err(
            "Cancellation was not acknowledged; saved operation retains its reservations".into(),
        );
    }
    Ok(())
}

/// Read the original relay binding without updating the journal or opening signing tools.
pub fn saved_broadcaster_configuration(
    session: &WalletSession,
    id: &str,
) -> Result<invisi_sdk::broadcaster::Configuration, String> {
    use invisi_sdk_session::session::ManagedPrepared;
    let state = session.snapshot()?;
    if state.invalidated {
        return Err("wallet requires canonical resync".into());
    }
    let record = state.operations.get(id).ok_or("operation not found")?;
    if record.broadcaster_id.as_deref() != Some(id) || !record.externalized || record.call.is_none()
    {
        return Err("saved Broadcaster attempt required".into());
    }
    let prepared = record.snapshot.restore(session.wallet(), None)?;
    let saved = match &prepared {
        ManagedPrepared::Funds(value) => value.broadcaster_state(),
        ManagedPrepared::Credit(value) => value.broadcaster_state(),
    }
    .ok_or("saved Broadcaster configuration unavailable")?;
    Ok(invisi_sdk::broadcaster::Configuration {
        endpoint: saved.endpoint.clone(),
        quote_signer: saved.signer,
        fee_recipient: saved.fee_recipient,
    })
}
