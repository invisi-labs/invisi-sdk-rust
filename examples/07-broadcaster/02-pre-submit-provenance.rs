//! Prepare and authorize a private payment, obtain Source precheck, then send through the host.
mod support;
use alloy_primitives::{Address, U256};
use invisi_sdk::sdk::{self, ChainState, Wallet};
use invisi_sdk_session::session::{RefreshOptions, SessionTransactionOptions};
use std::{
    env,
    time::{Duration, Instant},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let support::SessionRuntime {
        chain,
        session,
        prover,
        from_block,
    } = support::session_runtime()?;
    let mut refresh = RefreshOptions::from_block(
        env::var("FROM_BLOCK")
            .ok()
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(from_block),
    );
    refresh.to_block = env::var("TO_BLOCK").ok().map(|s| s.parse()).transpose()?;
    session
        .refresh(refresh)?
        .decrypt(&invisi_sdk_examples::AppDecryptor)?;
    let recipient = Wallet::from_address(&env::var("RECIPIENT_ADDRESS")?)?;
    let token: Address = env::var("TOKEN_ADDRESS")?.parse()?;
    let amount = U256::from_str_radix(&env::var("AMOUNT")?, 10)?;
    let output =
        sdk::NoteOutput::for_recipient(chain.context(), token, &recipient, amount, Vec::new())?;
    let mut operation = session.prepare_transfer(sdk::TransferPreparation {
        token,
        inputs: Vec::new(),
        outputs: vec![output],
        withdrawal: None,
        funding: sdk::empty_funding(),
        fee: sdk::Fee::default(),
        deadline: env::var("DEADLINE")?.parse()?,
        automatic_change: true,
    })?;
    println!("Saved operation: {}", operation.id());
    let request = operation.export_wallet_authorization()?;
    let signature = invisi_sdk_examples::sign_authorization(&request)?;
    operation = operation
        .with_wallet_signature(&signature)?
        .prove(prover.as_ref(), false)?;
    let packet = operation.prove_provenance()?;
    let source = support::source_client()?;
    let accepted = sdk::submit_provenance_proof(source.as_ref(), &packet)?;
    let tracking = invisi_sdk::provenance_tracking::tracking_from_result(&accepted, None)?;
    println!("Operation digest: {}", packet.operation_digest);
    println!("Source precheck: {accepted}; tracking: {}", tracking.id);
    let sender = invisi_sdk_examples::AppTransactionSender::connect(&env::var("ETH_RPC_URL")?)?;
    let transaction = session.send_transaction(
        &mut operation,
        &sender,
        SessionTransactionOptions {
            caller: env::var("CALLER_ADDRESS")?.parse()?,
            gas_limit: env::var("GAS_LIMIT")?.parse()?,
        },
    )?;
    println!("Payment transaction: {transaction}");
    let timeout = support::confirmation_timeout()?;
    let until = Instant::now() + timeout;
    loop {
        let observed = operation.confirmation()?;
        if observed.level == invisi_sdk::rpc::ConfirmationLevel::Finalized
            && observed.status == invisi_sdk::rpc::FinalityStatus::Available
        {
            break;
        }
        if Instant::now() >= until {
            return Err(
                "native finality timed out; recover the saved operation instead of resending"
                    .into(),
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    match session.reconcile(operation.id())? {
        invisi_sdk_session::session::Reconciliation::Ready(pending) => {
            pending.decrypt(&invisi_sdk_examples::AppDecryptor)?;
        }
        invisi_sdk_session::session::Reconciliation::Pending => {
            return Err("finalized receipt not yet available to reconciliation".into())
        }
    }
    if session.snapshot()?.operations[operation.id()].status
        != invisi_sdk_session::session::OperationStatus::Confirmed
    {
        return Err("canonical payment execution did not succeed".into());
    }
    let recognition = source.wait_tracking(&tracking.id, Duration::from_millis(500), timeout)?;
    println!("Source recognition after native finality: {recognition}");
    Ok(())
}
