//! Spend earlier shielded Notes to send AMOUNT privately; any excess returns as encrypted change.

mod support;
use alloy_primitives::{Address, U256};
use invisi_sdk::{
    rpc::{EthereumChain, HttpTransport, ProtocolDeployment},
    sdk::{self, ChainState, Fee, Invisi, RpcChainState, Wallet},
};
use std::{env, fs, sync::Arc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !std::env::args().any(|arg| arg == "--execute") {
        println!("Pass --execute after configuring the environment described in examples/README.md. No network, files or keys were opened.");
        return Ok(());
    }

    let deployment: ProtocolDeployment =
        serde_json::from_slice(&fs::read(env::var("DEPLOYMENT_JSON")?)?)?;
    let ethereum = EthereumChain::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?);
    let chain = Arc::new(RpcChainState::new(ethereum, deployment.clone())?);
    let prover = Arc::new(invisi_sdk::prover::NativeProver {
        bb_binary: env::var("BB_BINARY")?.into(),
        timeout: std::time::Duration::from_secs(600),
        threads: 4,
        assets: Arc::new(invisi_sdk::prover::DirectoryAssets {
            directory: env::var("PROVER_ASSETS")?.into(),
        }),
        witness_executor: Arc::new(invisi_sdk::prover::NoirCli {
            binary: env::var("NOIR_EXECUTOR")?.into(),
            timeout: std::time::Duration::from_secs(120),
        }),
    });
    let mut invisi = Invisi::new(chain.clone()).with_prover(prover.clone())?;
    if env::var("SOURCE_PROVIDER_ID").is_ok() {
        invisi = invisi.with_provenance(Arc::new(
            sdk::PreparedProvenance::from_local_configuration(support::source_configuration()?)?,
        ))?;
    }
    let relay = Arc::new(invisi_sdk::broadcaster::BroadcasterClient::connect(
        invisi_sdk::broadcaster::Configuration {
            endpoint: env::var("BROADCASTER_ENDPOINT")?,
            quote_signer: env::var("BROADCASTER_QUOTE_SIGNER")?.parse()?,
            fee_recipient: env::var("BROADCASTER_FEE_RECIPIENT")?.parse()?,
        },
    )?);
    let wallet = Wallet::from_address(&env::var("WALLET_ADDRESS")?)?;
    let token: Address = env::var("TOKEN_ADDRESS")?.parse()?;
    let deadline: u64 = env::var("DEADLINE")?.parse()?;
    if !relay.supports_token(
        token,
        chain.context().chain_id,
        sdk::word_address(chain.context().protocol_address)?,
    )? {
        return Err("Broadcaster does not support this token".into());
    }

    let (discovery, pending) = invisi_sdk_examples::discover(
        &invisi,
        &wallet,
        deployment.clone(),
        &env::var("PROTOCOL_RPC_URL")?,
        &env::var("ETH_RPC_URL")?,
        env::var("FROM_BLOCK").ok().map(|s| s.parse()).transpose()?,
        env::var("TO_BLOCK").ok().map(|s| s.parse()).transpose()?,
    )?;

    // The application decryptor returns plaintext; the SDK checks openings against chain data.
    pending.decrypt(&invisi_sdk_examples::AppDecryptor)?;

    let discovered = discovery.snapshot()?;

    let recipient = Wallet::from_address(&env::var("RECIPIENT_ADDRESS")?)?;
    let amount = U256::from_str_radix(&env::var("AMOUNT")?, 10)?;
    let selection_amount = amount;
    let inputs = invisi_sdk_examples::select_notes(&discovered, token, selection_amount)?;
    let output =
        sdk::NoteOutput::for_recipient(chain.context(), token, &recipient, amount, Vec::new())?;
    let prepared = invisi.prepare_transfer(
        &wallet,
        sdk::TransferPreparation {
            token,
            inputs,
            outputs: vec![output],
            withdrawal: None,
            funding: sdk::empty_funding(),
            fee: Fee::default(),
            deadline,
            automatic_change: true,
        },
    )?;

    let prepared = prepared.with_broadcaster(
        chain.clone(),
        relay.clone(),
        &sdk::BroadcasterOptions {
            max_fee_amount: Some(U256::from_str_radix(&env::var("MAX_FEE_AMOUNT")?, 10)?),
            ..Default::default()
        },
    )?;
    // Authorize the frozen inputs and outputs so the proof cannot silently change the recipient or
    // amount.
    let request = prepared.export_wallet_authorization()?;
    let signature = invisi_sdk_examples::sign_authorization(&request)?;
    let prepared = prepared.with_wallet_signature(&signature)?;

    // Proof generation uses pinned circuit assets and independently verifies the resulting proof.

    let mut prepared = prepared.prove(prover.as_ref(), None)?;
    prepared.freeze_broadcaster_evidence(chain.as_ref(), relay.as_ref())?;
    let status = prepared.submit_broadcaster(chain.as_ref(), relay.as_ref())?;
    println!("{}", serde_json::to_string_pretty(&status)?);
    let limit = std::time::Duration::from_secs(
        env::var("CONFIRMATION_TIMEOUT_SECONDS")
            .unwrap_or_else(|_| "180".into())
            .parse()?,
    );
    let until = std::time::Instant::now() + limit;
    let mut status = status;
    let transaction = loop {
        if let Some(hash) = status.transaction_hash {
            break hash;
        }
        if matches!(
            status.state,
            invisi_sdk::broadcaster::StatusState::Rejected
                | invisi_sdk::broadcaster::StatusState::Expired
                | invisi_sdk::broadcaster::StatusState::Reverted
        ) {
            return Err("broadcast failed before canonical inclusion".into());
        }
        if std::time::Instant::now() >= until {
            return Err(
                "broadcast status timed out; preserve the submitted operation for recovery".into(),
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
        status = relay.status(&status.id)?;
    };
    let until = std::time::Instant::now() + limit;
    loop {
        let observed = chain.transaction_confirmation(transaction)?;
        if observed.level == invisi_sdk::rpc::ConfirmationLevel::Finalized
            && observed.status == invisi_sdk::rpc::FinalityStatus::Available
        {
            break;
        }
        if std::time::Instant::now() >= until {
            return Err("native finality wait timed out; do not resend the transaction".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let independent = EthereumChain::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?);
    let receipt = invisi_sdk::rpc::ChainReceipts::receipt(&independent, transaction)?
        .ok_or("finalized receipt unavailable")?;
    if !receipt.success {
        return Err("canonical transaction reverted".into());
    }
    if prepared
        .broadcaster_state()
        .is_some_and(|state| state.provenance_mode().is_some())
    {
        let source = support::source_client()?;
        let packet = prepared.prove_provenance(chain.as_ref())?;
        let accepted = sdk::submit_provenance_proof(source.as_ref(), &packet)?;
        let tracking = invisi_sdk::provenance_tracking::tracking_from_result(&accepted, None)?;
        let result =
            source.wait_tracking(&tracking.id, std::time::Duration::from_millis(500), limit)?;
        println!("Source tracking after native finality: {result}");
    }
    Ok(())
}
