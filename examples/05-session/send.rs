//! Discover deposits and prepare a managed transfer, or resume the saved operation and reconcile
//! its exact transaction.
use invisi_sdk_session::session::{sqlite::SQLiteRecords, EncryptedWalletStore, WalletSession};

use alloy_primitives::{Address, U256};
use invisi_sdk::{
    rpc::{EthereumChain, HttpTransport, ProtocolDeployment, ProtocolRpcClient},
    sdk::{self, ChainState, Fee, Invisi, RpcChainState, Wallet},
};
use serde_json::json;
use std::{env, fs, sync::Arc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !std::env::args().any(|arg| arg == "--execute") {
        println!("Pass --execute after configuring the environment described in examples/README.md. No network, files or keys were opened.");
        return Ok(());
    }

    let deployment: ProtocolDeployment =
        serde_json::from_slice(&fs::read(env::var("DEPLOYMENT_JSON")?)?)?;
    let from_block = deployment.protocol.from_block;
    let ethereum = EthereumChain::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?);
    let chain = Arc::new(RpcChainState::new(ethereum, deployment.clone())?);
    let invisi = Invisi::new(chain.clone());
    let wallet = Wallet::from_address(&env::var("WALLET_ADDRESS")?)?;
    let source = Arc::new(ProtocolRpcClient::new(
        HttpTransport::protocol(&env::var("PROTOCOL_RPC_URL")?, deployment.chain_id()?)?,
        EthereumChain::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?),
        deployment,
    )?);

    // This is a host-provided storage-encryption key, not an account or wallet private key.
    let key_bytes = zeroize::Zeroizing::new(fs::read(env::var("WALLET_STORE_KEY_FILE")?)?);
    let storage_key: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "storage key must contain 32 raw bytes")?;
    let records = Arc::new(SQLiteRecords::open(env::var("WALLET_DB")?)?);
    let store = Arc::new(EncryptedWalletStore::new(records, storage_key)?);
    let session = WalletSession::connect(invisi, wallet, store, source, "examples")?;

    let prover = invisi_sdk::prover::NativeProver {
        bb_binary: env::var("BB_BINARY")?.into(),
        timeout: std::time::Duration::from_secs(600),
        threads: 4,
        assets: invisi_sdk_examples::prover_assets(),
        witness_executor: Arc::new(invisi_sdk::prover::NoirCli {
            binary: env::var("NOIR_EXECUTOR")?.into(),
            timeout: std::time::Duration::from_secs(120),
        }),
    };

    let token: Address = env::var("TOKEN_ADDRESS")?.parse()?;
    let caller: Address = env::var("CALLER_ADDRESS")?.parse()?;

    // New transfers discover the preceding deposits; resumed operations retain their frozen inputs.
    if env::var("OPERATION_ID").is_err() {
        let mut options = invisi_sdk_session::session::RefreshOptions::from_block(
            env::var("FROM_BLOCK")
                .ok()
                .map(|s| s.parse())
                .transpose()?
                .unwrap_or(from_block),
        );
        options.to_block = env::var("TO_BLOCK").ok().map(|s| s.parse()).transpose()?;
        let pending = invisi_sdk_examples::refresh_receipt_ranges(&session, options)?;
        pending.decrypt(&invisi_sdk_examples::AppDecryptor)?;
    }

    let operation = if let Ok(id) = env::var("OPERATION_ID") {
        // Resume verifies saved proof metadata and its proof against the configured backend.
        session.resume(&id, Some(&prover))?
    } else {
        let recipient = Wallet::from_address(&env::var("RECIPIENT_ADDRESS")?)?;
        let amount = U256::from_str_radix(&env::var("AMOUNT")?, 10)?;
        let output =
            sdk::NoteOutput::for_recipient(chain.context(), token, &recipient, amount, Vec::new())?;
        session.prepare_transfer(sdk::TransferPreparation {
            token,
            inputs: Vec::new(),
            outputs: vec![output],
            withdrawal: None,
            funding: sdk::empty_funding(),
            fee: Fee::default(),
            deadline: env::var("DEADLINE")?.parse()?,
            automatic_change: true,
        })?
    };

    println!("Operation ID: {}", operation.id());
    let mut operation = operation;

    // A host hash enters recovery before any attempt to export a fresh transaction.
    if let Ok(hash) = env::var("HOST_TRANSACTION_HASH") {
        // The host has already signed and submitted this exact unsigned transaction.
        operation.track_transaction(hash.parse()?)?;
        match session.reconcile(operation.id())? {
            invisi_sdk_session::session::Reconciliation::Pending => {
                println!("Transaction is not yet canonically available.")
            }
            invisi_sdk_session::session::Reconciliation::Ready(pending) => {
                let applied = pending.decrypt(&invisi_sdk_examples::AppDecryptor)?;

                println!(
                    "Reconciliation applied at canonical block {}.",
                    applied.block.number
                );
            }
        }
        return Ok(());
    }

    // Restored verified proofs can skip approval and proving.
    if matches!(
        operation.phase(),
        sdk::Phase::Prepared | sdk::Phase::Authorized
    ) {
        let request = operation.export_wallet_authorization()?;
        let signature = invisi_sdk_examples::sign_authorization(&request)?;
        operation = operation
            .with_wallet_signature(&signature)?
            .prove(&prover, false)?;
    }

    // Export fences cancellation before exposing a transaction that the host could submit.
    let call = operation.calldata(caller)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "chainId": chain.context().chain_id.to_string(),
            "from": caller,
            "to": call.to,
            "data": format!("0x{}", hex::encode(call.data)),
            "value": call.value.to_string(),
        }))?
    );

    Ok(())
}
