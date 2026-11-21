//! Refresh encrypted Credit inventory, draw a managed grant operation, or resume its saved ID.
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

    // Refresh and authenticate earlier grants before choosing inputs for a new operation.
    if env::var("OPERATION_ID").is_err() {
        let mut options = invisi_sdk_session::session::RefreshOptions::from_block(
            env::var("FROM_BLOCK")
                .ok()
                .map(|s| s.parse())
                .transpose()?
                .unwrap_or(from_block),
        );
        options.to_block = env::var("TO_BLOCK").ok().map(|s| s.parse()).transpose()?;
        let pending = session.refresh(options)?;
        pending.decrypt(&invisi_sdk_examples::AppDecryptor)?;
    }

    let operation = if let Ok(id) = env::var("OPERATION_ID") {
        let saved = session.snapshot()?;
        let record = saved.operations.get(&id).ok_or("operation not found")?;
        if record.kind != "draw-credit" {
            return Err("OPERATION_ID belongs to a different operation kind".into());
        }
        session.resume(&id, Some(&prover))?
    } else {
        // A merchant collects the same debit from two independent payer grants into one Note.
        let debit = U256::from_str_radix(&env::var("DEBIT_PER_GRANT")?, 10)?;
        if debit == U256::ZERO {
            return Err("DEBIT_PER_GRANT must be positive".into());
        }
        let deadline: u64 = env::var("DEADLINE")?.parse()?;
        let timestamp = chain.snapshot()?.timestamp;
        let inventory = session
            .credit_inventory(Some(token), Some(invisi_sdk::delivery::CreditRole::Spender))?;
        let mut owners = std::collections::BTreeSet::new();
        let mut selections = Vec::new();
        for (key, credit) in inventory {
            let grant = &credit.delivery.note;
            if credit.status != 1
                || credit.consumed
                || credit.revoked
                || credit.reserved_by.is_some()
                || grant.expiry <= timestamp
                || grant.expiry < deadline
                || owners.contains(&grant.owner_wallet_identity)
                || invisi_sdk::credit::apply_credit_draw_usage(grant, debit, timestamp).is_err()
            {
                continue;
            }
            owners.insert(grant.owner_wallet_identity);
            selections.push((key, debit));
            if selections.len() == 2 {
                break;
            }
        }
        if selections.len() != 2 {
            return Err(
                "two distinct owners with eligible unreserved spender grants are required".into(),
            );
        }
        // The SDK rechecks both inputs and creates one recipient Note for their summed debits.
        let recipient = Wallet::from_address(&env::var("RECIPIENT_ADDRESS")?)?;
        session.prepare_draw_credit_explicit(
            &selections,
            &recipient,
            deadline,
            Fee::default(),
            Vec::new(),
        )?
    };

    println!("Operation ID: {}", operation.id());
    let mut operation = operation;

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
    }
    Ok(())
}
