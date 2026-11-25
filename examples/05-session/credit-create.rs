//! Refresh encrypted Credit inventory, create a managed grant operation, or resume its saved ID.
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
    let session = WalletSession::connect(invisi, wallet, store, source.clone(), "examples")?;

    let host_hash = env::var("HOST_TRANSACTION_HASH").ok();
    if let Ok(id) = env::var("OPERATION_ID") {
        if let Some(recovery) = invisi_sdk_examples::recover_sent_operation(
            &session,
            chain.as_ref(),
            source.as_ref(),
            &id,
            Some("create-credit"),
            host_hash.as_deref(),
        )? {
            match recovery {
                invisi_sdk_examples::Recovery::Pending => {
                    println!("Transaction is not yet canonically available.")
                }
                invisi_sdk_examples::Recovery::Confirmed(block) => println!(
                    "Reconciliation applied at canonical block {}.",
                    block.number
                ),
            }
            return Ok(());
        }
    } else if host_hash.is_some() {
        return Err("HOST_TRANSACTION_HASH requires the original OPERATION_ID".into());
    }

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
        let pending = invisi_sdk_examples::refresh_receipt_ranges(&session, options)?;
        pending.decrypt(&invisi_sdk_examples::AppDecryptor)?;
    }

    let operation = if let Ok(id) = env::var("OPERATION_ID") {
        let saved = session.snapshot()?;
        let record = saved.operations.get(&id).ok_or("operation not found")?;
        if record.kind != "create-credit" {
            return Err("OPERATION_ID belongs to a different operation kind".into());
        }
        session.resume(&id, Some(&prover))?
    } else {
        // Select a random grant ID once before freezing both role deliveries.
        let wallet = session.wallet();
        let spender = Wallet::from_address(&env::var("SPENDER_ADDRESS")?)?;
        let grant_id = sdk::random_grant_id();
        let state = invisi_sdk::delivery::CreditDeliveryState {
            note: invisi_sdk::credit::CreditState {
                context: chain.context(),
                token_address: sdk::address_word(token),
                owner_wallet_identity: sdk::address_word(wallet.owner_address()),
                spender_wallet_identity: sdk::address_word(spender.owner_address()),
                grant_id,
                nonce: invisi_sdk::note::generate_nonce(),
                expiry: env::var("EXPIRES_AT")?.parse()?,
                credit_shared_key: invisi_sdk::note::generate_credit_shared_key(),
                policy: invisi_sdk::credit::CreditPolicy::default(),
                usage: invisi_sdk::credit::CreditUsage::default(),
                available_credit: U256::from_str_radix(&env::var("AVAILABLE_CREDIT")?, 10)?,
                unlimited: env::var("UNLIMITED")
                    .unwrap_or_else(|_| "false".into())
                    .parse()?,
                payload: Vec::new(),
            },
            owner_receiving_keys: wallet.receiving_keys().clone(),
            spender_receiving_keys: spender.receiving_keys().clone(),
        };

        session.prepare_create_credit_explicit(
            state,
            env::var("DEADLINE")?.parse()?,
            Fee::default(),
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

    Ok(())
}
