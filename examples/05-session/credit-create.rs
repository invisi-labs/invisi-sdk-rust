//! Refresh encrypted Credit inventory, create a managed grant operation, or resume its saved ID.

use alloy_primitives::{Address, U256};
use invisi_sdk::{
    rpc::{EthereumChain, HttpTransport, ProtocolDeployment, ProtocolRpcClient},
    sdk::{self, ChainState, Fee, Invisi, RpcChainState, Wallet},
    session::{sqlite::SQLiteRecords, EncryptedWalletStore, WalletSession},
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
        assets: Arc::new(invisi_sdk::prover::DirectoryAssets {
            directory: env::var("PROVER_ASSETS")?.into(),
        }),
        witness_executor: Arc::new(invisi_sdk::prover::NoirCli {
            binary: env::var("NOIR_EXECUTOR")?.into(),
            timeout: std::time::Duration::from_secs(120),
        }),
    };

    let token: Address = env::var("TOKEN_ADDRESS")?.parse()?;
    let caller: Address = env::var("CALLER_ADDRESS")?.parse()?;

    // Refresh and authenticate earlier grants before choosing inputs for a new operation.
    if env::var("OPERATION_ID").is_err() {
        let mut options = invisi_sdk::session::RefreshOptions::from_block(
            env::var("FROM_BLOCK")
                .ok()
                .map(|s| s.parse())
                .transpose()?
                .unwrap_or(from_block),
        );
        options.to_block = env::var("TO_BLOCK").ok().map(|s| s.parse()).transpose()?;
        let pending = session.refresh(options)?;
        println!(
            "Native discovery requests: {}",
            serde_json::to_string(pending.wallet_requests())?
        );
        let responses: Vec<sdk::WalletResponse> = if pending.wallet_requests().is_empty() {
            Vec::new()
        } else {
            eprintln!("Execute the discovery array in your native host, then paste its response JSON array:");
            let mut response_json = String::new();
            std::io::stdin().read_line(&mut response_json)?;
            serde_json::from_str(&response_json)?
        };
        pending.apply_wallet_responses(&responses)?;
    }

    let operation = if let Ok(id) = env::var("OPERATION_ID") {
        let saved = session.snapshot()?;
        let record = saved.operations.get(&id).ok_or("operation not found")?;
        if record.kind != "create-credit" {
            return Err("OPERATION_ID belongs to a different operation kind".into());
        }
        session.resume(&id, Some(&prover))?
    } else {
        // Allocate a fresh public revocation reference before freezing the grant and both role
        // deliveries.
        let wallet = session.wallet();
        let spender = Wallet::from_address(&env::var("SPENDER_ADDRESS")?)?;
        let anchor = chain.snapshot()?;
        let (shard, slot) = chain.credit_allocation(wallet.owner_address(), token, &anchor)?;
        let state = invisi_sdk::delivery::CreditDeliveryState {
            note: invisi_sdk::credit::CreditState {
                context: chain.context(),
                token_address: sdk::address_word(token),
                owner_wallet_identity: sdk::address_word(wallet.owner_address()),
                spender_wallet_identity: sdk::address_word(spender.owner_address()),
                revocation_shard: shard,
                revocation_slot: slot,
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
            owner_receiving_keys: wallet
                .receiving_keys()
                .ok_or("WALLET_ADDRESS must be a complete receiving address")?
                .clone(),
            spender_receiving_keys: spender
                .receiving_keys()
                .ok_or("SPENDER_ADDRESS must be a complete receiving address")?
                .clone(),
        };

        session.prepare_create_credit(state, env::var("DEADLINE")?.parse()?, Fee::default())?
    };

    println!("Operation ID: {}", operation.id());
    let mut operation = operation;

    // Restored, verified proofs can skip approval and proving; unfinished plans still need native
    // consent.
    if matches!(
        operation.phase(),
        sdk::Phase::Prepared | sdk::Phase::Authorized
    ) {
        let request = operation.export_wallet_request("session-credit-create-example")?;
        println!(
            "Native wallet requests: {}",
            serde_json::to_string(std::slice::from_ref(&request))?
        );
        eprintln!("Approve through your native host and paste its one-line response JSON array:");
        let mut response_json = String::new();
        std::io::stdin().read_line(&mut response_json)?;
        let responses: Vec<sdk::WalletResponse> = serde_json::from_str(&response_json)?;
        session
            .wallet()
            .accept_batch(std::slice::from_ref(&request), &responses)?;
        let response = responses
            .iter()
            .find(|response| response.id == request.id)
            .ok_or("missing wallet response")?;

        operation = operation
            .with_wallet_response(response)?
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
            invisi_sdk::session::Reconciliation::Pending => {
                println!("Transaction is not yet canonically available.")
            }
            invisi_sdk::session::Reconciliation::Ready(pending) => {
                println!(
                    "Reconciliation viewing requests: {}",
                    serde_json::to_string(pending.wallet_requests())?
                );
                let responses = if pending.wallet_requests().is_empty() {
                    Vec::new()
                } else {
                    eprintln!(
                        "Execute the native viewing requests, then paste the response JSON array:"
                    );
                    let mut response_json = String::new();
                    std::io::stdin().read_line(&mut response_json)?;
                    serde_json::from_str(&response_json)?
                };
                let applied = pending.apply_wallet_responses(&responses)?;
                println!(
                    "Reconciliation applied at canonical block {}.",
                    applied.block.number
                );
            }
        }
    }
    Ok(())
}
