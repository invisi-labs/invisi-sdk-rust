//! Let the owner create spending authority for a spender; available Credit is authority, not
//! escrowed funds.

use alloy_primitives::{Address, U256};
use invisi_sdk::{
    rpc::{EthereumChain, HttpTransport, ProtocolDeployment},
    sdk::{self, ChainState, Fee, Invisi, RpcChainState, Wallet},
};
use serde_json::json;
use std::{env, fs, sync::Arc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !std::env::args().any(|arg| arg == "--execute") {
        println!("Pass --execute after configuring the environment described in examples/README.md. No network, files or keys were opened.");
        return Ok(());
    }

    if env::args().any(|a| a == "--submit") && env::var("BROADCASTER_CONFIG").is_err() {
        return Err("BROADCASTER_CONFIG required for explicit relay submission".into());
    }

    let deployment: ProtocolDeployment =
        serde_json::from_slice(&fs::read(env::var("DEPLOYMENT_JSON")?)?)?;
    let ethereum = EthereumChain::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?);
    let chain = Arc::new(RpcChainState::new(ethereum, deployment)?);
    let invisi = Invisi::new(chain.clone());
    let relay = if let Ok(path) = env::var("BROADCASTER_CONFIG") {
        let config: invisi_sdk::broadcaster::Configuration =
            serde_json::from_slice(&fs::read(path)?)?;
        let mut relay = invisi_sdk::broadcaster::BroadcasterClient::connect(config)?;
        if let Ok(policy) = env::var("BROADCASTER_POLICY_ID") {
            relay = relay.with_provenance_policy(policy.parse()?)?;
        }
        Some(Arc::new(relay))
    } else {
        None
    };
    let wallet = Wallet::from_address(&env::var("WALLET_ADDRESS")?)?;
    let token: Address = env::var("TOKEN_ADDRESS")?.parse()?;
    let deadline: u64 = env::var("DEADLINE")?.parse()?;

    // Allocate a fresh public revocation reference before freezing the grant and both role
    // deliveries.
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

    // Zero single/day/month limits disable those checks; available credit remains a finite balance.
    let prepared = invisi.prepare_create_credit(&wallet, state, deadline, Fee::default())?;

    // Owner approval binds the allocated grant, spender, expiry and policy before proving.
    let prepared = if let Some(relay) = &relay {
        prepared.with_broadcaster(
            chain.clone(),
            relay.clone(),
            &sdk::BroadcasterOptions::default(),
        )?
    } else {
        prepared
    };
    let request = prepared.export_wallet_request("create-credit-example")?;
    println!(
        "Native wallet requests: {}",
        serde_json::to_string(std::slice::from_ref(&request))?
    );
    eprintln!("Have your native host approve and execute this request array, then paste its one-line response JSON array:");
    let mut response_json = String::new();
    std::io::stdin().read_line(&mut response_json)?;
    let responses: Vec<sdk::WalletResponse> = serde_json::from_str(&response_json)?;
    wallet.accept_batch(std::slice::from_ref(&request), &responses)?;
    let response = responses
        .iter()
        .find(|response| response.id == request.id)
        .ok_or("missing wallet response")?;
    let prepared = prepared.with_wallet_response(&request, response)?;

    // Proof generation uses pinned circuit assets and independently verifies the resulting proof.
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

    let prepared = prepared.prove(&prover)?;

    if let Some(relay) = &relay {
        let caller = Address::ZERO;
        let call = prepared.calldata(chain.as_ref(), caller)?;
        let id = env::var("BROADCAST_ID")?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(env::var("BROADCAST_RECORD")?)?;
        use std::io::Write;
        file.write_all(&serde_json::to_vec_pretty(&json!({"data":format!("0x{}",hex::encode(&call.data)),"broadcastId":id,"context":prepared.broadcaster_state().ok_or("saved Credit relay context required")?}))?)?;
        file.sync_all()?;
        if env::args().any(|a| a == "--submit") {
            println!(
                "{:?}",
                prepared.submit_broadcaster(chain.as_ref(), relay.as_ref(), &id)?
            );
        }
        return Ok(());
    }

    let caller: Address = env::var("CALLER_ADDRESS")?.parse()?;
    let call = prepared.calldata(&*chain, caller)?;

    // An EVM signer in the host reviews, signs and broadcasts this unsigned transaction.
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
