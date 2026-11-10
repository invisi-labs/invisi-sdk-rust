//! Let the spender draw AMOUNT from earlier grants into one recipient Note, retaining separate
//! owner accounting.

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
    let chain = Arc::new(RpcChainState::new(ethereum, deployment.clone())?);
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

    let (discovery, pending) = invisi_sdk_examples::discover(
        &invisi,
        &wallet,
        deployment.clone(),
        &env::var("PROTOCOL_RPC_URL")?,
        &env::var("ETH_RPC_URL")?,
        env::var("FROM_BLOCK").ok().map(|s| s.parse()).transpose()?,
        env::var("TO_BLOCK").ok().map(|s| s.parse()).transpose()?,
    )?;

    // Only the native host can unlock the account and decrypt these candidates.
    println!(
        "Native discovery requests: {}",
        serde_json::to_string(pending.wallet_requests())?
    );
    let responses: Vec<sdk::WalletResponse> = if pending.wallet_requests().is_empty() {
        Vec::new()
    } else {
        eprintln!(
            "Execute the discovery array in your native host, then paste its response JSON array:"
        );
        let mut response_json = String::new();
        std::io::stdin().read_line(&mut response_json)?;
        serde_json::from_str(&response_json)?
    };

    // Canonical receipts, commitments and membership are checked before any input is selected.
    pending.apply_wallet_responses(&responses)?;
    let discovered = discovery.snapshot()?;

    let amount = U256::from_str_radix(&env::var("AMOUNT")?, 10)?;
    let inputs = invisi_sdk_examples::select_credit_draw(
        &discovered,
        token,
        amount,
        chain.snapshot()?.timestamp,
    )?;
    let recipient = Wallet::from_address(&env::var("RECIPIENT_ADDRESS")?)?;
    let prepared = invisi.prepare_draw_credit(
        &wallet,
        inputs,
        &recipient,
        deadline,
        Fee::default(),
        Vec::new(),
    )?;
    // One ordinary Note receives the total debit. Each owner's grant remains separately accounted.

    // Spender approval binds every grant debit and the recipient Note in this prepared plan.
    let prepared = if let Some(relay) = &relay {
        prepared.with_broadcaster(
            chain.clone(),
            relay.clone(),
            &sdk::BroadcasterOptions::default(),
        )?
    } else {
        prepared
    };
    let request = prepared.export_wallet_request("draw-credit-example")?;
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
