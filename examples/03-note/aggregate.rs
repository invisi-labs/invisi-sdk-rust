//! Move each selected Note's full amount to the recipient, then aggregate the independently
//! authorized proofs.

use alloy_primitives::Address;
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

    let deployment: ProtocolDeployment =
        serde_json::from_slice(&fs::read(env::var("DEPLOYMENT_JSON")?)?)?;
    let ethereum = EthereumChain::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?);
    let chain = Arc::new(RpcChainState::new(ethereum, deployment.clone())?);
    let invisi = Invisi::new(chain.clone());
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

    let count: usize = env::var("AGGREGATE_MEMBERS")
        .unwrap_or_else(|_| "2".into())
        .parse()?;
    if ![1, 2, 5].contains(&count) {
        return Err("AGGREGATE_MEMBERS must be 1, 2 or 5".into());
    }
    let inputs: Vec<_> = invisi_sdk_examples::note_inputs(&discovered, token)
        .into_iter()
        .take(count)
        .collect();
    if inputs.len() != count {
        return Err("not enough discovered unspent Notes; create earlier deposits first".into());
    }

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

    let recipient = Wallet::from_address(&env::var("RECIPIENT_ADDRESS")?)?;
    let mut members = Vec::new();
    for (index, input) in inputs.into_iter().enumerate() {
        let output = sdk::NoteOutput::for_recipient(
            chain.context(),
            token,
            &recipient,
            input.note.amount,
            Vec::new(),
        )?;
        let prepared = invisi.prepare_transfer(
            &wallet,
            sdk::TransferPreparation {
                token,
                inputs: vec![input],
                outputs: vec![output],
                withdrawal: None,
                funding: sdk::empty_funding(),
                fee: Fee::default(),
                deadline,
                automatic_change: false,
            },
        )?;

        // Each member needs its own approval before its recursive proof can enter the aggregate.
        let request = prepared.export_wallet_request(format!("aggregate-member-{index}"))?;
        println!(
            "Native wallet requests: {}",
            serde_json::to_string(std::slice::from_ref(&request))?
        );
        eprintln!(
            "Approve this member in your native host and paste its one-line response JSON array:"
        );
        let mut response_json = String::new();
        std::io::stdin().read_line(&mut response_json)?;
        let responses: Vec<sdk::WalletResponse> = serde_json::from_str(&response_json)?;
        wallet.accept_batch(std::slice::from_ref(&request), &responses)?;
        let response = responses
            .iter()
            .find(|response| response.id == request.id)
            .ok_or("missing wallet response")?;

        // Recursive proofs carry the verified member statement into the final aggregate.
        members.push(
            prepared
                .with_wallet_response(&request, response)?
                .prove(&prover, true)?,
        );
    }

    let prepared = invisi.aggregate(&prover, members)?;

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
