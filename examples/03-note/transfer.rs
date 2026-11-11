//! Spend earlier shielded Notes to send AMOUNT privately; any excess returns as encrypted change.

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

    // Authorize the frozen inputs and outputs so the proof cannot silently change the recipient or
    // amount.
    // Available before authorization, proof generation and token approval.
    println!("{}", serde_json::to_string(&prepared.estimate_gas()?)?);

    let request = prepared.export_wallet_authorization()?;
    let signature = invisi_sdk_examples::sign_authorization(&request)?;
    let prepared = prepared.with_wallet_signature(&signature)?;

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

    let prepared = prepared.prove(&prover, false)?;

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
