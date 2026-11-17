//! Let the spender draw AMOUNT from earlier grants into one recipient Note, retaining separate
//! owner accounting.

use alloy_primitives::{Address, U256};
use invisi_sdk::{
    rpc::{EthereumChain, HttpTransport, ProtocolDeployment},
    sdk::{ChainState, Fee, Invisi, RpcChainState, Wallet},
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

    let amount = U256::from_str_radix(&env::var("AMOUNT")?, 10)?;
    let inputs = invisi_sdk_examples::select_credit_draw(
        &discovered,
        token,
        amount,
        chain.snapshot()?.timestamp,
    )?;
    let prepared = invisi.prepare_draw_credit(
        &wallet,
        invisi_sdk::sdk::DrawCreditRequest {
            inputs,
            recipient: env::var("RECIPIENT_ADDRESS")?,
            deadline,
            fee: Fee::default(),
            payload: Vec::new(),
        },
        None,
    )?;
    // One ordinary Note receives the total debit. Each owner's grant remains separately accounted.

    // Spender approval binds every grant debit and the recipient Note in this prepared plan.
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
        assets: invisi_sdk_examples::prover_assets(),
        witness_executor: Arc::new(invisi_sdk::prover::NoirCli {
            binary: env::var("NOIR_EXECUTOR")?.into(),
            timeout: std::time::Duration::from_secs(120),
        }),
    };

    let prepared = prepared.prove(&prover)?;

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
