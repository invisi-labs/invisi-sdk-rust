//! Shield AMOUNT from an approved public ERC20 balance into an encrypted recipient Note.

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
    let chain = Arc::new(RpcChainState::new(ethereum, deployment)?);
    let invisi = Invisi::new(chain.clone());
    let wallet = Wallet::from_address(&env::var("WALLET_ADDRESS")?)?;
    let token: Address = env::var("TOKEN_ADDRESS")?.parse()?;
    let deadline: u64 = env::var("DEADLINE")?.parse()?;

    let recipient = Wallet::from_address(&env::var("RECIPIENT_ADDRESS")?)?;
    let amount = U256::from_str_radix(&env::var("AMOUNT")?, 10)?;
    let output =
        sdk::NoteOutput::for_recipient(chain.context(), token, &recipient, amount, Vec::new())?;

    // Direct funding pulls exactly AMOUNT from the payer's existing balance and protocol allowance.
    let mut funding = sdk::empty_funding();
    funding.amount = amount;
    funding.payer = wallet.owner_address();
    let prepared = invisi.prepare_shield(
        &wallet,
        sdk::ShieldPreparation {
            token,
            outputs: vec![output],
            funding,
            fee: Fee::default(),
            deadline,
        },
    )?;
    println!("{}", serde_json::to_string(&prepared.estimate_gas()?)?);
    let prepared = prepared.ready()?;

    // Direct funding requires CALLER_ADDRESS to equal the public funding payer.
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
