//! Revoke a grant by its public reference; an owner call or verified EVM relay signature needs no
//! private circuit proof.

use alloy_primitives::Address;
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
    let chain = Arc::new(RpcChainState::new(ethereum, deployment)?);
    let invisi = Invisi::new(chain.clone());
    let wallet = Wallet::from_address(&env::var("WALLET_ADDRESS")?)?;
    let token: Address = env::var("TOKEN_ADDRESS")?.parse()?;
    let deadline: u64 = env::var("DEADLINE")?.parse()?;

    // These public references identify the earlier grant; no private Credit opening is needed.
    let shard = env::var("GRANT_SHARD")?.parse()?;
    let slot = env::var("GRANT_SLOT")?.parse()?;
    let mut prepared =
        invisi.prepare_revoke_credit(&wallet, token, shard, slot, deadline, Fee::default())?;
    let caller: Address = env::var("CALLER_ADDRESS")?.parse()?;

    // Relayers need owner EVM consent; this signature is separate from native circuit
    // authorization.
    if caller != wallet.owner_address() {
        println!(
            "Public EVM revocation authorization: {}",
            serde_json::to_string_pretty(&prepared.export_revocation_authorization()?)?
        );
        eprintln!("Sign through the owner's EVM host, then paste the hexadecimal signature:");
        let mut signature = String::new();
        std::io::stdin().read_line(&mut signature)?;
        let signature = hex::decode(
            signature
                .trim()
                .strip_prefix("0x")
                .ok_or("0x signature required")?,
        )?;
        prepared = prepared.with_revocation_signature(&*chain, signature)?;
    }

    let call = prepared.calldata(&*chain, caller)?;

    // The host signs and submits this unsigned EVM transaction after reviewing the revocation.
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
