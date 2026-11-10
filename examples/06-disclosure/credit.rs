//! Discover an owner grant and reveal its financial opening while keeping the Credit shared key
//! private.

use alloy_primitives::Address;
use invisi_sdk::{
    disclosure::{Disclosure, DisclosureOutput, DisclosureRole},
    rpc::{EthereumChain, HttpTransport, ProtocolDeployment},
    sdk::{Invisi, RpcChainState, Wallet},
};
use std::{env, fs, sync::Arc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !env::args().any(|arg| arg == "--execute") {
        println!("Pass --execute to discover an earlier financial output and explicitly disclose its opening.");
        return Ok(());
    }

    let deployment: ProtocolDeployment =
        serde_json::from_slice(&fs::read(env::var("DEPLOYMENT_JSON")?)?)?;
    let ethereum = EthereumChain::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?);
    let chain = Arc::new(RpcChainState::new(ethereum, deployment.clone())?);
    let invisi = Invisi::new(chain);
    let wallet = Wallet::from_address(&env::var("WALLET_ADDRESS")?)?;
    let token: Address = env::var("TOKEN_ADDRESS")?.parse()?;

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

    let index: usize = env::var("CREDIT_INDEX")
        .unwrap_or_else(|_| "0".into())
        .parse()?;
    let input = invisi_sdk_examples::credit_inputs(
        &discovered,
        token,
        invisi_sdk::delivery::CreditRole::Owner,
    )
    .into_iter()
    .nth(index)
    .ok_or("no discovered owner Credit at CREDIT_INDEX")?;
    let disclosure = Disclosure::from_credit(&input.delivery.note)?;

    // Disclosure is a deliberate privacy boundary, separate from wallet authorization or proving.
    let exported = disclosure.export();
    disclosure.verify(&DisclosureOutput {
        context: exported.context.clone(),
        role: DisclosureRole::Owner,
        ciphertext: None,
    })?;

    // The export contains the shared-key hash, never the private Credit shared key.
    println!("{}", serde_json::to_string_pretty(&exported)?);
    Ok(())
}
