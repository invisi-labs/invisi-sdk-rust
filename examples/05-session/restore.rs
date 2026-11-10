//! Rediscover earlier outputs through native viewing and atomically restore validated inventory
//! into encrypted SQLite.

use alloy_primitives::Address;
use invisi_sdk::{
    rpc::{EthereumChain, HttpTransport, ProtocolDeployment, ProtocolRpcClient},
    sdk::{Invisi, RpcChainState, Wallet},
    session::{sqlite::SQLiteRecords, EncryptedWalletStore, WalletSession},
};
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

    let mut options = invisi_sdk::session::RefreshOptions::from_block(
        env::var("FROM_BLOCK")
            .ok()
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(from_block),
    );
    options.to_block = env::var("TO_BLOCK").ok().map(|s| s.parse()).transpose()?;
    let pending = session.refresh(options)?;

    // Discovery only stages work; an unlock error must leave the saved checkpoint unchanged.
    let refreshed = pending.decrypt(&invisi_sdk_examples::AppDecryptor)?;

    let token: Address = env::var("TOKEN_ADDRESS")?.parse()?;
    let balance = session.balance(token)?;
    println!(
        "Canonical block: {}, recovered Notes: {}, Credit states: {}",
        refreshed.block.number, refreshed.notes, refreshed.credits
    );
    println!(
        "Known balance: {}, available: {:?}",
        balance.known, balance.available
    );
    Ok(())
}
