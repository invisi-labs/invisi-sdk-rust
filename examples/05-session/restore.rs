//! Rediscover earlier outputs through native viewing and atomically restore validated inventory
//! into encrypted SQLite.
use invisi_sdk_session::session::{
    sqlite::SQLiteRecords, RecordWalletStore, ScanOptions, WalletSession,
};

use alloy_primitives::Address;
use invisi_sdk::{
    rpc::{EthereumChain, HttpTransport, ProtocolDeployment, ProtocolRpcClient},
    sdk::{Invisi, RpcChainState, Wallet},
};
use invisi_sdk_session::public_history::{
    PublicHistory, PublicHistoryScope, PublicHistoryStore, Retention,
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
    let public_scope = PublicHistoryScope {
        chain_id: deployment.chain_id()?,
        protocol_address: deployment.protocol.address,
        runtime_code_hash: deployment.protocol.runtime_code_hash,
        deployment_block: from_block,
    };
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
    let database = env::var("WALLET_DB")?;
    let records = Arc::new(SQLiteRecords::open(&database)?);
    let store = Arc::new(RecordWalletStore::new(records, storage_key)?);
    let public_records = Arc::new(SQLiteRecords::open_public(&database)?);
    let public_store = Arc::new(PublicHistoryStore::new(
        public_records,
        Retention::default(),
    )?);
    let history = Arc::new(PublicHistory::new(
        public_store,
        public_scope,
        source.clone(),
    )?);

    let session = WalletSession::connect(invisi, wallet, store, source, "examples")?
        .with_public_history(history)?;
    let options = ScanOptions {
        from_block: env::var("FROM_BLOCK").ok().map(|s| s.parse()).transpose()?,
        to_block: env::var("TO_BLOCK").ok().map(|s| s.parse()).transpose()?,
        ..Default::default()
    };
    let refreshed = session.scan(&invisi_sdk_examples::AppDecryptor, options)?;
    println!("Scan state: {:?}", session.scan_status()?);

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
