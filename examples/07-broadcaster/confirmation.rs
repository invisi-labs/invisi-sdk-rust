//! Observe a transaction using the independent Chain RPC, never relay claims.
use alloy_primitives::B256;
use invisi_sdk::rpc::{read_transaction_confirmation, EthereumChain, HttpTransport};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::var("CHAIN_RPC_URL")?;
    let hash: B256 = std::env::args()
        .nth(1)
        .ok_or("transaction hash required")?
        .parse()?;
    let chain = EthereumChain::new(HttpTransport::new(&url)?);
    let confirmation = read_transaction_confirmation(&chain, hash)?;
    println!("{}", serde_json::to_string(&confirmation)?);
    Ok(())
}
