//! Publish public receiving keys with an owner-signed EVM transaction to the pinned registry.

use alloy_primitives::{keccak256, Bytes, B256};
use alloy_sol_types::SolCall;
use invisi_sdk::{
    protocol::{IAddressRegistry, InvisiAddressRegistry, ProtocolContract},
    rpc::{CanonicalChain, CanonicalHead, EthereumChain, HttpTransport, ProtocolDeployment},
    sdk::{self, Wallet},
};
use serde_json::json;
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !env::args().any(|arg| arg == "--execute") {
        println!(
            "Pass --execute after configuring examples/README.md. No network or files were opened."
        );
        return Ok(());
    }

    let deployment: ProtocolDeployment =
        serde_json::from_slice(&fs::read(env::var("DEPLOYMENT_JSON")?)?)?;
    deployment.validate()?;
    let chain = EthereumChain::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?);
    if chain.chain_id()? != deployment.chain_id()? {
        return Err("provider chain mismatch".into());
    }
    let registry = deployment
        .registry
        .ok_or("deployment must pin an address registry")?;

    // Pin registry code and nonce to a canonical block before preparing registration calldata.
    let block = chain.head()?;
    if keccak256(chain.code_at(registry.address, Some(block.number))?) != registry.runtime_code_hash
    {
        return Err("registry runtime code mismatch".into());
    }

    let wallet = Wallet::from_address(&env::var("WALLET_ADDRESS")?)?;
    let keys = wallet
        .receiving_keys()
        .ok_or("a complete receiving address is required")?;
    let identity = sdk::field_word(sdk::address_word(wallet.owner_address()));
    let call = InvisiAddressRegistry::nonceOfCall {
        walletIdentity: identity,
    };
    let result = chain.call(registry.address, &call.abi_encode(), block.number)?;
    let nonce = InvisiAddressRegistry::nonceOfCall::abi_decode_returns(&result, true)?._0;
    let deadline: u64 = env::var("DEADLINE")?.parse()?;
    if deadline < block.timestamp {
        return Err("registration deadline expired".into());
    }

    let registration = IAddressRegistry::Registration {
        walletIdentity: identity,
        keys: IAddressRegistry::ReceivingKeys {
            viewingPublicKey: keys.viewing_public_key.to_vec().into(),
            clueKey: B256::from(keys.clue_key),
        },
        nonce,
        deadline,
    };
    let unsigned =
        ProtocolContract::new(registry.address)?.call(&InvisiAddressRegistry::registerKeysCall {
            registration,
            signature: Bytes::new(),
        });

    // Empty authorization is valid only when the EVM transaction caller is the owner.
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "chainId": deployment.chain_id,
            "from": wallet.owner_address(),
            "to": unsigned.to,
            "data": format!("0x{}", hex::encode(unsigned.data)),
            "value": "0",
        }))?
    );
    Ok(())
}
