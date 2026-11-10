//! Revoke a grant by its public reference; an owner call or verified EVM relay signature needs no
//! private circuit proof.

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

    if env::args().any(|a| a == "--submit") && env::var("BROADCASTER_CONFIG").is_err() {
        return Err("BROADCASTER_CONFIG required for explicit relay submission".into());
    }

    let deployment: ProtocolDeployment =
        serde_json::from_slice(&fs::read(env::var("DEPLOYMENT_JSON")?)?)?;
    let ethereum = EthereumChain::new(HttpTransport::new(&env::var("ETH_RPC_URL")?)?);
    let chain = Arc::new(RpcChainState::new(ethereum, deployment)?);
    let invisi = Invisi::new(chain.clone());
    let wallet = Wallet::from_address(&env::var("WALLET_ADDRESS")?)?;
    let token: Address = env::var("TOKEN_ADDRESS")?.parse()?;
    let deadline: u64 = env::var("DEADLINE")?.parse()?;

    let relay = if let Ok(path) = env::var("BROADCASTER_CONFIG") {
        let config: invisi_sdk::broadcaster::Configuration =
            serde_json::from_slice(&fs::read(path)?)?;
        let mut relay = invisi_sdk::broadcaster::BroadcasterClient::connect(config)?;
        if let Ok(policy) = env::var("BROADCASTER_POLICY_ID") {
            relay = relay.with_provenance_policy(policy.parse()?)?;
        }
        Some(relay)
    } else {
        None
    };

    // These public references identify the earlier grant; no private Credit opening is needed.
    let shard = env::var("GRANT_SHARD")?.parse()?;
    let slot = env::var("GRANT_SLOT")?.parse()?;
    let mut prepared =
        invisi.prepare_revoke_credit(&wallet, token, shard, slot, deadline, Fee::default())?;
    // Credit lifecycle has no private Note source proof. Its existing lowlevel relay API is explicit.
    let quote = if let Some(relay) = &relay {
        let mut fee = relay.fee(token, None)?;
        let mut final_quote = None;
        for _ in 0..8 {
            let candidate = invisi.prepare_revoke_credit(
                &wallet,
                token,
                shard,
                slot,
                deadline,
                Fee {
                    recipient: fee.fee_recipient,
                    amount: U256::from_str_radix(&fee.fee_amount, 10)?,
                },
            )?;
            let unsigned = candidate.calldata(chain.as_ref(), wallet.owner_address())?;
            let next = relay.fee(token, Some(&unsigned.data))?;
            if next.fee_amount == fee.fee_amount && next.fee_recipient == fee.fee_recipient {
                final_quote = Some(relay.quote(
                    &unsigned.data,
                    chain.context().chain_id,
                    unsigned.to,
                    chain.snapshot()?.timestamp,
                )?);
                prepared = candidate;
                break;
            }
            fee = next;
        }
        Some(final_quote.ok_or("Credit relay fee convergence budget exceeded")?)
    } else {
        None
    };
    let caller: Address = if relay.is_some() {
        Address::ZERO
    } else {
        env::var("CALLER_ADDRESS")?.parse()?
    };

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

    if let (Some(relay), Some(quote)) = (&relay, &quote) {
        let id = env::var("BROADCAST_ID")?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(env::var("BROADCAST_RECORD")?)?;
        use std::io::Write;
        file.write_all(&serde_json::to_vec_pretty(&json!({"data":format!("0x{}",hex::encode(&call.data)),"broadcastId":id,"quote":quote.signed()}))?)?;
        file.sync_all()?;
        if env::args().any(|a| a == "--submit") {
            println!("{:?}", relay.submit(&call.data, quote, &id)?);
        }
        return Ok(());
    }

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
