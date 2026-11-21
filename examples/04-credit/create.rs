//! Let the owner create spending authority for a spender; available Credit is authority, not
//! escrowed funds.

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

    let prepared = invisi.prepare_create_credit(
        &wallet,
        sdk::CreateCreditRequest {
            grant_id: None,
            credit_shared_key: None,
            // Gross owner debit includes the broadcaster fee; the encrypted first Note belongs to the spender.
            initial_payment: env::var("INITIAL_PAYMENT_GROSS")
                .ok()
                .map(|value| {
                    value
                        .parse::<U256>()
                        .map(|amount| sdk::InitialCreditPayment {
                            net_amount: None,
                            amount,
                            payload: Vec::new(),
                        })
                })
                .transpose()?,
            token,
            spender: env::var("SPENDER_ADDRESS")?,
            policy: invisi_sdk::credit::CreditPolicy::default(),
            available_credit: U256::from_str_radix(&env::var("AVAILABLE_CREDIT")?, 10)?,
            unlimited: env::var("UNLIMITED")
                .unwrap_or_else(|_| "false".into())
                .parse()?,
            expiry: env::var("EXPIRES_AT")?.parse()?,
            payload: Vec::new(),
            deadline,
            fee: Fee::default(),
        },
        None,
    )?;

    // Owner approval binds the allocated grant, spender, expiry and policy before proving.
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
