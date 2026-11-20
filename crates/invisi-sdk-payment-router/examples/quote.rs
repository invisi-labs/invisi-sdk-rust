//! Quote-only CLI. No signing, broadcasting or implicit API credentials.
use alloy_primitives::{Address, U256};
use invisi_sdk_payment_router::*;
use std::sync::Arc;
#[tokio::main(flavor = "current_thread")]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 11 {
        return Err("Usage: quote RPC_URL CHAIN_ID ROUTER CORE WETH DEX QUOTER TOKEN AMOUNT_OUT MAX_ETH_INPUT DEADLINE".into());
    }
    let address = |i: usize| args[i].parse::<Address>();
    let deployment = PaymentRouterDeployment {
        chain_id: args[1].parse()?,
        router_address: address(2)?,
        core_address: address(3)?,
        weth_address: address(4)?,
        uniswap_router_address: address(5)?,
        runtime_code_hash: None,
        zero_ex: None,
    };
    let provider = Arc::new(HttpRouterProvider::new(&args[0])?);
    let adapter = UniswapV3Adapter::new(
        provider.clone(),
        address(6)?,
        vec![V3Route {
            tokens: vec![deployment.weth_address, address(7)?],
            fees: vec![3000],
        }],
    )?;
    let client = PaymentRouterClient::new(deployment, provider)?;
    let quote = client
        .quote(
            &adapter,
            QuoteParameters {
                token_out: address(7)?,
                amount_out: U256::from_str_radix(&args[8], 10)?,
                max_input: U256::from_str_radix(&args[9], 10)?,
                deadline: args[10].parse()?,
                slippage_bps: Some(50),
                cancellation: None,
            },
        )
        .await?;
    println!(
        "Output: {} Estimated ETH input: {} Maximum ETH input: {} Deadline: {}",
        quote.amount_out, quote.estimated_input, quote.max_input, quote.deadline
    );
    Ok(())
}
