//! Legacy native-only quote CLI (`quote`, not `quote_canonical_v3`/`quote_canonical_zeroex`).
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
            fees: vec![v3_fee()?],
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

fn v3_fee() -> std::result::Result<u32, Box<dyn std::error::Error>> {
    let fee = std::env::var("V3_FEE")
        .unwrap_or_else(|_| "3000".into())
        .parse::<u32>()?;
    if fee == 0 || fee >= (1 << 24) {
        return Err("V3_FEE must be a positive uint24 pool fee".into());
    }
    Ok(fee)
}

#[cfg(test)]
mod tests {
    #[test]
    fn explicit_v3_fee_is_used_and_validated() {
        let old = std::env::var_os("V3_FEE");
        std::env::set_var("V3_FEE", "500");
        let configured = super::v3_fee();
        std::env::set_var("V3_FEE", "16777216");
        let oversized = super::v3_fee();
        match old {
            Some(value) => std::env::set_var("V3_FEE", value),
            None => std::env::remove_var("V3_FEE"),
        }
        assert_eq!(configured.unwrap(), 500);
        assert!(oversized.is_err(), "pool fee must fit uint24");
    }
}
