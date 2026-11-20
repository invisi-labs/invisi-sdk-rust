# Invisi Payment Router

Optional native ETH payment orchestration for the reviewed Invisi Payment Router contracts. The crate composes the existing `invisi-sdk` preparation/proof lifecycle with exact-output Uniswap V3 routes and registry-verified native 0x quotes. It never signs or broadcasts transactions.

```toml
[dependencies]
invisi-sdk-payment-router = "=1.3.1"
```

The core SDK does not depend on this crate. Applications explicitly opt in and provide a trusted deployment, an async Ethereum provider and their existing SDK/wallet capabilities. Alloy `Address`, `U256` and `B256` types enforce address and integer representations. Chain IDs and deadlines are `u64`; amounts are checked against their protocol bounds.

## Configure and quote

`PaymentRouterDeployment` requires chain ID, Router, Core, WETH and original V3 router addresses. All addresses must be nonzero and distinct. Supply `runtime_code_hash` to pin the Router bytecode. Enabling 0x additionally requires an allowance holder and Settler registry. No deployment addresses or credentials are inferred.

```rust,no_run
use std::sync::Arc;
use alloy_primitives::{Address, U256};
use invisi_sdk_payment_router::*;

async fn quote_native_payment(
    deployment: PaymentRouterDeployment,
    quoter: Address,
    token: Address,
    deadline: u64,
) -> Result<SwapQuote> {
    let provider = Arc::new(HttpRouterProvider::new("http://127.0.0.1:8545")?);
    let client = PaymentRouterClient::new(deployment.clone(), provider.clone())?;
    let adapter = UniswapV3Adapter::new(provider, quoter, vec![V3Route {
        tokens: vec![deployment.weth_address, token], fees: vec![3000],
    }])?;
    client.quote(&adapter, QuoteParameters {
        token_out: token,
        amount_out: U256::from(10),
        max_input: U256::from(1_000_000_000_000_000_000u64),
        deadline,
        slippage_bps: Some(50),
        cancellation: None,
    }).await
}
```

The V3 adapter reverses configured forward paths, calls QuoterV2 at the client-selected block, tolerates failed individual routes and chooses the least estimated input within the budget. Its ceiling-rounded slippage budget uses integer arithmetic. Slippage defaults to 50 basis points, with an inclusive range of 0–10000. WETH output is unsupported.

For native 0x exact-buy quotes use `ZeroExAdapter::new(ZeroExHttpTransport::new(api_key, None)?)`, or inject an async closure taking an owned `SwapQuoteRequest` and returning JSON. The explicit HTTP transport requires HTTPS, disallows endpoint credentials/query/fragment, rejects redirects and sanitizes transport/HTTP/JSON errors. `with_backend` supports host-managed HTTP implementations; these must not follow redirects or log requests carrying credentials. Both `buyAmount` and Router taker/recipient are sent. No sell-only quote substitution occurs.

A quote is accepted only after authenticating chain, code and Router getters, resolving `ownerOf(2)` for the current Settler, validating exact output and the single native guard, and refreshing the chain frame after transport. Returned quotes own their data, so callers and transports cannot rewrite retained financial requirements. `CancellationToken` supports explicit cancellation; HTTP operations are cancelled while in flight, and provider/adapter boundaries recheck cancellation.

## Prepare, prove, build and simulate

```rust,no_run
use alloy_primitives::Address;
use invisi_sdk::sdk::{Invisi, Wallet};
use invisi_sdk::prover::Prover;
use invisi_sdk_payment_router::*;
use invisi_sdk_protocol::protocol::TransactionCall;

async fn payment(
    client: &PaymentRouterClient,
    sdk: &Invisi,
    wallet: &Wallet,
    prover: &dyn Prover,
    preparation: RouterPaymentPreparation,
    quote: SwapQuote,
    submitting_wallet: Address,
) -> Result<TransactionCall> {
    let prepared = client.prepare_payment(sdk, wallet, preparation).await?;
    let ready = prepared.prove(prover, false)
        .map_err(Error::Preparation)?;
    let call = client.build_prepared_payment_transaction(
        &ready, quote, submitting_wallet,
    ).await?;
    let simulation = client.simulate_payment(call.clone(), submitting_wallet).await?;
    assert!(simulation.eth_spent <= call.value);
    Ok(call) // The host chooses whether to sign and submit.
}
```

Preparation requires at least two positive Note outputs, includes the explicit fee in positive uint128 funding, selects no private inputs and uses the Router as the canonical direct payer. The SDK validates output context/order, builds the real witness and binds the proved statement. `build_prepared_payment_transaction` uses the SDK detached `export_transaction` method, retaining phase/proof checks without requiring the Router to hold tokens or approve Core before its atomic swap. Existing SDK `calldata` retains live funding validation. `build_payment_transaction` also accepts an already-exported core `TransactionCall`.

The builder checks the actual tuple `transact` ABI, nonempty proof, canonical direct funding, empty sources/nullifiers/withdrawal, output shape/field/uniqueness, delivery encodings, fee pairing and core deadline. Quote token, amount and deadline must match the existing proof's requirements. The builder preserves proof/request values and canonicalizes nested 0x envelopes before encoding `pay` or `payWithZeroEx`. Refund recipients must be nonzero and differ from the Router.

Simulation validates the complete payable Router call and performs both `eth_call` and `eth_estimateGas` at the authenticated block with the actual sender. It returns gas estimate, ETH spent and ETH refunded, and rejects spends above the attached budget. Provider errors/reverts propagate. Authentication and hash rechecks detect deployment mismatches and reorganizations; this preflight snapshot cannot guarantee later execution. Contracts enforce current deadlines, Settler and balances again at execution.

`RouterProvider` is an injectable async interface. Its reads, calls and gas estimates receive explicit block numbers. `HttpRouterProvider` is the default JSON-RPC adapter. `PAYMENT_ROUTER_ABI` and `ZERO_EX_PAYMENT_ROUTER_ABI` expose reviewed snapshots; `abi` supplies typed Alloy Router and 0x calls. `encode_v3_exact_output_path`, `validate_v3_path` and `validate_zeroex_payload` are independently usable.

## Verification

```sh
cargo test -p invisi-sdk-payment-router
INVISI_PAYMENT_ROUTER_FIXTURE=/path/to/isolated-anvil-fixture.json \
  cargo test -p invisi-sdk-payment-router --test anvil
```

Package-local fixtures are generated by the TypeScript reference and checked against native Rust encoding: all paths, 14 positive/negative native 0x cases and three complete payment/simulation cases. Independent tests cover deployment/reorg/registry/time guards, malformed funding/delivery shapes, integer budgets, cancellation, HTTP sanitization and the real SDK prepare/prove/export lifecycle with an explicit test prover boundary.

The opt-in Anvil test requires the isolated loopback fixture generated from the reviewed contracts. It builds and simulates in Rust, then its test host uses an unlocked local account to check execution, exact spend/refund, Core custody, Payment event/proof hash, cleared approvals and failed-Core rollback for V3, direct 0x and holder-wrapped 0x. These use Core/DEX test doubles and do not establish production proof verification or live external DEX/API acceptance.
