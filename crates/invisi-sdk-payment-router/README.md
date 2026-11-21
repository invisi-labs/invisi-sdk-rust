# Invisi Payment Router

**Unreleased source API (planned 1.3.3; crate versions remain 1.3.2).** The
canonical unversioned `PaymentRouter` and `PaymentRouterAccount` bindings for Periphery `ffd81f4`, with direct native/ERC20, signed ERC20 relay and EIP-7702 sponsored native payments. The optional crate composes detached Core proof preparation with Router intent signing, validated V3/0x routes, complete outer-call simulation and Broadcaster envelope submission. Wallet signatures remain host-provided. The dependency pin below identifies the current crate cohort; it does not claim these unreleased additions are published.

```toml
[dependencies]
invisi-sdk-payment-router = "=1.3.2"
```

The core SDK does not depend on this crate. Applications explicitly opt in and provide a trusted deployment, an async Ethereum provider and their existing SDK/wallet capabilities. Alloy `Address`, `U256` and `B256` types enforce address and integer representations. Chain IDs and deadlines are `u64`; amounts are checked against their protocol bounds.

## Canonical payments

Use `canonical::{Payment, Intent, Route, Permit, NativePayment}` for the new deployment. `PAYMENT_ROUTER_ABI` and `PAYMENT_ROUTER_ACCOUNT_ABI` are the actual compiler ABIs. The four execution modes are:

| Mode | Input / outer sender | Authorization |
| --- | --- | --- |
| `DIRECT_NATIVE=0` | Native / payer | Host signs its payable Router transaction |
| `DIRECT_TOKEN=1` | Any ERC20 / payer | Router approval or ERC-2612 permit; host signs transaction |
| `RELAYED_TOKEN=2` | Any ERC20 / fixed Broadcaster relayer | Router approval/permit plus payer's Router intent signature |
| `SPONSORED_NATIVE=3` | Native from payer EOA / fixed Broadcaster relayer | Account payment signature and optional EIP-7702 delegation authorization; zero outer value |

Route channels are None=0, V3=1, 0x=2. Native input is address zero. All routes and public proof fields are bound with canonical ABI encoding and EIP-712 domains from the contracts.

1. Configure `PaymentRouterClient` with the immutable deployment, preferably its runtime hash, and an explicit `RouterProvider`/`HttpRouterProvider`. `prepare_payment` prepares pure public funding with the Router as Core payer. Prove it through the existing SDK lifecycle and call `export_transaction()` for its detached Core call. Do not use live `calldata` export to require the Router to have settlement funds before its atomic swap. Funding authorization stays empty; the settlement token funding amount is exactly the positive Note outputs plus Core's token-denominated Broadcaster fee. For example, 100 USDT of Notes plus 0.2 USDT fee requires a 100.2 USDT exact-output route. There is no separate input-token fee. Supply the current positive fee as an explicit initial candidate, then use the executable estimate/rebuild loop below.
2. Read `router_nonce(payer)`, construct an `Intent` and `Route`, and call `prepare_canonical(core, intent, route)`. The builder validates the live deployment, route and nonce, and fills `coreRequestHash`/`routeHash` without changing proof-bound fields. Any stale registry/nonce, expired deadline or changed signed field requires rebuilding and signing again. Offline `Payment::prepare` accepts a host-validated timestamp and current Settler.
3. Sign `payment.digest(chain_id)` through the host wallet for relayed ERC20. Direct modes pass an empty Router signature. `payment.router_call(permit, signature)` produces the canonical call: native sends the maximum input as value; ERC20 sends zero value. `approval(token, router, amount)` prepares an ERC20 approval. `Permit` and `permit_digest` support ERC-2612 when the token implements it and the host has verified its domain/permit nonce. Permit is optional and separate from the intent signature. ERC1271 Router payers are validated by complete simulation rather than EOA recovery.
4. Call `simulate_canonical` with the actual outer sender before sending. It checks the current Router nonce and route, simulates the complete Router or delegated-account call, and estimates the same call's gas at one canonical block. Submitters use their existing transaction signer or the relay client below.

Before simulation or either relay quote method, the payer needs sufficient input balance. ERC20 inputs also require an effective Router allowance covering the input cap, or a valid ERC-2612 permit. `approval(token, router, amount)` only returns an unsigned call: the host must send it and wait for it to take effect. DEX liquidity and deployment/registry state must also make the complete call executable. An unsigned intent, empty proof, or unfunded payer cannot serve as a quote placeholder.

`Route::default()` is a no-swap route for same-token ERC20 and native-to-WETH wrapping. `quote_canonical_v3` supports arbitrary ERC20 input with the original V3 exact-output router's reversed path (use WETH as the V3 input for native payment modes); `encode_v3_exact_output_path` constructs it. The raw input estimate is returned so the host chooses the signed slippage cap. For 0x, call `quote_canonical_zeroex(&transport, core, intent, slippage_bps, cancellation)` with `ZeroExHttpTransport::new(api_key, None)` for built-in native or arbitrary ERC20 exact-buy HTTP. It sends Core's complete required funding as `buyAmount` and the Router as taker/recipient, maps native input to the API sentinel, and checks the current registry Settler before and after HTTP. The transport retains HTTPS/no-redirect rules, explicit sensitive credential headers, sanitized errors and cancellation. The convenience method canonicalizes accepted API sender aliases and narrows an unsigned native intent's cap/expiry to the accepted quote before returning the payment for wallet signing. `prepare_canonical_zeroex_quote` also accepts a host-fetched response when desired. Both paths check the native guard or canonical AllowanceHolder envelope, recipient, buy token/amount, input cap and chain. Applications must still review/simulate trusted Settler liquidity actions; envelope checks do not certify them.

```rust,no_run
use alloy_primitives::Bytes;
use invisi_sdk_payment_router::{canonical::*, PaymentRouterClient, Result};
use invisi_sdk_protocol::protocol::TransactionCall;

async fn build_direct(
    client: &PaymentRouterClient, proved_core: TransactionCall,
    intent: Intent, route: Route,
) -> Result<TransactionCall> {
    let payer = intent.payer;
    let payment = client.prepare_canonical(proved_core, intent, route).await?;
    let call = payment.router_call(Permit::default(), Bytes::new())?;
    client.simulate_canonical(&payment, call.clone(), payer, &[], None).await?;
    Ok(call)
}
```

## Sponsored native and Broadcaster

`AccountDeployment` requires the account implementation and its runtime hash. `prepare_native_account` checks implementation code, immutable Router/address/code hash, the installed `0xef0100 || implementation` delegation and independent account action nonce. It rejects an incompatible existing wallet delegation, including when pending delegation is allowed. With an empty payer account, explicit `allow_pending_delegation=true` permits preparing a new delegation. It never installs or replaces wallet code. Empty/revoked payer code still requires reading the namespaced account nonce with `eth_getStorageAt`; account storage survives revocation, so pending delegation never assumes nonce zero. Custom providers without storage reads fail explicitly for that path.

The host separately signs `AuthorizationRequest::digest()` for the exact chain, implementation and EOA authorization nonce, and `NativePayment::digest(chain_id)` for the payment. `SignedAuthorization` uses geth hex quantities. `NativePayment::envelope` attaches the wallet-signed list (or an empty list for an installed delegation). `simulate_canonical` verifies the account payment signature, action nonce, expiry, exact-chain authorization signatures, the current EOA transaction nonce for every supplied authorization, and the complete zero-value account transaction. The transaction-count read uses the same pinned block as simulation, including when the intended delegation is already installed; stale authorizations are rejected even if the EVM would skip them. Custom providers must implement `nonce_at` for this path. Pending authorization simulation needs RPC support for type-4 `authorizationList`; a provider without that capability fails explicitly. Track three payer nonce domains independently: Router intent nonce (`router_nonce`), delegated account action nonce (read by `prepare_native_account`), and the EOA transaction nonce used for EIP-7702 authorization (`AuthorizationRequest::nonce`). An authorization nonce is the EOA transaction-count domain, not another Router/account counter. The Broadcaster's own outer transaction nonce is separate. EIP-7702 delegation persists even if payment execution reverts, and revocation/reinstallation does not reset stored action nonce. Persistent delegation/revocation and wallet/chain/RPC capability detection remain host responsibilities.

`RouterRelayClient<T: RpcTransport>` uses the ordinary `broadcaster_estimateQuote`, `broadcaster_getQuote` and `broadcaster_submitTransaction` methods with `{data: embeddedCoreCalldata, router: {to, data, value: "0", authorizationList?}}`. Relayed ERC20 uses `payment.relay_envelope`; sponsored native uses the account envelope. Provide registered `Trust` (chain/Core/quote signer) and fee recipient. `get_quote`/`verify_quote` require direct execution, `requestHashFormat="payment-router-envelope-v1"`, exact envelope hash, unchanged Core settlement token/fee, bounded expiry and a trusted quote signature. `submit_transaction` rechecks this binding and sends `quote`, `signature` and caller-supplied provenance sidecars. Canonical Router payments use pure public funding with no foreign private Note inputs: use an empty sidecar list (`&[]`), even when the service's general capability metadata reports `provenanceRequired: true`. Ordinary private Core Source-proof rules are separate. Scheduling and aggregate execution are rejected.

Discover enabled `paymentRouters` policies through Broadcaster status/token-support and configure matching trusted pins; an empty policy list disables relay. Only the Core settlement/fee token needs Broadcaster price support, even when principal comes from native ETH or another ERC20.

Both `estimate_quote` and `get_quote` require the real full proof and valid payer Router/account signatures (and delegation authorization when needed). Both simulate and estimate the complete outer call through the service's chain RPC, including the authorization list, balances and permit/allowance. This Router flow is separate from ordinary Core `BroadcasterClient::quote` before proving.

The client does not rewrite a proof to accommodate a fee estimate: if `estimate_quote` changes the fee, prepare/prove the correct Core funding statement, rebuild the Router/account calldata and obtain fresh wallet signatures and a signed quote. A changed route, input cap, deadline, nonce or authorization also requires rebuilding and fresh applicable wallet signatures. Bound fee convergence attempts and total fees in the host; service submission rejects a stale fee/gas cap instead of increasing a signed fee. Simulate again near submission. Retain the returned service status and your transaction/provenance journal; the Router helper does not replace the core SDK's reconciliation lifecycle. `envelope_hash` matches the Go/Broadcaster ABI schema, including authorization tuple order and signatures.

## Compile-checked host recipes

See [`examples/canonical.rs`](examples/canonical.rs) for real prepare/prove/export,
intent construction, self-submitted ERC20, relayed ERC20 and sponsored native with
injected host signing callbacks. It also shows `estimate_quote` fee convergence,
`get_quote` verification and explicit `submit_transaction(..., &[])`. Its main
prints guidance without opening RPC, fabricating proofs or broadcasting. Run:

```sh
cargo check -p invisi-sdk-payment-router --examples
cargo test -p invisi-sdk-payment-router --doc
cargo run -p invisi-sdk-payment-router --example canonical
```

The host configures `RouterRelayClient::new(transport, Trust { chain_id, protocol,
signer }, fee_recipient)` with registered Broadcaster trust. Keep returned
submission IDs and frozen original envelopes for status/idempotent recovery.

## Legacy native-only APIs

The following existing `quote`, `build_payment_transaction`, `build_prepared_payment_transaction` and `simulate_payment` APIs target the previous native-only contracts (`pay`/`payWithZeroEx`). They remain available for existing deployments. `LEGACY_PAYMENT_ROUTER_ABI` and `ZERO_EX_PAYMENT_ROUTER_ABI` expose those ABIs. Use the canonical APIs above for the unversioned Router; no deployment autodetection or fallback changes the selected ABI.

## Legacy configure and quote

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
