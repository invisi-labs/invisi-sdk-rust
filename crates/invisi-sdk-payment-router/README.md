# Invisi Payment Router

**Canonical API in 1.3.4.** The
canonical unversioned `PaymentRouter` and `PaymentRouterAccount` bindings for Periphery `ffd81f4`, with direct native/ERC20, signed ERC20 relay and EIP-7702 sponsored native payments. The optional crate composes detached Core proof preparation with Router intent signing, validated V3/0x routes, complete outer-call simulation and Broadcaster envelope submission. Wallet signatures remain host-provided.

```toml
[dependencies]
invisi-sdk-payment-router = "=1.3.4"
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

1. Configure `PaymentRouterClient` with immutable deployment/runtime pins and a `RouterProvider`. `prepare_payment` prepares pure public funding with the Router as Core payer. Call `prepared.broadcaster_intent()` to export the unproved Core draft. Settlement funding equals positive Note outputs plus the Core-token Broadcaster fee: 100 USDT of Notes plus 0.2 USDT fee requires 100.2 USDT exact output. Supply a positive fee candidate and keep host fee convergence bounded.
2. Read `router_nonce(payer)`, finalize `Intent` and `Route`, then call `prepare_canonical_draft(core, intent, route)` or offline `Payment::prepare_draft`. Draft preparation validates business fields without requiring a proof. `payment.estimate_gas(permit_enabled, authorization_count, trusted_zeroex_budget)` uses the existing Core shape baseline plus the bundled conservative `payment-router-gas-v1` allowances. These have `source="model"`; Router allowances are engineering budgets, not receipt-calibrated swap measurements. Opaque 0x has no available estimate without a trusted service-policy route gas budget.
3. Build `payment.draft_relay_envelope(permit)` for relayed ERC20, retaining any permit deadline while leaving signatures empty. For native, use `prepare_native_account` and `native.draft_envelope`, including `AuthorizationRequest::draft()` metadata if delegation will be installed. Call relay `estimate_quote`; increase and rebuild the Core funding candidate and route only if required, within wallet `maxFeeAmount` (token base units) and a bounded attempt count. Retain an already approved higher fee when the estimate falls. Get the signed relay quote on the final draft **before proving or wallet signing**.
4. Prove that prepared Core transaction, export with `export_transaction()`, and rebuild using `prepare_canonical`/`Payment::prepare`. Sign the final Router/account digest, permit and authorization as applicable, then encode the final envelope. Proof/signature changes preserve semantic quote identity; all business fields remain frozen. `router_call` and final submission require actual proof/signatures. Direct modes use empty Router signatures; `approval` and `permit_digest` provide the separate ERC20 allowance/permit flow.
5. Call `simulate_canonical` with the actual sender and final authorization list before submission. It checks pinned runtime, live Router/account/authorization nonces, actual Core/route hashes and complete call execution. Final execution needs sufficient principal, effective allowance or a signed permit, and executable liquidity. Submit using the retained quote. Dynamic service gas pricing stays within its signed gas cap; a stale cap/expired quote requires refreshing, never increasing a wallet-signed token fee automatically.

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

`RouterRelayClient<T: RpcTransport>` uses the ordinary `broadcaster_estimateQuote`, `broadcaster_getQuote` and `broadcaster_submitTransaction` methods with `{data: embeddedCoreCalldata, router: {to, data, value: "0", authorizationList?}}`. Draft quotes use `payment.draft_relay_envelope` for relayed ERC20 and `native.draft_envelope` for sponsored native; final calls use the corresponding signed envelope builders. Provide registered `Trust` (chain/Core/quote signer) and fee recipient. `get_quote`/`verify_quote` require direct execution, `requestHashFormat="payment-router-intent-v1"`, semantic intent hash, unchanged Core settlement token/fee, bounded expiry and a trusted quote signature. `submit_transaction` rechecks this binding and sends `quote`, `signature` and caller-supplied provenance sidecars. Canonical Router payments use pure public funding with no foreign private Note inputs: use an empty sidecar list (`&[]`), even when the service's general capability metadata reports `provenanceRequired: true`. Ordinary private Core Source-proof rules are separate. Scheduling and aggregate execution are rejected.

Discover enabled `paymentRouters` policies through Broadcaster status/token-support and configure matching trusted pins; an empty policy list disables relay. Only the Core settlement/fee token needs Broadcaster price support, even when principal comes from native ETH or another ERC20.

Both `estimate_quote` and `get_quote` accept empty-proof, unsigned draft envelopes. They use the shared conservative Router model with dynamic chain fee pricing rather than simulating a nonexistent signed call. Business fields, deployment pins and live nonces still apply. `submit_transaction` requires the actual proof/signatures and verifies that the final business intent matches the quoted draft; Broadcaster performs complete actual-call estimation and simulation before sending.

`router_intent_hash` uses canonical Alloy ABI normalization: empty embedded proof, recomputed empty-proof `coreRequestHash`, cleared Router/account/permit signatures and cleared 7702 v/r/s. Amounts, Core funding and deliveries, fee, route, deadlines, nonces, account action and authorization chain/delegate/nonce/order stay bound. `envelope_hash` remains the raw signed-envelope utility. The caller's Core calldata must always exactly match the envelope's embedded Core data. Changing a business field requires a new quote and applicable proof/signatures. Retain the signed quote, original business intent, service status and transaction journal for idempotent recovery.

## Compile-checked host recipes

See [`examples/canonical.rs`](examples/canonical.rs): `quote_token_before_proof`
runs bounded draft fee convergence, obtains the quote, then proves, signs and
simulates. `native_quote_draft` supplies unsigned native/account/authorization
metadata; obtain its quote before using `relayed_native` for final proof data and
signing. Additional recipes cover direct ERC20 and 0x. They also show `estimate_quote` fee convergence,
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

Host signing callbacks return low-s `r || s || v` EOA signatures with on-chain
`v` equal to 27 or 28. Convert recovery parity 0/1 before attaching Router/account
signatures. EIP-7702 authorization `yParity` stays 0/1. ERC-1271 Router payer
signatures follow the contract wallet's format instead.

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

The legacy `quote` example accepts `V3_FEE` for its explicit pool tier (default `3000`). For Pancake V3 chain 97, use a deployed enabled tier such as `V3_FEE=500` with real liquidity; the CLI does not infer or create pools.

The canonical `quote_token_before_proof` host recipe accepts a fresh clock callback. It obtains the reviewed quote before proving and renews only the identical fee/route/intent after proving before wallet signing. Hosts that perform additional simulations must recheck/renew that same intent with a current clock immediately before `submit`; changing business fields still requires a fresh approval/proof. The opt-in `canonical_example_live` regression uses an explicit `INVISI_CANONICAL_LIVE_RUNNER` to verify these renewals and actual finalized envelope matching.
