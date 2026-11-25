# Canonical Router host recipes

These five native Rust binaries are compile-checked host integration recipes for the
canonical API in 1.3.3. Their `main`
functions only print guidance: running with or without arguments opens no RPC,
wallet, credential file, prover or Broadcaster. They are not configured live demos.
A host must invoke the exported functions with its own real capabilities. The Core RPC and native prover adapters perform blocking work. An asynchronous host must run the composite recipe in a blocking bridge; for example, use `tokio::task::block_in_place` on a multithread runtime while polling the Router future with a local executor. Creating or invoking the synchronous RPC adapter directly inside an ordinary async worker can panic. A current-thread Tokio runtime does not support that blocking bridge. The SDK
has no browser wallet or universal EIP-7702 transaction signer to substitute here.
The legacy crate examples remain available.

| Binary / source | Principal | Outer gas payer | Host entry point |
|---|---|---|---|
| `router-self-token` / `01-self-token.rs` | Payer ERC20 | Payer | `self_token` |
| `router-self-native` / `02-self-native.rs` | Payer native coin | Payer | `self_native` |
| `router-relayed-token` / `03-relayed-token.rs` | Payer ERC20 | Broadcaster | `relay_token` |
| `router-sponsored-native-7702` / `04-sponsored-native-7702.rs` | Delegated payer EOA native balance | Broadcaster | `relay_native` |
| `router-self-token-zeroex` / `05-self-token-zeroex.rs` | Payer ERC20 | Payer | `self_token_zeroex` |

Run/check from the repository root:

```sh
cargo check -p invisi-sdk-examples --all-targets --all-features
cargo run -p invisi-sdk-examples --bin router-self-native
cargo run -p invisi-sdk-examples --bin router-sponsored-native-7702
```

Each file exports a host function; `support.rs` contains shared orchestration,
not a scenario runner. Start by configuring `PaymentRouterClient` with independently
trusted chain/Core/Router/WETH/V3 and optional 0x deployment pins, plus an actual
`RouterProvider`. Pin Router runtime code and account implementation runtime from
trusted deployment records. Build `Invisi`, a complete public `Wallet` and real
native `Prover` using the existing configuration in [the main README](../README.md).
`payment_preparation` constructs two real encrypted Note outputs in the final Core
token. Their sum plus the explicitly reviewed Core-token fee is exact funding.
`payment_intent` reads the real payer Router nonce and binds the reviewed input cap,
refund address, fixed relayer, mode and deadline.

`RouteSelection::SameTokenOrWrap` uses the SDK's validated no-swap/wrap path.
`RouteSelection::UniswapV3` takes actual pool token/fee configuration and a trusted
QuoterV2 address, encodes the SDK's exact-output path, calls the on-chain quoter at
a pinned block and checks against the host's input cap. The cap is the host's
slippage budget; it is not increased automatically. Native input paths begin with
WETH; ERC20 paths begin with that input token. `RouteSelection::ZeroEx` uses a
host-configured `ZeroExHttpTransport` with its actual API credential. The built-in
HTTP exact-buy response is validated against Core's fee-inclusive output amount,
Holder/Settler deployment, recipient and cap. Both adapters work before proving;
no hand-built swap calldata or sample quote is substituted. Relay functions accept
these same selections. Refresh the route whenever approved fee/funding changes.

For ERC20 input, the host separately reads allowance and uses
`canonical::approval(token, router, cap)` or a real permit. The spender is Router,
not Core or an arbitrary 0x target. Handle reset-to-zero tokens explicitly. Approval
is a separate host transaction and may cost the payer gas even in relay mode;
allowance does not prove payment or establish Source recognition. Final simulation
requires executable principal and allowance/permit.

Direct functions quote the real route, prove Core, build the unsigned Router call,
simulate it as payer and invoke the host `send_as_payer` callback. Relay functions
first obtain and verify the Broadcaster's signed quote on an unsigned, unproved
draft, then generate Core proof, obtain the payer signature, verify the same quote
against the completed envelope, simulate the full actual call and submit. The
host supplies a fresh Unix clock callback for expiry checks after potentially long
proving. Fees are denominated in Core's output token, bounded by `max_fee`. A
higher service minimum fails before proving/signing; review the fee and rebuild
Core plus route, then quote again. The code does not silently approve a higher
fee. Save the frozen request and service result for recovery before any retry.
Do not treat a submit acknowledgement as canonical confirmation.

The ERC20 relay signature signs the final Router digest. Native sponsorship
signs the final account payment digest and, only when installing delegation, the
separate `AuthorizationRequest::digest()`. The host reads the actual EOA
authorization nonce for the exact outer transaction context; Router nonce and
account action nonce are independent and the example guesses none of them.
Supply `None` only for already installed compatible delegation. The SDK checks
account code/counters and final authorizations. Account/Router EVM signatures use
low-s `r || s || v` with v=27/28; EIP-7702 authorization parity stays 0/1. The host
must supply a signer and broadcaster that genuinely support the chain's 7702
execution. The outer native relay value is zero; Broadcaster supplies gas and the
payer EOA supplies principal. Delegation can persist after payment revert;
revocation and wallet account management remain explicit host actions.

Canonical public Router funding creates hidden Note outputs and therefore needs
Core proof, but consumes no previous private Note and submits no private-input
Source proof sidecars. Source recognizes the actual principal path asynchronously;
see [recognition and later private spending](../09-provenance/README.md). Nothing
here changes Core ABI, the 11-input Source proof statement, or production APIs.
