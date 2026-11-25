# Rust scenarios

Each file has its own `main` and shows the calls in execution order. There is no shared scenario runner. All SDK imports use the public `invisi_sdk` facade; applications may instead depend on individual workspace crates.

Run from the repository root:

```sh
cargo run -p invisi-sdk-examples --bin note-output
cargo run -p invisi-sdk-examples --bin transfer -- --execute
cargo run -p invisi-sdk-examples --features sqlite --bin restore-session -- --execute
```

`note-output` constructs an encrypted Note offline using public receiving material only. Set `RECIPIENT_ADDRESS`, `TOKEN_ADDRESS`, `CHAIN_ID` and `PROTOCOL_ADDRESS` to construct it for your deployment; unset values retain the offline public fixtures. Explicit malformed values fail validation. Examples 01–06 and the Broadcaster submit/cancel examples require `--execute` before opening their configuration. Source examples `pre-submit-provenance` and `recover-and-submit-provenance` run their configured normal flow directly with `--features sqlite`. Examples 01–06 export unsigned EVM transactions for the application to review, sign and submit. Broadcaster and independent Source proof flows live in `07-broadcaster`.

## Files

| Directory | Binary | Flow |
|---|---|---|
| `01-address-registry` | `register` | Pinned registry read and direct-owner unsigned registration |
| `02-note` | `note-output`, `shield` | Offline encrypted Note construction; public ERC20 funding into an encrypted Note |
| `03-note` | `transfer`, `withdraw`, `aggregate` | Located Note inputs, external wallet authorization, proving, unsigned calldata |
| `04-credit` | `create-credit`, `draw-credit`, `update-credit`, `revoke-credit` | Available spending authority, distinct payer draws, policy updates, public EVM revocation |
| `05-session` | `restore-session`, `send-session`, `create-credit-session`, `draw-credit-session`, `update-credit-session`, `revoke-credit-session` | Encrypted SQLite inventory, application decryption callbacks, managed operations and recovery |
| `06-disclosure` | `disclose-note`, `disclose-credit` | Explicit financial opening exports and independent commitment checks |
| `07-broadcaster` | `prepare-and-broadcast`, `pre-submit-provenance`, `recover-and-submit-provenance`, `scheduled-broadcaster`, `transaction-confirmation` | Client-owned Broadcaster lifecycle, host-paid Source precheck, encrypted recovery and independent confirmation |
| `08-payment-router` | `router-self-token`, `router-self-native`, `router-relayed-token`, `router-sponsored-native-7702`, `router-self-token-zeroex` | Host recipes for all four canonical funding modes and real V3/0x quotes |
| `09-provenance` | `router-output-recognition`, `recognized-note-spend` | Host recipes for real Source status and later private Core/Provenance proof submission |

## Public Wallet initialization

For local host initialization, put the original 32 raw account-key bytes in an access-restricted `OWNER_KEY_FILE`, choose new `VIEWING_KEY_FILE` and `DETECTION_KEY_FILE` paths, and run:

```sh
cargo run -p invisi-sdk-examples --bin receiving-address -- --execute
```

This offline example prints only the public owner and v1 `0i` receiving address. It creates the two capability files exclusively (mode 0600 on Unix), refusing to overwrite existing keys. Keep those files outside Git. Payments use the printed public address; receiving initialization is a separate host step.

The executable `AppDecryptor` is an example host adapter. Set `VIEWING_KEY_FILE` and `DETECTION_KEY_FILE` to the matching raw 32-byte capabilities. It performs FMD detection before local AEAD decryption, reports authentication failures separately from nonrecipients, and rejects malformed or financially inconsistent deliveries. Production applications should replace this adapter with their own capability storage and unlocking policy.


Use `Wallet::from_address(receiving_address)` with a complete public receiving address. The SDK retains only public owner and receiving material. The application owns account selection, delivery decryption and EVM signing.

Private Note/Credit authorization uses ordinary EIP-712 signing:

```rust
let estimate = prepared.estimate_gas()?; // Local receipt median or calibrated estimate for direct execution.
let request = prepared.export_wallet_authorization()?;
// Your EIP-712 wallet signs request.typed_data; request.digest is the same signing hash.
let signature = invisi_sdk_examples::sign_authorization(&request)?;
let authorized = prepared.with_wallet_signature(&signature)?;
```

`support/discovery.rs::sign_authorization` is application example code. It reads `OWNER_PRIVATE_KEY` and uses k256 to produce a standard 65-byte EVM signature. The SDK receives the signature, recovers the signer and checks the owner and frozen statement. Production applications can replace this helper with their wallet provider. Transaction signing remains a separate application step.

`support/discovery.rs::AppDecryptor` is an explicit integration placeholder. Implement its `decrypt_note` and `decrypt_credit` callbacks using your application's delivery decryption; return `None` for a different recipient and an error on decryption failure. The SDK receives plaintext bytes and independently authenticates the financial opening against the chain. The placeholder returns an integration error if a candidate needs decryption; examples using discovery require this adapter to be implemented.

## Public live configuration

Set these for transaction scenarios:

```sh
export ETH_RPC_URL='https://your-ethereum-rpc.example'
export PROTOCOL_RPC_URL='https://your-index.example/v1'
export DEPLOYMENT_JSON='/absolute/path/to/deployment.json'
export WALLET_ADDRESS='your complete 0i receiving address'
export TOKEN_ADDRESS='0x...'
export CALLER_ADDRESS='0x...'
export DEADLINE='explicit future Unix seconds'
export OWNER_PRIVATE_KEY='0x...application example signing key...'
```

`DEPLOYMENT_JSON` contains independently trusted deployment pins, not a response accepted blindly from the indexed service:

```json
{
  "chainId": "31337",
  "protocol": {
    "address": "0x1111111111111111111111111111111111111111",
    "runtimeCodeHash": "0x...32-byte-runtime-code-keccak...",
    "fromBlock": 1
  }
}
```

Replace the displayed addresses and hash with the actual deployment. Registration additionally requires a `registry` entry with the same `address`, `runtimeCodeHash`, `fromBlock` fields. Session examples also set `PROTOCOL_RPC_URL` to the indexed service's `/v1` URL. SDK preparation checks the Ethereum chain and pinned protocol runtime.

Use complete receiving addresses for `WALLET_ADDRESS`, `RECIPIENT_ADDRESS` and `SPENDER_ADDRESS` wherever encrypted delivery or change is needed. `OWNER_PRIVATE_KEY` is used only by the application example signer for private Note/Credit authorization; it must match the selected wallet owner. Do not send account keys to the SDK.

Proving scenarios require real matching tools and pinned release assets:

```sh
export BB_BINARY='/path/to/bb-6.0.0'
export NOIR_EXECUTOR='/path/to/noir-1.0.0-compatible-executor'
# Optional: use a pre-existing local circuit directory instead of lazy resources.
# export PROVER_ASSETS='/path/to/authenticated/circuits'
# export INVISI_PROVER_CACHE_DIR='/path/to/public-resource-cache'
# export INVISI_PROVER_OFFLINE=1
```

The executor implements the documented `NoirCli` interface (`--artifact-path`, `--prover-file`, `--output-dir`, `--witness-name`). Circuit files are named `<circuit>.json`; verification keys are `<circuit>.evm.vk` and, for aggregation members, `<circuit>.noir-recursive.vk`. The SDK checks their authenticated release identities and independently verifies generated proofs.

## Note inputs and amounts

Set `AMOUNT` to integer token base units, `RECIPIENT_ADDRESS` for transfers, and `WITHDRAWAL_ADDRESS` for withdrawals. `shield` uses direct funding, so `CALLER_ADDRESS` must equal the public wallet owner and the payer must already have sufficient ERC20 balance and allowance to the protocol. Approval requirements are explicit SDK data; no scenario submits an approval implicitly.

Transfer, withdrawal, aggregate, draw, update and disclosure examples discover earlier deposits and grants through `PROTOCOL_RPC_URL`. Discovery starts at the trusted deployment block by default; optional `FROM_BLOCK` and `TO_BLOCK` bound the range. Each main calls `pending.decrypt(&AppDecryptor)` and applies canonical receipt, opening, membership, spent and revocation checks before selecting inputs. No private input or Merkle-path files are required. Decryption errors leave the saved checkpoint unchanged. For deliberately partial receipt-based discovery, `RECEIPT_RANGES_JSON` may name a JSON file such as `[{"fromBlock":144723059,"toBlock":144723059},{"fromBlock":144723571,"toBlock":144723571}]`. It replaces the candidate FROM/TO range for discovery/refresh examples with ordered, disjoint windows of at most 256 blocks each (at most 64 windows). Each window still passes normal canonical receipt, membership, liveness, finality and application decryption checks; earlier accepted windows merge into the same inventory and commit independently. A failure stops before the failing window applies. This does not claim complete historical synchronization, and does not change `restore-session` scan semantics.

Transfers and withdrawals choose enough available Notes for `AMOUNT`. `aggregate` selects `AGGREGATE_MEMBERS` Notes (default two; supported values one, two or five), authorizes each member externally and proves the aggregate. Run the earlier shield/deposit scenario enough times to supply those Notes and wait for indexing.

## Credit inputs

Creation requires `SPENDER_ADDRESS`, `EXPIRES_AT`, and `AVAILABLE_CREDIT`. The latter is remaining spending authority, not held funds or a lifetime limit. `UNLIMITED=true` requires `AVAILABLE_CREDIT=0`. This example disables single/day/month limits explicitly by using the default zero policy; edit that visible policy construction to set limits. Allocation, nonce, independent shared key and both role deliveries are prepared in the file.

Draws use `AMOUNT` and automatically select spender-role grants while respecting available authority, expiry and single/day/month usage limits. Different owners remain distinct payer receipts. Updates select an unconsumed, unrevoked owner-role grant using `CREDIT_INDEX` (default zero). Both discover the grants created by the earlier creation example; no Credit-state input files are required.

`CREDIT_CHANGES_JSON` is a current update object, for example:

```json
{"increaseAvailableCredit":"100","singleLimit":"10","dailyLimit":"40","monthlyLimit":"60","expiry":"2050000000"}
```

Choose a future expiry and deadline for your chain. Increases and decreases are mutually exclusive; updates preserve gross usage. Creation, update and revocation fees in these examples are zero. A draw also uses zero fee, so its ordinary Note receives the full debit.

Revocation uses a positive uint128 `GRANT_ID`. Direct calls require the owner as `CALLER_ADDRESS`. For another caller, the example exports public EIP-712 data and signs it with the application `OWNER_PRIVATE_KEY` helper. It verifies the signature through the configured chain before exporting calldata. This is distinct from private circuit wallet authorization.

## Persistent sessions

Enable `--features sqlite`, then configure:

```sh
export PROTOCOL_RPC_URL='https://your-index.example/v1'
export WALLET_DB='/absolute/path/to/wallet.sqlite'
export WALLET_STORE_KEY_FILE='/absolute/path/to/host-storage-key.bin'
```

The key file contains exactly 32 raw bytes managed by the host. It encrypts financial inventory records and is **not** an EVM or native wallet private key. Keep the database and its key outside the repository.

Run `restore-session` to discover candidates, authenticate canonical receipts and request native viewing. If there are viewing requests, paste the native response array directly; each member carries `version`, `id`, `ownerAddress`, `method`, and exactly one `result` or `error: {code}`. Only `WALLET_NOT_RECIPIENT` skips a candidate; cancellation, locked accounts and other errors abort without advancing state. The SDK validates accepted financial openings and commitments before updating inventory.

Run `send-session` with `AMOUNT`, `RECIPIENT_ADDRESS` and `DEADLINE` to refresh earlier deposits automatically and select unreserved Notes and prepare a managed transfer. Keep the printed operation ID. Set `OPERATION_ID` on a later run to resume that exact operation with saved proof verification. Once your host has signed and submitted the exported transaction, set `HOST_TRANSACTION_HASH` on a resumed run to track and reconcile the explicit hash. The example never interprets exporting calldata as chain confirmation. With `HOST_TRANSACTION_HASH`, recovery tracks and reconciles the original hash before attempting a new calldata export; already consumed Notes or created grant IDs must never be revalidated as a fresh send. Recovery of a proved operation requires its public wallet and decryption capabilities, rather than a new owner signature.

The managed Credit binaries use the same encrypted store and explicit application decryption callbacks. They retain operation IDs, reserve inputs, export unsigned host transactions, and support `OPERATION_ID` + `HOST_TRANSACTION_HASH` recovery and canonical reconciliation just like `send-session`. Use a separate database per owner/spender wallet, with the same wallet and storage key when resuming. The examples reject saved operations of a different kind. Resume with the binary that created the operation; do not set `OPERATION_ID` for a new operation.

```sh
# Owner grants authority; spender draws it into a recipient Note.
cargo run -p invisi-sdk-examples --features sqlite --bin create-credit-session -- --execute
cargo run -p invisi-sdk-examples --features sqlite --bin draw-credit-session -- --execute
cargo run -p invisi-sdk-examples --features sqlite --bin update-credit-session -- --execute
cargo run -p invisi-sdk-examples --features sqlite --bin revoke-credit-session -- --execute
```

| Managed action | Additional configuration | Inventory selection |
|---|---|---|
| Create | `SPENDER_ADDRESS`, `EXPIRES_AT`, `AVAILABLE_CREDIT`, optional `UNLIMITED` | Fresh allocated grant; no input grant |
| Draw | `DEBIT_PER_GRANT`, `RECIPIENT_ADDRESS` | Two current unreserved spender grants from distinct owners, each covering the debit within expiry and policy limits |
| Update | `INCREASE_AVAILABLE_CREDIT`, optional `CREDIT_INDEX` (default zero) | Current unreserved owner grant; visible typed changes increase remaining authority |
| Revoke | Optional `CREDIT_INDEX` (default zero) | Current unreserved owner grant; derives public grant ID from inventory |

The managed draw is a merchant batching example: run creation from two different owner wallets granting the same spender, then switch to that spender’s wallet/database. `DEBIT_PER_GRANT` is the amount charged to **each** of two payers; one recipient Note receives `2 × DEBIT_PER_GRANT` with zero fee. Selection checks current usage limits and expiry through `DEADLINE`; SDK preparation rechecks the selected grants. The stateless draw continues to interpret `AMOUNT` as its total.

All actions also use `TOKEN_ADDRESS`, `CALLER_ADDRESS` and `DEADLINE`. Create, draw and update need the prover configuration; revoke needs no prover and requests an owner EVM signature only for a relay caller. The update main constructs `CreditUpdateChanges` directly: edit that visible struct for policy/expiry changes. No plaintext grant, Merkle-path or update-input file is needed for these managed scenarios. The stateless `04-credit` flows remain available independently.

## Disclosure

`disclose-note` automatically discovers earlier unspent Notes and selects `NOTE_INDEX` (default zero); `disclose-credit` discovers owner-role grants and selects `CREDIT_INDEX` (default zero). Both require the normal public discovery configuration and `--execute` because their output intentionally reveals a financial opening. Credit opening export contains the shared-key hash, not the shared key. Payload-key disclosure is a separate explicit API and is not substituted for these opening examples.

## Checks

```sh
cargo check -p invisi-sdk-examples --all-targets --all-features
cargo run -p invisi-sdk-examples --bin note-output
```

Run the other binaries without `--execute` to inspect their guard behavior without configuring services.

## Broadcaster and independent Source proofs

See `07-broadcaster` for fee-frozen quotation and submission. Example 01 discovers token-supporting Broadcasters through the authenticated registry rather than manually supplied operator identities. Set `PROVE_PROVENANCE=1` to explicitly prove and submit Source evidence before broadcasting even when the signed Broadcaster quote does not require it, then wait for recognition after native finality. Example 02 is a normal managed payment: synchronize/decrypt inventory, prepare, authorize, prove, submit Source precheck, then call `session.send_transaction` with a host signer and an explicit `GAS_LIMIT`. It prints the saved operation ID, Source digest/tracking, and sent hash, waits for independent native finality, reconciles inventory, and waits for Source recognition. Example 03 reopens the encrypted session by `OPERATION_ID`, records `HOST_TRANSACTION_HASH` only when a crash prevented the original hash from being journaled, reconciles canonical state, generates Source evidence from retained openings, submits it and waits for recognition. Already completed payments use their retained journal directly. Both examples require `--features sqlite` and run directly without scenario flags. The native `AppDecryptor` reads the explicit host capability files described above.

These flows use `DEPLOYMENT_JSON`, `ETH_RPC_URL`, `PROTOCOL_RPC_URL`, `WALLET_ADDRESS`, `WALLET_DB`, `WALLET_STORE_KEY_FILE`, `BB_BINARY`, `NOIR_EXECUTOR` (optional `PROVER_ASSETS` selects existing local circuits). Example 02 also uses `TOKEN_ADDRESS`, `RECIPIENT_ADDRESS`, `AMOUNT`, `DEADLINE`, `CALLER_ADDRESS`, positive `GAS_LIMIT`, and `OWNER_PRIVATE_KEY` for the example application signer. The same host signer signs EIP-712 authorizations and standard EIP-155 Ethereum transactions; the SDK never receives the EVM private key. Production hosts can inject a hardware wallet or external signer. SQLite stores the encrypted operation journal; the examples do not export extra JSON records. Optional `CONFIRMATION_TIMEOUT_SECONDS` defaults to 180. The host examples poll native confirmation and Source tracking every two seconds to leave room in shared service read budgets; transport failures retain the saved operation/tracking ID for explicit recovery.

Example 01 uses `BROADCASTER_ENDPOINT`, `BROADCASTER_QUOTE_SIGNER`, `BROADCASTER_FEE_RECIPIENT` and positive `MAX_FEE_AMOUNT`. Registering the native prover enables the official Source configuration automatically. Private Source overrides use `SOURCE_CHAIN_ID`, `SOURCE_PROTOCOL_ADDRESS`, `SOURCE_GENERATION`, `SOURCE_PROVIDER_ID`, `SOURCE_SIGNING_KEY_ID`, `SOURCE_SIGNING_PUBLIC_KEY` and optional `SOURCE_ENDPOINT`; local override proving additionally needs `SOURCE_ASSET_ROOT`. Ordinary examples 01–06 have no optional Broadcaster mode or Source availability requirement.

The authenticated signed quote determines whether Source evidence is required; no legacy provenance-mode hint is needed. When a private Note payment requires evidence, freezing submission lazily resolves the configured trusted Source capability, validates its scope/manifest, and then generates or reuses verified evidence. Missing or invalid capabilities still reject submission. Protocol version remains 1.

The SQLite `restore-session` example uses `RecordWalletStore` for independently encrypted private rows and `SQLiteRecords::open_public` for a deployment-wide canonical cache in a separate table of the same database. `session.scan` recovers the current head first, then historical gaps; reuse the public store for other accounts while providing separate private account storage keys. `AppDecryptor` is a host integration stub: implement complete-context native detection and explicit nonrecipient/authentication-ambiguity/error outcomes before using `--execute`. Shared history never requires exporting detection or viewing keys.

Credit revocation uses `OWNER_ADDRESS` (an EVM `0x` address) independently of `WALLET_ADDRESS`.

### Public Wallet addresses

`Wallet::from_address` accepts only complete `0i` receiving addresses. Use `Wallet::from_keys(owner_address, receiving_keys)` when the public materials are separate. `address()` encodes a complete `0i` address without RPC resolution. EVM owners are independent addresses; owner-only operations do not need a Wallet.

```rust,ignore
let request = sdk::prepare_wallet_request(owner_address, "public", "wallet.public", json!({}))?;
let response = native_host.execute(&request)?;
let wallet = Wallet::from_response(&request, &response)?;
let receiving_address = wallet.address()?;
assert_eq!(Wallet::from_address(&receiving_address)?, wallet);
let revocation = invisi.prepare_revoke_credit_explicit(owner_address, token, grant_id, deadline, Fee::default())?;
```

`source-tracking` (`07-broadcaster/source-tracking.rs`) accepts a saved public tracking ID and the normal deployment/trust configuration to resume an authenticated lookup after a transient polling failure. It never proves or submits a payment.

`transaction-confirmation` (`07-broadcaster/confirmation.rs`) reads `CHAIN_RPC_URL` and a transaction hash argument to report independently authenticated native inclusion/finality. It performs no submission, resend, or wallet mutation.

The Credit create/draw examples use request-based preparation and complete recipient
addresses; EVM recipients require a receiving-key resolver. Updates use optional
payloads (`None` preserves, `Some(Vec::new())` clears). Broadcaster example 01 registers
the main native prover before quoting, so the official Provenance service and bundled
local Source resources work without `SOURCE_*` trust/asset configuration. Explicit
`SOURCE_PROVIDER_ID` still selects private trust overrides. Fee limits remain app configured.

Scheduling: `scheduled-broadcaster` (with `--features sqlite`) quotes, submits,
resumes the encrypted operation by its local ID, checks the returned Broadcaster ID,
and cancels a Note transfer, then independently reconciles its inputs.
It uses the existing environment configuration plus `PUBLISH_AFTER`, optional
`EXECUTE_BEFORE`, `WALLET_DB`, and `WALLET_STORE_KEY_FILE`; its cancellation
capability is persisted in the encrypted SQLite journal before submission.
The complete `prepare-and-broadcast` example
also accepts `PUBLISH_AFTER` and optional `EXECUTE_BEFORE` (defaults to 300
seconds after publication). Set the signed operation deadline beyond execution
plus the broadcaster's advertised slack. For restart-safe cancellation, use a
managed session, call `client.quote(&mut operation, chain.clone(), &options)`,
`client.submit(&mut operation, chain.as_ref())`, then `client.cancel(&mut operation)`.
Cancellation persists the acknowledgement and independently checks canonical consumption
before returning and releasing reservations. Retry cancellation after canonical outages;
the saved acknowledgement permits recovery even while the relay is offline.
Keep operation journals encrypted.

## Contributing

See the [contribution guidelines](../README.md#contributing) for issues, pull requests, validation, and handling sensitive material.

### Canonical PaymentRouter integration

The canonical API in 1.3.3 has a [compile-checked canonical example](../crates/invisi-sdk-payment-router/examples/canonical.rs)
for self-submitted ERC20, relayed ERC20, and sponsored native with host-provided
signing callbacks. Run `cargo check -p invisi-sdk-payment-router --examples` and
`cargo run -p invisi-sdk-payment-router --example canonical` to check/build it;
its main only prints guidance and opens no RPC connection. The functions accept
real unproved draft or final proved Core calls and explicit deployment, payer, route and wallet
capabilities; they contain no fake proof or automatic broadcast. The existing
`--example quote` CLI targets the legacy native-only API.

The [Router guide](../crates/invisi-sdk-payment-router/README.md) covers all four
modes, arbitrary ERC20/native V3 and built-in 0x quotes, and same-token/wrap paths.
For Router relay, `quote_token_before_proof` demonstrates bounded fee convergence
on an unsigned, unproved draft, obtains the signed quote, then proves, signs and
simulates. `native_quote_draft` supplies account fields and unsigned 7702 metadata;
obtain its quote before using `relayed_native` with final proved Core data and
wallet signatures. `RouterRelayClient::{estimate_quote, get_quote}` accept these
drafts. The host limits attempts and token-denominated wallet `maxFeeAmount`,
retaining a previously approved higher fee if the estimated minimum falls.

Local previews and service quotes use conservative `payment-router-gas-v1`
Router allowances over the Core baseline with `source="model"`, not
receipt-calibrated swap figures. Opaque 0x needs a trusted service-policy route gas
budget or estimation is unavailable. The service prices the model using dynamic
chain fees within its configured operational maximum. Fee pricing uses the Core
output token and exact funding includes the fee.

`payment-router-intent-v1` binds business fields while proof and wallet signature
completion preserve the quote identity. Changed Core fees, routes, deadlines,
nonces or authorization metadata require a fresh quote and applicable
proof/signatures. Final submission requires actual proof/signatures, executable
principal and approval/permit, and full actual-call estimation/simulation with
pinned runtime and live-counter checks. Ordinary `07-broadcaster` Core quote
capabilities are unchanged. Router relay is direct only, without
scheduling/aggregation. Native relay uses EIP-7702 and zero outer value; the payer's
balance supplies principal. Host wallets own signing and persistent
delegation/revocation, and must track independent Router, account action, and EOA
transaction/authorization nonces.

### Router and recognition scenario binaries

The native [Router recipes](08-payment-router/README.md) cover self ERC20, self
native, relayed ERC20 and EIP-7702 native sponsorship, including actual V3 and 0x
route selection. The [Source recipes](09-provenance/README.md) query real Router
output recognition and show later private Note authorization, Core/Provenance
proving and independent public Source submission, with the cross-mode scenario
matrix. These binaries are host-injected, compile-checked recipes: their ordinary
entry points print guidance only, and their exported functions require real host
wallet, deployment, proving and submission capabilities. No fake proof, quote or
7702 authorization is used. Existing `07-broadcaster` and crate examples remain
available.

A read-only live regression for an exported, confirmed but unreconciled Session journal is available with `cargo test -p invisi-sdk-examples --features sqlite --test host_recovery confirmed_host_recovery -- --ignored`. Set `INVISI_EXAMPLE_RECOVERY_BIN` to the corresponding official binary and `INVISI_EXAMPLE_RECOVERY_ENV` to an access-restricted JSON object containing its normal environment plus `OPERATION_ID` and the original `HOST_TRANSACTION_HASH`. The test requires canonical reconciliation and rejects output containing newly exported calldata; it never submits another transaction.

`owner_revocation_main_exports_without_a_private_circuit_ready_transition` is a separate opt-in actual-main regression. Set `INVISI_REVOKE_EXAMPLE_BIN` and `INVISI_REVOKE_EXAMPLE_ENV` for an unsubmitted managed revocation journal with `OPERATION_ID` and the owner as `CALLER_ADDRESS`. It removes owner signing keys and disables private proving tools, then requires real public revocation calldata to export through the ordinary live grant/canonical checks. It never broadcasts the export.
