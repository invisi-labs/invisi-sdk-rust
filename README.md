# Invisi Rust SDK

A Rust SDK for ordinary private Notes and deferred Credit grants, aligned with the
shared TypeScript and Go protocol behavior. Source, comments and documentation use English.
The SDK does not select accounts, read Keychain/Keystore, hold a mnemonic, or approve requests.

## Core contract bindings

Contract bindings follow the current `invisi-core` compiler artifacts: `InvisiCore` / `IInvisiCore` and `InvisiCoreFactory` / `IInvisiCoreFactory`. Update direct binding imports and generated tuple type names accordingly. Generic Protocol objects, package names, `protocolAddress` / `protocol_address`, deployment catalog records, EIP-712 domains and wire encodings retain their existing meanings. Regenerate compiler ABIs with `python3 scripts/sync-core-abis.py ../invisi-core`.

## Release validation

The public crates share version **1.3.2**. See [local release validation](RELEASE.md)
for packaging checks and the required publication order.

Version 1.3.2 exposes six common modules, the independent IPP crate, the separate native FFI adapter and the optional Payment Router crate.
Replace `invisi-sdk-core` dependencies/imports with `invisi-sdk-primitives`.
Use `invisi_sdk::sdk` for stateless operations and `invisi_sdk_session::session`
for managed wallets; enable `sqlite` on `invisi-sdk-session` when needed.
The former runtime crate is integrated into `invisi-sdk`. Public Source contracts
are in `invisi_sdk_protocol::provenance`; local Source witnesses and proving
capabilities are in `invisi_sdk_prover::provenance`. Encrypted Source recovery
and its coordinator are in `invisi_sdk_session::provenance_recovery`.

## Preparation and portable output APIs

`Invisi::prepare_create_credit`, `prepare_update_credit`, `prepare_draw_credit`, and
`prepare_revoke_credit` accept `CreateCreditRequest`, `UpdateCreditRequest`,
`DrawCreditRequest`, and `RevokeCreditRequest`. Create allocates the revocation
reference and generates the nonce/shared key. Spender and draw recipients accept
complete receiving addresses; EVM addresses require an injected receiving-key
resolver. The granular state-based variants are named `*_explicit`.
Absent update/member draw payloads preserve the previous payload; `Some(vec![])` clears it.
All ordinary preparation methods return `PreparationResult<T>` with a structured
`InvisiError` code and details. Recipient errors distinguish invalid addresses,
`EVM_ADDRESS_NOT_REGISTERED`, lookup failures, and missing capabilities.

`PreparedTransaction::get_outputs()` and `PreparedCredit::get_outputs()`
return detached `TransactionOutput` snapshots, including token, typed recipient and generated change. Export
an opening with `export_payment_note()`, decode it with `PaymentNote::decode`, and
verify inclusion or current spendability with `verify` / `verify_spendable` against
an independent chain and Protocol RPC client. IPN encoding is the shared canonical
149-byte, payload-free format. Verification defaults should use native finalized
heads; explicit latest/safe choices remain available.

Broadcaster fee preparation defaults to four attempts (allowed range 1..16).
`BroadcasterFeeSource` selects public funding or private inputs. Public fees add to
the explicit payer's funding amount; `funding_permit` receives the final gross
amount once, before the final signed quote. Existing permits cannot silently
cover increased funding. Source replay defaults are ten root pages and 100,000 leaves.

Register a configured local backend with `Invisi::with_prover(Arc<dyn Prover>)`
before preparing a Provenance broadcaster transaction. Native backends expose the
authenticated Source resources on demand and inherit the main witness executor and
BB configuration. Official scoped trust bootstraps lazily when Source service
access is needed, without network access during local preparation. Explicit
`with_provenance` private-service trust takes precedence.

## Workspace

| Crate | Responsibility |
| --- | --- |
| `invisi-sdk-primitives` | Wallet cryptography, Note/Credit models and transitions, addresses, FMD, delivery, disclosure, payment requests. No HTTP, prover or managed store. |
| `invisi-sdk-protocol` | Current contract ABIs, shared chain/output types, strict codecs, public circuit statements, Source digests, capacity catalogs, gas references and canonical receipt decoding. |
| `invisi-sdk-prover` | Authenticated circuit identities, explicit local witnesses, native BB proving and recursive aggregation. |
| `invisi-sdk-rpc` | Indexed Protocol RPC, independent Ethereum reads and registered broadcaster quote/submit/status transport. |
| `invisi-sdk` | Public Wallet, stateless preparation, external authorization, funding, proving and calldata. |
| `invisi-sdk-session` | Inventory, staged synchronization, reservations, history, journal recovery and encrypted persistence; optional SQLite. |
| `invisi-sdk-ffi` | Narrow native C ABI backed by primitives only. It does not pull in HTTP, proving or Session. |
| `invisi-sdk-examples` | Flat, independent scenario programs, corresponding to the Go/TS examples. |

Dependencies flow from primitives to protocol, then prover and RPC, then the stateless SDK, then Session. Session directly uses protocol DTOs and accesses proving through SDK.
Protocol DTOs live below RPC so receipt decoding does not create a dependency cycle.
Native hosts that only need wallet cryptography depend on primitives or FFI directly.

## Public Wallet and application capabilities

`Wallet` stores only a public `owner_address` and required `receiving_keys`. `address()` encodes a complete `0i` receiving address on each call. `from_address()` accepts only complete `0i` addresses; `from_keys()` validates a nonzero owner and both receiving keys. Constructors perform no RPC or registry lookup. Use independent EVM owner addresses for owner-only operations: `prepare_wallet_request`, `accept_wallet_response`, Credit revocation, and original-owner sweeps. Standalone `ReceivingAddress` still supports short `0x` encoding. Applications provide delivery decryption and ordinary EIP-712 signing; the SDK never needs an account private key or wallet transport.

```rust,ignore
let request = prepared.export_wallet_authorization()?;
let signature = app_sign_typed_data(&request.typed_data)?;
let authorized = prepared.with_wallet_signature(&signature)?;
let ready = authorized.prove(&prover, false)?;
let call = ready.calldata(&chain, caller)?;
// The application separately signs and submits the final EVM transaction.
```

`EvmSigningRequest` includes standard typed data and its digest. Signature attachment recovers and verifies the owner against the final frozen Note/Credit statement, then derives the transient proving authorization. Funding and public Credit revocation use their own EVM authorization contracts.

`delivery::DeliveryDecryptor` is the application callback boundary. Its Note and Credit methods receive encrypted delivery bytes and public scope; they return plaintext bytes or `None` for an unrelated recipient. `Wallet::decrypt_note` / `decrypt_credit` authenticate returned openings, roles and receiving keys. Errors abort without committing inventory changes. No JSON wallet request/response bridge is needed by normal application flows.

## Note and Credit

`CreateCreditRequest.initial_payment` optionally combines creation with a first encrypted
payment to the spender. `InitialCreditPayment.amount` is the gross owner debit including
the actual fee; all Credit limits and available authority count that gross amount. The
owner signs once, the remaining grant and first Note share one proof, and both are
available through the normal managed Session and portable output APIs. IPP's
`credit.initialPayment.amount` is the merchant net amount; its adapter adds the local fee
and always sets `InitialCreditPayment.net_amount`. This optional pin requires initial
`amount == net_amount + fee.amount`, survives saved journals, and makes quotation
rebuild gross debit, grant usage and deliveries while keeping the merchant Note fixed.
Without a net pin, `amount` stays gross and the fee reduces the Note.
The creation example accepts `INITIAL_PAYMENT_GROSS`. Combined circuit resources use the same independent Core catalog and the existing lazy cache, explicit directory and offline settings; the historical separate pin is used only in explicit legacy mode. No circuit assets are bundled. `legacy_create_credit_call` retains explicit
encoding for pure creation against legacy deployments.

Notes use envelope `0x01`. Credit uses `0x82`, finite `availableCredit`, a canonical
`unlimited` flag, three limits and gross usage counters. Create/update/revoke fees are
pulled from the owner allowance; draw collects gross amounts, deducts its fee and issues
one net ordinary Note. Updates use explicit balance deltas. Revocation is a public grant
reference operation and does not need a ZK proof. There is no prepaid Credit compatibility
model in the current business API.

Ordinary spending requires private authorization. An explicit permissionless owner sweep
can withdraw disclosed Notes only to their original owner, without outputs, funding or a
fee, as required by the current circuit. Preparation and final export recheck membership,
consumption, revocation, balances, allowance and public funding/revocation authorization.

## Synchronization and storage

Session refresh returns an opaque staged handle. Call `pending.decrypt(&app_decryptor)` to authenticate candidates and atomically commit the checked inventory through a revision CAS. Reconciliation uses the same callback. Decryption and canonical-chain failures leave the checkpoint unchanged; `None` skips only an unrelated recipient. Inventory and Credit role state remain separate.

`EncryptedWalletStore` binds AES-GCM records to scope and revision. Hosts can supply an
atomic encrypted-record backend; the `sqlite` feature supplies persistent SQLite with
cross-connection transactional CAS. Keys and private wallet authorization witnesses are
not journaled. Submitted call/hash and public signatures can be retained for reconciliation.

## Proving and native integration

Noir 1.0.0 / BB 6.0.0 release metadata and VK hashes are bundled with the prover crate.
`NativeProver::new(bb_binary, witness_executor)` loads public circuit artifacts and verification
keys on the first prove/verify call. `ResourceProvider::default()` also works in existing
`NativeProver` struct literals. The default source is `https://assets.invisipay.fi/prover/sets/<index-sha256>/`.
The SDK pins the SHA-256 of the Core resource index,
Noir/BB versions, original circuit statements, and independent Source manifest. Each
cached read verifies the exact indexed size and SHA-256; downloads publish atomically.
Only public resource GET requests leave the host. Witness execution and proofs remain local.

Set `INVISI_PROVER_CACHE_DIR` to choose the disk cache, `INVISI_PROVER_SOURCE` for an HTTPS
mirror or a directory of Core release objects, and `INVISI_PROVER_OFFLINE=1` to require
cached resources. `INVISI_PROVER_ASSETS` selects the Core object directory with its index and hashed objects. Set `INVISI_PROVENANCE_ASSETS` for a separate Provenance object directory and `INVISI_PROVENANCE_SOURCE` for its source. The cache is shared and uses `<pin>.index.json`; a producer directory can also contain its single `index.json`.
For a mirror serving separate release sets, use an explicit `{pin}` placeholder in
`INVISI_PROVER_SOURCE` (for example `https://mirror.example/prover/sets/{pin}`).
A flat mirror may instead serve both pin-named indices and content-addressed objects. `ResourceOptions` configures these explicitly.
`DirectoryAssets` retains its existing explicit local circuit-directory behavior.
Recursive aggregation uses the same configured provider to load only the needed
binary verification keys. It authenticates SHA-256, 115 canonical BN254 words and
the trusted Poseidon commitment before witness assembly. Dedicated aggregation
loads one key; mixed aggregation loads C1–C5. Custom backends may implement the
optional `Prover::load_verification_key` capability; unsupported loaders fail
locally. Constructors perform no resource I/O. See the [prover documentation](crates/invisi-sdk-prover/README.md#recursive-verification-keys).
`NativeProver` accepts a host `WitnessExecutor`, including the external Noir CLI adapter;
a mobile host can use its embedded native ACVM. Blocking RPC/proving work belongs
off the UI thread.

`crates/invisi-sdk-ffi/include/invisi_wallet.h` provides length-delimited borrowed inputs
and owned JSON output. Release every output with `invisi_wallet_free`. Swift can call the
C ABI; Android can forward it from JNI. React Native uses `@invisi-labs/native-wallet`
for JSON transport. Platform binaries and the consuming App are separate integrations.
The C ABI exports only `invisi_wallet_execute_batch` and `invisi_wallet_free`.
Its methods are `wallet.public`, `wallet.detect`, `wallet.decryptNote`,
`wallet.decryptCredit` and `wallet.authorize`, using the same dispatcher and wire
messages as the SDK. Note commitments and nullifiers bind both chain ID and
Protocol address. Native hosts use the current Protocol/SDK preparation APIs
for Shield, transact and Credit; ERC20 approval is explicit SDK data.

## Examples and verification

The SDK uses the Alloy 1 type family aligned with the mobile App. Exact core and consensus versions are pinned in the crate manifests. Consumers must rebuild generated ABI bindings and public Rust DTOs against these dependencies; protocol calldata and wallet wire formats are unchanged. The aligned consensus dependency requires Rust 1.91 or newer.

```sh
cargo run -p invisi-sdk-examples --bin note-output
cargo check -p invisi-sdk-examples --all-targets --all-features
python3 scripts/check-english.py
cargo fmt --all --check
cargo test --workspace --all-features
cargo test --workspace --all-features --release
cargo build -p invisi-sdk-ffi --release
```

Live examples require `--execute` before opening network/storage and print unsigned calls
for the host signer. See [examples](examples/README.md) and the
[shared capability matrix](docs/sdk-parity.md) for scope, environment and reproduction.
No release, push or App migration is performed by these commands.

## Optional Provenance tracking

The independent Provenance module keeps Source recognition separate from protocol settlement. Ready private Note payments expose `prove_provenance`, `precheck_provenance`, and independent `submit_provenance` with an optional transaction hash. Rebuilding Source evidence preserves the existing payment. Broadcaster estimates fees separately from its final signed quote, advertises Source requirements, and assigns opaque server submission IDs. The mandatory signed `quote.execution` selects `direct` or `aggregate`; `prepared.prove(&prover, None)` (also on managed operations) follows that quote. Passing `false`/`Some(false)` or `true`/`Some(true)` explicitly must agree with it. Aggregate relay execution accepts only unfunded private C1–C10 Note transfers, submits a canonical single-operation envelope plus public `memberProof`, and cannot be exported as a direct EVM transaction. Credit and Shield use direct execution. Managed retries durably retain the exact request, including recursive proof bytes and Source sidecars, before sending. After a server submission ID is known, retries only query that ID, including when the server reports it missing; they never resubmit. `queued`, `proving`, `rejected`, and `expired` relay states retain reservations until canonical reconciliation or explicit safe expiry resolves the operation. Canonical aggregate confirmation requires the exact business member exactly once. See the parallel [Broadcaster examples](examples/07-broadcaster) and ordinary [Note](examples/03-note/transfer.rs) and [Credit](examples/04-credit/create.rs) flows. Apps supply ordinary signing and delivery decryption.

Native Note and all Credit prepared transactions, plus managed operations, expose `estimate_gas()` before authorization, proving or token approval. This immutable local preview covers every legal direct Shield (1–10 outputs), canonical Transact (C1–190), and Credit create/update/revoke/draw (1–80 inputs) shape. It returns `source: "benchmark"`, positive `gasUnits`, and `statistic: "median"` for exact receipt rows or `"estimate"` for the calibrated model. Aggregate and recursive execution remain `shape-not-covered`. It performs no provider, allowance, balance or calldata-export calls and changes no reservations or journal state. Payload bytes, source trees, permits and funding signatures have explicit allowances. Unknown/ERC-1271 revocation uses a conservative 60,000-gas authorization allowance; prepared revocations have no caller context and use unknown authorization. `protocolCommit` and `sourceSha256` identify the pinned measurements. Apps and Broadcasters own final simulation, gas limits and current fee prices.

```rust,ignore
let prepared = invisi.prepare_transfer(&wallet, request)?;
let estimate = prepared.estimate_gas()?;
if let Some(units) = estimate.gas_units() {
    println!("benchmark gas units: {units}");
}
// The application can now request authorization and prove the transaction.
```

`ProtocolRpcClient::discover_broadcasters(token)` pages enabled registrations at one canonical registry anchor and independently probes each operator's token support. Unsupported, unreachable or incorrectly identified services are skipped. Apps with their own network policy may use `discover_broadcasters_with_transport`; the Protocol RPC wire query itself has no token filter.

### Native chain finality

`rpc::read_chain_finality(&chain)` independently samples native `finalized`, `safe`, and `latest` block tags, checks every returned block against canonical numeric reads (number, hash, parent hash, timestamp), and retries an incoherent sample once. Every head has an explicit `available`, `unsupported`, `unavailable`, or `inconsistent` status. There is no depth or elapsed-time fallback. Custom `CanonicalChain` adapters keep working and default to unsupported native capabilities; implement `block_by_tag` and `confirmation_receipt` to opt in. `EthereumChain` implements both against its configured independent Chain RPC. Protocol service finality claims are optional for compatibility and authenticated against that primary; a service ahead of the primary becomes unavailable without blocking latest discovery.

`rpc::read_transaction_confirmation(&chain, hash)` verifies the receipt and canonical inclusion again after native head reads. Its `pending` / `included` / `safe` / `finalized` result is independent of execution success and broadcaster status claims. `PreparedTransaction::confirmation(chain, hash)` and managed `Operation::confirmation()` expose the same observation; they never release reservations, advance journal generations, or mutate preparation state. Spendability checks continue using latest state. An operation without a stored transaction hash reports pending. Broadcaster confirmation fields are strictly parsed but never authorize local finality. Rust has separate `PreparedCredit` and `PreparedAggregate` types; use the generic `rpc::read_transaction_confirmation` helper for their stateless transactions, or managed `Operation::confirmation()` when journaled.

This Rust release does not expose a high-level IPN/Disclosure verification policy API; consumers requiring finalized evidence must explicitly require an available native finalized head covering their canonically authenticated evidence block. The native helpers do not turn parsing a note/disclosure into verification.

Run `CHAIN_RPC_URL=https://your-independent-node cargo run -p invisi-sdk-examples --bin transaction-confirmation -- 0x<transaction-hash>` for an observational query. The example neither submits nor retries a transaction.

Preparation and quotation preserve the existing API. Independent Note/Credit checks use at most four workers per group and preserve statement order. Each prepared handle can reuse block-bound public reads during fee convergence for up to 30 seconds (1,024 entries); snapshots, canonical checks, funding nonces and signature verification remain live. Transaction export retains its existing live submission checks, now with bounded parallel input and payer validation. Portable recovery snapshots do not serialize read caches.

### Broadcaster client

For ordinary Core Note/Credit and managed Session relay flows, call
`client.quote(&mut prepared, chain.clone(), &options)` before authorization or proving.
Router relay uses the separate unsigned-draft envelope flow described below, also quoting
before proof and wallet signatures. Ordinary Core quotation capabilities are unchanged.
The same client accepts ordinary Note/Credit preparations and managed Session operations.
Managed quotation commits its final plan, quote and scheduling capability in the encrypted store;
failed quotation leaves the target unchanged. The independent RPC client remains available through
`client.rpc()` for public calldata requests. Promote an RPC discovery result with
`let client = invisi_sdk::broadcaster::BroadcasterClient::from_rpc(raw_client);`
before calling the same high-level `quote`. SDK and Session preparation objects do not expose
an alternate quotation entry point.

After proving, call `client.submit(&mut target, chain.as_ref())`; cancel scheduled custody with
`client.cancel(&mut target)`. Both accept ordinary Note/Credit preparations and Session operations.
Managed cancellation saves the remote acknowledgement, independently reconciles canonical input
consumption, and releases reservations before returning success. Retry after a canonical outage;
the durable acknowledgement allows recovery without another relay request. Ordinary prepared
objects have no wallet inventory to release. Raw transport calls are named `submit_transaction`
and `cancel_transaction` and remain wallet-independent.

`WalletSession::send_transaction(&mut target, &host_sender, options)` accepts a raw `TransactionCall`
or its own managed `Operation`. The injected `TransactionSender` supplies the caller, chain and
standard EVM send; options require explicit positive gas. The SDK validates caller/chain and managed
submission, exports the exact call durably, sends once and records the hash. EVM keys remain in the
host. Recover a `TransactionSendError.transaction_hash` by tracking and reconciling that original hash;
uncertain sends and post-send storage failures retain reservations and never automatically resend.

Collection workflows can use `rpc::TrustedProvider` for explicitly trusted
Protocol RPC chain reads (no Ethereum endpoint), then authenticate known Note
openings with `invisi_sdk_session::session::WalletSession::import_notes` and freeze
an exact selection with `prepare_collection`. `sdk::BroadcasterFeeSource::Payout`
pays the relay from a pure full-sum withdrawal, subject to a mandatory fee cap,
positive net payout and owner authorization. See the RPC and session crate READMEs
for the trust model and public APIs.

## Contributing

Open a focused GitHub issue or pull request describing the problem, scope, and validation. Run `cargo fmt --all --check`, `cargo test --workspace --all-features`, and `python3 scripts/check-release.py` for your change. Never include private keys, credentials, or private witnesses in issues, pull requests, logs, or fixtures.

## Independent proving resource sets

Core (Transact/Credit, including initial-payment) and Provenance use separate immutable catalogs. The default Core index is `36f58bac1a0f70c6f8422b47f7cc35a30416a20f8a0f30038d23db0832e2bc93`; the Provenance index is `8d5a3e60e3e5cbe315150511207d7aff67f4e2924148d396b67d82017ecd1f1c`. Public objects retain their existing bytes and logical names. Downloads use `/prover/sets/<index-hash>/`, and verified objects share the same content-addressed cache.

Core operations do not require the Provenance catalog; Provenance operations do not load Core. Missing or corrupt split resources fail without a legacy downgrade. Historical catalogs remain available through explicit legacy configuration.

**Release prerequisite:** these split catalogs have been built and verified locally but are not claimed published. Publish each producer's authenticated CI artifact before releasing SDKs with these new defaults. Until then, provision matching local catalogs or select legacy mode explicitly. No production pins are fetched from an untrusted URL or inferred from a failed download.

`ResourceOptions` accepts `legacy_combined: true` for historical compatibility. Core uses `source`, `directory` and `index_sha256`; Provenance uses `provenance_source`, `provenance_directory` and `provenance_index_sha256`. The source may contain an explicit `{pin}` placeholder for a shared mirror. Prefer struct literals with `..ResourceOptions::default()`. Cache and offline settings remain shared.

### Optional Payment Router

**Unreleased (planned 1.3.3; versions remain 1.3.2):**
`invisi-sdk-payment-router` supports the canonical unversioned `PaymentRouter` and
`PaymentRouterAccount`: self-submitted native/ERC20, signed ERC20 relay, and EIP-7702
sponsored native. Native or arbitrary ERC20 inputs support V3 and built-in 0x
exact-buy quoting (`quote_canonical_zeroex`); same-token/wrap payments use an empty
route. Exact Core funding includes the Broadcaster fee in the Core settlement token.
ERC20 payers approve the Router or supply an ERC-2612 permit.

`RouterRelayClient` estimates and quotes an unsigned Router/account draft before
proof generation or wallet signatures. Export the unproved Core call with
`prepared.broadcaster_intent()`, use `prepare_canonical_draft`, and build
`draft_relay_envelope` or the native `draft_envelope` with unsigned authorization
metadata. Keep fee convergence bounded by the wallet's token-denominated
`maxFeeAmount`; fees and exact-output funding use the Core settlement token.

Local `Payment::estimate_gas` and service previews use the conservative
`payment-router-gas-v1` allowances over the existing Core gas baseline, with
`source="model"`; these Router budgets are not receipt-calibrated swap figures.
Opaque 0x estimation is unavailable without a trusted service-policy route gas
budget. Broadcaster prices the model using dynamic chain fees within its configured
operational gas-price maximum; the signed gas cap remains a submission bound.

Quotes bind `payment-router-intent-v1` and direct execution. Proof completion and
Router/account/permit/7702 signature completion preserve quote identity while all
business amounts, fees, routes, deadlines, nonces and authorization metadata stay
bound. Rebuild the final payment after proving and sign its actual wallet digests.
Only the final actual call needs executable principal, allowance/permit and full
simulation before submission; Broadcaster verifies actual hashes/signatures,
pinned runtime and live counters, then estimates/simulates the complete call.
Changed business fields require a fresh quote and applicable proof/signatures.
`envelope_hash` remains available for raw signed-envelope identity.

Router relay supports neither scheduling nor aggregation. Sponsored native relay
sends zero outer value and spends principal from the payer EOA. Wallet signing,
persistent delegation/revocation, transaction signing and durable reconciliation
remain host responsibilities. See [the crate guide](crates/invisi-sdk-payment-router/README.md)
and [compile-checked integration example](crates/invisi-sdk-payment-router/examples/canonical.rs).
The existing native-only `quote`/`pay` helpers remain explicitly legacy APIs.
