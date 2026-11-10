# Invisi Rust SDK

A Rust SDK for ordinary private Notes and deferred Credit grants, aligned with the
shared TypeScript and Go protocol behavior. Source, comments and documentation use English.
The SDK does not select accounts, read Keychain/Keystore, hold a mnemonic, or approve requests.

## Release validation

The public crates share version **1.2.0**. See [local release validation](RELEASE.md)
for packaging checks and the required publication order.

Version 1.2.0 exposes six common modules plus the separate native FFI adapter.
Replace `invisi-sdk-core` dependencies/imports with `invisi-sdk-primitives`.
Use `invisi_sdk::sdk` for stateless operations and `invisi_sdk_session::session`
for managed wallets; enable `sqlite` on `invisi-sdk-session` when needed.
The former runtime crate is integrated into `invisi-sdk`. Public Source contracts
are in `invisi_sdk_protocol::provenance`; local Source witnesses and proving
capabilities are in `invisi_sdk_prover::provenance`. Encrypted Source recovery
and its coordinator are in `invisi_sdk_session::provenance_recovery`.

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

`Wallet` stores public owner and receiving material. Applications provide delivery decryption and ordinary EIP-712 signing; the SDK never needs an account private key or wallet transport.

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
Circuit files and tool binaries are explicit authenticated host assets, not silent remote
services. `NativeProver` accepts a host `WitnessExecutor`, including the external Noir CLI
adapter; a mobile host can use its embedded native ACVM. Blocking RPC/proving work belongs
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

The independent [Provenance module](PROVENANCE.md) keeps Source recognition separate from protocol settlement. Ready private Note payments expose `prove_provenance`, `precheck_provenance`, and independent `submit_provenance` with an optional transaction hash. Rebuilding Source evidence preserves the existing payment. Broadcaster estimates fees separately from its final signed quote, advertises Source requirements, and assigns opaque server submission IDs. Managed retries retain the exact request and the returned server ID. See the parallel [Broadcaster examples](examples/07-broadcaster) and ordinary [Note](examples/03-note/transfer.rs) and [Credit](examples/04-credit/create.rs) flows. Apps supply ordinary signing and delivery decryption.

Final RPC gas estimates are available on native Note and Credit prepared transactions and managed operations through `estimate_gas`. They use the exact exported calldata and caller. Managed estimates retain the export fence even if the provider rejects the estimate. These RPC results are separate from documented benchmark references, relay fees and quote gas ceilings.

`ProtocolRpcClient::discover_broadcasters(token)` pages enabled registrations at one canonical registry anchor and independently probes each operator's token support. Unsupported, unreachable or incorrectly identified services are skipped. Apps with their own network policy may use `discover_broadcasters_with_transport`; the Protocol RPC wire query itself has no token filter.
