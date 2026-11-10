# Invisi Rust SDK

A Rust SDK for ordinary private Notes and deferred Credit grants, aligned with the
shared TypeScript and Go protocol behavior. Source, comments and documentation use English.
The SDK does not select accounts, read Keychain/Keystore, hold a mnemonic, or approve requests.

## Workspace

| Crate | Responsibility |
| --- | --- |
| `invisi-sdk-core` | Wallet cryptography, Note/Credit models and transitions, addresses, FMD, delivery, disclosure, payment requests and measured gas references. No HTTP, prover or managed store. |
| `invisi-sdk-protocol` | Current contract ABIs, shared chain/output types and canonical receipt decoding. |
| `invisi-sdk-prover` | Authenticated circuit identities, explicit local witnesses, native BB proving and recursive aggregation. |
| `invisi-sdk-rpc` | Indexed Protocol RPC, independent Ethereum reads and registered broadcaster quote/submit/status transport. |
| `invisi-sdk-runtime` | Public Wallet, stateless preparation, external authorization, funding, proving and calldata. |
| `invisi-sdk-session` | Inventory, staged synchronization, reservations, history, journal recovery and encrypted persistence; optional SQLite. |
| `invisi-sdk-ffi` | Narrow native C ABI backed by core only. It does not pull in HTTP, proving or Session. |
| `invisi-sdk` | Convenience facade that reexports the focused crates. Its `src` contains only `lib.rs`. |
| `invisi-sdk-examples` | Flat, independent scenario programs, corresponding to the Go/TS examples. |

Dependencies flow from core to protocol/prover, then RPC and runtime, then Session.
Protocol DTOs live below RPC so receipt decoding does not create a dependency cycle.
Native hosts that only need wallet cryptography depend on core or FFI directly.

## Wallet boundary

`invisi_sdk::sdk::Wallet` contains public identity and receiving keys only. Session
configuration contains no executor, viewing key or authorization callback. The App/Vault
executes explicit requests and returns responses. Managed and stateless preparation use
the same transcript:

```rust,ignore
let request = prepared.export_wallet_request("payment-authorization")?;
let requests = [request];
// Send the serialized array to the native host and read its response array.
wallet.accept_batch(&requests, &native_responses)?;
let response = native_responses.iter().find(|r| r.id == requests[0].id)
    .ok_or("missing wallet response")?;
let authorized = prepared.with_wallet_response(&requests[0], response)?;
let ready = authorized.prove(&prover, false)?;
let call = ready.calldata(&chain, caller)?;
// EVM transaction signing is a separate host operation after calldata exists.
```

Wallet methods are `wallet.public`, `wallet.detect`, `wallet.decryptNote`,
`wallet.decryptCredit`, and `wallet.authorize`. Integers use canonical decimal strings;
bytes use lowercase `0x` hex. IDs are printable ASCII, 1–128 bytes. Native responses are
checked against the retained request, identity, signatures, contexts and financial
commitments. Public material never includes spending, viewing or detection private keys.
Decrypted financial data and transient proving witnesses may return to the business SDK.

The explicit native API `wallet::execute_batch(account_key, requests)` takes a host-owned key
as a function argument. It never obtains a key from the JSON request or persists it.
The host owns unlock, consent, key access and clearing its original key buffers.
Batches permit at most 1024 items and 16 MiB of total JSON in each direction. All requests
must have unique IDs and the same owner; the native core validates the entire batch before
execution. Empty batches return empty arrays. Responses may arrive in any order; SDK
acceptance rejects missing, duplicated, unknown or incorrectly bound responses. The C ABI
exposes `invisi_wallet_execute_batch` with a length-delimited JSON array input.
Request IDs correlate responses; chain replay rules and host approval policy are separate.

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

Session refresh returns an opaque staged handle with serializable `wallet_requests`.
The host returns a direct response array. Each response has `version`, `id`, `ownerAddress`,
`method`, and exactly one `result` or `error: {code}`. Only `WALLET_NOT_RECIPIENT`
skips a candidate; other errors abort without state changes.
Apply rechecks canonical data and atomically commits through a revision CAS. Unlock or
transport failures leave the work pending. Oversized staged refreshes fail without writes;
select a smaller block range to remain within the native batch limits. Inventory and Credit
role state remain separate.

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
Protocol address. Native hosts use the current Protocol/runtime preparation APIs
for Shield, transact and Credit; ERC20 approval is explicit runtime data.

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

The independent [Provenance module](PROVENANCE.md) keeps source recognition separate from protocol spendability. Ordinary direct prepare/prove/export never requires Source or Broadcaster; the App independently chooses source evaluation before sending or source proof submission after confirmation. Explicit `with_broadcaster` for Notes and all four Credit operations delegates policy preflight to Broadcaster, retains the verified quote/tracking and submits the frozen context. Managed retries persist their first ID and query the relay journal before any fresh attempt, including after restart with Source offline or absent. See the normal [Note](examples/03-note/transfer.rs) and [Credit](examples/04-credit/create.rs) examples. App integration, account signing and nonce reservations remain host-owned.
