# invisi-sdk-session

Version `1.2.2`. Wallet inventory, synchronization, reservations, history, encrypted storage and recovery. Depends on SDK, RPC and primitives; protocol is direct because public session interfaces expose its canonical DTOs. Proving is accessed through SDK.

See the [workspace documentation](https://github.com/invisi-lab/invisi-sdk-rust) for usage. Licensed under Apache-2.0.

## Shared public history

`PublicHistory` separates deployment-wide public discovery from encrypted account inventory. A scope binds chain ID, protocol address, runtime code hash and deployment block; it contains no owner or detection key. `PublicHistoryStore` reuses `AtomicRecords`; built-in memory and SQLite adapters support the atomic batch writes/deletes required for bounded physical storage. SQLite `SQLiteRecords::open_public(path)` uses `invisi_public_history_records` in the same database as the separate private records table.

```rust,no_run
# use std::sync::Arc;
# use invisi_sdk_session::{session::*, public_history::*};
# fn composition(source: Arc<dyn SessionSource>, scope: PublicHistoryScope, invisi: invisi_sdk_session::sdk::Invisi, wallet: invisi_sdk_session::sdk::Wallet) -> Result<()> {
let public = Arc::new(PublicHistory::new(
    Arc::new(PublicHistoryStore::new(
        Arc::new(MemoryAtomicRecords::default()), Retention::default(),
    )?), scope, source.clone(),
)?);
let private = Arc::new(RecordWalletStore::new(
    Arc::new(MemoryAtomicRecords::default()), [7; 32], // host storage encryption key
)?);
let session = WalletSession::connect(invisi, wallet, private, source, "application")?
    .with_public_history(public.clone())?;
public.sync(PublicSyncOptions::default(), &CancellationToken::default())?;
# Ok(()) }
```

Share the same public store instance across accounts. `PublicHistory::sync` downloads and validates public data without a wallet; `WalletSession::scan` privately scans it using the injected native decryptor. Account B reuses A's canonical receipts and keeps independent coverage. Without explicit injection, sessions using the same `Invisi` chain instance and a `ProtocolRpcClient` share an ephemeral cache; custom sources expose `runtime_code_hash` to opt into this default or inject an explicit history instance.

The public cache defaults to 128 MiB, 4096 pages and 8 MiB per page. Pages contain at most 256 headers. Retention keeps the highest blocks, including during reverse backfill; evicted payloads can be downloaded again. Coverage describes completed validation, including empty ranges, and survives eviction independently of retained payloads. Oversized pages return an error asking the caller to reduce page size. Page insertion, metadata publication and eviction deletes share one atomic storage transaction, so rejected generations cannot leave orphan payload rows.

Downloads sharing a store serialize and reuse overlapping retained pages. Cancellation of one subscriber does not cancel another subscriber's download; blocking source calls finish before that caller observes cancellation. Independently opened stores/processes use revision CAS for consistency without network request coalescing. Sources must provide canonical receipt/header data and enforce the deployment's runtime-code identity.

## Account scanning and status

`session.scan(decryptor, ScanOptions::default())` first catches up the most recent uncovered head, then processes descending historical pages to deployment. Each page atomically commits inventory and independent private coverage. `scan_with_progress` reports committed page boundaries; returning an error or cancelling preserves earlier committed pages, and a restart resumes actual gaps. `refresh`/`PendingWalletRefresh::decrypt` remain available for explicit range and staged-decryption integrations.

Discovery membership is verified at the selected indexed snapshot. Known Note nullifiers and Credit revocation/consumption are refreshed against the current primary head, even when the indexer lags or the page has no candidates. Empty pages advance coverage without invoking detect or decrypt. Reverse Credit discovery persists replay start, target, through and revision; after backfill, successors are recovered in chronological order. Required parents remain active while replay is pending. A request for an earlier snapshot cannot clear a later replay obligation. `retry_unresolved` can recover older parents and requeue their successors.

`scan_status()` returns recovery start/boundary, known/indexed heads, maximum scanned height, contiguous fully scanned height, missing/suggested ranges, next action and exact block progress for recent, recovery and overall ranges. Ratios are truncated to four decimals; empty denominators yield `None`. `scan_complete` describes block coverage. `is_synced` additionally requires no pending Credit replay; unresolved deliveries independently keep `asset_completeness` unknown. Status reads small encrypted metadata with `RecordWalletStore`.

`funds_status(token)` independently reports fresh unspent, unreserved known funds; a historical gap does not freeze verified current Notes. Invalidated, spent, reserved or stale inputs do not contribute to spendable funds. Transaction preparation validates membership and identity using retained canonical facts when available; live submission validates current eligibility.

Public generation changes fence private snapshots, status, preparation and commit. Reorged inventory requires `ScanOptions { reset: true, ..Default::default() }`; affected archived externalized journals and input reservations are restored before rebuilding. The SDK rebuilds from canonical data and does not implement automatic incremental undo. Reset preserves in-flight journals and their reservations.

## Native delivery boundary

`DeliveryDecryptor::detect` receives a batch of `DetectionCandidate`: clue, chain/protocol/token/commitment context, owner and funds/owner/spender role. Detection keys stay native. The default implementation considers every candidate; an explicit `false` skips it. The existing decrypt methods remain source compatible. Native integrations can override `decrypt_note_outcome` and `decrypt_credit_outcome` to return `Plaintext`, explicit `NonRecipient` or `AuthenticationFailed`.

Ambiguous authentication is persisted in encrypted per-record unresolved storage and scanning continues; asset completeness stays unknown until retry succeeds. Locked wallets, cancellation, expiry, wrong accounts and invalid authenticated plaintext are operational errors: return `Err`, which aborts the page without advancing coverage. Never translate arbitrary errors into nonrecipient results. Authenticated plaintext still passes commitment, recipient and context validation before inventory changes.

The existing C ABI and wallet wire requests are unchanged. Native `wallet.detect` still accepts clue batches; a host adapter validates and binds the complete `DetectionCandidate` context around that call. AEAD failures now return `WALLET_AUTHENTICATION_FAILED`, which the adapter maps to `AuthenticationFailed`; only explicit `WALLET_NOT_RECIPIENT` maps to `NonRecipient`. Other native error codes abort the account batch. No detection/viewing keys are exported by shared history.

## Bounded private history

Use `RecordWalletStore` for normal applications. It encrypts each asset, operation and unresolved delivery independently, authenticates manifest/row identity and revision, and performs guarded atomic writes. Active inputs, in-flight journals, reservations and required Credit parents remain hot; by default only 128 terminal records per kind remain hot. Cold history stays in the encrypted archive and survives reopen. Existing encrypted blob states migrate on the next successful write; `EncryptedWalletStore` remains available for explicit legacy blob compatibility.

`session.history_page(direction, after, limit, token)` returns projected incoming or outgoing business entries with revision, checked-through, invalidated, archived and canonical metadata. Active and archived rows are `current` only within the observed public-history generation; invalidated rows are `unknown`. Both full and paged history fence public generation and wallet revision before returning. `record_page` / `record_page_filtered` expose bounded low-level inventory rows. Cursors bind account, selected kind, token, generation and revision; restart after changes. A filtered page may be empty and still have a continuation. `history(token)` is the explicit full business view. Hosts own database lifecycle, export and deliberate deletion.

`Operation::abandon` / `WalletSession::abandon_operation` release only unexternalized local operations and persist terminal `Failed` status. Exported proofs, calldata and broadcast operations retain their reservations until canonical reconciliation.

See [`examples/05-session/restore.rs`](../../examples/05-session/restore.rs) for persistent shared public and encrypted private storage in one SQLite database. The example's application decryptor is an integration point and deliberately returns an operational error until the host implements it.

For offline recovery, first synchronize public history online, then call `scan` with `ScanOptions { offline: true, ..Default::default() }`. Retained public pages include canonical insertion positions and full Merkle paths. Offline scanning reads authenticated storage and uses these cached proofs without RPC; an evicted page must be synchronized online again. It advances account discovery but clears current spent-state freshness, does not replay missing Credit successors through the network, and cannot claim spendable funds. An online scan refreshes known inputs and finishes queued chronological Credit replay. Offline discovery alone does not create a preparation snapshot.

Custom `SessionSource` implementations must implement `known_root(tree, root, block)` using the independent canonical chain before their public membership proofs can be cached. The default rejects this capability; a self-consistent Merkle path alone is insufficient. The built-in `ProtocolRpcClient` checks the on-chain `rootHistory` mapping at a canonically bound block. Offline scans reject cached membership proofs issued after the explicitly selected target snapshot; synchronize an appropriate range online when only a later proof is retained. `funds_status` performs no RPC and describes freshness against the latest cached public head (or private observation when no public head exists); submission remains the current-chain authority.

`Operation::confirmation()` observes the operation's stored transaction hash through the independent chain reader. It does not change journal state, generation, locks, or reservations, and remains usable for completed operations. A missing hash yields pending. Native finality is optional on custom `ChainState` implementations and defaults to unsupported; `RpcChainState` with `EthereumChain` reads actual native tags and canonical receipts.

Encrypted stores keep an instance-local authenticated plaintext cache bounded to 512 records and 8 MiB of ciphertext/plaintext weight. Current ciphertext, revision, scope and manifest checks remain authoritative; returned state is detached, and cached plaintext is zeroized on eviction or store drop. Repeated wallet validation is reused only when the entire detached state has the same fingerprint; public-history generation fencing still runs on every snapshot. Neither cache is persisted.


## Offline transaction preparation

Normal online private refresh retains a typed preparation snapshot inside encrypted wallet storage: deployment pins, the genuine canonical block, verified Note/Credit paths and roots, observed consumption/revocation, the wallet funding nonce and per-token Credit allocation. Existing valid paths and same-block facts are reused; changed or expired roots refresh only affected paths. Snapshot capture shares the inventory CAS and checks canonical identity and public-history generation before commit.

`RpcChainState::new` eagerly validates the chain online. For fully offline process startup, use an existing configured adapter or the existing public `RpcChainState { chain, deployment }` initializer with locally pinned deployment configuration; session reconnect validates those pins against the encrypted snapshot. Live submission still validates the chain through `snapshot`.

After reopening the encrypted store, existing `prepare_transfer`, `prepare_shield` and all four Credit preparation methods automatically reuse these facts. Local wallet authorization, EOA funding/revocation signatures, proving with local artifacts and final `operation.calldata(caller)` export can run without chain or Protocol RPC access. A missing fact falls back to ordinary online preparation; unsupported nonce readers retain online-only behavior. New tokens and third-party funding may require an online refresh. Credit draws use the later of local construction time and cached block time for usage periods, while preserving the original canonical anchor in the saved operation.

`operation.submission_validation_pending()` reports that exported calldata still requires live checks. External senders must call `operation.validate_submission(caller)` immediately before sending. The live gate verifies deployment/canonical identity, deadlines and usage period, funding nonce/signature, root acceptance, input consumption, Credit revocation/allocation and payer balances/allowances. Managed Broadcaster submission performs its live gate automatically. Cached facts never establish that a transaction is currently safe to submit. Saved operations retain their preparation facts across restarts; restoring a proof verifies it locally rather than proving or requesting authorization again.
