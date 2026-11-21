# Wallet state refresh performance

The original `WalletSession::refresh(RefreshOptions)` keeps its preparation snapshot and offline preparation behavior. Hosts that only need current inventory may opt out of transaction material preloading:

```rust
let pending = session.refresh_with_behavior(
    RefreshOptions::from_block(from_block),
    RefreshBehavior { inventory_only: true },
)?;
let result = pending.decrypt(decryptor)?;
```

This deliberately drops an older retained preparation snapshot. Transfers, collections, credit updates and credit draws align only selected wallet input paths when they subsequently prepare online. Shielding and other transaction material use the existing online preparation path. Full/default refresh continues to preload nonce and aligned inventory paths.

Both refresh modes retain canonical and deployment checks, current nullifier/consumption checks for **all** records (including historical consumed records), revocation checks, pending operation recovery, revision/generation protection, cancellation and atomic commit. Independent reads run in at most four scoped workers; results merge in deterministic input order. Duplicate role/nullifier and exact revocation queries share one read within the same fixed numeric block/hash. No cache survives a refresh invocation or supplies signing/submission validation. The existing multi-page scan cache remains scoped to that scan and captured block/hash.

Rust's `ChainState`, `CanonicalChain` and `SessionSource` require `Send + Sync`, so synchronous scoped worker threads are supported without changing provider trait bounds. `ChainState::credit_status` returns the authenticated grant status keyed by owner/token/uint128 GrantID; exact queries are deduplicated and unknown/active/revoked distinctions remain intact. `RpcChainState::snapshot` continues to authenticate chain identity and runtime code at its captured block. Rust did not previously perform extra VERSION/registry binding checks in preparation snapshot capture; this change preserves its existing validation model.

`ProtocolRpcClient::get_memberships(inputs, block)` accepts at most 256 ordered inputs. The client itself supplies pinned deployment scope. One authenticated status/finality read and shared root/known-root evidence serve the operation. Every individual response binding, path depth, field and Merkle proof is verified. Each tree uses a common root that covers its highest requested leaf; conflicting explicit roots fail before network IO. Canonical root anchors, indexed status head and the requested block are fenced again before returning any paths. `get_membership` remains available and delegates to a one-element batch. `SessionSource::memberships` has a source-compatible sequential fallback; the RPC implementation shares evidence through the new batch API.

Preparation path capture first batches missing highest-leaf leaders, then batches missing followers pinned to those roots. Valid cached paths are reused. Each request is bounded to 256 paths and any failure discards the pending wallet update.

## Reproduce

```sh
cargo test -p invisi-sdk-rpc --test membership_batch -- --ignored --nocapture
cargo test -p invisi-sdk-session benchmark_wallet_state_refresh_materialization --lib -- --ignored --nocapture
cargo test -p invisi-sdk-session bounded_read_tests --lib
```

These deterministic fixtures use real Merkle hashing and real wallet state, without remote services, transactions, or sleep-based timing assertions. Benchmarks print request counts and local elapsed microseconds; tests assert counts, state and safety properties, never a timing threshold. Wall time varies with build mode, CPU contention and actual provider latency.

The membership benchmark compares repeated single calls with an ordered same-tree batch. It requests repeated fixture leaves to isolate evidence sharing while verifying every returned path; separate tests use distinct leaves in both input orders to verify highest-leaf/common-root behavior. Indexed status, roots and known-root calls reduce from `3N` to `3`, while `N` individual path requests remain:

| Requested paths | Single indexed/contract requests | Batch indexed/contract requests |
| ---: | ---: | ---: |
| 1 | 4 | 4 |
| 8 | 32 | 11 |
| 32 | 128 | 35 |
| 128 | 512 | 131 |
| 256 | 1024 | 259 |

The benchmark separately prints canonical header and chain identity read counts, preserving start/end fences. No finality claim is configured in this fixture; when present, finality authentication is performed by the single shared status validation.

The materialization benchmark seeds one tree per inventory Note and observes one extra receipt Note. Both modes query every nullifier. For `N` seeded Notes, full refresh performs `N+1` root checks plus one nonce read; inventory-only performs the one new receipt's root check and skips nonce preload. Real wallets with many Notes in one tree share root checks, so these figures describe this explicit fixture rather than a universal per-Note saving.

Run local timings without concurrent compilation or other benchmark jobs for comparable measurements. The counters demonstrate request reduction independently of local CPU timing; they do not claim a measured production network speedup.

Example local debug-build results (2026-11-21): at 256 requested paths, single calls took 4,738 ms and the batch took 4,692 ms; header reads fell from 1,536 to 6 and chain-identity reads from 1,792 to 7. In the 257-Note materialization fixture, full and inventory-only refresh took 7,926 ms and 7,943 ms respectively while retaining 257 nullifier queries in both. These no-network timings are dominated by hashing/state validation and show why request reduction must be reported separately from wall time. No synthetic network delay was added.

Online refresh always reauthenticates stored root acceptance, including a prior snapshot at the same block/hash. Only root evidence verified during the current refresh can be shared. This does not add live reads to an explicitly offline preparation replay.
