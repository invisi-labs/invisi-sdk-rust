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

## Broadcaster submission preflight

Managed Funds submission freezes immutable calldata, quote and proof evidence
before writing its journal. It then performs one complete live validation gate
immediately before first send, after persistence. That gate captures one fresh,
authenticated block and shares it across root/nullifier checks, funding balance,
allowance, nonce and signature validation. No live-read cache crosses commands,
journal persistence, or separate attempts.

Freeze reads only lightweight chain time to retain automatic renewal of expired,
unfrozen quotes before exposing the durable retry marker. RpcChainState obtains
this metadata from one latest-header request; only unsupported tag reads fall
back to CanonicalHead. The source-compatible default for custom ChainState
implementations uses snapshot(), so custom wrappers should forward or implement
submission_timestamp() to receive this metadata optimization. This advisory time
never authorizes a send. Uncached Source preparation can additionally require
historical canonical-anchor reads; these are separate from live spendability.

The final gate refreshes service requirements once and checks frozen calldata,
member proof, Source capability/trust/cardinality/statement bindings and quote
expiry. RPC fact readers fence the complete successful read group before
returning: balance and allowance share one return fence, and EOA recovery is
purely local. ERC1271 contract signature checks and the whole live gate retain
canonical fences. Deployment identity and runtime code are still authenticated
by the final snapshot; a distinct preparation anchor is still checked.

Definitive pre-send Funds failures clear the durable retry shortcut while
preserving prior reservations/status. Attempted or uncertain sends retain exact
original calldata, quote, proof evidence and reservations. Quote renewal finishes
before the journal marker; no replacement packet is written after exposing that
marker. Journal failure prevents transport.

The same native diagnostic, public-funded one-output shield, retained preparation,
macOS arm64 debug build and BSC Testnet input were used for a sequential re-run:

| Submission preflight | Previous two-gate optimization | Single live gate |
| --- | ---: | ---: |
| HTTP attempts | 49 | 25 |
| Elapsed | 15.557 s | 7.692 s |
| Network interval union | 15.520 s | 7.663 s |
| Complete live validation snapshots | 2 | 1 |
| Separate quote-time header | 0 | 1 |
| Block-number RPCs | 2 | 1 |
| Header RPCs | 29 | 12 |
| Chain ID RPCs | 5 | 4 |
| Runtime/account code RPCs | 3 | 2 |
| Contract RPCs | 7 | 4 |
| Broadcaster status RPCs | 2 | 1 |
| Indexed registration RPCs | 1 | 1 |

Requests fell 49.0%; this pair's elapsed time fell 50.6%. Published 1.3.4 originally
used 95 HTTP attempts (37.198 s in the earlier sample); the current request count
is 73.7% lower. RTT/service latency varies, so request counts and safety regressions
are stronger evidence than a universal speedup claim. Cached quote is unchanged.

Both measured submit stages retain the App's 11-request final registration check;
the separate bound-route lookup preceding submit is excluded. All requests used
the first endpoint with no remote errors, failover or dropped records. Real ERC20
reads execute, but the unfunded synthetic wallet's balance/allowance results are
substituted locally. The in-memory fixture blocks the final HTTP submit at the
innermost transport; no transaction was broadcast. These are preflight measurements,
not device, SQLite, private-input proving or complete broadcast timings.

The only profiler adapter change is forwarding the new submission_timestamp()
method through DiagnosticChain; fixture input, stage boundaries, counters and
broadcast guard remain identical. Raw source/input hashes and results are retained
locally in benchmarks/native-submit-single-gate-{before,after}.json and their
comparison.json companion. The earlier published/first-round captures remain.
The repository's existing local /docs/ and /benchmarks/ excludes were preserved.

Regression coverage asserts zero complete snapshots/balance/nonce reads before
journal persistence, one each afterward, and coherent block pins when the head
advances. Post-journal nonce, funds, context, reorg, expiry or service changes
reject transport and resumed first-send retries. Other regressions cover expired
unfrozen quote renewal before persistence, renewed quote expiry after persistence,
exact durable quote replay after an uncertain response, save failure, frozen
calldata/member tampering, duplicate Source sidecars and read-time reorgs.

Reproduce with the App tools/native-public-check runner and --profile-network
--network, retaining tools/benchmarks/native-network-input.json. Build the local
SDK with the isolated [patch.crates-io] overlay for invisi-sdk, primitives,
protocol, prover, rpc and session, without changing App production pins. Forward
the new timestamp method in reader decorators; custom defaults remain safe but
may perform an additional full metadata snapshot.

## Explicit initialized native policy

`RpcChainState` keeps its original full-validation behavior, including for custom
`CanonicalHead` readers and public struct literals. Applications using a fixed
native HTTP endpoint can explicitly adopt `sdk::InitializedRpcChainState`:

```rust,ignore
let chain = EthereumChain::new(HttpTransport::new(chain_endpoint)?);
let initialized = Arc::new(InitializedRpcChainState::ethereum(chain, deployment)?);
// Discover configured broadcasters and probe token support during initialization,
// then reuse the same initialized reader and BroadcasterClient for operations.
let invisi = Invisi::new(initialized.clone());
// On a host-observed endpoint/failover change, retire before using a new reader.
initialized.invalidate();
```

The wrapper owns its transport and immutable validated deployment pins. It has no
listeners or background threads and dropping it disposes the receipt. Each
snapshot retains current chain identity and canonical-header fences. Any failed
fact read permanently retires the receipt; later reads fall back to the original
runtime validation. Construct a fresh wrapper after switching endpoints. Receipt
reuse never caches funding nonces, balances, allowances or signature policy.

Fresh authorization reads are optional and network bound. Custom `ChainState`
implementations retain full snapshots unless they explicitly supply a capability.
A self-contained Shield with encrypted embedded recipient material, direct signed
public funding, no permit or schedule can delegate execution-state validity to
stock broadcaster exact simulation and the contract only when both the initialized
native reader and stock RPC broadcaster supply sealed policy capabilities. The
final network fence, exact calldata/quote binding, current broadcaster status,
journal freeze, reservations and uncertain-send recovery remain in force. All
custom readers/broadcasters, identity-only recipients, private inputs, Credit,
manual calls, scheduling and permits retain their existing validation.

Stock ordinary unscheduled no-permit Shield quotes price paid fee/signature
features in the initial unsigned estimate, reprepare with the returned exact fee,
and request the signed quote without a redundant convergence estimate. Legacy
structured `-32000` quote refusal permits a bounded fresh estimate only when the
fee increased within the user cap. Other errors never trigger price refresh.

For a configured relay, initialize support once and reuse the scoped collection:

```rust,ignore
let chain: Arc<dyn ChainState> = initialized.clone();
let relay = invisi_sdk_rpc::broadcaster::BroadcasterClient::connect(configuration)?;
let relays = InitializedBroadcasters::configured(relay, chain.clone(), token)?;
relays.quote(&mut operation, chain.clone(), &options)?;
relays.submit(&mut operation, chain.as_ref())?;
```

`InitializedBroadcasters::discover` instead initializes registry discovery plus
support probes. `clients_for` returns `None` for a different token/reader or a
retired lifetime, allowing normal discovery to resume. `invalidate` retires both
support/discovery and deployment receipts, including pending reads. Initialization
probes check the lifetime again before publishing a receipt. No current service
halt/tracking policy is cached.

Embedded-recipient and stock-quote policy metadata survives newly written journal
roundtrips. Missing legacy metadata uses full validation. Restoring stock quote
metadata reauthenticates the signed quote against the exact intent and saved
configuration; malformed output-origin metadata fails closed. Registry-resolved
outputs remain conservative even when they carry encrypted delivery material.

An explicit nonce prerequisite should be attached with
`PreparedTransaction::with_fresh_funding_nonce` or
`session::Operation::with_fresh_funding_nonce`, consuming the opaque
`FreshFundingNonce` returned by the initialized reader. It binds payer and
protocol context and persists selection only within that prepared intent.
A manually populated nonzero funding deadline does not imply a selected nonce:
quote preparation still reads the current nonce once. A successful explicitly
fenced `with_funding_terms` also records selection. Fee refresh preserves those
terms throughout the same operation; uncertain replay never selects new terms.

Eligible first submissions keep two network-only fences: one entering first-send
preflight before service-status work and one after local packet/quote checks,
immediately before transport. Receipt retirement between them rejects the
attempt. Uncertain replay and known-ID status recovery keep their frozen path.

The initialized pool preserves frozen recovery after receipt retirement. Built-in
prepared targets must show an actual attempted/known submission; managed targets
must show the durable relay handoff and exact stored call. The SDK authenticates
that frozen packet and signed quote, then selects only the same client/config
already owned by the pool. Unknown IDs replay identical parameters; known IDs
query status only. Ordinary wallet exports and never-attempted targets still
require a valid initialization receipt. Custom targets default to no frozen
recovery capability.

## Controlled HTTP alignment measurement

The final common driver uses three independent fixtures, two operations per
fixture, repeated-byte public synthetic payers 1/2 with current nonces 7/14,
one encrypted embedded long-address output, business amount 30, fee 5 and cap 10.
The same initialized reader/client/session and first journal are retained within
each fixture. The driver verifies the selected nonces and byte-identical first
journal after the second operation. All actual chain and broadcaster loopback
HTTP responses carry a 20 ms delay. Before and after run sequentially with the
same debug profile; compilation, process launch and human review dwell are excluded.
Initialization and cold object setup are counted separately and charged once.

| Rust controlled result | Frozen before | Final initialized policy |
| --- | ---: | ---: |
| Initialization HTTP per fixture | 12 | 10 |
| First transaction HTTP | 71 | 7 |
| Repeated transaction HTTP | 71 | 7 |
| All three fixtures HTTP | 462 | 72 |
| First transaction median | 3269.029 ms | 1692.472 ms |
| Repeat transaction median | 3284.159 ms | 1714.746 ms |
| First median including cold/setup once | 3584.675 ms | 1953.447 ms |
| Two-transaction fixture median including startup | 6865.257 ms | 3668.193 ms |

First-transaction ranges over three fixtures are 3250.297–3275.115 ms before
and 1687.512–1728.259 ms after. Repeat ranges are 3280.582–3311.028 ms before
and 1707.065–1724.820 ms after. Transaction HTTP fell 90.14%; fixture HTTP including
initialization fell 84.42%. First/repeat median elapsed fell 48.23%/47.79% under
this controlled latency and matched debug profile. Actual note encryption and
other CPU work remain included, so elapsed reduction differs from request reduction.
These are not public-network, App registry, device, or absolute cross-language
speed measurements. Earlier App/native figures above remain historical context.

Each group denied six broadcasts before outbound write HTTP; actual write HTTP
was zero. Final submit trace order is network fence, current service status,
network fence. The separate managed long-Shield recovery regression permits only
a synthetic loopback relay to record requests, never a chain send. It covers
first journal failure with byte-identical old state and zero HTTP, durable exact
packet/quote before acceptance, lost response plus journal resume and identical
replay, receipt retirement and known-ID status-only recovery, and prior wallet
export followed by a structured refusal.

Final evidence is in `test-support/performance/three-sdk-alignment/`: `before.json`,
`after.json`, `comparison.json`, `benchmark-metadata.json`,
`after-source-manifest.json`, and `validation-results.json`. The common driver
SHA-256 is `23affb4a54c7397751e6d2853e40581ca6c053d0b4b8b602b7c026823f7b376c`.
Full workspace validation passed 507 tests with 17 intentional ignores; the
new unified managed HTTP regression additionally passed its focused test covering
two failure scenarios. Formatting, Clippy, module boundaries and English checks
passed. Clippy retains repository warnings and a test-only callback type warning.
