# Wallet history performance

The implementation retains receipt/event decoding, membership and root validation, original TrustedProvider header hash verification, canonical anchor checks, consumption/revocation checks, durable private cursor updates, public-generation fences and reorganization recovery. Public wallet APIs and persisted wallet formats do not change.

## Changes

- Schedule Credit replay from the actual earliest newly authenticated owned state, rather than the page boundary. An already known delivery does not create another replay obligation. Earlier newly recovered dependencies rewind pending replay; later dependencies retain committed replay progress. Pending target/revision fencing remains intact.
- Index owned predecessor nullifiers within each refresh, including both owner/spender roles and successors recovered earlier in the same ordered receipt sequence. Recovery still works without decrypting successor ciphertext.
- Pin the indexed target and primary observation for one scan. Consumption and revocation results are reused only for that exact numeric block and hash during that invocation. Each map holds at most 8,192 results; excess entries are read without caching. Every private commit performs fresh independent canonical checks. A later scan and every ordinary refresh/pre-execution operation obtain fresh state. An observation behind the target or any recovered inventory is rejected.
- Read Note/Credit history with one call-local authenticated status. Both responses retain their existing range, row, deployment and canonical anchor checks.
- Use optional TrustedProvider bulk headers through existing `invisi_readChainState` JSON-RPC batches of at most 20. Correlation, member count, duplicate/unknown IDs, errors, version/deployment, full header hash and requested height are checked. PublicHistory also checks continuity across chunks and cancellation between chunks. Errors never trigger a permissive fallback. Providers without the capability retain the bounded eight-reader path.
- Reuse the acquired public metadata view while reading retained page payloads, retain digest checks and add a final generation check. Use the already downloaded end header for a new page's initial anchor; the final independent anchor read remains. Private page checkpoints and externally observable journals are not skipped.

## Reproduction

```bash
cargo test -p invisi-sdk-session --features sqlite --lib benchmark_wallet_history_pipeline -- --ignored --nocapture
cargo test -p invisi-sdk-session --features sqlite --lib benchmark_credit_replay_pipeline -- --ignored --nocapture
cargo test -p invisi-sdk-rpc --test trusted_provider benchmark_trusted_header_batch -- --ignored --nocapture
```

The reference source was exported with `git archive 6559db6` to a separate temporary directory. Only the identical instrumented session test fixture was copied into that export; reference production files were unchanged. A separate Cargo target directory prevented interference with the working tree. Three samples were collected for each comparison. Build time and wallet fixture construction are excluded from the timed sections.

The fixtures use in-memory storage. The scan fixture covers 128 blocks in eight pages, placing one owned Note either near the beginning or the end of history. Each logical source header read sleeps for 2 ms; cryptographic receipt/delivery/membership work remains real. Source counters count SDK source calls, not the total wire requests produced by a real provider. The optional SQLite feature was enabled in both reference and optimized test builds, but the measured backend remains the same in-memory implementation. CPU scheduling and concurrent builds affect these short debug-profile timings.

The Credit fixture first completes historical parent/successor recovery, then re-presents a formerly unresolved parent delivery whose opening is already authenticated. It times retry plus required replay. Both before and after assert the same recovered successor and consumed predecessor, clear unresolved material, and retain all required state checks. No synthetic latency is added in this case.

The standalone header comparison obtains the same 256 fully validated TrustedProvider headers through singles and batches. Its transport adds 2 ms per send. It measures HTTP round-trip reduction; it does not assume the server executes members concurrently.

## Results

Median of three samples, milliseconds:

| Discovery fixture | Before | After | Logical indexed reads | Logical source block reads |
| --- | ---: | ---: | ---: | ---: |
| Private discovery Note at10 cold | 151.079 | 123.439 | 9 → 1 | 33 → 18 |
| Private discovery Note at10 warm | 40.059 | 41.184 | 1 → 1 | 3 → 3 |
| Private discovery Note at120 cold | 369.855 | 333.213 | 9 → 1 | 33 → 18 |
| Private discovery Note at120 warm | 39.986 | 39.997 | 1 → 1 | 3 → 3 |
| Shared public history Note at10 cold | 310.084 | 269.433 | 9 → 1 | 192 → 169 |
| Shared public history Note at10 warm | 45.853 | 46.209 | 1 → 1 | 4 → 4 |
| Shared public history Note at120 cold | 530.938 | 510.714 | 9 → 1 | 192 → 169 |
| Shared public history Note at120 warm | 46.222 | 46.623 | 1 → 1 | 4 → 4 |

Cold discovery keeps the same eight pages/private commits and the same receipt/membership work. When the Note is discovered early in scan execution (block120), consumption reads fall from eight to one at the pinned observation. Warm scans already perform zero history downloads; their counts do not improve, and their short elapsed times vary slightly. No broad warm-cache speedup is claimed.

| Additional fixture | Before | After | Work avoided |
| --- | ---: | ---: | --- |
| Retry already owned Credit and finish replay | 5102.237 ms | 286.011 ms |42 →0 replay pages;43 →1 commits;43 →1 indexed reads;170 →2 source block reads |
|256 full TrustedProvider headers, singles versus batch | 670.844 ms | 71.196 ms |256 →13 transport sends; all256 headers validated |

The large retry improvement applies to the redundant owned-delivery replay case, not every sync or collection. Likewise, header transport savings are a component benchmark, not a whole-wallet throughput claim. Signing, proving, broadcast, finality waiting and remote RPC load were not benchmarked. Real deployment timing requires a subsequent application-level run; no financial transactions were sent for these measurements.

All individual sample counters and timings are retained in [wallet-history-20261121.json](wallet-history-20261121.json).

## Regression coverage

- Exact owned-parent lower bound, duplicate owned delivery, both roles sharing a nullifier, successor recovery without accepting its ciphertext, and nonrecipient Credit events without replay obligations.
- Interrupted replay resumes its durable cursor; later dependencies retain progress, earlier dependencies rewind, and replaying an earlier target cannot clear a later obligation.
- Consumption/revocation refresh, next-invocation fresh state, same-height forks, observations behind discovery, public/private generation races, corrupt memberships and unknown roots.
- Bounded unordered JSON-RPC batches, missing/duplicate/unknown members, typed remote errors, malformed/ambiguous errors, changed deployment, wrong full-header hash/height, broken continuity, and cancellation after the first bulk chunk without partial cache writes.
- Existing canonical reset, uncertain submissions, operation reconciliation and reservation-preservation suites remain in the full workspace run.

## Validation

- `CARGO_BUILD_JOBS=2 cargo test --workspace --all-features --all-targets`: 397 passed, zero failed, 12 explicitly ignored, across 76 test binaries. This includes 95 session unit tests plus SQLite/store integrations and all downstream workspace compilation.
- The final transport error-classification review fix was subsequently verified with `CARGO_BUILD_JOBS=2 cargo test -p invisi-sdk-rpc`: 48 passed, zero failed, one explicitly ignored benchmark; RPC doctests also passed (zero examples).
- Both ignored session benchmarks and the ignored TrustedProvider benchmark were run explicitly in three-sample comparisons. Other ignored tests require explicitly configured native proving/live resources and were not enabled.
- `cargo fmt --all -- --check` and `git diff --check` passed.

The initial unconstrained workspace build stalled in macOS dynamic-library loading/code-signature checks. Verification was restarted with a command-local build-job limit of two; no security settings or toolchain configuration were changed.
