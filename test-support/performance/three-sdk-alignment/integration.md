# Rust integration verification

The optimization safety commit is `b59de24`. It merges develop's fee-lock commit
`ddbc3c6` and receiving-signature-v1 commit `54df7f5` without rebasing. Conflicts
were confined to the Funds/Credit broadcaster implementations. The resolution
retains fee-lock negotiation, tariff propagation and validation together with
local fee repricing, explicit Source finalization, frozen attempted recovery,
and post-persistence wallet/network fences.

Fee-lock capabilities are authenticated during initialized broadcaster setup and
cached per client/deployment from the validated full token-support response. Other clients discover them on their first quote.
Authenticated unexpired tickets are reused for the same deployment/token/recipient;
expired or invalid responses fail explicitly. Every first submission still checks
live service requirements. Tests cover capability reuse, deployment isolation,
unchanged signed tariff propagation, expiration refetch and no silent downgrade.
Explicit support revalidation or a new client establishes a new capability lifetime. Cache locks never span transport I/O. Probe epochs and per-token fetch sequences prevent late capability or tariff publication, and structured fee-lock refusal evicts only the exact client/epoch/ticket entry.

No proof-resource downloads, public-chain writes, pushes or worktree removals
are part of this integration. Synthetic Source/native provers remain test-only;
resource-dependent native proving tests remain intentionally ignored. Historical
elapsed benchmarks remain unchanged and are not claimed as merged-tree timings.

Verification commands and results are recorded below after completion. Full logs
are local artifacts under `/tmp/invisi-sdk-integration-20261125/rust-*`.

## Functional stage checks

- `INVISI_ALIGNMENT_DELAY_MS=0 INVISI_ALIGNMENT_STAGE_CONTRACT=1 INVISI_ALIGNMENT_OUTPUT=/tmp/rust-http.json cargo test --locked -p invisi-sdk-session --all-features --test alignment_http -- --include-ignored`: 2 passed. Three fixtures with two distinct payer nonces (7/14) each retain seven operation HTTP requests: prepare 2, quote 2, funding signature 0, submit 3. Initialization uses 10 requests; validated token support also supplies the fee-lock capability. All six broadcasts are denied before write HTTP, and the first journal is byte-identical after the second operation.
- `INVISI_STAGE_NO_READY_FAILURE=1 INVISI_ALIGNMENT_DELAY_MS=0 INVISI_STAGE_SOURCE_TRACE=/tmp/rust-source.json cargo test --locked -p invisi-sdk-session --all-features --lib private_source_stage_boundaries_and_exact_recovery`: 1 passed. Quote adds no chain/Source reads; prove uses one main proof and zero Source work; ready adds one Source proof and three loopback Source RPCs. First submission and unknown-ID replay add no proving or Source work; known-ID recovery queries status only. Default full-suite mode additionally injects a ready failure.
- `cargo test --locked -p invisi-sdk-rpc --test fee_lock`: 7 passed, including repeated capability/ticket reuse, wrong-deployment rejection, expired-ticket refetch rejection, same-thread reentrant transport callbacks, late legacy discovery, cross-client ticket rejection and delayed-old-refusal/new-ticket preservation and actual/no-op provenance policy transitions.

The diagnostic selects the current signature-prepare API by default. Explicit
`invisi_alignment_before` or `invisi_stage_before` builds keep the baseline adapter.
These runs validate request counts and stage behavior; elapsed values captured
in their traces were not collected under a quiet timing protocol.

## Full verification

`cargo test --locked --workspace --all-features --no-fail-fast` exited 0 on the
hardened merged tree before the final consuming-policy-setter follow-up: 100 groups, 529 passed, 0 failed and 17 intentional ignores.
Local workspace package artifacts were cleaned before the first merged rebuild;
third-party dependency caches were retained. `cargo clippy --locked --workspace
--all-features --all-targets`, `cargo fmt --all -- --check`,
`python3 scripts/check-boundaries.py`, `python3 scripts/check-english.py` and
`git diff --check` all exited 0. Clippy retains repository warnings.

The final policy-setter regression reproduced old tariff authority surviving
`with_provenance_mode` (exit 101). The setter now retires the cache only on the
actual None-to-Some policy transition; a repeated no-op preserves it. All RPC
crate tests were rerun afterward (72 passed, 3 ignored), together with both
HTTP alignment tests and the required-Source fixture. Unchanged exhaustive gas
and unrelated workspace tests were not repeated for this three-line follow-up.
