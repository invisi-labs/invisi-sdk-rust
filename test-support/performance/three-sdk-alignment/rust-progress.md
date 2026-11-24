# Rust alignment progress

Scope: only isolated submit-read-dedup worktree; no commits, merges, releases or real sends.

## Phase 0

- Read common plan and existing preparation, quote, funding and submission gates.
- Frozen before sources were supplied externally; existing edits are preserved.
- Baseline `cargo test -p invisi-sdk --test submission_reads`: 3 passed.
- Production edits await root GO after TS lifetime fix and Go atomic externalization fix.

## Design

Existing `RpcChainState` remains source compatible (public struct literals and custom
`CanonicalHead` implementations). A separate initialized native wrapper can own
fixed endpoint transport and validated deployment receipt; it must retain network
and canonical fences, invalidate explicitly, and fall back to full runtime checks
when invalidated. Custom trait capabilities default to None/full validation.
Fresh nonce capability must return current nonce, timestamp and network identity;
legacy snapshot path keeps custom behavior. Plain unscheduled no-permit Shield
can estimate paid features from locally cloned unsigned calldata, reprepare once,
then obtain the exact signed quote. Only structured business refusal may refresh
price; transport/signature errors remain terminal. No blanket custom-policy bypass.

## Benchmark boundaries

Use ordinary signature-funded one-output Shield to long receiving address. Reuse
initialized objects; three fixtures, two flows, payers one/two. Count HTTP at actual
transport, deny writes; separate init/cold/steady phases. Do not run elapsed
measurements concurrently with heavy checks. Existing three submission reader
regressions are safety evidence, not HTTP benchmark evidence.

## Red tests

- `cargo test -p invisi-sdk --test submission_reads`: added conservative custom
  capability regression fails compilation on absent optional capability methods.
- `cargo test -p invisi-sdk --lib stock_plain_shield_quotes_paid_features_with_one_estimate`:
  fails as intended: actual estimate→estimate→quote vs required estimate→quote.
  Existing stock mock transport signs the exact final request and validates the
  feature-estimate data independently. No production changes yet.

## Production phase (root GO received)

- Added separate fixed-native `InitializedRpcChainState`; legacy literals and
  custom readers remain full-validation. Failed fact reads and explicit
  invalidation permanently retire the receipt. Every snapshot keeps live
  network and canonical fences; native endpoint is privately owned and immutable.
- Added fresh authorization nonce metadata capability, default None.
- Added sealed native reader and stock broadcaster policy values. Narrow
  self-contained encrypted-recipient signature-funded direct Shield can delegate
  execution state only with both capabilities; custom/identity-only/manual/
  permit/schedule/private/Credit paths retain full gates.
- Stock ordinary Shield quotes use paid-feature estimate then exact reprepare
  and signed quote. Bounded structured -32000 refusal refresh only if increased
  under cap; custom broadcaster convergence unchanged.
- Conservative reader regression passes 4/4. New initialization tests compiled.
- macOS dyld delays test binary startup; sampling showed pre-main _dyld_start,
  112 KB memory and no SDK execution. This is excluded from measured timings.

## Scope tightened after coordination

- Fresh nonce is now latest-state call plus final network identity (two HTTPs on
  Ethereum native), no mutable cache or fake timestamp. Legacy/custom paths keep
  their original snapshot/ancestry policy. Existing FundingParams consume the
  actual prerequisite nonce/deadline; quote selects those terms once and retains
  them through all fee refresh attempts.
- Managed stock-quoted embedded Shield auth export/attachment rebuilds local
  typed data and recovers EOA signatures locally. Unquoted/manual and custom
  quoted paths retain current nonce/signature validation.
- Initialized embedded Shield construction may reuse its immutable initialization
  anchor; quote/freeze use host clock, and delegated final submission reads only
  current network identity plus the existing broadcaster status check.
- Recipient provenance is explicit: embedded supplied keys true, EVM registry
  resolution false. New journal snapshots persist origin and stock quote policy;
  absent legacy fields remain false/full. Restoration validates complete output
  data and authenticates the signed quote against exact frozen intent/config.
- Native nonce/network/snapshot capabilities reject invalidation during IO;
  discovery/support publication checks the receipt again after the probe. Pool
  invalidation retires the associated chain receipt. Token mismatch and foreign
  reader instances never reuse support receipts.
- The common diagnostic now resumes the journal after quote before signature and
  again after ready before first submission, using the same session/store and
  preserving the first operation. Baseline cannot quote a resumed unquoted Shield
  (its template was absent), so that stage is not inserted in the common run;
  the new implementation reconstructs a validated Shield repricing template.

## Validation state

- Earlier production checkpoint: all 78 SDK lib tests completed (76 passed,
  2 intentionally ignored proving-resource tests). This preceded final scope and
  journal changes and is not claimed as the final full check.
- Final full workspace check is running; further focused compilation is green.
- A zero-delay diagnostic exposed an inherited nonblocking accepted-socket race
  on macOS. The fixture now explicitly switches accepted streams to blocking IO
  and avoids a second panic in Drop. This is harness-only, not a product failure.
- Measured 20 ms runs remain on hold pending root CPU-quiet GO.

## Final corrections and source isolation

- The explicit nonce prerequisite now uses opaque payer/context-bound metadata
  and `with_fresh_funding_nonce` on prepared/managed operations. Raw nonzero
  FundingParams deadlines retain fresh selection. Regression covers current
  nonce 7 vs supplied default 0, explicit next nonce 8 without another read, and
  wrong-payer rejection. A successfully fenced `with_funding_terms` also marks
  an explicit selection.
- Ready-stage stock quote restore authenticates the already validated snapshot
  unsigned call, avoiding the stage-restricted draft quote exporter. Regression
  covers Prepared and Ready roundtrips, missing legacy metadata, and quote
  tampering. Legacy fixture now omits all three new marker fields.
- Prior manual export retains frozen uncertainty after a structured first relay
  refusal: rollback requires `!previously_externalized`. New regression retains
  call/local relay ID/externalized status and prevents abandonment.
- Uniform first-send contract now keeps entry and final network-only fences.
  A retired receipt between them rejects the attempt; uncertain replay skips both.
- Before and after build targets are strictly isolated. Initially sharing target
  artifacts caused same-version local SDK rlib collisions. Only local workspace
  package artifacts were cleaned, third-party dependencies retained, and the
  final baseline is built in `/tmp/invisi-rust-before-target-isolated` against
  frozen sources. No global caches or other chats' processes were modified.

## Functional HTTP evidence (not elapsed benchmark)

Common driver SHA-256:
`5969a13a82e52a64b3d2a1dc1672f91d0cca2033ca78a3e7a64c95a43985fe8e`.
The before SDK source hash matches initial manifest `14cff2ce...`.
Zero-delay controlled loopback runs use actual HTTP for both services, the same
session/store for two payers, and journal resume after quote and before submit.
Before: initialization 12 HTTP, each transaction 71 = prepare 13 + quote 23 +
signature 22 + submit 13. After with the final two-fence contract is expected 7;
its new functional run is in progress. Every fixture denies two writes before
HTTP; actual write HTTP is zero. These are controlled synthetic loopback tests,
not public network, App registry, device, or absolute cross-language speed data.
The matched Rust profile is debug; crypto CPU and complete phase time are included.

## Final pool recovery boundary

- Added conservative-default frozen-authority introspection. SDK snapshots
  authenticate exact calldata/request hash/signed quote/config before minting
  a sealed scope token. Direct targets require attempted/known submission;
  managed targets require their own durable relay handoff and stored call.
- A retired pool may recover only that same owned endpoint/client/context/token;
  it never discovers a replacement or reads a new nonce. First sends retain
  normal reader/token/receipt checks. Ordinary wallet export is not relay authority.
- Focused regression passed: retired unknown-ID retry sends identical parameters,
  known-ID retry issues status only, and an armed panic-on-network-read hook is
  never called. Fresh/wallet-exported, foreign endpoint and changed packet cases
  reject without transport. Prior manual export/typed refusal regression passed.
- Added permit-callback selection-marker regression: observed RED with invalid
  saved selection metadata, then GREEN after clearing optimization selection
  metadata on final permit/scheduled/noneligible candidates. Actual nonce and
  existing fallback loops/checks remain unchanged.
- Parent approved the controlled loopback comparison for this turn, explicitly
  excluding a new public-network/App/device comparison. Parent GO authorizes
  sequential 20 ms before/after groups after final heavy checks finish.

## Final completed evidence

- Final driver `23affb4a54c7397751e6d2853e40581ca6c053d0b4b8b602b7c026823f7b376c`
  is identical in the independently built frozen-before and after executables.
  Both normal flows assert real current payer nonces 7/14 and byte-identical
  first journal after the second operation. Final zero-delay runs both passed.
- Full workspace command exited 0: 99 groups, 507 passed, 0 failed, 17 ignored.
  Additional test-only unified managed long-Shield HTTP recovery regression
  passed focused (one test, loss and prior-wallet-export scenarios). No production
  changes followed the full workspace compile. fmt/clippy/boundaries/English exit 0.
- Root TS handoff completed before the final Rust timing groups. No own cargo,
  Clippy, compilation or heavy tests overlapped measurement. Other applications'
  background activity was not controlled or terminated.
- Final 20 ms actual-HTTP runs: before then after, each 3 fixtures × 2 flows,
  both exit 0. Before initialization 12 HTTP and each transaction 71; after
  initialization 10 and each transaction 7. Group totals 462→72 HTTP. Both groups
  deny six writes before HTTP; actual write HTTP is zero.
- First medians 3269.029376→1692.471874 ms (48.23% lower); repeat medians
  3284.158583→1714.746334 ms (47.79% lower). Including startup once, first median
  3584.674584→1953.446582 ms. Complete two-flow fixture median
  6865.256710→3668.192916 ms. Per-transaction HTTP drops 90.14%; initialization-
  charged fixture HTTP drops 84.42%. Matched debug crypto work remains included.
- Full sample arrays/ranges and source hashes are in comparison.json and the
  separate before.json/after.json artifacts; exact build/run commands, compiler,
  executable paths and binary SHA-256 hashes are in benchmark-metadata.json.
  Metadata status is completed. Old zero-delay/prior-driver artifacts are kept
  separately from the final 20 ms samples.
- These are controlled loopback measurements, not new public network/App/device
  timings. Historical App/native data is explicitly separate. No commits,
  rebases, merges, releases, funded keys, real-chain writes, or other worktree
  source edits were performed.
