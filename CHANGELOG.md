# Changelog

## 1.3.4

- Recover confirmed tracked Source proofs after a native deadline through historical proof delivery, while retaining strict initial evaluation and authenticated mined-locator checks. Persist accepted replacement tracking before polling so interruptions resume without reproof or resubmission.
- Accept the zero native-token address in indexed Credit status queries, including fee-free native Credit revocation, while retaining nonzero owner/grant ID and canonical block validation.
- Initialize the host Provenance capability from authenticated signed Broadcaster quote requirements when no legacy status hint is present. Validate its deployment and mode before freezing evidence; malformed signatures and mismatched capabilities remain rejected.
- Add Credit recovery coverage across wallet, chain and Core deployment scopes in shared stores. Cover create/update/draw/revoke resume isolation, owner/spender reservations, stale-handle abandonment and canonical successor recovery without decrypting replacement envelopes.
- Align all nine public crates, exact sibling dependencies, lockfile, private examples and release checks at 1.3.4. The examples package remains private at 0.1.0; the public C ABI, contract bindings and proving asset pins are unchanged.

## 1.3.3

### Core and Credit protocol migration

- Replace Credit revocation shard/slot references with a positive uint128 `grant_id` across models, commitments, wallet authorization, delivery/disclosure encodings, IPP terms, contract calls/events, RPC discovery, managed operations and recovery. `CreateCreditRequest::grant_id` accepts an explicit ID or selects one once using OS randomness; revocation now takes that ID. Creation, fallback and quote retries preserve the selected ID and shared key.
- Refresh Core/Factory compiler ABIs after address-screening removal and the grant-ID change, together with circuit identities, witness layouts and cross-language Note/Credit, receipt, authorization and gas parity fixtures. Core construction takes protocol parameters and the address registry; Factory deployment/address prediction no longer takes a screener.
- **Migration:** rebuild all Rust consumers and update shard/slot fields, Credit status adapters and generated ABI call/tuple types. Current Credit requires matching Core deployment, RPC/Broadcaster and proving assets; previous Credit statements and historical circuit catalogs cannot prove current statements. Credit proving uses manifest 8 / format 9 while Core protocol version remains 1. Gas previews retain their recorded historical measurement identity; this grant-ID release has not been remeasured.

### Canonical Payment Router and quotes before proving

- Extend the optional `invisi-sdk-payment-router` crate with unversioned `PaymentRouter`/`PaymentRouterAccount` compiler bindings and four modes: self-submitted native, self-submitted ERC20, relayed ERC20 and EIP-7702 sponsored native. Add intent/call builders, EIP-712 and ERC-2612 digests, approvals, same-token/wrap, V3 and 0x exact-buy routes, plus shared contract/Go parity fixtures. Existing native-only helpers remain legacy APIs.
- Add built-in canonical native/ERC20 0x HTTP quotes with Router taker/recipient binding, current-Settler refresh, cancellation and normalized payloads. Validate deployment/runtime, account state and live counters, including a block-pinned EOA authorization nonce even when an account is already delegated.
- Add `RouterRelayClient` draft estimation and quotation before Core proving or wallet signatures. Bind quotes to `payment-router-intent-v1`: completing actual proofs, hashes and signatures preserves identity, while changed amounts, fees, routes, deadlines, nonces or authorization metadata require a fresh quote. Retain raw `envelope_hash` for signed-envelope identity. Final builders require the actual proof; submission validates and estimates/simulates the complete final call.
- Add conservative `payment-router-gas-v1` draft previews with `source="model"` over the recorded Core baseline and shared gas/hash fixtures. Opaque 0x routes require a trusted service-policy gas budget. Broadcaster pricing uses current chain fees within its operational maximum; the preview is not a receipt measurement or final gas limit. Bound draft fee convergence by wallet `maxFeeAmount` without rebuilding downward after authorization.
- Add compile-checked host recipes for all four modes, token 0x, Router output recognition and later private Note spending. These binaries print integration guidance; live wallet signing, transaction sending, RPC/prover configuration, simulation and durable reconciliation are injected by the host. Recognition describes actual principal/fund flows; a successful receipt or prior recognition query alone is not Provenance membership evidence. Private spending replays recognized inputs, verifies certificates/anchors, proves locally and checks service evaluation/tracking. No new production Provenance API or blanket recognition guarantee is introduced. Router relay has no scheduling or aggregation support.

### Authenticated proving resources

- Use independently published Core and Provenance catalogs at `https://assets.invisipay.fi/prover/sets/<index>/`, with isolated capability namespaces, authenticated content-addressed cache, explicit directory/offline support and no silent downgrade to legacy resources. Core is `invisi-core` commit `4940be21de91689b59ba1a2fe46945f767c3a34c`, index `85a5d1dffe40fc965ab4345a28b632f463c3ad861c44d5845850fbc7447fd8f6`; Provenance is `invisi-periphery` commit `33ba458ea11e07da282c21b8a2b091a0be1ebd01`, index `8d5a3e60e3e5cbe315150511207d7aff67f4e2924148d396b67d82017ecd1f1c`. Explicit historical legacy pins remain fixed.
- Load recursive verification keys on demand through configured prover assets. Authenticate binary SHA-256 and canonical BN254 fields, then recompute the pinned Poseidon commitment before dedicated or mixed aggregation. Bundle trust hashes/commitments rather than runtime key words; retain member and outer proof verification and offline/cache/directory policy. Authenticate exported VK JSON against its binary before synchronization, with producer regression tests in CI. Heavy proving resources remain external.

### Verified history and wallet refresh

- Add bounded, correlated JSON-RPC batches and validated trusted historical `invisi_getBlockHeaders` ranges, chunked at 256 blocks. Fall back to live batches only for explicit unsupported/unavailable historical capability errors. Reject incomplete fork-field prefixes and authenticate complete headers through `slotNumber` while preserving canonical/reorg checks and pinned Alloy versions.
- Reuse public-history page references and verified receipt evidence within the captured scan, avoid redundant header reads and fence the history generation before returning results. Preserve causal Credit replay and reject stale prior private observations, including their canonical/finality anchors, before an atomic refresh commit.
- Add ordered `get_memberships` batches of at most 256 inputs, sharing authenticated status/root evidence while validating every path and fencing indexed/canonical anchors again before return. Preparation batches highest-leaf leaders and followers against consistent roots. `SessionSource::memberships` retains a sequential fallback.
- Add opt-in `RefreshBehavior { inventory_only: true }`; default refresh still preloads preparation material. Bound independent refresh reads to four workers and deduplicate exact nullifier/revocation queries within one block/hash. Both modes check every record, retain cancellation/revision protection and discard failed updates. Inventory-only drops an older preparation snapshot and aligns selected inputs when later preparing online. Request-count fixtures document savings without claiming a production wall-time improvement; standalone benchmark sources/reports are excluded from the SDK tree.

### Credit submission and recovery boundaries

- Freeze UTC day/month for Credit draws and creation with an initial payment, then validate fresh canonical chain time before first submission, including after relay preflight. A rollover yields `CREDIT_PERIOD_CHANGED` / `InvisiErrorCode::CreditPeriodChanged` and requires new authorization and proof. Deadline extension and cached/offline construction do not extend the proof period. Scheduled execution must fit within the frozen UTC day; contract execution-time checks remain authoritative.
- Preserve optional Broadcaster `reason_code`, `publish_after` and `execute_before`. A first structured refusal is known unsent only for matching code/reason pairs `-32024/CREDIT_PERIOD_CHANGED`, `-32025/INSUFFICIENT_EXECUTION_SLACK` or `-32026/CREDIT_PERIOD_ENDING`. Persist that state in managed journals and block unchanged resubmission; refresh or safely abandon it before obtaining a new quote, authorization and proof. Rebuilding initial-payment creation must preserve the original grant ID.
- Keep exact-request reconciliation and reservations after an uncertain earlier attempt, ordinary transport failure or malformed/mismatched refusal. A missing transaction hash never permits rebuilding. Detached callers retain their handle and provide durable recovery storage.

### Release cohort and validation

- Align all nine public crates, exact sibling dependencies, lockfile, examples and release checks at 1.3.3. The examples package remains private at 0.1.0; public C ABI exports are unchanged.
- Keep offline fixtures, model/parity checks and compile-checked host recipes distinct from opt-in native Noir/BB proofs, configured live chain/relay integration and platform-specific host behavior. Release CI verifies workspace tests, formatting/clippy, native exports and all nine isolated package archives before publication.

## 1.3.2

- Add the optional `invisi-sdk-payment-router` crate for detached Router-funded Note preparation, native ETH exact-output V3 and registry-verified 0x quotes, canonical transaction construction and full-call simulation. Adds detached `PreparedTransaction::export_transaction` with existing phase/proof bindings so atomic callers need no pre-swap token balance or allowance. Includes explicit async RPC and 0x HTTP transports, deployment and reorg authentication, and cross-language parity fixtures.
- Align all nine public crates and exact sibling dependencies at 1.3.2; retain the private examples package with the same SDK cohort.

## 1.3.1

- Accept unified CreditDraw events in indexed Credit RPC responses, including post-debit state deliveries.
- Preserve canonical block, range, membership, duplicate and ciphertext checks; restore automatic IPP Credit reconciliation.

## 1.3.0

- Support optional owner-only Credit initial payments, post-debit Credit state, merchant net Notes, gross funding checks and UTC-period validation.
- Align contract bindings, unified Note operation events and CreditDraw/CreditStateTransition discovery and recovery with the redeployed Core contracts.
- Recompute operation IDs and validate physical insertions and aggregate membership against shared real-receipt fixtures.
- Add independently pinned lazy resources and witness metadata for the 18-input combined circuit without bundling large assets.
- Refresh measured Gas models and TS parity vectors; expose uncovered paths explicitly.
- Extend IPP initial-payment terms and receipts; remove the obsolete Invisi action field.
- Prepare the complete SDK module cohort at 1.3.0; no registry publication or contract deployment is performed.

- Align Alloy core types and ABI bindings to 1.5.7 and consensus/EIP decoding to 1.7.3, matching the mobile App. Public Rust types and generated return types change; consumers must rebuild against the aligned dependencies.
- Preserve strict call, return and event ABI validation while adopting the Alloy 1 decoding APIs.


## 1.2.9

- Validate Provenance certificate anchors without requiring synthetic headers.

## 1.2.8

- Add native receiving-key registration and recovery preparation, including registration state queries and externally authorized calls.
- Read the registry nonce for unregistered receiving addresses so initial registration uses the current on-chain nonce.

## 1.2.7

- Resolve the host-provided Provenance capabilities throughout session proof recovery.

## 1.2.6

- Update GitHub repository and release references to the `invisi-labs` organization.

## 1.2.5

- Restore required non-semantic compiler metadata for official Noir CLI execution of stripped resources without changing pinned artifact or verification-key identities.

- Align the eight-crate cohort with independent IPP support and Invisi Core interfaces.
- Load pinned public proving resources lazily with verified, shared disk caches; retain local directory and offline circuit support.


## 1.2.4

- Refresh receipt-calibrated gas estimates for optimized Protocol contracts and validate authorization and unsigned funding boundaries.
- Add trusted RPC Note confirmation and collection with broadcaster fees deducted from the payout.
- Support scheduled broadcaster submissions and cancellation; align quote lifecycle, Credit proof validation and managed recovery.
- Bound parallel public-history header reads during wallet synchronization.
- Preserve Protocol ABI and authenticated circuit formats. Gas estimates remain distinct from transaction gas limits.

## 1.2.3

- Align transaction preparation, public history and Provenance interfaces with the current protocol contracts.
- Include complete Source runtime artifacts in distributable crates and preserve isolated archive verification.

## 1.2.2

Rust skips version 1.2.1; this release includes all changes since 1.2.0.

- Require complete public material for `Wallet`, reject owner-only `0x` construction, and encode `0i` addresses on demand; expose independent owner-address request/response and revocation paths while retaining standalone short receiving addresses.

- Make `estimate_gas()` a local prepared-plan benchmark lookup for Note, all Credit forms and managed operations before authorization or proving; return explicit unsupported-shape reasons and retain measurement provenance across SDK/circuit versions.
- Remove public raw gas reference getters and SDK RPC gas simulation; applications and Broadcasters own final simulation and current prices.

- Share bounded canonical public history across accounts and persist independent private scan coverage.
- Prioritize recent assets, recover historical gaps and replay causal Credit state with durable checkpoints.
- Expose scan completeness and known spendable funds separately; support offline recovery from validated public proofs.
- Preserve ambiguous delivery candidates, carry complete native detection/decryption contexts, and page authenticated encrypted wallet archives.

- Align current protocol/RPC contracts and remove delegated RPC detection; applications supply native detection and decryption context.
- Follow signed broadcaster execution quotes, including aggregate member relay and quote-bound fees.

## 1.2.0

- Establish six common modules: primitives, protocol, prover, RPC, stateless SDK, and Session; retain FFI as a separate adapter.
- Rename the core crate to `invisi-sdk-primitives` and merge runtime into the root SDK.
- Separate Source witness/proving capabilities from public protocol types, digests and gas references.

- Align all seven public Rust SDK crates and their registry dependency requirements
  with the shared SDK release version.
- Make crate archives self-contained with protocol ABIs, required runtime assets,
  provenance manifests, public verification data, and package-local test fixtures.
- Add isolated local registry-source packaging, verification, and unpacked-archive
  test checks to the release workflow.
- Keep the examples crate private and preserve the existing native C ABI version.
- Reuse cached Provenance packets locally, recover and regenerate evidence from
  original confirmed payments, and retain existing evidence if fresh proving fails.
- Converge broadcaster fees against actual calldata, estimate final Note/Credit
  calls through the chain RPC, and discover token-compatible broadcasters.
