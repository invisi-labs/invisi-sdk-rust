# Changelog

## Unreleased

- Add the optional `invisi-sdk-payment-router` crate for detached Router-funded Note preparation, native ETH exact-output V3 and registry-verified 0x quotes, canonical transaction construction and full-call simulation. Adds detached `PreparedTransaction::export_transaction` with existing phase/proof bindings so atomic callers need no pre-swap token balance or allowance. Includes explicit async RPC and 0x HTTP transports, deployment and reorg authentication, and cross-language parity fixtures.


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
