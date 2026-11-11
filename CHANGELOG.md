# Changelog

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
