# Changelog

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
