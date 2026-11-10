# Changelog

## 1.1.8

- Align all eight public Rust SDK crates and their registry dependency requirements
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
