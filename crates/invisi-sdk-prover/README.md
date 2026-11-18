# invisi-sdk-prover

Version `1.2.6`. Local witness construction, authenticated proving artifacts, prove/verify and recursive aggregation. Depends on primitives and public protocol contracts.

See the [workspace documentation](https://github.com/invisi-labs/invisi-sdk-rust) for usage. Licensed under Apache-2.0.

## Contributing

See the [contribution guidelines](../../README.md#contributing) for issues, pull requests, validation, and handling sensitive material.

Public circuit resources are loaded lazily by `ResourceProvider` and `NativeProver::new`.
The generated `assets/prover/resource-release.json` pins the independent Core release
index, Noir 1.0.0, and BB 6.0.0. Resources are size/hash checked on each cache read;
misses download only public artifacts, with bounded timeout and atomic publication.
Witnesses never enter the resource transport. `ResourceOptions` supports an explicit
HTTPS/object-directory source, cache directory, published object directory (or a logical asset layout), and offline mode.
Existing `NativeProver` struct literals and `DirectoryAssets` remain supported.

The default disk cache is the system cache directory plus `invisi/prover-assets`:
`~/Library/Caches/invisi/prover-assets` on macOS,
`${XDG_CACHE_HOME:-~/.cache}/invisi/prover-assets` on Linux, and
`%LOCALAPPDATA%/invisi/prover-assets` on Windows.
An explicit cache option overrides `INVISI_PROVER_CACHE_DIR`, which overrides this default.
Index files use `<index-sha256>.index.json`; objects use `<sha256>.json` or `<sha256>.vk`,
so Node, Go and Rust can share the same verified disk cache. Offline mode defaults to false.
