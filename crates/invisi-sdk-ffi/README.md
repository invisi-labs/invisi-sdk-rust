# invisi-sdk-ffi

Version `1.2.2`. Thin native C ABI adapter over primitives. Hosts retain key custody; this crate adds no wallet business rules.

See the [workspace documentation](https://github.com/invisi-lab/invisi-sdk-rust) for usage. Licensed under Apache-2.0.

Shared-history integrations keep native detection/viewing keys inside the application. The Rust session's `DeliveryDecryptor::detect` receives complete clue/owner/chain/protocol/token/commitment/role context; host adapters bind this context to the existing clue-only `wallet.detect` wire call. `WALLET_AUTHENTICATION_FAILED` denotes ambiguous AEAD failure and maps to the session's retryable `DecryptionOutcome::AuthenticationFailed`. Only explicit `WALLET_NOT_RECIPIENT` means skip. Locked/cancelled/expired/wrong-account and other errors abort a private scan page. The C ABI and account derivation are unchanged.
