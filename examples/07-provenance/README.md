# Normal private transfer with Provenance

The first flat example follows the normal SDK flow: discover and decrypt earlier deposits through the existing native host boundary, prepare a private transfer, call `with_broadcaster`, approve the wallet request in the host, prove the main transaction locally and call `submit_broadcaster`. Source paths, source capacity, source witness/proof, preflight tracking and the policy-bound quote are assembled by the SDK before host approval. No prepared JSON, private opening or hand-built sidecar is an example input.

Copy `config.example.json` outside the checkout and replace its public deployment/policy/provider/signing-key pins from trusted operator configuration. Synchronize local source assets with `python3 scripts/sync-provenance.py ../invisi-protocol`; `assetRoot` points to `.cache/provenance`. Configure the existing main proving release with `PROVER_ASSETS`, and pinned executables with `NOIR_EXECUTOR` and `BB_BINARY`. The local source adapter authenticates artifacts/VKs and independently verifies its proof. No remote prover receives a witness.

Set `PROVENANCE_CONFIG`, `DEPLOYMENT_JSON`, `PROTOCOL_RPC_URL`, `WALLET_ADDRESS` (resolved receiving keys are required for change), `RECIPIENT_ADDRESS`, `TOKEN_ADDRESS`, `AMOUNT` (raw integer units), `DEADLINE` (Unix seconds), `BROADCAST_ID` and a new `PROVENANCE_RECORD` path. Discovery and approval requests are printed as native-host request arrays; paste the corresponding response arrays when prompted. This is the existing explicit host boundary, not a new wallet signer. The example selects discovered unspent Notes locally; ensure sufficient balance for the amount and converged relay fee.

```sh
cargo run -p invisi-sdk-examples --bin provenance-prove-and-broadcast -- --execute
# Add --submit to explicitly send through the configured relay.
cargo run -p invisi-sdk-examples --bin provenance-confirm-source -- --execute
```

Without `--execute`, both programs exit before accessing files, keys or the network. The first exclusively creates and syncs a public source/quote/tracking/calldata record before possible relay submission. It keeps all raw openings in local memory. For durable private inventory and reservations, use the existing encrypted `WalletSession` store and its `Operation::with_broadcaster`/`submit_broadcaster` methods; this example does not wire the App.

After submission set `TRANSACTION_HASH` to the actual mined transaction. The second example authenticates the exact calldata, successful receipt and canonical block through the configured primary, waits for the retained automatic tracking ID, then queries the exact operation's recognition. Preflight allow and proof validity alone are not operation recognition. Receivers separately authenticate signed source roots and their Note membership.

Keep the same record/hash/IDs after provider outages or uncertain relay responses. Generation changes require primary reconciliation and explicit local reproof; neither example changes or resends the transaction. Normal confirmation does not call `submitProof`. Explicit self-broadcast/reproof recovery remains available through `prepare_direct` or direct source submission; missing tracking never chooses that fallback automatically. Recovery base keys are 1–63 printable ASCII bytes and cannot start with reserved `internal/`.
