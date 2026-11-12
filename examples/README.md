# Rust scenarios

Each file has its own `main` and shows the calls in execution order. There is no shared scenario runner. All SDK imports use the public `invisi_sdk` facade; applications may instead depend on individual workspace crates.

Run from the repository root:

```sh
cargo run -p invisi-sdk-examples --bin note-output
cargo run -p invisi-sdk-examples --bin transfer -- --execute
cargo run -p invisi-sdk-examples --features sqlite --bin restore-session -- --execute
```

`note-output` constructs an encrypted Note offline using public receiving material only. Every other binary returns before opening configuration, files, databases, keys or network unless `--execute` is present. Examples 01–06 export unsigned EVM transactions for the application to review, sign and submit. Broadcaster and independent Source proof flows live in `07-broadcaster`.

## Files

| Directory | Binary | Flow |
|---|---|---|
| `01-address-registry` | `register` | Pinned registry read and direct-owner unsigned registration |
| `02-note` | `note-output`, `shield` | Offline encrypted Note construction; public ERC20 funding into an encrypted Note |
| `03-note` | `transfer`, `withdraw`, `aggregate` | Located Note inputs, external wallet authorization, proving, unsigned calldata |
| `04-credit` | `create-credit`, `draw-credit`, `update-credit`, `revoke-credit` | Available spending authority, distinct payer draws, policy updates, public EVM revocation |
| `05-session` | `restore-session`, `send-session`, `create-credit-session`, `draw-credit-session`, `update-credit-session`, `revoke-credit-session` | Encrypted SQLite inventory, application decryption callbacks, managed operations and recovery |
| `06-disclosure` | `disclose-note`, `disclose-credit` | Explicit financial opening exports and independent commitment checks |

## Public Wallet initialization

Use `Wallet::from_address(receiving_address)` with a complete public receiving address. The SDK retains only public owner and receiving material. The application owns account selection, delivery decryption and EVM signing.

Private Note/Credit authorization uses ordinary EIP-712 signing:

```rust
let estimate = prepared.estimate_gas()?; // Local receipt median or calibrated estimate for direct execution.
let request = prepared.export_wallet_authorization()?;
// Your EIP-712 wallet signs request.typed_data; request.digest is the same signing hash.
let signature = invisi_sdk_examples::sign_authorization(&request)?;
let authorized = prepared.with_wallet_signature(&signature)?;
```

`support/discovery.rs::sign_authorization` is application example code. It reads `OWNER_PRIVATE_KEY` and uses k256 to produce a standard 65-byte EVM signature. The SDK receives the signature, recovers the signer and checks the owner and frozen statement. Production applications can replace this helper with their wallet provider. Transaction signing remains a separate application step.

`support/discovery.rs::AppDecryptor` is an explicit integration placeholder. Implement its `decrypt_note` and `decrypt_credit` callbacks using your application's delivery decryption; return `None` for a different recipient and an error on decryption failure. The SDK receives plaintext bytes and independently authenticates the financial opening against the chain. The placeholder returns an integration error if a candidate needs decryption; examples using discovery require this adapter to be implemented.

## Public live configuration

Set these for transaction scenarios:

```sh
export ETH_RPC_URL='https://your-ethereum-rpc.example'
export PROTOCOL_RPC_URL='https://your-index.example/v1'
export DEPLOYMENT_JSON='/absolute/path/to/deployment.json'
export WALLET_ADDRESS='your complete 0i receiving address'
export TOKEN_ADDRESS='0x...'
export CALLER_ADDRESS='0x...'
export DEADLINE='explicit future Unix seconds'
export OWNER_PRIVATE_KEY='0x...application example signing key...'
```

`DEPLOYMENT_JSON` contains independently trusted deployment pins, not a response accepted blindly from the indexed service:

```json
{
  "chainId": "31337",
  "protocol": {
    "address": "0x1111111111111111111111111111111111111111",
    "runtimeCodeHash": "0x...32-byte-runtime-code-keccak...",
    "fromBlock": 1
  }
}
```

Replace the displayed addresses and hash with the actual deployment. Registration additionally requires a `registry` entry with the same `address`, `runtimeCodeHash`, `fromBlock` fields. Session examples also set `PROTOCOL_RPC_URL` to the indexed service's `/v1` URL. SDK preparation checks the Ethereum chain and pinned protocol runtime.

Use complete receiving addresses for `WALLET_ADDRESS`, `RECIPIENT_ADDRESS` and `SPENDER_ADDRESS` wherever encrypted delivery or change is needed. `OWNER_PRIVATE_KEY` is used only by the application example signer for private Note/Credit authorization; it must match the selected wallet owner. Do not send account keys to the SDK.

Proving scenarios require real matching tools and pinned release assets:

```sh
export BB_BINARY='/path/to/bb-6.0.0'
export NOIR_EXECUTOR='/path/to/noir-1.0.0-compatible-executor'
export PROVER_ASSETS='/path/to/authenticated/circuits'
```

The executor implements the documented `NoirCli` interface (`--artifact-path`, `--prover-file`, `--output-dir`, `--witness-name`). Circuit files are named `<circuit>.json`; verification keys are `<circuit>.evm.vk` and, for aggregation members, `<circuit>.noir-recursive.vk`. The SDK checks their authenticated release identities and independently verifies generated proofs.

## Note inputs and amounts

Set `AMOUNT` to integer token base units, `RECIPIENT_ADDRESS` for transfers, and `WITHDRAWAL_ADDRESS` for withdrawals. `shield` uses direct funding, so `CALLER_ADDRESS` must equal the public wallet owner and the payer must already have sufficient ERC20 balance and allowance to the protocol. Approval requirements are explicit SDK data; no scenario submits an approval implicitly.

Transfer, withdrawal, aggregate, draw, update and disclosure examples discover earlier deposits and grants through `PROTOCOL_RPC_URL`. Discovery starts at the trusted deployment block by default; optional `FROM_BLOCK` and `TO_BLOCK` bound the range. Each main calls `pending.decrypt(&AppDecryptor)` and applies canonical receipt, opening, membership, spent and revocation checks before selecting inputs. No private input or Merkle-path files are required. Decryption errors leave the saved checkpoint unchanged.

Transfers and withdrawals choose enough available Notes for `AMOUNT`. `aggregate` selects `AGGREGATE_MEMBERS` Notes (default two; supported values one, two or five), authorizes each member externally and proves the aggregate. Run the earlier shield/deposit scenario enough times to supply those Notes and wait for indexing.

## Credit inputs

Creation requires `SPENDER_ADDRESS`, `EXPIRES_AT`, and `AVAILABLE_CREDIT`. The latter is remaining spending authority, not held funds or a lifetime limit. `UNLIMITED=true` requires `AVAILABLE_CREDIT=0`. This example disables single/day/month limits explicitly by using the default zero policy; edit that visible policy construction to set limits. Allocation, nonce, independent shared key and both role deliveries are prepared in the file.

Draws use `AMOUNT` and automatically select spender-role grants while respecting available authority, expiry and single/day/month usage limits. Different owners remain distinct payer receipts. Updates select an unconsumed, unrevoked owner-role grant using `CREDIT_INDEX` (default zero). Both discover the grants created by the earlier creation example; no Credit-state input files are required.

`CREDIT_CHANGES_JSON` is a current update object, for example:

```json
{"increaseAvailableCredit":"100","singleLimit":"10","dailyLimit":"40","monthlyLimit":"60","expiry":"2050000000"}
```

Choose a future expiry and deadline for your chain. Increases and decreases are mutually exclusive; updates preserve gross usage. Creation, update and revocation fees in these examples are zero. A draw also uses zero fee, so its ordinary Note receives the full debit.

Revocation uses `GRANT_SHARD` and `GRANT_SLOT`. Direct calls require the owner as `CALLER_ADDRESS`. For another caller, the example exports public EIP-712 data and signs it with the application `OWNER_PRIVATE_KEY` helper. It verifies the signature through the configured chain before exporting calldata. This is distinct from private circuit wallet authorization.

## Persistent sessions

Enable `--features sqlite`, then configure:

```sh
export PROTOCOL_RPC_URL='https://your-index.example/v1'
export WALLET_DB='/absolute/path/to/wallet.sqlite'
export WALLET_STORE_KEY_FILE='/absolute/path/to/host-storage-key.bin'
```

The key file contains exactly 32 raw bytes managed by the host. It encrypts financial inventory records and is **not** an EVM or native wallet private key. Keep the database and its key outside the repository.

Run `restore-session` to discover candidates, authenticate canonical receipts and request native viewing. If there are viewing requests, paste the native response array directly; each member carries `version`, `id`, `ownerAddress`, `method`, and exactly one `result` or `error: {code}`. Only `WALLET_NOT_RECIPIENT` skips a candidate; cancellation, locked accounts and other errors abort without advancing state. The SDK validates accepted financial openings and commitments before updating inventory.

Run `send-session` with `AMOUNT`, `RECIPIENT_ADDRESS` and `DEADLINE` to refresh earlier deposits automatically and select unreserved Notes and prepare a managed transfer. Keep the printed operation ID. Set `OPERATION_ID` on a later run to resume that exact operation with saved proof verification. Once your host has signed and submitted the exported transaction, set `HOST_TRANSACTION_HASH` on a resumed run to track and reconcile the explicit hash. The example never interprets exporting calldata as chain confirmation.

The managed Credit binaries use the same encrypted store and explicit application decryption callbacks. They retain operation IDs, reserve inputs, export unsigned host transactions, and support `OPERATION_ID` + `HOST_TRANSACTION_HASH` recovery and canonical reconciliation just like `send-session`. Use a separate database per owner/spender wallet, with the same wallet and storage key when resuming. The examples reject saved operations of a different kind. Resume with the binary that created the operation; do not set `OPERATION_ID` for a new operation.

```sh
# Owner grants authority; spender draws it into a recipient Note.
cargo run -p invisi-sdk-examples --features sqlite --bin create-credit-session -- --execute
cargo run -p invisi-sdk-examples --features sqlite --bin draw-credit-session -- --execute
cargo run -p invisi-sdk-examples --features sqlite --bin update-credit-session -- --execute
cargo run -p invisi-sdk-examples --features sqlite --bin revoke-credit-session -- --execute
```

| Managed action | Additional configuration | Inventory selection |
|---|---|---|
| Create | `SPENDER_ADDRESS`, `EXPIRES_AT`, `AVAILABLE_CREDIT`, optional `UNLIMITED` | Fresh allocated grant; no input grant |
| Draw | `DEBIT_PER_GRANT`, `RECIPIENT_ADDRESS` | Two current unreserved spender grants from distinct owners, each covering the debit within expiry and policy limits |
| Update | `INCREASE_AVAILABLE_CREDIT`, optional `CREDIT_INDEX` (default zero) | Current unreserved owner grant; visible typed changes increase remaining authority |
| Revoke | Optional `CREDIT_INDEX` (default zero) | Current unreserved owner grant; derives public shard/slot from inventory |

The managed draw is a merchant batching example: run creation from two different owner wallets granting the same spender, then switch to that spender’s wallet/database. `DEBIT_PER_GRANT` is the amount charged to **each** of two payers; one recipient Note receives `2 × DEBIT_PER_GRANT` with zero fee. Selection checks current usage limits and expiry through `DEADLINE`; SDK preparation rechecks the selected grants. The stateless draw continues to interpret `AMOUNT` as its total.

All actions also use `TOKEN_ADDRESS`, `CALLER_ADDRESS` and `DEADLINE`. Create, draw and update need the prover configuration; revoke needs no prover and requests an owner EVM signature only for a relay caller. The update main constructs `CreditUpdateChanges` directly: edit that visible struct for policy/expiry changes. No plaintext grant, Merkle-path or update-input file is needed for these managed scenarios. The stateless `04-credit` flows remain available independently.

## Disclosure

`disclose-note` automatically discovers earlier unspent Notes and selects `NOTE_INDEX` (default zero); `disclose-credit` discovers owner-role grants and selects `CREDIT_INDEX` (default zero). Both require the normal public discovery configuration and `--execute` because their output intentionally reveals a financial opening. Credit opening export contains the shared-key hash, not the shared key. Payload-key disclosure is a separate explicit API and is not substituted for these opening examples.

## Checks

```sh
cargo check -p invisi-sdk-examples --all-targets --all-features
cargo run -p invisi-sdk-examples --bin note-output
```

Run the other binaries without `--execute` to inspect their guard behavior without configuring services.

## Broadcaster and independent Source proofs

See `07-broadcaster` for fee-frozen prepared quotation, ready transaction proving and broadcaster submission. Example 02 takes `PREPARED_SNAPSHOT` plus local prover/Source configuration, prints the complete public packet and submits it before the transaction. Example 03 reads only `SOURCE_PROOF_JSON` plus public pins in flat environment settings to validate and resubmit before or after chain confirmation; it needs no private wallet state, proof generator or transaction hash. Ordinary examples 01–06 have no optional Broadcaster mode or Source availability requirement.

Broadcaster uses separate `estimateQuote` and `getQuote` requests. Its server assigns submission IDs; applications retain those IDs and the exact final request. Source uses its official default endpoint or an explicitly configured trusted endpoint, with bounded checkpoint replay and locally verified proof generation. No policy ID or mandatory transaction hash is part of the public Source packet. See [PROVENANCE.md](../PROVENANCE.md) for the full contract and assets.

Example 01 uses `BROADCASTER_ENDPOINT`, `BROADCASTER_QUOTE_SIGNER`, `BROADCASTER_FEE_RECIPIENT` and a positive `MAX_FEE_AMOUNT`. Source trust uses `SOURCE_CHAIN_ID`, `SOURCE_PROTOCOL_ADDRESS`, `SOURCE_GENERATION`, `SOURCE_PROVIDER_ID`, `SOURCE_SIGNING_KEY_ID` and `SOURCE_SIGNING_PUBLIC_KEY`; `SOURCE_ENDPOINT` defaults to the official service. Local Source proving additionally requires `SOURCE_ASSET_ROOT`, `BB_BINARY` and `NOIR_EXECUTOR`. Example 03 takes the public packet in `SOURCE_PROOF_JSON`, without opening those proving assets. Examples print outputs and never create record/configuration files.

The SQLite `restore-session` example uses `RecordWalletStore` for independently encrypted private rows and `SQLiteRecords::open_public` for a deployment-wide canonical cache in a separate table of the same database. `session.scan` recovers the current head first, then historical gaps; reuse the public store for other accounts while providing separate private account storage keys. `AppDecryptor` is a host integration stub: implement complete-context native detection and explicit nonrecipient/authentication-ambiguity/error outcomes before using `--execute`. Shared history never requires exporting detection or viewing keys.

Credit revocation uses `OWNER_ADDRESS` (an EVM `0x` address) independently of `WALLET_ADDRESS`.

### Public Wallet addresses

`Wallet::from_address` accepts only complete `0i` receiving addresses. Use `Wallet::from_keys(owner_address, receiving_keys)` when the public materials are separate. `address()` encodes a complete `0i` address without RPC resolution. EVM owners are independent addresses; owner-only operations do not need a Wallet.

```rust,ignore
let request = sdk::prepare_wallet_request(owner_address, "public", "wallet.public", json!({}))?;
let response = native_host.execute(&request)?;
let wallet = Wallet::from_response(&request, &response)?;
let receiving_address = wallet.address()?;
assert_eq!(Wallet::from_address(&receiving_address)?, wallet);
let revocation = invisi.prepare_revoke_credit(owner_address, token, shard, slot, deadline, Fee::default())?;
```

`transaction-confirmation` (`07-broadcaster/confirmation.rs`) reads `CHAIN_RPC_URL` and a transaction hash argument to report independently authenticated native inclusion/finality. It performs no submission, resend, or wallet mutation.
