# Rust scenarios

Each file has its own `main` and shows the calls in execution order. There is no shared scenario runner. All SDK imports use the public `invisi_sdk` facade; applications may instead depend on individual workspace crates.

Run from the repository root:

```sh
cargo run -p invisi-sdk-examples --bin note-output
cargo run -p invisi-sdk-examples --bin transfer -- --execute
cargo run -p invisi-sdk-examples --features sqlite --bin restore-session -- --execute
```

`note-output` constructs an encrypted Note offline using public receiving material only. Every other binary returns before reading environment configuration, opening files or databases, contacting RPC, or accessing keys unless `--execute` is present. The transaction examples export **unsigned** EVM transactions. Your host reviews, signs and submits them; the examples never broadcast automatically.

## Files

| Directory | Binary | Flow |
|---|---|---|
| `01-address-registry` | `register` | Pinned registry read and direct-owner unsigned registration |
| `02-note` | `note-output`, `shield` | Offline encrypted Note construction; public ERC20 funding into an encrypted Note |
| `03-note` | `transfer`, `withdraw`, `aggregate` | Located Note inputs, external wallet authorization, proving, unsigned calldata |
| `04-credit` | `create-credit`, `draw-credit`, `update-credit`, `revoke-credit` | Available spending authority, distinct payer draws, policy updates, public EVM revocation |
| `05-session` | `restore-session`, `send-session`, `create-credit-session`, `draw-credit-session`, `update-credit-session`, `revoke-credit-session` | Encrypted SQLite inventory, native viewing responses, managed operations and recovery |
| `06-disclosure` | `disclose-note`, `disclose-credit` | Explicit financial opening exports and independent commitment checks |

## Public Wallet initialization

Use `Wallet::from_address(receiving_address)` when the host already supplies a complete receiving address. Otherwise resolve the owner's public profile through the native host. The host owns account selection, unlock and keys; the SDK retains only public material.

```rust
use invisi_sdk::sdk::{Wallet, WalletResponse};
use serde_json::json;

let owner = Wallet::from_owner(owner_address)?;
let request = owner.prepare_request("public-profile", "wallet.public", json!({}))?;
let requests = [request];

// Send this JSON array through the application's native bridge and receive its response array.
let requests_json = serde_json::to_string(&requests)?;
let responses: Vec<WalletResponse> = serde_json::from_str(&responses_json)?;
owner.accept_batch(&requests, &responses)?;
let response = responses.iter()
    .find(|item| item.id == requests[0].id)
    .ok_or("missing public-profile response")?;
let wallet = Wallet::from_response(&requests[0], response)?;
println!("Receiving address: {}", wallet.address()?);
```

`owner_address` is the selected public EVM owner; `responses_json` is returned by your native bridge after executing `requests_json`. No private key crosses this boundary.

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

Use complete receiving addresses for `WALLET_ADDRESS`, `RECIPIENT_ADDRESS`, and `SPENDER_ADDRESS` wherever encrypted delivery or change is needed. No live scenario accepts an account private key. A printed wallet request array must be approved and executed by your own native host, which owns account selection, key custody and unlock. Paste its one-line JSON response array into the waiting program. Preparation remains alive while the host responds, so randomized outputs and their frozen authorization context remain unchanged.

Proving scenarios require real matching tools and pinned release assets:

```sh
export BB_BINARY='/path/to/bb-6.0.0'
export NOIR_EXECUTOR='/path/to/noir-1.0.0-compatible-executor'
export PROVER_ASSETS='/path/to/authenticated/circuits'
```

The executor implements the documented `NoirCli` interface (`--artifact-path`, `--prover-file`, `--output-dir`, `--witness-name`). Circuit files are named `<circuit>.json`; verification keys are `<circuit>.evm.vk` and, for aggregation members, `<circuit>.noir-recursive.vk`. The SDK checks their authenticated release identities and independently verifies generated proofs.

## Note inputs and amounts

Set `AMOUNT` to integer token base units, `RECIPIENT_ADDRESS` for transfers, and `WITHDRAWAL_ADDRESS` for withdrawals. `shield` uses direct funding, so `CALLER_ADDRESS` must equal the public wallet owner and the payer must already have sufficient ERC20 balance and allowance to the protocol. Approval requirements are explicit SDK data; no scenario submits an approval implicitly.

Transfer, withdrawal, aggregate, draw, update and disclosure examples automatically discover earlier deposits and grants through `PROTOCOL_RPC_URL`. Discovery starts at the trusted deployment block by default; optional `FROM_BLOCK` and `TO_BLOCK` bound the range. Each main prints a native viewing request array, reads the host response array, and applies canonical receipt, financial opening, membership, spent and revocation checks before selecting inputs. No private input or Merkle-path files are required. If a range exceeds native batch bounds, narrow it explicitly; no candidates are silently dropped.

Transfers and withdrawals choose enough available Notes for `AMOUNT`. `aggregate` selects `AGGREGATE_MEMBERS` Notes (default two; supported values one, two or five), authorizes each member externally and proves the aggregate. Run the earlier shield/deposit scenario enough times to supply those Notes and wait for indexing.

## Credit inputs

Creation requires `SPENDER_ADDRESS`, `EXPIRES_AT`, and `AVAILABLE_CREDIT`. The latter is remaining spending authority, not held funds or a lifetime limit. `UNLIMITED=true` requires `AVAILABLE_CREDIT=0`. This example disables single/day/month limits explicitly by using the default zero policy; edit that visible policy construction to set limits. Allocation, nonce, independent shared key and both role deliveries are prepared in the file.

Draws use `AMOUNT` and automatically select spender-role grants while respecting available authority, expiry and single/day/month usage limits. Different owners remain distinct payer receipts. Updates select an unconsumed, unrevoked owner-role grant using `CREDIT_INDEX` (default zero). Both discover the grants created by the earlier creation example; no Credit-state input files are required.

`CREDIT_CHANGES_JSON` is a current update object, for example:

```json
{"increaseAvailableCredit":"100","singleLimit":"10","dailyLimit":"40","monthlyLimit":"60","expiry":"2050000000"}
```

Choose a future expiry and deadline for your chain. Increases and decreases are mutually exclusive; updates preserve gross usage. Creation, update and revocation fees in these examples are zero. A draw also uses zero fee, so its ordinary Note receives the full debit.

Revocation uses `GRANT_SHARD` and `GRANT_SLOT`. Direct calls require the owner as `CALLER_ADDRESS`. For a relay, the example exports public EIP-712 data and waits for an EVM signature from the host. It verifies the signature through the configured chain before exporting calldata. This is distinct from private circuit wallet authorization.

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

The managed Credit binaries use the same encrypted store and refresh/native request-array exchange. They retain operation IDs, reserve inputs, export unsigned host transactions, and support `OPERATION_ID` + `HOST_TRANSACTION_HASH` recovery and canonical reconciliation just like `send-session`. Use a separate database per owner/spender wallet, with the same wallet and storage key when resuming. The examples reject saved operations of a different kind. Resume with the binary that created the operation; do not set `OPERATION_ID` for a new operation.

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
