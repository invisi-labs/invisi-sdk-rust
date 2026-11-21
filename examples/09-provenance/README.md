# Router recognition and later private Note spending

These are compile-checked Rust host recipes. Ordinary `main` functions only print
guidance and perform no network, signing, proving or submission. Provide actual
host capabilities to call the exported functions. They use existing Source and
private Note APIs; no contract or SDK production API is changed.

```sh
cargo run -p invisi-sdk-examples --bin router-output-recognition
cargo run -p invisi-sdk-examples --bin recognized-note-spend
cargo check -p invisi-sdk-examples --all-targets --all-features
```

`01-router-output-recognition.rs::query_router_output` accepts a trust-configured
`ProvenanceClient`, the actual Router transaction hash and an actual output
commitment. It calls `get_transaction_recognition` and `get_note_recognition` and
returns the service's states/reasons unchanged. Build the trusted client with the
official deployment configuration or independently reviewed private pins as in
`07-broadcaster/support.rs::source_client`; never promote a service response into
a trust root. A successful chain receipt alone does not imply recognized source.
Pending indexing/finality, unavailable traces, unrecognized dependencies and
service failures must remain visible. Querying a commitment reveals interest;
no viewing key, opening or witness is uploaded.

`02-private-note-spend.rs::spend_recognized_note` accepts a real `TransferPreparation`
from the discovery/decryption/canonical authentication flow in `03-note/transfer.rs`.
Use `discover`, `pending.decrypt`, a canonical snapshot and `select_notes` to choose
real unspent Notes; inspect Source recognition for candidate inputs as in example
01. The application must implement `AppDecryptor` (the existing default reports
an integration error), provide real recipient outputs and automatic change, and
attach the SDK's native Source capability as in `07-broadcaster`. This is a host
recipe, not an automatic configured discovery CLI. A prior recognized status
query is not membership evidence: actual `prove_provenance` replays recognized
leaves and verifies certificates/anchors before producing the unchanged 11-input
Source proof.

The function prepares the ordinary private transfer, requests external wallet
authorization, proves Core, calls `prove_provenance`, evaluates the actual public
packet and requires `broadcastDecision=allow`, matching operation digest and
tracking that permits broadcast on both evaluation and submission acknowledgement,
invokes host `simulate_main` on the full actual Core call, submits through
`sdk::submit_provenance_proof`, and invokes host `send_main` to sign/send that same
exported Core transaction. The recipe also compares its calldata bytes with the
Provenance packet before simulation. The host must persist the submission and sent
hash. Source submission uses only calldata,
public proofs and certificates. Openings, amounts/nonces used as witnesses,
membership paths and wallet decryption material stay local. Main execution and
Source tracking are independent; returned tracking can still be pending. Use
`get_tracking` or bounded `wait_tracking` and independent native confirmation.
For restart-safe retained-opening recovery see existing
`07-broadcaster/03-recover-and-submit-provenance.rs`.

| Scenario | Actual source/principal checks | Later private consumption |
|---|---|---|
| Self native -> Router -> Note | Actual native funding, wrapping/swap and final Core deposit | Recognized Note membership plus separate Provenance proof |
| Self ERC20 -> Router -> Note | Actual payer ERC20 debit and final deposit; allowance is not payment | Same |
| Relayed ERC20 -> Router -> Note | Payer signature and actual debit; gas-paying Broadcaster is distinct | Same |
| EIP-7702 native -> Router -> Note | Delegated execution, outer sender and actual native principal separately | Same |
| Third-party Router -> Note | Verifiable canonical fund flow/traces; no pre-registration assumed and no blanket recognition guarantee | Same |
| ETH -> USDT -> USDT Note | Source may begin in ETH; output and subsequent token scope remain USDT | Prove spending of USDT Notes, not ETH Notes |
| Old private inputs plus new public funds | New funds do not replace recognized membership of old inputs | Prove every actual private input, bound to the main operation |

For pure public canonical Router `transact`, Core proof remains required but there
is no old private input requiring a Provenance input proof. This does not change
the distinct `shield` interface. The mixed-input row describes existing private
Core semantics; the canonical Router recipe itself supports zero private inputs.
Source attributes actual principal using canonical execution/fund flows and
available traces, rather than simply using top-level `tx.from`.

`operationIndex` locates a protocol operation inside a transaction. It is not a
Note input/output index, token index or log index. The existing native Provenance
packet supports one direct private `transact` with sidecar index `0`; the example
preserves that SDK-generated packet. A batched/nested Router can have several
operations. Obtain Source's reliable locator and use an explicitly supported
binding API for such post-transaction evidence; never guess `0` or rewrite this
single-operation packet to claim arbitrary nested support.
