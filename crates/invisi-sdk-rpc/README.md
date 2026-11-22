# invisi-sdk-rpc

Version `1.2.3`. ProtocolRPC, broadcaster and Provenance network clients, canonical response validation and transport errors. Depends on primitives and protocol; no local proving or wallet storage.

Wallet-aware quotation is provided by `invisi_sdk::broadcaster::BroadcasterClient::{quote, submit, cancel}`,
which accepts ordinary Core preparations and managed Session operations. This module keeps
its independent calldata-level `submit_transaction` and `cancel_transaction` APIs;
access them through `client.rpc()` from the SDK wrapper.

See the [workspace documentation](https://github.com/invisi-labs/invisi-sdk-rust) for usage. Licensed under Apache-2.0.

`ProtocolRpcClient::get_credit_status` accepts the zero address for the native token, with a nonzero owner and positive uint128 grant ID; deployment identity and exact canonical block checks still apply.

Protocol RPC exposes public Note updates and Credit transitions. Account detection and authenticated decryption stay local; no detection key is sent to the service. Status validates deployment/version pins and returns the indexed head without detection metadata.

Native finality is exposed by `rpc::{read_chain_finality, read_transaction_confirmation}` and pure DTOs in `invisi_sdk_protocol::finality`. `EthereumChain` reads native tags; optional custom adapter hooks default to unsupported. Receipt confirmation uses this independent chain, never the broadcaster's optional confirmation claim. Heads require canonical hash, parent, timestamp, and ordering checks, with one bounded retry. Protocol service claims ahead of the primary become unavailable, preserving latest discovery. No depth/time fallback is provided.

Scheduled relay quotes add an optional `schedule` with canonical decimal-string
`publishAfter` and `executeBefore`, and a nonzero lowercase `cancelTokenHash`.
They use the `ScheduledQuote` EIP-712 type in the unchanged broadcaster domain;
ordinary quotes retain their existing digest. `estimate_quote_with_schedule` and
`quote_with_schedule` preserve the existing unscheduled methods. Submit always
uses the authenticated quote's schedule. Scheduling capability limits come from
`broadcaster_getStatus.scheduling` (all seconds are wire strings); clients do not
impose a fixed seven-day maximum. The relay defaults are max delay 604800,
default execution window 300, maximum window 3600 and deadline slack 120 seconds.

High-level `BroadcasterOptions.schedule` generates a random cancellation preimage
and stores it with the signed quote and frozen submission evidence before sending.
Submission IDs are opaque values allocated by the broadcaster. The managed session
persists the returned ID before returning success. After a lost response, replay
`client.submit(&mut operation, chain.as_ref())` on the previously attempted saved operation: it reuses the
exact frozen request without requoting or reproving and persists the returned ID.
Cancellation requires that recovered ID; a never-submitted operation is not sent
merely to obtain a cancellation ID. Treat saved operation
journals as secrets and encrypt them at rest. Debug output redacts the token.
`client.cancel(&mut operation)` is scoped to the saved relay and submission ID.
For managed operations it persists the cancellation acknowledgement, independently
checks canonical unspent inputs, and releases reservations before returning success.
On a canonical-reader outage, retry the same call: the saved acknowledgement avoids
another relay request. Completed safe cancellations are idempotent. Ordinary prepared
targets have no managed inventory and return the acknowledgement directly.
Cancellation acknowledges relay custody and does not revoke protocol signatures.
Uncertain cancellation responses retain reservations.
`scheduled`, `preparing`, and `cancelled` statuses coexist with existing native
confirmation metadata. Scheduling does not change provenance statements.

`TrustedProtocolRpcClient::new(transport, deployment)?.get_note(commitment,
FinalityTag::Finalized)` (or `Safe`) uses the `invisi_getNote` confirmation
selector without a `CanonicalChain`. Its distinct `TrustedNoteLookup` result
checks deployment/version pins, complete pending/confirmed envelopes, finality
and block bindings, and the Poseidon membership proof locally. Canonical chain,
receipt success, and root-history authentication remain trusted RPC assertions.
A pending result contains no partial evidence and does not prove nonpayment.
`Latest` is rejected. The existing `ProtocolRpcClient::get_note(commitment,
&block)` retains independent chain verification and its historic wire format.

### Trusted Protocol RPC reads

`rpc::TrustedProvider::new(transport, deployment)` implements `CanonicalChain`,
`CanonicalHead`, `ChainReceipts` and `ChainTransactions` using only
`invisi_readChainState`. Pass it wherever `EthereumChain` is accepted, including
`ProtocolRpcClient` and `sdk::RpcChainState`. Supply explicit deployment pins;
every response must match all pins and API/protocol versions v1/1. Header and
signed transaction hashes are recomputed, and receipts bind to a canonical header.
This mode trusts the Protocol RPC service for chain facts; it does not independently
verify consensus or connect to an Ethereum endpoint. It exposes no submission API.

## Contributing

See the [contribution guidelines](../../README.md#contributing) for issues, pull requests, validation, and handling sensitive material.

Receiving-key registration is exposed by `registration::RegistrationOperation` and
re-exported through the root SDK and session crate. `prepare` pins the deployment,
reads a canonical registry nonce, and freezes the keys and deadline. Call
`authorize_direct` for an owner-sent transaction, or obtain `authorization` and
attach a verified EOA/ERC-1271 signature with `with_signature`. `export_transaction`
checks freshness again; the host still owns fees, signing and durable submission.
After sending, use `track` and `reconcile`. Recovery uses the original transaction
hash through `recover`, or a deployment-bound serialized public operation through
`restore`; it never creates a second registration. Confirmation requires the
exact transaction, canonical receipt and matching `ReceivingKeysSet` event.

### Optional PaymentRouter relay

The canonical Router API is available in 1.3.3.
Use `invisi_sdk_payment_router::RouterRelayClient`, rather than the ordinary Core
quote verifier, for Router/account envelopes. It calls the same
`broadcaster_estimateQuote`, `broadcaster_getQuote`, and
`broadcaster_submitTransaction` methods with `{data, router}`: `data` is the exact
embedded Core calldata and `router` contains the complete outer `to`, `data`,
`value: "0"`, and optional EIP-7702 `authorizationList` (Ethereum hex quantities).
Submit adds `quote`, its separate `signature`, and `proofSidecars: []` for Router
pure public funding with no foreign Note inputs, even if general service metadata
reports `provenanceRequired: true`.

Estimate and signed quote accept an unproved, unsigned draft. Export Core data with
`prepared.broadcaster_intent()`, prepare with `prepare_canonical_draft`, and encode
`draft_relay_envelope` or native `draft_envelope` plus unsigned authorization
metadata. Finalize all business fields before obtaining the signed quote, then
prove and sign the actual Router/account/permit/7702 messages. Ordinary Core quote
capabilities and their lifecycle above remain unchanged.

The shared conservative `payment-router-gas-v1` model adds Router allowances to the
existing Core baseline and reports `source: "model"`, not receipt-calibrated swap
measurements. Opaque 0x estimation is unavailable without a trusted service-policy
route gas budget. Broadcaster uses dynamic chain fees bounded by its operational
gas-price maximum. The host bounds fee convergence attempts and wallet
`maxFeeAmount` in Core-token base units; retain an approved higher fee when the
minimum falls. Fees are denominated only in the embedded Core settlement token,
and exact funding includes the fee. Input-token price support is not required.
Discover enabled `paymentRouters` through service status/token-support responses
and configure trusted deployment and quote-signer pins.

Quotes require `requestHashFormat: "payment-router-intent-v1"`, the semantic intent
hash and `execution: "direct"`. Proof/signature completion preserves this identity;
amounts, fees, route, deadlines, nonces, account fields and authorization metadata
remain bound. `envelope_hash` retains raw signed-envelope identity. Business-field
changes require a fresh quote and applicable proof/signatures. Only final
submission requires executable principal and allowance/permit plus the actual
proof/signatures. Broadcaster checks actual Core/route hashes, pinned runtime and
live counters, then estimates and simulates the complete actual outer call before
sending, within signed gas/token-fee caps. Scheduling and aggregation are rejected.
Native relay spends the payer EOA's principal with zero outer value; the host owns
EIP-7702 signing and persistent delegation/revocation. See the
[Router guide](../invisi-sdk-payment-router/README.md) for nonce and simulation rules.
