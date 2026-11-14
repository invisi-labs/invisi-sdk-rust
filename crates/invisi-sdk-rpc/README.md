# invisi-sdk-rpc

Version `1.2.3`. ProtocolRPC, broadcaster and Provenance network clients, canonical response validation and transport errors. Depends on primitives and protocol; no local proving or wallet storage.

Wallet-aware quotation is provided by `invisi_sdk::broadcaster::BroadcasterClient::{quote, submit, cancel}`,
which accepts ordinary preparations and managed Session operations. This module keeps
its independent calldata-level `submit_transaction` and `cancel_transaction` APIs;
access them through `client.rpc()` from the SDK wrapper.

See the [workspace documentation](https://github.com/invisi-lab/invisi-sdk-rust) for usage. Licensed under Apache-2.0.

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
