# invisi-sdk-rpc

Version `1.2.3`. ProtocolRPC, broadcaster and Provenance network clients, canonical response validation and transport errors. Depends on primitives and protocol; no local proving or wallet storage.

See the [workspace documentation](https://github.com/invisi-lab/invisi-sdk-rust) for usage. Licensed under Apache-2.0.

Protocol RPC exposes public Note updates and Credit transitions. Account detection and authenticated decryption stay local; no detection key is sent to the service. Status validates deployment/version pins and returns the indexed head without detection metadata.

Native finality is exposed by `rpc::{read_chain_finality, read_transaction_confirmation}` and pure DTOs in `invisi_sdk_protocol::finality`. `EthereumChain` reads native tags; optional custom adapter hooks default to unsupported. Receipt confirmation uses this independent chain, never the broadcaster's optional confirmation claim. Heads require canonical hash, parent, timestamp, and ordering checks, with one bounded retry. Protocol service claims ahead of the primary become unavailable, preserving latest discovery. No depth/time fallback is provided.
