# invisi-sdk-rpc

Version `1.2.2`. ProtocolRPC, broadcaster and Provenance network clients, canonical response validation and transport errors. Depends on primitives and protocol; no local proving or wallet storage.

See the [workspace documentation](https://github.com/invisi-lab/invisi-sdk-rust) for usage. Licensed under Apache-2.0.

Protocol RPC exposes public Note updates and Credit transitions. Account detection and authenticated decryption stay local; no detection key is sent to the service. Status validates deployment/version pins and returns the indexed head without detection metadata.
