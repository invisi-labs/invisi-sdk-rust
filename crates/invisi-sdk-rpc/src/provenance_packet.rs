//! Bind public recovery packets to canonical calldata and the complete native statement before Source submission.
use crate::{
    broadcaster,
    protocol::{InvisiProtocol, ProtocolContract},
    provenance_client::ProvenanceClient,
};
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
use invisi_sdk_core::provenance::{self as source, ProvenanceProof, TrustContext};
use serde_json::{json, Value};
use std::collections::BTreeSet;
type Result<T> = std::result::Result<T, String>;
fn number(s: &str) -> Result<U256> {
    source::parse_integer(s, 256).map_err(|e| e.to_string())
}
fn word(n: U256) -> String {
    format!("0x{}", hex::encode(n.to_be_bytes::<32>()))
}
fn split(n: B256) -> [U256; 2] {
    [U256::from_be_slice(&n[..16]), U256::from_be_slice(&n[16..])]
}
pub fn validate_provenance_proof(packet: &ProvenanceProof, trust: &TrustContext) -> Result<()> {
    if packet.format != "invisi-provenance-submission-v1"
        || packet.sidecars.len() != 1
        || number(&packet.context.chain_id)? != U256::from(trust.scope.chain_id)
        || number(&packet.context.protocol_address)? != trust.scope.protocol_address
    {
        return Err("provenance packet deployment or shape mismatch".into());
    }
    let data = hex::decode(
        packet
            .data
            .strip_prefix("0x")
            .ok_or("0x calldata required")?,
    )
    .map_err(|e| e.to_string())?;
    broadcaster::decode_intent(&data).map_err(|e| e.to_string())?;
    let InvisiProtocol::InvisiProtocolCalls::transact_0(call) =
        ProtocolContract::decode_call(&data)?
    else {
        return Err("private transact calldata required".into());
    };
    let request = &call.r;
    let p = &request.params;
    let input_count = p.nullifiers.len();
    let output_count = p.noteCommitments.len();
    let slots = input_count
        .checked_add(output_count)
        .ok_or("slot count overflow")?;
    if input_count == 0 || slots > 190 {
        return Err("private transact input shape required".into());
    }
    let capacity = if slots <= 10 {
        slots
    } else {
        slots.div_ceil(10) * 10
    };
    if capacity != packet.main_circuit_capacity
        || request.deliveries.len() != output_count
        || p.sources.is_empty()
        || p.sources.len() > input_count
        || p.token == Address::ZERO
        || number(&packet.context.token_address)? != U256::from_be_slice(p.token.as_slice())
    {
        return Err("provenance native statement shape mismatch".into());
    }
    let mut previous = None;
    let mut ids = vec![U256::ZERO; capacity];
    let mut roots = ids.clone();
    for (i, s) in p.sources.iter().enumerate() {
        if s.treeId >= U256::from(1) << 64 || previous.is_some_and(|n| n >= s.treeId) {
            return Err("source IDs must be sorted unique uint64".into());
        }
        previous = Some(s.treeId);
        ids[i] = s.treeId;
        roots[i] = U256::from_be_slice(s.merkleRoot.as_slice());
    }
    let mut seen = BTreeSet::new();
    let mut values = vec![U256::ZERO; capacity];
    for (i, n) in p.nullifiers.iter().chain(&p.noteCommitments).enumerate() {
        let n = U256::from_be_slice(n.as_slice());
        if n == U256::ZERO || !seen.insert(n) {
            return Err("invalid duplicate or zero native slot".into());
        };
        values[i] = n;
    }
    if p.withdrawalAmount >= U256::from(1) << 128
        || p.feeAmount >= U256::from(1) << 128
        || request.funding.amount >= U256::from(1) << 128
        || ((p.withdrawalAmount == U256::ZERO) != (p.withdrawalAddress == Address::ZERO))
        || ((p.feeAmount == U256::ZERO) != (p.feeRecipient == Address::ZERO))
    {
        return Err("invalid native amount or recipient".into());
    }
    let mut words = vec![
        U256::from(trust.scope.chain_id),
        trust.scope.protocol_address,
        U256::from_be_slice(p.token.as_slice()),
        U256::from(input_count),
        U256::from(output_count),
        U256::from(p.sources.len()),
    ];
    words.extend(ids);
    words.extend(roots);
    words.extend(values);
    words.extend(split(keccak256(
        (request.deliveries.clone(),).abi_encode_params(),
    )));
    words.extend([
        U256::from_be_slice(p.withdrawalAddress.as_slice()),
        p.withdrawalAmount,
        p.deadline,
        request.funding.amount,
        U256::from_be_slice(request.funding.payer.as_slice()),
        U256::from_be_slice(p.feeRecipient.as_slice()),
        p.feeAmount,
    ]);
    let authorization = invisi_sdk_core::wallet::authorization_digest(
        &json!({"operation":"transact","capacity":capacity,"context":{"chainId":trust.scope.chain_id.to_string(),"protocolAddress":word(trust.scope.protocol_address)},"words":words.iter().map(U256::to_string).collect::<Vec<_>>()}),
    )?;
    words.extend(split(B256::from(authorization)));
    let public = words.iter().copied().map(word).collect::<Vec<_>>();
    if public != packet.public_inputs {
        return Err("provenance native statement mismatch".into());
    }
    let digest =
        source::operation_digest(&trust.scope, capacity, &words).map_err(|e| e.to_string())?;
    if packet.operation_digest != format!("0x{}", hex::encode(digest)) {
        return Err("provenance operation digest mismatch".into());
    }
    let sidecar = &packet.sidecars[0];
    if sidecar.operation_index != "0" {
        return Err("unsupported operation index".into());
    }
    source::validate_proof_bundle(&sidecar.proof_bundle, trust).map_err(|e| e.to_string())?;
    let pi = &sidecar.proof_bundle.public_inputs;
    let nfs = p
        .nullifiers
        .iter()
        .map(|n| U256::from_be_slice(n.as_slice()))
        .collect::<Vec<_>>();
    let limbs = split(B256::from(digest));
    if number(&pi[2])? != U256::from_be_slice(p.token.as_slice())
        || number(&pi[6])? != U256::from(input_count)
        || number(&pi[7])? != limbs[0]
        || number(&pi[8])? != limbs[1]
        || number(&pi[9])? != source::input_digest(&nfs).map_err(|e| e.to_string())?
    {
        return Err("provenance proof statement mismatch".into());
    }
    Ok(())
}
pub fn submit_provenance_proof(
    client: &ProvenanceClient,
    packet: &ProvenanceProof,
) -> Result<Value> {
    validate_provenance_proof(packet, &client.trust)?;
    client.submit_source_proof(json!(packet.data), &packet.sidecars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;
    use alloy_sol_types::SolCall;
    use invisi_sdk_core::provenance::{
        ProofBundle, ProofContext, ProofSidecar, RootCertificate, Scope, Source,
    };
    use std::collections::BTreeMap;
    fn fixture() -> (ProvenanceProof, TrustContext) {
        let golden: Value =
            serde_json::from_str(include_str!("../testdata/golden-vectors.json")).unwrap();
        let mut fields = golden["certificate"]["fields"].clone();
        for value in fields.as_object_mut().unwrap().values_mut() {
            *value = json!(value.to_string())
        }
        fields["signature"] = json!(format!(
            "0x{}",
            golden["certificate"]["signatureHex"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x")
        ));
        let certificate: RootCertificate = serde_json::from_value(fields).unwrap();
        let spki = hex::decode(
            golden["certificate"]["publicKeySpkiHex"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let key: [u8; 32] = spki[spki.len() - 32..].try_into().unwrap();
        let trust = TrustContext {
            scope: Scope {
                chain_id: 4,
                protocol_address: U256::from(5),
            },
            chain_generation: 6,
            provider_id: U256::from(1),
            signing_keys: BTreeMap::from([(U256::from(2), key)]),
            signing_key_validity: BTreeMap::new(),
            manifest_sha256: "a".repeat(64),
        };
        let request = crate::protocol::IInvisiProtocol::TransactRequest {
            params: crate::protocol::IInvisiProtocol::CrossTreeTransactParams {
                token: Address::from_slice(&U256::from(2).to_be_bytes::<32>()[12..]),
                sources: vec![crate::protocol::IInvisiProtocol::InputSource {
                    treeId: U256::from(1),
                    merkleRoot: B256::from(U256::from(11).to_be_bytes::<32>()),
                }],
                nullifiers: vec![B256::from(U256::from(12).to_be_bytes::<32>())],
                noteCommitments: vec![],
                withdrawalAddress: Address::from_slice(&U256::from(10).to_be_bytes::<32>()[12..]),
                withdrawalAmount: U256::from(1),
                deadline: U256::from(100),
                feeRecipient: Address::ZERO,
                feeAmount: U256::ZERO,
            },
            deliveries: vec![],
            funding: crate::protocol::IInvisiProtocol::FundingParams {
                amount: U256::ZERO,
                payer: Address::ZERO,
                sigNonce: U256::ZERO,
                deadline: U256::ZERO,
                signature: Bytes::new(),
                permit: crate::protocol::IMetaTx::TokenPermit {
                    deadline: U256::ZERO,
                    v: 0,
                    r: B256::ZERO,
                    s: B256::ZERO,
                },
            },
        };
        // The fixed native statement is independent of the decoder. Only ZK proof bytes are mocked; the certificate uses a signed cross-SDK vector.
        let mut words = vec![4, 5, 2, 1, 0, 1, 1, 11, 12]
            .into_iter()
            .map(U256::from)
            .collect::<Vec<_>>();
        words.extend(split(keccak256(
            (request.deliveries.clone(),).abi_encode_params(),
        )));
        words.extend([10, 1, 100, 0, 0, 0, 0].map(U256::from));
        let auth=invisi_sdk_core::wallet::authorization_digest(&json!({"operation":"transact","capacity":1,"context":{"chainId":"4","protocolAddress":"5"},"words":words.iter().map(U256::to_string).collect::<Vec<_>>()})).unwrap();
        words.extend(split(B256::from(auth)));
        let digest = source::operation_digest(&trust.scope, 1, &words).unwrap();
        let digest_value = U256::from_be_bytes(digest);
        let sd = source::sources_digest(
            6,
            &[Source {
                tree_id: 8,
                root: U256::from(10),
                leaf_count: 9,
            }],
        )
        .unwrap();
        let nd = source::input_digest(&[U256::from(12)]).unwrap();
        let limbs = source::limbs(digest_value);
        let binding = source::binding_digest(
            source::scope_hash(&trust.scope).unwrap(),
            U256::from(2),
            6,
            1,
            sd,
            1,
            digest_value,
            nd,
        )
        .unwrap();
        let pi = [
            U256::from(4),
            U256::from(5),
            U256::from(2),
            U256::from(6),
            U256::from(1),
            sd,
            U256::from(1),
            limbs[0],
            limbs[1],
            nd,
            binding,
        ]
        .map(word)
        .to_vec();
        let packet = ProvenanceProof {
            format: "invisi-provenance-submission-v1".into(),
            data: format!(
                "0x{}",
                hex::encode(
                    InvisiProtocol::transact_0Call {
                        _0: Bytes::from(vec![1, 2]),
                        r: request
                    }
                    .abi_encode()
                )
            ),
            context: ProofContext {
                chain_id: "4".into(),
                protocol_address: "0x0000000000000000000000000000000000000005".into(),
                token_address: "0x0000000000000000000000000000000000000002".into(),
            },
            main_circuit_capacity: 1,
            public_inputs: words.into_iter().map(word).collect(),
            operation_digest: word(digest_value),
            sidecars: vec![ProofSidecar {
                operation_index: "0".into(),
                proof_bundle: ProofBundle {
                    format: "invisi-provenance-proof-v1".into(),
                    circuit_id: "provenance_k10".into(),
                    manifest_sha256: trust.manifest_sha256.clone(),
                    target: "evm".into(),
                    public_inputs: pi,
                    proof: "0x0102".into(),
                    root_certificates: vec![certificate],
                },
            }],
        };
        (packet, trust)
    }
    #[test]
    fn public_packet_binds_complete_native_statement_and_certified_source() {
        let (packet, trust) = fixture();
        validate_provenance_proof(&packet, &trust).unwrap();
        for field in [
            "native_words",
            "calldata",
            "context",
            "digest",
            "sidecar",
            "certificate",
            "capacity",
        ] {
            let mut changed = packet.clone();
            match field {
                "native_words" => changed.public_inputs[0] = word(U256::from(9)),
                "calldata" => {
                    let raw = hex::decode(packet.data.trim_start_matches("0x")).unwrap();
                    let InvisiProtocol::InvisiProtocolCalls::transact_0(mut call) =
                        ProtocolContract::decode_call(&raw).unwrap()
                    else {
                        panic!()
                    };
                    call.r.params.deadline += U256::from(1);
                    changed.data = format!("0x{}", hex::encode(call.abi_encode()));
                }
                "context" => changed.context.token_address = "3".into(),
                "digest" => changed.operation_digest = word(U256::from(9)),
                "sidecar" => changed.sidecars[0].operation_index = "1".into(),
                "certificate" => {
                    changed.sidecars[0].proof_bundle.root_certificates[0].root = "11".into()
                }
                "capacity" => changed.main_circuit_capacity = 10,
                _ => unreachable!(),
            }
            assert!(
                validate_provenance_proof(&changed, &trust).is_err(),
                "accepted mutated {field}"
            );
        }
    }
    #[test]
    fn submits_restored_public_packet_without_transaction_hash_or_prover() {
        use std::io::{Read, Write};
        let (packet, trust) = fixture();
        let restored: ProvenanceProof =
            serde_json::from_slice(&serde_json::to_vec(&packet).unwrap()).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut bytes = vec![];
            let mut buffer = [0u8; 4096];
            let request: Value = loop {
                let n = socket.read(&mut buffer).unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&buffer[..n]);
                if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..end]);
                    let length: usize = headers
                        .lines()
                        .find_map(|l| {
                            l.to_lowercase()
                                .strip_prefix("content-length:")
                                .map(|s| s.trim().parse().unwrap())
                        })
                        .unwrap();
                    if bytes.len() >= end + 4 + length {
                        break serde_json::from_slice(&bytes[end + 4..end + 4 + length]).unwrap();
                    }
                }
            };
            assert_eq!(request["method"], "provenance_submitSourceProof");
            let q = &request["params"][0];
            assert_eq!(q.as_object().unwrap().len(), 2);
            assert_eq!(q["proofSidecars"].as_array().unwrap().len(), 1);
            assert!(q["data"].as_str().unwrap().starts_with("0x"));
            let result = json!({"scope":{"chainId":"4","protocolAddress":"5"},"chainGeneration":"6","providerId":"1","signingKeyId":"2","manifestSha256":"a".repeat(64),"tracking":{"id":"ab".repeat(24),"status":"pending_confirmation"}});
            let body =
                serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
                    .unwrap();
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            socket.write_all(&body).unwrap();
        });
        let client = ProvenanceClient::new(&endpoint, trust).unwrap();
        submit_provenance_proof(&client, &restored).unwrap();
        task.join().unwrap();
    }
}
