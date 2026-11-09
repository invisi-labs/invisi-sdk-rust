use alloy_primitives::{keccak256, Address, B256, U256};
use invisi_sdk::broadcaster::provenance::{
    verify_provenance_quote, ProvenanceSignedQuote, REQUEST_HASH_FORMAT,
};
use invisi_sdk::broadcaster::{
    quote_digest, request_hash, verify_quote, Quote, SignedQuote, Trust,
};
#[test]
fn provenance_quote_requires_bound_configured_policy() {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/broadcaster-vectors.json")).unwrap();
    let row = &rows[0];
    let data = hex::decode(row["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
    let key = k256::ecdsa::SigningKey::from_slice(&[0x11; 32]).unwrap();
    let public = key.verifying_key().to_encoded_point(false);
    let trust = Trust {
        chain_id: row["trust"]["chainId"].as_str().unwrap().parse().unwrap(),
        protocol: row["trust"]["protocol"].as_str().unwrap().parse().unwrap(),
        signer: Address::from_slice(&keccak256(&public.as_bytes()[1..])[12..]),
    };
    let policy = B256::repeat_byte(0x77);
    let mut quote: Quote = serde_json::from_value(row["quote"].clone()).unwrap();
    quote.request_hash = B256::from(invisi_sdk::provenance::provenance_intent_hash(
        request_hash(&data).unwrap().0,
        U256::from_be_bytes(policy.0),
    ));
    let (signature, recovery) = key
        .sign_prehash_recoverable(quote_digest(&quote, &trust).unwrap().as_slice())
        .unwrap();
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(recovery.to_byte());
    let mut s = ProvenanceSignedQuote {
        quote: quote.clone(),
        signature: format!("0x{}", hex::encode(bytes)),
        provenance_policy_id: Some(policy),
        request_hash_format: Some(REQUEST_HASH_FORMAT.into()),
    };
    verify_provenance_quote(&s, &trust, &data, 0, policy).unwrap();
    assert!(verify_provenance_quote(&s, &trust, &data, 0, B256::repeat_byte(0x78)).is_err());
    assert!(verify_quote(
        &SignedQuote {
            quote,
            signature: s.signature.clone()
        },
        &trust,
        &data,
        0
    )
    .is_err());
    assert!(serde_json::from_value::<SignedQuote>(serde_json::to_value(&s).unwrap()).is_err());
    s.provenance_policy_id = None;
    assert!(verify_provenance_quote(&s, &trust, &data, 0, policy).is_err());
}
