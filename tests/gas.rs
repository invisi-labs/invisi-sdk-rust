use invisi_sdk::gas::*;
#[test]
fn documented_measurements_match_ts_go_and_pinned_asset_digest() {
    use sha2::{Digest, Sha256};
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/current-gas.json")).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "fixtures/documented-references.json"
        ))),
        DOCUMENTED_CATALOG_SHA256
    );
    for row in fixtures["vectors"].as_array().unwrap() {
        let reference = estimate_gas(row["query"].as_object().unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&reference).unwrap()["source"],
            "benchmark"
        );
        assert_eq!(reference.available(), row["available"].as_bool().unwrap());
        if reference.available() {
            assert_eq!(reference.gas_units().unwrap().to_string(), row["gasUnits"]);
        } else {
            assert_eq!(
                serde_json::to_value(reference).unwrap()["reason"],
                row["reason"]
            );
        }
    }
}
#[test]
fn compact_catalog_provenance_and_unsupported_shapes_remain_exact() {
    use sha2::{Digest, Sha256};
    let fixtures: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/current-gas.json")).unwrap();
    let raw = include_bytes!("fixtures/documented-references.json");
    let mut compact = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    for &byte in raw {
        if quoted {
            compact.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
            compact.push(byte);
        } else if !byte.is_ascii_whitespace() {
            compact.push(byte);
        }
    }
    assert_eq!(
        hex::encode(Sha256::digest(compact)),
        fixtures["catalogSha256"]
    );
    for query in fixtures["unsupported"].as_array().unwrap() {
        let reference = estimate_gas(query.as_object().unwrap()).unwrap();
        assert!(!reference.available());
        assert!(reference.gas_units().is_none());
    }
}
