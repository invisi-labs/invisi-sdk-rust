use invisi_sdk_ipp::{api_url, parse_checkout_input, parse_json};
use serde_json::json;
#[test]
fn strict_json_rejects_duplicate_keys_and_noncanonical_numbers() {
    for input in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":{"b":1,"b":2}}"#,
        r#"{"a":1.2}"#,
        r#"{"a":-1}"#,
        r#"{"a":9007199254740992}"#,
    ] {
        assert!(parse_json(input.as_bytes()).is_err(), "{input}");
    }
    assert!(parse_json(br#"{"a":1}"#).is_ok());
}
#[test]
fn exact_https_links_reject_normalization_and_secrets() {
    for input in [
        "http://example.com/",
        "https://EXAMPLE.com/",
        "https://example.com",
        "https://example.com:443/",
        "https://a:b@example.com/",
        "https://example.com/#",
        "https://example.com/?token=a",
        "https://example.com/%zz",
    ] {
        assert!(api_url(input, None).is_err(), "{input}");
    }
    assert!(api_url(
        "https://example.com/custom?q=one",
        Some("https://example.com")
    )
    .is_ok());
    assert!(api_url("https://evil.example/custom", Some("https://example.com")).is_err());
}
#[test]
fn checkout_input_enforces_terms_and_allows_expired_replay() {
    let input = json!({"ippVersion":1,"mode":"payment","expiresAt":"2000-01-01T00:00:00Z","options":[{"id":"p","method":"invisi","network":"eip155:1","asset":{"address":format!("0x{}", "01".repeat(20)),"symbol":"USDC","decimals":6},"amount":"1"}]});
    assert!(parse_checkout_input(input.clone()).is_ok());
    let mut invalid = input.clone();
    invalid["options"][0]["amount"] = json!("01");
    assert!(parse_checkout_input(invalid).is_err());
    let mut invalid = input;
    invalid["unexpected"] = json!(true);
    assert!(parse_checkout_input(invalid).is_err());
}

#[test]
fn invisi_request_uses_method_and_terms_without_action() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/ipp-wire-vectors.json")).unwrap();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| {
            let raw = case["json"].as_str().unwrap_or("");
            raw.contains("payment_request") && case["valid"].as_bool().unwrap_or(false)
        })
        .unwrap_or(&vectors["cases"][1]);
    let mut request: serde_json::Value =
        serde_json::from_str(case["json"].as_str().unwrap()).unwrap();
    request.as_object_mut().unwrap().remove("action");
    assert!(invisi_sdk_ipp::parse_payment_request(request.clone(), None).is_ok());
    request["action"] = json!({"type":"invisi_transaction"});
    assert!(invisi_sdk_ipp::parse_payment_request(request, None).is_err());
}
