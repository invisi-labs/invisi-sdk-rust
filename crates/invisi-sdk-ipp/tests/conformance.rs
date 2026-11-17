use invisi_sdk_ipp::*;
#[test]
fn shared_typescript_wire_corpus() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/ipp-wire-vectors.json")).unwrap();
    let origin = corpus["origin"].as_str().unwrap();
    for case in corpus["cases"].as_array().unwrap() {
        let result =
            parse_json(case["json"].as_str().unwrap().as_bytes()).and_then(|v| {
                match case["kind"].as_str().unwrap() {
                    "session" => parse_payment_session(v, Some(origin)).map(|_| ()),
                    "request" => parse_payment_request(v, Some(origin)).map(|_| ()),
                    "checkout" => parse_checkout(v).map(|_| ()),
                    "input" => parse_checkout_input(v).map(|_| ()),
                    "credential" => parse_credential(v, None).map(|_| ()),
                    other => panic!("unknown case kind {other}"),
                }
            });
        assert_eq!(
            result.is_ok(),
            case["valid"].as_bool().unwrap(),
            "{}: {:?}",
            case["name"],
            result
        );
    }
}
