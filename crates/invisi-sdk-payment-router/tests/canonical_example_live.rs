//! Host-supplied testnet regression: the runner executes the actual canonical example functions.
#[test]
#[ignore = "requires an explicit testnet write window and configured canonical host runner"]
fn slow_proving_and_simulation_keep_same_intent_quote_fresh_before_submission() {
    let runner =
        std::env::var("INVISI_CANONICAL_LIVE_RUNNER").expect("configured live host runner");
    let output = std::process::Command::new(runner)
        .output()
        .expect("execute live canonical host");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8(output.stdout).expect("host output UTF-8");
    let record: serde_json::Value =
        serde_json::from_str(stdout.lines().last().expect("host result"))
            .expect("parse host result");
    assert_eq!(record["status"], "live_pass");
    assert!(
        record["rpcMethods"]["broadcaster:broadcaster_getQuote"]
            .as_u64()
            .is_some_and(|count| count >= 3),
        "initial approval, post-proof renewal and final same-intent renewal must all run"
    );
    assert!(record["transactionHash"]
        .as_str()
        .is_some_and(|v| v.starts_with("0x") && v.len() == 66));
    let log = std::fs::read_to_string(record["log"].as_str().expect("host raw result log"))
        .expect("read actual result");
    let actual: serde_json::Value =
        serde_json::from_str(log.lines().last().expect("actual native result"))
            .expect("parse native result");
    assert_eq!(actual["actualEnvelopeMatched"], true);
    assert_eq!(actual["receiptStatus"], 1);
    assert_eq!(actual["finality"]["level"], "finalized");
    assert_eq!(actual["finality"]["status"], "available");
}
