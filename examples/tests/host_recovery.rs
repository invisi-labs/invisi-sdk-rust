//! Explicit read-only live regression for an already submitted official Session example.
//! The host supplies an access-restricted JSON environment and the official binary path.
#[test]
#[ignore = "requires an existing exported journal and its actual confirmed host transaction hash"]
fn confirmed_host_recovery_reconciles_without_exporting_a_new_transaction() {
    let executable = std::env::var("INVISI_EXAMPLE_RECOVERY_BIN").expect("official binary path");
    let environment_file =
        std::env::var("INVISI_EXAMPLE_RECOVERY_ENV").expect("host environment path");
    let environment: std::collections::BTreeMap<String, String> = serde_json::from_slice(
        &std::fs::read(environment_file).expect("read host recovery environment"),
    )
    .expect("parse host recovery environment");
    assert!(environment.contains_key("OPERATION_ID"));
    assert!(environment.contains_key("HOST_TRANSACTION_HASH"));
    let output = std::process::Command::new(executable)
        .arg("--execute")
        .envs(environment)
        .env_remove("OWNER_PRIVATE_KEY")
        .env_remove("OWNER_KEY_FILE")
        .output()
        .expect("run official recovery example");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Reconciliation applied at canonical block"));
    assert!(
        !stdout.contains("\"data\": \"0x"),
        "recovery must not export a new sendable transaction"
    );
}

#[test]
#[ignore = "requires an existing unsubmitted public revocation journal and host RPC configuration"]
fn owner_revocation_main_exports_without_a_private_circuit_ready_transition() {
    let executable =
        std::env::var("INVISI_REVOKE_EXAMPLE_BIN").expect("official revocation binary");
    let environment_file =
        std::env::var("INVISI_REVOKE_EXAMPLE_ENV").expect("revocation host environment");
    let environment: std::collections::BTreeMap<String, String> = serde_json::from_slice(
        &std::fs::read(environment_file).expect("read revocation environment"),
    )
    .expect("parse revocation environment");
    assert!(environment.contains_key("OPERATION_ID"));
    assert!(!environment.contains_key("HOST_TRANSACTION_HASH"));
    let output = std::process::Command::new(executable)
        .arg("--execute")
        .envs(environment)
        .env("BB_BINARY", "/unavailable/no-private-circuit-prover")
        .env("NOIR_EXECUTOR", "/unavailable/no-private-witness-executor")
        .env_remove("OWNER_PRIVATE_KEY")
        .env_remove("OWNER_KEY_FILE")
        .output()
        .expect("run actual revocation main");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"data\": \"0x"),
        "owner revocation must export its actual public calldata"
    );
    assert!(
        !stdout.contains("Reconciliation applied"),
        "an unsent revocation is not confirmed"
    );
}

#[cfg(feature = "sqlite")]
#[test]
fn source_pre_submit_refuses_a_saved_id_before_opening_a_new_payment() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_pre-submit-provenance"))
        .env_clear()
        .env("OPERATION_ID", "the-original-saved-intent")
        .output()
        .expect("run official Source entry point");
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("recover-and-submit-provenance"), "{error}");
}

#[cfg(feature = "sqlite")]
#[test]
fn scheduled_replay_flag_requires_a_saved_id_before_opening_configuration() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_scheduled-broadcaster"))
        .arg("--execute")
        .arg("--recover-submit-id")
        .env_clear()
        .output()
        .expect("run official scheduled entry point");
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("OPERATION_ID"), "{error}");
}
