use std::process::Command;

const FROM: &str = "0x1111111111111111111111111111111111111111";
const TO: &str = "0x2222222222222222222222222222222222222222";
const UNLIMITED_APPROVAL: &str = "0x095ea7b30000000000000000000000003333333333333333333333333333333333333333ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

#[test]
fn inspect_emits_a_critical_json_finding_for_unlimited_approval() {
    let output = Command::new(env!("CARGO_BIN_EXE_evmguard"))
        .args([
            "inspect",
            "--chain-id",
            "8453",
            "--from",
            FROM,
            "--to",
            TO,
            "--data",
            UNLIMITED_APPROVAL,
            "--format",
            "json",
        ])
        .output()
        .expect("run inspect command");

    let stdout = String::from_utf8(output.stdout).expect("decode command output");

    assert!(output.status.success());
    assert!(stdout.contains("\"highestSeverity\": \"critical\""));
    assert!(stdout.contains("\"ruleId\": \"erc20.unlimited-approval\""));
}

#[test]
fn preflight_requires_an_rpc_endpoint() {
    let output = Command::new(env!("CARGO_BIN_EXE_evmguard"))
        .args([
            "preflight",
            "--chain-id",
            "8453",
            "--from",
            FROM,
            "--to",
            TO,
            "--data",
            "0x",
        ])
        .output()
        .expect("run preflight command");

    let stderr = String::from_utf8(output.stderr).expect("decode command error");

    assert!(!output.status.success());
    assert!(stderr.contains("--rpc-url is required."));
}
