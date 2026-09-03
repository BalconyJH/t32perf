use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use tempfile::TempDir;

#[test]
fn json_logging_keeps_stdout_protocol_separate_and_omits_arguments() {
    let temp = TempDir::new().expect("temporary directory");
    let secret = "must-not-appear-in-logs";
    let mut command = cargo_bin_cmd!("t32perf");
    let output = command
        .arg("--artifact-root")
        .arg(temp.path().join("artifacts"))
        .arg("--json")
        .args([
            "session",
            "create",
            "--id",
            "invalid/session",
            "--request",
            secret,
        ])
        .env("RUST_LOG", "warn")
        .env("T32PERF_LOG_FORMAT", "json")
        .output()
        .expect("run t32perf");

    assert_eq!(output.status.code(), Some(1));
    let stdout: Value = serde_json::from_slice(&output.stdout).expect("stdout JSON");
    assert_eq!(stdout["error"]["code"], "OPERATIONAL_ERROR");
    let stderr = std::str::from_utf8(&output.stderr).expect("stderr UTF-8");
    assert!(!stderr.contains(secret));
    let events = stderr
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("structured log line"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["error_code"], "OPERATIONAL_ERROR");
    assert_eq!(events[0]["command"], "session");
}
