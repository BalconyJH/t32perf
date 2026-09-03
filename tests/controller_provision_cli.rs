use std::{fs, path::Path, process::Output};

use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use tempfile::TempDir;

fn run(root: &Path, arguments: &[&str]) -> Output {
    cargo_bin_cmd!("t32perf")
        .args(["--artifact-root", &root.to_string_lossy(), "--json"])
        .args(arguments)
        .output()
        .expect("run t32perf")
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON stdout: {error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn create(root: &Path, session: &str) {
    let output = run(root, &["session", "create", "--id", session]);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn firmware_provision_rejects_wrong_elf_without_advancing_session() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("artifacts");
    create(&root, "wrong-firmware");
    fs::write(
        root.join("wrong-firmware/capture/staging/not-firmware.elf"),
        b"not an ELF",
    )
    .unwrap();

    let output = run(
        &root,
        &[
            "controller",
            "provision-firmware",
            "wrong-firmware",
            "--staged",
            "not-firmware.elf",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        json_stdout(&output)["error"]["message"]
            .as_str()
            .is_some_and(|value| value.contains("SHA-256"))
    );

    let status = run(&root, &["session", "status", "wrong-firmware"]);
    assert_eq!(status.status.code(), Some(0));
    assert_eq!(json_stdout(&status)["result"]["state"]["state"], "created");
}

#[test]
fn generic_ingest_cannot_forge_deployment_artifacts() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("artifacts");
    create(&root, "reserved-deployment");
    fs::write(
        root.join("reserved-deployment/capture/staging/forgery.json"),
        b"{}\n",
    )
    .unwrap();

    for arguments in [
        vec![
            "session",
            "ingest",
            "reserved-deployment",
            "--staged",
            "forgery.json",
            "--id",
            "firmware-elf",
            "--kind",
            "other",
            "--destination",
            "capture/other.bin",
            "--media-type",
            "application/octet-stream",
        ],
        vec![
            "session",
            "ingest",
            "reserved-deployment",
            "--staged",
            "forgery.json",
            "--id",
            "Firmware-Elf",
            "--kind",
            "other",
            "--destination",
            "capture/portable-case.bin",
            "--media-type",
            "application/octet-stream",
        ],
        vec![
            "session",
            "ingest",
            "reserved-deployment",
            "--staged",
            "forgery.json",
            "--id",
            "other",
            "--kind",
            "other",
            "--destination",
            "capture/deployment/target-adapter-scenario.json",
            "--media-type",
            "application/json",
        ],
        vec![
            "session",
            "ingest",
            "reserved-deployment",
            "--staged",
            "forgery.json",
            "--id",
            "trace32-firmware-s3",
            "--kind",
            "other",
            "--destination",
            "capture/other-s3.bin",
            "--media-type",
            "application/octet-stream",
        ],
        vec![
            "session",
            "ingest",
            "reserved-deployment",
            "--staged",
            "forgery.json",
            "--id",
            "other-s3-portable-path",
            "--kind",
            "other",
            "--destination",
            "Capture/Trace32-Firmware.s3",
            "--media-type",
            "application/octet-stream",
        ],
        vec![
            "session",
            "ingest",
            "reserved-deployment",
            "--staged",
            "forgery.json",
            "--id",
            "other-s3-kind",
            "--kind",
            "trace32_firmware_measurement",
            "--destination",
            "capture/other-s3-kind.bin",
            "--media-type",
            "application/octet-stream",
        ],
        vec![
            "session",
            "ingest",
            "reserved-deployment",
            "--staged",
            "forgery.json",
            "--id",
            "other-s3-path",
            "--kind",
            "other",
            "--destination",
            "capture/trace32-firmware.s3",
            "--media-type",
            "application/octet-stream",
        ],
        vec![
            "session",
            "ingest",
            "reserved-deployment",
            "--staged",
            "forgery.json",
            "--id",
            "other-s3-producer",
            "--kind",
            "other",
            "--destination",
            "capture/other-s3-producer.bin",
            "--media-type",
            "application/octet-stream",
            "--producer",
            "t32perf-controller-firmware-image/v1",
        ],
    ] {
        let output = run(&root, &arguments);
        assert_eq!(output.status.code(), Some(1));
        assert!(
            json_stdout(&output)["error"]["message"]
                .as_str()
                .is_some_and(|value| value.contains("reserved"))
        );
    }
    let status = run(&root, &["session", "status", "reserved-deployment"]);
    assert_eq!(status.status.code(), Some(0));
    assert_eq!(json_stdout(&status)["result"]["state"]["state"], "created");
}

#[test]
fn scenario_rejects_unknown_values_before_any_controller_request() {
    let temp = TempDir::new().unwrap();
    let root = temp.path().join("artifacts");
    create(&root, "scenario-unknown");

    let output = run(
        &root,
        &[
            "controller",
            "select-scenario",
            "scenario-unknown",
            "--scenario",
            "caller-script-path",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert!(
        json_stdout(&output)["error"]["message"]
            .as_str()
            .is_some_and(|value| value.contains("closed deployment vocabulary"))
    );
}
