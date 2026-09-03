use std::{
    fs::{self, OpenOptions},
    path::Path,
    process::Output,
};

use assert_cmd::cargo::cargo_bin_cmd;
use fs2::FileExt as _;
use serde_json::Value;
use tempfile::TempDir;

fn run(root: &Path, arguments: &[&str]) -> Output {
    cargo_bin_cmd!("t32perf")
        .args(["--artifact-root", &root.to_string_lossy(), "--json"])
        .args(arguments)
        .output()
        .expect("run t32perf")
}

fn document(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON stdout: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

#[test]
fn drive_cli_exposes_only_the_closed_deployment_surface() {
    let temporary = TempDir::new().unwrap();
    for forbidden in [
        "--endpoint",
        "--executable",
        "--skill",
        "--script",
        "--fault",
    ] {
        let output = run(
            temporary.path(),
            &[
                "controller",
                "drive",
                "driver-session",
                "--surface",
                "capabilities",
                forbidden,
                "caller-value",
            ],
        );
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(document(&output)["error"]["code"], "INVALID_ARGUMENT");
    }
}

#[test]
fn drive_rejects_capture_mode_on_the_capability_surface_before_loading_config() {
    let temporary = TempDir::new().unwrap();
    let output = run(
        temporary.path(),
        &[
            "controller",
            "drive",
            "driver-session",
            "--surface",
            "capabilities",
            "--mode",
            "raw_ascii",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    let error = &document(&output)["error"];
    assert_eq!(error["code"], "OPERATIONAL_ERROR");
    assert!(
        error["message"]
            .as_str()
            .unwrap()
            .contains("only with --surface capture")
    );
}

#[test]
fn abort_upstream_reason_is_a_closed_cli_value() {
    let temporary = TempDir::new().unwrap();
    let output = run(
        temporary.path(),
        &[
            "controller",
            "abort-upstream",
            "driver-session",
            "33333333333333333333333333333333",
            "--reason",
            "caller-defined",
        ],
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(document(&output)["error"]["code"], "INVALID_ARGUMENT");
}

#[test]
fn preflight_accepts_no_session_or_endpoint_arguments() {
    let temporary = TempDir::new().unwrap();
    let output = run(
        temporary.path(),
        &["controller", "driver-preflight", "unexpected-session"],
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(document(&output)["error"]["code"], "INVALID_ARGUMENT");
}

#[test]
fn execution_lease_excludes_driver_and_external_controller_mutations() {
    let temporary = TempDir::new().unwrap();
    let root = temporary.path();
    let created = run(root, &["session", "create", "--id", "lease-session"]);
    assert_eq!(created.status.code(), Some(0));

    let controller = root.join(".t32perf-control/controller");
    fs::create_dir_all(&controller).unwrap();
    let lease_path = controller.join("trace32-driver-execution.lock");
    let lease = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lease_path)
        .unwrap();
    lease.try_lock_exclusive().unwrap();

    for arguments in [
        vec!["controller", "driver-preflight"],
        vec!["perf_capabilities", "lease-session"],
        vec![
            "controller",
            "prepare",
            "lease-session",
            "--operation",
            "perf_get_capabilities",
        ],
    ] {
        let output = run(root, &arguments);
        assert_eq!(output.status.code(), Some(1));
        let error = document(&output);
        assert_eq!(error["error"]["code"], "CONTROLLER_DRIVER_BUSY");
        assert!(
            error["error"]["message"]
                .as_str()
                .unwrap()
                .contains("TRACE32 driver execution lease")
        );
    }

    let status = run(root, &["controller", "status", "lease-session"]);
    assert_eq!(
        status.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    fs2::FileExt::unlock(&lease).unwrap();
}
