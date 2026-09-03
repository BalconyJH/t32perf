use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Output,
};

use assert_cmd::cargo::cargo_bin_cmd;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use t32perf_model::ArtifactPath;
use tempfile::TempDir;

const GOLDEN_SCHEMA: &str = "t32perf.golden-artifact-set/v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoldenArtifactSet {
    schema: String,
    session_id: String,
    event_count: u64,
    artifacts: BTreeMap<String, GoldenArtifact>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GoldenArtifact {
    size_bytes: u64,
    sha256: String,
}

#[test]
fn fixed_synthetic_input_matches_the_versioned_end_to_end_golden() {
    let golden: GoldenArtifactSet = serde_json::from_str(include_str!(
        "../fixtures/golden/synthetic-pipeline-v1.json"
    ))
    .expect("golden artifact set");
    assert_eq!(golden.schema, GOLDEN_SCHEMA);
    assert!(!golden.artifacts.is_empty());

    let temp = TempDir::new().expect("temporary directory");
    let root = temp.path().join("artifacts");
    let event_count = golden.event_count.to_string();
    let captured = run(
        &root,
        &[
            "capture",
            "--provider",
            "synthetic",
            "--id",
            &golden.session_id,
            "--events",
            &event_count,
        ],
    );
    assert_success(&captured, "capture.synthetic");
    let analyzed = run(&root, &["analyze", &golden.session_id]);
    assert_success(&analyzed, "analyze");
    let converted = run(
        &root,
        &["convert", &golden.session_id, "--format", "perfetto-json"],
    );
    assert_success(&converted, "convert");
    let validated = run(&root, &["validate", &golden.session_id, "--deep"]);
    assert_success(&validated, "validate");
    let validation = json_stdout(&validated);
    assert_eq!(validation["result"]["valid"], true);
    assert_eq!(validation["result"]["health_verdict"], "VALID");

    let inspected = run(
        &root,
        &["maintenance", "inspect", &golden.session_id, "--deep"],
    );
    assert_success(&inspected, "maintenance.inspect");
    let inspection = json_stdout(&inspected);
    assert_eq!(inspection["result"]["healthy"], true);
    assert_eq!(inspection["result"]["retained_staging_files_total"], 1);
    assert_eq!(
        inspection["result"]["committed_staging_sources"][0]["artifact_id"],
        "analysis-request"
    );
    assert_eq!(
        inspection["result"]["committed_staging_sources"][0]["staged_relative_path"],
        "host-analysis/analysis-request.json"
    );

    let session = root.join(&golden.session_id);
    let actual_paths = public_artifact_paths(&session);
    let expected_paths = golden.artifacts.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(actual_paths, expected_paths, "public artifact set drifted");

    for (relative, expected) in golden.artifacts {
        ArtifactPath::new(relative.clone()).expect("golden path uses artifact syntax");
        let path = session.join(Path::new(&relative));
        let metadata = fs::symlink_metadata(&path).expect("golden artifact metadata");
        assert!(
            metadata.is_file(),
            "{} is not a regular file",
            path.display()
        );
        assert_eq!(
            metadata.len(),
            expected.size_bytes,
            "size drift for {relative}"
        );
        let digest = Sha256::digest(fs::read(&path).expect("read golden artifact"));
        assert_eq!(
            encode_hex(&digest),
            expected.sha256,
            "digest drift for {relative}"
        );
    }
}

fn public_artifact_paths(session: &Path) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    let retained_staging_root = session.join("capture").join("staging");
    for directory in ["capture", "normalized", "analysis", "report"] {
        let root = session.join(directory);
        if !root.exists() {
            continue;
        }
        let mut pending = vec![root];
        while let Some(current) = pending.pop() {
            for entry in fs::read_dir(&current).expect("read artifact directory") {
                let entry = entry.expect("artifact directory entry");
                let metadata = entry.metadata().expect("artifact entry metadata");
                if metadata.is_dir() {
                    if entry.path() == retained_staging_root {
                        continue;
                    }
                    pending.push(entry.path());
                    continue;
                }
                assert!(metadata.is_file(), "artifact entry must be a regular file");
                let relative = entry
                    .path()
                    .strip_prefix(session)
                    .expect("artifact below session")
                    .to_string_lossy()
                    .replace('\\', "/");
                paths.insert(relative);
            }
        }
    }
    paths
}

fn run(root: &Path, arguments: &[&str]) -> Output {
    cargo_bin_cmd!("t32perf")
        .arg("--artifact-root")
        .arg(root)
        .arg("--json")
        .args(arguments)
        .output()
        .expect("run t32perf")
}

fn assert_success(output: &Output, command: &str) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document = json_stdout(output);
    assert_eq!(document["ok"], true);
    assert_eq!(document["command"], command);
}

fn json_stdout(output: &Output) -> Value {
    let stdout = std::str::from_utf8(&output.stdout).expect("stdout is UTF-8");
    assert_eq!(stdout.lines().count(), 1, "stdout was not one JSON object");
    serde_json::from_str(stdout).expect("stdout is JSON")
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
