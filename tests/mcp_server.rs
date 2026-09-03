use std::{io::Write as _, process::Stdio};

use assert_cmd::cargo::{cargo_bin, cargo_bin_cmd};
use rmcp::{
    ServiceExt as _,
    model::CallToolRequestParams,
    transport::{ConfigureCommandExt as _, TokioChildProcess},
};
use serde_json::{Value, json};
use tempfile::TempDir;

const TOOL_NAMES: [&str; 8] = [
    "perf_capabilities",
    "perf_capture",
    "perf_compare",
    "perf_convert",
    "perf_get_status",
    "perf_get_summary",
    "perf_list_artifacts",
    "perf_run",
];

#[test]
fn stdio_initialization_inventory_and_tool_results_are_interoperable() -> anyhow::Result<()> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("artifacts");
    cargo_bin_cmd!("t32perf")
        .arg("--artifact-root")
        .arg(&root)
        .arg("--json")
        .args(["session", "create", "--id", "mcp-wire"])
        .assert()
        .success();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let executable = cargo_bin("t32perf");
            let transport = TokioChildProcess::new(
                tokio::process::Command::new(executable).configure(|command| {
                    command.arg("--artifact-root").arg(&root).arg("mcp");
                }),
            )?;
            let client = ().serve(transport).await?;

            let peer = client.peer_info().expect("server initialization info");
            assert_eq!(
                peer.server_info.as_ref().map(|info| info.name.as_str()),
                Some("t32perf")
            );
            assert!(
                peer.instructions
                    .as_deref()
                    .is_some_and(|instructions| instructions.contains("perf_get_status"))
            );

            let tools = client.list_all_tools().await?;
            assert_eq!(
                tools
                    .iter()
                    .map(|tool| tool.name.as_ref())
                    .collect::<Vec<_>>(),
                TOOL_NAMES
            );
            assert!(tools.iter().all(|tool| tool.output_schema.is_some()));
            for tool in &tools {
                let output_schema = serde_json::to_string(
                    tool.output_schema.as_ref().expect("typed output schema"),
                )?;
                assert!(
                    output_schema.contains(tool.name.as_ref()),
                    "{} output schema must contain its success operation",
                    tool.name
                );
                for operation in TOOL_NAMES {
                    let allowed_nested_capability_action =
                        tool.name.as_ref() == "perf_capabilities" && operation == "perf_capture";
                    if operation != tool.name.as_ref() && !allowed_nested_capability_action {
                        assert!(
                            !output_schema.contains(operation),
                            "{} output schema must not contain {operation}",
                            tool.name
                        );
                    }
                }
                assert!(output_schema.contains("code"));
                assert!(output_schema.contains("message"));
                for internal in [
                    "execute_practice_skill",
                    "collect_practice_skill_response",
                    "run_workload",
                    "response_handoff",
                    "prepared",
                    "pending",
                ] {
                    assert!(
                        !output_schema.contains(internal),
                        "{} output schema leaked {internal}",
                        tool.name
                    );
                }
            }
            let run = tools
                .iter()
                .find(|tool| tool.name.as_ref() == "perf_run")
                .expect("perf_run schema");
            assert!(
                run.input_schema
                    .get("required")
                    .and_then(Value::as_array)
                    .is_some_and(|required| required.iter().any(|name| name == "session_id")),
                "MCP perf_run must require a resumable Session identifier"
            );

            let status = client
                .call_tool(
                    CallToolRequestParams::new("perf_get_status").with_arguments(arguments(
                        json!({
                            "session_id": "mcp-wire"
                        }),
                    )),
                )
                .await?;
            assert_eq!(status.is_error, Some(false));
            assert_eq!(
                status.structured_content.as_ref().and_then(|value| {
                    value
                        .pointer("/operation")
                        .and_then(serde_json::Value::as_str)
                }),
                Some("perf_get_status")
            );

            let missing = client
                .call_tool(
                    CallToolRequestParams::new("perf_get_status").with_arguments(arguments(
                        json!({
                            "session_id": "missing"
                        }),
                    )),
                )
                .await?;
            assert_eq!(missing.is_error, Some(true));
            assert_eq!(
                missing
                    .structured_content
                    .as_ref()
                    .and_then(|value| value.get("code"))
                    .and_then(serde_json::Value::as_str),
                Some("OPERATIONAL_ERROR")
            );

            let invalid = client
                .call_tool(
                    CallToolRequestParams::new("perf_get_status").with_arguments(arguments(json!(
                        {
                            "session_id": "x".repeat(65)
                        }
                    ))),
                )
                .await?;
            assert_eq!(invalid.is_error, Some(true));
            assert_eq!(
                invalid
                    .structured_content
                    .as_ref()
                    .and_then(|value| value.get("code"))
                    .and_then(Value::as_str),
                Some("INVALID_ARGUMENT")
            );

            client.cancel().await?;
            Ok::<_, anyhow::Error>(())
        })
}

#[test]
fn fatal_stdio_framing_is_nonzero_and_keeps_stdout_protocol_clean() -> anyhow::Result<()> {
    let temporary = TempDir::new()?;
    let root = temporary.path().join("artifacts");
    let mut child = std::process::Command::new(cargo_bin("t32perf"))
        .arg("--artifact-root")
        .arg(root)
        .arg("--json")
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(b"{\"jsonrpc\":\"2.0\"")?;

    let output = child.wait_with_output()?;
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "MCP stdout must remain protocol-only"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("truncated frame"),
        "fatal framing reason must be available on local stderr: {stderr}"
    );
    Ok(())
}

#[test]
fn non_mcp_argument_values_do_not_change_json_clap_errors() -> anyhow::Result<()> {
    let output = std::process::Command::new(cargo_bin("t32perf"))
        .args(["--json", "--artifact-root", "mcp", "not-a-command"])
        .output()?;
    assert!(!output.status.success());
    let document: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(
        document.pointer("/error/code").and_then(Value::as_str),
        Some("INVALID_ARGUMENT")
    );
    assert!(output.stderr.is_empty());
    Ok(())
}

fn arguments(value: Value) -> serde_json::Map<String, Value> {
    value.as_object().cloned().expect("tool arguments object")
}
