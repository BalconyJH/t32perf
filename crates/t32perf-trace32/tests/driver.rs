use jsonschema::validator_for;
use serde_json::{Value, json};
use t32perf_trace32::{
    EXPECTED_T32MCP_DRIVER_VERSION, MAX_T32MCP_DRIVER_CONFIG_BYTES, T32MCP_DRIVER_CONFIG_SCHEMA,
    driver_schema_documents, parse_t32mcp_driver_config,
};

fn valid_document() -> Value {
    json!({
        "schema": T32MCP_DRIVER_CONFIG_SCHEMA,
        "executable": "t32mcp",
        "expected_executable_sha256": "b".repeat(64),
        "skills_root": "C:\\ProgramData\\t32perf\\skills",
        "trace32_port": 20_000,
        "expected_t32mcp_version": EXPECTED_T32MCP_DRIVER_VERSION,
        "expected_bundle_sha256": "a".repeat(64),
        "poll_interval_ms": 100,
        "operation_timeout_ms": 300_000,
        "max_stderr_bytes": 65_536,
        "workload": {
            "executable": "workload-runner",
            "expected_executable_sha256": "c".repeat(64),
            "arguments": [
                "--root={artifact_root}",
                "--session={session_id}",
                "--transaction={transaction_id}",
                "--binding={binding_sha256}",
                "--state={initial_target_state}",
                "--workload={workload_identity}"
            ],
            "timeout_ms": 600_000
        },
        "fault_actions": {
            "trace32_disconnect_at_stop": {
                "executable": "disconnect-trace32",
                "expected_executable_sha256": "d".repeat(64),
                "arguments": [
                    "--transaction={transaction_id}",
                    "--binding={binding_sha256}"
                ],
                "timeout_ms": 10_000
            }
        },
        "performance_run": {
            "max_duration_ns": 300_000_000_000_u64,
            "firmware": {
                "path": "C:\\ProgramData\\t32perf\\firmware\\approved.elf",
                "sha256": "e".repeat(64)
            },
            "workload_command": {
                "executable": "performance-run-workload",
                "expected_executable_sha256": "8".repeat(64),
                "arguments": [
                    "--root={artifact_root}",
                    "--session={session_id}",
                    "--state={initial_target_state}",
                    "--workload={workload_identity}",
                    "--duration-ns={duration_ns}"
                ],
                "timeout_ms": 600_000
            },
            "qualification": {
                "policy_id": "production-qualification-policy",
                "qualification_receipt": {
                    "path": "C:\\ProgramData\\t32perf\\qualification\\receipt.json",
                    "sha256": "7".repeat(64)
                },
                "hil_receipt": {
                    "path": "C:\\ProgramData\\t32perf\\qualification\\hil.json",
                    "sha256": "6".repeat(64)
                },
                "recovery_evidence": {
                    "path": "C:\\ProgramData\\t32perf\\qualification\\recovery.json",
                    "sha256": "5".repeat(64)
                }
            },
            "attestation": {
                "policy_path": "C:\\ProgramData\\t32perf\\policy\\capture.json",
                "policy_sha256": "f".repeat(64),
                "policy_id": "production-policy",
                "key_id": "production-key",
                "signer_command": {
                    "executable": "capture-attestation-signer",
                    "expected_executable_sha256": "9".repeat(64),
                    "arguments": [
                        "--root={artifact_root}",
                        "--session={session_id}",
                        "--request={signing_request_path}",
                        "--request-sha256={signing_request_sha256}",
                        "--output={attestation_output_path}",
                        "--policy={policy_id}",
                        "--key={key_id}"
                    ],
                    "timeout_ms": 30_000
                },
                "idempotent_by_signing_request_sha256": true
            }
        }
    })
}

fn parse(document: &Value) -> Result<(), String> {
    parse_t32mcp_driver_config(&serde_json::to_vec(document).unwrap())
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[test]
fn valid_config_is_strictly_parsed() {
    let config =
        parse_t32mcp_driver_config(&serde_json::to_vec(&valid_document()).unwrap()).unwrap();

    assert_eq!(
        config.expected_t32mcp_version,
        EXPECTED_T32MCP_DRIVER_VERSION
    );
    assert!(config.workload.is_some());
    assert!(config.fault_actions.trace32_disconnect_at_stop.is_some());
    assert!(config.performance_run.is_some());

    let mut without_performance_run = valid_document();
    without_performance_run
        .as_object_mut()
        .unwrap()
        .remove("performance_run");
    assert!(parse(&without_performance_run).is_ok());

    let mut without_recovery = valid_document();
    without_recovery["performance_run"]["qualification"]
        .as_object_mut()
        .unwrap()
        .remove("recovery_evidence");
    assert!(parse(&without_recovery).is_ok());

    let mut without_resources = valid_document();
    without_resources["performance_run"]
        .as_object_mut()
        .unwrap()
        .remove("resources");
    assert!(parse(&without_resources).is_ok());

    let mut without_qualification = valid_document();
    without_qualification["performance_run"]
        .as_object_mut()
        .unwrap()
        .remove("qualification");
    assert!(parse(&without_qualification).is_err());

    let mut without_duration_bound = valid_document();
    without_duration_bound["performance_run"]
        .as_object_mut()
        .unwrap()
        .remove("max_duration_ns");
    assert!(parse(&without_duration_bound).is_err());
}

#[test]
fn performance_run_resources_are_closed_and_all_or_nothing_by_group() {
    let mut complete = valid_document();
    complete["performance_run"]["resources"] = json!({
        "linker_map": { "path": "C:\\ProgramData\\t32perf\\build\\approved.map", "sha256": "1".repeat(64) },
        "stack_usage": { "path": "C:\\ProgramData\\t32perf\\build\\approved.su", "sha256": "2".repeat(64) },
        "static_ram_config": { "path": "C:\\ProgramData\\t32perf\\build\\static-ram.json", "sha256": "3".repeat(64) },
        "program_flow": {
            "orti": { "path": "C:\\ProgramData\\t32perf\\build\\approved.orti", "sha256": "4".repeat(64) },
            "task_markers": { "path": "C:\\ProgramData\\t32perf\\build\\markers.json", "sha256": "5".repeat(64) },
            "task_events_mapping_template": { "path": "C:\\ProgramData\\t32perf\\build\\taskevents-template.json", "sha256": "6".repeat(64) }
        },
        "custom_events": {
            "c_wire_mapping": { "path": "C:\\ProgramData\\t32perf\\build\\wire-map.json", "sha256": "7".repeat(64) },
            "instrumentation_overhead": { "path": "C:\\ProgramData\\t32perf\\build\\overhead.json", "sha256": "8".repeat(64) }
        }
    });
    assert!(parse(&complete).is_ok());

    let mut partial_program_flow = complete.clone();
    partial_program_flow["performance_run"]["resources"]["program_flow"]
        .as_object_mut()
        .unwrap()
        .remove("task_events_mapping_template");
    assert!(parse(&partial_program_flow).is_err());

    let mut partial_custom_events = complete.clone();
    partial_custom_events["performance_run"]["resources"]["custom_events"]
        .as_object_mut()
        .unwrap()
        .remove("instrumentation_overhead");
    assert!(parse(&partial_custom_events).is_err());

    let mut resource_unknown = complete;
    resource_unknown["performance_run"]["resources"]["linker_map"]["artifact_id"] =
        json!("forbidden");
    assert!(parse(&resource_unknown).is_err());
}

#[test]
fn unknown_and_duplicate_members_are_rejected_recursively() {
    let mut unknown = valid_document();
    unknown["unexpected"] = json!(true);
    assert!(parse(&unknown).is_err());

    let mut nested_unknown = valid_document();
    nested_unknown["fault_actions"]["unexpected"] = json!({});
    assert!(parse(&nested_unknown).is_err());

    let mut performance_unknown = valid_document();
    performance_unknown["performance_run"]["attestation"]["caller_policy_override"] =
        json!("forbidden");
    assert!(parse(&performance_unknown).is_err());

    let mut qualification_unknown = valid_document();
    qualification_unknown["performance_run"]["qualification"]["trust_store_path"] =
        json!("forbidden");
    assert!(parse(&qualification_unknown).is_err());

    let mut resources_unknown = valid_document();
    resources_unknown["performance_run"]["resources"] = json!({ "unknown": true });
    assert!(parse(&resources_unknown).is_err());

    let duplicate_top = format!(
        r#"{{"schema":"{0}","schema":"{0}"}}"#,
        T32MCP_DRIVER_CONFIG_SCHEMA
    );
    assert!(parse_t32mcp_driver_config(duplicate_top.as_bytes()).is_err());

    let duplicate_nested = format!(
        r#"{{"schema":"{schema}","executable":"t32mcp","skills_root":"skills","trace32_port":20000,"expected_t32mcp_version":"0.2.2","expected_bundle_sha256":"{digest}","poll_interval_ms":100,"operation_timeout_ms":1000,"max_stderr_bytes":1024,"fault_actions":{{"trace32_disconnect_at_stop":{{"executable":"x","executable":"y","arguments":["{{transaction_id}}","{{binding_sha256}}"],"timeout_ms":1000}}}}}}"#,
        schema = T32MCP_DRIVER_CONFIG_SCHEMA,
        digest = "a".repeat(64),
    );
    assert!(parse_t32mcp_driver_config(duplicate_nested.as_bytes()).is_err());
}

#[test]
fn numeric_and_collection_bounds_are_enforced() {
    for (pointer, invalid) in [
        ("/trace32_port", json!(0)),
        ("/poll_interval_ms", json!(9)),
        ("/poll_interval_ms", json!(10_001)),
        ("/operation_timeout_ms", json!(99)),
        ("/operation_timeout_ms", json!(3_600_001)),
        ("/max_stderr_bytes", json!(0)),
        ("/max_stderr_bytes", json!(1_048_577)),
        ("/workload/timeout_ms", json!(99)),
        ("/workload/timeout_ms", json!(3_600_001)),
        (
            "/performance_run/attestation/signer_command/timeout_ms",
            json!(99),
        ),
        ("/performance_run/max_duration_ns", json!(0)),
        (
            "/performance_run/max_duration_ns",
            json!(1_800_000_000_001_u64),
        ),
    ] {
        let mut document = valid_document();
        *document.pointer_mut(pointer).unwrap() = invalid;
        assert!(parse(&document).is_err(), "accepted invalid {pointer}");
    }

    let mut too_many_arguments = valid_document();
    too_many_arguments["workload"]["arguments"] =
        Value::Array((0..17).map(|index| json!(format!("arg-{index}"))).collect());
    assert!(parse(&too_many_arguments).is_err());

    let mut oversized_argument = valid_document();
    oversized_argument["workload"]["arguments"][0] = json!("x".repeat(4097));
    assert!(parse(&oversized_argument).is_err());

    let mut empty_executable = valid_document();
    empty_executable["fault_actions"]["trace32_disconnect_at_stop"]["executable"] = json!("");
    assert!(parse(&empty_executable).is_err());

    for pointer in [
        "/workload",
        "/fault_actions/trace32_disconnect_at_stop",
        "/performance_run/workload_command",
        "/performance_run/attestation/signer_command",
    ] {
        let mut missing_digest = valid_document();
        missing_digest
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("expected_executable_sha256");
        assert!(
            parse(&missing_digest).is_err(),
            "accepted command without executable digest at {pointer}"
        );
    }

    let mut non_idempotent = valid_document();
    non_idempotent["performance_run"]["attestation"]["idempotent_by_signing_request_sha256"] =
        json!(false);
    assert!(parse(&non_idempotent).is_err());

    let mut traversal_policy = valid_document();
    traversal_policy["performance_run"]["qualification"]["policy_id"] = json!("../policy");
    assert!(parse(&traversal_policy).is_err());

    let mut short_workload_timeout = valid_document();
    short_workload_timeout["performance_run"]["workload_command"]["timeout_ms"] = json!(300_000);
    assert!(parse(&short_workload_timeout).is_err());
}

#[test]
fn encoded_document_size_is_bounded_before_decoding() {
    assert!(parse_t32mcp_driver_config(&[]).is_err());
    assert!(parse_t32mcp_driver_config(&vec![b' '; MAX_T32MCP_DRIVER_CONFIG_BYTES + 1]).is_err());
}

#[test]
fn only_the_canonical_upstream_version_is_accepted() {
    for version in ["v0.2.2", "0.2.2 ", "0.2.1", "0.2.02"] {
        let mut document = valid_document();
        document["expected_t32mcp_version"] = json!(version);
        assert!(parse(&document).is_err(), "accepted version {version}");
    }
}

#[test]
fn placeholders_are_closed_unique_and_role_bound() {
    let cases = [
        ("/workload/arguments/0", "--root={board_id}"),
        ("/workload/arguments/0", "--root=$(malicious)"),
        ("/workload/arguments/0", "--root={artifact_root"),
        ("/workload/arguments/1", "--session={artifact_root}"),
        (
            "/fault_actions/trace32_disconnect_at_stop/arguments/0",
            "--workload={workload_identity}",
        ),
        (
            "/performance_run/attestation/signer_command/arguments/2",
            "--request={transaction_id}",
        ),
    ];
    for (pointer, replacement) in cases {
        let mut document = valid_document();
        *document.pointer_mut(pointer).unwrap() = json!(replacement);
        assert!(
            parse(&document).is_err(),
            "accepted invalid template {replacement}"
        );
    }

    let mut missing_required = valid_document();
    missing_required["fault_actions"]["trace32_disconnect_at_stop"]["arguments"] =
        json!(["--transaction={transaction_id}"]);
    assert!(parse(&missing_required).is_err());

    let mut missing_signer_binding = valid_document();
    missing_signer_binding["performance_run"]["attestation"]["signer_command"]["arguments"] =
        json!([
            "--session={session_id}",
            "--request={signing_request_path}",
            "--output={attestation_output_path}",
            "--policy={policy_id}",
            "--key={key_id}"
        ]);
    assert!(parse(&missing_signer_binding).is_err());

    let mut missing_duration = valid_document();
    missing_duration["performance_run"]["workload_command"]["arguments"] = json!([
        "--state={initial_target_state}",
        "--workload={workload_identity}"
    ]);
    assert!(parse(&missing_duration).is_err());

    let mut low_level_duration = valid_document();
    low_level_duration["workload"]["arguments"]
        .as_array_mut()
        .unwrap()
        .push(json!("--duration-ns={duration_ns}"));
    assert!(parse(&low_level_duration).is_err());

    let mut retired_driver_disconnect = valid_document();
    retired_driver_disconnect["fault_actions"]["driver_disconnect_at_export"] = json!({
        "executable": "disconnect-driver",
        "expected_executable_sha256": "e".repeat(64),
        "arguments": [
            "--transaction={transaction_id}",
            "--binding={binding_sha256}"
        ],
        "timeout_ms": 1000
    });
    assert!(parse(&retired_driver_disconnect).is_err());

    let mut arbitrary_cmm_abort = valid_document();
    arbitrary_cmm_abort["fault_actions"]["cmm_abort_at_start"] = json!({
        "executable": "arbitrary-abort",
        "arguments": [],
        "timeout_ms": 1000
    });
    assert!(parse(&arbitrary_cmm_abort).is_err());
}

#[test]
fn generated_schema_is_versioned_closed_and_validates_the_corpus() {
    let documents = driver_schema_documents();
    let schema = &documents["t32mcp-driver-config.schema.json"];

    assert_eq!(schema["$id"], T32MCP_DRIVER_CONFIG_SCHEMA);
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["expected_executable_sha256"]["pattern"],
        "^[0-9a-f]{64}$"
    );
    assert_eq!(
        schema["properties"]["expected_t32mcp_version"]["const"],
        EXPECTED_T32MCP_DRIVER_VERSION
    );
    assert_eq!(
        schema["$defs"]["DriverCommand"]["properties"]["arguments"]["items"]["maxLength"],
        4096
    );
    assert_eq!(
        schema["$defs"]["DriverCommand"]["properties"]["expected_executable_sha256"]["pattern"],
        "^[0-9a-f]{64}$"
    );
    assert_eq!(
        schema["$defs"]["DriverAttestationDeployment"]["properties"]["idempotent_by_signing_request_sha256"]
            ["const"],
        true
    );
    assert_eq!(
        schema["$defs"]["DriverPerformanceRunResources"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["$defs"]["DriverPerformanceRunDeployment"]["properties"]["max_duration_ns"]["maximum"],
        1_800_000_000_000_u64
    );
    assert!(
        schema["$defs"]["DriverPerformanceRunProgramFlowResources"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "task_events_mapping_template")
    );
    assert!(
        schema["$defs"]["DriverCommand"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field == "expected_executable_sha256")
    );
    let validator = validator_for(schema).unwrap();
    assert!(validator.is_valid(&valid_document()));

    let mut unknown = valid_document();
    unknown["fault_actions"]["cmm_abort_at_start"] = json!({
        "executable": "arbitrary-abort",
        "arguments": [],
        "timeout_ms": 1000
    });
    assert!(!validator.is_valid(&unknown));

    let mut invalid_version = valid_document();
    invalid_version["expected_t32mcp_version"] = json!("0.2.3");
    assert!(!validator.is_valid(&invalid_version));
}
