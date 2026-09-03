use t32perf_trace32::{
    PERF_CLEANUP_SCRIPT, PERF_CONFIGURE_SCRIPT, PERF_EXPORT_SCRIPT, PERF_GET_CAPABILITIES_SCRIPT,
    PERF_GET_HEALTH_SCRIPT, PERF_GET_HOTSPOTS_SCRIPT, PERF_START_SCRIPT, PERF_STOP_SCRIPT,
    PerfFrameError, PerfFrameLimits, PerfOperation, PerfStatus, T32PERF_PROTOCOL,
    T32PERF_RESULT_BEGIN, T32PERF_RESULT_END, T32PERF_SKILL_NAME, parse_t32mcp_perf_response,
};

fn wrapper(payload: &str) -> String {
    let payload = serde_json::from_str::<serde_json::Value>(payload)
        .ok()
        .and_then(|mut value| {
            value.as_object_mut()?.insert(
                "binding_sha256".to_owned(),
                serde_json::Value::String("0".repeat(64)),
            );
            serde_json::to_string(&value).ok()
        })
        .unwrap_or_else(|| payload.to_owned());
    raw_wrapper(&payload)
}

fn raw_wrapper(payload: &str) -> String {
    format!("<FINISHED>\n<CONTENT>\n{T32PERF_RESULT_BEGIN}\n{payload}\n{T32PERF_RESULT_END}\n")
}

#[test]
fn fixed_skill_and_script_names_are_typed_and_path_free() {
    assert_eq!(T32PERF_SKILL_NAME, "trace32-perf");
    assert_eq!(
        PerfOperation::ALL
            .into_iter()
            .map(PerfOperation::script_name)
            .collect::<Vec<_>>(),
        vec![
            PERF_GET_CAPABILITIES_SCRIPT,
            PERF_CONFIGURE_SCRIPT,
            PERF_START_SCRIPT,
            PERF_STOP_SCRIPT,
            PERF_GET_HEALTH_SCRIPT,
            PERF_EXPORT_SCRIPT,
            PERF_GET_HOTSPOTS_SCRIPT,
            PERF_CLEANUP_SCRIPT,
        ]
    );
    assert!(
        PerfOperation::ALL
            .into_iter()
            .all(|operation| !operation.script_name().contains(['/', '\\']))
    );
}

#[test]
fn valid_frame_is_parsed_into_typed_fields() {
    let input = wrapper(
        r#"{"protocol":"t32perf/1","operation":"perf_export","status":"OK","code":"raw_ascii_exported"}"#,
    );
    let response = parse_t32mcp_perf_response(&input, PerfFrameLimits::default()).unwrap();
    assert_eq!(response.protocol, T32PERF_PROTOCOL);
    assert_eq!(response.operation, PerfOperation::Export);
    assert_eq!(response.status, PerfStatus::Ok);
    assert_eq!(response.code, "raw_ascii_exported");
    assert_eq!(response.binding_sha256, "0".repeat(64));
}

#[test]
fn initial_target_state_drift_is_closed_and_machine_parseable() {
    for operation in ["perf_configure", "perf_start"] {
        let input = wrapper(&format!(
            r#"{{"protocol":"t32perf/1","operation":"{operation}","status":"INVALID_ARGUMENT","code":"initial_target_state_drift","expected_initial_target_state":"running","observed_target_state":"halted"}}"#
        ));
        let response = parse_t32mcp_perf_response(&input, PerfFrameLimits::default()).unwrap();
        assert_eq!(response.status, PerfStatus::InvalidArgument);
        assert_eq!(response.code, "initial_target_state_drift");
    }

    for payload in [
        r#"{"protocol":"t32perf/1","operation":"perf_start","status":"INVALID_ARGUMENT","code":"initial_target_state_drift","expected_initial_target_state":"running"}"#,
        r#"{"protocol":"t32perf/1","operation":"perf_start","status":"INVALID_ARGUMENT","code":"initial_target_state_drift","expected_initial_target_state":"running","observed_target_state":"running"}"#,
        r#"{"protocol":"t32perf/1","operation":"perf_stop","status":"INVALID_ARGUMENT","code":"initial_target_state_drift","expected_initial_target_state":"running","observed_target_state":"halted"}"#,
        r#"{"protocol":"t32perf/1","operation":"perf_start","status":"OK","code":"started","expected_initial_target_state":"running","observed_target_state":"halted"}"#,
    ] {
        assert!(parse_t32mcp_perf_response(&wrapper(payload), PerfFrameLimits::default()).is_err());
    }
}

#[test]
fn missing_or_invalid_controller_binding_is_rejected() {
    let missing = raw_wrapper(
        r#"{"protocol":"t32perf/1","operation":"perf_export","status":"OK","code":"raw_ascii_exported"}"#,
    );
    assert!(matches!(
        parse_t32mcp_perf_response(&missing, PerfFrameLimits::default()),
        Err(PerfFrameError::InvalidJson { .. })
    ));

    let invalid = raw_wrapper(
        r#"{"protocol":"t32perf/1","operation":"perf_export","status":"OK","code":"raw_ascii_exported","binding_sha256":"ABC"}"#,
    );
    assert!(matches!(
        parse_t32mcp_perf_response(&invalid, PerfFrameLimits::default()),
        Err(PerfFrameError::InvalidBinding { .. })
    ));
}

#[test]
fn duplicate_status_and_binding_fields_are_rejected() {
    let duplicate_status = raw_wrapper(&format!(
        r#"{{"protocol":"t32perf/1","operation":"perf_export","status":"OK","status":"UNSUPPORTED_NEEDS_TRACE32","code":"raw_ascii_exported","binding_sha256":"{}"}}"#,
        "0".repeat(64)
    ));
    assert!(matches!(
        parse_t32mcp_perf_response(&duplicate_status, PerfFrameLimits::default()),
        Err(PerfFrameError::InvalidJson { .. })
    ));

    let duplicate_binding = raw_wrapper(&format!(
        r#"{{"protocol":"t32perf/1","operation":"perf_export","status":"OK","code":"raw_ascii_exported","binding_sha256":"{}","binding_sha256":"{}"}}"#,
        "0".repeat(64),
        "1".repeat(64)
    ));
    assert!(matches!(
        parse_t32mcp_perf_response(&duplicate_binding, PerfFrameLimits::default()),
        Err(PerfFrameError::InvalidJson { .. })
    ));
}

#[test]
fn version_one_success_codes_are_reserved_for_evidence_backed_adapters() {
    for (operation, code) in [
        ("perf_get_capabilities", "capabilities_exported"),
        ("perf_configure", "configured"),
        ("perf_start", "started"),
        ("perf_stop", "stopped"),
        ("perf_get_health", "health_exported"),
    ] {
        let response = wrapper(&format!(
            r#"{{"protocol":"t32perf/1","operation":"{operation}","status":"OK","code":"{code}"}}"#
        ));
        assert_eq!(
            parse_t32mcp_perf_response(&response, PerfFrameLimits::default())
                .unwrap()
                .status,
            PerfStatus::Ok
        );
    }

    let cleanup = wrapper(
        r#"{"protocol":"t32perf/1","operation":"perf_cleanup","status":"OK","code":"cleanup_completed","files_deleted":false}"#,
    );
    assert_eq!(
        parse_t32mcp_perf_response(&cleanup, PerfFrameLimits::default())
            .unwrap()
            .status,
        PerfStatus::Ok
    );
}

#[test]
fn missing_and_duplicate_markers_are_rejected() {
    let missing_begin = format!("<FINISHED>\n<CONTENT>\n{{}}\n{T32PERF_RESULT_END}\n");
    assert_eq!(
        parse_t32mcp_perf_response(&missing_begin, PerfFrameLimits::default()),
        Err(PerfFrameError::MissingBeginMarker)
    );

    let duplicate_begin = format!(
        "<FINISHED>\n<CONTENT>\n{T32PERF_RESULT_BEGIN}\n{T32PERF_RESULT_BEGIN}\n{{}}\n{T32PERF_RESULT_END}\n"
    );
    assert_eq!(
        parse_t32mcp_perf_response(&duplicate_begin, PerfFrameLimits::default()),
        Err(PerfFrameError::DuplicateBeginMarker)
    );

    let missing_end = format!("<FINISHED>\n<CONTENT>\n{T32PERF_RESULT_BEGIN}\n{{}}\n");
    assert_eq!(
        parse_t32mcp_perf_response(&missing_end, PerfFrameLimits::default()),
        Err(PerfFrameError::MissingEndMarker)
    );

    let duplicate_end = format!(
        "<FINISHED>\n<CONTENT>\n{T32PERF_RESULT_BEGIN}\n{{}}\n{T32PERF_RESULT_END}\n{T32PERF_RESULT_END}\n"
    );
    assert_eq!(
        parse_t32mcp_perf_response(&duplicate_end, PerfFrameLimits::default()),
        Err(PerfFrameError::DuplicateEndMarker)
    );

    let duplicate_content = format!(
        "<FINISHED>\n<CONTENT>\n<CONTENT>\n{T32PERF_RESULT_BEGIN}\n{{}}\n{T32PERF_RESULT_END}\n"
    );
    assert_eq!(
        parse_t32mcp_perf_response(&duplicate_content, PerfFrameLimits::default()),
        Err(PerfFrameError::DuplicateContentMarker)
    );
}

#[test]
fn marker_external_output_is_protocol_contamination() {
    let before = format!(
        "<FINISHED>\n<CONTENT>\nunexpected\n{T32PERF_RESULT_BEGIN}\n{{}}\n{T32PERF_RESULT_END}\n"
    );
    assert!(matches!(
        parse_t32mcp_perf_response(&before, PerfFrameLimits::default()),
        Err(PerfFrameError::ProtocolContamination { line: 3, .. })
    ));

    let after = format!(
        "<FINISHED>\n<CONTENT>\n{T32PERF_RESULT_BEGIN}\n{{}}\n{T32PERF_RESULT_END}\nnoise\n"
    );
    assert!(matches!(
        parse_t32mcp_perf_response(&after, PerfFrameLimits::default()),
        Err(PerfFrameError::ProtocolContamination { .. })
    ));
}

#[test]
fn payload_size_is_bounded_before_json_parsing() {
    let input = wrapper(&"x".repeat(17));
    assert_eq!(
        parse_t32mcp_perf_response(
            &input,
            PerfFrameLimits {
                max_payload_bytes: 16
            }
        ),
        Err(PerfFrameError::PayloadTooLarge {
            limit: 16,
            actual: 17
        })
    );
}

#[test]
fn unknown_operation_status_code_and_fields_are_rejected() {
    let unknown_protocol = wrapper(
        r#"{"protocol":"t32perf/2","operation":"perf_export","status":"OK","code":"raw_ascii_exported"}"#,
    );
    assert!(matches!(
        parse_t32mcp_perf_response(&unknown_protocol, PerfFrameLimits::default()),
        Err(PerfFrameError::InvalidProtocol { .. })
    ));

    let unknown_operation = wrapper(
        r#"{"protocol":"t32perf/1","operation":"perf_magic","status":"OK","code":"raw_ascii_exported"}"#,
    );
    assert!(matches!(
        parse_t32mcp_perf_response(&unknown_operation, PerfFrameLimits::default()),
        Err(PerfFrameError::UnknownOperation { .. })
    ));

    let unknown_status = wrapper(
        r#"{"protocol":"t32perf/1","operation":"perf_export","status":"MAYBE","code":"raw_ascii_exported"}"#,
    );
    assert!(matches!(
        parse_t32mcp_perf_response(&unknown_status, PerfFrameLimits::default()),
        Err(PerfFrameError::UnknownStatus { .. })
    ));

    let unknown_code = wrapper(
        r#"{"protocol":"t32perf/1","operation":"perf_export","status":"OK","code":"magic"}"#,
    );
    assert!(matches!(
        parse_t32mcp_perf_response(&unknown_code, PerfFrameLimits::default()),
        Err(PerfFrameError::UnknownCode { .. })
    ));

    let mismatched_status = wrapper(
        r#"{"protocol":"t32perf/1","operation":"perf_export","status":"HOST_PROCESSING_REQUIRED","code":"raw_ascii_exported"}"#,
    );
    assert!(matches!(
        parse_t32mcp_perf_response(&mismatched_status, PerfFrameLimits::default()),
        Err(PerfFrameError::CodeStatusMismatch { .. })
    ));

    let unknown_field = wrapper(
        r#"{"protocol":"t32perf/1","operation":"perf_export","status":"OK","code":"raw_ascii_exported","future":true}"#,
    );
    assert!(matches!(
        parse_t32mcp_perf_response(&unknown_field, PerfFrameLimits::default()),
        Err(PerfFrameError::UnknownField { .. })
    ));
}

#[test]
fn unfinished_and_cleanup_deletion_responses_fail_closed() {
    let unfinished =
        format!("<NOT FINISHED>\n<CONTENT>\n{T32PERF_RESULT_BEGIN}\n{{}}\n{T32PERF_RESULT_END}\n");
    assert_eq!(
        parse_t32mcp_perf_response(&unfinished, PerfFrameLimits::default()),
        Err(PerfFrameError::NotFinished)
    );

    let deleted = wrapper(
        r#"{"protocol":"t32perf/1","operation":"perf_cleanup","status":"UNSUPPORTED_NEEDS_TRACE32","code":"target_cleanup_required","files_deleted":true}"#,
    );
    assert_eq!(
        parse_t32mcp_perf_response(&deleted, PerfFrameLimits::default()),
        Err(PerfFrameError::CleanupDeletedFiles)
    );

    let invalid_arguments = wrapper(
        r#"{"protocol":"t32perf/1","operation":"perf_cleanup","status":"INVALID_ARGUMENT","code":"invalid_arguments"}"#,
    );
    assert_eq!(
        parse_t32mcp_perf_response(&invalid_arguments, PerfFrameLimits::default())
            .unwrap()
            .files_deleted,
        None
    );

    let safe_cleanup = wrapper(
        r#"{"protocol":"t32perf/1","operation":"perf_cleanup","status":"UNSUPPORTED_NEEDS_TRACE32","code":"target_cleanup_required","files_deleted":false}"#,
    );
    assert_eq!(
        parse_t32mcp_perf_response(&safe_cleanup, PerfFrameLimits::default())
            .unwrap()
            .files_deleted,
        Some(false)
    );

    let missing_cleanup_evidence = wrapper(
        r#"{"protocol":"t32perf/1","operation":"perf_cleanup","status":"UNSUPPORTED_NEEDS_TRACE32","code":"target_cleanup_required"}"#,
    );
    assert!(matches!(
        parse_t32mcp_perf_response(&missing_cleanup_evidence, PerfFrameLimits::default()),
        Err(PerfFrameError::InvalidJson { .. })
    ));
}

#[test]
fn only_the_exact_pending_wrapper_grammar_is_not_finished() {
    for unfinished in [
        "<NOT FINISHED>\n<CONTENT>\n".to_owned(),
        "<NOT FINISHED>\n<CONTENT>\nbounded progress\n".to_owned(),
    ] {
        assert_eq!(
            parse_t32mcp_perf_response(&unfinished, PerfFrameLimits::default()),
            Err(PerfFrameError::NotFinished)
        );
    }

    for malformed in [
        "<NOT FINISHED>\n",
        "<NOT FINISHED>\nnoise\n<CONTENT>\n",
        "<NOT FINISHED>\n<CONTENT>\n<CONTENT>\n",
        "<NOT FINISHED>\n<CONTENT>\n<FINISHED>\n",
        "<NOT FINISHED>\n<CONTENT>\n<NOT FINISHED>\n",
    ] {
        assert!(
            !matches!(
                parse_t32mcp_perf_response(malformed, PerfFrameLimits::default()),
                Err(PerfFrameError::NotFinished)
            ),
            "malformed wrapper was incorrectly classified as pending: {malformed:?}"
        );
    }
}
