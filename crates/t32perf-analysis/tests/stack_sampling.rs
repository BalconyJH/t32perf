use serde_json::json;
use t32perf_analysis::build_folded_stack_profile;
use t32perf_model::{
    DebuggerSymbolizationSource, DebuggerSymbolizationTrust, EndpointFingerprintScheme,
    FirmwareBinding, FirmwareBindingStatus, SamplingAddressSpace, Sha256Digest,
    StackCaptureRequest, StackDriverEvent, StackDriverEventDetails, StackDriverEventSchemaVersion,
    StackDriverOwner, StackDriverTrue, StackFrameOrder, StackSample, StackSampleFrame,
    StackSampleTermination, StackSamples, StackSamplesSchemaVersion, StackSamplingMethod,
    TargetExecutionState, validate_successful_stack_event_sequence,
};

fn digest(character: char) -> Sha256Digest {
    Sha256Digest::new(character.to_string().repeat(64)).unwrap()
}

fn frame(depth: u32, pc: u64, name: &str) -> StackSampleFrame {
    StackSampleFrame {
        depth,
        pc,
        function_name: Some(name.to_owned()),
        source_file: None,
        source_line: None,
    }
}

fn samples() -> StackSamples {
    StackSamples {
        schema: StackSamplesSchemaVersion,
        session_id: "session-01".to_owned(),
        endpoint_fingerprint: digest('a'),
        endpoint_fingerprint_scheme: EndpointFingerprintScheme::T32PerfEndpointFingerprintV2,
        trace32: "R.2026.02".to_owned(),
        cpu: "CortexM0+".to_owned(),
        core_id: 0,
        address_space: SamplingAddressSpace::P,
        method: StackSamplingMethod::BreakFrameWalk,
        intrusive: true,
        frame_order: StackFrameOrder::LeafToRoot,
        requested_duration_ms: 100,
        observed_duration_ms: 101,
        requested_sample_period_ms: 10,
        max_samples: 4,
        max_frames: 4,
        attempted_samples: 3,
        collected_samples: 3,
        total_halt_cycle_duration_ns: 60,
        target_state_before: TargetExecutionState {
            powered: true,
            running: true,
            halted: false,
        },
        target_state_after: TargetExecutionState {
            powered: true,
            running: true,
            halted: false,
        },
        firmware: FirmwareBinding {
            status: FirmwareBindingStatus::Unverified,
            elf_sha256: None,
            proof: None,
        },
        cleanup_complete: true,
        debugger_symbolization_source: DebuggerSymbolizationSource::Trace32SymbolTable,
        debugger_symbolization_trust: DebuggerSymbolizationTrust::DebuggerReported,
        samples: vec![
            StackSample {
                sample_index: 1,
                halt_cycle_duration_ns: 10,
                termination: StackSampleTermination::TerminalUnverified,
                frames: vec![
                    frame(0, 0x30, "leaf"),
                    frame(1, 0x20, "parent"),
                    frame(2, 0x10, "root"),
                ],
            },
            StackSample {
                sample_index: 2,
                halt_cycle_duration_ns: 20,
                termination: StackSampleTermination::TerminalUnverified,
                frames: vec![
                    frame(0, 0x30, "leaf"),
                    frame(1, 0x20, "parent"),
                    frame(2, 0x10, "root"),
                ],
            },
            StackSample {
                sample_index: 3,
                halt_cycle_duration_ns: 30,
                termination: StackSampleTermination::FrameCycle,
                frames: vec![
                    frame(0, 0x30, "leaf"),
                    frame(1, 0x30, "leaf"),
                    frame(2, 0x10, "root"),
                ],
            },
        ],
    }
}

#[test]
fn reverses_and_aggregates_full_observed_paths_deterministically() {
    let raw = samples();
    let profile = build_folded_stack_profile(&raw, digest('b')).unwrap();
    assert_eq!(profile.included_samples, 3);
    assert_eq!(profile.terminal_unverified_samples, 2);
    assert_eq!(profile.truncated_samples, 1);
    assert_eq!(profile.paths.len(), 2);
    assert_eq!(
        profile.paths[0]
            .frames
            .iter()
            .map(|frame| frame.pc)
            .collect::<Vec<_>>(),
        vec![0x10, 0x20, 0x30]
    );
    assert_eq!(profile.paths[0].samples, 2);
    assert_eq!(
        profile.paths[1]
            .frames
            .iter()
            .map(|frame| frame.pc)
            .collect::<Vec<_>>(),
        vec![0x10, 0x30, 0x30]
    );
    assert_eq!(profile.paths[1].samples, 1);
    profile.validate().unwrap();
    assert_eq!(
        profile,
        build_folded_stack_profile(&raw, digest('b')).unwrap()
    );
}

#[test]
fn raw_stack_samples_v1_rejects_an_unselected_core() {
    let mut raw = samples();
    raw.core_id = 1;
    assert!(raw.validate().is_err());
}

#[test]
fn stack_capture_request_v1_rejects_an_unselected_core() {
    let request: StackCaptureRequest = serde_json::from_value(json!({
        "schema": "t32perf.stack-capture-request/v1",
        "acknowledge_intrusive": true,
        "sample_period_ms": 10,
        "duration_ms": 100,
        "max_samples": 1,
        "max_frames": 1,
        "core_id": 1,
        "address_space": "P"
    }))
    .unwrap();
    assert!(request.validate().is_err());
}

fn event(sequence: u64, details: StackDriverEventDetails) -> StackDriverEvent {
    StackDriverEvent {
        schema: StackDriverEventSchemaVersion,
        transaction_id: "123e4567-e89b-42d3-a456-426614174000".to_owned(),
        endpoint_fingerprint: digest('c'),
        endpoint_fingerprint_scheme: EndpointFingerprintScheme::T32PerfEndpointFingerprintV2,
        owner: StackDriverOwner::LauterbachStackSamplingMcpV1,
        sequence,
        observed_at: "2026-09-01T00:00:00Z".to_owned(),
        details,
    }
}

#[test]
fn stack_driver_requires_complete_indexed_break_go_cycles_before_export() {
    let journal = vec![
        event(
            1,
            StackDriverEventDetails::CaptureIntent {
                initial_running: StackDriverTrue,
                duration_ms: 100,
                sample_period_ms: 10,
                max_samples: 2,
                max_frames: 4,
            },
        ),
        event(2, StackDriverEventDetails::BreakIntent { sample_index: 1 }),
        event(
            3,
            StackDriverEventDetails::BreakObserved { sample_index: 1 },
        ),
        event(4, StackDriverEventDetails::GoIntent { sample_index: 1 }),
        event(5, StackDriverEventDetails::GoObserved { sample_index: 1 }),
        event(
            6,
            StackDriverEventDetails::CaptureObserved {
                attempted_samples: 1,
                collected_samples: 1,
            },
        ),
        event(7, StackDriverEventDetails::CleanupIntent { recovery: None }),
        event(8, StackDriverEventDetails::CleanupObserved {}),
        event(9, StackDriverEventDetails::ExportIntent {}),
        event(
            10,
            StackDriverEventDetails::ExportObserved {
                relative_path: "capture/stack.json".parse().unwrap(),
                sha256: digest('d'),
                size_bytes: 12,
            },
        ),
    ];
    let binding = validate_successful_stack_event_sequence(&journal).unwrap();
    assert_eq!(binding.successful_sample_count, 1);
    assert_eq!(binding.attempted_sample_count, 1);
    assert_eq!(binding.event_count, 10);

    let mut wrong_index = journal;
    wrong_index[4].details = StackDriverEventDetails::GoObserved { sample_index: 2 };
    assert!(validate_successful_stack_event_sequence(&wrong_index).is_err());
}
