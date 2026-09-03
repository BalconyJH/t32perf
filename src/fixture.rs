use std::collections::BTreeMap;

use serde_json::json;
use t32perf_model::{
    AdapterInfo, Artifact, ArtifactPath, CaptureConfigDocument, CaptureConfigSchemaVersion,
    CaptureDurationConfig, CaptureRtosAwarenessConfig, CaptureSinkConfig, CaptureTimestampConfig,
    CaptureTriggerConfig, ContextKind, CounterSemantic, CounterSubject, DictionaryEntry,
    InitialTargetState, Observation, ObservationDictionary, ObservationEvent,
    ObservationStreamHeader, Quality,
};
use t32perf_session::{ArtifactSpec, Session, SessionLock};
use t32perf_trace32::{
    LineLimits, NdjsonObservationWriter, ObservationSource, SyntheticConfig, SyntheticSource,
};

use crate::{
    app::AppError,
    capture_config::{
        CAPTURE_CONFIG_ID, CAPTURE_CONFIG_KIND, CAPTURE_CONFIG_PATH,
        SYNTHETIC_CAPTURE_CONFIG_PRODUCER, capture_config_claim,
    },
    receipt::{CAPTURE_RECEIPT_ID, synthetic_capture_receipt},
};

pub struct GeneratedFixture {
    pub capture_config: Artifact,
    pub observations: Artifact,
    pub capture_receipt: Artifact,
    pub event_count: u64,
}

pub fn generate(
    session: &Session,
    lock: &SessionLock,
    event_count: u64,
) -> Result<GeneratedFixture, AppError> {
    let capture_config_document = synthetic_capture_config(session.id().as_str(), event_count);
    let capture_config = session
        .write_json_artifact(
            lock,
            ArtifactSpec {
                id: CAPTURE_CONFIG_ID.to_owned(),
                kind: CAPTURE_CONFIG_KIND.to_owned(),
                relative_path: ArtifactPath::new(CAPTURE_CONFIG_PATH)
                    .map_err(AppError::operational)?,
                media_type: "application/json".to_owned(),
                producer: SYNTHETIC_CAPTURE_CONFIG_PRODUCER.to_owned(),
                input_artifact_ids: Vec::new(),
            },
            &capture_config_document,
        )
        .map_err(AppError::operational)?;
    let dictionary = dictionary(session.id().as_str());
    let writer = session
        .create_artifact(
            lock,
            artifact_spec(
                "observations",
                "observations",
                "normalized/observations.ndjson",
                "application/x-ndjson",
            )?,
        )
        .map_err(AppError::operational)?;
    let header = ObservationStreamHeader::ndjson(session.id().as_str());
    let default_limits = LineLimits::default();
    let dictionary_record_count = u64::try_from(dictionary.entries.len()).map_err(|_| {
        AppError::operational("synthetic dictionary record count exceeds the supported u64 range")
    })?;
    let mut writer = NdjsonObservationWriter::new(
        writer,
        &header,
        &dictionary,
        LineLimits {
            max_line_bytes: default_limits.max_line_bytes,
            max_records: event_count
                .checked_add(dictionary_record_count)
                .and_then(|count| count.checked_add(1))
                .ok_or_else(|| {
                    AppError::operational(
                        "synthetic event count overflows NDJSON record accounting",
                    )
                })?,
            max_dictionary_entries: default_limits.max_dictionary_entries,
            max_dictionary_bytes: default_limits.max_dictionary_bytes,
        },
    )
    .map_err(AppError::operational)?;
    let mut source_config = SyntheticConfig::new("synthetic", event_count);
    source_config.step_ns = 1_000;
    let mut source = SyntheticSource::new(source_config).map_err(AppError::operational)?;
    while let Some(ordered) = source.next_observation().map_err(AppError::operational)? {
        let observation = synthetic_observation(ordered.observation, event_count);
        writer
            .write_observation(&observation)
            .map_err(AppError::operational)?;
    }
    let writer = writer.finish().map_err(AppError::operational)?;
    let observations_artifact = session
        .commit_artifact(lock, writer)
        .map_err(AppError::operational)?;
    let capture_receipt = session
        .write_json_artifact(
            lock,
            ArtifactSpec {
                id: CAPTURE_RECEIPT_ID.to_owned(),
                kind: "capture_receipt".to_owned(),
                relative_path: ArtifactPath::new("capture/capture-receipt.json")
                    .map_err(AppError::operational)?,
                media_type: "application/json".to_owned(),
                producer: "t32perf.fixture.synthetic/v1".to_owned(),
                input_artifact_ids: vec![
                    observations_artifact.id.clone(),
                    capture_config.id.clone(),
                ],
            },
            &synthetic_capture_receipt(
                session.id().as_str(),
                session.request_sha256().map_err(AppError::operational)?,
                capture_config_claim(&capture_config, &capture_config_document)
                    .map_err(AppError::operational)?,
            ),
        )
        .map_err(AppError::operational)?;

    Ok(GeneratedFixture {
        capture_config,
        observations: observations_artifact,
        capture_receipt,
        event_count,
    })
}

fn synthetic_capture_config(session_id: &str, event_count: u64) -> CaptureConfigDocument {
    CaptureConfigDocument {
        schema: CaptureConfigSchemaVersion,
        session_id: session_id.to_owned(),
        provider: "synthetic".to_owned(),
        adapter: AdapterInfo {
            id: "synthetic-v1".to_owned(),
            version: "1".to_owned(),
        },
        mode: "synthetic".to_owned(),
        covered_cores: vec![0],
        sink: CaptureSinkConfig {
            kind: "synthetic_memory".to_owned(),
            id: "fixture-buffer".to_owned(),
            capacity_bytes: None,
            stream_destination_identity: None,
        },
        timestamp: CaptureTimestampConfig {
            enabled: true,
            clock_id: Some("session".to_owned()),
        },
        filters: Vec::new(),
        trigger: CaptureTriggerConfig {
            kind: "immediate".to_owned(),
            pre_trigger_ns: None,
            post_trigger_ns: None,
            condition_identity: None,
        },
        duration: CaptureDurationConfig {
            duration_ns: None,
            observation_limit: Some(event_count),
        },
        workload_identity: "t32perf.synthetic-fixture/v1".to_owned(),
        initial_target_state: InitialTargetState::Running,
        rtos_awareness: CaptureRtosAwarenessConfig {
            kind: "none".to_owned(),
            metadata_artifact_ids: Vec::new(),
        },
        instrumentation: None,
        adapter_parameters: BTreeMap::from([
            ("event_count".to_owned(), json!(event_count)),
            ("step_ns".to_owned(), json!(1_000_u64)),
        ]),
    }
}

fn dictionary(session_id: &str) -> ObservationDictionary {
    let mut dictionary = ObservationDictionary::new(session_id);
    dictionary.entries = vec![
        DictionaryEntry::DefineContext {
            id: "core-0".to_owned(),
            kind: ContextKind::Core,
            name: "Synthetic Core 0".to_owned(),
            core_id: Some(0),
            priority: None,
        },
        DictionaryEntry::DefineContext {
            id: "task-main".to_owned(),
            kind: ContextKind::Task,
            name: "Synthetic Main".to_owned(),
            core_id: Some(0),
            priority: Some(1),
        },
        DictionaryEntry::DefineFunction {
            id: "function-work".to_owned(),
            name: "synthetic_work".to_owned(),
            module: Some("synthetic-fixture".to_owned()),
            address: Some(0x1000),
            file: Some("fixture/synthetic.c".to_owned()),
            line: Some(1),
        },
        DictionaryEntry::DefineCounter {
            id: "counter-7f3a".to_owned(),
            name: "Synthetic gauge".to_owned(),
            unit: Some("bytes".to_owned()),
            description: Some("Deterministic synthetic resource counter".to_owned()),
            semantic: Some(
                CounterSemantic::new(CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES)
                    .expect("built-in semantic is valid"),
            ),
            subject: Some(CounterSubject::Allocator {
                allocator_id: "system".to_owned(),
            }),
        },
    ];
    dictionary
}

fn synthetic_observation(source: Observation, total: u64) -> Observation {
    let sequence = source.source_seq;
    let ts_ns = source.ts_ns();
    let event = if total <= 2 && sequence + 1 == total {
        ObservationEvent::Instant {
            ts_ns,
            core_id: Some(0),
            context_id: Some("task-main".to_owned()),
            name: "synthetic marker".to_owned(),
            args: BTreeMap::from([("sequence".to_owned(), json!(sequence))]),
        }
    } else if sequence == 0 {
        ObservationEvent::ContextSwitch {
            ts_ns,
            core_id: 0,
            prev_context_id: None,
            next_context_id: "task-main".to_owned(),
            reason: Some("synthetic_start".to_owned()),
        }
    } else if sequence == 1 {
        ObservationEvent::FunctionEnter {
            ts_ns,
            core_id: 0,
            context_id: "task-main".to_owned(),
            function_id: "function-work".to_owned(),
            frame_id: Some("synthetic-frame".to_owned()),
        }
    } else if sequence + 1 == total {
        ObservationEvent::FunctionExit {
            ts_ns,
            core_id: 0,
            context_id: "task-main".to_owned(),
            function_id: "function-work".to_owned(),
            frame_id: Some("synthetic-frame".to_owned()),
        }
    } else if sequence.is_multiple_of(2) {
        ObservationEvent::Counter {
            ts_ns,
            core_id: Some(0),
            context_id: Some("task-main".to_owned()),
            counter_id: "counter-7f3a".to_owned(),
            value: sequence as f64 * 64.0,
            args: BTreeMap::new(),
        }
    } else {
        ObservationEvent::Instant {
            ts_ns,
            core_id: Some(0),
            context_id: Some("task-main".to_owned()),
            name: "synthetic marker".to_owned(),
            args: BTreeMap::from([("sequence".to_owned(), json!(sequence))]),
        }
    };
    Observation::new("synthetic", sequence, Quality::Exact, event)
}

fn artifact_spec(
    id: &str,
    kind: &str,
    relative_path: &str,
    media_type: &str,
) -> Result<ArtifactSpec, AppError> {
    Ok(ArtifactSpec {
        id: id.to_owned(),
        kind: kind.to_owned(),
        relative_path: ArtifactPath::new(relative_path).map_err(AppError::operational)?,
        media_type: media_type.to_owned(),
        producer: "t32perf.fixture.synthetic/v1".to_owned(),
        input_artifact_ids: vec![CAPTURE_CONFIG_ID.to_owned()],
    })
}
