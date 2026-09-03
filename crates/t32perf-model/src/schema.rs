//! Schema identifiers, version validation, and checked-in schema generation.

use std::{borrow::Cow, collections::BTreeMap};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema, schema_for};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::Value;
use thiserror::Error;

use crate::{
    AnalysisReport, AnalysisStageReceipt, AnalysisSummaryDocument, AttestationSigningRequest,
    CaptureAttestation, CaptureConfigDocument, CaptureReceipt, CaptureTrustPolicy,
    ComparisonReport, DerivedDocument, DerivedStreamHeader, FirmwareBindingEvidence,
    FoldedStackProfile, HealthReport, Heatmap, HotspotReport,
    InstrumentationOverheadEvidenceDocument, Manifest, ObservationDictionary, ObservationDocument,
    PcHitHistogram, PerfRunPayload, PerfSurfaceEnvelope, PerformanceRunRequest,
    SamplingCaptureReceipt, SamplingCaptureRequest, SamplingDriverEvent, SamplingEndpointBinding,
    SessionState, StackCaptureAttempt, StackCaptureReceipt, StackCaptureRequest, StackDriverEvent,
    StackSamples, StaticRamConfigDocument,
};

/// Schema identifier for session manifests.
pub const MANIFEST_SCHEMA: &str = "t32perf.manifest/v1";
/// Schema identifier for durable session state.
pub const STATE_SCHEMA: &str = "t32perf.state/v1";
/// Schema identifier for immutable capture receipts.
pub const CAPTURE_RECEIPT_SCHEMA: &str = "t32perf.capture-receipt/v1";
/// Schema identifier for signed external capture attestations.
pub const CAPTURE_ATTESTATION_SCHEMA: &str = "t32perf.capture-attestation/v1";
/// Schema identifier for deployment capture-trust policies.
pub const CAPTURE_TRUST_POLICY_SCHEMA: &str = "t32perf.capture-trust-policy/v1";
/// Schema identifier for authoritative capture configuration documents.
pub const CAPTURE_CONFIG_SCHEMA: &str = "t32perf.capture-config/v1";
/// Schema identifier for immutable instrumentation-overhead evidence.
pub const INSTRUMENTATION_OVERHEAD_EVIDENCE_SCHEMA: &str =
    "t32perf.instrumentation-overhead-evidence/v1";
/// Schema identifier for trace health reports.
pub const HEALTH_SCHEMA: &str = "t32perf.health/v1";
/// Schema identifier for normalized observations.
pub const OBSERVATION_SCHEMA: &str = "t32perf.observation/v1";
/// Schema identifier for explicit normalization configuration.
pub const NORMALIZE_CONFIG_SCHEMA: &str = "t32perf.normalize-config/v1";
/// Schema identifier for observation dictionaries.
pub const DICTIONARY_SCHEMA: &str = "t32perf.dictionary/v1";
/// Schema identifier for derived event data.
pub const DERIVED_SCHEMA: &str = "t32perf.derived/v1";
/// Schema identifier for streaming derived function spans.
pub const DERIVED_STREAM_SCHEMA: &str = "t32perf.derived-stream/v1";
/// Schema identifier for hotspot reports.
pub const HOTSPOTS_SCHEMA: &str = "t32perf.hotspots/v1";
/// Schema identifier for machine-facing analysis summaries.
pub const ANALYSIS_SUMMARY_SCHEMA: &str = "t32perf.analysis-summary/v1";
/// Schema identifier for immutable analysis-stage receipts.
pub const ANALYSIS_STAGE_SCHEMA: &str = "t32perf.analysis-stage/v1";
/// Schema identifier for comparison reports.
pub const COMPARISON_SCHEMA: &str = "t32perf.comparison/v1";
/// Schema identifier for human-facing analysis reports.
pub const REPORT_SCHEMA: &str = "t32perf.report/v1";
/// Schema identifier for exact static-RAM parser configuration artifacts.
pub const STATIC_RAM_CONFIG_SCHEMA: &str = "t32perf.static-ram-config/v1";
/// Schema identifier for the exact host-side `perf_*` façade.
pub const PERF_SURFACE_SCHEMA: &str = "t32perf.perf-surface/v1";
/// Schema identifier for closed performance-run requests.
pub const PERFORMANCE_RUN_REQUEST_SCHEMA: &str = "t32perf.performance-run-request/v1";
/// Schema identifier for closed performance-run response payloads.
pub const PERFORMANCE_RUN_PAYLOAD_SCHEMA: &str = "t32perf.performance-run-payload/v1";
/// Schema identifier for closed attestation signer requests.
pub const ATTESTATION_SIGNING_REQUEST_SCHEMA: &str = "t32perf.attestation-signing-request/v1";
/// Schema identifier for immutable release build and linkage provenance.
pub const RELEASE_PROVENANCE_SCHEMA: &str = "t32perf.release-provenance/v1";
/// Schema identifier for TRACE32 PERF PC-hit histograms.
pub const PC_HIT_HISTOGRAM_SCHEMA: &str = "t32perf.pc-hit-histogram/v1";
/// Schema identifier for coarse statistical heatmaps projected from PC-hit histograms.
pub const HEATMAP_SCHEMA: &str = "t32perf.heatmap/v1";
/// Schema identifier for immutable firmware-binding evidence artifacts.
pub const FIRMWARE_BINDING_EVIDENCE_SCHEMA: &str = "t32perf.firmware-binding-evidence/v1";
/// Schema identifier for sampling endpoint bindings.
pub const SAMPLING_ENDPOINT_BINDING_SCHEMA: &str = "t32perf.sampling-endpoint-binding/v1";
/// Schema identifier for sampling sidecar driver events.
pub const SAMPLING_DRIVER_EVENT_SCHEMA: &str = "t32perf.sampling-driver-event/v1";
/// Schema identifier for host-derived sampling-capture receipts.
pub const SAMPLING_CAPTURE_RECEIPT_SCHEMA: &str = "t32perf.sampling-capture-receipt/v1";
/// Schema identifier for bounded sampling-capture requests.
pub const SAMPLING_CAPTURE_REQUEST_SCHEMA: &str = "t32perf.sampling-capture-request/v1";
/// Schema identifier for explicitly intrusive stack-capture requests.
pub const STACK_CAPTURE_REQUEST_SCHEMA: &str = "t32perf.stack-capture-request/v1";
/// Schema identifier for the durable one-use intrusive capture marker.
pub const STACK_CAPTURE_ATTEMPT_SCHEMA: &str = "t32perf.stack-capture-attempt/v1";
/// Schema identifier for raw intrusive stack samples.
pub const STACK_SAMPLES_SCHEMA: &str = "t32perf.stack-samples/v1";
/// Schema identifier for deterministic folded stack profiles.
pub const FOLDED_STACK_PROFILE_SCHEMA: &str = "t32perf.folded-stack-profile/v1";
/// Schema identifier for append-only intrusive stack-driver events.
pub const STACK_DRIVER_EVENT_SCHEMA: &str = "t32perf.stack-driver-event/v1";
/// Schema identifier for host-derived intrusive stack-capture receipts.
pub const STACK_CAPTURE_RECEIPT_SCHEMA: &str = "t32perf.stack-capture-receipt/v1";

/// An error returned when a document declares an incompatible schema.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SchemaVersionError {
    /// The identifier does not use the `<family>/v<major>` form.
    #[error("invalid schema identifier `{value}`; expected `<family>/v<major>`")]
    InvalidFormat {
        /// The rejected identifier.
        value: String,
    },
    /// The identifier names a different document family.
    #[error("schema family `{actual}` does not match expected family `{expected}`")]
    WrongFamily {
        /// The required family.
        expected: String,
        /// The family found in the document.
        actual: String,
    },
    /// The identifier declares an unsupported major version.
    #[error("schema `{family}` major v{actual} is unsupported; supported major is v{supported}")]
    UnsupportedMajor {
        /// The schema family.
        family: String,
        /// The supported major version.
        supported: u32,
        /// The rejected major version.
        actual: u32,
    },
}

/// Validates a schema identifier against the supported family and major.
///
/// Minor-compatible changes remain within the same `/v1` identifier and may
/// only add optional fields. A different family or major is rejected.
pub fn validate_schema_version(
    actual: &str,
    supported: &'static str,
) -> Result<(), SchemaVersionError> {
    let (actual_family, actual_major) = parse_schema_version(actual)?;
    let (supported_family, supported_major) = parse_schema_version(supported)?;

    if actual_family != supported_family {
        return Err(SchemaVersionError::WrongFamily {
            expected: supported_family.to_owned(),
            actual: actual_family.to_owned(),
        });
    }
    if actual_major != supported_major {
        return Err(SchemaVersionError::UnsupportedMajor {
            family: actual_family.to_owned(),
            supported: supported_major,
            actual: actual_major,
        });
    }
    Ok(())
}

fn parse_schema_version(value: &str) -> Result<(&str, u32), SchemaVersionError> {
    let Some((family, major)) = value.rsplit_once("/v") else {
        return Err(SchemaVersionError::InvalidFormat {
            value: value.to_owned(),
        });
    };
    if family.is_empty()
        || major.is_empty()
        || (major.len() > 1 && major.starts_with('0'))
        || !major.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(SchemaVersionError::InvalidFormat {
            value: value.to_owned(),
        });
    }
    let major = major
        .parse()
        .map_err(|_| SchemaVersionError::InvalidFormat {
            value: value.to_owned(),
        })?;
    Ok((family, major))
}

macro_rules! schema_version_type {
    ($name:ident, $schema:ident, $schema_name:literal, $docs:literal) => {
        #[doc = $docs]
        #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name;

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str($schema)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                validate_schema_version(&value, $schema).map_err(D::Error::custom)?;
                Ok(Self)
            }
        }

        impl JsonSchema for $name {
            fn inline_schema() -> bool {
                true
            }

            fn schema_name() -> Cow<'static, str> {
                Cow::Borrowed($schema_name)
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "const": $schema
                })
            }
        }
    };
}

schema_version_type!(
    ManifestSchemaVersion,
    MANIFEST_SCHEMA,
    "ManifestSchemaVersion",
    "The supported session manifest schema version."
);
schema_version_type!(
    StateSchemaVersion,
    STATE_SCHEMA,
    "StateSchemaVersion",
    "The supported durable session-state schema version."
);
schema_version_type!(
    CaptureReceiptSchemaVersion,
    CAPTURE_RECEIPT_SCHEMA,
    "CaptureReceiptSchemaVersion",
    "The supported immutable capture-receipt schema version."
);
schema_version_type!(
    CaptureAttestationSchemaVersion,
    CAPTURE_ATTESTATION_SCHEMA,
    "CaptureAttestationSchemaVersion",
    "The supported signed capture-attestation schema version."
);
schema_version_type!(
    CaptureTrustPolicySchemaVersion,
    CAPTURE_TRUST_POLICY_SCHEMA,
    "CaptureTrustPolicySchemaVersion",
    "The supported deployment capture-trust-policy schema version."
);
schema_version_type!(
    CaptureConfigSchemaVersion,
    CAPTURE_CONFIG_SCHEMA,
    "CaptureConfigSchemaVersion",
    "The supported authoritative capture-configuration schema version."
);
schema_version_type!(
    InstrumentationOverheadEvidenceSchemaVersion,
    INSTRUMENTATION_OVERHEAD_EVIDENCE_SCHEMA,
    "InstrumentationOverheadEvidenceSchemaVersion",
    "The supported immutable instrumentation-overhead evidence schema version."
);
schema_version_type!(
    HealthSchemaVersion,
    HEALTH_SCHEMA,
    "HealthSchemaVersion",
    "The supported trace-health schema version."
);
schema_version_type!(
    ObservationSchemaVersion,
    OBSERVATION_SCHEMA,
    "ObservationSchemaVersion",
    "The supported normalized-observation schema version."
);
schema_version_type!(
    DictionarySchemaVersion,
    DICTIONARY_SCHEMA,
    "DictionarySchemaVersion",
    "The supported observation-dictionary schema version."
);
schema_version_type!(
    DerivedSchemaVersion,
    DERIVED_SCHEMA,
    "DerivedSchemaVersion",
    "The supported derived-data schema version."
);
schema_version_type!(
    DerivedStreamSchemaVersion,
    DERIVED_STREAM_SCHEMA,
    "DerivedStreamSchemaVersion",
    "The supported streaming derived-span schema version."
);
schema_version_type!(
    HotspotsSchemaVersion,
    HOTSPOTS_SCHEMA,
    "HotspotsSchemaVersion",
    "The supported hotspot-report schema version."
);
schema_version_type!(
    AnalysisSummarySchemaVersion,
    ANALYSIS_SUMMARY_SCHEMA,
    "AnalysisSummarySchemaVersion",
    "The supported machine-facing analysis-summary schema version."
);
schema_version_type!(
    AnalysisStageSchemaVersion,
    ANALYSIS_STAGE_SCHEMA,
    "AnalysisStageSchemaVersion",
    "The supported immutable analysis-stage receipt schema version."
);
schema_version_type!(
    ComparisonSchemaVersion,
    COMPARISON_SCHEMA,
    "ComparisonSchemaVersion",
    "The supported comparison-report schema version."
);
schema_version_type!(
    ReportSchemaVersion,
    REPORT_SCHEMA,
    "ReportSchemaVersion",
    "The supported analysis-report schema version."
);
schema_version_type!(
    StaticRamConfigSchemaVersion,
    STATIC_RAM_CONFIG_SCHEMA,
    "StaticRamConfigSchemaVersion",
    "The supported static-RAM configuration schema version."
);
schema_version_type!(
    PerfSurfaceSchemaVersion,
    PERF_SURFACE_SCHEMA,
    "PerfSurfaceSchemaVersion",
    "The supported exact host-side perf façade schema version."
);
schema_version_type!(
    PerformanceRunRequestSchemaVersion,
    PERFORMANCE_RUN_REQUEST_SCHEMA,
    "PerformanceRunRequestSchemaVersion",
    "The supported closed performance-run request schema version."
);
schema_version_type!(
    AttestationSigningRequestSchemaVersion,
    ATTESTATION_SIGNING_REQUEST_SCHEMA,
    "AttestationSigningRequestSchemaVersion",
    "The supported closed attestation-signing request schema version."
);
schema_version_type!(
    PcHitHistogramSchemaVersion,
    PC_HIT_HISTOGRAM_SCHEMA,
    "PcHitHistogramSchemaVersion",
    "The supported PC-hit histogram schema version."
);
schema_version_type!(
    HeatmapSchemaVersion,
    HEATMAP_SCHEMA,
    "HeatmapSchemaVersion",
    "The supported coarse heatmap schema version."
);
schema_version_type!(
    FirmwareBindingEvidenceSchemaVersion,
    FIRMWARE_BINDING_EVIDENCE_SCHEMA,
    "FirmwareBindingEvidenceSchemaVersion",
    "The supported firmware-binding evidence schema version."
);
schema_version_type!(
    SamplingEndpointBindingSchemaVersion,
    SAMPLING_ENDPOINT_BINDING_SCHEMA,
    "SamplingEndpointBindingSchemaVersion",
    "The supported sampling endpoint-binding schema version."
);
schema_version_type!(
    SamplingDriverEventSchemaVersion,
    SAMPLING_DRIVER_EVENT_SCHEMA,
    "SamplingDriverEventSchemaVersion",
    "The supported sampling-driver event schema version."
);
schema_version_type!(
    SamplingCaptureReceiptSchemaVersion,
    SAMPLING_CAPTURE_RECEIPT_SCHEMA,
    "SamplingCaptureReceiptSchemaVersion",
    "The supported sampling-capture receipt schema version."
);
schema_version_type!(
    SamplingCaptureRequestSchemaVersion,
    SAMPLING_CAPTURE_REQUEST_SCHEMA,
    "SamplingCaptureRequestSchemaVersion",
    "The supported sampling-capture request schema version."
);
schema_version_type!(
    StackCaptureRequestSchemaVersion,
    STACK_CAPTURE_REQUEST_SCHEMA,
    "StackCaptureRequestSchemaVersion",
    "The supported intrusive stack-capture request schema version."
);
schema_version_type!(
    StackCaptureAttemptSchemaVersion,
    STACK_CAPTURE_ATTEMPT_SCHEMA,
    "StackCaptureAttemptSchemaVersion",
    "The supported intrusive stack-capture attempt schema version."
);
schema_version_type!(
    StackSamplesSchemaVersion,
    STACK_SAMPLES_SCHEMA,
    "StackSamplesSchemaVersion",
    "The supported raw intrusive stack-samples schema version."
);
schema_version_type!(
    FoldedStackProfileSchemaVersion,
    FOLDED_STACK_PROFILE_SCHEMA,
    "FoldedStackProfileSchemaVersion",
    "The supported folded-stack profile schema version."
);
schema_version_type!(
    StackDriverEventSchemaVersion,
    STACK_DRIVER_EVENT_SCHEMA,
    "StackDriverEventSchemaVersion",
    "The supported intrusive stack-driver event schema version."
);
schema_version_type!(
    StackCaptureReceiptSchemaVersion,
    STACK_CAPTURE_RECEIPT_SCHEMA,
    "StackCaptureReceiptSchemaVersion",
    "The supported intrusive stack-capture receipt schema version."
);

/// Generates every public v1 JSON Schema document.
///
/// Keys are stable filenames relative to `schemas/v1`. The function is pure
/// so build tooling can compare generated schemas with the checked-in files.
pub fn schema_documents() -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (
            "analysis-stage.schema.json",
            schema_document::<AnalysisStageReceipt>(ANALYSIS_STAGE_SCHEMA),
        ),
        (
            "analysis-summary.schema.json",
            schema_document::<AnalysisSummaryDocument>(ANALYSIS_SUMMARY_SCHEMA),
        ),
        (
            "capture-attestation.schema.json",
            schema_document::<CaptureAttestation>(CAPTURE_ATTESTATION_SCHEMA),
        ),
        (
            "capture-config.schema.json",
            schema_document::<CaptureConfigDocument>(CAPTURE_CONFIG_SCHEMA),
        ),
        (
            "capture-receipt.schema.json",
            schema_document::<CaptureReceipt>(CAPTURE_RECEIPT_SCHEMA),
        ),
        (
            "capture-trust-policy.schema.json",
            schema_document::<CaptureTrustPolicy>(CAPTURE_TRUST_POLICY_SCHEMA),
        ),
        (
            "comparison.schema.json",
            schema_document::<ComparisonReport>(COMPARISON_SCHEMA),
        ),
        (
            "derived.schema.json",
            schema_document::<DerivedDocument>(DERIVED_SCHEMA),
        ),
        (
            "derived-stream.schema.json",
            schema_document::<DerivedStreamHeader>(DERIVED_STREAM_SCHEMA),
        ),
        (
            "firmware-binding-evidence.schema.json",
            schema_document::<FirmwareBindingEvidence>(FIRMWARE_BINDING_EVIDENCE_SCHEMA),
        ),
        (
            "sampling-capture-receipt.schema.json",
            schema_document::<SamplingCaptureReceipt>(SAMPLING_CAPTURE_RECEIPT_SCHEMA),
        ),
        (
            "sampling-capture-request.schema.json",
            schema_document::<SamplingCaptureRequest>(SAMPLING_CAPTURE_REQUEST_SCHEMA),
        ),
        (
            "stack-capture-request.schema.json",
            schema_document::<StackCaptureRequest>(STACK_CAPTURE_REQUEST_SCHEMA),
        ),
        (
            "stack-capture-attempt.schema.json",
            schema_document::<StackCaptureAttempt>(STACK_CAPTURE_ATTEMPT_SCHEMA),
        ),
        (
            "stack-samples.schema.json",
            schema_document::<StackSamples>(STACK_SAMPLES_SCHEMA),
        ),
        (
            "folded-stack-profile.schema.json",
            schema_document::<FoldedStackProfile>(FOLDED_STACK_PROFILE_SCHEMA),
        ),
        (
            "stack-driver-event.schema.json",
            schema_document::<StackDriverEvent>(STACK_DRIVER_EVENT_SCHEMA),
        ),
        (
            "stack-capture-receipt.schema.json",
            schema_document::<StackCaptureReceipt>(STACK_CAPTURE_RECEIPT_SCHEMA),
        ),
        (
            "sampling-driver-event.schema.json",
            schema_document::<SamplingDriverEvent>(SAMPLING_DRIVER_EVENT_SCHEMA),
        ),
        (
            "sampling-endpoint-binding.schema.json",
            schema_document::<SamplingEndpointBinding>(SAMPLING_ENDPOINT_BINDING_SCHEMA),
        ),
        (
            "dictionary.schema.json",
            schema_document::<ObservationDictionary>(DICTIONARY_SCHEMA),
        ),
        (
            "health.schema.json",
            schema_document::<HealthReport>(HEALTH_SCHEMA),
        ),
        (
            "heatmap.schema.json",
            schema_document::<Heatmap>(HEATMAP_SCHEMA),
        ),
        (
            "hotspots.schema.json",
            schema_document::<HotspotReport>(HOTSPOTS_SCHEMA),
        ),
        (
            "instrumentation-overhead-evidence.schema.json",
            schema_document::<InstrumentationOverheadEvidenceDocument>(
                INSTRUMENTATION_OVERHEAD_EVIDENCE_SCHEMA,
            ),
        ),
        (
            "manifest.schema.json",
            schema_document::<Manifest>(MANIFEST_SCHEMA),
        ),
        (
            "normalize-config.schema.json",
            checked_in_normalize_config_schema_document(),
        ),
        (
            "observation.schema.json",
            schema_document::<ObservationDocument>(OBSERVATION_SCHEMA),
        ),
        (
            "perf-surface.schema.json",
            schema_document::<PerfSurfaceEnvelope>(PERF_SURFACE_SCHEMA),
        ),
        (
            "performance-run-request.schema.json",
            schema_document::<PerformanceRunRequest>(PERFORMANCE_RUN_REQUEST_SCHEMA),
        ),
        (
            "performance-run-payload.schema.json",
            schema_document::<PerfRunPayload>(PERFORMANCE_RUN_PAYLOAD_SCHEMA),
        ),
        (
            "pc-hit-histogram.schema.json",
            schema_document::<PcHitHistogram>(PC_HIT_HISTOGRAM_SCHEMA),
        ),
        (
            "attestation-signing-request.schema.json",
            schema_document::<AttestationSigningRequest>(ATTESTATION_SIGNING_REQUEST_SCHEMA),
        ),
        (
            "report.schema.json",
            schema_document::<AnalysisReport>(REPORT_SCHEMA),
        ),
        (
            "release-provenance.schema.json",
            checked_in_release_provenance_schema_document(),
        ),
        (
            "state.schema.json",
            schema_document::<SessionState>(STATE_SCHEMA),
        ),
        (
            "static-ram-config.schema.json",
            schema_document::<StaticRamConfigDocument>(STATIC_RAM_CONFIG_SCHEMA),
        ),
    ])
}

// The CLI owns the private serde representation for this schema. This checked-in
// document is exposed here for schema inventory only; xtask deliberately does
// not treat this value as independently generated drift evidence. The binary
// unit test validates a bidirectional JSON Schema/private-serde corpus.
fn checked_in_normalize_config_schema_document() -> Value {
    let mut schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/v1/normalize-config.schema.json"
    ))
    .expect("checked-in normalization schema is valid JSON");
    schema
        .as_object_mut()
        .expect("normalization schema root is an object")
        .insert(
            "$id".to_owned(),
            Value::String(NORMALIZE_CONFIG_SCHEMA.to_owned()),
        );
    schema
}

// Release packaging is owned by xtask rather than a runtime model type. The
// checked-in document is nevertheless included in the unified public schema
// inventory. xtask validates its exact closed field set and all file claims.
fn checked_in_release_provenance_schema_document() -> Value {
    let mut schema: Value = serde_json::from_str(include_str!(
        "../../../schemas/v1/release-provenance.schema.json"
    ))
    .expect("checked-in release provenance schema is valid JSON");
    schema
        .as_object_mut()
        .expect("release provenance schema root is an object")
        .insert(
            "$id".to_owned(),
            Value::String(RELEASE_PROVENANCE_SCHEMA.to_owned()),
        );
    schema
}

fn schema_document<T: JsonSchema>(id: &'static str) -> Value {
    let mut schema =
        serde_json::to_value(schema_for!(T)).expect("schema serialization is infallible");
    schema
        .as_object_mut()
        .expect("root schemas are objects")
        .insert("$id".to_owned(), Value::String(id.to_owned()));
    schema
}
