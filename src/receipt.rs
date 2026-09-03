use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;
use t32perf_analysis::AnalysisCapabilities;
use t32perf_model::{
    ANALYZER_CONTRACT, AdapterInfo, AnalysisStageReceipt, Artifact, CaptureCapabilities,
    CaptureConfigArtifactClaim, CaptureReceipt, CaptureReceiptSchemaVersion, ClockInfo,
    FirmwareInfo, HealthVerdict, MetricSupportEntry, MetricSupportLevel, Sha256Digest, TargetInfo,
};

use crate::app::AppError;
use t32perf_trace32::{ELF_SECTIONS_V1_FLAVOR, GNU_LD_MAP_V1_FLAVOR};

pub const CAPTURE_RECEIPT_ID: &str = "capture-receipt";
pub const SYNTHETIC_RECEIPT_PRODUCER: &str = "t32perf.fixture.synthetic/v1";
pub const ANALYSIS_STAGE_ID: &str = "analysis-stage";
pub const ANALYSIS_STAGE_PRODUCER: &str = "t32perf-analysis";
pub const ANALYSIS_REQUIRED_OUTPUT_IDS: [&str; 3] = ["derived", "health", "analysis-summary"];
pub const STATIC_RAM_ID: &str = "static-ram";
pub const STACK_USAGE_ID: &str = "stack-usage";
pub const STATIC_RAM_GNU_LD_KIND: &str = "static_ram:gnu-ld-map-v1";
pub const STATIC_RAM_ELF_KIND: &str = "static_ram:elf-sections-v1";

pub fn static_ram_artifact_kind(flavor: &str) -> Option<&'static str> {
    match flavor {
        GNU_LD_MAP_V1_FLAVOR => Some(STATIC_RAM_GNU_LD_KIND),
        ELF_SECTIONS_V1_FLAVOR => Some(STATIC_RAM_ELF_KIND),
        _ => None,
    }
}

pub fn static_ram_source_kind(flavor: &str) -> Option<&'static str> {
    match flavor {
        GNU_LD_MAP_V1_FLAVOR => Some("linker_map"),
        ELF_SECTIONS_V1_FLAVOR => Some("firmware_elf"),
        _ => None,
    }
}

pub fn synthetic_capture_receipt(
    session_id: &str,
    request_sha256: Sha256Digest,
    capture_config: CaptureConfigArtifactClaim,
) -> CaptureReceipt {
    let exact = MetricSupportEntry::new(MetricSupportLevel::Exact);
    let unavailable_samples = MetricSupportEntry {
        support: MetricSupportLevel::Unavailable,
        reasons: vec!["synthetic provider does not emit PC samples".to_owned()],
    };
    CaptureReceipt {
        schema: CaptureReceiptSchemaVersion,
        session_id: session_id.to_owned(),
        provider: "synthetic".to_owned(),
        mode: "synthetic".to_owned(),
        adapter: AdapterInfo {
            id: "synthetic-v1".to_owned(),
            version: "1".to_owned(),
        },
        target: Some(TargetInfo {
            architecture: Some("synthetic".to_owned()),
            device: Some("t32perf-fixture".to_owned()),
            board: None,
            core_count: Some(1),
            properties: BTreeMap::new(),
        }),
        trace32: None,
        firmware: FirmwareInfo {
            elf_path: None,
            elf_sha256: None,
            build_id: Some("synthetic-fixture-v1".to_owned()),
        },
        clocks: vec![ClockInfo {
            id: "session".to_owned(),
            frequency_hz: Some(1_000_000_000),
            source: Some("synthetic nanosecond clock".to_owned()),
            properties: BTreeMap::new(),
        }],
        covered_cores: vec![0],
        capabilities: CaptureCapabilities {
            function_events: exact.clone(),
            context_switches: exact.clone(),
            interrupt_events: exact.clone(),
            samples: unavailable_samples,
            custom_events: exact.clone(),
            counters: exact,
        },
        health_observations: Vec::new(),
        request_sha256,
        capture_config: Some(capture_config),
        controller_health: None,
        properties: BTreeMap::from([("observation_artifact_id".to_owned(), json!("observations"))]),
    }
}

pub fn validate_trusted_synthetic_receipt(
    receipt: &CaptureReceipt,
    session_id: &str,
    request_sha256: &Sha256Digest,
) -> Result<(), AppError> {
    receipt.validate().map_err(AppError::operational)?;
    if receipt.session_id != session_id
        || receipt.provider != "synthetic"
        || receipt.mode != "synthetic"
        || receipt.adapter.id != "synthetic-v1"
        || &receipt.request_sha256 != request_sha256
    {
        return Err(AppError::operational(
            "synthetic capture receipt identity, provider, or request digest is invalid",
        ));
    }
    if receipt.target.is_none() || receipt.clocks.is_empty() || receipt.firmware.build_id.is_none()
    {
        return Err(AppError::operational(
            "synthetic capture receipt omits required provenance",
        ));
    }
    if receipt.capture_config.is_none() {
        return Err(AppError::operational(
            "synthetic capture receipt omits capture-config provenance",
        ));
    }
    if receipt.properties.get("observation_artifact_id") != Some(&json!("observations")) {
        return Err(AppError::operational(
            "synthetic capture receipt does not identify its canonical observation artifact",
        ));
    }
    Ok(())
}

pub fn analyzer_capabilities(receipt: &CaptureReceipt) -> AnalysisCapabilities {
    AnalysisCapabilities {
        function_events: receipt.capabilities.function_events.clone(),
        context_switches: receipt.capabilities.context_switches.clone(),
        interrupt_events: receipt.capabilities.interrupt_events.clone(),
        samples: receipt.capabilities.samples.clone(),
        resource_counters: receipt.capabilities.counters.clone(),
    }
}

pub fn validate_analysis_stage_receipt(
    receipt: &AnalysisStageReceipt,
    stage_artifact: &Artifact,
    catalog: &[Artifact],
    session_id: &str,
) -> Result<(), AppError> {
    receipt.validate().map_err(AppError::operational)?;
    if receipt.session_id != session_id {
        return Err(AppError::operational(
            "analysis stage receipt belongs to a different session",
        ));
    }
    if receipt.contracts.analyzer != ANALYZER_CONTRACT
        || receipt.tool.name != "t32perf"
        || receipt.contracts.health_policy != "t32perf.health-policy/v1"
    {
        return Err(AppError::operational(
            "analysis stage receipt declares an unsupported analyzer, tool, or health-policy contract",
        ));
    }
    if stage_artifact.id != ANALYSIS_STAGE_ID
        || stage_artifact.kind != "analysis_stage"
        || stage_artifact.relative_path.as_str() != "analysis/stage.json"
        || stage_artifact.media_type != "application/json"
        || stage_artifact.producer != ANALYSIS_STAGE_PRODUCER
    {
        return Err(AppError::operational(
            "analysis stage artifact identity, path, media type, kind, or producer is invalid",
        ));
    }

    for claim in receipt
        .input_artifacts
        .iter()
        .chain(&receipt.output_artifacts)
    {
        let registered = catalog
            .iter()
            .find(|artifact| artifact.id == claim.id)
            .ok_or_else(|| {
                AppError::operational(format!(
                    "analysis stage receipt claims missing artifact `{}`",
                    claim.id
                ))
            })?;
        if registered != claim {
            return Err(AppError::operational(format!(
                "analysis stage receipt claim for artifact `{}` does not exactly match the catalog",
                claim.id
            )));
        }
    }

    let inputs = receipt
        .input_artifacts
        .iter()
        .map(|artifact| artifact.id.as_str())
        .collect::<BTreeSet<_>>();
    if !inputs.contains("observations") || !inputs.contains(CAPTURE_RECEIPT_ID) {
        return Err(AppError::operational(
            "analysis stage receipt omits the observations or capture-receipt input claim",
        ));
    }
    let outputs = receipt
        .output_artifacts
        .iter()
        .map(|artifact| artifact.id.as_str())
        .collect::<BTreeSet<_>>();
    let required = ANALYSIS_REQUIRED_OUTPUT_IDS
        .into_iter()
        .collect::<BTreeSet<_>>();
    let allowed = ANALYSIS_REQUIRED_OUTPUT_IDS
        .into_iter()
        .chain(["hotspots", STATIC_RAM_ID, STACK_USAGE_ID])
        .collect::<BTreeSet<_>>();
    if !required.is_subset(&outputs) || !outputs.is_subset(&allowed) {
        return Err(AppError::operational(
            "analysis stage receipt has missing or unknown output claims",
        ));
    }
    if receipt.health_verdict == HealthVerdict::Valid {
        if !outputs.contains("hotspots") {
            return Err(AppError::operational(
                "a VALID analysis stage receipt must claim a hotspots artifact",
            ));
        }
    } else if outputs.contains("hotspots") {
        return Err(AppError::operational(
            "a nonvalid analysis stage receipt must not claim a quantitative hotspots artifact",
        ));
    }

    for claim in &receipt.output_artifacts {
        if claim.id == STATIC_RAM_ID {
            if !matches!(
                claim.kind.as_str(),
                STATIC_RAM_GNU_LD_KIND | STATIC_RAM_ELF_KIND
            ) || claim.producer != "t32perf-static-ram"
            {
                return Err(AppError::operational(format!(
                    "analysis output artifact `{}` has an unexpected kind or producer",
                    claim.id
                )));
            }
            continue;
        }
        let expected = match claim.id.as_str() {
            "derived" => ("derived", ANALYSIS_STAGE_PRODUCER),
            "health" => ("health", ANALYSIS_STAGE_PRODUCER),
            "hotspots" => ("hotspots", ANALYSIS_STAGE_PRODUCER),
            "analysis-summary" => ("analysis_summary", ANALYSIS_STAGE_PRODUCER),
            STACK_USAGE_ID => ("stack_usage:gcc-stack-usage-v1", "t32perf-stack-usage"),
            _ => unreachable!("allowed output IDs were checked above"),
        };
        if claim.kind != expected.0 || claim.producer != expected.1 {
            return Err(AppError::operational(format!(
                "analysis output artifact `{}` has an unexpected kind or producer",
                claim.id
            )));
        }
    }

    let expected_stage_inputs = receipt
        .input_artifacts
        .iter()
        .chain(&receipt.output_artifacts)
        .map(|artifact| artifact.id.clone())
        .collect::<Vec<_>>();
    if stage_artifact.input_artifact_ids != expected_stage_inputs {
        return Err(AppError::operational(
            "analysis stage artifact provenance does not exactly match its receipt claims",
        ));
    }
    Ok(())
}
