//! Health-gated comparison of two completed analysis runs.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use t32perf_model::{
    AnalysisSummaryDocument, ComparisonMetricKind, ComparisonReport, ComparisonSchemaVersion,
    ComparisonSubject, ComparisonSubjectKind, ComparisonVerdict, CounterSemantic, CounterSubject,
    DerivedResourceMetricSummary, FunctionHotspot, HealthReport, HealthSeverity, HealthVerdict,
    HotspotReport, Manifest, MetricComparison, MetricComparisonOutcome, MetricSupportEntry,
    MetricSupportLevel, Quality, ResourceComparisonAggregate, ResourceComparisonDirection,
    ResourceCounterSummary, ResourceMetricComparison, ResourceMetricComparisonOutcome,
    ResourceMetricSource, ResourceSummary, SamplingHotspot, StaticRamAnalysisSummary,
    StaticRamMetricComparison, StaticRamMetricKind,
};

/// References to the manifest, health, hotspot, and versioned summary artifacts of one run.
#[derive(Debug, Clone, Copy)]
pub struct ComparisonInput<'a> {
    /// Session manifest containing capture provenance.
    pub manifest: &'a Manifest,
    /// Host-policy health report.
    pub health: &'a HealthReport,
    /// Health-gated hotspot report.
    pub hotspots: &'a HotspotReport,
    /// Validated, health-gated analysis-summary document.
    pub summary: &'a AnalysisSummaryDocument,
}

/// One explicit dynamic-resource comparison rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceComparisonRule {
    /// Counter semantic selected by this rule.
    pub semantic: CounterSemantic,
    /// Exact subject selected by this rule, or every subject with the semantic when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<CounterSubject>,
    /// Summary aggregate compared across sessions.
    pub aggregate: ResourceComparisonAggregate,
    /// Direction used to classify a material change.
    pub direction: ResourceComparisonDirection,
    /// Absolute change that must be exceeded.
    pub absolute_threshold: f64,
    /// Relative change that must be exceeded when the baseline is nonzero.
    pub relative_threshold: f64,
}

/// Threshold and comparability policy for regression comparison.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComparisonPolicy {
    /// Relative change required for a regression or improvement.
    pub relative_threshold: f64,
    /// Absolute nanosecond change required for time metrics.
    pub absolute_time_threshold_ns: u64,
    /// Absolute change required for count metrics.
    pub absolute_count_threshold: u64,
    /// Whether every compared metric must have exact support.
    pub require_exact_metrics: bool,
    /// Whether equal capture request digests are required when both are present.
    pub require_matching_request: bool,
    /// Whether capture adapter versions must match exactly.
    pub require_same_adapter_version: bool,
    /// Whether the two complete firmware identities must identify the same image.
    #[serde(default)]
    pub require_same_firmware_identity: bool,
    /// Whether both health reports must use the same host-policy contract.
    #[serde(default = "default_true")]
    pub require_same_health_policy_version: bool,
    /// Whether the manifest-producing tool name and version must match.
    #[serde(default = "default_true")]
    pub require_same_tool_contract: bool,
    /// Whether functions added to or removed from a build are compared against zero.
    #[serde(default)]
    pub allow_function_set_changes: bool,
    /// Explicit rules that may affect the verdict for dynamic resources.
    #[serde(default)]
    pub resource_rules: Vec<ResourceComparisonRule>,
    /// Whether configured resource subjects added or removed across sessions are compared with zero.
    #[serde(default)]
    pub allow_resource_subject_set_changes: bool,
    /// Whether statistical sampling shares may be compared heuristically.
    pub compare_statistical_metrics: bool,
    /// Whether target, clock, firmware, and request provenance must be present.
    #[serde(default = "default_true")]
    pub require_complete_provenance: bool,
}

impl Default for ComparisonPolicy {
    fn default() -> Self {
        Self {
            relative_threshold: 0.05,
            absolute_time_threshold_ns: 0,
            absolute_count_threshold: 0,
            require_exact_metrics: true,
            require_matching_request: true,
            require_same_adapter_version: true,
            require_same_firmware_identity: false,
            require_same_health_policy_version: true,
            require_same_tool_contract: true,
            allow_function_set_changes: false,
            resource_rules: default_resource_rules(),
            allow_resource_subject_set_changes: false,
            compare_statistical_metrics: false,
            require_complete_provenance: true,
        }
    }
}

fn default_resource_rules() -> Vec<ResourceComparisonRule> {
    use ResourceComparisonAggregate::{Latest, Max};

    [
        (CounterSemantic::HEAP_CURRENT_ALLOCATED_BYTES, Latest),
        (CounterSemantic::HEAP_PEAK_ALLOCATED_BYTES, Max),
        (CounterSemantic::STACK_PEAK_USED_BYTES, Max),
        (CounterSemantic::RAM_PEAK_USED_BYTES, Max),
        (CounterSemantic::HEAP_EXTERNAL_FRAGMENTATION_RATIO, Latest),
    ]
    .into_iter()
    .map(|(semantic, aggregate)| ResourceComparisonRule {
        semantic: standard_semantic(semantic),
        subject: None,
        aggregate,
        direction: ResourceComparisonDirection::LowerIsBetter,
        absolute_threshold: 0.0,
        relative_threshold: 0.05,
    })
    .collect()
}

fn standard_semantic(value: &str) -> CounterSemantic {
    CounterSemantic::new(value).expect("built-in counter semantic must be valid")
}

/// Compares two sessions after health, metric support, and capture provenance checks.
#[must_use]
pub fn compare_sessions(
    baseline: ComparisonInput<'_>,
    candidate: ComparisonInput<'_>,
    policy: &ComparisonPolicy,
) -> ComparisonReport {
    let mut reasons = comparability_reasons(baseline, candidate, policy);
    if !reasons.is_empty() {
        return inconclusive_report(baseline, candidate, reasons);
    }

    let mut metrics = compare_function_hotspots(
        &baseline.hotspots.functions,
        &candidate.hotspots.functions,
        policy,
        &mut reasons,
    );
    metrics.extend(compare_sampling_hotspots(
        &baseline.hotspots.sampling,
        &candidate.hotspots.sampling,
        policy,
        &mut reasons,
    ));

    let baseline_quantitative = baseline
        .summary
        .quantitative
        .as_ref()
        .expect("validated VALID summary must contain quantitative values");
    let candidate_quantitative = candidate
        .summary
        .quantitative
        .as_ref()
        .expect("validated VALID summary must contain quantitative values");
    let resource_metrics = compare_resource_metrics(
        &baseline_quantitative.analysis.resources,
        &candidate_quantitative.analysis.resources,
        &baseline.summary.metric_support.resource_counters,
        &candidate.summary.metric_support.resource_counters,
        policy,
        &mut reasons,
    );
    let static_ram_metrics = compare_static_ram(
        baseline_quantitative.static_ram.as_ref(),
        candidate_quantitative.static_ram.as_ref(),
        policy,
        &mut reasons,
    );
    let outcomes = comparison_outcomes(&metrics, &resource_metrics, &static_ram_metrics);

    let verdict = if !reasons.is_empty() {
        ComparisonVerdict::Inconclusive
    } else if outcomes.is_empty() {
        reasons.push("no_common_metrics".to_owned());
        ComparisonVerdict::Inconclusive
    } else if outcomes.contains(&MetricComparisonOutcome::Inconclusive) {
        ComparisonVerdict::Inconclusive
    } else if outcomes.contains(&MetricComparisonOutcome::Regressed) {
        ComparisonVerdict::Regressed
    } else if outcomes.contains(&MetricComparisonOutcome::Improved) {
        ComparisonVerdict::Improved
    } else if outcomes
        .iter()
        .all(|outcome| *outcome == MetricComparisonOutcome::Unchanged)
    {
        ComparisonVerdict::Unchanged
    } else {
        ComparisonVerdict::Inconclusive
    };

    ComparisonReport {
        schema: ComparisonSchemaVersion,
        baseline_session_id: baseline.manifest.session_id.clone(),
        candidate_session_id: candidate.manifest.session_id.clone(),
        baseline_health: baseline.health.verdict,
        candidate_health: candidate.health.verdict,
        verdict,
        metrics,
        resource_metrics,
        static_ram_metrics,
        reasons,
    }
}

fn comparability_reasons(
    baseline: ComparisonInput<'_>,
    candidate: ComparisonInput<'_>,
    policy: &ComparisonPolicy,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if !policy.relative_threshold.is_finite() || policy.relative_threshold < 0.0 {
        reasons.push("comparison_policy_invalid".to_owned());
    }
    if !resource_policy_valid(policy) {
        push_reason_once(&mut reasons, "comparison_policy_invalid");
    }
    validate_session_links(baseline, "baseline", &mut reasons);
    validate_session_links(candidate, "candidate", &mut reasons);
    if baseline.manifest.validate().is_err() {
        reasons.push("baseline_manifest_invalid".to_owned());
    }
    if candidate.manifest.validate().is_err() {
        reasons.push("candidate_manifest_invalid".to_owned());
    }
    if !health_report_valid(baseline.health) {
        reasons.push("baseline_health_invalid".to_owned());
    }
    if !health_report_valid(candidate.health) {
        reasons.push("candidate_health_invalid".to_owned());
    }
    if baseline.hotspots.validate().is_err() {
        reasons.push("baseline_hotspots_invalid".to_owned());
    }
    if candidate.hotspots.validate().is_err() {
        reasons.push("candidate_hotspots_invalid".to_owned());
    }
    if baseline.summary.validate().is_err() {
        reasons.push("baseline_summary_invalid".to_owned());
    }
    if candidate.summary.validate().is_err() {
        reasons.push("candidate_summary_invalid".to_owned());
    }

    if baseline.health.verdict != HealthVerdict::Valid {
        reasons.push("baseline_health_not_valid".to_owned());
    }
    if candidate.health.verdict != HealthVerdict::Valid {
        reasons.push("candidate_health_not_valid".to_owned());
    }
    if baseline.summary.health_verdict != HealthVerdict::Valid {
        reasons.push("baseline_summary_not_valid".to_owned());
    }
    if candidate.summary.health_verdict != HealthVerdict::Valid {
        reasons.push("candidate_summary_not_valid".to_owned());
    }
    if baseline.summary.health_verdict != baseline.health.verdict
        || baseline.summary.metric_support != baseline.health.metric_support
    {
        reasons.push("baseline_summary_health_mismatch".to_owned());
    }
    if candidate.summary.health_verdict != candidate.health.verdict
        || candidate.summary.metric_support != candidate.health.metric_support
    {
        reasons.push("candidate_summary_health_mismatch".to_owned());
    }
    if policy.require_same_health_policy_version
        && baseline.health.policy_version != candidate.health.policy_version
    {
        reasons.push("health_policy_version_mismatch".to_owned());
    }
    if policy.require_same_tool_contract
        && (baseline.manifest.tool.name != candidate.manifest.tool.name
            || baseline.manifest.tool.version != candidate.manifest.tool.version)
    {
        reasons.push("tool_contract_mismatch".to_owned());
    }
    if policy.require_complete_provenance
        && [baseline.manifest, candidate.manifest]
            .iter()
            .any(|manifest| {
                manifest.capture.mode.is_empty()
                    || manifest.capture.adapter.id.is_empty()
                    || manifest.capture.adapter.version.is_empty()
            })
    {
        reasons.push("capture_identity_incomplete".to_owned());
    }
    compare_capture_receipt_facts(
        baseline.manifest,
        candidate.manifest,
        policy.require_complete_provenance,
        &mut reasons,
    );
    if baseline.manifest.capture.mode != candidate.manifest.capture.mode {
        reasons.push("capture_mode_mismatch".to_owned());
    }
    if baseline.manifest.capture.adapter.id != candidate.manifest.capture.adapter.id {
        reasons.push("capture_adapter_mismatch".to_owned());
    }
    if policy.require_same_adapter_version
        && baseline.manifest.capture.adapter.version != candidate.manifest.capture.adapter.version
    {
        reasons.push("capture_adapter_version_mismatch".to_owned());
    }
    if !targets_comparable(
        baseline.manifest.capture.target.as_ref(),
        candidate.manifest.capture.target.as_ref(),
        policy.require_complete_provenance,
    ) {
        reasons.push("capture_target_mismatch".to_owned());
    }
    if !clocks_comparable(
        baseline.manifest,
        candidate.manifest,
        policy.require_complete_provenance,
    ) {
        reasons.push("capture_clock_mismatch".to_owned());
    }
    let baseline_firmware = firmware_identity(baseline.manifest);
    let candidate_firmware = firmware_identity(candidate.manifest);
    if policy.require_complete_provenance
        && (baseline_firmware.is_none() || candidate_firmware.is_none())
    {
        reasons.push("capture_firmware_identity_incomplete".to_owned());
    }
    if policy.require_same_firmware_identity
        && !firmware_identities_match(baseline_firmware, candidate_firmware)
    {
        reasons.push("capture_firmware_mismatch".to_owned());
    }
    if !trace32_comparable(
        baseline.manifest,
        candidate.manifest,
        policy.require_complete_provenance,
    ) {
        reasons.push("capture_trace32_mismatch".to_owned());
    }
    match (
        baseline.manifest.capture.request_sha256.as_ref(),
        candidate.manifest.capture.request_sha256.as_ref(),
    ) {
        (Some(baseline_digest), Some(candidate_digest))
            if policy.require_matching_request && baseline_digest != candidate_digest =>
        {
            reasons.push("capture_request_mismatch".to_owned());
        }
        (Some(_), Some(_)) => {}
        (None, None) if !policy.require_complete_provenance => {}
        _ if policy.require_complete_provenance || policy.require_matching_request => {
            reasons.push("capture_request_mismatch".to_owned());
        }
        _ => {}
    }

    for (name, baseline_support, candidate_support) in [
        (
            "call_count",
            &baseline.health.metric_support.call_count,
            &candidate.health.metric_support.call_count,
        ),
        (
            "active",
            &baseline.health.metric_support.active,
            &candidate.health.metric_support.active,
        ),
        (
            "self",
            &baseline.health.metric_support.self_time,
            &candidate.health.metric_support.self_time,
        ),
    ] {
        if !support_comparable(
            baseline_support,
            candidate_support,
            policy.require_exact_metrics,
        ) {
            reasons.push(format!("metric_support_mismatch:{name}"));
        }
    }
    if policy.require_exact_metrics
        && (baseline
            .hotspots
            .functions
            .iter()
            .chain(&candidate.hotspots.functions)
            .any(|row| row.quality != Quality::Exact))
    {
        reasons.push("function_hotspot_quality_not_exact".to_owned());
    }
    reasons
}

fn compare_capture_receipt_facts(
    baseline: &Manifest,
    candidate: &Manifest,
    require_complete: bool,
    reasons: &mut Vec<String>,
) {
    match (
        baseline.capture.provider.as_deref(),
        candidate.capture.provider.as_deref(),
    ) {
        (Some(baseline), Some(candidate)) if baseline != candidate => {
            reasons.push("capture_provider_mismatch".to_owned());
        }
        (Some(_), Some(_)) => {}
        _ if require_complete => reasons.push("capture_provider_incomplete".to_owned()),
        _ => {}
    }

    let baseline_cores = baseline
        .capture
        .covered_cores
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let candidate_cores = candidate
        .capture
        .covered_cores
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if baseline_cores.is_empty() || candidate_cores.is_empty() {
        if require_complete {
            reasons.push("capture_core_coverage_incomplete".to_owned());
        }
    } else if baseline_cores != candidate_cores {
        reasons.push("capture_core_coverage_mismatch".to_owned());
    }

    match (
        baseline.capture.capabilities.as_ref(),
        candidate.capture.capabilities.as_ref(),
    ) {
        (Some(baseline), Some(candidate)) if baseline != candidate => {
            reasons.push("capture_capabilities_mismatch".to_owned());
        }
        (Some(_), Some(_)) => {}
        _ if require_complete => reasons.push("capture_capabilities_incomplete".to_owned()),
        _ => {}
    }

    match (
        baseline.capture.capture_config.as_ref(),
        candidate.capture.capture_config.as_ref(),
    ) {
        (Some(baseline), Some(candidate)) => {
            if baseline.artifact_id != candidate.artifact_id {
                reasons.push("capture_config_artifact_mismatch".to_owned());
            }
            if baseline.configuration_sha256 != candidate.configuration_sha256 {
                reasons.push("capture_config_digest_mismatch".to_owned());
            }
        }
        _ if require_complete => reasons.push("capture_config_incomplete".to_owned()),
        _ => {}
    }
}

fn validate_session_links(input: ComparisonInput<'_>, label: &str, reasons: &mut Vec<String>) {
    if input.health.session_id != input.manifest.session_id {
        reasons.push(format!("{label}_health_session_mismatch"));
    }
    if input.hotspots.session_id != input.manifest.session_id {
        reasons.push(format!("{label}_hotspots_session_mismatch"));
    }
    if input.summary.session_id != input.manifest.session_id {
        reasons.push(format!("{label}_summary_session_mismatch"));
    }
}

fn health_report_valid(report: &HealthReport) -> bool {
    if report.validate().is_err()
        || report.session_id.trim().is_empty()
        || report.policy_version.trim().is_empty()
        || report.observations.iter().any(|observation| {
            observation.code.trim().is_empty() || observation.source.trim().is_empty()
        })
        || report.issues.iter().any(|issue| {
            issue.code.trim().is_empty()
                || issue.source.trim().is_empty()
                || issue.message.trim().is_empty()
        })
    {
        return false;
    }
    let has_invalidating_issue = report.issues.iter().any(|issue| {
        matches!(
            issue.severity,
            HealthSeverity::Error | HealthSeverity::Fatal
        )
    });
    let has_warning = report
        .issues
        .iter()
        .any(|issue| issue.severity == HealthSeverity::Warning);
    match report.verdict {
        HealthVerdict::Valid => !has_warning && !has_invalidating_issue,
        HealthVerdict::Degraded => !has_invalidating_issue,
        HealthVerdict::Invalid => true,
    }
}

fn targets_comparable(
    baseline: Option<&t32perf_model::TargetInfo>,
    candidate: Option<&t32perf_model::TargetInfo>,
    require_complete: bool,
) -> bool {
    match (baseline, candidate) {
        (None, None) => !require_complete,
        (Some(baseline), Some(candidate)) => {
            if require_complete
                && (!present(&baseline.architecture)
                    || !present(&baseline.device)
                    || baseline.core_count.is_none_or(|count| count == 0)
                    || !present(&candidate.architecture)
                    || !present(&candidate.device)
                    || candidate.core_count.is_none_or(|count| count == 0))
            {
                return false;
            }
            baseline.architecture == candidate.architecture
                && baseline.device == candidate.device
                && baseline.board == candidate.board
                && baseline.core_count == candidate.core_count
        }
        _ => false,
    }
}

fn clock_frequencies(manifest: &Manifest) -> BTreeMap<&str, Option<u64>> {
    manifest
        .clocks
        .iter()
        .map(|clock| (clock.id.as_str(), clock.frequency_hz))
        .collect()
}

fn clocks_comparable(baseline: &Manifest, candidate: &Manifest, require_complete: bool) -> bool {
    if require_complete
        && (baseline.clocks.is_empty()
            || candidate.clocks.is_empty()
            || baseline
                .clocks
                .iter()
                .chain(&candidate.clocks)
                .any(|clock| {
                    clock.id.is_empty() || clock.frequency_hz.is_none_or(|frequency| frequency == 0)
                }))
    {
        return false;
    }
    clock_frequencies(baseline) == clock_frequencies(candidate)
}

fn firmware_identity(manifest: &Manifest) -> Option<(&'static str, &str)> {
    manifest
        .firmware
        .elf_sha256
        .as_ref()
        .map(|digest| ("elf", digest.as_str()))
        .or_else(|| {
            manifest
                .firmware
                .build_id
                .as_deref()
                .filter(|build_id| !build_id.is_empty())
                .map(|build_id| ("build", build_id))
        })
}

fn firmware_identities_match(
    baseline: Option<(&str, &str)>,
    candidate: Option<(&str, &str)>,
) -> bool {
    matches!((baseline, candidate), (Some(baseline), Some(candidate)) if baseline == candidate)
}

fn trace32_comparable(baseline: &Manifest, candidate: &Manifest, require_complete: bool) -> bool {
    match (
        baseline.capture.trace32.as_ref(),
        candidate.capture.trace32.as_ref(),
    ) {
        (None, None) => true,
        (Some(baseline), Some(candidate)) => {
            if require_complete
                && (!present(&baseline.build)
                    || !present(&baseline.architecture_package)
                    || !present(&candidate.build)
                    || !present(&candidate.architecture_package))
            {
                return false;
            }
            baseline.build == candidate.build
                && baseline.architecture_package == candidate.architecture_package
        }
        _ => false,
    }
}

fn present(value: &Option<String>) -> bool {
    value.as_deref().is_some_and(|value| !value.is_empty())
}

const fn default_true() -> bool {
    true
}

fn support_comparable(
    baseline: &MetricSupportEntry,
    candidate: &MetricSupportEntry,
    require_exact: bool,
) -> bool {
    if require_exact {
        baseline.support == MetricSupportLevel::Exact
            && candidate.support == MetricSupportLevel::Exact
    } else {
        baseline.support == candidate.support && baseline.support != MetricSupportLevel::Unavailable
    }
}

fn resource_policy_valid(policy: &ComparisonPolicy) -> bool {
    let mut selectors = BTreeSet::new();
    policy.resource_rules.iter().all(|rule| {
        let thresholds_valid = rule.absolute_threshold.is_finite()
            && rule.absolute_threshold >= 0.0
            && rule.relative_threshold.is_finite()
            && rule.relative_threshold >= 0.0;
        let subject_valid = rule.subject.as_ref().is_none_or(|subject| {
            subject.validate().is_ok()
                && rule
                    .semantic
                    .standard_spec()
                    .is_none_or(|spec| subject.kind().is_some_and(|kind| kind == spec.subject_kind))
        });
        thresholds_valid
            && subject_valid
            && selectors.insert((rule.semantic.clone(), rule.subject.clone()))
    })
}

type ResourceIdentity = (CounterSemantic, CounterSubject);

#[derive(Clone, Copy)]
enum ResourceValueSource<'a> {
    Counter(&'a ResourceCounterSummary),
    Derived(&'a DerivedResourceMetricSummary),
}

impl<'a> ResourceValueSource<'a> {
    fn unit(self) -> Option<&'a str> {
        match self {
            Self::Counter(counter) => counter.unit.as_deref(),
            Self::Derived(derived) => Some(&derived.unit),
        }
    }

    fn support(self) -> &'a MetricSupportEntry {
        match self {
            Self::Counter(counter) => &counter.support,
            Self::Derived(derived) => &derived.support,
        }
    }

    fn quality(self) -> Option<Quality> {
        match self {
            Self::Counter(counter) => Some(counter.quality),
            Self::Derived(derived) => derived.quality,
        }
    }

    fn diagnostic(self) -> ResourceMetricSource {
        match self {
            Self::Counter(counter) => ResourceMetricSource::Counter {
                counter_id: counter.counter_id.clone(),
            },
            Self::Derived(derived) => ResourceMetricSource::Derived {
                source_counter_ids: derived.source_counter_ids.clone(),
            },
        }
    }
}

struct ResourceIndex<'a> {
    by_identity: BTreeMap<ResourceIdentity, ResourceValueSource<'a>>,
    by_counter_id: BTreeMap<String, ResourceIdentity>,
}

fn build_resource_index<'a>(
    summary: &'a ResourceSummary,
    label: &str,
    reasons: &mut Vec<String>,
) -> Option<ResourceIndex<'a>> {
    let mut by_identity = BTreeMap::new();
    let mut by_counter_id = BTreeMap::new();
    let mut all_counter_ids = BTreeSet::new();
    let mut valid = true;

    for counter in &summary.counters {
        if !resource_counter_summary_valid(counter) {
            valid = false;
            continue;
        }
        if !all_counter_ids.insert(counter.counter_id.clone()) {
            valid = false;
        }
        let identity = match (&counter.semantic, &counter.subject) {
            (Some(semantic), Some(subject)) => (semantic.clone(), subject.clone()),
            (None, None) => continue,
            _ => {
                valid = false;
                continue;
            }
        };
        if by_identity
            .insert(identity.clone(), ResourceValueSource::Counter(counter))
            .is_some()
        {
            valid = false;
        }
        if by_counter_id
            .insert(counter.counter_id.clone(), identity.clone())
            .is_some_and(|existing| existing != identity)
        {
            valid = false;
        }
    }

    for derived in &summary.derived {
        if !derived_resource_summary_valid(derived)
            || derived
                .source_counter_ids
                .iter()
                .any(|counter_id| !all_counter_ids.contains(counter_id))
        {
            valid = false;
            continue;
        }
        let identity = (derived.semantic.clone(), derived.subject.clone());
        if by_identity
            .insert(identity, ResourceValueSource::Derived(derived))
            .is_some()
        {
            valid = false;
        }
    }

    if valid {
        Some(ResourceIndex {
            by_identity,
            by_counter_id,
        })
    } else {
        reasons.push(format!("{label}_resource_summary_invalid"));
        None
    }
}

fn resource_counter_summary_valid(counter: &ResourceCounterSummary) -> bool {
    if counter.counter_id.trim().is_empty()
        || counter.sample_count == 0
        || !counter.latest.is_finite()
        || !counter.min.is_finite()
        || !counter.max.is_finite()
        || !counter.mean.is_finite()
        || counter.first.is_some_and(|value| !value.is_finite())
        || counter.delta.is_some_and(|value| !value.is_finite())
        || counter
            .rate_per_second
            .is_some_and(|value| !value.is_finite())
        || counter.min > counter.max
        || counter.latest < counter.min
        || counter.latest > counter.max
        || counter.mean < counter.min
        || counter.mean > counter.max
        || !support_entry_valid(&counter.support)
    {
        return false;
    }
    let (Some(semantic), Some(subject)) = (&counter.semantic, &counter.subject) else {
        return counter.semantic.is_none() && counter.subject.is_none();
    };
    if subject.validate().is_err() {
        return false;
    }
    semantic.standard_spec().is_none_or(|spec| {
        counter.class == spec.class
            && subject.kind() == Some(spec.subject_kind)
            && [
                counter.first,
                Some(counter.latest),
                Some(counter.min),
                Some(counter.max),
            ]
            .into_iter()
            .flatten()
            .all(|value| spec.value_is_valid(value))
    })
}

fn derived_resource_summary_valid(derived: &DerivedResourceMetricSummary) -> bool {
    if derived.subject.validate().is_err()
        || derived.unit.trim().is_empty()
        || derived.value.is_some_and(|value| !value.is_finite())
        || derived.source_counter_ids.is_empty()
        || derived
            .source_counter_ids
            .iter()
            .any(|counter_id| counter_id.trim().is_empty())
        || derived
            .source_counter_ids
            .windows(2)
            .any(|ids| ids[0] >= ids[1])
        || !support_entry_valid(&derived.support)
        || derived
            .value
            .is_some_and(|_| derived.quality.is_none() || !derived.support.is_available())
        || derived.support.is_available() && derived.value.is_none()
    {
        return false;
    }
    derived.semantic.standard_spec().is_none_or(|spec| {
        derived.unit == spec.unit
            && derived.subject.kind() == Some(spec.subject_kind)
            && derived.value.is_none_or(|value| spec.value_is_valid(value))
    })
}

fn support_entry_valid(entry: &MetricSupportEntry) -> bool {
    if entry.support != MetricSupportLevel::Exact && entry.reasons.is_empty() {
        return false;
    }
    let mut reasons = BTreeSet::new();
    entry
        .reasons
        .iter()
        .all(|reason| !reason.trim().is_empty() && reasons.insert(reason))
}

fn matching_resource_rule<'a>(
    policy: &'a ComparisonPolicy,
    identity: &ResourceIdentity,
) -> Option<&'a ResourceComparisonRule> {
    policy
        .resource_rules
        .iter()
        .find(|rule| rule.semantic == identity.0 && rule.subject.as_ref() == Some(&identity.1))
        .or_else(|| {
            policy
                .resource_rules
                .iter()
                .find(|rule| rule.semantic == identity.0 && rule.subject.is_none())
        })
}

fn resource_subjects(
    index: &ResourceIndex<'_>,
    rule: &ResourceComparisonRule,
) -> BTreeSet<CounterSubject> {
    index
        .by_identity
        .keys()
        .filter(|(semantic, subject)| {
            semantic == &rule.semantic
                && rule
                    .subject
                    .as_ref()
                    .is_none_or(|expected| expected == subject)
        })
        .map(|(_, subject)| subject.clone())
        .collect()
}

fn compare_resource_metrics(
    baseline: &ResourceSummary,
    candidate: &ResourceSummary,
    baseline_support: &MetricSupportEntry,
    candidate_support: &MetricSupportEntry,
    policy: &ComparisonPolicy,
    reasons: &mut Vec<String>,
) -> Vec<ResourceMetricComparison> {
    let Some(baseline) = build_resource_index(baseline, "baseline", reasons) else {
        return Vec::new();
    };
    let Some(candidate) = build_resource_index(candidate, "candidate", reasons) else {
        return Vec::new();
    };

    let has_configured_identity = baseline
        .by_identity
        .keys()
        .chain(candidate.by_identity.keys())
        .any(|identity| matching_resource_rule(policy, identity).is_some());
    if has_configured_identity
        && !support_comparable(
            baseline_support,
            candidate_support,
            policy.require_exact_metrics,
        )
    {
        reasons.push("metric_support_mismatch:resource_counters".to_owned());
    }

    if !policy.allow_resource_subject_set_changes {
        for rule in &policy.resource_rules {
            if resource_subjects(&baseline, rule) != resource_subjects(&candidate, rule) {
                push_reason_once(
                    reasons,
                    format!("resource_subject_set_differs:{}", rule.semantic),
                );
            }
        }
    }

    let mut incomparable = BTreeSet::new();
    for (counter_id, baseline_identity) in &baseline.by_counter_id {
        if let Some(candidate_identity) = candidate.by_counter_id.get(counter_id)
            && baseline_identity != candidate_identity
        {
            incomparable.insert(baseline_identity.clone());
            incomparable.insert(candidate_identity.clone());
            if matching_resource_rule(policy, baseline_identity).is_some()
                || matching_resource_rule(policy, candidate_identity).is_some()
            {
                push_reason_once(
                    reasons,
                    format!("resource_counter_identity_mismatch:{counter_id}"),
                );
            }
        }
    }

    let baseline_keys = baseline
        .by_identity
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let candidate_keys = candidate
        .by_identity
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut metrics = Vec::new();
    for identity in baseline_keys.union(&candidate_keys) {
        if incomparable.contains(identity) {
            continue;
        }
        let baseline_counter = baseline.by_identity.get(identity).copied();
        let candidate_counter = candidate.by_identity.get(identity).copied();
        let rule = matching_resource_rule(policy, identity);
        if rule.is_none() && (baseline_counter.is_none() || candidate_counter.is_none()) {
            continue;
        }
        if rule.is_some()
            && (baseline_counter.is_none() || candidate_counter.is_none())
            && !policy.allow_resource_subject_set_changes
        {
            continue;
        }
        let aggregate = rule.map_or(ResourceComparisonAggregate::Latest, |rule| rule.aggregate);
        let baseline_value = match baseline_counter {
            Some(counter) => match aggregate_value(counter, aggregate) {
                Some(value) => value,
                None => {
                    if rule.is_some() {
                        push_reason_once(
                            reasons,
                            format!(
                                "resource_aggregate_unavailable:{}:{aggregate:?}",
                                identity.0
                            ),
                        );
                    }
                    continue;
                }
            },
            None => 0.0,
        };
        let candidate_value = match candidate_counter {
            Some(counter) => match aggregate_value(counter, aggregate) {
                Some(value) => value,
                None => {
                    if rule.is_some() {
                        push_reason_once(
                            reasons,
                            format!(
                                "resource_aggregate_unavailable:{}:{aggregate:?}",
                                identity.0
                            ),
                        );
                    }
                    continue;
                }
            },
            None => 0.0,
        };
        metrics.push(resource_metric_comparison(
            identity,
            ResourceMetricInputs {
                baseline_counter,
                candidate_counter,
                aggregate,
                baseline: baseline_value,
                candidate: candidate_value,
                rule,
            },
            policy,
            reasons,
        ));
    }
    metrics
}

struct ResourceMetricInputs<'a> {
    baseline_counter: Option<ResourceValueSource<'a>>,
    candidate_counter: Option<ResourceValueSource<'a>>,
    aggregate: ResourceComparisonAggregate,
    baseline: f64,
    candidate: f64,
    rule: Option<&'a ResourceComparisonRule>,
}

fn resource_metric_comparison(
    identity: &ResourceIdentity,
    inputs: ResourceMetricInputs<'_>,
    policy: &ComparisonPolicy,
    report_reasons: &mut Vec<String>,
) -> ResourceMetricComparison {
    let ResourceMetricInputs {
        baseline_counter,
        candidate_counter,
        aggregate,
        baseline,
        candidate,
        rule,
    } = inputs;
    let delta = candidate - baseline;
    let relative_change = if baseline == 0.0 {
        None
    } else {
        Some(delta / baseline)
    };
    let quality = match (baseline_counter, candidate_counter) {
        (Some(baseline), Some(candidate)) => baseline
            .quality()
            .into_iter()
            .chain(candidate.quality())
            .max()
            .expect("available resource values must record quality"),
        (Some(counter), None) | (None, Some(counter)) => counter
            .quality()
            .expect("available resource value must record quality"),
        (None, None) => unreachable!("a union resource identity must have a counter"),
    };
    let mut row_reasons = Vec::new();
    match (baseline_counter, candidate_counter) {
        (None, Some(_)) => row_reasons.push("resource_subject_added".to_owned()),
        (Some(_), None) => row_reasons.push("resource_subject_removed".to_owned()),
        _ => {}
    }

    let units_match = match (baseline_counter, candidate_counter) {
        (Some(baseline), Some(candidate)) => {
            baseline.unit().is_some_and(|unit| !unit.trim().is_empty())
                && baseline.unit() == candidate.unit()
        }
        (Some(counter), None) | (None, Some(counter)) => {
            counter.unit().is_some_and(|unit| !unit.trim().is_empty())
        }
        (None, None) => false,
    };
    let units_comparable = units_match
        && identity.0.standard_spec().is_none_or(|spec| {
            [baseline_counter, candidate_counter]
                .into_iter()
                .flatten()
                .all(|source| source.unit() == Some(spec.unit))
        });
    let support_comparable = match (baseline_counter, candidate_counter) {
        (Some(baseline), Some(candidate)) => support_comparable(
            baseline.support(),
            candidate.support(),
            policy.require_exact_metrics,
        ),
        (Some(counter), None) | (None, Some(counter)) => {
            support_usable(counter.support(), policy.require_exact_metrics)
        }
        (None, None) => false,
    };

    let outcome = if let Some(rule) = rule {
        if !units_comparable {
            row_reasons.push("resource_unit_mismatch".to_owned());
            push_reason_once(
                report_reasons,
                format!("resource_unit_mismatch:{}", identity.0),
            );
        }
        if !support_comparable {
            row_reasons.push("resource_support_mismatch".to_owned());
            push_reason_once(
                report_reasons,
                format!("resource_support_mismatch:{}", identity.0),
            );
        }
        if units_comparable && support_comparable {
            resource_outcome(baseline, candidate, relative_change, rule)
        } else {
            ResourceMetricComparisonOutcome::Inconclusive
        }
    } else {
        if !units_comparable {
            row_reasons.push("resource_unit_mismatch".to_owned());
        }
        if !support_comparable {
            row_reasons.push("resource_support_mismatch".to_owned());
        }
        row_reasons.push("no_resource_rule".to_owned());
        ResourceMetricComparisonOutcome::Informational
    };

    ResourceMetricComparison {
        semantic: identity.0.clone(),
        subject: identity.1.clone(),
        aggregate,
        baseline_source: baseline_counter.map(ResourceValueSource::diagnostic),
        candidate_source: candidate_counter.map(ResourceValueSource::diagnostic),
        baseline_unit: baseline_counter
            .and_then(ResourceValueSource::unit)
            .map(str::to_owned),
        candidate_unit: candidate_counter
            .and_then(ResourceValueSource::unit)
            .map(str::to_owned),
        baseline_support: baseline_counter.map(|counter| counter.support().support),
        candidate_support: candidate_counter.map(|counter| counter.support().support),
        baseline,
        candidate,
        delta,
        relative_change,
        quality,
        direction: rule.map(|rule| rule.direction),
        absolute_threshold: rule.map(|rule| rule.absolute_threshold),
        relative_threshold: rule.map(|rule| rule.relative_threshold),
        outcome,
        reasons: row_reasons,
    }
}

fn support_usable(entry: &MetricSupportEntry, require_exact: bool) -> bool {
    if require_exact {
        entry.support == MetricSupportLevel::Exact
    } else {
        entry.support != MetricSupportLevel::Unavailable
    }
}

fn aggregate_value(
    source: ResourceValueSource<'_>,
    aggregate: ResourceComparisonAggregate,
) -> Option<f64> {
    match source {
        ResourceValueSource::Counter(counter) => match aggregate {
            ResourceComparisonAggregate::Latest => Some(counter.latest),
            ResourceComparisonAggregate::Min => Some(counter.min),
            ResourceComparisonAggregate::Max => Some(counter.max),
            ResourceComparisonAggregate::Mean => Some(counter.mean),
            ResourceComparisonAggregate::Delta => counter.delta,
            ResourceComparisonAggregate::RatePerSecond => counter.rate_per_second,
        },
        ResourceValueSource::Derived(derived) => match aggregate {
            ResourceComparisonAggregate::Latest => derived.value,
            ResourceComparisonAggregate::RatePerSecond
                if derived.semantic.as_str()
                    == CounterSemantic::HEAP_ALLOCATION_RATE_PER_SECOND =>
            {
                derived.value
            }
            ResourceComparisonAggregate::Min
            | ResourceComparisonAggregate::Max
            | ResourceComparisonAggregate::Mean
            | ResourceComparisonAggregate::Delta
            | ResourceComparisonAggregate::RatePerSecond => None,
        },
    }
}

fn resource_outcome(
    baseline: f64,
    candidate: f64,
    relative_change: Option<f64>,
    rule: &ResourceComparisonRule,
) -> ResourceMetricComparisonOutcome {
    let delta = candidate - baseline;
    let changed_absolutely = delta.abs() > rule.absolute_threshold;
    let changed_relatively =
        relative_change.is_some_and(|change| change.abs() > rule.relative_threshold);
    if !changed_absolutely || baseline != 0.0 && !changed_relatively {
        return ResourceMetricComparisonOutcome::Unchanged;
    }
    match (rule.direction, delta.is_sign_positive()) {
        (ResourceComparisonDirection::LowerIsBetter, true)
        | (ResourceComparisonDirection::HigherIsBetter, false) => {
            ResourceMetricComparisonOutcome::Regressed
        }
        (ResourceComparisonDirection::LowerIsBetter, false)
        | (ResourceComparisonDirection::HigherIsBetter, true) => {
            ResourceMetricComparisonOutcome::Improved
        }
    }
}

fn compare_static_ram(
    baseline: Option<&StaticRamAnalysisSummary>,
    candidate: Option<&StaticRamAnalysisSummary>,
    policy: &ComparisonPolicy,
    reasons: &mut Vec<String>,
) -> Vec<StaticRamMetricComparison> {
    let (Some(baseline), Some(candidate)) = (baseline, candidate) else {
        if baseline.is_some() != candidate.is_some() {
            reasons.push("static_ram_summary_set_differs".to_owned());
        }
        return Vec::new();
    };
    let mut comparable = true;
    if !static_ram_summary_valid(baseline) {
        reasons.push("baseline_static_ram_summary_invalid".to_owned());
        comparable = false;
    }
    if !static_ram_summary_valid(candidate) {
        reasons.push("candidate_static_ram_summary_invalid".to_owned());
        comparable = false;
    }
    if baseline.flavor != candidate.flavor {
        reasons.push("static_ram_flavor_mismatch".to_owned());
        comparable = false;
    }
    match (&baseline.config, &candidate.config) {
        (Some(baseline), Some(candidate)) if baseline.sha256 == candidate.sha256 => {}
        (Some(_), Some(_)) => {
            reasons.push("static_ram_config_digest_mismatch".to_owned());
            comparable = false;
        }
        _ => {
            reasons.push("static_ram_config_digest_missing".to_owned());
            comparable = false;
        }
    }
    if !support_comparable(
        &baseline.support,
        &candidate.support,
        policy.require_exact_metrics,
    ) {
        reasons.push("static_ram_support_mismatch".to_owned());
        comparable = false;
    }
    if !comparable {
        return Vec::new();
    }

    let baseline_totals = &baseline.totals;
    let candidate_totals = &candidate.totals;
    [
        (
            StaticRamMetricKind::Total,
            baseline.total_bytes,
            candidate.total_bytes,
        ),
        (
            StaticRamMetricKind::Data,
            baseline_totals.data_bytes,
            candidate_totals.data_bytes,
        ),
        (
            StaticRamMetricKind::Bss,
            baseline_totals.bss_bytes,
            candidate_totals.bss_bytes,
        ),
        (
            StaticRamMetricKind::Noinit,
            baseline_totals.noinit_bytes,
            candidate_totals.noinit_bytes,
        ),
        (
            StaticRamMetricKind::Dma,
            baseline_totals.dma_bytes,
            candidate_totals.dma_bytes,
        ),
        (
            StaticRamMetricKind::Rtos,
            baseline_totals.rtos_bytes,
            candidate_totals.rtos_bytes,
        ),
        (
            StaticRamMetricKind::Custom,
            baseline_totals.custom_bytes,
            candidate_totals.custom_bytes,
        ),
    ]
    .into_iter()
    .map(
        |(metric, baseline_bytes, candidate_bytes)| StaticRamMetricComparison {
            metric,
            baseline_bytes,
            candidate_bytes,
            outcome: match candidate_bytes.cmp(&baseline_bytes) {
                std::cmp::Ordering::Less => MetricComparisonOutcome::Improved,
                std::cmp::Ordering::Equal => MetricComparisonOutcome::Unchanged,
                std::cmp::Ordering::Greater => MetricComparisonOutcome::Regressed,
            },
            reasons: vec!["lower_is_better".to_owned()],
        },
    )
    .collect()
}

fn static_ram_summary_valid(summary: &StaticRamAnalysisSummary) -> bool {
    !summary.artifact_id.trim().is_empty()
        && !summary.source_artifact_id.trim().is_empty()
        && !summary.flavor.trim().is_empty()
        && summary.totals.checked_total() == Some(summary.total_bytes)
        && support_entry_valid(&summary.support)
        && summary.config.as_ref().is_none_or(|config| {
            config
                .artifact_id
                .as_deref()
                .is_none_or(|artifact_id| !artifact_id.trim().is_empty())
        })
}

fn comparison_outcomes(
    metrics: &[MetricComparison],
    resources: &[ResourceMetricComparison],
    static_ram: &[StaticRamMetricComparison],
) -> Vec<MetricComparisonOutcome> {
    metrics
        .iter()
        .map(|metric| metric.outcome)
        .chain(resources.iter().filter_map(|metric| match metric.outcome {
            ResourceMetricComparisonOutcome::Improved => Some(MetricComparisonOutcome::Improved),
            ResourceMetricComparisonOutcome::Unchanged => Some(MetricComparisonOutcome::Unchanged),
            ResourceMetricComparisonOutcome::Regressed => Some(MetricComparisonOutcome::Regressed),
            ResourceMetricComparisonOutcome::Inconclusive => {
                Some(MetricComparisonOutcome::Inconclusive)
            }
            ResourceMetricComparisonOutcome::Informational => None,
        }))
        .chain(static_ram.iter().map(|metric| metric.outcome))
        .collect()
}

fn push_reason_once(reasons: &mut Vec<String>, reason: impl Into<String>) {
    let reason = reason.into();
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn compare_function_hotspots(
    baseline: &[FunctionHotspot],
    candidate: &[FunctionHotspot],
    policy: &ComparisonPolicy,
    reasons: &mut Vec<String>,
) -> Vec<MetricComparison> {
    let baseline = baseline
        .iter()
        .map(|row| ((row.function_id.as_str(), row.context_id.as_deref()), row))
        .collect::<BTreeMap<_, _>>();
    let candidate = candidate
        .iter()
        .map(|row| ((row.function_id.as_str(), row.context_id.as_deref()), row))
        .collect::<BTreeMap<_, _>>();
    let baseline_keys = baseline.keys().copied().collect::<BTreeSet<_>>();
    let candidate_keys = candidate.keys().copied().collect::<BTreeSet<_>>();
    if baseline_keys != candidate_keys && !policy.allow_function_set_changes {
        reasons.push("function_set_differs".to_owned());
    }

    let mut metrics = Vec::new();
    for key in baseline_keys.union(&candidate_keys) {
        let baseline = baseline.get(key).copied();
        let candidate = candidate.get(key).copied();
        if (baseline.is_none() || candidate.is_none()) && !policy.allow_function_set_changes {
            continue;
        }
        let row = baseline.or(candidate).expect("union key must have a row");
        let subject = ComparisonSubject {
            kind: ComparisonSubjectKind::Function,
            id: row.function_id.clone(),
            context_id: row.context_id.clone(),
        };
        let quality = match (baseline, candidate) {
            (Some(baseline), Some(candidate)) => baseline.quality.max(candidate.quality),
            (Some(row), None) | (None, Some(row)) => row.quality,
            (None, None) => unreachable!("union key must have a row"),
        };
        let membership_reason = match (baseline, candidate) {
            (None, Some(_)) => Some("function_added"),
            (Some(_), None) => Some("function_removed"),
            (Some(_), Some(_)) => None,
            (None, None) => unreachable!("union key must have a row"),
        };
        for (metric, baseline_value, candidate_value, absolute_threshold) in [
            (
                ComparisonMetricKind::InclusiveActiveNs,
                baseline.map_or(0.0, |row| row.inclusive_active_ns as f64),
                candidate.map_or(0.0, |row| row.inclusive_active_ns as f64),
                policy.absolute_time_threshold_ns as f64,
            ),
            (
                ComparisonMetricKind::SelfActiveNs,
                baseline.map_or(0.0, |row| row.self_active_ns as f64),
                candidate.map_or(0.0, |row| row.self_active_ns as f64),
                policy.absolute_time_threshold_ns as f64,
            ),
            (
                ComparisonMetricKind::Count,
                baseline.map_or(0.0, |row| row.count as f64),
                candidate.map_or(0.0, |row| row.count as f64),
                policy.absolute_count_threshold as f64,
            ),
            (
                ComparisonMetricKind::MinActiveNs,
                baseline.map_or(0.0, |row| row.min_active_ns as f64),
                candidate.map_or(0.0, |row| row.min_active_ns as f64),
                policy.absolute_time_threshold_ns as f64,
            ),
            (
                ComparisonMetricKind::MaxActiveNs,
                baseline.map_or(0.0, |row| row.max_active_ns as f64),
                candidate.map_or(0.0, |row| row.max_active_ns as f64),
                policy.absolute_time_threshold_ns as f64,
            ),
            (
                ComparisonMetricKind::AvgActiveNs,
                baseline.map_or(0.0, |row| row.avg_active_ns as f64),
                candidate.map_or(0.0, |row| row.avg_active_ns as f64),
                policy.absolute_time_threshold_ns as f64,
            ),
        ] {
            let mut comparison = metric_comparison(
                subject.clone(),
                metric,
                baseline_value,
                candidate_value,
                absolute_threshold,
                policy.relative_threshold,
                quality,
            );
            if let Some(reason) = membership_reason {
                comparison.reasons.push(reason.to_owned());
            }
            metrics.push(comparison);
        }
    }
    metrics
}

fn compare_sampling_hotspots(
    baseline: &[SamplingHotspot],
    candidate: &[SamplingHotspot],
    policy: &ComparisonPolicy,
    reasons: &mut Vec<String>,
) -> Vec<MetricComparison> {
    if policy.require_exact_metrics || !policy.compare_statistical_metrics {
        return Vec::new();
    }
    let baseline = baseline
        .iter()
        .map(|row| (sampling_key(row), row))
        .collect::<BTreeMap<_, _>>();
    let candidate = candidate
        .iter()
        .map(|row| (sampling_key(row), row))
        .collect::<BTreeMap<_, _>>();
    let baseline_keys = baseline.keys().cloned().collect::<BTreeSet<_>>();
    let candidate_keys = candidate.keys().cloned().collect::<BTreeSet<_>>();
    if baseline_keys != candidate_keys {
        reasons.push("sampling_set_differs".to_owned());
    }

    let mut metrics = Vec::new();
    for key in baseline_keys.intersection(&candidate_keys) {
        let baseline = baseline[key];
        let candidate = candidate[key];
        let subject = ComparisonSubject {
            kind: if baseline.function_id.is_some() {
                ComparisonSubjectKind::Function
            } else {
                ComparisonSubjectKind::Custom
            },
            id: baseline
                .function_id
                .clone()
                .unwrap_or_else(|| format!("address:{:x}", baseline.address.unwrap_or_default())),
            context_id: baseline.context_id.clone(),
        };
        metrics.push(metric_comparison(
            subject,
            ComparisonMetricKind::EstimatedShare,
            baseline.estimated_share,
            candidate.estimated_share,
            0.0,
            policy.relative_threshold,
            Quality::Statistical,
        ));
    }
    metrics
}

fn sampling_key(row: &SamplingHotspot) -> (Option<String>, Option<u64>, Option<String>) {
    (row.function_id.clone(), row.address, row.context_id.clone())
}

fn metric_comparison(
    subject: ComparisonSubject,
    metric: ComparisonMetricKind,
    baseline: f64,
    candidate: f64,
    absolute_threshold: f64,
    relative_threshold: f64,
    quality: Quality,
) -> MetricComparison {
    let delta = candidate - baseline;
    let relative_change = if baseline == 0.0 {
        None
    } else {
        Some(delta / baseline)
    };
    let changed_absolutely = delta.abs() > absolute_threshold.max(0.0);
    let changed_relatively =
        relative_change.is_some_and(|change| change.abs() > relative_threshold.max(0.0));
    let outcome = if changed_absolutely && (baseline == 0.0 || changed_relatively) {
        if delta > 0.0 {
            MetricComparisonOutcome::Regressed
        } else {
            MetricComparisonOutcome::Improved
        }
    } else {
        MetricComparisonOutcome::Unchanged
    };
    MetricComparison {
        subject,
        metric,
        baseline,
        candidate,
        delta,
        relative_change,
        quality,
        outcome,
        reasons: Vec::new(),
    }
}

fn inconclusive_report(
    baseline: ComparisonInput<'_>,
    candidate: ComparisonInput<'_>,
    reasons: Vec<String>,
) -> ComparisonReport {
    ComparisonReport {
        schema: ComparisonSchemaVersion,
        baseline_session_id: baseline.manifest.session_id.clone(),
        candidate_session_id: candidate.manifest.session_id.clone(),
        baseline_health: baseline.health.verdict,
        candidate_health: candidate.health.verdict,
        verdict: ComparisonVerdict::Inconclusive,
        metrics: Vec::new(),
        resource_metrics: Vec::new(),
        static_ram_metrics: Vec::new(),
        reasons,
    }
}
