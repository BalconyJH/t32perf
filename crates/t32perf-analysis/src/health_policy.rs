//! Versioned host-side trace health policy.

use serde_json::json;
use t32perf_model::{
    HealthIssue, HealthObservation, HealthReport, HealthSchemaVersion, HealthSeverity,
    HealthVerdict, MetricSupport, MetricSupportEntry, MetricSupportLevel, Properties,
};

use crate::AnalysisCapabilities;

const MAX_RETAINED_UNKNOWN_HEALTH_CODE_BYTES: usize = 256;

/// Host policy that maps source facts to issues, verdict, and metric support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthPolicy {
    version: String,
}

impl HealthPolicy {
    /// Creates a policy with a durable version identifier.
    #[must_use]
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
        }
    }

    /// Returns the durable policy version identifier.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Evaluates health observations under this policy.
    #[must_use]
    pub fn evaluate(
        &self,
        session_id: impl Into<String>,
        observations: &[HealthObservation],
        capabilities: &AnalysisCapabilities,
    ) -> HealthReport {
        let mut verdict = HealthVerdict::Valid;
        let mut support = support_from_capabilities(capabilities);
        let mut issues = Vec::new();

        let mut normalized_observations = Vec::with_capacity(observations.len());

        for observation in observations {
            let observation = canonicalize_observation(observation);
            let normalized = normalize_code(&observation.code);
            let (code, rule, evidence) = match issue_rule(&normalized) {
                Some(rule) => (normalized, rule, observation.evidence.clone()),
                None if !normalized.is_empty() => {
                    let (original_code, original_code_truncated) =
                        bounded_unknown_health_code(&observation.code);
                    let mut evidence = observation.evidence.clone();
                    evidence.insert("original_code".to_owned(), json!(original_code));
                    if original_code_truncated {
                        evidence.insert("original_code_truncated".to_owned(), json!(true));
                    }
                    (
                        "unknown_health_fact".to_owned(),
                        unknown_health_fact_rule(),
                        evidence,
                    )
                }
                None => unreachable!(
                    "invalid health observations are canonicalized before policy evaluation"
                ),
            };
            verdict = combine_verdict(verdict, rule.verdict);
            apply_metric_impact(&mut support, rule.impact, &code);
            issues.push(HealthIssue {
                code,
                severity: rule.severity,
                source: observation.source.clone(),
                artifact_id: observation.artifact_id.clone(),
                record: observation.record,
                start_ns: observation.start_ns,
                end_ns: observation.end_ns,
                evidence,
                message: rule.message.to_owned(),
            });
            normalized_observations.push(observation);
        }

        HealthReport {
            schema: HealthSchemaVersion,
            session_id: session_id.into(),
            verdict,
            policy_version: self.version.clone(),
            observations: normalized_observations,
            issues,
            metric_support: support,
        }
    }
}

fn canonicalize_observation(observation: &HealthObservation) -> HealthObservation {
    let empty_code = normalize_code(&observation.code).is_empty();
    let empty_source = observation.source.trim().is_empty();
    if !empty_code && !empty_source {
        return observation.clone();
    }

    let mut evidence = observation.evidence.clone();
    evidence.insert("empty_code".to_owned(), json!(empty_code));
    evidence.insert("empty_source".to_owned(), json!(empty_source));
    insert_bounded_identity_evidence(&mut evidence, "original_code", &observation.code);
    insert_bounded_identity_evidence(&mut evidence, "original_source", &observation.source);

    HealthObservation {
        code: "invalid_health_observation".to_owned(),
        source: "health_policy".to_owned(),
        artifact_id: observation.artifact_id.clone(),
        record: observation.record,
        start_ns: observation.start_ns,
        end_ns: observation.end_ns,
        evidence,
    }
}

fn insert_bounded_identity_evidence(evidence: &mut Properties, field: &str, value: &str) {
    let (value, truncated) = bounded_unknown_health_code(value);
    evidence.insert(field.to_owned(), json!(value));
    if truncated {
        evidence.insert(format!("{field}_truncated"), json!(true));
    }
}

impl Default for HealthPolicy {
    fn default() -> Self {
        Self::new("t32perf.health-policy/v1")
    }
}

#[derive(Debug, Clone, Copy)]
struct IssueRule {
    severity: HealthSeverity,
    verdict: HealthVerdict,
    message: &'static str,
    impact: MetricImpact,
}

fn unknown_health_fact_rule() -> IssueRule {
    IssueRule {
        severity: HealthSeverity::Fatal,
        verdict: HealthVerdict::Invalid,
        message: "The health policy does not recognize this source fact.",
        impact: MetricImpact::AllUnavailable,
    }
}

#[derive(Debug, Clone, Copy)]
enum MetricImpact {
    AllUnavailable,
    FunctionUnavailable,
    InterruptUnavailable,
    ContextUnavailable,
    Gap,
    ContextInferred,
    ResourceUnavailable,
    None,
}

fn issue_rule(code: &str) -> Option<IssueRule> {
    let fatal = |message, impact| IssueRule {
        severity: HealthSeverity::Fatal,
        verdict: HealthVerdict::Invalid,
        message,
        impact,
    };
    let error = |message, impact| IssueRule {
        severity: HealthSeverity::Error,
        verdict: HealthVerdict::Invalid,
        message,
        impact,
    };
    let warning = |message, impact| IssueRule {
        severity: HealthSeverity::Warning,
        verdict: HealthVerdict::Degraded,
        message,
        impact,
    };

    Some(match code {
        "trace_overflow" => fatal(
            "The trace source overflowed and lost program-flow data.",
            MetricImpact::AllUnavailable,
        ),
        "flow_error" => fatal(
            "The decoded program flow is invalid.",
            MetricImpact::AllUnavailable,
        ),
        "sampling_buffer_full" => fatal(
            "The bounded sampling buffer became full before the requested capture stop.",
            MetricImpact::AllUnavailable,
        ),
        "sampling_unexpected_stop" => fatal(
            "Real-time program-counter sampling stopped before the request for an unclassified reason.",
            MetricImpact::AllUnavailable,
        ),
        "truncated_input" => fatal(
            "The input artifact is truncated.",
            MetricImpact::AllUnavailable,
        ),
        "malformed_input" => fatal(
            "The input artifact violates the canonical observation format.",
            MetricImpact::AllUnavailable,
        ),
        "elf_mismatch" => fatal(
            "The firmware ELF does not match the captured program.",
            MetricImpact::FunctionUnavailable,
        ),
        "out_of_order_timestamp" | "out_of_order_sequence" => fatal(
            "Observation order is not monotonic.",
            MetricImpact::AllUnavailable,
        ),
        "timestamp_discontinuity" => fatal(
            "The hardware capture reported an unexplained timestamp discontinuity.",
            MetricImpact::AllUnavailable,
        ),
        "program_flow_unclosed" => fatal(
            "The hardware capture could not prove program-flow closure.",
            MetricImpact::AllUnavailable,
        ),
        "unmatched_function_exit" | "mismatched_function_exit" | "unclosed_function" => error(
            "Function activation records do not form a closed stack.",
            MetricImpact::FunctionUnavailable,
        ),
        "unmatched_interrupt_exit" | "mismatched_interrupt_exit" | "unclosed_interrupt" => error(
            "Interrupt activation records do not form a closed stack.",
            MetricImpact::InterruptUnavailable,
        ),
        "duplicate_interrupt_activation" => error(
            "An interrupt activation identifier was reused before its prior activation ended.",
            MetricImpact::InterruptUnavailable,
        ),
        "duplicate_span_begin"
        | "unmatched_span_end"
        | "unclosed_span"
        | "duplicate_async_begin"
        | "unmatched_async_end"
        | "unclosed_async"
        | "open_custom_span_limit_exceeded" => error(
            "Custom span boundaries are inconsistent or exceed the configured resident-state limit.",
            MetricImpact::None,
        ),
        "context_mismatch" | "context_switch_mismatch" | "concurrent_context" => error(
            "Execution-context attribution is inconsistent.",
            MetricImpact::ContextUnavailable,
        ),
        "timestamp_overflow" | "duration_overflow" => error(
            "A timestamp or duration cannot be represented safely.",
            MetricImpact::AllUnavailable,
        ),
        "diagnostics_truncated" => fatal(
            "Health diagnostics exceeded their configured retention limit.",
            MetricImpact::AllUnavailable,
        ),
        "invalid_health_observation" => fatal(
            "A health observation has an empty code or source identity.",
            MetricImpact::AllUnavailable,
        ),
        "invalid_health_policy_identity" => fatal(
            "The health policy version identity is empty.",
            MetricImpact::AllUnavailable,
        ),
        "trace_gap" => warning(
            "The trace contains a bounded interval without reliable observations.",
            MetricImpact::Gap,
        ),
        "missing_scheduled_context" => warning(
            "Running time could not be assigned to a scheduled context.",
            MetricImpact::ContextInferred,
        ),
        "invalid_resource_counter" => warning(
            "A resource counter contains an invalid value.",
            MetricImpact::ResourceUnavailable,
        ),
        "invalid_resource_counter_definition" | "resource_counter_unit_mismatch" => error(
            "A resource counter definition violates its explicit semantic contract.",
            MetricImpact::ResourceUnavailable,
        ),
        "resource_counter_subject_conflict" => error(
            "Two resource counters claim the same semantic subject identity.",
            MetricImpact::ResourceUnavailable,
        ),
        "resource_counter_out_of_range" => warning(
            "A resource counter value is outside its semantic range.",
            MetricImpact::ResourceUnavailable,
        ),
        "resource_counter_not_monotonic" => warning(
            "A monotonic or high-watermark resource counter decreased.",
            MetricImpact::ResourceUnavailable,
        ),
        "resource_counter_invariant_violation" => warning(
            "Related resource counters violate a declared capacity or ordering invariant.",
            MetricImpact::ResourceUnavailable,
        ),
        "resource_counter_window_incomplete" => warning(
            "A resource-counter derivation window is incomplete.",
            MetricImpact::ResourceUnavailable,
        ),
        _ => return None,
    })
}

fn normalize_code(code: &str) -> String {
    match code
        .trim()
        .to_ascii_lowercase()
        .replace(['-', ' '], "_")
        .as_str()
    {
        "overflow" | "capture_overflow" => "trace_overflow".to_owned(),
        "trace_flow_error" => "flow_error".to_owned(),
        "truncation" | "truncated" | "trace_truncated" => "truncated_input".to_owned(),
        "firmware_mismatch" => "elf_mismatch".to_owned(),
        normalized => normalized.to_owned(),
    }
}

fn bounded_unknown_health_code(code: &str) -> (String, bool) {
    if code.len() <= MAX_RETAINED_UNKNOWN_HEALTH_CODE_BYTES {
        return (code.to_owned(), false);
    }

    let mut end = 0;
    for (index, character) in code.char_indices() {
        let next = index + character.len_utf8();
        if next > MAX_RETAINED_UNKNOWN_HEALTH_CODE_BYTES {
            break;
        }
        end = next;
    }
    (code[..end].to_owned(), true)
}

fn combine_verdict(current: HealthVerdict, next: HealthVerdict) -> HealthVerdict {
    match (current, next) {
        (HealthVerdict::Invalid, _) | (_, HealthVerdict::Invalid) => HealthVerdict::Invalid,
        (HealthVerdict::Degraded, _) | (_, HealthVerdict::Degraded) => HealthVerdict::Degraded,
        _ => HealthVerdict::Valid,
    }
}

fn support_from_capabilities(capabilities: &AnalysisCapabilities) -> MetricSupport {
    let mut support = MetricSupport::uniform(MetricSupportLevel::Exact);

    for target in [
        &mut support.function_timeline,
        &mut support.call_count,
        &mut support.elapsed,
    ] {
        merge_declared_support(target, &capabilities.function_events, "function_events");
    }
    if capabilities.function_events.support == MetricSupportLevel::Unavailable {
        append_declared_reasons(&mut support.active, &capabilities.function_events);
        if capabilities.samples.support == MetricSupportLevel::Unavailable {
            lower(
                &mut support.active,
                MetricSupportLevel::Unavailable,
                "function_events_and_samples_unavailable",
            );
        } else {
            lower(
                &mut support.active,
                MetricSupportLevel::Statistical,
                "active_time_estimated_from_samples",
            );
            append_declared_reasons(&mut support.active, &capabilities.samples);
        }
        lower(
            &mut support.self_time,
            MetricSupportLevel::Unavailable,
            "function_events_unavailable",
        );
        append_declared_reasons(&mut support.self_time, &capabilities.function_events);
    } else {
        merge_declared_support(
            &mut support.active,
            &capabilities.function_events,
            "function_events",
        );
        merge_declared_support(
            &mut support.self_time,
            &capabilities.function_events,
            "function_events",
        );
    }

    merge_declared_support(
        &mut support.task_timeline,
        &capabilities.context_switches,
        "context_switches",
    );
    if capabilities.context_switches.support == MetricSupportLevel::Unavailable {
        lower(
            &mut support.active,
            MetricSupportLevel::Inferred,
            "context_switches_unavailable",
        );
        lower(
            &mut support.self_time,
            MetricSupportLevel::Inferred,
            "context_switches_unavailable",
        );
        append_declared_reasons(&mut support.active, &capabilities.context_switches);
        append_declared_reasons(&mut support.self_time, &capabilities.context_switches);
    } else {
        merge_declared_support(
            &mut support.active,
            &capabilities.context_switches,
            "context_switches",
        );
        merge_declared_support(
            &mut support.self_time,
            &capabilities.context_switches,
            "context_switches",
        );
    }

    merge_declared_support(
        &mut support.isr_timeline,
        &capabilities.interrupt_events,
        "interrupt_events",
    );
    if capabilities.interrupt_events.support == MetricSupportLevel::Unavailable {
        lower(
            &mut support.active,
            MetricSupportLevel::Inferred,
            "interrupt_events_unavailable",
        );
        lower(
            &mut support.self_time,
            MetricSupportLevel::Inferred,
            "interrupt_events_unavailable",
        );
        append_declared_reasons(&mut support.active, &capabilities.interrupt_events);
        append_declared_reasons(&mut support.self_time, &capabilities.interrupt_events);
    } else {
        merge_declared_support(
            &mut support.active,
            &capabilities.interrupt_events,
            "interrupt_events",
        );
        merge_declared_support(
            &mut support.self_time,
            &capabilities.interrupt_events,
            "interrupt_events",
        );
    }

    merge_declared_support(
        &mut support.resource_counters,
        &capabilities.resource_counters,
        "resource_counters",
    );

    support
}

fn merge_declared_support(
    target: &mut MetricSupportEntry,
    declared: &MetricSupportEntry,
    family: &str,
) {
    if support_rank(declared.support) > support_rank(target.support) {
        target.support = declared.support;
    }
    append_declared_reasons(target, declared);
    if declared.support != MetricSupportLevel::Exact && declared.reasons.is_empty() {
        let reason = format!("{family}:{:?}", declared.support).to_ascii_lowercase();
        if !target.reasons.contains(&reason) {
            target.reasons.push(reason);
        }
    }
}

fn append_declared_reasons(target: &mut MetricSupportEntry, declared: &MetricSupportEntry) {
    for reason in &declared.reasons {
        if !target.reasons.contains(reason) {
            target.reasons.push(reason.clone());
        }
    }
}

fn apply_metric_impact(support: &mut MetricSupport, impact: MetricImpact, reason: &str) {
    match impact {
        MetricImpact::AllUnavailable => {
            for entry in support_entries_mut(support) {
                lower(entry, MetricSupportLevel::Unavailable, reason);
            }
        }
        MetricImpact::FunctionUnavailable => {
            for entry in [
                &mut support.function_timeline,
                &mut support.call_count,
                &mut support.elapsed,
                &mut support.active,
                &mut support.self_time,
            ] {
                lower(entry, MetricSupportLevel::Unavailable, reason);
            }
        }
        MetricImpact::InterruptUnavailable => {
            lower(
                &mut support.isr_timeline,
                MetricSupportLevel::Unavailable,
                reason,
            );
            lower(&mut support.active, MetricSupportLevel::Unavailable, reason);
            lower(
                &mut support.self_time,
                MetricSupportLevel::Unavailable,
                reason,
            );
        }
        MetricImpact::ContextUnavailable => {
            lower(
                &mut support.task_timeline,
                MetricSupportLevel::Unavailable,
                reason,
            );
            lower(&mut support.active, MetricSupportLevel::Unavailable, reason);
            lower(
                &mut support.self_time,
                MetricSupportLevel::Unavailable,
                reason,
            );
        }
        MetricImpact::Gap => {
            lower(
                &mut support.function_timeline,
                MetricSupportLevel::Inferred,
                reason,
            );
            lower(
                &mut support.call_count,
                MetricSupportLevel::Unavailable,
                reason,
            );
            lower(&mut support.elapsed, MetricSupportLevel::Inferred, reason);
            lower(&mut support.active, MetricSupportLevel::Inferred, reason);
            lower(&mut support.self_time, MetricSupportLevel::Inferred, reason);
            lower(
                &mut support.task_timeline,
                MetricSupportLevel::Inferred,
                reason,
            );
            lower(
                &mut support.isr_timeline,
                MetricSupportLevel::Inferred,
                reason,
            );
            lower(
                &mut support.resource_counters,
                MetricSupportLevel::Unavailable,
                reason,
            );
        }
        MetricImpact::ContextInferred => {
            lower(
                &mut support.task_timeline,
                MetricSupportLevel::Inferred,
                reason,
            );
            lower(&mut support.active, MetricSupportLevel::Inferred, reason);
            lower(&mut support.self_time, MetricSupportLevel::Inferred, reason);
        }
        MetricImpact::ResourceUnavailable => lower(
            &mut support.resource_counters,
            MetricSupportLevel::Unavailable,
            reason,
        ),
        MetricImpact::None => {}
    }
}

fn support_entries_mut(support: &mut MetricSupport) -> [&mut MetricSupportEntry; 8] {
    [
        &mut support.function_timeline,
        &mut support.call_count,
        &mut support.elapsed,
        &mut support.active,
        &mut support.self_time,
        &mut support.task_timeline,
        &mut support.isr_timeline,
        &mut support.resource_counters,
    ]
}

fn lower(entry: &mut MetricSupportEntry, next: MetricSupportLevel, reason: &str) {
    if support_rank(next) > support_rank(entry.support) {
        entry.support = next;
    }
    if !entry.reasons.iter().any(|existing| existing == reason) {
        entry.reasons.push(reason.to_owned());
    }
}

fn support_rank(level: MetricSupportLevel) -> u8 {
    match level {
        MetricSupportLevel::Exact => 0,
        MetricSupportLevel::Inferred => 1,
        MetricSupportLevel::Statistical => 2,
        MetricSupportLevel::Unavailable => 3,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use t32perf_model::{HealthObservation, HealthSeverity, HealthVerdict, Properties};

    use super::{AnalysisCapabilities, HealthPolicy, MAX_RETAINED_UNKNOWN_HEALTH_CODE_BYTES};

    fn observation(code: impl Into<String>, record: u64) -> HealthObservation {
        HealthObservation {
            code: code.into(),
            source: "adapter".to_owned(),
            artifact_id: Some("capture".to_owned()),
            record: Some(record),
            start_ns: Some(record as i64),
            end_ns: Some(record as i64),
            evidence: Properties::from([("source_detail".to_owned(), json!(record))]),
        }
    }

    #[test]
    fn unknown_health_fact_is_fatal_and_disables_quantitative_metrics() {
        let report = HealthPolicy::default().evaluate(
            "unknown-health",
            &[observation("future_adapter_fact", 7)],
            &AnalysisCapabilities::exact_program_flow(),
        );

        assert_eq!(report.verdict, HealthVerdict::Invalid);
        assert!(!report.verdict.allows_quantitative_results());
        assert_eq!(report.issues.len(), 1);
        let issue = &report.issues[0];
        assert_eq!(issue.code, "unknown_health_fact");
        assert_eq!(issue.severity, HealthSeverity::Fatal);
        assert_eq!(
            issue.evidence["original_code"],
            json!("future_adapter_fact")
        );
        assert_eq!(issue.evidence["source_detail"], json!(7));
        assert!(!report.metric_support.active.is_available());
        assert!(!report.metric_support.resource_counters.is_available());
        assert!(report.validate().is_ok());
    }

    #[test]
    fn known_and_unknown_health_facts_are_each_retained() {
        let report = HealthPolicy::default().evaluate(
            "mixed-health",
            &[
                observation("trace_gap", 1),
                observation("future_adapter_fact", 2),
                observation("overflow", 3),
            ],
            &AnalysisCapabilities::exact_program_flow(),
        );

        assert_eq!(report.verdict, HealthVerdict::Invalid);
        assert_eq!(report.issues.len(), 3);
        assert_eq!(report.issues[0].code, "trace_gap");
        assert_eq!(report.issues[1].code, "unknown_health_fact");
        assert_eq!(report.issues[2].code, "trace_overflow");
        assert_eq!(report.issues[1].record, Some(2));
    }

    #[test]
    fn repeated_unknown_health_facts_are_not_silently_coalesced() {
        let report = HealthPolicy::default().evaluate(
            "repeated-unknown-health",
            &[
                observation("future_adapter_fact", 1),
                observation("future_adapter_fact", 2),
            ],
            &AnalysisCapabilities::exact_program_flow(),
        );

        assert_eq!(report.issues.len(), 2);
        assert!(
            report
                .issues
                .iter()
                .all(|issue| issue.code == "unknown_health_fact")
        );
        assert_eq!(report.issues[0].record, Some(1));
        assert_eq!(report.issues[1].record, Some(2));
    }

    #[test]
    fn unknown_health_fact_code_retention_is_byte_bounded() {
        let exact = "x".repeat(MAX_RETAINED_UNKNOWN_HEALTH_CODE_BYTES);
        let oversized = format!("{exact}y");
        let report = HealthPolicy::default().evaluate(
            "bounded-unknown-health",
            &[observation(exact.clone(), 1), observation(oversized, 2)],
            &AnalysisCapabilities::exact_program_flow(),
        );

        assert_eq!(report.issues.len(), 2);
        assert_eq!(report.issues[0].evidence["original_code"], json!(exact));
        assert!(
            !report.issues[0]
                .evidence
                .contains_key("original_code_truncated")
        );
        assert_eq!(
            report.issues[1].evidence["original_code"],
            json!("x".repeat(MAX_RETAINED_UNKNOWN_HEALTH_CODE_BYTES))
        );
        assert_eq!(
            report.issues[1].evidence["original_code_truncated"],
            json!(true)
        );
    }

    #[test]
    fn invalid_observation_identity_is_canonicalized_fail_closed() {
        let mut empty_source = observation("trace_gap", 3);
        empty_source.source = " \t ".to_owned();
        let report = HealthPolicy::default().evaluate(
            "invalid-health-observations",
            &[
                observation("", 1),
                observation(" \n\t ", 2),
                empty_source,
                observation("trace_gap", 4),
            ],
            &AnalysisCapabilities::exact_program_flow(),
        );

        assert_eq!(report.verdict, HealthVerdict::Invalid);
        assert_eq!(report.observations.len(), 4);
        assert_eq!(report.issues.len(), 4);
        for (index, issue) in report.issues.iter().take(3).enumerate() {
            assert_eq!(issue.code, "invalid_health_observation");
            assert_eq!(issue.severity, HealthSeverity::Fatal);
            assert_eq!(issue.source, "health_policy");
            assert_eq!(issue.record, Some((index + 1) as u64));
        }
        assert_eq!(report.issues[3].code, "trace_gap");
        assert_eq!(report.observations[0].code, "invalid_health_observation");
        assert_eq!(report.observations[1].code, "invalid_health_observation");
        assert_eq!(report.observations[2].code, "invalid_health_observation");
        assert_eq!(report.observations[2].source, "health_policy");
        assert_eq!(report.issues[0].evidence["empty_code"], json!(true));
        assert_eq!(report.issues[0].evidence["empty_source"], json!(false));
        assert_eq!(report.issues[2].evidence["empty_code"], json!(false));
        assert_eq!(report.issues[2].evidence["empty_source"], json!(true));
        assert!(
            report
                .metric_support
                .active
                .reasons
                .contains(&"invalid_health_observation".to_owned())
        );
        assert!(report.validate().is_ok());
    }

    #[test]
    fn invalid_identity_evidence_is_byte_bounded() {
        let oversized_code = " ".repeat(MAX_RETAINED_UNKNOWN_HEALTH_CODE_BYTES + 1);
        let report = HealthPolicy::default().evaluate(
            "bounded-invalid-health-observation",
            &[observation(oversized_code, 1)],
            &AnalysisCapabilities::exact_program_flow(),
        );

        let evidence = &report.issues[0].evidence;
        assert_eq!(
            evidence["original_code"],
            json!(" ".repeat(MAX_RETAINED_UNKNOWN_HEALTH_CODE_BYTES))
        );
        assert_eq!(evidence["original_code_truncated"], json!(true));
        assert!(report.validate().is_ok());
    }
}
