//! Public analyzer configuration and result summaries.

use serde::{Deserialize, Serialize};
use t32perf_model::{
    DerivedDocument, HealthReport, HotspotReport, MetricSupportEntry, MetricSupportLevel,
};

pub use t32perf_model::{
    AnalysisSummary, CallDepthSummary, ContextCpuSummary, ResourceClass, ResourceCounterSummary,
    ResourceSummary,
};

/// Declares which observation families a capture can supply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisCapabilities {
    /// Support declared for function enter and exit observations.
    pub function_events: MetricSupportEntry,
    /// Support declared for Task context-switch observations.
    pub context_switches: MetricSupportEntry,
    /// Support declared for interrupt enter and exit observations.
    pub interrupt_events: MetricSupportEntry,
    /// Support declared for statistical program-counter samples.
    pub samples: MetricSupportEntry,
    /// Support declared for explicit numeric resource counters.
    pub resource_counters: MetricSupportEntry,
}

impl Default for AnalysisCapabilities {
    fn default() -> Self {
        Self {
            function_events: missing_receipt_support("function_events"),
            context_switches: missing_receipt_support("context_switches"),
            interrupt_events: missing_receipt_support("interrupt_events"),
            samples: missing_receipt_support("samples"),
            resource_counters: missing_receipt_support("resource_counters"),
        }
    }
}

impl AnalysisCapabilities {
    /// Declares a verified complete program-flow capture with Task and ISR events.
    #[must_use]
    pub fn exact_program_flow() -> Self {
        Self {
            function_events: MetricSupportEntry::new(MetricSupportLevel::Exact),
            context_switches: MetricSupportEntry::new(MetricSupportLevel::Exact),
            interrupt_events: MetricSupportEntry::new(MetricSupportLevel::Exact),
            samples: MetricSupportEntry {
                support: MetricSupportLevel::Unavailable,
                reasons: vec!["samples_not_declared".to_owned()],
            },
            resource_counters: MetricSupportEntry::new(MetricSupportLevel::Exact),
        }
    }
}

fn missing_receipt_support(family: &str) -> MetricSupportEntry {
    MetricSupportEntry {
        support: MetricSupportLevel::Unavailable,
        reasons: vec![format!("capture_receipt_missing:{family}")],
    }
}

/// Configuration of one streaming analysis run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzerConfig {
    /// Version string of the host health policy.
    pub health_policy_version: String,
    /// Observation families supported by the capture.
    pub capabilities: AnalysisCapabilities,
    /// Maximum retained health observations, including the truncation sentinel.
    ///
    /// Values below one are treated as one.
    #[serde(default = "default_max_health_observations")]
    pub max_health_observations: usize,
    /// Maximum number of concurrently open custom synchronous and asynchronous spans.
    ///
    /// Values below one are treated as one. Additional begins are rejected from
    /// resident state and recorded as invalid health observations.
    #[serde(default = "default_max_open_custom_spans")]
    pub max_open_custom_spans: usize,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            health_policy_version: "t32perf.health-policy/v1".to_owned(),
            capabilities: AnalysisCapabilities::default(),
            max_health_observations: default_max_health_observations(),
            max_open_custom_spans: default_max_open_custom_spans(),
        }
    }
}

fn default_max_health_observations() -> usize {
    4_096
}

fn default_max_open_custom_spans() -> usize {
    65_536
}

/// Complete output of one analyzer run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Reconstructed function spans, including incomplete diagnostic spans.
    pub derived: DerivedDocument,
    /// Host-policy health verdict and metric support.
    pub health: HealthReport,
    /// Health-gated function and sampling hotspot aggregates.
    pub hotspots: HotspotReport,
    /// Additional call-depth, CPU, and resource summaries.
    pub summary: AnalysisSummary,
}

impl AnalysisResult {
    /// Returns hotspot aggregates only when the capture passed the strict health gate.
    #[must_use]
    pub fn trusted_hotspots(&self) -> Option<&HotspotReport> {
        self.health
            .verdict
            .allows_quantitative_results()
            .then_some(&self.hotspots)
    }

    /// Returns quantitative summaries only when the capture passed the strict health gate.
    #[must_use]
    pub fn trusted_summary(&self) -> Option<&AnalysisSummary> {
        self.health
            .verdict
            .allows_quantitative_results()
            .then_some(&self.summary)
    }
}
