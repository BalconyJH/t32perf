//! Closed, bounded contracts for the one-shot `perf_run` workflow.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Artifact, AttestationSigningRequestSchemaVersion, CaptureAttestationPayload, HealthVerdict,
    PerfTrustStatus, PerformanceRunRequestSchemaVersion, SessionStatus, Sha256Digest,
};

/// The only report serialization a performance run may request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum PerformanceReportFormat {
    /// The immutable Perfetto JSON report artifact.
    #[serde(rename = "perfetto_json")]
    PerfettoJson,
}

/// Strict caller-owned input for a complete performance run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerformanceRunRequest {
    /// Request schema identity.
    pub schema: PerformanceRunRequestSchemaVersion,
    /// Requested capture duration. The adapter may impose a stricter bound.
    #[schemars(range(min = 1))]
    pub duration_ns: u64,
    /// Maximum number of hotspot rows requested in the bounded summary.
    #[schemars(range(min = 1, max = 100))]
    pub top: u8,
    /// Closed report serialization choice.
    pub report_format: PerformanceReportFormat,
}

impl PerformanceRunRequest {
    /// Validates semantic bounds independent of the adapter's capacity policy.
    pub fn validate(&self) -> Result<(), PerformanceRunValidationError> {
        if self.duration_ns == 0 {
            return Err(PerformanceRunValidationError::ZeroDuration);
        }
        if !(1..=100).contains(&self.top) {
            return Err(PerformanceRunValidationError::InvalidTop { top: self.top });
        }
        Ok(())
    }
}

/// Durable phase of a complete performance run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PerformanceRunPhase {
    /// Firmware/resource provisioning is in progress.
    Provision,
    /// Target control and capture are in progress.
    Control,
    /// Raw trace is being normalized.
    Normalize,
    /// Capture evidence is being attested.
    Attest,
    /// Normalized data is being analyzed.
    Analyze,
    /// Report conversion is in progress.
    Convert,
    /// All requested artifacts are durable.
    Complete,
}

/// Small aggregate summary returned without inlining a report artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfRunSummary {
    /// Number of hotspot entries returned by a separately bounded summary.
    #[schemars(range(max = 100))]
    pub hotspots_returned: u8,
    /// Total matching hotspot count before truncation.
    pub hotspots_total: u64,
    /// Whether the bounded result omitted additional hotspot rows.
    pub truncated: bool,
}

impl PerfRunSummary {
    fn validate(&self) -> Result<(), PerformanceRunValidationError> {
        if self.hotspots_returned > 100 || u64::from(self.hotspots_returned) > self.hotspots_total {
            return Err(PerformanceRunValidationError::InvalidSummary);
        }
        if self.truncated != (u64::from(self.hotspots_returned) < self.hotspots_total) {
            return Err(PerformanceRunValidationError::InvalidSummary);
        }
        Ok(())
    }
}

/// Typed bounded response for `perf_run`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerfRunPayload {
    /// Owning Session.
    #[schemars(length(min = 1, max = 256))]
    pub session_id: String,
    /// Current run phase.
    pub phase: PerformanceRunPhase,
    /// Durable Session status.
    pub state: SessionStatus,
    /// Trust projection for completed analysis.
    pub trust_status: PerfTrustStatus,
    /// Health projection when analysis has produced one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_verdict: Option<HealthVerdict>,
    /// Bounded aggregate summary; never embeds raw observations or a report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<PerfRunSummary>,
    /// Immutable converted report reference; report bytes are never inlined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_artifact: Option<Artifact>,
    /// Digest of the final immutable session manifest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_sha256: Option<Sha256Digest>,
    /// Whether this response resumed a prior durable run.
    pub resumed: bool,
}

impl PerfRunPayload {
    /// Validates phase-dependent response invariants and bounded projections.
    pub fn validate(&self) -> Result<(), PerformanceRunValidationError> {
        if self.session_id.trim().is_empty() {
            return Err(PerformanceRunValidationError::EmptySessionId);
        }
        let complete = self.phase == PerformanceRunPhase::Complete;
        if complete {
            if self.state != SessionStatus::Complete
                || self.report_artifact.is_none()
                || self.manifest_sha256.is_none()
            {
                return Err(PerformanceRunValidationError::InconsistentPhase);
            }
            match (self.trust_status, self.health_verdict) {
                (PerfTrustStatus::Valid, Some(HealthVerdict::Valid)) if self.summary.is_some() => {}
                (PerfTrustStatus::Degraded, Some(HealthVerdict::Degraded))
                | (PerfTrustStatus::Invalid, Some(HealthVerdict::Invalid))
                    if self.summary.is_none() => {}
                _ => return Err(PerformanceRunValidationError::InconsistentPhase),
            }
        } else if self.state == SessionStatus::Complete
            || self.trust_status != PerfTrustStatus::NotEvaluated
            || self.health_verdict.is_some()
            || self.summary.is_some()
            || self.report_artifact.is_some()
            || self.manifest_sha256.is_some()
        {
            return Err(PerformanceRunValidationError::InconsistentPhase);
        }
        if let Some(summary) = &self.summary {
            summary.validate()?;
        }
        if let Some(artifact) = &self.report_artifact {
            artifact
                .validate()
                .map_err(|_| PerformanceRunValidationError::InvalidReportArtifact)?;
        }
        if matches!(self.phase, PerformanceRunPhase::Provision)
            && self.state != SessionStatus::Created
        {
            return Err(PerformanceRunValidationError::InconsistentPhase);
        }
        if matches!(self.phase, PerformanceRunPhase::Control)
            && !matches!(
                self.state,
                SessionStatus::Capturing | SessionStatus::Captured
            )
        {
            return Err(PerformanceRunValidationError::InconsistentPhase);
        }
        if matches!(
            self.phase,
            PerformanceRunPhase::Normalize | PerformanceRunPhase::Attest
        ) && self.state != SessionStatus::Captured
        {
            return Err(PerformanceRunValidationError::InconsistentPhase);
        }
        if matches!(
            self.phase,
            PerformanceRunPhase::Analyze | PerformanceRunPhase::Convert
        ) && self.state != SessionStatus::Processing
        {
            return Err(PerformanceRunValidationError::InconsistentPhase);
        }
        Ok(())
    }
}

/// Closed request handed to a deployment-owned attestation signer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttestationSigningRequest {
    /// Request schema identity.
    pub schema: AttestationSigningRequestSchemaVersion,
    /// Exact deployment trust-policy identity.
    #[schemars(length(min = 1, max = 256))]
    pub policy_id: String,
    /// Exact configured public-key identity.
    #[schemars(length(min = 1, max = 256))]
    pub key_id: String,
    /// Existing validated facts to be signed. No private key or path is present.
    pub payload: CaptureAttestationPayload,
}

impl AttestationSigningRequest {
    /// Returns deterministic request bytes for idempotency or request hashing.
    ///
    /// These bytes are not the Ed25519 signing message.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PerformanceRunValidationError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| PerformanceRunValidationError::Canonicalization)
    }

    /// Returns the exact existing attestation payload bytes for Ed25519 signing.
    pub fn payload_signing_bytes(&self) -> Result<Vec<u8>, PerformanceRunValidationError> {
        self.validate()?;
        self.payload
            .signing_bytes()
            .map_err(|_| PerformanceRunValidationError::Canonicalization)
    }

    /// Validates signer routing and the existing attestation payload.
    pub fn validate(&self) -> Result<(), PerformanceRunValidationError> {
        for (field, value) in [("policy_id", &self.policy_id), ("key_id", &self.key_id)] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(PerformanceRunValidationError::InvalidSigningIdentity {
                    field: field.to_owned(),
                });
            }
        }
        self.payload
            .validate()
            .map_err(|_| PerformanceRunValidationError::InvalidAttestationPayload)?;
        if self.payload.key_id != self.key_id {
            return Err(PerformanceRunValidationError::SigningKeyMismatch);
        }
        Ok(())
    }
}

/// Semantic invariant violation in a performance-run contract.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PerformanceRunValidationError {
    /// Duration is zero.
    #[error("performance run duration_ns must be nonzero")]
    ZeroDuration,
    /// Requested top count exceeds the closed bound.
    #[error("performance run top `{top}` must be in 1..=100")]
    InvalidTop {
        /// Rejected caller value.
        top: u8,
    },
    /// Session identity is empty.
    #[error("performance run session_id is empty")]
    EmptySessionId,
    /// Summary counts are inconsistent.
    #[error("performance run summary is inconsistent")]
    InvalidSummary,
    /// Report reference is malformed.
    #[error("performance run report artifact is invalid")]
    InvalidReportArtifact,
    /// Fields do not match the declared phase.
    #[error("performance run phase and fields are inconsistent")]
    InconsistentPhase,
    /// A signer routing identity is invalid.
    #[error("attestation signing {field} is empty or contains a control character")]
    InvalidSigningIdentity {
        /// Rejected identity field name.
        field: String,
    },
    /// The embedded attestation payload is invalid.
    #[error("attestation signing payload is invalid")]
    InvalidAttestationPayload,
    /// The request key does not equal the payload key.
    #[error("attestation signing request key_id does not match payload.key_id")]
    SigningKeyMismatch,
    /// Canonical JSON serialization failed.
    #[error("attestation signing request could not be canonicalized")]
    Canonicalization,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::ArtifactPath;

    use super::*;

    #[test]
    fn run_request_round_trips_and_is_closed() {
        let request = PerformanceRunRequest {
            schema: PerformanceRunRequestSchemaVersion,
            duration_ns: 1,
            top: 100,
            report_format: PerformanceReportFormat::PerfettoJson,
        };
        request.validate().unwrap();
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(
            serde_json::from_value::<PerformanceRunRequest>(value).unwrap(),
            request
        );
        assert!(
            serde_json::from_value::<PerformanceRunRequest>(json!({
                "schema": "t32perf.performance-run-request/v1",
                "duration_ns": 1,
                "top": 1,
                "report_format": "perfetto_json",
                "path": "forbidden"
            }))
            .is_err()
        );
    }

    #[test]
    fn run_request_rejects_zero_and_out_of_range_top() {
        let mut request = PerformanceRunRequest {
            schema: PerformanceRunRequestSchemaVersion,
            duration_ns: 0,
            top: 1,
            report_format: PerformanceReportFormat::PerfettoJson,
        };
        assert_eq!(
            request.validate(),
            Err(PerformanceRunValidationError::ZeroDuration)
        );
        request.duration_ns = 1;
        request.top = 0;
        assert!(matches!(
            request.validate(),
            Err(PerformanceRunValidationError::InvalidTop { .. })
        ));
    }

    #[test]
    fn payload_enforces_phase_consistency_without_inline_artifacts() {
        let payload = PerfRunPayload {
            session_id: "session-1".to_owned(),
            phase: PerformanceRunPhase::Provision,
            state: SessionStatus::Created,
            trust_status: PerfTrustStatus::NotEvaluated,
            health_verdict: None,
            summary: None,
            report_artifact: None,
            manifest_sha256: None,
            resumed: false,
        };
        payload.validate().unwrap();
        let mut invalid = payload.clone();
        invalid.phase = PerformanceRunPhase::Complete;
        assert_eq!(
            invalid.validate(),
            Err(PerformanceRunValidationError::InconsistentPhase)
        );
        let mut normalize = payload.clone();
        normalize.phase = PerformanceRunPhase::Normalize;
        normalize.state = SessionStatus::Captured;
        normalize.validate().unwrap();
        normalize.state = SessionStatus::Processing;
        assert_eq!(
            normalize.validate(),
            Err(PerformanceRunValidationError::InconsistentPhase)
        );
        assert!(
            serde_json::from_value::<PerfRunPayload>(json!({
                "session_id": "session-1",
                "phase": "provision",
                "state": "created",
                "trust_status": "NOT_EVALUATED",
                "resumed": false,
                "report_bytes": "forbidden"
            }))
            .is_err()
        );
    }

    #[test]
    fn noncomplete_payload_rejects_forged_trust_health_and_summary() {
        for (phase, state) in [
            (PerformanceRunPhase::Provision, SessionStatus::Created),
            (PerformanceRunPhase::Control, SessionStatus::Capturing),
            (PerformanceRunPhase::Normalize, SessionStatus::Captured),
            (PerformanceRunPhase::Attest, SessionStatus::Captured),
            (PerformanceRunPhase::Analyze, SessionStatus::Processing),
            (PerformanceRunPhase::Convert, SessionStatus::Processing),
        ] {
            let payload = PerfRunPayload {
                session_id: "session-1".to_owned(),
                phase,
                state,
                trust_status: PerfTrustStatus::NotEvaluated,
                health_verdict: None,
                summary: None,
                report_artifact: None,
                manifest_sha256: None,
                resumed: false,
            };
            payload.validate().unwrap();

            let mut forged_valid = payload.clone();
            forged_valid.trust_status = PerfTrustStatus::Valid;
            forged_valid.health_verdict = Some(HealthVerdict::Valid);
            assert_eq!(
                forged_valid.validate(),
                Err(PerformanceRunValidationError::InconsistentPhase)
            );

            let mut forged_degraded = payload.clone();
            forged_degraded.trust_status = PerfTrustStatus::Degraded;
            forged_degraded.health_verdict = Some(HealthVerdict::Degraded);
            assert_eq!(
                forged_degraded.validate(),
                Err(PerformanceRunValidationError::InconsistentPhase)
            );

            let mut forged_summary = payload;
            forged_summary.summary = Some(PerfRunSummary {
                hotspots_returned: 1,
                hotspots_total: 1,
                truncated: false,
            });
            assert_eq!(
                forged_summary.validate(),
                Err(PerformanceRunValidationError::InconsistentPhase)
            );

            let mut forged_report = forged_summary.clone();
            forged_report.summary = None;
            forged_report.report_artifact = Some(Artifact {
                id: "performance-report".to_owned(),
                kind: "perfetto_report".to_owned(),
                relative_path: ArtifactPath::new("reports/performance.json").unwrap(),
                media_type: "application/json".to_owned(),
                size_bytes: 1,
                sha256: Sha256Digest::new("a".repeat(64)).unwrap(),
                producer: "t32perf-perfetto".to_owned(),
                input_artifact_ids: Vec::new(),
            });
            assert_eq!(
                forged_report.validate(),
                Err(PerformanceRunValidationError::InconsistentPhase)
            );

            let mut forged_manifest = forged_summary;
            forged_manifest.summary = None;
            forged_manifest.manifest_sha256 = Some(Sha256Digest::new("b".repeat(64)).unwrap());
            assert_eq!(
                forged_manifest.validate(),
                Err(PerformanceRunValidationError::InconsistentPhase)
            );
        }
    }
}
