//! Durable control-plane contracts for one TRACE32 sampling endpoint.

use std::collections::BTreeSet;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;

use crate::{
    ArtifactPath, SamplingCaptureReceiptSchemaVersion, SamplingCaptureRequestSchemaVersion,
    SamplingDriverEventSchemaVersion, SamplingEndpointBindingSchemaVersion, Sha256Digest,
    is_portable_session_id,
};

/// Maximum journal claims in a successful sampling-capture receipt.
pub const SUCCESSFUL_SAMPLING_JOURNAL_EVENT_COUNT: usize = 10;
/// Maximum requested ranges and expanded PC-hit buckets per sampling capture.
pub const MAX_SAMPLING_CAPTURE_BUCKETS: usize = 256;

/// Algorithm used to derive a TRACE32 endpoint fingerprint.
///
/// This is independent of the document schema version: it identifies the
/// cryptographic endpoint-binding algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum EndpointFingerprintScheme {
    /// Canonical endpoint identity bound to the observed TRACE32 probe.
    #[serde(rename = "t32perf.endpoint-fingerprint/v2")]
    T32PerfEndpointFingerprintV2,
}

/// One nonempty half-open address range requested for PC-hit sampling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SamplingAddressRange {
    /// Inclusive range start.
    pub start_address: u64,
    /// Exclusive range end.
    pub end_address: u64,
}

/// Sampling-method policy selected before capability probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SamplingMethodPolicy {
    /// Permit only non-intrusive runtime PC snooping.
    RealtimeOnly,
    /// Permit explicitly requested Stop-and-Go sampling when realtime is unavailable.
    AllowStopAndGo,
}

/// TRACE32 address space supported by the sampling sidecar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SamplingAddressSpace {
    /// TRACE32 program address space.
    #[serde(rename = "P")]
    P,
}

/// Bounded request for one aggregate TRACE32 PERF sampling capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SamplingCaptureRequest {
    /// The sampling-capture request schema version.
    pub schema: SamplingCaptureRequestSchemaVersion,
    /// Sorted, non-overlapping nonempty ranges to sample.
    #[schemars(length(min = 1, max = 256))]
    pub ranges: Vec<SamplingAddressRange>,
    /// Width of each exact half-open PC-hit bucket in bytes.
    #[schemars(range(min = 1, max = 1_048_576))]
    pub bucket_size: u64,
    /// Requested aggregate sampling duration in milliseconds.
    #[schemars(range(min = 1, max = 60_000))]
    pub duration_ms: u32,
    /// Permitted acquisition methods.
    pub method_policy: SamplingMethodPolicy,
    /// Core supplying sampled program counters.
    pub core_id: u32,
    /// Required TRACE32 program address space.
    pub address_space: SamplingAddressSpace,
    /// Optional SHA-256 assertion for the deployed ELF used by later function attribution.
    ///
    /// Address-only heatmaps intentionally omit this assertion.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_sha256_digest"
    )]
    #[schemars(schema_with = "optional_sha256_digest_schema")]
    pub deployed_firmware_elf_sha256: Option<Sha256Digest>,
}

fn deserialize_optional_sha256_digest<'de, D>(
    deserializer: D,
) -> Result<Option<Sha256Digest>, D::Error>
where
    D: Deserializer<'de>,
{
    Sha256Digest::deserialize(deserializer).map(Some)
}

fn optional_sha256_digest_schema(generator: &mut SchemaGenerator) -> Schema {
    Sha256Digest::json_schema(generator)
}

impl SamplingCaptureRequest {
    /// Validates ranges and the bounded expansion they imply.
    pub fn validate(&self) -> Result<(), SamplingCaptureRequestValidationError> {
        if self.ranges.is_empty() || self.ranges.len() > MAX_SAMPLING_CAPTURE_BUCKETS {
            return Err(SamplingCaptureRequestValidationError::InvalidRangeCount);
        }
        if self.bucket_size == 0 || self.bucket_size > 0x10_0000 {
            return Err(SamplingCaptureRequestValidationError::InvalidBucketSize);
        }
        if !(1..=60_000).contains(&self.duration_ms) {
            return Err(SamplingCaptureRequestValidationError::InvalidDuration);
        }
        let mut previous_end = None;
        let mut total_buckets = 0_usize;
        for range in &self.ranges {
            if range.start_address >= range.end_address {
                return Err(SamplingCaptureRequestValidationError::InvalidRange);
            }
            if let Some(end) = previous_end
                && range.start_address < end
            {
                return Err(SamplingCaptureRequestValidationError::UnsortedOrOverlappingRanges);
            }
            previous_end = Some(range.end_address);
            let length = range
                .end_address
                .checked_sub(range.start_address)
                .ok_or(SamplingCaptureRequestValidationError::AddressArithmeticOverflow)?;
            let bucket_count = length
                .checked_add(self.bucket_size - 1)
                .ok_or(SamplingCaptureRequestValidationError::AddressArithmeticOverflow)?
                / self.bucket_size;
            total_buckets = total_buckets
                .checked_add(
                    usize::try_from(bucket_count)
                        .map_err(|_| SamplingCaptureRequestValidationError::TooManyBuckets)?,
                )
                .ok_or(SamplingCaptureRequestValidationError::TooManyBuckets)?;
            if total_buckets > MAX_SAMPLING_CAPTURE_BUCKETS {
                return Err(SamplingCaptureRequestValidationError::TooManyBuckets);
            }
        }
        Ok(())
    }

    /// Expands requested ranges into exact bounded half-open PC-hit buckets.
    pub fn buckets(
        &self,
    ) -> Result<Vec<SamplingAddressRange>, SamplingCaptureRequestValidationError> {
        self.validate()?;
        let mut buckets = Vec::new();
        for range in &self.ranges {
            let mut start = range.start_address;
            while start < range.end_address {
                let end = start
                    .checked_add(self.bucket_size)
                    .map_or(range.end_address, |candidate| {
                        candidate.min(range.end_address)
                    });
                buckets.push(SamplingAddressRange {
                    start_address: start,
                    end_address: end,
                });
                start = end;
            }
        }
        Ok(buckets)
    }
}

/// Binds a sampling-only process to exactly one TRACE32 endpoint identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SamplingEndpointBinding {
    /// The endpoint-binding schema version.
    pub schema: SamplingEndpointBindingSchemaVersion,
    /// SHA-256 fingerprint for the exclusively leased TRACE32 endpoint.
    pub endpoint_fingerprint: Sha256Digest,
    /// Fixed algorithm used for [`Self::endpoint_fingerprint`].
    pub endpoint_fingerprint_scheme: EndpointFingerprintScheme,
}

impl SamplingEndpointBinding {
    /// Validates this closed endpoint binding document.
    pub fn validate(&self) -> Result<(), SamplingEndpointBindingValidationError> {
        Ok(())
    }
}

/// Requested sampling method for a configure event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SamplingConfigureMethod {
    /// Runtime PC snooping without stopping the target.
    Realtime,
    /// Periodic stop-and-restart PC sampling.
    StopAndGo,
}

/// Exact JSON `true` when cleanup is specifically part of recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplingCleanupRecovery;

impl Serialize for SamplingCleanupRecovery {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for SamplingCleanupRecovery {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(D::Error::custom("recovery must be true"))
        }
    }
}

impl JsonSchema for SamplingCleanupRecovery {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("SamplingCleanupRecovery")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({"type": "boolean", "const": true})
    }
}

/// Fixed sidecar identity allowed to emit sampling-driver events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum SamplingDriverOwner {
    /// Current Lauterbach sampling MCP sidecar contract.
    #[serde(rename = "lauterbach-sampling-mcp/v1")]
    LauterbachSamplingMcpV1,
}

/// Tagged details of one durable sampling-driver event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "event",
    content = "details",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum SamplingDriverEventDetails {
    /// Intent to configure TRACE32 PERF.
    ConfigureIntent {
        /// Sampling method to configure.
        method: SamplingConfigureMethod,
    },
    /// TRACE32 PERF configuration was observed.
    ConfigureObserved {
        /// Sampling method TRACE32 reported after configuration.
        method: SamplingConfigureMethod,
    },
    /// Intent to start a bounded sampling interval.
    StartIntent {
        /// Requested capture duration in milliseconds.
        #[schemars(range(min = 1, max = 60_000))]
        duration_ms: u32,
    },
    /// Sampling start was observed.
    StartObserved {},
    /// Intent to stop sampling.
    StopIntent {},
    /// Sampling stop was observed.
    StopObserved {},
    /// Intent to clean up PERF state.
    CleanupIntent {
        /// Present only as `true` when cleanup is part of recovery.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery: Option<SamplingCleanupRecovery>,
    },
    /// PERF cleanup was observed.
    CleanupObserved {},
    /// PERF cleanup failed with a bounded diagnostic.
    CleanupFailed {
        /// Present as `true` when this failure occurred during recovery.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery: Option<SamplingCleanupRecovery>,
        /// Failure diagnostic safe for durable logs.
        #[schemars(length(min = 1, max = 1_024))]
        error: String,
    },
    /// Recovery state was observed before a new transaction proceeds.
    RecoveryObserved {
        /// Recovery state was explicitly observed.
        recovery: SamplingCleanupRecovery,
    },
    /// Intent to export the final sampling artifact.
    ExportIntent {},
    /// Exported artifact metadata was observed.
    ExportObserved {
        /// Canonical path relative to the Session artifact directory.
        relative_path: ArtifactPath,
        /// SHA-256 of the exported artifact bytes.
        sha256: Sha256Digest,
        /// Nonzero byte size of the exported artifact.
        #[schemars(range(min = 1))]
        size_bytes: u64,
    },
}

/// One append-only event emitted by the sampling sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SamplingDriverEvent {
    /// The sampling-driver event schema version.
    pub schema: SamplingDriverEventSchemaVersion,
    /// Canonical lowercase UUID v4 for the sampling transaction.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    ))]
    pub transaction_id: String,
    /// SHA-256 fingerprint for the exclusively leased TRACE32 endpoint.
    pub endpoint_fingerprint: Sha256Digest,
    /// Fixed algorithm used for [`Self::endpoint_fingerprint`].
    pub endpoint_fingerprint_scheme: EndpointFingerprintScheme,
    /// Fixed versioned sidecar identity that emitted this event.
    pub owner: SamplingDriverOwner,
    /// Strictly positive append-only transaction sequence.
    #[schemars(range(min = 1))]
    pub sequence: u64,
    /// Bounded timestamp string observed by the sidecar.
    #[schemars(length(min = 1, max = 64))]
    pub observed_at: String,
    /// Tagged event name and exact details.
    #[serde(flatten)]
    pub details: SamplingDriverEventDetails,
}

impl SamplingDriverEvent {
    /// Validates transaction identity and event-detail constraints.
    pub fn validate(&self) -> Result<(), SamplingDriverEventValidationError> {
        if !is_canonical_uuid_v4(&self.transaction_id) {
            return Err(SamplingDriverEventValidationError::InvalidTransactionId);
        }
        validate_text(&self.observed_at, 64)
            .map_err(|_| SamplingDriverEventValidationError::InvalidObservedAt)?;
        if self.sequence == 0 {
            return Err(SamplingDriverEventValidationError::ZeroSequence);
        }
        match &self.details {
            SamplingDriverEventDetails::StartIntent { duration_ms }
                if !(1..=60_000).contains(duration_ms) =>
            {
                Err(SamplingDriverEventValidationError::InvalidStartDuration)
            }
            SamplingDriverEventDetails::CleanupFailed { error, .. }
                if validate_text(error, 1_024).is_err() =>
            {
                Err(SamplingDriverEventValidationError::InvalidFailureError)
            }
            SamplingDriverEventDetails::ExportObserved { size_bytes: 0, .. } => {
                Err(SamplingDriverEventValidationError::ZeroExportSize)
            }
            _ => Ok(()),
        }
    }
}

/// Event name used by the receipt's digest claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SamplingDriverEventName {
    /// Configure intent event.
    ConfigureIntent,
    /// Configure observed event.
    ConfigureObserved,
    /// Start intent event.
    StartIntent,
    /// Start observed event.
    StartObserved,
    /// Stop intent event.
    StopIntent,
    /// Stop observed event.
    StopObserved,
    /// Cleanup intent event.
    CleanupIntent,
    /// Cleanup observed event.
    CleanupObserved,
    /// Cleanup failed event.
    CleanupFailed,
    /// Recovery observed event.
    RecoveryObserved,
    /// Export intent event.
    ExportIntent,
    /// Export observed event.
    ExportObserved,
}

/// Content-addressed claim for one durable driver-journal event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SamplingJournalEventClaim {
    /// Event sequence in the sidecar journal.
    #[schemars(range(min = 1, max = 10))]
    pub sequence: u64,
    /// Event named by the claimed bytes.
    pub event: SamplingDriverEventName,
    /// SHA-256 digest of the exact serialized journal event bytes.
    pub sha256: Sha256Digest,
}

/// Host-derived receipt proving a complete successful sampling transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SamplingCaptureReceipt {
    /// The sampling-capture receipt schema version.
    pub schema: SamplingCaptureReceiptSchemaVersion,
    /// Portable Session identifier owning the capture.
    #[schemars(length(min = 1, max = 64))]
    pub session_id: String,
    /// Current host Session operation identifier as 32 lowercase hexadecimal characters.
    #[schemars(regex(pattern = r"^[0-9a-f]{32}$"))]
    pub session_operation_id: String,
    /// Canonical lowercase UUID v4 for the completed transaction.
    #[schemars(regex(
        pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    ))]
    pub transaction_id: String,
    /// SHA-256 fingerprint for the exclusively leased TRACE32 endpoint.
    pub endpoint_fingerprint: Sha256Digest,
    /// Fixed algorithm used for [`Self::endpoint_fingerprint`].
    pub endpoint_fingerprint_scheme: EndpointFingerprintScheme,
    /// SHA-256 digest of the exact session-owned sampling capture request.
    pub session_request_sha256: Sha256Digest,
    /// SHA-256 digest of the accepted PC-hit histogram artifact.
    pub histogram_sha256: Sha256Digest,
    /// Nonzero byte size of the accepted PC-hit histogram artifact.
    #[schemars(range(min = 1))]
    pub histogram_size_bytes: u64,
    /// Exact successful sidecar event sequence and byte digests.
    #[schemars(length(min = 10, max = 10))]
    pub journal_event_claims: Vec<SamplingJournalEventClaim>,
}

/// Validation error for a sampling-capture request.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SamplingCaptureRequestValidationError {
    /// Request range count was outside the bounded contract.
    #[error("ranges must contain 1..=256 entries")]
    InvalidRangeCount,
    /// Bucket size was outside the allowed byte range.
    #[error("bucket_size must be in 1..=1048576")]
    InvalidBucketSize,
    /// Duration was outside the allowed sidecar range.
    #[error("duration_ms must be in 1..=60000")]
    InvalidDuration,
    /// One range was empty or reversed.
    #[error("ranges must be nonempty half-open intervals")]
    InvalidRange,
    /// Ranges were not strictly sorted or overlapped.
    #[error("ranges must be strictly sorted and non-overlapping")]
    UnsortedOrOverlappingRanges,
    /// Address calculations overflowed.
    #[error("range bucket expansion overflowed address arithmetic")]
    AddressArithmeticOverflow,
    /// Range expansion exceeded the maximum bucket count.
    #[error("range expansion exceeds 256 buckets")]
    TooManyBuckets,
}

impl SamplingCaptureReceipt {
    /// Validates receipt identity and the complete successful journal sequence.
    pub fn validate(&self) -> Result<(), SamplingCaptureReceiptValidationError> {
        if !is_portable_session_id(&self.session_id) {
            return Err(SamplingCaptureReceiptValidationError::InvalidSessionId);
        }
        if !is_lowercase_hex(&self.session_operation_id, 32) {
            return Err(SamplingCaptureReceiptValidationError::InvalidSessionOperationId);
        }
        if !is_canonical_uuid_v4(&self.transaction_id) {
            return Err(SamplingCaptureReceiptValidationError::InvalidTransactionId);
        }
        if self.histogram_size_bytes == 0 {
            return Err(SamplingCaptureReceiptValidationError::ZeroHistogramSize);
        }
        if self.journal_event_claims.len() != SUCCESSFUL_SAMPLING_JOURNAL_EVENT_COUNT {
            return Err(SamplingCaptureReceiptValidationError::WrongClaimCount);
        }
        let expected = [
            SamplingDriverEventName::ConfigureIntent,
            SamplingDriverEventName::ConfigureObserved,
            SamplingDriverEventName::StartIntent,
            SamplingDriverEventName::StartObserved,
            SamplingDriverEventName::StopIntent,
            SamplingDriverEventName::StopObserved,
            SamplingDriverEventName::CleanupIntent,
            SamplingDriverEventName::CleanupObserved,
            SamplingDriverEventName::ExportIntent,
            SamplingDriverEventName::ExportObserved,
        ];
        let mut digests = BTreeSet::new();
        for (index, (claim, expected_event)) in
            self.journal_event_claims.iter().zip(expected).enumerate()
        {
            if claim.sequence != (index + 1) as u64 || claim.event != expected_event {
                return Err(SamplingCaptureReceiptValidationError::InvalidSuccessfulEventOrder);
            }
            if !digests.insert(claim.sha256.clone()) {
                return Err(SamplingCaptureReceiptValidationError::DuplicateJournalClaimDigest);
            }
        }
        Ok(())
    }
}

/// Returns whether `value` is exactly a lowercase, hyphenated UUID v4.
#[must_use]
pub fn is_canonical_uuid_v4(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            14 => byte == b'4',
            19 => matches!(byte, b'8' | b'9' | b'a' | b'b'),
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn is_lowercase_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_text(value: &str, max_bytes: usize) -> Result<(), ()> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(());
    }
    Ok(())
}

/// Validation error for an endpoint binding.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SamplingEndpointBindingValidationError {}

/// Validation error for a sampling-driver event.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SamplingDriverEventValidationError {
    /// The transaction identifier was not canonical lowercase UUID v4.
    #[error("transaction_id must be a canonical lowercase UUID v4")]
    InvalidTransactionId,
    /// Observed timestamp was empty, oversized, or contained a control character.
    #[error("observed_at is invalid")]
    InvalidObservedAt,
    /// Journal sequence must start at one.
    #[error("sequence must be nonzero")]
    ZeroSequence,
    /// Start duration must be in the bounded sidecar range.
    #[error("start duration_ms must be in 1..=60000")]
    InvalidStartDuration,
    /// Cleanup failures need a bounded diagnostic.
    #[error("cleanup failure error is invalid")]
    InvalidFailureError,
    /// Exported artifacts cannot be empty.
    #[error("export size_bytes must be nonzero")]
    ZeroExportSize,
}

/// Validation error for a successful sampling-capture receipt.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SamplingCaptureReceiptValidationError {
    /// Session identifiers must use the shared portable syntax.
    #[error("session_id must use the portable Session-ID syntax")]
    InvalidSessionId,
    /// The Host Session operation identifier was not canonical lowercase hex.
    #[error("session_operation_id must be 32 lowercase hexadecimal characters")]
    InvalidSessionOperationId,
    /// The transaction identifier was not canonical lowercase UUID v4.
    #[error("transaction_id must be a canonical lowercase UUID v4")]
    InvalidTransactionId,
    /// Histogram artifacts cannot be empty.
    #[error("histogram_size_bytes must be nonzero")]
    ZeroHistogramSize,
    /// Successful capture receipts require exactly ten journal claims.
    #[error("successful capture receipt requires exactly ten journal claims")]
    WrongClaimCount,
    /// Claims were not the exact successful event sequence numbered one through ten.
    #[error("journal claims are not in the required successful sequence")]
    InvalidSuccessfulEventOrder,
    /// Each claimed event byte digest must be unique.
    #[error("journal claim digests must be unique")]
    DuplicateJournalClaimDigest,
}
