//! Session manifests, artifact provenance, and durable lifecycle state.

use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
    fmt,
    str::FromStr,
};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

use crate::{
    CaptureCapabilities, CaptureConfigArtifactClaim, CaptureInstrumentationConfig,
    ManifestSchemaVersion, Properties, StateSchemaVersion,
};

/// Maximum UTF-8 byte length of an artifact identifier.
pub const MAX_ARTIFACT_ID_BYTES: usize = 128;
/// Maximum UTF-8 byte length of a canonical artifact path.
pub const MAX_ARTIFACT_PATH_BYTES: usize = 1_024;
/// Maximum number of direct provenance inputs for one artifact.
pub const MAX_ARTIFACT_INPUTS: usize = 1_024;
/// Maximum number of artifacts declared by one manifest.
pub const MAX_MANIFEST_ARTIFACTS: usize = 16_384;
/// Maximum number of clock domains declared by one manifest.
pub const MAX_MANIFEST_CLOCKS: usize = 1_024;
/// Maximum number of processing stages declared by one manifest.
pub const MAX_MANIFEST_STAGES: usize = 4_096;
/// Maximum number of artifact references in one stage input or output list.
pub const MAX_STAGE_ARTIFACT_REFERENCES: usize = MAX_MANIFEST_ARTIFACTS;

const MAX_SHORT_METADATA_BYTES: usize = 256;
const MAX_LONG_METADATA_BYTES: usize = 4_096;
const MAX_PROPERTY_KEY_BYTES: usize = 128;
const MAX_PROPERTY_STRING_BYTES: usize = 16 * 1_024;
const MAX_PROPERTY_ENTRIES: usize = 1_024;
const MAX_PROPERTY_ARRAY_ITEMS: usize = 4_096;
const MAX_PROPERTY_DEPTH: usize = 16;

/// A canonical, portable path relative to its session artifact directory.
///
/// Backslashes, drive prefixes, empty segments, `.` segments, and `..`
/// segments are rejected. Segments are restricted to printable ASCII so the
/// serialized path has the same identity on case-sensitive Linux filesystems
/// and default case-insensitive Windows filesystems.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ArtifactPath(String);

impl ArtifactPath {
    /// Validates and constructs a relative artifact path.
    pub fn new(path: impl Into<String>) -> Result<Self, ArtifactPathError> {
        let path = path.into();
        validate_artifact_path(&path)?;
        Ok(Self(path))
    }

    /// Returns the canonical forward-slash path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the ASCII-case-folded key used for portable path uniqueness.
    #[must_use]
    pub fn portable_key(&self) -> String {
        portable_name_key(&self.0)
    }
}

impl AsRef<str> for ArtifactPath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ArtifactPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ArtifactPath {
    type Err = ArtifactPathError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for ArtifactPath {
    type Error = ArtifactPathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for ArtifactPath {
    type Error = ArtifactPathError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for ArtifactPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

impl JsonSchema for ArtifactPath {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("ArtifactPath")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": 1024,
            "pattern": r#"^(?=[\u0020-\u007E]+$)(?!/)(?!.*[<>:"\\|?*])(?!.*//)(?!.*(?:^|/)\.\.?(?:/|$))(?!.*/$)(?!.*[. ](?:/|$))(?!(?:.*?/)?(?:[Cc][Oo][Nn]|[Pp][Rr][Nn]|[Aa][Uu][Xx]|[Nn][Uu][Ll]|[Cc][Oo][Nn][Ii][Nn]\$|[Cc][Oo][Nn][Oo][Uu][Tt]\$|[Cc][Oo][Mm][1-9]|[Ll][Pp][Tt][1-9]) *(?:\.[^/]*)?(?:/|$)).+$"#
        })
    }
}

/// Returns the ASCII-case-folded key used by portable identifiers and paths.
///
/// Session identifiers, artifact identifiers, and artifact paths are all
/// restricted to ASCII before using this key for uniqueness. A store created
/// on a case-sensitive host therefore remains unambiguous on default
/// case-insensitive Windows filesystems.
#[must_use]
pub fn portable_name_key(value: &str) -> String {
    let mut key = value.to_owned();
    key.make_ascii_lowercase();
    key
}

/// Returns whether one printable-ASCII path segment is portable across hosts.
///
/// This rejects Windows-invalid characters, control characters, trailing dots
/// or spaces, and reserved device basenames even when they have an extension.
#[must_use]
pub fn is_portable_name_segment(segment: &str) -> bool {
    !segment.is_empty()
        && !segment.ends_with(['.', ' '])
        && segment.chars().all(|character| {
            character.is_ascii()
                && !character.is_ascii_control()
                && !matches!(
                    character,
                    '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*' | '/'
                )
        })
        && !is_windows_device_basename(segment)
}

/// Returns whether a value satisfies the shared portable Session-ID contract.
#[must_use]
pub fn is_portable_session_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => true,
            b'_' | b'-' => index > 0,
            _ => false,
        })
        && is_portable_name_segment(value)
}

/// Returns whether a value satisfies the shared portable artifact-ID contract.
#[must_use]
pub fn is_portable_artifact_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ARTIFACT_ID_BYTES
        && value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => true,
            b'_' | b'-' | b'.' => index > 0,
            _ => false,
        })
        && is_portable_name_segment(value)
}

fn is_windows_device_basename(segment: &str) -> bool {
    let basename = segment
        .split_once('.')
        .map_or(segment, |(name, _)| name)
        .trim_end_matches(['.', ' ']);
    basename.eq_ignore_ascii_case("con")
        || basename.eq_ignore_ascii_case("prn")
        || basename.eq_ignore_ascii_case("aux")
        || basename.eq_ignore_ascii_case("nul")
        || basename.eq_ignore_ascii_case("conin$")
        || basename.eq_ignore_ascii_case("conout$")
        || device_number(basename, "com")
        || device_number(basename, "lpt")
}

fn device_number(basename: &str, prefix: &str) -> bool {
    let Some(suffix) = basename.get(prefix.len()..) else {
        return false;
    };
    basename
        .get(..prefix.len())
        .is_some_and(|actual| actual.eq_ignore_ascii_case(prefix))
        && matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
}

fn validate_artifact_path(path: &str) -> Result<(), ArtifactPathError> {
    if path.is_empty() {
        return Err(ArtifactPathError::Empty);
    }
    if path.len() > MAX_ARTIFACT_PATH_BYTES {
        return Err(ArtifactPathError::TooLong {
            max_bytes: MAX_ARTIFACT_PATH_BYTES,
            actual_bytes: path.len(),
        });
    }
    if path.starts_with('/') || path.starts_with('\\') || path.contains(':') {
        return Err(ArtifactPathError::Absolute);
    }
    if path.contains('\\') {
        return Err(ArtifactPathError::Backslash);
    }
    if path.contains('\0') {
        return Err(ArtifactPathError::Nul);
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(ArtifactPathError::InvalidSegment);
        }
        if !is_portable_name_segment(segment) {
            return Err(ArtifactPathError::NonPortableSegment {
                segment: segment.to_owned(),
            });
        }
    }
    Ok(())
}

/// A rejected artifact path.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ArtifactPathError {
    /// The path is empty.
    #[error("artifact path is empty")]
    Empty,
    /// The path is absolute or contains a platform drive or URI prefix.
    #[error("artifact path must be relative and must not contain a drive or URI prefix")]
    Absolute,
    /// The path uses a backslash instead of the canonical forward slash.
    #[error("artifact path must use forward slashes")]
    Backslash,
    /// The path contains a NUL byte.
    #[error("artifact path contains a NUL byte")]
    Nul,
    /// The path contains an empty, current-directory, or parent-directory segment.
    #[error("artifact path contains an empty, `.` or `..` segment")]
    InvalidSegment,
    /// One segment is not representable without ambiguity on Windows.
    #[error("artifact path segment `{segment}` is not portable")]
    NonPortableSegment {
        /// Rejected path segment.
        segment: String,
    },
    /// The path exceeds the portable serialized-size limit.
    #[error("artifact path is {actual_bytes} bytes; maximum is {max_bytes}")]
    TooLong {
        /// Maximum permitted UTF-8 byte length.
        max_bytes: usize,
        /// Observed UTF-8 byte length.
        actual_bytes: usize,
    },
}

/// A lowercase hexadecimal SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Validates and constructs a SHA-256 digest.
    pub fn new(digest: impl Into<String>) -> Result<Self, Sha256DigestError> {
        let digest = digest.into();
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(Sha256DigestError::InvalidDigest);
        }
        Ok(Self(digest))
    }

    /// Returns the lowercase hexadecimal digest.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Sha256Digest {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Sha256Digest {
    type Err = Sha256DigestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = Sha256DigestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Sha256Digest {
    type Error = Sha256DigestError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

impl JsonSchema for Sha256Digest {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("Sha256Digest")
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^[0-9a-f]{64}$"
        })
    }
}

/// A rejected SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Sha256DigestError {
    /// The digest is not exactly 64 lowercase hexadecimal characters.
    #[error("SHA-256 digest must contain exactly 64 lowercase hexadecimal characters")]
    InvalidDigest,
}

/// Version and provenance of the t32perf tool writing a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ToolInfo {
    /// Tool or executable name.
    pub name: String,
    /// Tool semantic version or build version.
    pub version: String,
    /// Source-control commit when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

/// Capture-adapter identity recorded in a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AdapterInfo {
    /// Stable adapter identifier.
    pub id: String,
    /// Adapter contract or implementation version.
    pub version: String,
}

/// Target identity and capability metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TargetInfo {
    /// Target architecture name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    /// MCU, SoC, or device name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Board name or revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub board: Option<String>,
    /// Number of traced processor cores.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_count: Option<u32>,
    /// Adapter-specific target metadata.
    #[serde(default, skip_serializing_if = "Properties::is_empty")]
    pub properties: Properties,
}

/// TRACE32 installation and probe metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Trace32Info {
    /// TRACE32 build identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
    /// Probe model or serial-safe identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<String>,
    /// Loaded TRACE32 architecture package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture_package: Option<String>,
    /// Additional TRACE32 metadata.
    #[serde(default, skip_serializing_if = "Properties::is_empty")]
    pub properties: Properties,
}

/// Parameters and environment used for capture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CaptureInfo {
    /// Capture provider that issued the trusted receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Selected capture mode, such as `etm`, `itm`, or `sampling`.
    pub mode: String,
    /// Adapter responsible for capture and normalization.
    pub adapter: AdapterInfo,
    /// Target metadata when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetInfo>,
    /// TRACE32 metadata when capture used TRACE32.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace32: Option<Trace32Info>,
    /// Digest of the canonical capture request when retained.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_sha256: Option<Sha256Digest>,
    /// Cores for which the trusted receipt claims coverage.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub covered_cores: Vec<u32>,
    /// Observation-family support copied from the trusted capture receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<CaptureCapabilities>,
    /// Exact immutable capture-configuration artifact and digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_config: Option<CaptureConfigArtifactClaim>,
    /// Target custom-event method and measured incremental overhead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instrumentation: Option<CaptureInstrumentationConfig>,
}

/// Firmware identity used during a capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FirmwareInfo {
    /// User-provided ELF path when disclosure is permitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elf_path: Option<String>,
    /// SHA-256 digest of the ELF file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elf_sha256: Option<Sha256Digest>,
    /// Firmware build identifier extracted from the image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
}

/// A clock domain relevant to timestamp conversion or analysis.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ClockInfo {
    /// Stable clock-domain identifier.
    pub id: String,
    /// Clock frequency in hertz when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub frequency_hz: Option<u64>,
    /// Source or derivation of the frequency value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Clock-specific metadata.
    #[serde(default, skip_serializing_if = "Properties::is_empty")]
    pub properties: Properties,
}

/// Status of one capture or processing stage recorded in the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    /// The stage has not started.
    Pending,
    /// The stage is running.
    Running,
    /// The stage completed successfully.
    Complete,
    /// The stage failed.
    Failed,
    /// The stage was intentionally skipped.
    Skipped,
}

/// Provenance and outcome of one capture or processing stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StageInfo {
    /// Stable stage name.
    pub name: String,
    /// Current or terminal stage status.
    pub status: StageStatus,
    /// RFC 3339 start timestamp when the stage started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// RFC 3339 completion timestamp when the stage ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    /// Artifact identifiers consumed by the stage.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_artifact_ids: Vec<String>,
    /// Artifact identifiers produced by the stage.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_artifact_ids: Vec<String>,
    /// Optional stage status detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// One immutable file artifact and its provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Artifact {
    /// Stable artifact identifier unique within the session.
    pub id: String,
    /// Extensible artifact kind such as `raw_trace` or `perfetto`.
    pub kind: String,
    /// Canonical path relative to the session directory.
    pub relative_path: ArtifactPath,
    /// IANA media type of the file.
    pub media_type: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// SHA-256 digest of the complete file.
    pub sha256: Sha256Digest,
    /// Tool or stage identifier that produced the file.
    pub producer: String,
    /// Artifact identifiers consumed to produce this artifact.
    pub input_artifact_ids: Vec<String>,
}

impl Artifact {
    /// Validates bounded artifact metadata and direct provenance references.
    pub fn validate(&self) -> Result<(), ArtifactValidationError> {
        validate_artifact_identifier(&self.id, "artifact.id")?;
        validate_text(&self.kind, "artifact.kind", MAX_SHORT_METADATA_BYTES)?;
        validate_text(
            &self.media_type,
            "artifact.media_type",
            MAX_SHORT_METADATA_BYTES,
        )?;
        if !self.media_type.contains('/') {
            return Err(ArtifactValidationError::InvalidField {
                field: "artifact.media_type",
                reason: "must contain a type/subtype separator",
            });
        }
        validate_text(
            &self.producer,
            "artifact.producer",
            MAX_SHORT_METADATA_BYTES,
        )?;
        if self.input_artifact_ids.len() > MAX_ARTIFACT_INPUTS {
            return Err(ArtifactValidationError::TooManyInputs {
                limit: MAX_ARTIFACT_INPUTS,
                actual: self.input_artifact_ids.len(),
            });
        }
        let mut inputs = BTreeSet::new();
        let self_key = portable_name_key(&self.id);
        for input in &self.input_artifact_ids {
            validate_artifact_identifier(input, "artifact.input_artifact_ids")?;
            let input_key = portable_name_key(input);
            if input_key == self_key {
                return Err(ArtifactValidationError::SelfReference);
            }
            if !inputs.insert(input_key) {
                return Err(ArtifactValidationError::DuplicateInput {
                    artifact_id: input.clone(),
                });
            }
        }
        Ok(())
    }
}

/// A semantic invariant violation in artifact metadata.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ArtifactValidationError {
    /// A textual field is empty, too long, contains control characters, or has invalid syntax.
    #[error("invalid {field}: {reason}")]
    InvalidField {
        /// Rejected field name.
        field: &'static str,
        /// Stable rejection reason.
        reason: &'static str,
    },
    /// An artifact declares more direct inputs than the bounded contract permits.
    #[error("artifact has {actual} inputs; maximum is {limit}")]
    TooManyInputs {
        /// Maximum permitted input count.
        limit: usize,
        /// Observed input count.
        actual: usize,
    },
    /// One input identifier appears more than once.
    #[error("artifact contains duplicate input `{artifact_id}`")]
    DuplicateInput {
        /// Duplicated input identifier.
        artifact_id: String,
    },
    /// An artifact directly names itself as an input.
    #[error("artifact directly references itself as an input")]
    SelfReference,
}

/// Durable session manifest and artifact index.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Manifest {
    /// The manifest schema version.
    pub schema: ManifestSchemaVersion,
    /// Stable session identifier.
    pub session_id: String,
    /// RFC 3339 session creation timestamp.
    pub created_at: String,
    /// Tool version and source provenance.
    pub tool: ToolInfo,
    /// Capture configuration and adapter identity.
    pub capture: CaptureInfo,
    /// Firmware identity.
    pub firmware: FirmwareInfo,
    /// Relevant clock domains.
    pub clocks: Vec<ClockInfo>,
    /// Capture and processing stages.
    pub stages: Vec<StageInfo>,
    /// Immutable artifacts owned by the session.
    pub artifacts: Vec<Artifact>,
}

impl Manifest {
    /// Validates artifact uniqueness, references, and provenance acyclicity.
    pub fn validate(&self) -> Result<(), ManifestValidationError> {
        if !is_portable_session_id(&self.session_id) {
            return Err(invalid_manifest_metadata(
                "session_id",
                "must use the portable Session-ID syntax",
            ));
        }
        validate_manifest_text(&self.created_at, "created_at", 64)?;
        validate_manifest_text(&self.tool.name, "tool.name", MAX_SHORT_METADATA_BYTES)?;
        validate_manifest_text(&self.tool.version, "tool.version", MAX_SHORT_METADATA_BYTES)?;
        validate_manifest_optional_text(
            self.tool.commit.as_deref(),
            "tool.commit",
            MAX_SHORT_METADATA_BYTES,
        )?;
        validate_manifest_text(&self.capture.mode, "capture.mode", MAX_SHORT_METADATA_BYTES)?;
        validate_manifest_optional_text(
            self.capture.provider.as_deref(),
            "capture.provider",
            MAX_SHORT_METADATA_BYTES,
        )?;
        let trusted_capture_fields = [
            self.capture.provider.is_some(),
            self.capture.capabilities.is_some(),
            self.capture.capture_config.is_some(),
        ];
        if trusted_capture_fields.iter().any(|present| *present)
            && !trusted_capture_fields.iter().all(|present| *present)
        {
            return Err(invalid_manifest_metadata(
                "capture",
                "provider, capabilities, and capture_config must all be present or all be absent",
            ));
        }
        if let Some(capabilities) = &self.capture.capabilities {
            capabilities.validate().map_err(|error| {
                invalid_manifest_metadata("capture.capabilities", error.to_string())
            })?;
        }
        if let Some(instrumentation) = &self.capture.instrumentation {
            if self.capture.capture_config.is_none() {
                return Err(invalid_manifest_metadata(
                    "capture.instrumentation",
                    "instrumentation requires an immutable capture_config claim",
                ));
            }
            instrumentation.validate().map_err(|error| {
                invalid_manifest_metadata("capture.instrumentation", error.to_string())
            })?;
        }
        validate_manifest_identifier(
            &self.capture.adapter.id,
            "capture.adapter.id",
            MAX_SHORT_METADATA_BYTES,
        )?;
        validate_manifest_text(
            &self.capture.adapter.version,
            "capture.adapter.version",
            MAX_SHORT_METADATA_BYTES,
        )?;
        if let Some(target) = &self.capture.target {
            validate_manifest_optional_text(
                target.architecture.as_deref(),
                "capture.target.architecture",
                MAX_SHORT_METADATA_BYTES,
            )?;
            validate_manifest_optional_text(
                target.device.as_deref(),
                "capture.target.device",
                MAX_SHORT_METADATA_BYTES,
            )?;
            validate_manifest_optional_text(
                target.board.as_deref(),
                "capture.target.board",
                MAX_SHORT_METADATA_BYTES,
            )?;
            validate_properties(&target.properties, "capture.target.properties")?;
        }
        let mut covered_cores = BTreeSet::new();
        for core_id in &self.capture.covered_cores {
            if !covered_cores.insert(*core_id) {
                return Err(invalid_manifest_metadata(
                    "capture.covered_cores",
                    format!("core {core_id} appears more than once"),
                ));
            }
            if self
                .capture
                .target
                .as_ref()
                .and_then(|target| target.core_count)
                .is_some_and(|core_count| *core_id >= core_count)
            {
                return Err(invalid_manifest_metadata(
                    "capture.covered_cores",
                    format!("core {core_id} is outside the declared target core count"),
                ));
            }
        }
        if let Some(trace32) = &self.capture.trace32 {
            validate_manifest_optional_text(
                trace32.build.as_deref(),
                "capture.trace32.build",
                MAX_SHORT_METADATA_BYTES,
            )?;
            validate_manifest_optional_text(
                trace32.probe.as_deref(),
                "capture.trace32.probe",
                MAX_SHORT_METADATA_BYTES,
            )?;
            validate_manifest_optional_text(
                trace32.architecture_package.as_deref(),
                "capture.trace32.architecture_package",
                MAX_SHORT_METADATA_BYTES,
            )?;
            validate_properties(&trace32.properties, "capture.trace32.properties")?;
        }
        validate_manifest_optional_text(
            self.firmware.elf_path.as_deref(),
            "firmware.elf_path",
            MAX_LONG_METADATA_BYTES,
        )?;
        validate_manifest_optional_text(
            self.firmware.build_id.as_deref(),
            "firmware.build_id",
            MAX_SHORT_METADATA_BYTES,
        )?;

        if self.clocks.len() > MAX_MANIFEST_CLOCKS {
            return Err(ManifestValidationError::TooManyClocks {
                limit: MAX_MANIFEST_CLOCKS,
                actual: self.clocks.len(),
            });
        }

        let mut clocks = BTreeSet::new();
        for clock in &self.clocks {
            validate_manifest_identifier(&clock.id, "clocks[].id", MAX_ARTIFACT_ID_BYTES)?;
            if clock.frequency_hz == Some(0) {
                return Err(invalid_manifest_metadata(
                    "clocks[].frequency_hz",
                    "clock frequency must be greater than zero when present",
                ));
            }
            validate_manifest_optional_text(
                clock.source.as_deref(),
                "clocks[].source",
                MAX_SHORT_METADATA_BYTES,
            )?;
            validate_properties(&clock.properties, "clocks[].properties")?;
            if !clocks.insert(clock.id.as_str()) {
                return Err(ManifestValidationError::DuplicateClockId {
                    id: clock.id.clone(),
                });
            }
        }

        if self.stages.len() > MAX_MANIFEST_STAGES {
            return Err(ManifestValidationError::TooManyStages {
                limit: MAX_MANIFEST_STAGES,
                actual: self.stages.len(),
            });
        }
        let mut stages = BTreeSet::new();
        for stage in &self.stages {
            validate_manifest_identifier(&stage.name, "stages[].name", MAX_ARTIFACT_ID_BYTES)?;
            if !stages.insert(stage.name.as_str()) {
                return Err(ManifestValidationError::DuplicateStageName {
                    name: stage.name.clone(),
                });
            }
            validate_manifest_optional_text(
                stage.started_at.as_deref(),
                "stages[].started_at",
                64,
            )?;
            validate_manifest_optional_text(
                stage.completed_at.as_deref(),
                "stages[].completed_at",
                64,
            )?;
            validate_manifest_optional_text(
                stage.message.as_deref(),
                "stages[].message",
                MAX_LONG_METADATA_BYTES,
            )?;
            validate_stage_references(&stage.input_artifact_ids, "stages[].input_artifact_ids")?;
            validate_stage_references(&stage.output_artifact_ids, "stages[].output_artifact_ids")?;
        }

        if self.artifacts.len() > MAX_MANIFEST_ARTIFACTS {
            return Err(ManifestValidationError::TooManyArtifacts {
                limit: MAX_MANIFEST_ARTIFACTS,
                actual: self.artifacts.len(),
            });
        }

        let mut artifacts = BTreeMap::new();
        let mut artifact_keys = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for (index, artifact) in self.artifacts.iter().enumerate() {
            artifact.validate().map_err(|error| {
                ManifestValidationError::InvalidArtifactMetadata {
                    index,
                    message: error.to_string(),
                }
            })?;
            if !artifact_keys.insert(portable_name_key(&artifact.id))
                || artifacts.insert(artifact.id.as_str(), artifact).is_some()
            {
                return Err(ManifestValidationError::DuplicateArtifactId {
                    id: artifact.id.clone(),
                });
            }
            if !paths.insert(artifact.relative_path.portable_key()) {
                return Err(ManifestValidationError::DuplicateArtifactPath {
                    path: artifact.relative_path.clone(),
                });
            }
        }

        if let Some(claim) = &self.capture.capture_config {
            claim.validate().map_err(|error| {
                invalid_manifest_metadata("capture.capture_config", error.to_string())
            })?;
            let artifact = artifacts.get(claim.artifact_id.as_str()).ok_or_else(|| {
                invalid_manifest_metadata(
                    "capture.capture_config",
                    format!("artifact `{}` is not registered", claim.artifact_id),
                )
            })?;
            if artifact.kind != "capture_config" || artifact.sha256 != claim.sha256 {
                return Err(invalid_manifest_metadata(
                    "capture.capture_config",
                    "artifact kind or digest does not match the capture config claim",
                ));
            }
            if let Some(instrumentation) = &self.capture.instrumentation {
                let evidence_id = &instrumentation.overhead.evidence_artifact_id;
                let Some(evidence) = artifacts.get(evidence_id.as_str()) else {
                    return Err(invalid_manifest_metadata(
                        "capture.instrumentation",
                        format!("evidence artifact `{evidence_id}` is not registered"),
                    ));
                };
                if evidence.kind != "instrumentation_overhead"
                    || evidence.media_type != "application/json"
                {
                    return Err(invalid_manifest_metadata(
                        "capture.instrumentation",
                        "evidence artifact must use kind instrumentation_overhead and media type application/json",
                    ));
                }
                if !artifact
                    .input_artifact_ids
                    .iter()
                    .any(|artifact_id| artifact_id == evidence_id)
                {
                    return Err(invalid_manifest_metadata(
                        "capture.instrumentation",
                        "capture_config provenance omits instrumentation evidence",
                    ));
                }
            }
        }

        for artifact in &self.artifacts {
            validate_artifact_references(&artifact.id, &artifact.input_artifact_ids, &artifacts)?;
        }
        for stage in &self.stages {
            validate_artifact_references(&stage.name, &stage.input_artifact_ids, &artifacts)?;
            validate_artifact_references(&stage.name, &stage.output_artifact_ids, &artifacts)?;
        }

        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        for artifact_id in artifacts.keys() {
            visit_artifact(artifact_id, &artifacts, &mut visiting, &mut visited)?;
        }
        Ok(())
    }
}

fn validate_identifier(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ArtifactValidationError> {
    if value.is_empty() {
        return Err(ArtifactValidationError::InvalidField {
            field,
            reason: "must not be empty",
        });
    }
    if value.len() > max_bytes {
        return Err(ArtifactValidationError::InvalidField {
            field,
            reason: "exceeds the UTF-8 byte limit",
        });
    }
    let valid = value.bytes().enumerate().all(|(index, byte)| match byte {
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' => true,
        b'_' | b'-' | b'.' => index > 0,
        _ => false,
    });
    if !valid {
        return Err(ArtifactValidationError::InvalidField {
            field,
            reason: "must use the portable identifier syntax",
        });
    }
    Ok(())
}

fn validate_artifact_identifier(
    value: &str,
    field: &'static str,
) -> Result<(), ArtifactValidationError> {
    if !is_portable_artifact_id(value) {
        return Err(ArtifactValidationError::InvalidField {
            field,
            reason: "must use the portable artifact identifier syntax",
        });
    }
    Ok(())
}

fn validate_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ArtifactValidationError> {
    if value.trim().is_empty() {
        return Err(ArtifactValidationError::InvalidField {
            field,
            reason: "must not be empty or whitespace",
        });
    }
    if value.len() > max_bytes {
        return Err(ArtifactValidationError::InvalidField {
            field,
            reason: "exceeds the UTF-8 byte limit",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ArtifactValidationError::InvalidField {
            field,
            reason: "contains a control character",
        });
    }
    Ok(())
}

fn validate_manifest_identifier(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ManifestValidationError> {
    validate_identifier(value, field, max_bytes).map_err(|error| {
        ManifestValidationError::InvalidMetadata {
            field,
            message: error.to_string(),
        }
    })
}

fn validate_manifest_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ManifestValidationError> {
    validate_text(value, field, max_bytes).map_err(|error| {
        ManifestValidationError::InvalidMetadata {
            field,
            message: error.to_string(),
        }
    })
}

fn validate_manifest_optional_text(
    value: Option<&str>,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ManifestValidationError> {
    match value {
        Some(value) => validate_manifest_text(value, field, max_bytes),
        None => Ok(()),
    }
}

fn validate_stage_references(
    references: &[String],
    field: &'static str,
) -> Result<(), ManifestValidationError> {
    if references.len() > MAX_STAGE_ARTIFACT_REFERENCES {
        return Err(ManifestValidationError::TooManyStageArtifactReferences {
            field,
            limit: MAX_STAGE_ARTIFACT_REFERENCES,
            actual: references.len(),
        });
    }
    let mut unique = BTreeSet::new();
    for reference in references {
        if !is_portable_artifact_id(reference) {
            return Err(invalid_manifest_metadata(
                field,
                "artifact reference must use the portable artifact identifier syntax",
            ));
        }
        if !unique.insert(portable_name_key(reference)) {
            return Err(ManifestValidationError::DuplicateStageArtifactReference {
                field,
                artifact_id: reference.clone(),
            });
        }
    }
    Ok(())
}

fn validate_properties(
    properties: &Properties,
    field: &'static str,
) -> Result<(), ManifestValidationError> {
    validate_property_object(properties, field, 0)
}

fn validate_property_object(
    properties: &Properties,
    field: &'static str,
    depth: usize,
) -> Result<(), ManifestValidationError> {
    validate_property_entries(properties.len(), properties.iter(), field, depth)
}

fn validate_property_entries<'a>(
    count: usize,
    entries: impl Iterator<Item = (&'a String, &'a serde_json::Value)>,
    field: &'static str,
    depth: usize,
) -> Result<(), ManifestValidationError> {
    if depth > MAX_PROPERTY_DEPTH {
        return Err(invalid_manifest_metadata(
            field,
            "property nesting is too deep",
        ));
    }
    if count > MAX_PROPERTY_ENTRIES {
        return Err(invalid_manifest_metadata(
            field,
            "property object has too many entries",
        ));
    }
    for (key, value) in entries {
        if key.is_empty() || key.len() > MAX_PROPERTY_KEY_BYTES || key.chars().any(char::is_control)
        {
            return Err(invalid_manifest_metadata(field, "property key is invalid"));
        }
        validate_property_value(value, field, depth + 1)?;
    }
    Ok(())
}

fn validate_property_value(
    value: &serde_json::Value,
    field: &'static str,
    depth: usize,
) -> Result<(), ManifestValidationError> {
    if depth > MAX_PROPERTY_DEPTH {
        return Err(invalid_manifest_metadata(
            field,
            "property nesting is too deep",
        ));
    }
    match value {
        serde_json::Value::String(value) => {
            if value.len() > MAX_PROPERTY_STRING_BYTES || value.chars().any(char::is_control) {
                return Err(invalid_manifest_metadata(
                    field,
                    "property string is invalid",
                ));
            }
        }
        serde_json::Value::Array(values) => {
            if values.len() > MAX_PROPERTY_ARRAY_ITEMS {
                return Err(invalid_manifest_metadata(
                    field,
                    "property array has too many items",
                ));
            }
            for value in values {
                validate_property_value(value, field, depth + 1)?;
            }
        }
        serde_json::Value::Object(values) => {
            validate_property_entries(values.len(), values.iter(), field, depth)?;
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
    Ok(())
}

fn invalid_manifest_metadata(
    field: &'static str,
    message: impl Into<String>,
) -> ManifestValidationError {
    ManifestValidationError::InvalidMetadata {
        field,
        message: message.into(),
    }
}

fn validate_artifact_references(
    owner: &str,
    references: &[String],
    artifacts: &BTreeMap<&str, &Artifact>,
) -> Result<(), ManifestValidationError> {
    for artifact_id in references {
        if !artifacts.contains_key(artifact_id.as_str()) {
            return Err(ManifestValidationError::UnknownArtifactReference {
                owner: owner.to_owned(),
                artifact_id: artifact_id.clone(),
            });
        }
    }
    Ok(())
}

fn visit_artifact<'a>(
    artifact_id: &'a str,
    artifacts: &BTreeMap<&'a str, &'a Artifact>,
    visiting: &mut BTreeSet<&'a str>,
    visited: &mut BTreeSet<&'a str>,
) -> Result<(), ManifestValidationError> {
    if visited.contains(artifact_id) {
        return Ok(());
    }
    if !visiting.insert(artifact_id) {
        return Err(ManifestValidationError::CyclicArtifactProvenance {
            artifact_id: artifact_id.to_owned(),
        });
    }
    for input in &artifacts[artifact_id].input_artifact_ids {
        visit_artifact(input, artifacts, visiting, visited)?;
    }
    visiting.remove(artifact_id);
    visited.insert(artifact_id);
    Ok(())
}

/// A semantic invariant violation in a session manifest.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ManifestValidationError {
    /// A bounded manifest field or nested property is invalid.
    #[error("invalid manifest metadata `{field}`: {message}")]
    InvalidMetadata {
        /// Rejected field family.
        field: &'static str,
        /// Validation detail.
        message: String,
    },
    /// One artifact contains invalid bounded metadata.
    #[error("manifest artifact at index {index} is invalid: {message}")]
    InvalidArtifactMetadata {
        /// Zero-based artifact position.
        index: usize,
        /// Validation detail.
        message: String,
    },
    /// The manifest contains too many artifact records.
    #[error("manifest has {actual} artifacts; maximum is {limit}")]
    TooManyArtifacts {
        /// Maximum permitted artifact count.
        limit: usize,
        /// Observed artifact count.
        actual: usize,
    },
    /// The manifest contains too many clock records.
    #[error("manifest has {actual} clocks; maximum is {limit}")]
    TooManyClocks {
        /// Maximum permitted clock count.
        limit: usize,
        /// Observed clock count.
        actual: usize,
    },
    /// The manifest contains too many stage records.
    #[error("manifest has {actual} stages; maximum is {limit}")]
    TooManyStages {
        /// Maximum permitted stage count.
        limit: usize,
        /// Observed stage count.
        actual: usize,
    },
    /// Two stages have the same stable name.
    #[error("manifest contains duplicate stage name `{name}`")]
    DuplicateStageName {
        /// Duplicated stage name.
        name: String,
    },
    /// One stage reference list exceeds its bounded count.
    #[error("manifest `{field}` has {actual} entries; maximum is {limit}")]
    TooManyStageArtifactReferences {
        /// Rejected reference list.
        field: &'static str,
        /// Maximum permitted reference count.
        limit: usize,
        /// Observed reference count.
        actual: usize,
    },
    /// One stage repeats an artifact reference.
    #[error("manifest `{field}` contains duplicate artifact `{artifact_id}`")]
    DuplicateStageArtifactReference {
        /// Rejected reference list.
        field: &'static str,
        /// Duplicated artifact identifier.
        artifact_id: String,
    },
    /// Two clock domains have the same identifier.
    #[error("manifest contains duplicate clock id `{id}`")]
    DuplicateClockId {
        /// Duplicated clock identifier.
        id: String,
    },
    /// Two artifacts have the same identifier.
    #[error("manifest contains duplicate artifact id `{id}`")]
    DuplicateArtifactId {
        /// Duplicated artifact identifier.
        id: String,
    },
    /// Two artifacts claim the same relative path.
    #[error("manifest contains duplicate artifact path `{path}`")]
    DuplicateArtifactPath {
        /// Duplicated canonical path.
        path: ArtifactPath,
    },
    /// A stage or artifact references an unknown artifact identifier.
    #[error("`{owner}` references unknown artifact `{artifact_id}`")]
    UnknownArtifactReference {
        /// Stage or artifact containing the reference.
        owner: String,
        /// Missing artifact identifier.
        artifact_id: String,
    },
    /// Artifact provenance contains a cycle.
    #[error("artifact provenance contains a cycle at `{artifact_id}`")]
    CyclicArtifactProvenance {
        /// Artifact where a cycle was detected.
        artifact_id: String,
    },
}

/// Durable lifecycle status of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// The session directory and initial metadata exist.
    Created,
    /// Trace capture is in progress.
    Capturing,
    /// Trace capture completed and raw artifacts are durable.
    Captured,
    /// Host-side normalization or analysis is in progress.
    Processing,
    /// All requested artifacts completed successfully.
    Complete,
    /// The current operation failed.
    Failed,
}

impl SessionStatus {
    /// Returns whether an ordinary state transition to `next` is valid.
    ///
    /// Completion is committed through the separate Session finalization
    /// operation and is therefore never accepted here.
    #[must_use]
    pub const fn can_transition_to(self, next: Self) -> bool {
        (self as u8 == next as u8 && !matches!(self, Self::Complete | Self::Failed))
            || matches!(
                (self, next),
                (Self::Created, Self::Capturing | Self::Failed)
                    | (Self::Capturing, Self::Captured | Self::Failed)
                    | (Self::Captured, Self::Processing | Self::Failed)
                    | (Self::Processing, Self::Failed)
            )
    }

    /// Returns whether finalization can accept this durable status.
    #[must_use]
    pub const fn can_finalize(self) -> bool {
        matches!(self, Self::Captured | Self::Processing | Self::Complete)
    }
}

/// Structured terminal failure stored in durable session state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SessionError {
    /// Stable machine-readable error code.
    pub code: String,
    /// Concise human-readable error message.
    pub message: String,
    /// Structured diagnostic details.
    #[serde(default, skip_serializing_if = "Properties::is_empty")]
    pub details: Properties,
}

/// Atomically replaced durable state for one session operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SessionState {
    /// The state schema version.
    pub schema: StateSchemaVersion,
    /// RFC 3339 timestamp at which the Session was created.
    pub created_at: String,
    /// Current lifecycle status.
    #[serde(rename = "state")]
    pub status: SessionStatus,
    /// Identifier of the operation owning this state sequence.
    pub operation_id: String,
    /// Monotonically increasing state revision.
    pub revision: u64,
    /// RFC 3339 timestamp of the latest durable update.
    pub updated_at: String,
    /// Terminal failure detail, present only for [`SessionStatus::Failed`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<SessionError>,
}

impl SessionState {
    /// Validates status-dependent error and identity invariants.
    pub fn validate(&self) -> Result<(), SessionStateValidationError> {
        if self.created_at.is_empty() {
            return Err(SessionStateValidationError::EmptyCreatedAt);
        }
        if self.operation_id.is_empty() {
            return Err(SessionStateValidationError::EmptyOperationId);
        }
        match (self.status, self.error.is_some()) {
            (SessionStatus::Failed, false) => Err(SessionStateValidationError::MissingError),
            (SessionStatus::Failed, true) | (_, false) => Ok(()),
            (_, true) => Err(SessionStateValidationError::UnexpectedError),
        }
    }
}

/// A semantic invariant violation in durable session state.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SessionStateValidationError {
    /// The immutable Session creation timestamp is empty.
    #[error("session state created_at is empty")]
    EmptyCreatedAt,
    /// The operation identifier is empty.
    #[error("session state operation_id is empty")]
    EmptyOperationId,
    /// Failed state does not contain structured failure detail.
    #[error("failed session state is missing error detail")]
    MissingError,
    /// A nonfailed state contains terminal failure detail.
    #[error("nonfailed session state contains error detail")]
    UnexpectedError,
}
