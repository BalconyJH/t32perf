use std::io::Read as _;

use anyhow::{Context as _, Result, ensure};
use sha2::{Digest as _, Sha256};
use t32perf_model::{
    Artifact, CaptureConfigArtifactClaim, CaptureConfigDocument, CaptureReceipt, strict_json,
};
use t32perf_session::Session;

pub const CAPTURE_CONFIG_ID: &str = "capture-config";
pub const CAPTURE_CONFIG_KIND: &str = "capture_config";
pub const CAPTURE_CONFIG_PATH: &str = "capture/capture-config.json";
pub const SYNTHETIC_CAPTURE_CONFIG_PRODUCER: &str = "t32perf.fixture.synthetic/v1";
pub const MAX_CAPTURE_CONFIG_BYTES: u64 = 1024 * 1024;

pub struct RegisteredCaptureConfig<'a> {
    pub artifact: &'a Artifact,
    pub document: CaptureConfigDocument,
}

pub fn registered_capture_config<'a>(
    session: &Session,
    artifacts: &'a [Artifact],
) -> Result<RegisteredCaptureConfig<'a>> {
    let artifact = artifacts
        .iter()
        .find(|artifact| artifact.id == CAPTURE_CONFIG_ID)
        .ok_or_else(|| {
            anyhow::anyhow!("required artifact `{CAPTURE_CONFIG_ID}` is not registered")
        })?;
    ensure!(
        artifact.kind == CAPTURE_CONFIG_KIND
            && artifact.relative_path.as_str() == CAPTURE_CONFIG_PATH
            && artifact.media_type == "application/json",
        "capture-config artifact catalog identity, kind, path, or media type is invalid"
    );
    ensure!(
        artifact.size_bytes <= MAX_CAPTURE_CONFIG_BYTES,
        "capture-config artifact exceeds the {MAX_CAPTURE_CONFIG_BYTES}-byte limit"
    );
    let mut file = session
        .open_artifact(artifact)
        .context("open immutable capture config")?;
    let mut bytes = Vec::with_capacity(usize::try_from(artifact.size_bytes).unwrap_or(0));
    (&mut file)
        .take(MAX_CAPTURE_CONFIG_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .context("read immutable capture config")?;
    ensure!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX) <= MAX_CAPTURE_CONFIG_BYTES,
        "capture-config artifact grew beyond the {MAX_CAPTURE_CONFIG_BYTES}-byte limit while reading"
    );
    let document = decode_capture_config(&bytes)?;
    document.validate().context("invalid capture config")?;
    ensure!(
        document.session_id == session.id().as_str(),
        "capture config belongs to a different Session"
    );
    let expected_inputs = document.input_artifact_ids();
    for metadata_id in &expected_inputs {
        ensure!(
            artifacts.iter().any(|artifact| artifact.id == *metadata_id),
            "capture config references missing metadata or instrumentation evidence artifact `{metadata_id}`"
        );
    }
    if let Some(instrumentation) = &document.instrumentation {
        let evidence_id = &instrumentation.overhead.evidence_artifact_id;
        let evidence = artifacts
            .iter()
            .find(|artifact| &artifact.id == evidence_id)
            .expect("validated capture-config input exists");
        ensure!(
            evidence.kind == "instrumentation_overhead"
                && evidence.media_type == "application/json",
            "instrumentation evidence artifact must use kind instrumentation_overhead and media type application/json"
        );
    }
    if artifact.producer == crate::controller_capture_config::CONTROLLER_CAPTURE_CONFIG_PRODUCER {
        crate::controller_capture_config::validate_registered(
            session, artifacts, artifact, &document,
        )
        .context("invalid Controller capture-config provenance")?;
    } else {
        ensure!(
            artifact
                .input_artifact_ids
                .iter()
                .map(String::as_str)
                .eq(expected_inputs.iter().copied()),
            "capture-config artifact provenance does not match its RTOS or instrumentation evidence references"
        );
        let identity = configuration_sha256(&document)?;
        crate::controller::validate_capture_config_against_controller(
            session, artifacts, &document, &identity,
        )
        .map_err(|error| anyhow::anyhow!("{}: {}", error.code, error.message))?;
    }
    Ok(RegisteredCaptureConfig { artifact, document })
}

fn decode_capture_config(bytes: &[u8]) -> Result<CaptureConfigDocument> {
    strict_json::from_slice(bytes).context("parse immutable capture config")
}

pub fn capture_config_claim(
    artifact: &Artifact,
    document: &CaptureConfigDocument,
) -> Result<CaptureConfigArtifactClaim> {
    Ok(CaptureConfigArtifactClaim {
        artifact_id: artifact.id.clone(),
        sha256: artifact.sha256.clone(),
        configuration_sha256: configuration_sha256(document)?,
    })
}

pub fn validate_capture_config_claim(
    registered: &RegisteredCaptureConfig<'_>,
    claim: &CaptureConfigArtifactClaim,
) -> Result<()> {
    claim.validate().context("invalid capture-config claim")?;
    ensure!(
        claim.artifact_id == registered.artifact.id,
        "capture-config claim artifact ID does not match the catalog"
    );
    ensure!(
        claim.sha256 == registered.artifact.sha256,
        "capture-config claim digest does not match the catalog"
    );
    ensure!(
        claim.configuration_sha256 == configuration_sha256(&registered.document)?,
        "capture-config claim configuration digest does not match the authoritative document"
    );
    Ok(())
}

pub(crate) fn configuration_sha256(
    document: &CaptureConfigDocument,
) -> Result<t32perf_model::Sha256Digest> {
    let bytes = document
        .configuration_identity_bytes()
        .context("serialize capture-config identity")?;
    let digest = Sha256::digest(bytes);
    t32perf_model::Sha256Digest::new(lower_hex(digest.as_ref()))
        .context("construct capture-config identity digest")
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub fn validate_capture_config_receipt(
    registered: &RegisteredCaptureConfig<'_>,
    receipt: &CaptureReceipt,
) -> Result<()> {
    let claim = receipt.capture_config.as_ref().ok_or_else(|| {
        anyhow::anyhow!("trusted capture receipt omits capture-config provenance")
    })?;
    validate_capture_config_claim(registered, claim)?;
    let config = &registered.document;
    ensure!(
        config.provider == receipt.provider,
        "capture config provider does not match the trusted receipt"
    );
    ensure!(
        config.adapter == receipt.adapter,
        "capture config adapter does not match the trusted receipt"
    );
    ensure!(
        config.mode == receipt.mode,
        "capture config mode does not match the trusted receipt"
    );
    ensure!(
        config.covered_cores == receipt.covered_cores,
        "capture config core coverage does not match the trusted receipt"
    );
    if let Some(target) = &receipt.target
        && let Some(core_count) = target.core_count
    {
        ensure!(
            config.covered_cores.iter().all(|core| *core < core_count),
            "capture config claims a core outside the trusted target"
        );
    }
    if config.timestamp.enabled {
        let clock_id = config
            .timestamp
            .clock_id
            .as_deref()
            .expect("validated capture config has a timestamp clock");
        ensure!(
            receipt.clocks.iter().any(|clock| clock.id == clock_id),
            "capture config timestamp clock is absent from the trusted receipt"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::decode_capture_config;

    #[test]
    fn capture_config_rejects_duplicate_adapter_parameters_recursively() {
        let error = decode_capture_config(
            br#"{"adapter_parameters":{"sink":{"mode":"first","mode":"last"}}}"#,
        )
        .expect_err("duplicate capture-config property");

        assert!(
            error
                .root_cause()
                .to_string()
                .contains("duplicate JSON object member name `mode`")
        );
    }
}
