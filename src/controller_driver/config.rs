use std::{
    collections::BTreeSet,
    fs::{self, File, Metadata},
    io::{Read as _, Seek as _, SeekFrom},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use t32perf_model::{CaptureTrustPolicy, Sha256Digest, is_portable_name_segment, strict_json};
use t32perf_session::{ArtifactRoot, verify_opened_plain_file_identity};
use t32perf_trace32::{
    DriverCommand, DriverCommandRole, DriverPerformanceRunDeployment,
    MAX_C_WIRE_COUNTER_MAPPING_DOCUMENT_BYTES, MAX_HIL_VERIFICATION_RECEIPT_BYTES,
    MAX_T32MCP_DRIVER_CONFIG_BYTES, MAX_TRICORE_FIRMWARE_ELF_BYTES, T32mcpDriverConfig,
    TargetAdapterBundleDescriptor, TargetAdapterControllerProtocol,
    compiled_target_adapter_bundle_catalog, parse_t32mcp_driver_config,
    parse_target_adapter_profile, parse_target_adapter_qualification_receipt,
};

pub(crate) const DRIVER_CONFIG_RELATIVE_PATH: &str =
    ".t32perf-control/deployment/t32mcp-driver.json";

const SKILL_PACKAGE_DIRECTORY: &str = "skill-trace32-perf";
const BUNDLE_MANIFEST_FILE: &str = "bundle-manifest.json";
const PROFILE_FILE: &str = "profile.json";
const BUNDLE_MANIFEST_FORMAT: &str = "t32perf-target-adapter-bundle-manifest-v1";
const MAX_BUNDLE_FILE_COUNT: usize = 128;
const MAX_BUNDLE_PATH_BYTES: usize = 1_024;
const MAX_BUNDLE_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_PROFILE_BYTES: u64 = 64 * 1024;
const MAX_BUNDLE_MEMBER_BYTES: u64 = 4 * 1024 * 1024;
// Documentation and agent metadata do not affect adapter execution and must not
// invalidate an admitted runtime implementation when their wording changes.
const SHARED_BUNDLE_RUNTIME_FILES: &[&str] = &[
    "scripts/perf_cleanup.cmm",
    "scripts/perf_configure.cmm",
    "scripts/perf_export.cmm",
    "scripts/perf_get_capabilities.cmm",
    "scripts/perf_get_health.cmm",
    "scripts/perf_get_hotspots.cmm",
    "scripts/perf_start.cmm",
    "scripts/perf_stop.cmm",
    "scripts/perf_cleanup_v2.cmm",
    "scripts/perf_configure_v2.cmm",
    "scripts/perf_export_v2.cmm",
    "scripts/perf_get_health_v2.cmm",
    "scripts/perf_start_v2.cmm",
    "scripts/perf_stop_v2.cmm",
];
const V1_ROOT_CMM_SET: &[&str] = &[
    "scripts/perf_cleanup.cmm",
    "scripts/perf_configure.cmm",
    "scripts/perf_export.cmm",
    "scripts/perf_get_capabilities.cmm",
    "scripts/perf_get_health.cmm",
    "scripts/perf_get_hotspots.cmm",
    "scripts/perf_start.cmm",
    "scripts/perf_stop.cmm",
];
const V2_ROOT_CMM_SET: &[&str] = &[
    "scripts/perf_cleanup_v2.cmm",
    "scripts/perf_configure_v2.cmm",
    "scripts/perf_export_v2.cmm",
    "scripts/perf_get_capabilities.cmm",
    "scripts/perf_get_health_v2.cmm",
    "scripts/perf_get_hotspots.cmm",
    "scripts/perf_start_v2.cmm",
    "scripts/perf_stop_v2.cmm",
];
const MAX_EXECUTABLE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CAPTURE_TRUST_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_QUALIFICATION_RECEIPT_BYTES: u64 = 64 * 1024;
const MAX_RECOVERY_EVIDENCE_BYTES: u64 = 64 * 1024;
const MAX_LINKER_MAP_BYTES: u64 = 256 * 1024 * 1024;
const MAX_STACK_USAGE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_STATIC_RAM_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_ORTI_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TASK_MARKERS_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TASK_EVENTS_MAPPING_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INSTRUMENTATION_OVERHEAD_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoadedDriverConfig {
    pub(crate) path: PathBuf,
    pub(crate) config: T32mcpDriverConfig,
    /// The sole compiled target-adapter bundle selected for target operations
    /// by the deployment's expected release digest. Endpoint discovery can
    /// reach any compiled bundle, and load/revalidation verifies that complete
    /// catalog before an MCP side effect.
    pub(crate) selected_bundle: TargetAdapterBundleDescriptor,
    /// Exact deployment document admitted for an active execution lease.
    ///
    /// The parsed configuration is intentionally insufficient here: an
    /// equivalent JSON rewrite is still a deployment replacement.
    config_bytes: Vec<u8>,
    pub(crate) config_sha256: Sha256Digest,
}

impl LoadedDriverConfig {
    #[cfg(test)]
    pub(crate) fn for_test(path: PathBuf, config: T32mcpDriverConfig) -> Self {
        let config_bytes =
            serde_json::to_vec(&config).expect("test driver configuration must serialize to JSON");
        let config_sha256 = digest(Sha256::digest(&config_bytes).as_ref());
        Self {
            path,
            selected_bundle: select_compiled_bundle_descriptor(
                &compiled_target_adapter_bundle_catalog(),
                &config.expected_bundle_sha256,
            )
            .expect("test configuration must select a compiled bundle")
            .clone(),
            config,
            config_bytes,
            config_sha256,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleManifest {
    format: String,
    files: Vec<BundleFileClaim>,
    bundle_sha256: Sha256Digest,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleFileClaim {
    path: String,
    sha256: Sha256Digest,
}

pub(crate) fn load_driver_config(root: &ArtifactRoot) -> Result<LoadedDriverConfig> {
    let loaded = load_receipt_bound_driver_config(root)?;
    validate_deployment_paths(&loaded.config, &loaded.selected_bundle)?;
    verify_installed_adapter_bundle_catalog(&loaded.config)?;
    Ok(loaded)
}

/// Reads and strictly parses the fixed driver configuration without accessing
/// deployment source inputs. This is the admission step used while deciding
/// whether an existing Session receipt can replace those source inputs.
pub(crate) fn load_receipt_bound_driver_config(root: &ArtifactRoot) -> Result<LoadedDriverConfig> {
    load_receipt_bound_driver_config_from_root(root.path())
}

/// Reloads every deployment trust input and rejects replacement during one execution lease.
///
/// This repeats configuration, executable, hook, bundle, and compiled-profile
/// validation from the canonical artifact root. Exact equality with the
/// initially admitted deployment prevents a valid-but-different replacement
/// from silently changing an active MCP lifecycle.
pub(crate) fn revalidate_loaded_driver_config(
    root: &ArtifactRoot,
    initial: &LoadedDriverConfig,
) -> Result<LoadedDriverConfig> {
    let current = load_driver_config(root).context("fully revalidate active t32mcp deployment")?;
    ensure!(
        current == *initial,
        "t32mcp deployment configuration changed during the active driver execution lease"
    );
    Ok(current)
}

/// Revalidates a receipt-bound active Session without re-reading deployment
/// sources which are already captured by that Session's receipt/artifacts.
///
/// The driver configuration itself remains byte-for-byte immutable. Runtime
/// executables, command semantics, and the installed adapter bundle/profile
/// remain live trust inputs and are therefore checked again.
pub(crate) fn revalidate_receipt_bound_driver_config(
    root: &ArtifactRoot,
    initial: &LoadedDriverConfig,
) -> Result<LoadedDriverConfig> {
    let current = load_receipt_bound_driver_config(root)
        .context("reload receipt-bound t32mcp driver configuration")?;
    ensure!(
        current.config_bytes == initial.config_bytes
            && current.config_sha256 == initial.config_sha256,
        "t32mcp deployment configuration bytes changed during the active receipt-bound driver execution lease"
    );
    validate_runtime_deployment_paths(&current.config)
        .context("revalidate receipt-bound active t32mcp runtime deployment")?;
    verify_installed_adapter_bundle_catalog(&current.config)
        .context("revalidate receipt-bound installed target-adapter bundle catalog")?;
    Ok(current)
}

pub(crate) fn require_performance_run_config(
    loaded: &LoadedDriverConfig,
) -> Result<&DriverPerformanceRunDeployment> {
    loaded.config.performance_run.as_ref().with_context(
        || "t32mcp deployment does not configure the optional performance_run trust boundary",
    )
}

pub(crate) fn performance_run_deployment_sha256(
    loaded: &LoadedDriverConfig,
) -> Result<Sha256Digest> {
    let deployment = require_performance_run_config(loaded)?;
    let canonical = serde_json::to_vec(deployment)
        .context("serialize canonical performance_run deployment block")?;
    Ok(digest(Sha256::digest(&canonical).as_ref()))
}

pub(crate) fn read_verified_deployment_source(
    path: &Path,
    expected: &Sha256Digest,
    maximum: u64,
    description: &str,
) -> Result<Vec<u8>> {
    let bytes = read_bounded_plain_file(path, maximum, description)?;
    let actual = digest(Sha256::digest(&bytes).as_ref());
    ensure!(
        &actual == expected,
        "{description} has SHA-256 `{actual}`, expected `{expected}`"
    );
    Ok(bytes)
}

fn load_receipt_bound_driver_config_from_root(root: &Path) -> Result<LoadedDriverConfig> {
    let path = root.join(DRIVER_CONFIG_RELATIVE_PATH);
    let bytes = read_bounded_plain_file(
        &path,
        u64::try_from(MAX_T32MCP_DRIVER_CONFIG_BYTES).expect("driver configuration bound fits u64"),
        "t32mcp driver configuration",
    )?;
    let config = parse_t32mcp_driver_config(&bytes)
        .context("parse deployment t32mcp driver configuration")?;
    let config_sha256 = digest(Sha256::digest(&bytes).as_ref());
    let selected_bundle = select_compiled_bundle_descriptor(
        &compiled_target_adapter_bundle_catalog(),
        &config.expected_bundle_sha256,
    )?
    .clone();
    Ok(LoadedDriverConfig {
        path,
        config,
        selected_bundle,
        config_bytes: bytes,
        config_sha256,
    })
}

fn validate_deployment_paths(
    config: &T32mcpDriverConfig,
    selected_bundle: &TargetAdapterBundleDescriptor,
) -> Result<()> {
    validate_runtime_deployment_paths(config)?;
    if let Some(performance_run) = &config.performance_run {
        validate_performance_run_source_paths(performance_run, selected_bundle)?;
    }
    Ok(())
}

fn validate_runtime_deployment_paths(config: &T32mcpDriverConfig) -> Result<()> {
    let executable = Path::new(&config.executable);
    verify_plain_executable_sha256(
        executable,
        &config.expected_executable_sha256,
        "t32mcp executable",
    )?;
    verify_absolute_plain_directory(Path::new(&config.skills_root), "skills_root")?;
    if let Some(command) = &config.workload {
        verify_driver_command_executable(command, DriverCommandRole::Workload)?;
    }
    if let Some(command) = &config.fault_actions.trace32_disconnect_at_stop {
        verify_driver_command_executable(command, DriverCommandRole::Trace32DisconnectAtStop)?;
    }
    if let Some(performance_run) = &config.performance_run {
        validate_performance_run_runtime_paths(performance_run)?;
    }
    Ok(())
}

fn validate_performance_run_runtime_paths(
    deployment: &DriverPerformanceRunDeployment,
) -> Result<()> {
    verify_driver_command_executable(&deployment.workload_command, DriverCommandRole::Workload)?;
    verify_driver_command_executable(
        &deployment.attestation.signer_command,
        DriverCommandRole::AttestationSigner,
    )?;
    Ok(())
}

fn validate_performance_run_source_paths(
    deployment: &DriverPerformanceRunDeployment,
    selected_bundle: &TargetAdapterBundleDescriptor,
) -> Result<()> {
    verify_plain_file_sha256(
        Path::new(&deployment.firmware.path),
        &deployment.firmware.sha256,
        u64::try_from(MAX_TRICORE_FIRMWARE_ELF_BYTES).expect("firmware bound fits u64"),
        "performance-run firmware ELF",
    )?;
    verify_plain_file_sha256(
        Path::new(&deployment.qualification.qualification_receipt.path),
        &deployment.qualification.qualification_receipt.sha256,
        MAX_QUALIFICATION_RECEIPT_BYTES,
        "performance-run qualification receipt",
    )?;
    verify_plain_file_sha256(
        Path::new(&deployment.qualification.hil_receipt.path),
        &deployment.qualification.hil_receipt.sha256,
        u64::try_from(MAX_HIL_VERIFICATION_RECEIPT_BYTES).expect("HIL receipt bound fits u64"),
        "performance-run HIL verification receipt",
    )?;
    if let Some(recovery) = &deployment.qualification.recovery_evidence {
        verify_plain_file_sha256(
            Path::new(&recovery.path),
            &recovery.sha256,
            MAX_RECOVERY_EVIDENCE_BYTES,
            "performance-run recovery evidence",
        )?;
    }
    if let Some(linker_map) = &deployment.resources.linker_map {
        verify_plain_file_sha256(
            Path::new(&linker_map.path),
            &linker_map.sha256,
            MAX_LINKER_MAP_BYTES,
            "performance-run linker map",
        )?;
    }
    if let Some(stack_usage) = &deployment.resources.stack_usage {
        verify_plain_file_sha256(
            Path::new(&stack_usage.path),
            &stack_usage.sha256,
            MAX_STACK_USAGE_BYTES,
            "performance-run stack-usage report",
        )?;
    }
    if let Some(static_ram_config) = &deployment.resources.static_ram_config {
        verify_plain_file_sha256(
            Path::new(&static_ram_config.path),
            &static_ram_config.sha256,
            MAX_STATIC_RAM_CONFIG_BYTES,
            "performance-run static-RAM configuration",
        )?;
    }
    if let Some(program_flow) = &deployment.resources.program_flow {
        verify_plain_file_sha256(
            Path::new(&program_flow.orti.path),
            &program_flow.orti.sha256,
            MAX_ORTI_BYTES,
            "performance-run program-flow ORTI input",
        )?;
        verify_plain_file_sha256(
            Path::new(&program_flow.task_markers.path),
            &program_flow.task_markers.sha256,
            MAX_TASK_MARKERS_BYTES,
            "performance-run program-flow task markers",
        )?;
        verify_plain_file_sha256(
            Path::new(&program_flow.task_events_mapping_template.path),
            &program_flow.task_events_mapping_template.sha256,
            MAX_TASK_EVENTS_MAPPING_BYTES,
            "performance-run program-flow TASKEVENTS mapping template",
        )?;
    }
    if let Some(custom_events) = &deployment.resources.custom_events {
        verify_plain_file_sha256(
            Path::new(&custom_events.c_wire_mapping.path),
            &custom_events.c_wire_mapping.sha256,
            u64::try_from(MAX_C_WIRE_COUNTER_MAPPING_DOCUMENT_BYTES)
                .expect("C wire mapping bound fits u64"),
            "performance-run custom-event C wire mapping",
        )?;
        verify_plain_file_sha256(
            Path::new(&custom_events.instrumentation_overhead.path),
            &custom_events.instrumentation_overhead.sha256,
            MAX_INSTRUMENTATION_OVERHEAD_BYTES,
            "performance-run custom-event instrumentation overhead",
        )?;
    }

    let policy_path = Path::new(&deployment.attestation.policy_path);
    let policy_bytes = read_bounded_plain_file(
        policy_path,
        MAX_CAPTURE_TRUST_POLICY_BYTES,
        "performance-run capture trust policy",
    )?;
    ensure!(
        !policy_bytes.is_empty(),
        "performance-run capture trust policy `{}` is empty",
        policy_path.display()
    );
    let policy_sha256 = digest(Sha256::digest(&policy_bytes).as_ref());
    ensure!(
        policy_sha256 == deployment.attestation.policy_sha256,
        "performance-run capture trust policy has SHA-256 `{policy_sha256}`, expected `{}`",
        deployment.attestation.policy_sha256
    );
    let policy: CaptureTrustPolicy = strict_json::from_slice(&policy_bytes)
        .context("parse strict performance-run capture trust policy")?;
    policy
        .validate()
        .context("validate performance-run capture trust policy")?;
    ensure!(
        policy.policy_id == deployment.attestation.policy_id,
        "performance-run capture trust policy declares policy_id `{}`, expected `{}`",
        policy.policy_id,
        deployment.attestation.policy_id
    );
    ensure!(
        policy.key(&deployment.attestation.key_id).is_some(),
        "performance-run capture trust policy `{}` does not contain key_id `{}`",
        policy.policy_id,
        deployment.attestation.key_id
    );
    ensure!(
        deployment.firmware.sha256 == selected_bundle.candidate_profile.firmware_elf_sha256,
        "performance-run firmware SHA-256 does not match the selected compiled target-adapter bundle"
    );
    let qualification_bytes = read_bounded_plain_file(
        Path::new(&deployment.qualification.qualification_receipt.path),
        MAX_QUALIFICATION_RECEIPT_BYTES,
        "performance-run qualification receipt",
    )?;
    let qualification = parse_target_adapter_qualification_receipt(&qualification_bytes)
        .context("parse strict performance-run qualification receipt")?;
    ensure!(
        qualification.adapter_id == selected_bundle.candidate_profile.adapter_id
            && qualification.adapter_version == selected_bundle.candidate_profile.adapter_version
            && qualification.implementation_sha256
                == selected_bundle.candidate_profile.implementation_sha256
            && qualification.firmware_elf_sha256
                == selected_bundle.candidate_profile.firmware_elf_sha256
            && qualification.candidate_profile_sha256
                == selected_bundle
                    .candidate_profile
                    .qualification_identity_digest()
                    .map_err(anyhow::Error::from)?
            && qualification.hil_verification_receipt_sha256
                == deployment.qualification.hil_receipt.sha256,
        "performance-run qualification receipt does not select the configured compiled target-adapter bundle"
    );
    Ok(())
}

fn verify_driver_command_executable(
    command: &DriverCommand,
    role: DriverCommandRole,
) -> Result<()> {
    command
        .validate(role)
        .with_context(|| format!("validate `{role}` command"))?;
    verify_plain_executable_sha256(
        Path::new(&command.executable),
        &command.expected_executable_sha256,
        &format!("`{role}` executable"),
    )
}

pub(super) fn verify_plain_executable_sha256(
    path: &Path,
    expected_sha256: &Sha256Digest,
    description: &str,
) -> Result<()> {
    verify_plain_file_sha256(path, expected_sha256, MAX_EXECUTABLE_BYTES, description)
}

pub(super) fn verify_plain_file_sha256(
    path: &Path,
    expected_sha256: &Sha256Digest,
    maximum: u64,
    description: &str,
) -> Result<()> {
    let file = open_bounded_plain_file(path, maximum, description)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect opened {description} `{}`", path.display()))?;
    ensure!(
        metadata.len() > 0,
        "{description} `{}` is empty",
        path.display()
    );
    verify_opened_plain_file_identity(path, &file)
        .with_context(|| format!("reverify {description} `{}`", path.display()))?;
    let actual_sha256 = sha256_plain_file(path, maximum, description)?;
    ensure!(
        actual_sha256 == *expected_sha256,
        "{description} has SHA-256 `{actual_sha256}`, expected `{expected_sha256}`"
    );
    Ok(())
}

fn verify_installed_adapter_bundle_catalog(config: &T32mcpDriverConfig) -> Result<()> {
    let catalog = compiled_target_adapter_bundle_catalog();
    verify_installed_adapter_bundle_catalog_from(config, &catalog)
}

fn verify_installed_adapter_bundle_catalog_from(
    config: &T32mcpDriverConfig,
    catalog: &[TargetAdapterBundleDescriptor],
) -> Result<()> {
    validate_compiled_bundle_catalog(catalog)?;
    for descriptor in catalog {
        verify_installed_adapter_bundle(config, descriptor)?;
    }
    Ok(())
}

fn verify_installed_adapter_bundle(
    config: &T32mcpDriverConfig,
    descriptor: &TargetAdapterBundleDescriptor,
) -> Result<()> {
    descriptor.validate().map_err(anyhow::Error::from)?;

    let skills_root = Path::new(&config.skills_root);
    let skill_package_root = skills_root.join(SKILL_PACKAGE_DIRECTORY);
    verify_absolute_plain_directory(&skill_package_root, "TRACE32 skill package root")?;
    let canonical_skill_package_root =
        fs::canonicalize(&skill_package_root).with_context(|| {
            format!(
                "canonicalize TRACE32 skill package root `{}`",
                skill_package_root.display()
            )
        })?;
    let adapter_directory = skill_package_root.join(descriptor.bundle_relative_directory);
    verify_absolute_plain_directory(&adapter_directory, "target-adapter directory")?;

    let manifest_path = adapter_directory.join(BUNDLE_MANIFEST_FILE);
    let manifest_bytes = read_bounded_plain_file(
        &manifest_path,
        MAX_BUNDLE_MANIFEST_BYTES,
        "target-adapter bundle manifest",
    )?;
    let manifest: BundleManifest = strict_json::from_slice(&manifest_bytes)
        .context("parse strict target-adapter bundle manifest")?;
    ensure!(
        manifest.format == BUNDLE_MANIFEST_FORMAT,
        "target-adapter bundle manifest format is not `{BUNDLE_MANIFEST_FORMAT}`"
    );
    ensure!(
        manifest.files.len() <= MAX_BUNDLE_FILE_COUNT,
        "target-adapter bundle manifest exceeds the {MAX_BUNDLE_FILE_COUNT}-file bound"
    );
    ensure_strictly_sorted_bundle_paths(&manifest.files)?;

    let mut canonical_bundle = Sha256::new();
    let mut portable_paths = BTreeSet::new();
    let mut root_members = BTreeSet::new();
    for claim in &manifest.files {
        ensure!(
            portable_paths.insert(claim.path.to_ascii_lowercase()),
            "target-adapter bundle path `{}` is not portable-unique",
            claim.path
        );
        let member_path = resolve_bundle_member(
            &adapter_directory,
            &skill_package_root,
            descriptor.bundle_relative_directory,
            &claim.path,
        )?;
        let root_relative = member_path
            .strip_prefix(&skill_package_root)
            .expect("member resolution retains skill root")
            .to_string_lossy()
            .replace('\\', "/");
        root_members.insert(root_relative);
        let actual = sha256_plain_file(
            &member_path,
            MAX_BUNDLE_MEMBER_BYTES,
            "target-adapter bundle member",
        )?;
        ensure!(
            actual == claim.sha256,
            "target-adapter bundle member `{}` has SHA-256 `{actual}`, expected `{}`",
            claim.path,
            claim.sha256
        );
        let canonical_member = fs::canonicalize(&member_path).with_context(|| {
            format!(
                "canonicalize target-adapter bundle member `{}`",
                member_path.display()
            )
        })?;
        ensure!(
            canonical_member.starts_with(&canonical_skill_package_root),
            "target-adapter bundle member `{}` resolves outside the skill package root",
            claim.path
        );
        canonical_bundle.update(claim.path.as_bytes());
        canonical_bundle.update(b" ");
        canonical_bundle.update(claim.sha256.as_str().as_bytes());
        canonical_bundle.update(b"\n");
    }
    let actual_bundle_digest = digest(canonical_bundle.finalize().as_ref());
    ensure!(
        actual_bundle_digest == manifest.bundle_sha256,
        "target-adapter canonical bundle digest is `{actual_bundle_digest}`, manifest declares `{}`",
        manifest.bundle_sha256
    );
    ensure!(
        manifest.bundle_sha256 == descriptor.candidate_profile.implementation_sha256,
        "target-adapter manifest digest does not match compiled candidate"
    );

    let profile_path = adapter_directory.join(PROFILE_FILE);
    let profile_bytes =
        read_bounded_plain_file(&profile_path, MAX_PROFILE_BYTES, "target-adapter profile")?;
    let profile = parse_target_adapter_profile(&profile_bytes)
        .context("parse installed target-adapter profile")?;
    ensure!(
        profile == descriptor.candidate_profile,
        "installed target-adapter profile does not equal the compiled candidate"
    );
    ensure!(
        profile.implementation_sha256 == manifest.bundle_sha256,
        "installed target-adapter profile implementation digest does not match the verified bundle"
    );
    validate_required_root_cmm_members(descriptor, &root_members)?;
    Ok(())
}

fn validate_required_root_cmm_members(
    descriptor: &TargetAdapterBundleDescriptor,
    root_members: &BTreeSet<String>,
) -> Result<()> {
    let required = match descriptor.candidate_profile.controller_protocol {
        TargetAdapterControllerProtocol::V1 => V1_ROOT_CMM_SET,
        TargetAdapterControllerProtocol::V2CustomEventsExport => V2_ROOT_CMM_SET,
    };
    for path in required {
        ensure!(
            root_members.contains(*path),
            "target-adapter bundle does not cover required root CMM `{path}` for its controller protocol"
        );
    }
    Ok(())
}

fn select_compiled_bundle_descriptor<'a>(
    catalog: &'a [TargetAdapterBundleDescriptor],
    expected_bundle_sha256: &Sha256Digest,
) -> Result<&'a TargetAdapterBundleDescriptor> {
    validate_compiled_bundle_catalog(catalog)?;
    let matches = catalog
        .iter()
        .filter(|descriptor| {
            descriptor.candidate_profile.implementation_sha256 == *expected_bundle_sha256
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [descriptor] => Ok(*descriptor),
        [] => anyhow::bail!(
            "configured bundle digest does not select a compiled target-adapter bundle"
        ),
        _ => anyhow::bail!(
            "configured bundle digest selects multiple compiled target-adapter bundles"
        ),
    }
}

fn validate_compiled_bundle_catalog(catalog: &[TargetAdapterBundleDescriptor]) -> Result<()> {
    ensure!(
        !catalog.is_empty(),
        "compiled target-adapter bundle catalog is empty"
    );
    let mut directories = BTreeSet::new();
    let mut adapter_ids = BTreeSet::new();
    let mut implementation_digests = BTreeSet::new();
    for descriptor in catalog {
        descriptor
            .validate()
            .map_err(|error| anyhow::anyhow!("invalid compiled target-adapter bundle: {error}"))?;
        let directory = descriptor.bundle_relative_directory.to_ascii_lowercase();
        ensure!(
            directories.insert(directory),
            "compiled target-adapter bundle catalog contains case-insensitive duplicate directories"
        );
        ensure!(
            adapter_ids.insert(descriptor.candidate_profile.adapter_id.as_str()),
            "compiled target-adapter bundle catalog contains duplicate adapter IDs"
        );
        ensure!(
            implementation_digests
                .insert(descriptor.candidate_profile.implementation_sha256.as_str()),
            "compiled target-adapter bundle catalog contains duplicate implementation digests"
        );
    }
    let paths = catalog
        .iter()
        .map(|descriptor| descriptor.bundle_relative_directory.to_ascii_lowercase())
        .collect::<Vec<_>>();
    for (index, directory) in paths.iter().enumerate() {
        for other in paths.iter().skip(index + 1) {
            ensure!(
                !directory.starts_with(&format!("{other}/"))
                    && !other.starts_with(&format!("{directory}/")),
                "compiled target-adapter bundle catalog contains overlapping adapter directories"
            );
        }
    }
    Ok(())
}

fn ensure_strictly_sorted_bundle_paths(files: &[BundleFileClaim]) -> Result<()> {
    for pair in files.windows(2) {
        ensure!(
            pair[0].path.as_bytes() < pair[1].path.as_bytes(),
            "target-adapter bundle paths must be strictly bytewise sorted and unique"
        );
    }
    Ok(())
}

fn resolve_bundle_member(
    adapter_directory: &Path,
    skill_package_root: &Path,
    adapter_relative_directory: &str,
    relative: &str,
) -> Result<PathBuf> {
    validate_bundle_path(relative)?;
    let mut resolved = adapter_directory.to_path_buf();
    for segment in relative.split('/') {
        if segment == ".." {
            ensure!(
                resolved != skill_package_root,
                "target-adapter bundle path `{relative}` escapes the skill package root"
            );
            ensure!(
                resolved.pop(),
                "target-adapter bundle path `{relative}` cannot be normalized"
            );
        } else {
            resolved.push(segment);
        }
    }
    ensure!(
        resolved.starts_with(skill_package_root),
        "target-adapter bundle path `{relative}` escapes the skill package root"
    );
    let root_relative = resolved
        .strip_prefix(skill_package_root)
        .expect("prefix checked above");
    ensure!(
        is_allowed_bundle_member(root_relative, adapter_relative_directory),
        "target-adapter bundle path `{relative}` is neither in the selected adapter subtree nor an allowed shared root member"
    );
    Ok(resolved)
}

fn is_allowed_bundle_member(root_relative: &Path, adapter_relative_directory: &str) -> bool {
    if root_relative.starts_with(Path::new(adapter_relative_directory)) {
        return root_relative
            .extension()
            .and_then(|extension| extension.to_str())
            .is_none_or(|extension| !extension.eq_ignore_ascii_case("md"));
    }
    let Some(portable) = root_relative.to_str().map(|value| value.replace('\\', "/")) else {
        return false;
    };
    SHARED_BUNDLE_RUNTIME_FILES.contains(&portable.as_str())
}

fn validate_bundle_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= MAX_BUNDLE_PATH_BYTES,
        "target-adapter bundle path is empty or exceeds {MAX_BUNDLE_PATH_BYTES} bytes"
    );
    ensure!(
        path.is_ascii() && !path.starts_with('/') && !path.ends_with('/'),
        "target-adapter bundle path `{path}` is not a portable relative path"
    );
    ensure!(
        !path.contains('\\') && !path.contains(":") && !path.contains("//"),
        "target-adapter bundle path `{path}` is not a portable relative path"
    );
    for segment in path.split('/') {
        ensure!(
            segment == ".." || (segment != "." && is_portable_name_segment(segment)),
            "target-adapter bundle path `{path}` contains a non-portable segment"
        );
    }
    ensure!(
        !Path::new(path).is_absolute(),
        "target-adapter bundle path `{path}` must be relative"
    );
    Ok(())
}

fn sha256_plain_file(path: &Path, maximum: u64, description: &str) -> Result<Sha256Digest> {
    let mut file = open_bounded_plain_file(path, maximum, description)?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("read {description} `{}`", path.display()))?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).expect("read count fits u64"))
            .context("bounded plain-file length overflow")?;
        ensure!(
            total <= maximum,
            "{description} `{}` exceeds the {maximum}-byte bound",
            path.display()
        );
        hasher.update(&buffer[..count]);
    }
    verify_opened_plain_file_identity(path, &file)
        .with_context(|| format!("reverify {description} `{}`", path.display()))?;
    Ok(digest(hasher.finalize().as_ref()))
}

pub(super) fn read_bounded_plain_file(
    path: &Path,
    maximum: u64,
    description: &str,
) -> Result<Vec<u8>> {
    let mut file = open_bounded_plain_file(path, maximum, description)?;
    file.seek(SeekFrom::Start(0))
        .with_context(|| format!("seek {description} `{}`", path.display()))?;
    let capacity = usize::try_from(maximum.min(64 * 1024)).expect("bounded capacity fits usize");
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {description} `{}`", path.display()))?;
    ensure!(
        u64::try_from(bytes.len()).expect("file length fits u64") <= maximum,
        "{description} `{}` exceeds the {maximum}-byte bound",
        path.display()
    );
    verify_opened_plain_file_identity(path, &file)
        .with_context(|| format!("reverify {description} `{}`", path.display()))?;
    Ok(bytes)
}

fn open_bounded_plain_file(path: &Path, maximum: u64, description: &str) -> Result<File> {
    ensure_absolute_normal_path(path, description)?;
    let parent = path.parent().with_context(|| {
        format!(
            "{description} path `{}` does not have a parent directory",
            path.display()
        )
    })?;
    verify_absolute_plain_directory(parent, &format!("{description} parent"))?;
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {description} `{}`", path.display()))?;
    ensure_plain_file_metadata(path, &before, description)?;
    ensure!(
        before.len() <= maximum,
        "{description} `{}` exceeds the {maximum}-byte bound",
        path.display()
    );
    let file =
        File::open(path).with_context(|| format!("open {description} `{}`", path.display()))?;
    verify_opened_plain_file_identity(path, &file)
        .with_context(|| format!("verify opened {description} `{}`", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect opened {description} `{}`", path.display()))?;
    ensure!(
        opened.len() <= maximum,
        "{description} `{}` exceeds the {maximum}-byte bound",
        path.display()
    );
    Ok(file)
}

pub(super) fn verify_absolute_plain_directory(path: &Path, description: &str) -> Result<()> {
    ensure_absolute_normal_path(path, description)?;
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        let metadata = fs::symlink_metadata(&current)
            .with_context(|| format!("inspect {description} component `{}`", current.display()))?;
        ensure!(
            !is_link_like(&metadata),
            "{description} component `{}` is a symlink or reparse point",
            current.display()
        );
        ensure!(
            metadata.is_dir(),
            "{description} component `{}` is not a directory",
            current.display()
        );
    }
    Ok(())
}

fn ensure_absolute_normal_path(path: &Path, description: &str) -> Result<()> {
    ensure!(
        path.is_absolute(),
        "{description} path `{}` must be absolute",
        path.display()
    );
    ensure!(
        path.components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir)),
        "{description} path `{}` must be lexically normalized",
        path.display()
    );
    Ok(())
}

fn ensure_plain_file_metadata(path: &Path, metadata: &Metadata, description: &str) -> Result<()> {
    ensure!(
        !is_link_like(metadata),
        "{description} `{}` is a symlink or reparse point",
        path.display()
    );
    ensure!(
        metadata.is_file(),
        "{description} `{}` is not a regular file",
        path.display()
    );
    Ok(())
}

fn is_link_like(metadata: &Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;

        write!(&mut encoded, "{byte:02x}").expect("write to String cannot fail");
    }
    Sha256Digest::new(encoded).expect("SHA-256 output is valid")
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use serde_json::{Value, json};
    use t32perf_model::{
        AdapterInfo, CaptureCapabilities, CaptureTrustKey, CaptureTrustPolicy,
        CaptureTrustPolicySchemaVersion, ClockInfo, MetricSupportEntry, PerformanceReportFormat,
        PerformanceRunRequest, PerformanceRunRequestSchemaVersion, Properties, TargetInfo,
        Trace32Info,
    };
    use t32perf_session::{ArtifactRoot, SessionId, SessionLimits};
    use tempfile::TempDir;

    use super::*;

    fn compiled_bundle_descriptor() -> TargetAdapterBundleDescriptor {
        let mut catalog = compiled_target_adapter_bundle_catalog();
        assert_eq!(catalog.len(), 1, "production fixture assumes one bundle");
        catalog.pop().expect("production bundle descriptor")
    }

    fn install_second_fixture_bundle(
        deployment: &DeploymentFixture,
    ) -> TargetAdapterBundleDescriptor {
        let first = compiled_bundle_descriptor();
        let package_root = deployment.skills_root.join(SKILL_PACKAGE_DIRECTORY);
        let source = package_root.join(first.bundle_relative_directory);
        let relative_directory = "scripts/adapters/test-second";
        let destination = package_root.join(relative_directory);
        copy_directory(&source, &destination);

        let version_bytes = b"fixture-second-adapter\n";
        fs::write(destination.join("ADAPTER_VERSION"), version_bytes).unwrap();
        let version_sha256 = digest(Sha256::digest(version_bytes).as_ref());
        let manifest_path = destination.join(BUNDLE_MANIFEST_FILE);
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        let version_claim = manifest["files"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|claim| claim["path"] == "ADAPTER_VERSION")
            .unwrap();
        version_claim["sha256"] = json!(version_sha256);
        let mut canonical = Sha256::new();
        for claim in manifest["files"].as_array().unwrap() {
            canonical.update(claim["path"].as_str().unwrap().as_bytes());
            canonical.update(b" ");
            canonical.update(claim["sha256"].as_str().unwrap().as_bytes());
            canonical.update(b"\n");
        }
        let bundle_sha256 = digest(canonical.finalize().as_ref());
        manifest["bundle_sha256"] = json!(bundle_sha256);
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        let mut descriptor = first;
        descriptor.bundle_relative_directory = relative_directory;
        descriptor.candidate_profile.adapter_id = "fixture-second-adapter".to_owned();
        descriptor.candidate_profile.implementation_sha256 = bundle_sha256;
        descriptor.candidate_profile.firmware_elf_sha256 =
            Sha256Digest::new("1".repeat(64)).unwrap();
        fs::write(
            destination.join(PROFILE_FILE),
            serde_json::to_vec(&descriptor.candidate_profile).unwrap(),
        )
        .unwrap();
        descriptor
    }

    #[test]
    fn loads_exact_installed_bundle_and_closed_config() {
        let deployment = deployment_fixture();
        let root = artifact_root(deployment.root.path());
        let loaded = load_driver_config(&root).unwrap();
        assert_eq!(
            loaded.path,
            fs::canonicalize(deployment.config_path).unwrap()
        );
        assert_eq!(
            loaded.config.expected_bundle_sha256,
            compiled_bundle_descriptor()
                .candidate_profile
                .implementation_sha256
        );
    }

    #[test]
    fn skill_documentation_does_not_change_runtime_bundle_identity() {
        let deployment = deployment_fixture();
        let documentation = deployment.skills_root.join("skill-trace32-perf/SKILL.md");
        let mut bytes = fs::read(&documentation).unwrap();
        bytes.extend_from_slice(b"\nAdditional deployment guidance.\n");
        fs::write(documentation, bytes).unwrap();

        load_driver_config(&artifact_root(deployment.root.path())).unwrap();
    }

    #[test]
    fn endpoint_reachable_catalog_verifies_every_bundle_not_only_the_selected_one() {
        let deployment = deployment_fixture();
        let root = artifact_root(deployment.root.path());
        let loaded = load_driver_config(&root).unwrap();
        let selected = compiled_bundle_descriptor();
        let second = install_second_fixture_bundle(&deployment);
        let catalog = vec![selected, second.clone()];

        verify_installed_adapter_bundle_catalog_from(&loaded.config, &catalog).unwrap();

        let private_member = deployment
            .skills_root
            .join(SKILL_PACKAGE_DIRECTORY)
            .join(second.bundle_relative_directory)
            .join("perf_start.cmm");
        fs::write(private_member, b"tampered second adapter").unwrap();
        let error =
            verify_installed_adapter_bundle_catalog_from(&loaded.config, &catalog).unwrap_err();
        assert!(format!("{error:#}").contains("target-adapter bundle member `perf_start.cmm`"));
    }

    #[test]
    fn compiled_bundle_catalog_selection_is_exact_and_rejects_shared_digests() {
        let first = compiled_bundle_descriptor();
        let mut second = first.clone();
        second.bundle_relative_directory = "scripts/adapters/test-second";
        second.candidate_profile.adapter_id = "test-second-adapter".to_owned();
        second.candidate_profile.implementation_sha256 = Sha256Digest::new("0".repeat(64)).unwrap();
        second.candidate_profile.firmware_elf_sha256 = Sha256Digest::new("1".repeat(64)).unwrap();

        let catalog = vec![first.clone(), second.clone()];
        assert_eq!(
            select_compiled_bundle_descriptor(
                &catalog,
                &second.candidate_profile.implementation_sha256
            )
            .unwrap(),
            &second
        );
        assert!(
            select_compiled_bundle_descriptor(
                &catalog,
                &Sha256Digest::new("f".repeat(64)).unwrap()
            )
            .is_err()
        );

        let mut shared_digest = second;
        shared_digest.candidate_profile.implementation_sha256 =
            first.candidate_profile.implementation_sha256.clone();
        let error = select_compiled_bundle_descriptor(
            &[first, shared_digest],
            &Sha256Digest::new("0".repeat(64)).unwrap(),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("duplicate implementation digests")
        );

        let mut case_variant = compiled_bundle_descriptor();
        case_variant.bundle_relative_directory = "scripts/adapters/TC234L-build190766";
        case_variant.candidate_profile.adapter_id = "case-variant-adapter".to_owned();
        case_variant.candidate_profile.implementation_sha256 =
            Sha256Digest::new("2".repeat(64)).unwrap();
        assert!(
            validate_compiled_bundle_catalog(&[compiled_bundle_descriptor(), case_variant,])
                .unwrap_err()
                .to_string()
                .contains("case-insensitive duplicate directories")
        );
    }

    #[test]
    fn bundle_member_boundary_allows_only_executable_shared_root_or_selected_adapter() {
        assert!(is_allowed_bundle_member(
            Path::new("scripts/adapters/tc234l-build190766/profile.json"),
            "scripts/adapters/tc234l-build190766"
        ));
        assert!(!is_allowed_bundle_member(
            Path::new("scripts/adapters/tc234l-build190766/README.md"),
            "scripts/adapters/tc234l-build190766"
        ));
        assert!(!is_allowed_bundle_member(
            Path::new("references/security.md"),
            "scripts/adapters/tc234l-build190766"
        ));
        assert!(is_allowed_bundle_member(
            Path::new("scripts/perf_start.cmm"),
            "scripts/adapters/tc234l-build190766"
        ));
        assert!(!is_allowed_bundle_member(
            Path::new("scripts/adapters/other/profile.json"),
            "scripts/adapters/tc234l-build190766"
        ));
        assert!(!is_allowed_bundle_member(
            Path::new("scripts/other.cmm"),
            "scripts/adapters/tc234l-build190766"
        ));
    }

    #[test]
    fn v2_bundle_requires_the_v2_root_cmm_set() {
        let mut descriptor = compiled_bundle_descriptor();
        descriptor.candidate_profile.controller_protocol =
            TargetAdapterControllerProtocol::V2CustomEventsExport;
        let members = BTreeSet::from(["scripts/perf_get_capabilities.cmm".to_owned()]);
        let error = validate_required_root_cmm_members(&descriptor, &members).unwrap_err();
        assert!(error.to_string().contains("perf_cleanup_v2.cmm"));

        let without_hotspots = V2_ROOT_CMM_SET
            .iter()
            .filter(|path| **path != "scripts/perf_get_hotspots.cmm")
            .map(|path| (*path).to_owned())
            .collect();
        let error = validate_required_root_cmm_members(&descriptor, &without_hotspots).unwrap_err();
        assert!(error.to_string().contains("perf_get_hotspots.cmm"));
    }

    #[test]
    fn replacement_revalidation_accepts_only_the_exact_initial_deployment() {
        let deployment = deployment_fixture();
        let root = artifact_root(deployment.root.path());
        let initial = load_driver_config(&root).unwrap();
        assert_eq!(
            revalidate_loaded_driver_config(&root, &initial).unwrap(),
            initial
        );

        let replacement = deployment.root.path().join(if cfg!(windows) {
            "replacement-t32mcp.exe"
        } else {
            "replacement-t32mcp"
        });
        let replacement_bytes = b"different but internally consistent executable";
        fs::write(&replacement, replacement_bytes).unwrap();
        let replacement_sha256 = digest(Sha256::digest(replacement_bytes).as_ref());
        let mut document: Value =
            serde_json::from_slice(&fs::read(&deployment.config_path).unwrap()).unwrap();
        document["executable"] = json!(replacement.to_string_lossy());
        document["expected_executable_sha256"] = json!(replacement_sha256);
        fs::write(
            &deployment.config_path,
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();

        let error = revalidate_loaded_driver_config(&root, &initial).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("changed during the active driver execution lease")
        );
    }

    #[test]
    fn replacement_revalidation_rechecks_executable_content() {
        let deployment = deployment_fixture();
        let root = artifact_root(deployment.root.path());
        let initial = load_driver_config(&root).unwrap();
        fs::write(&initial.config.executable, b"digest drift").unwrap();
        let error = revalidate_loaded_driver_config(&root, &initial).unwrap_err();
        assert!(error.to_string().contains("fully revalidate"));
        assert!(format!("{error:#}").contains("t32mcp executable has SHA-256"));
    }

    #[test]
    fn rejects_unknown_config_field_and_relative_paths() {
        let deployment = deployment_fixture();
        let mut document: Value =
            serde_json::from_slice(&fs::read(&deployment.config_path).unwrap()).unwrap();
        document["unknown"] = json!(true);
        fs::write(
            &deployment.config_path,
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(error.to_string().contains("parse deployment"));

        let deployment = deployment_fixture();
        let mut document: Value =
            serde_json::from_slice(&fs::read(&deployment.config_path).unwrap()).unwrap();
        document["executable"] = json!("relative/t32mcp");
        fs::write(
            &deployment.config_path,
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(error.to_string().contains("must be absolute"));
    }

    #[test]
    fn rejects_t32mcp_executable_digest_drift() {
        let deployment = deployment_fixture();
        let mut document: Value =
            serde_json::from_slice(&fs::read(&deployment.config_path).unwrap()).unwrap();
        document["expected_executable_sha256"] = json!("0".repeat(64));
        fs::write(
            &deployment.config_path,
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(error.to_string().contains("t32mcp executable has SHA-256"));
    }

    #[test]
    fn validates_external_hook_executable_digest() {
        let deployment = deployment_fixture();
        let mut document: Value =
            serde_json::from_slice(&fs::read(&deployment.config_path).unwrap()).unwrap();
        let executable = document["executable"].clone();
        let executable_sha256 = document["expected_executable_sha256"].clone();
        document["fault_actions"]["trace32_disconnect_at_stop"] = json!({
            "executable": executable,
            "expected_executable_sha256": executable_sha256,
            "arguments": ["{transaction_id}", "{binding_sha256}"],
            "timeout_ms": 100
        });
        fs::write(
            &deployment.config_path,
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        load_driver_config(&artifact_root(deployment.root.path())).unwrap();

        document["fault_actions"]["trace32_disconnect_at_stop"]["expected_executable_sha256"] =
            json!("0".repeat(64));
        fs::write(
            &deployment.config_path,
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("`trace32_disconnect_at_stop` executable has SHA-256")
        );
    }

    #[test]
    fn rejects_performance_run_firmware_not_bound_to_selected_bundle() {
        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        let root = artifact_root(deployment.root.path());
        let error = load_driver_config(&root).unwrap_err();
        assert!(format!("{error:#}").contains("firmware SHA-256 does not match"));
    }

    #[test]
    fn receipt_bound_runtime_revalidation_does_not_read_replaced_source_inputs() {
        let deployment = deployment_fixture();
        let material = enable_performance_run(&deployment);
        let resources = enable_performance_run_resources(&deployment);
        let root = artifact_root(deployment.root.path());
        let initial = load_receipt_bound_driver_config(&root).unwrap();

        for source in [
            material.firmware,
            material.policy,
            material.qualification_receipt,
            deployment.root.path().join("hil-verification-receipt.json"),
            deployment.root.path().join("recovery-evidence.json"),
            resources.linker_map,
            resources.task_events_mapping_template,
        ] {
            fs::remove_file(source).unwrap();
        }

        assert_eq!(
            revalidate_receipt_bound_driver_config(&root, &initial).unwrap(),
            initial
        );
        let error = load_driver_config(&root).unwrap_err();
        assert!(format!("{error:#}").contains("performance-run firmware ELF"));
    }

    #[test]
    fn receipt_bound_runtime_revalidation_rejects_config_byte_replacement() {
        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        let root = artifact_root(deployment.root.path());
        let initial = load_receipt_bound_driver_config(&root).unwrap();

        let mut bytes = fs::read(&deployment.config_path).unwrap();
        bytes.push(b'\n');
        fs::write(&deployment.config_path, bytes).unwrap();

        let error = revalidate_receipt_bound_driver_config(&root, &initial).unwrap_err();
        assert!(error.to_string().contains("configuration bytes changed"));
    }

    #[test]
    fn receipt_bound_runtime_revalidation_rechecks_every_live_executable() {
        for kind in ["t32mcp", "workload", "signer", "fault"] {
            let deployment = deployment_fixture();
            let material = enable_performance_run(&deployment);
            let root = artifact_root(deployment.root.path());
            let (path, description) = match kind {
                "t32mcp" => (
                    deployment.root.path().join(if cfg!(windows) {
                        "t32mcp.exe"
                    } else {
                        "t32mcp"
                    }),
                    "t32mcp executable",
                ),
                "workload" => (material.workload, "`workload` executable"),
                "signer" => (material.signer, "`attestation_signer` executable"),
                "fault" => {
                    let path = deployment.root.path().join(if cfg!(windows) {
                        "fault-hook.exe"
                    } else {
                        "fault-hook"
                    });
                    let bytes = b"fault hook fixture";
                    fs::write(&path, bytes).unwrap();
                    let sha256 = digest(Sha256::digest(bytes).as_ref());
                    mutate_config(&deployment, |document| {
                        document["fault_actions"]["trace32_disconnect_at_stop"] = json!({
                            "executable": path.to_string_lossy(),
                            "expected_executable_sha256": sha256,
                            "arguments": ["{transaction_id}", "{binding_sha256}"],
                            "timeout_ms": 100
                        });
                    });
                    (path, "`trace32_disconnect_at_stop` executable")
                }
                _ => unreachable!(),
            };
            let initial = load_receipt_bound_driver_config(&root).unwrap();
            fs::write(&path, b"runtime executable drift").unwrap();
            let error = revalidate_receipt_bound_driver_config(&root, &initial).unwrap_err();
            assert!(
                format!("{error:#}").contains(description),
                "expected {description} error, got {error:#}"
            );
        }
    }

    #[test]
    fn receipt_bound_runtime_revalidation_rechecks_bundle_and_profile() {
        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        let root = artifact_root(deployment.root.path());
        let initial = load_receipt_bound_driver_config(&root).unwrap();
        let adapter = deployment.skills_root.join(format!(
            "{SKILL_PACKAGE_DIRECTORY}/{}",
            compiled_bundle_descriptor().bundle_relative_directory
        ));

        let manifest: Value =
            serde_json::from_slice(&fs::read(adapter.join(BUNDLE_MANIFEST_FILE)).unwrap()).unwrap();
        let member = manifest["files"][0]["path"].as_str().unwrap();
        fs::write(adapter.join(member), b"bundle member drift").unwrap();
        let error = revalidate_receipt_bound_driver_config(&root, &initial).unwrap_err();
        assert!(format!("{error:#}").contains("target-adapter bundle member"));

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        let root = artifact_root(deployment.root.path());
        let initial = load_receipt_bound_driver_config(&root).unwrap();
        let profile = deployment.skills_root.join(format!(
            "{SKILL_PACKAGE_DIRECTORY}/{}/{PROFILE_FILE}",
            compiled_bundle_descriptor().bundle_relative_directory
        ));
        fs::write(profile, b"{}\n").unwrap();
        let error = revalidate_receipt_bound_driver_config(&root, &initial).unwrap_err();
        assert!(format!("{error:#}").contains("parse installed target-adapter profile"));
    }

    #[test]
    fn generic_driver_dispatch_requires_duration_admission_and_immutable_binding() {
        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        let root = artifact_root(deployment.root.path());
        let loaded = load_receipt_bound_driver_config(&root).unwrap();

        let oversized = root
            .create_session_with_id(
                SessionId::new("generic-driver-oversized").unwrap(),
                &serde_json::to_value(PerformanceRunRequest {
                    schema: PerformanceRunRequestSchemaVersion,
                    duration_ns: 100_000_001,
                    top: 1,
                    report_format: PerformanceReportFormat::PerfettoJson,
                })
                .unwrap(),
            )
            .unwrap();
        let oversized_before = oversized.read_state().unwrap();
        let error = super::super::ensure_strict_performance_run_driver_admission(
            &root,
            oversized.id().as_str(),
            &loaded,
        )
        .unwrap_err();
        assert!(error.message.contains("outside deployment range"));
        assert_eq!(oversized.read_state().unwrap(), oversized_before);
        assert!(oversized.registered_artifacts(false).unwrap().is_empty());

        let unbound = root
            .create_session_with_id(
                SessionId::new("generic-driver-unbound").unwrap(),
                &serde_json::to_value(PerformanceRunRequest {
                    schema: PerformanceRunRequestSchemaVersion,
                    duration_ns: 100_000_000,
                    top: 1,
                    report_format: PerformanceReportFormat::PerfettoJson,
                })
                .unwrap(),
            )
            .unwrap();
        let unbound_before = unbound.read_state().unwrap();
        let error = super::super::ensure_strict_performance_run_driver_admission(
            &root,
            unbound.id().as_str(),
            &loaded,
        )
        .unwrap_err();
        assert!(error.message.contains("deployment binding is absent"));
        assert_eq!(unbound.read_state().unwrap(), unbound_before);
        assert!(unbound.registered_artifacts(false).unwrap().is_empty());
    }

    #[test]
    fn rejects_performance_run_relative_paths_hash_drift_and_policy_identity() {
        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["max_duration_ns"] = json!(0);
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("max_duration_ns"));

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["workload_command"]["timeout_ms"] = json!(100);
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("must be strictly greater"));

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["firmware"]["path"] = json!("relative.elf");
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("firmware ELF path `relative.elf` must be absolute"));

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["qualification"]["qualification_receipt"]["path"] =
                json!("relative-qualification.json");
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("qualification receipt path"));
        assert!(format!("{error:#}").contains("must be absolute"));

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["attestation"]["policy_path"] =
                json!("relative-policy.json");
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("capture trust policy path"));
        assert!(format!("{error:#}").contains("must be absolute"));

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["workload_command"]["executable"] =
                json!("relative-performance-workload");
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("`workload` executable path"));
        assert!(format!("{error:#}").contains("must be absolute"));

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["attestation"]["signer_command"]["executable"] =
                json!("relative-signer");
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("`attestation_signer` executable path"));
        assert!(format!("{error:#}").contains("must be absolute"));

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["firmware"]["sha256"] = json!("0".repeat(64));
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("firmware ELF has SHA-256"));

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["qualification"]["hil_receipt"]["sha256"] =
                json!("0".repeat(64));
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("HIL verification receipt has SHA-256"));

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["attestation"]["policy_sha256"] = json!("0".repeat(64));
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("capture trust policy has SHA-256"));

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["workload_command"]["expected_executable_sha256"] =
                json!("0".repeat(64));
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("`workload` executable has SHA-256"));

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["attestation"]["signer_command"]["expected_executable_sha256"] =
                json!("0".repeat(64));
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("`attestation_signer` executable has SHA-256"));

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["attestation"]["policy_id"] = json!("other-policy");
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("declares policy_id"));

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["attestation"]["key_id"] = json!("missing-key");
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("does not contain key_id"));
    }

    #[test]
    fn rejects_performance_run_resources_without_a_bundle_bound_firmware() {
        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        let resources = enable_performance_run_resources(&deployment);
        let root = artifact_root(deployment.root.path());
        let error = load_driver_config(&root).unwrap_err();
        assert!(format!("{error:#}").contains("firmware SHA-256 does not match"));
        assert!(resources.linker_map.exists());
    }

    #[test]
    fn rejects_resource_relative_paths_and_hash_drift() {
        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        enable_performance_run_resources(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["resources"]["linker_map"]["path"] = json!("relative.map");
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("linker map path `relative.map` must be absolute"));

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        enable_performance_run_resources(&deployment);
        mutate_config(&deployment, |document| {
            document["performance_run"]["resources"]["custom_events"]["c_wire_mapping"]["sha256"] =
                json!("0".repeat(64));
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(format!("{error:#}").contains("custom-event C wire mapping has SHA-256"));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn rejects_linked_performance_run_firmware_and_policy() {
        let deployment = deployment_fixture();
        let material = enable_performance_run(&deployment);
        let firmware_target = deployment.root.path().join("firmware-target.elf");
        fs::write(&firmware_target, fs::read(&material.firmware).unwrap()).unwrap();
        fs::remove_file(&material.firmware).unwrap();
        if create_file_symlink(&firmware_target, &material.firmware).is_ok() {
            let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
            assert!(format!("{error:#}").contains("symlink or reparse point"));
        }

        let deployment = deployment_fixture();
        let material = enable_performance_run(&deployment);
        let policy_target = deployment.root.path().join("policy-target.json");
        fs::write(&policy_target, fs::read(&material.policy).unwrap()).unwrap();
        fs::remove_file(&material.policy).unwrap();
        if create_file_symlink(&policy_target, &material.policy).is_ok() {
            let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
            assert!(format!("{error:#}").contains("symlink or reparse point"));
        }

        let deployment = deployment_fixture();
        let material = enable_performance_run(&deployment);
        let workload_target = deployment.root.path().join("workload-target");
        fs::write(&workload_target, fs::read(&material.workload).unwrap()).unwrap();
        fs::remove_file(&material.workload).unwrap();
        if create_file_symlink(&workload_target, &material.workload).is_ok() {
            let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
            assert!(format!("{error:#}").contains("symlink or reparse point"));
        }

        let deployment = deployment_fixture();
        let material = enable_performance_run(&deployment);
        let receipt_target = deployment.root.path().join("qualification-target.json");
        fs::write(
            &receipt_target,
            fs::read(&material.qualification_receipt).unwrap(),
        )
        .unwrap();
        fs::remove_file(&material.qualification_receipt).unwrap();
        if create_file_symlink(&receipt_target, &material.qualification_receipt).is_ok() {
            let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
            assert!(format!("{error:#}").contains("symlink or reparse point"));
        }

        let deployment = deployment_fixture();
        let material = enable_performance_run(&deployment);
        let signer_target = deployment.root.path().join("signer-target");
        fs::write(&signer_target, fs::read(&material.signer).unwrap()).unwrap();
        fs::remove_file(&material.signer).unwrap();
        if create_file_symlink(&signer_target, &material.signer).is_ok() {
            let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
            assert!(format!("{error:#}").contains("symlink or reparse point"));
        }

        let deployment = deployment_fixture();
        enable_performance_run(&deployment);
        let resources = enable_performance_run_resources(&deployment);
        let resource_target = deployment.root.path().join("linker-map-target");
        fs::write(&resource_target, fs::read(&resources.linker_map).unwrap()).unwrap();
        fs::remove_file(&resources.linker_map).unwrap();
        if create_file_symlink(&resource_target, &resources.linker_map).is_ok() {
            let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
            assert!(format!("{error:#}").contains("symlink or reparse point"));
        }
    }

    #[test]
    fn rejects_manifest_escape_sort_and_digest_drift() {
        let deployment = deployment_fixture();
        mutate_manifest(&deployment, |manifest| {
            manifest["files"][0]["path"] = json!("../../../../outside");
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(error.to_string().contains("escapes the skill package root"));

        let deployment = deployment_fixture();
        mutate_manifest(&deployment, |manifest| {
            manifest["files"].as_array_mut().unwrap().swap(0, 1);
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(error.to_string().contains("strictly bytewise sorted"));

        let deployment = deployment_fixture();
        let member = deployment
            .skills_root
            .join("skill-trace32-perf/scripts/perf_start.cmm");
        fs::write(member, b"drift").unwrap();
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(error.to_string().contains("has SHA-256"));
    }

    #[test]
    fn rejects_manifest_unknown_fields_and_bundle_digest_drift() {
        let deployment = deployment_fixture();
        mutate_manifest(&deployment, |manifest| {
            manifest["unknown"] = json!(true);
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("strict target-adapter bundle manifest")
        );

        let deployment = deployment_fixture();
        mutate_manifest(&deployment, |manifest| {
            manifest["bundle_sha256"] = json!("0".repeat(64));
        });
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(error.to_string().contains("canonical bundle digest"));
    }

    #[test]
    fn rejects_profile_drift_even_when_bundle_is_intact() {
        let deployment = deployment_fixture();
        let path = deployment.skills_root.join(format!(
            "{SKILL_PACKAGE_DIRECTORY}/{}/{PROFILE_FILE}",
            compiled_bundle_descriptor().bundle_relative_directory
        ));
        let mut profile: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        profile["target_identifier"] = json!("different-target");
        fs::write(path, serde_json::to_vec(&profile).unwrap()).unwrap();
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not equal the compiled candidate")
        );
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn rejects_symlinked_driver_config_when_platform_allows_creation() {
        let deployment = deployment_fixture();
        let target = deployment.root.path().join("config-target.json");
        fs::write(&target, fs::read(&deployment.config_path).unwrap()).unwrap();
        fs::remove_file(&deployment.config_path).unwrap();
        if create_file_symlink(&target, &deployment.config_path).is_err() {
            return;
        }
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(error.to_string().contains("symlink or reparse point"));
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn rejects_symlinked_bundle_member_when_platform_allows_creation() {
        let deployment = deployment_fixture();
        let member = deployment
            .skills_root
            .join("skill-trace32-perf/scripts/perf_start.cmm");
        let target = deployment.root.path().join("link-target");
        fs::write(&target, fs::read(&member).unwrap()).unwrap();
        fs::remove_file(&member).unwrap();
        if create_file_symlink(&target, &member).is_err() {
            return;
        }
        let error = load_driver_config(&artifact_root(deployment.root.path())).unwrap_err();
        assert!(error.to_string().contains("symlink or reparse point"));
    }

    struct DeploymentFixture {
        root: TempDir,
        skills_root: PathBuf,
        config_path: PathBuf,
    }

    struct PerformanceRunMaterial {
        firmware: PathBuf,
        policy: PathBuf,
        workload: PathBuf,
        signer: PathBuf,
        qualification_receipt: PathBuf,
    }

    struct PerformanceRunResourcesMaterial {
        linker_map: PathBuf,
        task_events_mapping_template: PathBuf,
    }

    fn deployment_fixture() -> DeploymentFixture {
        let root = TempDir::new().unwrap();
        let skills_root = root.path().join("skills");
        fs::create_dir(&skills_root).unwrap();
        copy_directory(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("skill-trace32-perf"),
            &skills_root.join("skill-trace32-perf"),
        );
        let executable = root.path().join(if cfg!(windows) {
            "t32mcp.exe"
        } else {
            "t32mcp"
        });
        let executable_bytes = b"bounded executable fixture";
        fs::write(&executable, executable_bytes).unwrap();
        let executable_sha256 = digest(Sha256::digest(executable_bytes).as_ref());
        let config_path = root.path().join(DRIVER_CONFIG_RELATIVE_PATH);
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        let document = json!({
            "schema": "t32perf.t32mcp-driver-config/v1",
            "executable": executable.to_string_lossy(),
            "expected_executable_sha256": executable_sha256,
            "skills_root": skills_root.to_string_lossy(),
            "trace32_port": 20000,
            "expected_t32mcp_version": "0.2.2",
            "expected_bundle_sha256": compiled_bundle_descriptor().candidate_profile.implementation_sha256,
            "poll_interval_ms": 100,
            "operation_timeout_ms": 5000,
            "max_stderr_bytes": 4096,
            "fault_actions": {}
        });
        fs::write(&config_path, serde_json::to_vec(&document).unwrap()).unwrap();
        DeploymentFixture {
            root,
            skills_root,
            config_path,
        }
    }

    fn enable_performance_run(deployment: &DeploymentFixture) -> PerformanceRunMaterial {
        let firmware = deployment.root.path().join("approved-firmware.elf");
        let firmware_bytes = b"approved firmware fixture";
        fs::write(&firmware, firmware_bytes).unwrap();
        let firmware_sha256 = digest(Sha256::digest(firmware_bytes).as_ref());

        let policy = deployment.root.path().join("capture-trust-policy.json");
        let policy_bytes = serde_json::to_vec(&capture_trust_policy()).unwrap();
        fs::write(&policy, &policy_bytes).unwrap();
        let policy_sha256 = digest(Sha256::digest(&policy_bytes).as_ref());

        let workload = deployment.root.path().join(if cfg!(windows) {
            "performance-run-workload.exe"
        } else {
            "performance-run-workload"
        });
        let workload_bytes = b"performance run workload fixture";
        fs::write(&workload, workload_bytes).unwrap();
        let workload_sha256 = digest(Sha256::digest(workload_bytes).as_ref());

        let signer = deployment.root.path().join(if cfg!(windows) {
            "capture-attestation-signer.exe"
        } else {
            "capture-attestation-signer"
        });
        let signer_bytes = b"capture attestation signer fixture";
        fs::write(&signer, signer_bytes).unwrap();
        let signer_sha256 = digest(Sha256::digest(signer_bytes).as_ref());

        let qualification_receipt = deployment.root.path().join("qualification-receipt.json");
        let qualification_receipt_bytes = b"qualification receipt fixture";
        fs::write(&qualification_receipt, qualification_receipt_bytes).unwrap();
        let qualification_receipt_sha256 =
            digest(Sha256::digest(qualification_receipt_bytes).as_ref());

        let hil_receipt = deployment.root.path().join("hil-verification-receipt.json");
        let hil_receipt_bytes = b"HIL verification receipt fixture";
        fs::write(&hil_receipt, hil_receipt_bytes).unwrap();
        let hil_receipt_sha256 = digest(Sha256::digest(hil_receipt_bytes).as_ref());

        let recovery_evidence = deployment.root.path().join("recovery-evidence.json");
        let recovery_evidence_bytes = b"recovery evidence fixture";
        fs::write(&recovery_evidence, recovery_evidence_bytes).unwrap();
        let recovery_evidence_sha256 = digest(Sha256::digest(recovery_evidence_bytes).as_ref());

        mutate_config(deployment, |document| {
            document["performance_run"] = json!({
                "max_duration_ns": 100_000_000_u64,
                "firmware": {
                    "path": firmware.to_string_lossy(),
                    "sha256": firmware_sha256
                },
                "workload_command": {
                    "executable": workload.to_string_lossy(),
                    "expected_executable_sha256": workload_sha256,
                    "arguments": [
                        "--session={session_id}",
                        "--state={initial_target_state}",
                        "--workload={workload_identity}",
                        "--duration-ns={duration_ns}"
                    ],
                    "timeout_ms": 101
                },
                "qualification": {
                    "policy_id": "production-qualification-policy",
                    "qualification_receipt": {
                        "path": qualification_receipt.to_string_lossy(),
                        "sha256": qualification_receipt_sha256
                    },
                    "hil_receipt": {
                        "path": hil_receipt.to_string_lossy(),
                        "sha256": hil_receipt_sha256
                    },
                    "recovery_evidence": {
                        "path": recovery_evidence.to_string_lossy(),
                        "sha256": recovery_evidence_sha256
                    }
                },
                "attestation": {
                    "policy_path": policy.to_string_lossy(),
                    "policy_sha256": policy_sha256,
                    "policy_id": "production-policy",
                    "key_id": "production-key",
                    "signer_command": {
                        "executable": signer.to_string_lossy(),
                        "expected_executable_sha256": signer_sha256,
                        "arguments": [
                            "--session={session_id}",
                            "--request={signing_request_path}",
                            "--request-sha256={signing_request_sha256}",
                            "--output={attestation_output_path}",
                            "--policy={policy_id}",
                            "--key={key_id}"
                        ],
                        "timeout_ms": 100
                    },
                    "idempotent_by_signing_request_sha256": true
                }
            });
        });
        PerformanceRunMaterial {
            firmware,
            policy,
            workload,
            signer,
            qualification_receipt,
        }
    }

    fn enable_performance_run_resources(
        deployment: &DeploymentFixture,
    ) -> PerformanceRunResourcesMaterial {
        let resource = |name: &str, bytes: &[u8]| {
            let path = deployment.root.path().join(name);
            fs::write(&path, bytes).unwrap();
            let sha256 = digest(Sha256::digest(bytes).as_ref());
            (path, sha256)
        };
        let (linker_map, linker_map_sha256) = resource("approved.map", b"linker map");
        let (stack_usage, stack_usage_sha256) = resource("approved.su", b"stack usage");
        let (static_ram_config, static_ram_config_sha256) =
            resource("static-ram.json", b"static ram config");
        let (orti, orti_sha256) = resource("approved.orti", b"orti");
        let (task_markers, task_markers_sha256) = resource("task-markers.json", b"markers");
        let (task_events_mapping_template, task_events_mapping_template_sha256) =
            resource("task-events-mapping.json", b"task mapping");
        let (c_wire_mapping, c_wire_mapping_sha256) =
            resource("c-wire-mapping.json", b"wire mapping");
        let (instrumentation_overhead, instrumentation_overhead_sha256) =
            resource("instrumentation-overhead.json", b"overhead");
        mutate_config(deployment, |document| {
            document["performance_run"]["resources"] = json!({
                "linker_map": { "path": linker_map.to_string_lossy(), "sha256": linker_map_sha256 },
                "stack_usage": { "path": stack_usage.to_string_lossy(), "sha256": stack_usage_sha256 },
                "static_ram_config": { "path": static_ram_config.to_string_lossy(), "sha256": static_ram_config_sha256 },
                "program_flow": {
                    "orti": { "path": orti.to_string_lossy(), "sha256": orti_sha256 },
                    "task_markers": { "path": task_markers.to_string_lossy(), "sha256": task_markers_sha256 },
                    "task_events_mapping_template": { "path": task_events_mapping_template.to_string_lossy(), "sha256": task_events_mapping_template_sha256 }
                },
                "custom_events": {
                    "c_wire_mapping": { "path": c_wire_mapping.to_string_lossy(), "sha256": c_wire_mapping_sha256 },
                    "instrumentation_overhead": { "path": instrumentation_overhead.to_string_lossy(), "sha256": instrumentation_overhead_sha256 }
                }
            });
        });
        PerformanceRunResourcesMaterial {
            linker_map,
            task_events_mapping_template,
        }
    }

    fn capture_trust_policy() -> CaptureTrustPolicy {
        let unavailable = MetricSupportEntry::unavailable("fixture");
        CaptureTrustPolicy {
            schema: CaptureTrustPolicySchemaVersion,
            policy_id: "production-policy".to_owned(),
            keys: vec![CaptureTrustKey {
                key_id: "production-key".to_owned(),
                public_key_ed25519: "1".repeat(64),
                producer: "deployment.capture-signer/v1".to_owned(),
                provider: "trace32".to_owned(),
                adapter: AdapterInfo {
                    id: "tricore-tc234l-snooper-pc-r2026.02-b190766-v1".to_owned(),
                    version: "1.0.0".to_owned(),
                },
                allowed_modes: vec!["snooper-pc-realtime-stack".to_owned()],
                target: TargetInfo {
                    architecture: Some("tricore".to_owned()),
                    device: Some("TC234L".to_owned()),
                    board: Some("deployment-board".to_owned()),
                    core_count: Some(1),
                    properties: Properties::new(),
                },
                trace32: Some(Trace32Info {
                    build: Some("R.2026.02.000190766".to_owned()),
                    probe: Some("Power Debug PRO".to_owned()),
                    architecture_package: Some("TriCore".to_owned()),
                    properties: Properties::new(),
                }),
                clocks: vec![ClockInfo {
                    id: "snooper_host_time".to_owned(),
                    frequency_hz: Some(1_000_000_000),
                    source: Some("trace32".to_owned()),
                    properties: Properties::new(),
                }],
                allowed_cores: vec![0],
                allowed_firmware_elf_sha256: vec![Sha256Digest::new("2".repeat(64)).unwrap()],
                capability_ceiling: CaptureCapabilities {
                    function_events: unavailable.clone(),
                    context_switches: unavailable.clone(),
                    interrupt_events: unavailable.clone(),
                    samples: unavailable.clone(),
                    custom_events: unavailable.clone(),
                    counters: unavailable,
                },
                config_constraints: None,
            }],
        }
    }

    fn mutate_config(deployment: &DeploymentFixture, mutate: impl FnOnce(&mut Value)) {
        let mut document: Value =
            serde_json::from_slice(&fs::read(&deployment.config_path).unwrap()).unwrap();
        mutate(&mut document);
        fs::write(
            &deployment.config_path,
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
    }

    fn mutate_manifest(deployment: &DeploymentFixture, mutate: impl FnOnce(&mut Value)) {
        let path = deployment.skills_root.join(format!(
            "{SKILL_PACKAGE_DIRECTORY}/{}/{BUNDLE_MANIFEST_FILE}",
            compiled_bundle_descriptor().bundle_relative_directory
        ));
        let mut manifest: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        mutate(&mut manifest);
        fs::write(path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    }

    fn artifact_root(path: &Path) -> ArtifactRoot {
        ArtifactRoot::open(
            path,
            SessionLimits {
                max_file_bytes: 16 * 1024 * 1024,
                max_session_bytes: 64 * 1024 * 1024,
            },
        )
        .unwrap()
    }

    fn copy_directory(source: &Path, destination: &Path) {
        fs::create_dir(destination).unwrap();
        for entry in fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let source_path = entry.path();
            let destination_path = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_directory(&source_path, &destination_path);
            } else {
                fs::copy(source_path, destination_path).unwrap();
            }
        }
    }

    #[cfg(unix)]
    fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }
}
