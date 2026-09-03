use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use sha2::{Digest as _, Sha256};
use t32perf_model::{schema_documents, strict_json};
use t32perf_trace32::{
    c_wire_schema_documents, controller_schema_documents, driver_schema_documents,
    qualification_schema_documents, resource_schema_documents, target_adapter_schema_documents,
    trace_export_schema_documents,
};
use tar::{Archive as TarArchive, Builder as TarBuilder};
use tempfile::TempDir;
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

const MAX_SCHEMA_DOCUMENT_BYTES: u64 = 16 * 1024 * 1024;

const MAX_PACKAGED_COMMAND_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

const RELEASE_PROVENANCE_SCHEMA: &str = "t32perf.release-provenance/v1";

const RELEASE_PROVENANCE_FILE: &str = "release-provenance.json";

const MAX_RELEASE_PROVENANCE_BYTES: u64 = 64 * 1024;

#[cfg(windows)]
const MAX_LINKAGE_AUDIT_BINARY_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(about = "T32Perf repository workflows", version)]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Debug, Subcommand)]
enum Task {
    /// Run formatting, lint, tests, schemas, C SDK, and software-only HIL checks.
    Check,
    /// Generate checked-in JSON Schemas or verify schema drift.
    Schemas {
        /// Compare generated schemas without writing files.
        #[arg(long)]
        check: bool,
    },
    /// Build and test the C99 target SDK.
    Sdk,
    /// Run HIL harness tests; hardware mode requires T32PERF_HIL_BOARD.
    Hil {
        /// Run the real hardware marker instead of software-only harness tests.
        #[arg(long)]
        hardware: bool,
    },
    /// Run analyzer Criterion or same-input parser candidate benchmarks.
    Bench {
        /// Canonical NDJSON input for the Rust/Python candidate comparison.
        #[arg(long)]
        input: Option<PathBuf>,
        /// Include the explicit 10-million-event analyzer case.
        #[arg(long)]
        extended: bool,
    },
    /// Validate the repository-owned T32Perf skills.
    Skill,
    /// Build a self-contained release bundle plus zip and tar.gz archives.
    Package {
        /// Output directory. Existing bundles and archives are never overwritten.
        #[arg(long, default_value = "dist")]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root = workspace_root()?;
    match cli.command {
        Task::Check => check(&root),
        Task::Schemas { check } => schemas(&root, check),
        Task::Sdk => sdk(&root),
        Task::Hil { hardware } => hil(&root, hardware),
        Task::Bench { input, extended } => bench(&root, input.as_deref(), extended),
        Task::Skill => skill(&root),
        Task::Package { output } => package(&root, &output),
    }
}

fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("xtask has no workspace parent"))
}

fn check(root: &Path) -> Result<()> {
    run(root, "cargo", ["fmt", "--all", "--check"])?;
    run(
        root,
        "cargo",
        [
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    if has_nextest(root) {
        run(
            root,
            "cargo",
            ["nextest", "run", "--workspace", "--all-features"],
        )?;
    } else {
        eprintln!("cargo-nextest is unavailable; falling back to cargo test");
        run(root, "cargo", ["test", "--workspace", "--all-features"])?;
    }
    run(root, "cargo", ["test", "--workspace", "--doc"])?;
    schemas(root, true)?;
    sdk(root)?;
    hil(root, false)?;
    sampling_sidecar(root)?;
    run(
        root,
        "uv",
        [
            "run",
            "--no-project",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tools/bench",
            "-p",
            "test_*.py",
        ],
    )?;
    skill(root)
}

fn sampling_sidecar(root: &Path) -> Result<()> {
    let project = root.join("tools").join("lauterbach-sampling-mcp");
    run(&project, "uv", ["sync", "--locked"])?;
    run(&project, "uv", ["run", "ruff", "check", "src", "tests"])?;
    run(
        &project,
        "uv",
        ["run", "ruff", "format", "--check", "src", "tests"],
    )?;
    run(&project, "uv", ["run", "pyright", "src", "tests"])?;
    run(&project, "uv", ["run", "pytest", "-q"])
}

fn skill(root: &Path) -> Result<()> {
    run(
        root,
        "uv",
        [
            "run",
            "--no-project",
            "-m",
            "unittest",
            "tools.test_validate_skill",
        ],
    )?;
    for skill in ["skill-trace32-perf", "skills/t32perf-mcp"] {
        run(
            root,
            "uv",
            ["run", "--no-project", "tools/validate_skill.py", skill],
        )?;
    }
    Ok(())
}

fn bench(root: &Path, input: Option<&Path>, extended: bool) -> Result<()> {
    if let Some(input) = input {
        let input = if input.is_absolute() {
            input.to_path_buf()
        } else {
            root.join(input)
        };
        if !input.is_file() {
            bail!(
                "benchmark input is not a regular file: `{}`",
                input.display()
            );
        }
        run(
            root,
            "cargo",
            [
                "build",
                "--release",
                "-p",
                "t32perf-trace32",
                "--example",
                "ndjson_candidate",
            ],
        )?;
        return run_os(
            root,
            "uv",
            [
                OsStr::new("run"),
                OsStr::new("--no-project"),
                OsStr::new("tools/bench/run_candidates.py"),
                input.as_os_str(),
            ],
        );
    }

    let mut command = Command::new("cargo");
    command
        .args(["bench", "-p", "t32perf-analysis", "--bench", "streaming"])
        .current_dir(root)
        .stdin(Stdio::null());
    if extended {
        command.env("T32PERF_BENCH_10M", "1");
    }
    let status = command.status().context("start `cargo bench`")?;
    if !status.success() {
        bail!("`cargo bench` exited with {status}");
    }
    Ok(())
}

fn schemas(root: &Path, check: bool) -> Result<()> {
    let directory = root.join("schemas").join("v1");
    if !check {
        fs::create_dir_all(&directory)
            .with_context(|| format!("create schema directory `{}`", directory.display()))?;
    }
    let mut generated_documents = schema_documents();
    for documents in [
        c_wire_schema_documents(),
        controller_schema_documents(),
        driver_schema_documents(),
        qualification_schema_documents(),
        resource_schema_documents(),
        target_adapter_schema_documents(),
        trace_export_schema_documents(),
    ] {
        for (name, document) in documents {
            if generated_documents.insert(name, document).is_some() {
                bail!("duplicate generated schema filename `{name}`");
            }
        }
    }
    let hand_authored_schemas = [(
        "comparison-artifact.schema.json",
        "t32perf.comparison-artifact/v1",
    )];
    let expected_filenames = generated_documents
        .keys()
        .copied()
        .chain(hand_authored_schemas.iter().map(|(name, _)| *name))
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    for (name, generated) in generated_documents {
        let path = directory.join(name);
        if matches!(
            name,
            "normalize-config.schema.json" | "release-provenance.schema.json"
        ) {
            // These serde/field contracts are owned outside t32perf-model. Their
            // owners validate accepted documents directly. Comparing the model's
            // include_str inventory copy to the same file would be a
            // self-comparison, so this workflow only checks that the contract
            // artifact exists, is strict JSON, and declares the exact family.
            let existing = read_schema_document(&path, "checked-in schema")?;
            let expected_id = if name == "normalize-config.schema.json" {
                "t32perf.normalize-config/v1"
            } else {
                RELEASE_PROVENANCE_SCHEMA
            };
            if existing.get("$id").and_then(serde_json::Value::as_str) != Some(expected_id) {
                bail!(
                    "checked-in private-owner schema has an invalid `$id` in `{}`",
                    path.display()
                );
            }
            continue;
        }
        if check {
            let existing = read_schema_document(&path, "checked-in schema")?;
            if existing != generated {
                bail!("schema drift detected in `{}`", path.display());
            }
        } else {
            let mut bytes = serde_json::to_vec_pretty(&generated)?;
            bytes.push(b'\n');
            fs::write(&path, bytes)
                .with_context(|| format!("write schema `{}`", path.display()))?;
        }
    }
    for (name, schema_id) in hand_authored_schemas {
        let path = directory.join(name);
        let document = read_schema_document(&path, "hand-authored schema")?;
        if document.get("$id").and_then(serde_json::Value::as_str) != Some(schema_id) {
            bail!(
                "hand-authored schema `{}` must declare `$id` `{schema_id}`",
                path.display()
            );
        }
    }
    let actual_filenames = fs::read_dir(&directory)
        .with_context(|| format!("read schema directory `{}`", directory.display()))?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<io::Result<BTreeSet<_>>>()?
        .into_iter()
        .filter(|filename| filename.ends_with(".schema.json"))
        .collect::<BTreeSet<_>>();
    if actual_filenames != expected_filenames {
        bail!(
            "checked-in schema file set differs from unified schema inventory: actual={actual_filenames:?}, expected={expected_filenames:?}"
        );
    }
    Ok(())
}

fn read_schema_document(path: &Path, description: &str) -> Result<serde_json::Value> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("inspect {description} `{}`", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_SCHEMA_DOCUMENT_BYTES {
        bail!(
            "{description} `{}` must be a regular file no larger than {MAX_SCHEMA_DOCUMENT_BYTES} bytes",
            path.display()
        );
    }
    let bytes =
        fs::read(path).with_context(|| format!("read {description} `{}`", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_SCHEMA_DOCUMENT_BYTES {
        bail!(
            "{description} `{}` grew beyond {MAX_SCHEMA_DOCUMENT_BYTES} bytes while reading",
            path.display()
        );
    }
    strict_json::from_slice(&bytes)
        .with_context(|| format!("parse {description} `{}`", path.display()))
}

fn sdk(root: &Path) -> Result<()> {
    let use_ninja = std::env::var_os("CMAKE_GENERATOR").is_none()
        && command_available(root, "ninja", "--version");
    let build = root
        .join("target")
        .join(if use_ninja { "c-sdk-ninja" } else { "c-sdk" });
    let mut configure = vec![
        OsStr::new("-S").to_os_string(),
        OsStr::new("sdk/c").to_os_string(),
        OsStr::new("-B").to_os_string(),
        build.as_os_str().to_os_string(),
        OsStr::new("-DT32PERF_BUILD_TESTS=ON").to_os_string(),
    ];
    if use_ninja {
        configure.push(OsStr::new("-G").to_os_string());
        configure.push(OsStr::new("Ninja").to_os_string());
    }
    run_os(root, "cmake", configure)?;
    run_os(
        root,
        "cmake",
        [
            OsStr::new("--build"),
            build.as_os_str(),
            OsStr::new("--config"),
            OsStr::new("Release"),
        ],
    )?;
    run_os(
        root,
        "ctest",
        [
            OsStr::new("--test-dir"),
            build.as_os_str(),
            OsStr::new("-C"),
            OsStr::new("Release"),
            OsStr::new("--output-on-failure"),
        ],
    )
}

fn hil(root: &Path, hardware: bool) -> Result<()> {
    let marker = if hardware { "hardware" } else { "not hardware" };
    run(root, "uv", ["sync", "--project", "hil", "--locked"])?;
    run(
        root,
        "uv",
        [
            "run",
            "--project",
            "hil",
            "ruff",
            "check",
            "--config",
            "hil/pyproject.toml",
            "hil",
            "tools/bench",
        ],
    )?;
    run(
        root,
        "uv",
        [
            "run",
            "--project",
            "hil",
            "ruff",
            "format",
            "--check",
            "--config",
            "hil/pyproject.toml",
            "hil",
            "tools/bench",
        ],
    )?;
    run(
        root,
        "uv",
        [
            "run",
            "--project",
            "hil",
            "pytest",
            "hil/tests",
            "-m",
            marker,
        ],
    )
}

fn package(root: &Path, output: &Path) -> Result<()> {
    let rustc_verbose = command_utf8_stdout(root, "rustc", ["--version", "--verbose"])?;
    let native_target = unique_prefixed_line(&rustc_verbose, "host: ", "rustc host triple")?;
    let explicit_target = std::env::var_os("CARGO_BUILD_TARGET")
        .map(|value| {
            value
                .into_string()
                .map_err(|_| anyhow!("CARGO_BUILD_TARGET is not valid Unicode"))
        })
        .transpose()?;
    if explicit_target
        .as_deref()
        .is_some_and(|target| target != native_target)
    {
        bail!(
            "package smoke executes the built binary and therefore rejects cross target `{}`; native target is `{native_target}`",
            explicit_target.as_deref().unwrap_or_default()
        );
    }
    run(root, "cargo", ["build", "--release", "-p", "t32perf"])?;

    let output = if output.is_absolute() {
        output.to_path_buf()
    } else {
        root.join(output)
    };
    fs::create_dir_all(&output)
        .with_context(|| format!("create package output `{}`", output.display()))?;

    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let bundle_name = format!("t32perf-{}-{platform}", env!("CARGO_PKG_VERSION"));
    let bundle = output.join(&bundle_name);
    let staging = output.join(format!(".{bundle_name}.{}.tmp", std::process::id()));
    let zip_path = output.join(format!("{bundle_name}.zip"));
    let tar_path = output.join(format!("{bundle_name}.tar.gz"));
    let archive_checksums = output.join(format!("{bundle_name}.SHA256SUMS"));
    for path in [&bundle, &staging, &zip_path, &tar_path, &archive_checksums] {
        if path.exists() {
            bail!(
                "refusing to overwrite existing package path `{}`",
                path.display()
            );
        }
    }
    fs::create_dir(&staging)
        .with_context(|| format!("create package staging `{}`", staging.display()))?;

    let executable = if cfg!(windows) {
        "t32perf.exe"
    } else {
        "t32perf"
    };
    let mut release_directory = cargo_target_directory(root)?;
    if let Some(target) = &explicit_target {
        release_directory.push(target);
    }
    release_directory.push("release");
    copy_file(
        &release_directory.join(executable),
        &staging.join(executable),
    )?;
    for file in [
        "README.md",
        "Cargo.lock",
        "zensical.toml",
        "TRACE32 - T32MCP Performance Observability System Development Plan.md",
    ] {
        copy_file(&root.join(file), &staging.join(file))?;
    }
    for directory in [
        "schemas",
        "docs",
        "fixtures/golden",
        "golden-firmware",
        "sample-trace",
        "skill-trace32-perf",
        "skills",
        "sdk/c",
        "hil",
        "tools",
    ] {
        copy_tree(&root.join(directory), &staging.join(directory))?;
    }
    let release_provenance = write_release_provenance(root, &staging, executable, &bundle_name)?;
    write_checksums(&staging)?;
    fs::rename(&staging, &bundle).with_context(|| {
        format!(
            "commit package staging `{}` to `{}`",
            staging.display(),
            bundle.display()
        )
    })?;

    create_zip(&bundle, &bundle_name, &zip_path)?;
    create_tar_gz(&bundle, &bundle_name, &tar_path)?;
    smoke_archives(&zip_path, &tar_path, &bundle_name, &release_provenance)?;
    let zip_digest = sha256_file(&zip_path)?;
    let tar_digest = sha256_file(&tar_path)?;
    let mut checksum_writer = BufWriter::new(
        File::create(&archive_checksums)
            .with_context(|| format!("create `{}`", archive_checksums.display()))?,
    );
    writeln!(
        checksum_writer,
        "{zip_digest}  {}",
        zip_path
            .file_name()
            .ok_or_else(|| anyhow!("zip path has no file name"))?
            .to_string_lossy()
    )?;
    writeln!(
        checksum_writer,
        "{tar_digest}  {}",
        tar_path
            .file_name()
            .ok_or_else(|| anyhow!("tar.gz path has no file name"))?
            .to_string_lossy()
    )?;
    checksum_writer.flush()?;
    println!(
        "{}",
        serde_json::json!({
            "bundle": bundle,
            "zip": {"path": zip_path, "sha256": zip_digest},
            "tar_gz": {"path": tar_path, "sha256": tar_digest},
            "archive_checksums": archive_checksums,
            "release_provenance": {
                "path": bundle.join(RELEASE_PROVENANCE_FILE),
                "sha256": sha256_file(&bundle.join(RELEASE_PROVENANCE_FILE))?,
            },
        })
    );
    Ok(())
}

fn write_release_provenance(
    root: &Path,
    bundle: &Path,
    executable: &str,
    bundle_name: &str,
) -> Result<serde_json::Value> {
    let source_commit = source_commit_from_environment()?;
    let rustc_verbose = command_utf8_stdout(root, "rustc", ["--version", "--verbose"])?;
    let rustc_version = rustc_verbose
        .lines()
        .next()
        .filter(|line| !line.trim().is_empty())
        .context("rustc verbose version omitted its version line")?;
    let target_triple = unique_prefixed_line(&rustc_verbose, "host: ", "rustc host triple")?;
    let cargo_version = command_utf8_stdout(root, "cargo", ["--version"])?;
    let cargo_version = cargo_version.trim();
    if cargo_version.is_empty() {
        bail!("cargo version output is empty");
    }

    let binary = bundle.join(executable);
    let cargo_lock = bundle.join("Cargo.lock");
    let document = serde_json::json!({
        "schema": RELEASE_PROVENANCE_SCHEMA,
        "package": {
            "name": "t32perf",
            "version": env!("CARGO_PKG_VERSION"),
            "bundle_name": bundle_name,
        },
        "target": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "triple": target_triple,
        },
        "toolchain": {
            "rustc": rustc_version,
            "cargo": cargo_version,
        },
        "source": {
            "commit": source_commit,
            "cargo_lock": file_claim(bundle, &cargo_lock)?,
        },
        "binary": file_claim(bundle, &binary)?,
        "linkage": release_linkage_claim(&binary, target_triple)?,
    });
    validate_release_provenance(&document, bundle, bundle_name)?;

    let mut bytes = serde_json::to_vec_pretty(&document)?;
    bytes.push(b'\n');
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RELEASE_PROVENANCE_BYTES {
        bail!("release provenance exceeds {MAX_RELEASE_PROVENANCE_BYTES} bytes");
    }
    let path = bundle.join(RELEASE_PROVENANCE_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("create release provenance `{}`", path.display()))?;
    file.write_all(&bytes)?;
    file.flush()?;
    file.sync_all()?;

    let persisted = read_release_provenance(&path)?;
    if persisted != document {
        bail!("persisted release provenance differs from the generated document");
    }
    Ok(document)
}

fn source_commit_from_environment() -> Result<Option<String>> {
    let Some(value) = std::env::var_os("T32PERF_COMMIT") else {
        return Ok(None);
    };
    let value = value
        .into_string()
        .map_err(|_| anyhow!("T32PERF_COMMIT is not valid Unicode"))?;
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("T32PERF_COMMIT must be a lowercase 40-character commit hash");
    }
    Ok(Some(value))
}

fn unique_prefixed_line<'a>(input: &'a str, prefix: &str, label: &str) -> Result<&'a str> {
    let mut matches = input
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .filter(|value| !value.trim().is_empty());
    let value = matches
        .next()
        .with_context(|| format!("{label} is missing"))?;
    if matches.next().is_some() {
        bail!("{label} is ambiguous");
    }
    Ok(value)
}

fn command_utf8_stdout<I, S>(root: &Path, program: &str, arguments: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(program);
    command
        .args(arguments)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = bounded_output(command).with_context(|| format!("run `{program}`"))?;
    if !output.status.success() {
        bail!(
            "`{program}` exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).with_context(|| format!("`{program}` output is not UTF-8"))
}

fn cargo_target_directory(root: &Path) -> Result<PathBuf> {
    let output = command_utf8_stdout(
        root,
        "cargo",
        ["metadata", "--no-deps", "--format-version", "1"],
    )?;
    let document = strict_json::value_from_str(&output).context("parse cargo metadata JSON")?;
    let target = document
        .get("target_directory")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .context("cargo metadata omitted target_directory")?;
    Ok(PathBuf::from(target))
}

fn file_claim(bundle: &Path, path: &Path) -> Result<serde_json::Value> {
    let relative = path.strip_prefix(bundle).with_context(|| {
        format!(
            "release provenance file `{}` is outside bundle `{}`",
            path.display(),
            bundle.display()
        )
    })?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect release file `{}`", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("release file is not a plain file: `{}`", path.display());
    }
    Ok(serde_json::json!({
        "path": relative.to_string_lossy().replace('\\', "/"),
        "size_bytes": metadata.len(),
        "sha256": sha256_file(path)?,
    }))
}

#[cfg(windows)]
fn release_linkage_claim(path: &Path, target_triple: &str) -> Result<serde_json::Value> {
    if !target_triple.ends_with("-windows-msvc") {
        bail!("Windows release packaging requires an MSVC target triple");
    }
    let imported_libraries = pe_imported_libraries(path)?;
    if let Some(runtime) = imported_libraries
        .iter()
        .find(|library| forbidden_windows_runtime(library))
    {
        bail!("Windows release imports dynamic CRT library `{runtime}`; build with +crt-static");
    }
    Ok(serde_json::json!({
        "policy": "windows-msvc-static-crt",
        "audit": "pe-import-table/v1",
        "imported_libraries": imported_libraries,
    }))
}

#[cfg(not(windows))]
fn release_linkage_claim(_path: &Path, _target_triple: &str) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "policy": "system-libc-dynamic-allowed",
        "audit": "platform-policy-only/v1",
        "imported_libraries": [],
    }))
}

#[cfg(windows)]
fn forbidden_windows_runtime(library: &str) -> bool {
    let library = library.to_ascii_lowercase();
    library == "ucrtbase.dll"
        || library.starts_with("api-ms-win-crt-")
        || library.starts_with("vcruntime")
        || library.starts_with("msvcp")
        || library.starts_with("msvcr")
        || library.starts_with("concrt")
        || library.starts_with("vcomp")
}

#[cfg(windows)]
fn pe_imported_libraries(path: &Path) -> Result<Vec<String>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect PE binary `{}`", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "PE import audit input is not a plain file: `{}`",
            path.display()
        );
    }
    if metadata.len() > MAX_LINKAGE_AUDIT_BINARY_BYTES {
        bail!(
            "PE import audit input `{}` exceeds {MAX_LINKAGE_AUDIT_BINARY_BYTES} bytes",
            path.display()
        );
    }
    let bytes = fs::read(path).with_context(|| format!("read PE binary `{}`", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_LINKAGE_AUDIT_BINARY_BYTES {
        bail!("PE import audit input grew beyond its bound while reading");
    }
    parse_pe_imported_libraries(&bytes)
}

#[cfg(windows)]
fn parse_pe_imported_libraries(bytes: &[u8]) -> Result<Vec<String>> {
    if bytes.get(..2) != Some(b"MZ") {
        bail!("release executable is not a PE image");
    }
    let pe_offset =
        usize::try_from(read_pe_u32(bytes, 0x3c)?).context("PE offset exceeds usize")?;
    if bytes.get(pe_offset..pe_offset.saturating_add(4)) != Some(b"PE\0\0") {
        bail!("release executable has an invalid PE signature");
    }
    let section_count = usize::from(read_pe_u16(bytes, pe_offset + 6)?);
    if section_count == 0 || section_count > 96 {
        bail!("release executable has an invalid PE section count");
    }
    let optional_size = usize::from(read_pe_u16(bytes, pe_offset + 20)?);
    let optional_offset = pe_offset
        .checked_add(24)
        .context("PE optional header offset overflow")?;
    let optional_end = optional_offset
        .checked_add(optional_size)
        .context("PE optional header size overflow")?;
    if optional_end > bytes.len() {
        bail!("release executable has a truncated PE optional header");
    }
    let (directory_offset, directory_count_offset) = match read_pe_u16(bytes, optional_offset)? {
        0x10b => (optional_offset + 96, optional_offset + 92),
        0x20b => (optional_offset + 112, optional_offset + 108),
        magic => bail!("release executable has unsupported PE optional-header magic {magic:#x}"),
    };
    let directory_count = read_pe_u32(bytes, directory_count_offset)?;
    let available_directories = u32::try_from(optional_end.saturating_sub(directory_offset) / 8)
        .context("PE data-directory count exceeds u32")?;
    if directory_count > available_directories {
        bail!("release executable declares PE data directories beyond its optional header");
    }
    if directory_count < 2 {
        bail!("release executable has no PE import directory");
    }
    let import_rva = read_pe_u32(bytes, directory_offset + 8)?;
    let import_size = read_pe_u32(bytes, directory_offset + 12)?;
    if import_rva == 0 || import_size < 20 {
        bail!("release executable has an empty PE import directory");
    }
    if directory_count > 13 {
        let delay_offset = directory_offset + 13 * 8;
        let delay_rva = read_pe_u32(bytes, delay_offset)?;
        let delay_size = read_pe_u32(bytes, delay_offset + 4)?;
        if delay_rva != 0 || delay_size != 0 {
            bail!("release executable uses unaudited PE delay imports");
        }
    }
    let section_table = optional_end;
    let section_bytes = section_count
        .checked_mul(40)
        .context("PE section table size overflow")?;
    if section_table
        .checked_add(section_bytes)
        .is_none_or(|end| end > bytes.len())
    {
        bail!("release executable has a truncated PE section table");
    }
    let headers_size = read_pe_u32(bytes, optional_offset + 60)?;
    let sections = (0..section_count)
        .map(|index| {
            let offset = section_table + index * 40;
            Ok(PeSection {
                virtual_size: read_pe_u32(bytes, offset + 8)?,
                virtual_address: read_pe_u32(bytes, offset + 12)?,
                raw_size: read_pe_u32(bytes, offset + 16)?,
                raw_offset: read_pe_u32(bytes, offset + 20)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let import_offset = pe_rva_to_offset(import_rva, headers_size, &sections, bytes.len())?;
    let maximum_descriptors = usize::try_from(import_size / 20)
        .context("PE import descriptor count exceeds usize")?
        .min(4096);
    let mut imports = BTreeSet::new();
    let mut terminated = false;
    for index in 0..maximum_descriptors {
        let offset = import_offset
            .checked_add(index * 20)
            .context("PE import descriptor offset overflow")?;
        let descriptor = bytes
            .get(offset..offset + 20)
            .context("release executable has a truncated PE import descriptor")?;
        if descriptor.iter().all(|byte| *byte == 0) {
            terminated = true;
            break;
        }
        let name_rva = read_pe_u32(bytes, offset + 12)?;
        if name_rva == 0 {
            bail!("release executable has a PE import without a library name");
        }
        let name_offset = pe_rva_to_offset(name_rva, headers_size, &sections, bytes.len())?;
        let name = read_pe_c_string(bytes, name_offset, 260)?.to_ascii_lowercase();
        imports.insert(name);
    }
    if !terminated {
        bail!("release executable PE import directory has no bounded terminator");
    }
    Ok(imports.into_iter().collect())
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct PeSection {
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
}

#[cfg(windows)]
fn pe_rva_to_offset(
    rva: u32,
    headers_size: u32,
    sections: &[PeSection],
    file_size: usize,
) -> Result<usize> {
    if rva < headers_size {
        let offset = usize::try_from(rva).context("PE header RVA exceeds usize")?;
        if offset < file_size {
            return Ok(offset);
        }
    }
    for section in sections {
        let span = section.virtual_size.max(section.raw_size);
        let Some(end) = section.virtual_address.checked_add(span) else {
            continue;
        };
        if rva >= section.virtual_address && rva < end {
            let delta = rva - section.virtual_address;
            if delta >= section.raw_size {
                bail!("PE RVA points into virtual data without file bytes");
            }
            let offset = section
                .raw_offset
                .checked_add(delta)
                .context("PE raw file offset overflow")?;
            let offset = usize::try_from(offset).context("PE raw file offset exceeds usize")?;
            if offset < file_size {
                return Ok(offset);
            }
        }
    }
    bail!("PE RVA {rva:#x} does not map to file data")
}

#[cfg(windows)]
fn read_pe_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes
        .get(offset..offset.saturating_add(2))
        .context("release executable has a truncated PE integer")?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

#[cfg(windows)]
fn read_pe_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes
        .get(offset..offset.saturating_add(4))
        .context("release executable has a truncated PE integer")?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

#[cfg(windows)]
fn read_pe_c_string(bytes: &[u8], offset: usize, maximum: usize) -> Result<String> {
    let available = bytes
        .get(offset..)
        .context("PE import name offset is outside the file")?;
    let length = available
        .iter()
        .take(maximum.saturating_add(1))
        .position(|byte| *byte == 0)
        .filter(|length| *length <= maximum)
        .context("PE import name is unterminated or oversized")?;
    let name = std::str::from_utf8(&available[..length]).context("PE import name is not UTF-8")?;
    if name.is_empty() || !name.is_ascii() {
        bail!("PE import name must be non-empty ASCII");
    }
    Ok(name.to_owned())
}

fn create_zip(bundle: &Path, bundle_name: &str, destination: &Path) -> Result<()> {
    let temporary = destination.with_extension("zip.tmp");
    if temporary.exists() {
        bail!("refusing to overwrite `{}`", temporary.display());
    }
    let file = File::create(&temporary)
        .with_context(|| format!("create zip `{}`", temporary.display()))?;
    let mut writer = ZipWriter::new(BufWriter::new(file));
    for path in regular_files(bundle)? {
        let relative = path.strip_prefix(bundle)?;
        let archive_path = Path::new(bundle_name).join(relative);
        let archive_name = archive_path.to_string_lossy().replace('\\', "/");
        let permissions = if relative.components().count() == 1
            && relative.file_name()
                == Some(OsStr::new(if cfg!(windows) {
                    "t32perf.exe"
                } else {
                    "t32perf"
                })) {
            0o755
        } else {
            0o644
        };
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .unix_permissions(permissions);
        writer.start_file(archive_name, options)?;
        let mut source =
            File::open(&path).with_context(|| format!("open package file `{}`", path.display()))?;
        std::io::copy(&mut source, &mut writer)?;
    }
    writer.finish()?.flush()?;
    fs::rename(&temporary, destination).with_context(|| {
        format!(
            "commit zip `{}` to `{}`",
            temporary.display(),
            destination.display()
        )
    })?;
    Ok(())
}

fn smoke_archives(
    zip_path: &Path,
    tar_path: &Path,
    bundle_name: &str,
    expected_provenance: &serde_json::Value,
) -> Result<()> {
    let zip_temp = TempDir::new().context("create zip smoke-test directory")?;
    extract_zip(zip_path, zip_temp.path())?;
    smoke_bundle(&zip_temp.path().join(bundle_name), expected_provenance)
        .with_context(|| format!("smoke-test zip `{}`", zip_path.display()))?;

    let tar_temp = TempDir::new().context("create tar smoke-test directory")?;
    extract_tar_gz(tar_path, tar_temp.path())?;
    smoke_bundle(&tar_temp.path().join(bundle_name), expected_provenance)
        .with_context(|| format!("smoke-test tar.gz `{}`", tar_path.display()))
}

fn extract_zip(source: &Path, destination: &Path) -> Result<()> {
    let file = File::open(source).with_context(|| format!("open zip `{}`", source.display()))?;
    let mut archive = ZipArchive::new(BufReader::new(file))?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        if entry.is_dir() {
            bail!(
                "zip unexpectedly contains a directory entry `{}`",
                entry.name()
            );
        }
        let relative = entry
            .enclosed_name()
            .ok_or_else(|| anyhow!("zip contains an unsafe path `{}`", entry.name()))?;
        let output = destination.join(relative);
        let parent = output
            .parent()
            .ok_or_else(|| anyhow!("zip entry has no parent `{}`", output.display()))?;
        fs::create_dir_all(parent)?;
        let mut writer = File::create(&output)
            .with_context(|| format!("create extracted file `{}`", output.display()))?;
        std::io::copy(&mut entry, &mut writer)?;
        writer.flush()?;
        #[cfg(unix)]
        if let Some(mode) = entry.unix_mode() {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&output, fs::Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

fn extract_tar_gz(source: &Path, destination: &Path) -> Result<()> {
    let file = File::open(source).with_context(|| format!("open tar.gz `{}`", source.display()))?;
    let mut archive = TarArchive::new(GzDecoder::new(BufReader::new(file)));
    for entry in archive.entries()? {
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        if !kind.is_file() && !kind.is_dir() {
            bail!("tar.gz contains a non-regular entry");
        }
        let path = entry.path()?.into_owned();
        if !entry.unpack_in(destination)? {
            bail!("tar.gz contains an unsafe path `{}`", path.display());
        }
    }
    Ok(())
}

fn smoke_bundle(bundle: &Path, expected_provenance: &serde_json::Value) -> Result<()> {
    verify_checksums(bundle)?;
    let provenance = read_release_provenance(&bundle.join(RELEASE_PROVENANCE_FILE))?;
    let expected_bundle_name = bundle
        .file_name()
        .and_then(OsStr::to_str)
        .context("release bundle has no Unicode file name")?;
    validate_release_provenance(&provenance, bundle, expected_bundle_name)?;
    if &provenance != expected_provenance {
        bail!("archive release provenance differs from the generated document");
    }
    let executable = bundle.join(if cfg!(windows) {
        "t32perf.exe"
    } else {
        "t32perf"
    });
    if !executable.is_file() {
        bail!("package executable is missing: `{}`", executable.display());
    }

    let artifacts = TempDir::new().context("create package smoke artifact root")?;
    run_json_command(&executable, artifacts.path(), ["doctor"], &[0, 20])?;
    run_json_command(
        &executable,
        artifacts.path(),
        [
            "capture",
            "--provider",
            "synthetic",
            "--id",
            "package-smoke",
            "--events",
            "64",
        ],
        &[0],
    )?;
    run_json_command(
        &executable,
        artifacts.path(),
        ["analyze", "package-smoke"],
        &[0],
    )?;
    run_json_command(
        &executable,
        artifacts.path(),
        ["convert", "package-smoke", "--format", "perfetto-json"],
        &[0],
    )?;
    verify_packaged_tool_provenance(&provenance, artifacts.path())?;
    run_json_command(
        &executable,
        artifacts.path(),
        ["validate", "package-smoke", "--deep"],
        &[0],
    )?;
    run_json_command(
        &executable,
        artifacts.path(),
        ["artifacts", "verify", "package-smoke", "--id", "perfetto"],
        &[0],
    )?;
    run_json_command(
        &executable,
        artifacts.path(),
        ["session", "create", "--id", "package-list-only"],
        &[0],
    )?;
    let sessions = run_json_command(
        &executable,
        artifacts.path(),
        ["session", "list", "--limit", "1"],
        &[0],
    )?;
    if sessions["result"]["truncated"] != true
        || sessions["result"]["returned_count"] != 1
        || sessions["result"]["next_after"].as_str().is_none()
    {
        bail!("package session.list smoke response omitted bounded pagination metadata");
    }
    fs::write(
        artifacts
            .path()
            .join("package-list-only/logs/package-residue.tmp"),
        b"package smoke crash residue",
    )?;
    let abandon = run_json_command(
        &executable,
        artifacts.path(),
        ["maintenance", "abandon", "plan", "package-list-only"],
        &[0],
    )?;
    let abandon_plan = abandon["result"]["plan_id"]
        .as_str()
        .context("package abandon plan omitted plan_id")?
        .to_owned();
    let abandon_confirmation = abandon["result"]["confirm_sha256"]
        .as_str()
        .context("package abandon plan omitted confirm_sha256")?
        .to_owned();
    run_json_command(
        &executable,
        artifacts.path(),
        [
            "maintenance".to_owned(),
            "abandon".to_owned(),
            "apply".to_owned(),
            abandon_plan.clone(),
            "--confirm".to_owned(),
            abandon_confirmation.clone(),
        ],
        &[0],
    )?;
    run_json_command(
        &executable,
        artifacts.path(),
        [
            "maintenance".to_owned(),
            "abandon".to_owned(),
            "restore".to_owned(),
            abandon_plan,
            "--confirm".to_owned(),
            abandon_confirmation,
        ],
        &[0],
    )?;
    let listed_artifacts = run_json_command(
        &executable,
        artifacts.path(),
        ["artifacts", "list", "package-smoke", "--limit", "1"],
        &[0],
    )?;
    if listed_artifacts["result"]["truncated"] != true
        || listed_artifacts["result"]["returned_count"] != 1
        || listed_artifacts["result"]["next_after"].as_str().is_none()
    {
        bail!("package artifacts.list smoke response omitted bounded pagination metadata");
    }
    let comparison = run_json_command(
        &executable,
        artifacts.path(),
        [
            "compare",
            "package-smoke",
            "package-smoke",
            "--policy",
            "strict",
            "--top",
            "1",
        ],
        &[0],
    )?;
    let comparison_path = comparison["result"]["report_artifact"]["control_path"]
        .as_str()
        .context("package comparison omitted control_path")?;
    let comparison_path = artifacts.path().join(comparison_path);
    if !comparison_path.is_file() {
        bail!(
            "package comparison did not publish `{}`",
            comparison_path.display()
        );
    }
    let comparison_digest = sha256_file(&comparison_path)?;
    if comparison["result"]["report_artifact"]["sha256"] != comparison_digest {
        bail!("package comparison artifact digest does not match its reference");
    }
    run_json_command(
        &executable,
        artifacts.path(),
        ["maintenance", "inspect", "package-smoke", "--deep"],
        &[0],
    )?;
    run_json_command(
        &executable,
        artifacts.path(),
        ["maintenance", "diagnostics", "package-smoke"],
        &[0],
    )?;
    run_json_command(
        &executable,
        artifacts.path(),
        ["maintenance", "schema", "package-smoke"],
        &[0],
    )?;
    let retention = run_json_command(
        &executable,
        artifacts.path(),
        [
            "maintenance",
            "retention",
            "plan",
            "--session",
            "package-smoke",
        ],
        &[0],
    )?;
    let plan_id = retention["result"]["plan_id"]
        .as_str()
        .context("package retention plan omitted plan_id")?
        .to_owned();
    let confirmation = retention["result"]["confirm_sha256"]
        .as_str()
        .context("package retention plan omitted confirm_sha256")?
        .to_owned();
    run_json_failure_command(
        &executable,
        artifacts.path(),
        [
            "maintenance".to_owned(),
            "retention".to_owned(),
            "apply".to_owned(),
            plan_id.clone(),
            "--confirm".to_owned(),
            "0".repeat(64),
        ],
        &[1],
    )?;
    run_json_command(
        &executable,
        artifacts.path(),
        [
            "maintenance".to_owned(),
            "retention".to_owned(),
            "apply".to_owned(),
            plan_id.clone(),
            "--confirm".to_owned(),
            confirmation.clone(),
        ],
        &[0],
    )?;
    run_json_command(
        &executable,
        artifacts.path(),
        [
            "maintenance".to_owned(),
            "retention".to_owned(),
            "apply".to_owned(),
            plan_id.clone(),
            "--confirm".to_owned(),
            confirmation.clone(),
        ],
        &[0],
    )?;
    run_json_command(
        &executable,
        artifacts.path(),
        [
            "maintenance".to_owned(),
            "retention".to_owned(),
            "restore".to_owned(),
            plan_id.clone(),
            "package-smoke".to_owned(),
            "--confirm".to_owned(),
            confirmation.clone(),
        ],
        &[0],
    )?;
    run_json_command(
        &executable,
        artifacts.path(),
        [
            "maintenance".to_owned(),
            "retention".to_owned(),
            "restore".to_owned(),
            plan_id,
            "package-smoke".to_owned(),
            "--confirm".to_owned(),
            confirmation,
        ],
        &[0],
    )?;
    run_json_command(
        &executable,
        artifacts.path(),
        [
            "capture",
            "--provider",
            "synthetic",
            "--id",
            "package-orphan",
            "--events",
            "8",
        ],
        &[0],
    )?;
    run_json_command(
        &executable,
        artifacts.path(),
        ["analyze", "package-orphan"],
        &[0],
    )?;
    fs::write(
        artifacts.path().join("package-orphan/logs/orphan.log"),
        b"package smoke orphan",
    )?;
    run_json_failure_command(
        &executable,
        artifacts.path(),
        [
            "maintenance",
            "retention",
            "plan",
            "--session",
            "package-orphan",
        ],
        &[1],
    )?;
    let report = artifacts
        .path()
        .join("package-smoke")
        .join("report")
        .join("trace.json");
    if !report.is_file() {
        bail!("package smoke test did not produce `{}`", report.display());
    }
    Ok(())
}

fn read_release_provenance(path: &Path) -> Result<serde_json::Value> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect release provenance `{}`", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "release provenance is not a plain file: `{}`",
            path.display()
        );
    }
    if metadata.len() > MAX_RELEASE_PROVENANCE_BYTES {
        bail!(
            "release provenance `{}` exceeds {MAX_RELEASE_PROVENANCE_BYTES} bytes",
            path.display()
        );
    }
    let bytes =
        fs::read(path).with_context(|| format!("read release provenance `{}`", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RELEASE_PROVENANCE_BYTES {
        bail!("release provenance grew beyond its size limit while reading");
    }
    strict_json::value_from_slice(&bytes).context("parse strict release provenance JSON")
}

fn validate_release_provenance(
    document: &serde_json::Value,
    bundle: &Path,
    expected_bundle_name: &str,
) -> Result<()> {
    let root = exact_object(
        document,
        "release provenance",
        &[
            "binary",
            "linkage",
            "package",
            "schema",
            "source",
            "target",
            "toolchain",
        ],
    )?;
    if root["schema"] != RELEASE_PROVENANCE_SCHEMA {
        bail!("release provenance declares an unsupported schema");
    }

    let package = exact_object(
        &root["package"],
        "release provenance package",
        &["bundle_name", "name", "version"],
    )?;
    require_exact_string(package, "name", "t32perf", "package name")?;
    require_exact_string(
        package,
        "version",
        env!("CARGO_PKG_VERSION"),
        "package version",
    )?;
    require_exact_string(package, "bundle_name", expected_bundle_name, "bundle name")?;

    let target = exact_object(
        &root["target"],
        "release provenance target",
        &["arch", "os", "triple"],
    )?;
    require_exact_string(target, "os", std::env::consts::OS, "target OS")?;
    require_exact_string(
        target,
        "arch",
        std::env::consts::ARCH,
        "target architecture",
    )?;
    require_nonempty_string(target, "triple", "target triple")?;

    let toolchain = exact_object(
        &root["toolchain"],
        "release provenance toolchain",
        &["cargo", "rustc"],
    )?;
    require_nonempty_string(toolchain, "rustc", "rustc version")?;
    require_nonempty_string(toolchain, "cargo", "cargo version")?;

    let source = exact_object(
        &root["source"],
        "release provenance source",
        &["cargo_lock", "commit"],
    )?;
    match &source["commit"] {
        serde_json::Value::Null => {}
        serde_json::Value::String(value)
            if value.len() == 40
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) => {}
        _ => bail!("release provenance source commit is not null or a lowercase 40-character hash"),
    }
    validate_file_claim(&source["cargo_lock"], bundle, "Cargo.lock")?;
    let executable = if cfg!(windows) {
        "t32perf.exe"
    } else {
        "t32perf"
    };
    validate_file_claim(&root["binary"], bundle, executable)?;
    let (linkage, imports) = validate_linkage_claim_fields(&root["linkage"])?;
    #[cfg(windows)]
    validate_windows_linkage_claim(linkage, imports, &root["target"], bundle, executable)?;
    #[cfg(not(windows))]
    validate_non_windows_linkage_claim(linkage, imports)?;
    Ok(())
}

fn validate_linkage_claim_fields(
    value: &serde_json::Value,
) -> Result<(
    &serde_json::Map<String, serde_json::Value>,
    &[serde_json::Value],
)> {
    let claim = exact_object(
        value,
        "release provenance linkage",
        &["audit", "imported_libraries", "policy"],
    )?;
    let imports = claim["imported_libraries"]
        .as_array()
        .context("release provenance imported_libraries must be an array")?;
    let mut previous = None;
    for import in imports {
        let import = import
            .as_str()
            .filter(|value| !value.is_empty())
            .context("release provenance imported library must be a non-empty string")?;
        if previous.is_some_and(|previous| previous >= import) {
            bail!("release provenance imported libraries must be unique and sorted");
        }
        previous = Some(import);
    }
    Ok((claim, imports))
}

#[cfg(windows)]
fn validate_windows_linkage_claim(
    claim: &serde_json::Map<String, serde_json::Value>,
    imports: &[serde_json::Value],
    target: &serde_json::Value,
    bundle: &Path,
    executable: &str,
) -> Result<()> {
    require_exact_string(claim, "policy", "windows-msvc-static-crt", "linkage policy")?;
    require_exact_string(claim, "audit", "pe-import-table/v1", "linkage audit")?;
    let triple = target["triple"]
        .as_str()
        .context("release provenance target triple is missing")?;
    if !triple.ends_with("-windows-msvc") {
        bail!("Windows release provenance requires an MSVC target triple");
    }
    if imports
        .iter()
        .filter_map(serde_json::Value::as_str)
        .any(forbidden_windows_runtime)
    {
        bail!("Windows release provenance imports a dynamically linked CRT runtime");
    }
    let observed = pe_imported_libraries(&bundle.join(executable))?;
    let declared = imports
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    if observed != declared {
        bail!("Windows PE import audit differs from release provenance");
    }
    Ok(())
}

#[cfg(not(windows))]
fn validate_non_windows_linkage_claim(
    claim: &serde_json::Map<String, serde_json::Value>,
    imports: &[serde_json::Value],
) -> Result<()> {
    require_exact_string(
        claim,
        "policy",
        "system-libc-dynamic-allowed",
        "linkage policy",
    )?;
    require_exact_string(claim, "audit", "platform-policy-only/v1", "linkage audit")?;
    if !imports.is_empty() {
        bail!("non-Windows policy-only linkage claim must not invent imported libraries");
    }
    Ok(())
}

fn exact_object<'a>(
    value: &'a serde_json::Value,
    label: &str,
    expected_keys: &[&str],
) -> Result<&'a serde_json::Map<String, serde_json::Value>> {
    let object = value
        .as_object()
        .with_context(|| format!("{label} must be an object"))?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected_keys.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        bail!("{label} fields differ: actual={actual:?}, expected={expected:?}");
    }
    Ok(object)
}

fn require_exact_string(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    expected: &str,
    label: &str,
) -> Result<()> {
    if object.get(field).and_then(serde_json::Value::as_str) != Some(expected) {
        bail!("release provenance {label} does not match `{expected}`");
    }
    Ok(())
}

fn require_nonempty_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
    label: &str,
) -> Result<&'a str> {
    object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("release provenance {label} must be a non-empty string"))
}

fn validate_file_claim(
    value: &serde_json::Value,
    bundle: &Path,
    expected_path: &str,
) -> Result<()> {
    let claim = exact_object(
        value,
        "release provenance file claim",
        &["path", "sha256", "size_bytes"],
    )?;
    require_exact_string(claim, "path", expected_path, "file path")?;
    let size_bytes = claim["size_bytes"]
        .as_u64()
        .context("release provenance file size must be a u64")?;
    let digest = require_nonempty_string(claim, "sha256", "file SHA-256")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("release provenance file SHA-256 is malformed");
    }
    let path = bundle.join(expected_path);
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspect claimed release file `{}`", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "claimed release file is not a plain file: `{}`",
            path.display()
        );
    }
    if metadata.len() != size_bytes {
        bail!("release provenance size mismatch for `{expected_path}`");
    }
    if sha256_file(&path)? != digest {
        bail!("release provenance digest mismatch for `{expected_path}`");
    }
    Ok(())
}

fn verify_packaged_tool_provenance(
    provenance: &serde_json::Value,
    artifact_root: &Path,
) -> Result<()> {
    let manifest_path = artifact_root.join("package-smoke").join("manifest.json");
    let bytes = fs::read(&manifest_path)
        .with_context(|| format!("read package smoke manifest `{}`", manifest_path.display()))?;
    let manifest = strict_json::value_from_slice(&bytes).context("parse package smoke manifest")?;
    let tool = manifest
        .get("tool")
        .and_then(serde_json::Value::as_object)
        .context("package smoke manifest omitted tool provenance")?;
    let package_version = provenance["package"]["version"]
        .as_str()
        .context("release provenance omitted package version")?;
    if tool.get("name").and_then(serde_json::Value::as_str) != Some("t32perf")
        || tool.get("version").and_then(serde_json::Value::as_str) != Some(package_version)
    {
        bail!("packaged binary manifest tool identity does not match release provenance");
    }
    let manifest_commit = tool.get("commit").unwrap_or(&serde_json::Value::Null);
    if manifest_commit != &provenance["source"]["commit"] {
        bail!("packaged binary embedded commit does not match release provenance");
    }
    Ok(())
}

fn verify_checksums(bundle: &Path) -> Result<()> {
    let checksum_path = bundle.join("SHA256SUMS");
    let contents = fs::read_to_string(&checksum_path)
        .with_context(|| format!("read `{}`", checksum_path.display()))?;
    let mut declared = BTreeSet::new();
    for (line_index, line) in contents.lines().enumerate() {
        let (digest, relative) = line.split_once("  ").ok_or_else(|| {
            anyhow!(
                "invalid SHA256SUMS line {} in `{}`",
                line_index + 1,
                checksum_path.display()
            )
        })?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("invalid SHA-256 digest on line {}", line_index + 1);
        }
        let relative = Path::new(relative);
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            bail!("unsafe checksum path `{}`", relative.display());
        }
        let normalized = relative.to_string_lossy().replace('\\', "/");
        if !declared.insert(normalized.clone()) {
            bail!("duplicate checksum path `{normalized}`");
        }
        let actual = sha256_file(&bundle.join(relative))?;
        if actual != digest {
            bail!("checksum mismatch for `{}`", relative.display());
        }
    }

    let actual = regular_files(bundle)?
        .into_iter()
        .filter_map(|path| {
            let relative = path.strip_prefix(bundle).ok()?;
            (relative != Path::new("SHA256SUMS"))
                .then(|| relative.to_string_lossy().replace('\\', "/"))
        })
        .collect::<BTreeSet<_>>();
    if actual != declared {
        bail!("SHA256SUMS does not exactly cover package files");
    }
    Ok(())
}

fn run_json_command<I, S>(
    executable: &Path,
    artifact_root: &Path,
    arguments: I,
    allowed_exit_codes: &[i32],
) -> Result<serde_json::Value>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let (document, code, stderr) = execute_json_command(executable, artifact_root, arguments)?;
    if !allowed_exit_codes.contains(&code) {
        let command = document
            .get("command")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<unknown>");
        bail!(
            "packaged command `{command}` exited with {code}: response={document}; stderr={}",
            stderr.trim()
        );
    }
    if document.get("ok") != Some(&serde_json::Value::Bool(true)) {
        bail!("packaged command reported failure: {document}");
    }
    Ok(document)
}

fn run_json_failure_command<I, S>(
    executable: &Path,
    artifact_root: &Path,
    arguments: I,
    allowed_exit_codes: &[i32],
) -> Result<serde_json::Value>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let (document, code, stderr) = execute_json_command(executable, artifact_root, arguments)?;
    if !allowed_exit_codes.contains(&code) {
        let command = document
            .get("command")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("<unknown>");
        bail!(
            "packaged command `{command}` exited with {code}: response={document}; stderr={}",
            stderr.trim()
        );
    }
    if document.get("ok") != Some(&serde_json::Value::Bool(false)) {
        bail!("packaged command unexpectedly reported success: {document}");
    }
    Ok(document)
}

fn execute_json_command<I, S>(
    executable: &Path,
    artifact_root: &Path,
    arguments: I,
) -> Result<(serde_json::Value, i32, String)>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(executable);
    command
        .arg("--artifact-root")
        .arg(artifact_root)
        .arg("--json")
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = bounded_output(command)
        .with_context(|| format!("run packaged `{}`", executable.display()))?;
    let code = output.status.code().unwrap_or(-1);
    let stdout = std::str::from_utf8(&output.stdout).context("packaged stdout is not UTF-8")?;
    if stdout.lines().count() != 1 {
        bail!("packaged command did not emit exactly one JSON object");
    }
    let document: serde_json::Value =
        strict_json::from_str(stdout).context("parse packaged command JSON")?;
    Ok((
        document,
        code,
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

fn bounded_output(mut command: Command) -> Result<Output> {
    let mut child = command.spawn().context("start bounded command")?;
    let stdout = child
        .stdout
        .take()
        .context("bounded command stdout was not piped")?;
    let stderr = child
        .stderr
        .take()
        .context("bounded command stderr was not piped")?;
    let abort = Arc::new(AtomicBool::new(false));
    let stdout_abort = Arc::clone(&abort);
    let stderr_abort = Arc::clone(&abort);
    let stdout_reader = thread::spawn(move || {
        read_bounded_output(stdout, MAX_PACKAGED_COMMAND_OUTPUT_BYTES, stdout_abort)
    });
    let stderr_reader = thread::spawn(move || {
        read_bounded_output(stderr, MAX_PACKAGED_COMMAND_OUTPUT_BYTES, stderr_abort)
    });

    let status = loop {
        if abort.load(Ordering::Acquire) {
            let _ = child.kill();
            break child.wait().context("wait for over-limit command")?;
        }
        if let Some(status) = child.try_wait().context("poll bounded command")? {
            break status;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow!("bounded stdout reader panicked"))?
        .context("read bounded command stdout")?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow!("bounded stderr reader panicked"))?
        .context("read bounded command stderr")?;
    if abort.load(Ordering::Acquire) {
        bail!(
            "packaged command output exceeded {MAX_PACKAGED_COMMAND_OUTPUT_BYTES} bytes on stdout or stderr"
        );
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn read_bounded_output<R: Read>(
    mut reader: R,
    limit: usize,
    abort: Arc<AtomicBool>,
) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(read) => read,
            Err(error) => {
                abort.store(true, Ordering::Release);
                return Err(error);
            }
        };
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > limit {
            abort.store(true, Ordering::Release);
            return Err(io::Error::other(format!(
                "command output exceeds {limit} bytes"
            )));
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

fn create_tar_gz(bundle: &Path, bundle_name: &str, destination: &Path) -> Result<()> {
    let temporary = destination.with_extension("gz.tmp");
    if temporary.exists() {
        bail!("refusing to overwrite `{}`", temporary.display());
    }
    let file = File::create(&temporary)
        .with_context(|| format!("create tar.gz `{}`", temporary.display()))?;
    let encoder = GzEncoder::new(BufWriter::new(file), Compression::best());
    let mut builder = TarBuilder::new(encoder);
    builder.append_dir_all(bundle_name, bundle)?;
    let encoder = builder.into_inner()?;
    encoder.finish()?.flush()?;
    fs::rename(&temporary, destination).with_context(|| {
        format!(
            "commit tar.gz `{}` to `{}`",
            temporary.display(),
            destination.display()
        )
    })?;
    Ok(())
}

fn write_checksums(bundle: &Path) -> Result<()> {
    let mut entries = Vec::new();
    for path in regular_files(bundle)? {
        let relative = path
            .strip_prefix(bundle)?
            .to_string_lossy()
            .replace('\\', "/");
        entries.push((relative, sha256_file(&path)?));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let destination = bundle.join("SHA256SUMS");
    let mut output = BufWriter::new(
        File::create(&destination)
            .with_context(|| format!("create `{}`", destination.display()))?,
    );
    for (relative, digest) in entries {
        writeln!(output, "{digest}  {relative}")?;
    }
    output.flush()?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut reader = BufReader::new(
        File::open(path).with_context(|| format!("open `{}` for hashing", path.display()))?,
    );
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(char::from(HEX[usize::from(byte >> 4)]));
        result.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    result
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(source).with_context(|| format!("inspect `{}`", source.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "package source is not a plain directory: `{}`",
            source.display()
        );
    }
    fs::create_dir_all(destination)
        .with_context(|| format!("create package directory `{}`", destination.display()))?;
    let mut entries = fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        if skip_package_entry(&entry.file_name()) {
            continue;
        }
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_symlink() {
            bail!(
                "package source contains a link: `{}`",
                source_path.display()
            );
        }
        if metadata.is_dir() {
            copy_tree(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            copy_file(&source_path, &destination_path)?;
        } else {
            bail!(
                "package source is not a regular file: `{}`",
                source_path.display()
            );
        }
    }
    Ok(())
}

fn skip_package_entry(name: &OsStr) -> bool {
    matches!(
        name.to_str(),
        Some(".venv" | ".pytest_cache" | ".ruff_cache" | "__pycache__" | ".DS_Store" | "dist")
    ) || name.to_str().is_some_and(|value| value.ends_with(".pyc"))
}

fn copy_file(source: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        bail!("refusing to overwrite `{}`", destination.display());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, destination)
        .with_context(|| format!("copy `{}` to `{}`", source.display(), destination.display()))?;
    Ok(())
}

fn regular_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(&directory)?.collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries.into_iter().rev() {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                bail!("archive input contains a link: `{}`", path.display());
            }
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                files.push(path);
            } else {
                bail!("archive input is not a regular file: `{}`", path.display());
            }
        }
    }
    files.sort();
    Ok(files)
}

fn has_nextest(root: &Path) -> bool {
    Command::new("cargo")
        .args(["nextest", "--version"])
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn command_available(root: &Path, program: &str, version_argument: &str) -> bool {
    Command::new(program)
        .arg(version_argument)
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn run<I, S>(root: &Path, program: &str, arguments: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    run_os(root, program, arguments)
}

fn run_os<I, S>(root: &Path, program: &str, arguments: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let status = Command::new(program)
        .args(arguments)
        .current_dir(root)
        .stdin(Stdio::null())
        .status()
        .with_context(|| format!("start `{program}`"))?;
    if !status.success() {
        bail!("`{program}` exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn release_fixture(bundle: &Path) -> serde_json::Value {
        let executable = if cfg!(windows) {
            "t32perf.exe"
        } else {
            "t32perf"
        };
        fs::copy(std::env::current_exe().unwrap(), bundle.join(executable)).unwrap();
        fs::write(bundle.join("Cargo.lock"), b"lock").unwrap();
        serde_json::json!({
            "schema": RELEASE_PROVENANCE_SCHEMA,
            "package": {
                "name": "t32perf",
                "version": env!("CARGO_PKG_VERSION"),
                "bundle_name": bundle.file_name().unwrap().to_string_lossy(),
            },
            "target": {
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "triple": if cfg!(windows) {
                    "x86_64-pc-windows-msvc"
                } else {
                    "x86_64-unknown-linux-gnu"
                },
            },
            "toolchain": {
                "rustc": "rustc test",
                "cargo": "cargo test",
            },
            "source": {
                "commit": "a".repeat(40),
                "cargo_lock": file_claim(bundle, &bundle.join("Cargo.lock")).unwrap(),
            },
            "binary": file_claim(bundle, &bundle.join(executable)).unwrap(),
            "linkage": release_linkage_claim(&bundle.join(executable), if cfg!(windows) {
                "x86_64-pc-windows-msvc"
            } else {
                "x86_64-unknown-linux-gnu"
            }).unwrap(),
        })
    }

    #[test]
    fn bounded_output_reader_accepts_the_exact_limit() {
        let abort = Arc::new(AtomicBool::new(false));
        let output = read_bounded_output(Cursor::new(vec![b'x'; 16]), 16, Arc::clone(&abort))
            .expect("read exact-limit output");
        assert_eq!(output.len(), 16);
        assert!(!abort.load(Ordering::Acquire));
    }

    #[test]
    fn bounded_output_reader_signals_overflow() {
        let abort = Arc::new(AtomicBool::new(false));
        let error = read_bounded_output(Cursor::new(vec![b'x'; 17]), 16, Arc::clone(&abort))
            .expect_err("reject over-limit output");
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(abort.load(Ordering::Acquire));
    }

    #[test]
    fn release_provenance_is_strict_and_binds_claimed_files() {
        let temporary = TempDir::new().unwrap();
        let bundle = temporary.path().join("t32perf-test-bundle");
        fs::create_dir(&bundle).unwrap();
        let document = release_fixture(&bundle);
        validate_release_provenance(&document, &bundle, "t32perf-test-bundle").unwrap();

        let mut unknown = document.clone();
        unknown["target"]["unexpected"] = serde_json::Value::Bool(true);
        assert!(validate_release_provenance(&unknown, &bundle, "t32perf-test-bundle").is_err());

        let executable = if cfg!(windows) {
            "t32perf.exe"
        } else {
            "t32perf"
        };
        fs::write(bundle.join(executable), b"tampered").unwrap();
        assert!(validate_release_provenance(&document, &bundle, "t32perf-test-bundle").is_err());
    }

    #[test]
    fn release_provenance_reader_rejects_duplicate_keys_and_oversize() {
        let temporary = TempDir::new().unwrap();
        let path = temporary.path().join(RELEASE_PROVENANCE_FILE);
        fs::write(
            &path,
            br#"{"schema":"t32perf.release-provenance/v1","schema":"t32perf.release-provenance/v1"}"#,
        )
        .unwrap();
        assert!(read_release_provenance(&path).is_err());

        fs::write(
            &path,
            vec![b' '; usize::try_from(MAX_RELEASE_PROVENANCE_BYTES + 1).unwrap()],
        )
        .unwrap();
        assert!(read_release_provenance(&path).is_err());
    }
}
