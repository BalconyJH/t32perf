---
title: Quickstart
description: Build T32Perf and complete a software-only performance observation loop
icon: material/rocket-launch-outline
status: new
---

# Quickstart

This guide builds T32Perf from source and runs a deterministic, software-only Session from
capture through deep verification. It does not require TRACE32 hardware.

!!! danger "Do not treat this run as hardware evidence"

    The `synthetic` provider validates the host pipeline and its contracts. It does not
    measure an MCU, probe, RTOS, firmware workload, or TRACE32 configuration.

## Prerequisites

- Rust stable with Cargo; CI currently resolves Rust `1.95.0`.
- A CMake-compatible C toolchain only when running the complete repository checks.
- [`uv`](https://docs.astral.sh/uv/) only for Python, HIL, benchmark, or documentation workflows.

## Build the CLI

=== "Windows PowerShell"

    ```powershell title="Build T32Perf"
    cargo build --release -p t32perf
    $T32PERF = ".\target\release\t32perf.exe"
    & $T32PERF --version
    ```

=== "Linux / macOS shell"

    ```bash title="Build T32Perf"
    cargo build --release -p t32perf
    T32PERF=./target/release/t32perf
    "$T32PERF" --version
    ```

Release bundles add provenance, archive verification, and packaging checks. See
[Installation and release verification](user-guide.md#installation-and-release-verification)
before installing a production binary.

## Complete the software loop

The commands below use a fixed Session ID so no output parsing is needed between steps.

=== "Windows PowerShell"

    ```powershell title="Synthetic capture to verified Perfetto report"
    $T32PERF = ".\target\release\t32perf.exe"
    & $T32PERF --artifact-root .\artifacts --json capture --provider synthetic --id quickstart-001 --events 1024
    & $T32PERF --artifact-root .\artifacts --json analyze quickstart-001
    & $T32PERF --artifact-root .\artifacts --json summary quickstart-001 --top 10
    & $T32PERF --artifact-root .\artifacts --json convert quickstart-001 --format perfetto-json
    & $T32PERF --artifact-root .\artifacts --json validate quickstart-001 --deep
    & $T32PERF --artifact-root .\artifacts --json artifacts verify quickstart-001
    ```

=== "Linux / macOS shell"

    ```bash title="Synthetic capture to verified Perfetto report"
    T32PERF=./target/release/t32perf
    "$T32PERF" --artifact-root ./artifacts --json capture --provider synthetic --id quickstart-001 --events 1024
    "$T32PERF" --artifact-root ./artifacts --json analyze quickstart-001
    "$T32PERF" --artifact-root ./artifacts --json summary quickstart-001 --top 10
    "$T32PERF" --artifact-root ./artifacts --json convert quickstart-001 --format perfetto-json
    "$T32PERF" --artifact-root ./artifacts --json validate quickstart-001 --deep
    "$T32PERF" --artifact-root ./artifacts --json artifacts verify quickstart-001
    ```

Each `--json` response is one JSON object on stdout. Logs remain on stderr. A successful
command has this outer shape:

```json title="Machine-readable response"
{"ok":true,"command":"...","result":{}}
```

## Inspect the result

The generated diagnostic timeline is:

```text
artifacts/quickstart-001/report/trace.json
```

Open it in [Perfetto UI](https://ui.perfetto.dev/) or another Chrome Trace JSON viewer.
The Session should finish with a `VALID` health verdict because the synthetic receipt
declares exactly which observation families the fixture provides.

??? info "What is stored in the Session?"

    ```text
    artifacts/quickstart-001/
    ├── request.json
    ├── state.json
    ├── manifest.json
    ├── capture/
    ├── normalized/
    │   └── observations.ndjson
    ├── analysis/
    │   ├── derived.ndjson
    │   ├── health.json
    │   ├── hotspots.json
    │   └── summary.json
    └── report/
        └── trace.json
    ```

    Artifact digests and provenance are recorded in an append-only index. The final
    manifest is immutable.

## Read verdicts and exit codes together

Automation must inspect both the process exit code and the typed result. A nonzero exit
can represent a semantic outcome rather than a CLI crash.

| Exit | Meaning |
|---:|---|
| `0` | Success, `IMPROVED`, `UNCHANGED`, or explicitly allowed `INCONCLUSIVE` |
| `10` | `DEGRADED` health |
| `11` | `INVALID` health |
| `12` | Performance `REGRESSED` |
| `13` | Comparison `INCONCLUSIVE` |
| `20` | Requested capability is `UNSUPPORTED` |
| `1` | Operational or argument error |

## Next steps

1. Read the [user guide](user-guide.md) for normalization, resources, comparison, and maintenance.
2. Review the [system architecture](architecture.md) and [data contracts](contracts.md).
3. Before using real hardware, follow the [TRACE32 integration runbook](trace32-runbook.md)
   and preserve its qualification boundary.
