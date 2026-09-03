# T32Perf User Guide

This guide describes the current `t32perf 0.1.0` CLI. The Windows release executable is `t32perf.exe`; the Linux executable is `t32perf`. Examples consistently use `t32perf`.

## Installation and release verification

A release directory contains the following deliverables:

```text
t32perf-<version>-<os>-<arch>/
t32perf-<version>-<os>-<arch>.zip
t32perf-<version>-<os>-<arch>.tar.gz
t32perf-<version>-<os>-<arch>.SHA256SUMS
```

The outer `.SHA256SUMS` covers the `.zip` and `.tar.gz` archives. The extracted bundle also contains `SHA256SUMS`, which covers every bundle file except itself exactly.

Example verification on Linux:

```text
sha256sum -c t32perf-<version>-linux-<arch>.SHA256SUMS
tar -xzf t32perf-<version>-linux-<arch>.tar.gz
cd t32perf-<version>-linux-<arch>
sha256sum -c SHA256SUMS
./t32perf --version
```

Example verification in Windows PowerShell:

```powershell
Get-Content .\t32perf-<version>-windows-<arch>.SHA256SUMS | ForEach-Object {
    $expected, $relative = $_ -split '  ', 2
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $relative).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "checksum mismatch: $relative" }
}

Expand-Archive -LiteralPath .\t32perf-<version>-windows-<arch>.zip -DestinationPath .
Set-Location .\t32perf-<version>-windows-<arch>
Get-Content .\SHA256SUMS | ForEach-Object {
    $expected, $relative = $_ -split '  ', 2
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $relative).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "checksum mismatch: $relative" }
}
.\t32perf.exe --version
```

Do not execute a binary directly from an unverified archive. Treat the extracted directory as a read-only release directory, and choose a separate artifact root with sufficient space that is written exclusively by the Controller.

Build from source and create release packages with:

```text
cargo build --release -p t32perf
cargo xtask package --output dist
```

`cargo xtask package` refuses to overwrite an existing output of the same name. It independently extracts both archives, verifies digests and release provenance, and runs a synthetic end-to-end smoke test. The bundle-root `release-provenance.json` follows `t32perf.release-provenance/v1` in the [schema catalog](schema-catalog.md). It binds the package version and name, target OS/architecture/triple, actual rustc and cargo, optional source commit, the size/SHA-256 of `Cargo.lock` and the binary, and the linkage policy. Windows MSVC packages use the static CRT. The packager and both archive smoke tests parse the PE import table and reject packages importing `VCRUNTIME*`, `MSVCP*`, `UCRTBASE`, or `api-ms-win-crt-*`. Linux explicitly permits the system dynamic libc; it is not presented as a fully static system image.

For tag releases, the Windows and Linux package jobs in the same workflow run `cargo xtask check` before publishing is permitted. Both checks and both package smoke tests must pass. Release builds also compile the exact `${{ github.sha }}` into Session tool provenance through `T32PERF_COMMIT` and record it in package provenance. Archive smoke tests run the packaged binary and require the two commit values to match exactly. A manual source build carries a commit only when that environment variable is explicitly set. The current `v*` workflow then publishes directly; it does not consume a digest-bound security approval or use a protected production environment. Treat that publication as development-only until P8 implements candidate-build/protected-publish separation. Production publish must consume the exact reviewed archives without rebuilding them.

The bundle contains benchmarks, a skill validator, and an optional Perfetto validator under `tools/`. The Python package, trace processor, compiler, and lab tools remain external runtime dependencies; the bundle does not claim to be a self-contained hardware environment.

Building only the host binary requires the repository-pinned Rust `1.95.0` toolchain. A full `cargo xtask check` additionally requires `uv`, CMake/CTest, and an available C99 compiler. If cargo-nextest is unavailable, the workflow explicitly falls back to `cargo test`.

Reproducible benchmark workflow:

```text
cargo xtask bench --input <canonical-observations.ndjson>
cargo xtask bench --extended
```

The first command release-builds the Rust candidate, then measures the Rust and Python parsers on identical input with the same runner and 100 ms working-set sampling. The second runs the analyzer Criterion suite including the 10M case. See [Current implementation status](implementation-status.md) for results and limitations.

## Global CLI conventions

```text
t32perf [GLOBAL OPTIONS] <COMMAND>
```

| Option | Default | Meaning |
|---|---:|---|
| `--artifact-root <PATH>` | `.t32perf` | Allowlisted root directory for Sessions |
| `--max-file-bytes <N>` | 68719476736 | Per-artifact limit; 64 GiB by default |
| `--max-session-bytes <N>` | 274877906944 | Per-Session total limit; 256 GiB by default |
| `--json` | Disabled | Emit single-line JSON to stdout; errors are also stdout JSON |

The Session limit must not be smaller than the per-file limit. Without `--json`, successful or semantic results use pretty JSON; parameter and operational errors normally go to stderr. Logs always go to stderr. Use `RUST_LOG` to change their level, and `T32PERF_LOG_FORMAT=json` for line-delimited structured logs. Logs never record CLI arguments, requests, policy paths, or artifact contents.

Automation should use `--json` and check all of the following:

1. The process exit code.
2. Top-level `ok`.
3. `result.health_verdict`, `result.trust_status`, or `result.verdict`.
4. `report.reasons` for comparisons.

## Synthetic quick start

```text
t32perf --artifact-root ./artifacts --json capture --provider synthetic --id quickstart-001 --events 1024
t32perf --artifact-root ./artifacts --json analyze quickstart-001
t32perf --artifact-root ./artifacts --json summary quickstart-001 --top 10
t32perf --artifact-root ./artifacts --json convert quickstart-001 --format perfetto-json
t32perf --artifact-root ./artifacts --json validate quickstart-001 --deep
t32perf --artifact-root ./artifacts --json artifacts verify quickstart-001
```

Primary outputs:

```text
artifacts/quickstart-001/normalized/observations.ndjson
artifacts/quickstart-001/analysis/derived.ndjson
artifacts/quickstart-001/analysis/health.json
artifacts/quickstart-001/analysis/hotspots.json
artifacts/quickstart-001/analysis/summary.json
artifacts/quickstart-001/report/trace.json
artifacts/quickstart-001/manifest.json
```

`capture --provider synthetic` and `fixture generate` both create deterministic software fixtures. Use them for software regressions, performance testing, and deployment smoke tests; they do not validate a real TRACE32 export, MCU time base, RTOS Awareness, or native statistics.

## Command reference

| Command | Purpose | Key constraint |
|---|---|---|
| `session create` | Create an empty Session | `--request` must be a JSON object |
| `session list` | Page through Sessions, states, and artifact counts | `--limit` is 1..1000 (default 100); use the preceding `next_after` as `--after`; no deep hashing |
| `session status <SESSION>` | Read durable state, manifest, and trust status | Health is `NOT_EVALUATED` before it is produced |
| `session ingest <SESSION>` | Promote a staging file to an immutable artifact | Source must be in that Session's `capture/staging` |
| `session attest <SESSION>` | Verify an external Ed25519 capture attestation and create a trusted receipt | Accepts only a `captured` Session; failure makes it `failed` |
| `capture --provider synthetic` | Create and complete a synthetic capture | The only built-in provider at present |
| `fixture generate` | Create a synthetic fixture Session | Not hardware capture |
| `perf_capabilities <SESSION>` | Prepare, resume, or complete a capability transaction | Returns one typed execute/collect/invoke `next_action`; never guesses hardware capabilities |
| `perf_capture <SESSION>` | Advance the real-capture control chain by durable phase | Prepares or accepts at most one transaction at a time; Start requires explicit `--workload-complete`; `--mode` is accepted only at Export |
| `perf_get_status <SESSION>` | Return typed durable-state/trust data | Reuses `session status` validation; exposes no arbitrary JSON |
| `perf_get_summary <SESSION>` | Return typed health, Top-N functions/samples, and Task/ISR summaries | `--top` is 1..100; detailed resources remain artifacts |
| `perf_list_artifacts <SESSION>` | Return a typed artifact page | `--limit` is 1..1000; a row includes at most 16 provenance input IDs |
| `perf_convert <SESSION> --format perfetto-json` | Return typed conversion and artifact reference | Does not inline trace content |
| `perf_compare <BASELINE> <CANDIDATE> --policy ...` | Return typed verdict/outcome counts and a complete report-artifact reference | Does not inline comparison rows |
| `perf_run --duration-ms <MS> [--id <SESSION>] [--top <N>]` | Create or resume the admitted one-command production workflow | The fixed deployment supplies firmware, qualification, workload, signer, trust policy, and optional resources; callers cannot override them |
| `sampling prepare <SESSION> --capture-request <JSON>` | Issue one immutable generic PC-sampling capability | Returns the operation ID and exact `sampling_capture` arguments; one Session authorizes one export |
| `sampling ingest <SESSION> --staged <PATH>` | Verify sidecar request/journal/endpoint evidence and register the histogram | Accepts only the sidecar-generated `capture/staging/pc-hit-histogram-*` path |
| `sampling bind-firmware <SESSION> --staged <ELF>` | Bind an exact precommitted ELF assertion for diagnostic function attribution | Requires `deployed_firmware_elf_sha256` in the immutable request; records `PrecommittedElfAssertion` / `deployment_asserted`, not verified firmware or a target-image comparison |
| `sampling analyze <SESSION> --histogram-artifact sampling-pc-hit-histogram --projection address\|function` | Create an aggregate statistical heatmap | Address projection automatically preserves bounded TRACE32 runtime code labels when available; function projection additionally requires the registered ELF and Host-reserved firmware evidence |
| `sampling summary\|render <SESSION> --projection address\|function` | Re-derive and present the registered heatmap | `summary --top` and `render --max-rows` are 1..100; SVG variants have distinct immutable IDs |
| `normalize <SESSION>` | Convert registered input(s) to canonical observations using explicit adapter configuration | `single_source` uses `--input-artifact`; `multi_source` gets inputs from configuration; does not grant hardware trust |
| `analyze <SESSION>` | Stream observations and optional resource input through analysis | Requires a synthetic receipt or verified external signed receipt |
| `summary <SESSION>` | Return a bounded, health-gated diagnostic or Top-N quantitative summary | `--top` is 1..100; only `VALID` returns `quantitative` |
| `convert <SESSION> --format perfetto-json` | Write Perfetto JSON and commit the manifest | Only `perfetto-json` is currently supported |
| `validate <SESSION> [--deep]` | Validate the Session, manifest, stage receipts, and health | `--deep` recomputes SHA-256 |
| `artifacts list <SESSION>` | Page catalog metadata | `--limit` is 1..1000 (default 100); use prior `next_after`; does not read full artifacts |
| `artifacts verify <SESSION>` | Validate all artifacts or one selected by `--id` | Deep by default; `--shallow` checks only type and size |
| `compare <BASELINE> <CANDIDATE> --policy ...` | Compare two completed Sessions | Both need manifest, health, hotspots, and verified analysis summary; `--top` affects only stdout projection |
| `controller prepare <SESSION>` | Write an immutable, binding-bound t32mcp request and allocate response/output paths | Only one active transaction per artifact root; shares the root-wide execution lease with the real driver |
| `controller accept <SESSION> <TRANSACTION>` | Ingest and validate a final t32mcp wrapper and optional output | Missing, unfinished, or invalid bindings remain pending and retain the root slot; Cleanup success materializes capture config under the same lease |
| `controller provision-firmware <SESSION>` | Create or exactly reuse the fixed `firmware-elf` artifact from a trusted staged ELF | Keeps the Session `created`; Controller accepts only an ELF exactly matching the selected profile |
| `controller provision-qualification <SESSION>` | Validate deployment trust, qualification, HIL, and optional recovery evidence and create the admission snapshot | The policy ID resolves only through the administrator trust store; `perf_run` invokes this internally from fixed deployment inputs |
| `controller select-scenario <SESSION>` | Register a deployment-owned target-adapter scenario | Public performance capture permits only `normal`; fault scenarios are for trusted fault/HIL flows |
| `controller abort <SESSION> <TRANSACTION>` | Write a bound abort plan and return the exact official abort call | Does not execute abort, finalize the Session, or release the slot |
| `controller confirm-abort <SESSION> <TRANSACTION>` | Let a trusted caller explicitly confirm upstream unbound-tool success | Requires `--acknowledge-unbound-success`; releasing the slot follows writing the abort receipt |
| `controller driver-preflight` | Under the root-wide OS lease, validate config, binary/bundle, version, initialization, and exact tool inventory | Does not call a practice tool or connect TRACE32; not board evidence |
| `controller drive <SESSION> --surface capabilities\|capture` | Drive the typed façade to a terminal projection with a managed stdio child | Append-only events prevent replaying execute/workload/fault/abort after crash; `--mode raw_ascii` is permitted only at Export |
| `controller drive-transaction <SESSION> <TRANSACTION>` | Execute/collect an existing immutable transaction and pass it to Host acceptance | On restart, driver journal determines accept, confirm, abort/quarantine, or ambiguous fail-closed; no blind retry |
| `controller abort-upstream <SESSION> <TRANSACTION> --reason ...` | Write an abort plan, call official abort, and confirm immediately | With `abort_success_observed`, retries only Host confirmation, never official abort/END |
| `controller recover prepare/accept` | Create and validate recovery evidence for endpoint or target quarantine | Recovery never turns a failed Session into a successful capture |
| `controller status <SESSION>` | List bounded transaction state | Returns at most 32 entries and reports truncation |
| `maintenance inspect <SESSION>` | Inspect state, catalog, manifest, staging, orphans, and link/reparse hazards | At most 512 samples per category plus total/truncated; `--deep` computes managed-file inventory |
| `maintenance diagnostics <SESSION>` | Create a bounded, create-new diagnostic bundle | <=1 MiB; does not copy request/policy/raw payload; only states artifact-root path redaction |
| `maintenance schema [SESSION]` | List supported and observed schemas | No in-place migration; a future major requires a new Session |
| `maintenance retention plan` | Produce an immutable quarantine plan for an explicitly complete Session | Must be complete/deep-healthy and have no intent, staging, orphan, unsafe, or truncation condition |
| `maintenance retention apply` | Confirm the entire plan SHA-256 again and move it to quarantine | Does not purge; repeated apply continues idempotently |
| `maintenance retention restore` | Restore one Session from a plan's quarantine | Does not overwrite an active Session |
| `maintenance abandon plan <SESSION>` | Produce a whole-Session inventory plan for an abnormally exited, incomplete Session | Rejects complete, pending-Controller, live-lock, unsafe, or truncated trees; includes staging/orphan/intent |
| `maintenance abandon apply` | Move the entire failed Session to abandon quarantine using plan SHA-256 | Does not delete individual files; repeated apply is idempotent |
| `maintenance abandon restore` | Fully restore a Session from abandon quarantine | Does not overwrite an active Session; revalidates every ordinary file |
| `doctor` | Inspect artifact root, adapter registry, and executable | Currently always returns 20 because hardware probing belongs to an external control plane |

Run `t32perf <COMMAND> --help` for complete options. Real TRACE32 is not a hidden `capture --provider` option; integration steps are in the [Real TRACE32 integration runbook](trace32-runbook.md).

### Generic TRACE32 PC-sampling workflow

Use this path when TRACE32 can debug a running core but no qualified ETM, MTB, ITM, SNOOPer,
target package, or Controller adapter is available. It produces aggregate PC-hit statistics, not
an execution trace, coverage, WCET, call count, or per-call timing.

Create one exact Host authorization first. The request must contain every acquisition field
explicitly; include the optional deployment digest only for function attribution:

```json
{
  "schema": "t32perf.sampling-capture-request/v1",
  "ranges": [{"start_address": 4096, "end_address": 8192}],
  "bucket_size": 32,
  "duration_ms": 1000,
  "method_policy": "realtime_only",
  "core_id": 0,
  "address_space": "P",
  "deployed_firmware_elf_sha256": "<64-lowercase-hex>"
}
```

Omit `deployed_firmware_elf_sha256` for an address-only workflow. Including it is an operator or
deployment assertion that the target was prepared from that exact ELF; it prevents choosing a new
symbol file after capture but does not read back, compare, or independently verify target memory.

```text
t32perf --artifact-root <ROOT> --json sampling prepare <SESSION> --capture-request <JSON>
```

Pass `result.sampling_capture_arguments` unchanged to the sidecar's `sampling_capture` MCP tool.
The operation ID is the one-use capability: the sidecar validates it, the immutable request, the
Created Session, and the Session lock before opening TRACE32. The deployment must use a dedicated
PowerView Remote API on loopback TCP; stop the general interactive MCP client for that endpoint.
First run a capabilities-only sidecar without an endpoint pin, record its reported probe and
endpoint fingerprints, then stop it. Restart the capture-capable sidecar with
`--expected-endpoint-fingerprint <DIGEST>`. Without that pin capture is disabled before RCL;
with a mismatched pin it stops after read-only identity queries and before journal recovery or
`PERF` mutation. The endpoint digest binds TRACE32 software and a hash of the observed debug-module
serial, cable serial, and debug port without exposing the raw serial values.
The target must already be powered, running, and non-halted. `realtime_only` never falls back to
StopAndGo. `allow_stop_and_go` permits TRACE32's intrusive periodic halt/resume only when realtime
PC snooping is unavailable.

`sampling_capabilities.code_labels` reports whether TRACE32 has a loaded program symbol table.
During capture the sidecar uses bounded branch-and-bound `PERF.PC.HITS()` queries against the same
stopped result buffer to prove the highest-hit interval of at most four bytes in each of at most ten
highest-hit coarse buckets, then queries `sYmbol.FUNCTION`, `sYmbol.SOURCEFILE`, and
`sYmbol.SOURCELINE`. A successful address SVG displays the function, source basename and line, and
`dominant_hits/bucket_hits`. An incomplete proof or missing/unreadable symbols do not fail capture;
the affected row remains an address. These labels are `debugger_reported`, not proof that the symbols match target
Flash.

The sidecar is not a PowerView launcher. Start the approved `t32marm` process and its Remote API
before this workflow; target bring-up, firmware loading, and `Go` remain explicit laboratory
operations. For hardware qualification, copy `hil/boards/sampling-only.example.toml`, pin the exact
endpoint/software/CPU/request identities, set `T32PERF_SAMPLING_HIL_BOARD`, and run
`uv --directory hil run pytest -q -m hardware tests/test_sampling_hardware.py`. That entry uses the
real two-tool MCP stdio bridge and succeeds only for a persisted PASS receipt; it does not require a
chip-specific target-adapter profile. PASS independently hashes the Session request/state, exact
four-entry artifact catalog, histogram, address heatmap, and SVG. It records an observed probe
endpoint class but keeps `target_id_observed=false`; it is not a unique target-board identity claim.

After a successful MCP result, pass its exact `artifact.relative_path` to the Host:

```text
t32perf --artifact-root <ROOT> --json sampling ingest <SESSION> --staged <RELATIVE_PATH>
t32perf --artifact-root <ROOT> --json sampling analyze <SESSION> --histogram-artifact sampling-pc-hit-histogram --projection address
t32perf --artifact-root <ROOT> --json sampling summary <SESSION> --projection address --top 10
t32perf --artifact-root <ROOT> --json sampling render <SESSION> --projection address --max-rows 25
```

For function ranking, place the asserted ELF in the Session staging directory, bind it, then use
the fixed returned artifact IDs. Version 1 accepts this mapping only when TRACE32 reports a
Cortex-M CPU and the executable is a little-endian ARM ELF32 image:

```text
t32perf --artifact-root <ROOT> --json sampling bind-firmware <SESSION> --staged firmware.elf
t32perf --artifact-root <ROOT> --json sampling analyze <SESSION> --histogram-artifact sampling-pc-hit-histogram --projection function --elf-artifact firmware-elf --firmware-evidence-artifact sampling-firmware-binding-evidence
t32perf --artifact-root <ROOT> --json sampling summary <SESSION> --projection function --top 10
t32perf --artifact-root <ROOT> --json sampling render <SESSION> --projection function --max-rows 25
```

The Host accepts only the journal-bound sidecar bytes and persists the request/operation/endpoint
receipt. The default quantitative floor is 100 in-scope hits, 100 ms observed duration, no snoop
failures, and at least 90% retained runtime for StopAndGo. A zero-hit bucket means only "not
observed during this window." Function projection additionally requires the exact registered ELF
and Host-reserved firmware-binding evidence. The generic path is labelled `deployment_asserted`,
proves only that the ELF digest was precommitted, and reports `target_image_compared=false`; omit
that assertion when it cannot be made honestly, leaving the result address-only.

### Intrusive stack flame graph

Use this path only when stopping and restarting the target is acceptable. It is useful on a
Cortex-M0+ without MTB or ETM, but it perturbs timing, watchdog servicing, and communications.
Load the matching ELF/symbols in TRACE32 before capture when function names are required; otherwise
the graph remains address-only. The PC `sampling flame` result is a flat profile with synthetic
hierarchy, whereas this command sequence records real debugger frame walks.

```text
t32perf --artifact-root <ROOT> --json stack prepare <SESSION> --capture-request <REQUEST_JSON>
# Pass result.stack_sampling_capture_arguments unchanged to stack_sampling_capture.
t32perf --artifact-root <ROOT> --json stack ingest <SESSION> --staged <RELATIVE_PATH>
t32perf --artifact-root <ROOT> --json stack analyze <SESSION> --stack-samples-artifact sampling-stack-samples
t32perf --artifact-root <ROOT> --json stack summary <SESSION> --top 10
t32perf --artifact-root <ROOT> --json stack render <SESSION> --max-depth 64
```

`<REQUEST_JSON>` must use `t32perf.stack-capture-request/v1` and include exact
`acknowledge_intrusive: true`, `sample_period_ms`, `duration_ms`, `max_samples`, `max_frames`,
`core_id`, and `address_space`. Bounds are 10..=1000 ms, 100..=60000 ms, 1..=512, and 1..=8;
version 1 fixes `core_id` to 0 and verifies `CORE.NUMBER()=1` plus `CORE()=0` before capture.
The standalone sidecar accepts only the prepared Session ID, operation ID, and unchanged request
fields, and requires an endpoint pin. It journals every target mutation and attempts `Go` during
cancel/error cleanup. If recovery cannot prove the state, treat the endpoint as quarantined and
do not replay the capture manually. Run the one-shot recovery entry point with a fresh explicit
authorization; it verifies the endpoint/core, recovers only an unmatched sidecar-owned Break,
reports the final state, and exits without starting another capture:

Capture also requires the exact clean TRACE32 `ERROR` object
`{"occurred":false,"id":""}` before and after it. A sidecar may reset only a confirmed
frame-walk `#emu_noframe` after its matching `Go`, then must reread ERROR as clean. Any other,
unknown, or pre-existing error remains untouched and fails closed. A HIL PASS binds both independent
clean capability responses.

```powershell
lauterbach-stack-sampling-mcp --host localhost --port 20001 --protocol TCP --timeout 10 `
  --artifact-root <ROOT> --expected-endpoint-fingerprint <SHA256> `
  --recover-quarantined --recover-only
```

The authorization is consumed before the attempt. A failed attempt requires a new process
invocation. The result reports TRACE32's `ERROR` state but recovery never clears it; inspect and
handle that state separately. Never use this command to resume a stop that is not backed by the
sidecar journal.

Each bar width is the number of observed halt-cycle samples. It is not CPU time, duration, call
count, or coverage. `terminal_unverified`, `halt_deadline`, and other truncated boundaries are
shown rather than filled with guessed callers. Symbol queries occur only after the matching `Go`;
without the deployed matching ELF the graph honestly remains address-only. Rendering retains up
to 128 real visible frame nodes and uses an explicit `[other observed paths]` marker for bounded,
count-conserving aggregation. For targets with qualified program-flow trace, TRACE32
`Trace.FlameGraph` is the higher-fidelity alternative.

### t32mcp Controller transactions

The real driver's deployment configuration is fixed at:

```text
<ROOT>/.t32perf-control/deployment/t32mcp-driver.json
```

It must conform to `t32perf.t32mcp-driver-config/v1` in the [schema catalog](schema-catalog.md); the CLI cannot supply an alternative path. The following is a release template without workload/fault hooks. Resolve `expected_bundle_sha256` from `skill-trace32-perf/scripts/adapters/tc234l-build190766/bundle-manifest.json` in the exact installed release:

```json
{
  "schema": "t32perf.t32mcp-driver-config/v1",
  "executable": "E:/approved/t32mcp/t32mcp.exe",
  "expected_executable_sha256": "31f4983a4e7a60a5025e8334e95e6ecb4bd242ce6bc9705f81cdf081af05dec2",
  "skills_root": "E:/approved/t32perf-release",
  "trace32_port": 20000,
  "expected_t32mcp_version": "0.2.2",
  "expected_bundle_sha256": "<CURRENT_RUNTIME_BUNDLE_SHA256>",
  "poll_interval_ms": 100,
  "operation_timeout_ms": 60000,
  "max_stderr_bytes": 65536,
  "fault_actions": {}
}
```

The example t32mcp SHA-256 applies to the Windows candidate built and verified from official-mirror v0.2.2 source for this release; it is not a universal digest for every v0.2.2 build. An administrator must reapprove the exact SHA after changing toolchain, target, or binary. `skills_root` points to the read-only release root containing `skill-trace32-perf`. The driver requires the manifest to contain only permitted runtime inputs as strictly sorted, portable-unique members and recomputes each SHA-256. Documentation and agent metadata are not manifest members. The canonical bundle digest must match the config, manifest, installed `profile.json` `implementation_sha256`, and compiled candidate constant.

### One-command admitted production workflow

`perf_run` is the eighth public Host façade operation. It creates or resumes one strict
performance-run Session and composes:

```text
Provision → Controller capture → Normalize → Attest → Analyze → Convert → Complete
```

The deployment administrator must first add the closed `performance_run` block to the fixed
driver configuration. That block supplies the maximum duration, approved firmware, fixed
workload command, qualification and HIL receipts, capture trust policy, idempotent signer, and
optional build resources by absolute path and exact SHA-256. The caller can supply only duration,
an optional Session ID, and the bounded Top-N count:

The block is necessary but not sufficient. The administrator must also install these plain,
no-follow, ACL-protected read-only files outside all Sessions:

```text
<ROOT>/.t32perf-control/deployment/target-adapter-qualification-trust-store.json
<ROOT>/.t32perf-control/deployment/target-adapter-policies/<POLICY_ID>.json
```

The first file follows `t32perf.target-adapter-qualification-trust-store/v1`; its sorted unique
entry binds `POLICY_ID` to the exact SHA-256 of the second file. The policy follows
`t32perf.target-adapter-qualification-policy/v1`. The `performance_run.qualification.policy_id`
must resolve through that trust store and equal the policy document's own `policy_id`. The policy
constraints then validate the qualification receipt, adapter profile, and HIL binding. Session
evidence is not an enrollment API, and `perf_run` cannot create or modify either deployment file.

`performance_run.workload_command` is not the optional top-level `workload`. Its argument list
must contain `{initial_target_state}`, `{workload_identity}`, and `{duration_ns}` exactly once.
Its `timeout_ms` must be strictly greater than `ceil(max_duration_ns / 1_000_000)` milliseconds.
The top-level `workload` forbids `{duration_ns}` and cannot be reused unchanged in this block.
These cross-field rules are enforced by runtime configuration validation, not by JSON Schema.

```text
t32perf --artifact-root ROOT --json perf_run --duration-ms 5000 --id RUN_ID --top 10
```

Use the same ID, duration, and Top-N value to resume an interrupted run. A conflicting request is
rejected. An ambiguous external side effect is not replayed, and a failed Session is not mutated;
recover the endpoint or target as directed, then start a new Session. The command is unavailable
when the deployment lacks a complete admitted `performance_run` configuration. No caller-supplied
path, executable, policy, key, receipt, signer, workload, or resource can enter this workflow.

Optional `workload` and `fault_actions.trace32_disconnect_at_stop` use the same `DriverCommand`: an absolute `executable`, that executable's own `expected_executable_sha256`, at most 16 separate `arguments`, and `timeout_ms`. The driver passes argv directly without a shell. Closed placeholders are `{artifact_root}`, `{session_id}`, `{transaction_id}`, and `{binding_sha256}`. A workload may additionally use and must include `{initial_target_state}` and `{workload_identity}`. The TRACE32 disconnect hook must include `{transaction_id}` and `{binding_sha256}`. Each placeholder is permitted at most once; shell metacharacters, unknown placeholders, and missing required placeholders are rejected.

Hook structure example. Replace both `<..._SHA256>` values with the 64-character lowercase SHA-256 of their respective executable; neither may reuse the t32mcp or bundle digest:

```json
{
  "workload": {
    "executable": "E:/approved/hooks/run-workload.exe",
    "expected_executable_sha256": "<WORKLOAD_EXECUTABLE_SHA256>",
    "arguments": [
      "--root", "{artifact_root}",
      "--session", "{session_id}",
      "--transaction", "{transaction_id}",
      "--binding", "{binding_sha256}",
      "--initial-state", "{initial_target_state}",
      "--workload", "{workload_identity}"
    ],
    "timeout_ms": 30000
  },
  "fault_actions": {
    "trace32_disconnect_at_stop": {
      "executable": "E:/approved/hooks/disconnect-trace32.exe",
      "expected_executable_sha256": "<TRACE32_DISCONNECT_EXECUTABLE_SHA256>",
      "arguments": [
        "--root", "{artifact_root}",
        "--session", "{session_id}",
        "--transaction", "{transaction_id}",
        "--binding", "{binding_sha256}"
      ],
      "timeout_ms": 10000
    }
  }
}
```

Hook stdout must be empty. Stderr is bounded by `max_stderr_bytes`, and each hook timeout is additionally constrained by the driver's overall `operation_timeout_ms` deadline. A timeout, stderr overflow, nonzero exit, or read failure terminates the entire process tree. Windows uses a Job Object and Unix a process group; both enable kill-on-drop. Hook stderr is only bounded diagnostics, not evidence that a workload completed or a fault occurred.

After installation, run the safe preflight first:

```text
t32perf --artifact-root ROOT --json controller driver-preflight
```

It validates the fixed config/binary/bundle, exact `t32mcp v0.2.2`, MCP initialization identity, tool capabilities, and the complete paged `tools/list` inventory, then shuts down. The inventory must contain exactly `execute_practice_skill`, `collect_practice_skill_response`, and `abort_practice_skill`; hidden `execute_practice`, extra, missing, or duplicate entries are rejected. The command invokes no practice tool and explicitly reports `tools_invoked=false`. Because upstream creates the RCL only in the tool handler, preflight does not connect TRACE32 and is not endpoint or on-board evidence.

The public entry points for real TRACE32 are the exact machine façade:

```text
t32perf --artifact-root ROOT --json perf_capabilities SESSION
t32perf --artifact-root ROOT --json perf_capture SESSION
```

### Host MCP service

An MCP client must start the `mcp` stdio mode of the same approved binary with the deployment's
fixed artifact root and limits. The service exposes only `perf_capabilities`, `perf_capture`,
`perf_get_status`, `perf_get_summary`, `perf_list_artifacts`, `perf_convert`, `perf_compare`,
and `perf_run`. `perf_run` is the preferred tool to begin a new admitted production Session; its
MCP input must contain a portable, stable `session_id` selected by the caller, so that the same
Session can be queried after a lost response or connection.

Codex can register this local service with the following command. A production deployment must
replace `t32perf` and `ROOT` with the absolute path to a verified binary and an ACL-protected
artifact root:

```text
codex mcp add t32perf -- t32perf --artifact-root ROOT mcp
```

Tool calls return only bounded structured results or structured tool-level errors. The service
provides no MCP resources or prompts, and returns artifact references rather than trace or other
large artifact bytes. A raw JSON line has a 1 MiB wire limit and a typed result envelope a
256 KiB limit; duplicate structured/text JSON wire representations are also constrained by the
1 MiB frame limit. The server drives Controller work for `perf_capabilities` and
`perf_capture`, consuming upstream execute/collect/workload handoffs without exposing these
low-level actions to the client. A terminal payload can contain a high-level Host `next_action`,
such as calling `perf_capture`.

Each tool's output schema describes only its own operation and structured error. Input
ranges/lengths are validated again by the server at runtime, and an encoded JSON-RPC request ID
must not exceed 128 bytes. An oversized or truncated frame makes the service fail closed before
any Host dispatch. Public errors and failed Session status do not return absolute paths, hook
stderr, or arbitrary diagnostic details; MCP-mode stderr likewise records only stable
code/exit/retryable values. Inspect the complete reason through durable operator evidence or an
explicit manual CLI path.

Cancellation is not rollback. A cancelled call can continue until the Controller records a
durable boundary; call `perf_get_status` and follow its durable state before retrying. This
service is only a software interface, not evidence of a connected TRACE32 instance, probe,
target, firmware, or HIL environment. Install the independent `skills/t32perf-mcp` user skill
for client guidance; it does not change the hash-bound `skill-trace32-perf` PRACTICE skill.

For automatic execution by the built-in driver, use:

```text
t32perf --artifact-root ROOT --json controller drive SESSION --surface capabilities
t32perf --artifact-root ROOT --json controller drive SESSION --surface capture --mode raw_ascii
```

`drive` reuses one managed stdio child and automatically executes, collects, and accepts along the typed `next_action`, running the fixed workload hook between Start and Stop. `--mode` is allowed only with `--surface capture` and is passed to the façade only once the durable phase reaches Export. The command acquires the root-wide OS lease before reading configuration. After the initial verified client spawn, it establishes the `operation_timeout_ms` budget; later polling, MCP calls, workload/fault hooks, and any permitted single replacement spawn plus abort share that deadline. The surface loop has a separate hard limit of 128 iterations.

The execution lease is fixed at:

```text
<ROOT>/.t32perf-control/controller/trace32-driver-execution.lock
```

It uses both an OS-exclusive file lock and a same-process registry. From full config reload/reverification onward, it covers version/init/tool inventory, execute/collect/abort, workload/fault hooks, response acceptance, abort confirmation, post-Cleanup capture-config materialization, and child cleanup. External `perf_capabilities`, `perf_capture`, firmware/qualification/scenario provisioning, `controller prepare/accept/abort/confirm-abort`, and recovery mutations for the same root use the same exclusion boundary. Read-only queries such as `controller status` do not present themselves as execution owners. The lease file must remain an empty ordinary file; a symlink/reparse point or a lease held by another process fails closed.

Before and after one-shot side effects, the driver records strict append-only artifacts conforming to `t32perf.controller-driver-event/v1` in the [schema catalog](schema-catalog.md). They use reserved kind `controller_driver_event`, producer `t32perf-controller-driver-journal/v1`, and path `logs/controller/driver-events/<TRANSACTION>/...json`. Every event binds the exact request artifact ID/SHA-256, complete Controller binding, and operation; abort/fault/workload events also bind their closed context.

| Event | Durable meaning | Restart behavior |
|---|---|---|
| `dispatch_intent` | Immutable request selected and about to execute upstream | Do not execute again or blindly collect; enter durable abort/quarantine recovery |
| `fault_intent` | One-shot fault action selected | Without `fault_triggered`, the side effect is indeterminate: do not rerun the fault or perform an unproven abort |
| `fault_triggered` | One-shot fault returned success and binds a durable abort plan | Continue the proven abort lifecycle; do not repeat the fault |
| `abort_attempt` | About to call ownership-free official abort/END | Without `abort_success_observed`, the result is ambiguous; do not repeat abort/END |
| `abort_success_observed` | Host observed official abort success | Retry only Host confirmation; never call abort/END again |
| `workload_intent` | Fixed workload for an accepted Start is about to run | Without `workload_complete`, do not rerun the hook; return ambiguous |
| `workload_complete` | Workload hook returned successfully | Resume the capture façade with `--workload-complete` and continue to Stop |

These events are a Host intent/observation journal; they do not replace an accepted Controller response, machine evidence, or confirmed abort receipt. An existing event is reused idempotently only when its document, artifact envelope, and provenance exactly match the retry. Any conflict or indeterminate window fails closed.

The `result` response is a `t32perf.perf-surface/v1` tagged union. `perf_capabilities`/`perf_capture` payloads contain the durable phase, completed operation, bounded artifact references, and exactly one `next_action`: `execute`, `collect`, `run_workload`, `invoke`, or `capture_config_ready`. For `run_workload`, the driver writes `workload_intent`, writes `workload_complete` after hook success, then resumes with `perf_capture SESSION --workload-complete`. It must not automatically jump from accepted Start to Stop or rerun a workload from an intent alone. After the full accepted chain, the TC234L Controller automatically materializes authoritative configuration and returns `capture_config_ready`; it does not accept a second configuration manually registered by an adapter.

The following low-level commands are for diagnostics or façade implementation, not the skill's preferred entry points:

```text
t32perf --artifact-root ROOT --json controller prepare SESSION --operation perf_get_capabilities
```

Execute only the exact execute call returned. If it returns a strict pending wrapper, use the collect call until a final wrapper is obtained. These external low-level mutations also acquire the root-wide driver execution lease, so they cannot run concurrently with the built-in driver. Write the final string unchanged to the response handoff path; calling the same `perf_*` façade again accepts it automatically. The low-level equivalent command is:

```text
t32perf --artifact-root ROOT --json controller accept SESSION TRANSACTION
```

The deployment driver's low-level equivalent entry point is:

```text
t32perf --artifact-root ROOT --json controller drive-transaction SESSION TRANSACTION
```

Every raw JSON line on the official stdio transport is limited to 1 MiB. Execute/collect accept one text block of at most 64 KiB; abort accepts only empty success. A Controller-frame JSON payload is additionally limited to 4 KiB per line. Pending grammar begins with `<NOT FINISHED>` on line one and `<CONTENT>` on line two; `<CONTENT>` occurs exactly once and subsequent partial content cannot contain a `<NOT FINISHED>` or `<FINISHED>` status header. Partial content may be empty or bounded progress text; it is not final evidence. Every other bounded tool response—including malformed pending headers/frames, unknown status/code, and binding mismatch—is first written unchanged to the immutable request's response staging path, then authoritatively rejected by Host `controller accept`. The driver neither treats a malformed final response as a reason to collect nor loses rejection evidence.

For each invocation, Controller rebuilds the capture phase from immutable artifacts and the driver journal, accepting only `perf_get_capabilities → perf_configure → perf_start → perf_stop → perf_get_health → perf_export → perf_cleanup`. Accepted Start and Stop are the only transitions `created → capturing → captured`; a new Session cannot export directly and a completed phase cannot be prepared again. Retry `accept` idempotently for its original transaction only when a response is staged. With `dispatch_intent` but no staged response, the driver neither re-executes nor guesses whether to collect; it performs durable abort/quarantine recovery. `controller status` reports `capture_phase`, `next_required_operation`, and the pending operation; do not delete the journal to force previous behavior.

`perf_export` additionally requires `--mode raw_ascii` or `--mode task_events_elf_orti_verified`. Controller-assigned paths support ordinary spaces but reject injection-relevant characters. Control success also requires operation-specific `t32perf.controller-*-evidence/v1`, at most 1 MiB and exactly bound to the operation and `binding_sha256`; arbitrary JSON is not accepted. Trace export consumes the Session file quota. The CLI returns only artifact references, never inline evidence claims. Hotspots are allowed only after the main chain completes, and Cleanup concludes it. An accepted Cleanup response does not release the root execution lease early: Host still idempotently materializes authoritative `capture-config` under that lease and the namespace/session lock. On materialization failure, it does not return `capture_config_ready`; restart can recover exactly from accepted Cleanup without rerunning CMM.

If collect/transport cannot complete, use the two-step abort:

```text
t32perf --artifact-root ROOT --json controller abort SESSION TRANSACTION --reason timeout
# Execute the returned abort_practice_skill in the same trusted single-tenant t32mcp instance.
t32perf --artifact-root ROOT --json controller confirm-abort SESSION TRANSACTION --acknowledge-unbound-success
```

The first command only creates a plan. Upstream abort has neither transaction ownership nor a bound acknowledgement, so the root slot and owner-Session mutation gate remain active until confirmation.

The real driver can perform both steps in one trusted flow:

```text
t32perf --artifact-root ROOT --json controller abort-upstream SESSION TRANSACTION --reason timeout
```

It first validates the existing immutable transaction and writes the plan idempotently. Without a durable attempt, the driver writes `abort_attempt` before calling official `abort_practice_skill`/END; after tool success it writes `abort_success_observed` and immediately performs Host confirmation. Confirmation does not wait for child shutdown, and a later shutdown failure cannot erase observed abort success. On restart, `abort_attempt` without a success marker means the upstream result is ambiguous, so the driver does not call abort/END again; with `abort_success_observed`, it retries only Host confirmation and does not start a second upstream abort.

Fault scenarios have closed execution boundaries:

- `trace32_disconnect_at_stop` persists `fault_intent` and an abort plan at the Stop-operation boundary, then runs the configured direct-argv TRACE32 disconnect hook instead of the normal Stop script. On hook success it writes `fault_triggered`, then completes official abort/confirm in the original child. A crash window without durable completion for the hook or abort never repeats the one-shot side effect; in particular, without a success marker after `abort_attempt`, it must not switch children and retry END.
- `driver_disconnect_at_export` has no external hook. The driver first calls the exact `execute_practice_skill` in the Export-owning child. A final response does not trigger disconnect: stage the original response and pass it to Host acceptance, which authoritatively determines a missed fault or another rejection. Only a strict pending wrapper meeting the unique-header rule permits `fault_intent`, an abort plan, and forcing the exact child tree. After successful force it writes `fault_triggered`, fully reloads/reverifies fixed-path config, t32mcp executable, every compiled endpoint bundle, selected target bundle, and tool inventory, then starts exactly one replacement solely for durable official abort/confirm.
- `cmm_abort_at_start` persists fault/dispatch intent before execute and accepts only CMM's exact bounded marker. After observing that marker it creates the plan, writes `fault_triggered`, performs official abort, and confirms immediately after success.

No permitted replacement reuses a cached deployment decision. Within the remaining overall deadline, it fully reloads the fixed config and revalidates binary SHA/version, all endpoint-reachable skill manifests/profiles/compiled digests, selected target binding, and exact MCP inventory.

The driver always attempts to terminate its child/process tree. If shutdown or forced cleanup fails, the CLI explicitly returns `CONTROLLER_DRIVER_CLEANUP_FAILED` and retains the primary error plus `durable_host_state_preserved=true` in details. Registered responses, journals, abort receipts, endpoint/target quarantine, and capture-config ingest intent are never deleted or rolled back due to cleanup error. Operations must isolate and audit that root first, and must not infer that no Host mutation occurred.

Analysis writes versioned `analysis-summary` and `analysis-stage` documents indexed in the [schema catalog](schema-catalog.md). The stage receipt binds complete input/output artifact metadata, tool, analyzer, health-policy/schema contracts, metric support, and diagnostic counts. A `DEGRADED`/`INVALID` summary contains no quantitative payload and writes no hotspots, static-RAM, or stack-usage artifact; diagnostic derived/health/Perfetto paths remain usable.

The operations control plane is fixed at `<artifact-root>/.t32perf-control`. The smallest retention unit is a whole Session, and apply only performs a same-volume quarantine rename; permanent purge remains the responsibility of the deployment system after an independent backup, approval, and exact path validation. Each plan entry binds the exact `state.json` digest and a canonical path/size/SHA-256 inventory of every regular Session control and artifact file. Apply and restore hold the namespace lease across the active root → quarantine root transition and revalidate the inventory, so same-size state tampering, zero-byte orphans, and concurrent Session creation all fail closed. An existing journal that is truncated, corrupt, or mismatched is also rejected before the rename. The full Compare result is stored in the control plane as well, not written into a completed Session.

Diagnostics do not copy the request body, capture trust policy, or raw artifact payload. `artifact_root_paths_redacted` covers only native and forward-slash variants of the canonical artifact root; it does not mean that every absolute path is redacted. Review bounded error text before disclosure. The built-in atomic publication and retry contract covers process crashes. On Unix, rename synchronizes the source and destination parent directories; Windows does not guarantee write-through or power-loss durability.

If a command fails and its durable failure state also cannot be written, it returns `STATE_PERSISTENCE_FAILED`. Automation must preserve both the original and persistence errors and stop writing to that root.

`session ingest` uses `ingest-intents/<artifact-id>.json` between the rename and catalog operations. After a process crash, a retry with the exact same staged path, ID, kind, destination, media type, producer, and input IDs can recover a `pending`, `resumable`, or `committed_stale` state. `maintenance inspect` lists the classification. A parameter or digest mismatch is a `conflict`; do not delete the intent, destination, or catalog to force a retry.

If recovery encounters a quota or retryable I/O problem, the CLI returns `INGEST_RECOVERY_REQUIRED` and retains the `created` or `capturing` state instead of recording a terminal failure. After correcting the external cause, reuse the exact same parameters; changing the specification fails closed and records `INGEST_FAILED`.

## External input, normalization, and attestation

External input has three distinct stages:

1. `t32perf.capture-config/v1` authoritatively records the actual capture configuration.
2. `normalize` proves only that bytes were converted successfully to canonical observations under explicit configuration.
3. `session attest` validates a signed adapter's claims about the Session, request, observation/config digests, and hardware.

Successful normalization does not make a capture trusted. JSON self-description, a producer string, and a user request cannot replace attestation.

### Create an import Session

```text
t32perf --artifact-root ./artifacts --json session create --id import-001 --request '{"provider":"external"}'
```

Write the capture config, raw input, and normalization config to `artifacts/import-001/capture/staging`, then register them:

```text
t32perf --artifact-root ./artifacts --json session ingest import-001 --staged capture-config.json --id capture-config --kind capture_config --destination capture/capture-config.json --media-type application/json --producer lab-controller
t32perf --artifact-root ./artifacts --json session ingest import-001 --staged input.csv --id raw-input --kind raw_trace --destination capture/raw/input.csv --media-type text/csv --producer lab-controller
t32perf --artifact-root ./artifacts --json session ingest import-001 --staged normalize.json --id normalize-config --kind normalization_config --destination capture/raw/normalize.json --media-type application/json --producer lab-controller
t32perf --artifact-root ./artifacts --json normalize import-001 --input-artifact raw-input --config-artifact normalize-config
```

The capture config schema is fixed at `t32perf.capture-config/v1` in the [schema catalog](schema-catalog.md) and rejects unknown fields. At minimum, it records the Session, provider, adapter and version, mode, covered cores, sink kind/ID/capacity/stream destination identity, timestamp enablement and clock, bounded filters, trigger, duration or record limit, workload identity, initial target state, RTOS-awareness kind and metadata artifact IDs, and bounded adapter parameters. The RTOS metadata IDs must exactly match the config artifact's `input_artifact_ids`. Host does not infer these fields from TRACE32 text.

If custom events are available on the target, the capture config must also include typed `instrumentation`: a versioned method, transport, baseline duration, duration with instrumentation enabled, positive event count, and immutable measurement artifact ID. The measurement artifact uses `kind=instrumentation_overhead` and `application/json`, and appears with the RTOS metadata in the capture-config artifact's `input_artifact_ids` in the exact config order. The manifest and `summary.result.capture.instrumentation` preserve the same contract. For real Sessions whose custom-event support is `exact` or `statistical`, HIL enforces the presence of this field, the measurement values, artifact kind/hash/provenance, and config/manifest consistency.

The normalization config is limited to 1 MiB, uses the fixed `t32perf.normalize-config/v1` contract in the [schema catalog](schema-catalog.md), and rejects unknown fields. It supports `single_source` and `multi_source`:

| Adapter | Input | Key requirements |
|---|---|---|
| `canonical_ndjson_v1` | Existing canonical NDJSON | The input header's Session ID must equal the target Session |
| `explicit_csv_v1` | CSV with an explicit header and column mapping | Must map the timestamp, source sequence, event type, and fields required by each event |
| `c_wire_v1` | C SDK 32-byte wire records | `wire_version=1`, with explicit core, clock, origin, and payload/record limits; may reference a capture-bound counter mapping source |
| `trace32_snooper_ascii_v1` | Accepted Controller raw ASCII export | Config references only the fixed profile and `firmware-elf`; Host derives the symbol mapping after controller/capture/qualification validation |
| `trace32_task_events_v1` | Accepted TASKEVENTS export | References only the fixed profile, firmware ELF, and deployment-owned mapping artifact; ORTI/marker/health/time-origin/qualification evidence must be closed |

The optional `counter_mapping_artifact_id` for `c_wire_v1` refers to a closed
`t32perf.c-wire-counter-mapping/v1` document. The mapping contains `counters` and,
when referenced by Task/ISR stack counters, the required `contexts`. Each context
maps a numeric wire `wire_context_id` to a stable dictionary `context_id`, `name`,
a closed `task` or `isr` kind, and optional `core_id` and `priority`. Before reading
begins, Host generates `DefineContext` and `DefineCounter` entries for the same
dictionary and rejects missing, duplicate, incorrectly typed, or source-core-
inconsistent contexts. A Task/ISR stack counter's wire `context_id` must also equal
the mapped `wire_context_id`. Without a counter mapping, generic C SDK counters
retain their existing compatibility behavior.

A minimal `Instant` CSV config follows:

```json
{
  "schema": "t32perf.normalize-config/v1",
  "mode": "single_source",
  "source": {
    "adapter": "explicit_csv_v1",
    "source_id": "lab-export",
    "columns": [
      {"field": "timestamp_ticks", "column": "ticks"},
      {"field": "source_sequence", "column": "seq"},
      {"field": "event_type", "column": "type"},
      {"field": "name", "column": "name"}
    ],
    "ignored_columns": [],
    "clock": {
      "domain_id": "trace",
      "frequency_hz": {"numerator": 100000000, "denominator": 1}
    },
    "origin": {"mode": "first_record", "session_ns": 0},
    "quality": "exact",
    "limits": {
      "max_line_bytes": 1048576,
      "max_records": 1000000,
      "max_dictionary_entries": 65536,
      "max_dictionary_bytes": 67108864
    }
  },
  "output_limits": {
    "max_line_bytes": 1048576,
    "max_records": 1000010,
    "max_dictionary_entries": 65536,
    "max_dictionary_bytes": 67108864
  }
}
```

Dictionary fields can be omitted to use the defaults above. Config limits are 16 MiB per line, 1,000,000,000 records, 1,048,576 dictionary entries, and 1 GiB of physical dictionary bytes. Zero and out-of-range values are rejected before input is read.

TRACE32 ASCII config carries no function ranges or any "verified" Boolean:

```json
{
  "schema": "t32perf.normalize-config/v1",
  "mode": "single_source",
  "source": {
    "adapter": "trace32_snooper_ascii_v1",
    "source_id": "tc234l-snooper",
    "expected_profile_id": "t32perf.trace32-ascii-profile/tc234l-build190766-v1",
    "firmware_elf_artifact_id": "firmware-elf",
    "limits": {"max_line_bytes": 1048576, "max_records": 10000000}
  },
  "output_limits": {"max_line_bytes": 1048576, "max_records": 10000010}
}
```

Host requires input that is identical to the accepted controller export artifact and verifies the authoritative capture-config's profile, ELF ID/SHA, clock, and ZERO contract. It then derives `[start,end)` ranges automatically from the executable ELF, registers a reserved `trace32-symbol-mapping` artifact, and records capabilities, HealthV2, StopV2, the raw export, and the actual qualification receipt in provenance. A candidate profile without a current qualification receipt returns exit 20. A digest alone, an inline JSON mapping, or ordinary ingest cannot bypass this gate. See the [TRACE32 text export format contract](trace32-export-formats.md) for the full format and evidence boundary.

The `counter_mapping_artifact_id` for `c_wire_v1` is optional. When omitted, it produces only a generic identity of the form `counter:<event_id>`, and the dictionary carries no resource semantic or subject. If the authoritative capture-config declares a mapping, omitting the reference fails. When enabled, capture-config must record `instrumentation.method=t32perf-c-wire/v1` and exactly bind the registered `c_wire_counter_mapping_source` JSON through `c_wire.counter_mapping_artifact_id` and `c_wire.counter_mapping_sha256`. After strict parsing, Host creates a reserved, content-addressed `c_wire_counter_mapping` artifact whose provenance always includes the mapping source and capture-config, then invokes the mapped source. An unknown Counter event ID fails at the original wire-record position. Multiple sources that share the same mapping exactly reuse the same derived artifact.

The `sources` array for `multi_source` must contain 2..64 distinct `input_artifact_id` values. Each entry contains a complete adapter config, the declared normalized `clock_domain`, and the fixed `order = reject_ambiguous_ties`. Every actual source descriptor must match its declared clock domain, and the K-way merge combines only sorted streams. If records at the same timestamp do not have a unique explicit order key for every participating source, normalization fails closed. A canonical source uses the `session` clock domain, and the canonical format carries no cross-source order key, so canonical sources must avoid timestamp ties. Omit `--input-artifact` when invoking multi-source normalization:

```json
{
  "schema": "t32perf.normalize-config/v1",
  "mode": "multi_source",
  "sources": [
    {
      "input_artifact_id": "core0",
      "clock_domain": "session",
      "order": "reject_ambiguous_ties",
      "source": {
        "adapter": "canonical_ndjson_v1",
        "source_id": "core0-channel",
        "limits": {"max_line_bytes": 1048576, "max_records": 1000000}
      }
    },
    {
      "input_artifact_id": "core1",
      "clock_domain": "session",
      "order": "reject_ambiguous_ties",
      "source": {
        "adapter": "canonical_ndjson_v1",
        "source_id": "core1-channel",
        "limits": {"max_line_bytes": 1048576, "max_records": 1000000}
      }
    }
  ],
  "output_limits": {"max_line_bytes": 1048576, "max_records": 2000010}
}
```

```text
t32perf --artifact-root ./artifacts --json normalize import-001 --config-artifact normalize-config
```

Multi-source dictionaries merge by context, function, and counter namespace. Identical definitions with the same ID are retained once; any conflicting definition or post-merge semantic conflict is rejected. Output provenance first contains all raw inputs, the normalization config, and the authoritative capture config. Sources that require additional trust material then append deduplicated mapping, ELF, controller evidence, and qualification artifact IDs.

Frequency represents `numerator / denominator` Hz. Optional `clock.wrap` requires `modulus` and `max_forward_ticks`. Origin can instead be `{"mode":"explicit","ticks":...,"session_ns":...}`. CSV mapping does not infer vendor columns; a real TRACE32 format must have a fixed mapping verified by fixtures and HIL.

CSV `event_type` uses the fixed snake_case values `function_enter`, `function_exit`, `context_switch`, `interrupt_enter`, `interrupt_exit`, `sample`, `instant`, `span_begin`, `span_end`, `async_begin`, `async_end`, `counter`, `trace_gap`, and `metadata`. The strict adapter validates the required mapping for each event type.

Normalize writes `normalized/observations.ndjson`, and the Session remains `captured` after success. A failure records `NORMALIZE_FAILED` and sets the Session to `failed`. Because artifacts are immutable, retry with a new Session.

### Validate an external capture attestation

The external signer constructs the `t32perf.capture-attestation/v1` payload from these Host-owned values:

- `state.operation_id` returned by `session status`, used as the nonce;
- immutable `request.json` SHA-256;
- the ID and SHA-256 of `observations` from `artifacts list`;
- the `capture-config` artifact ID, exact SHA-256, and configuration SHA-256 with the Session ID excluded;
- for a Controller capture, the ID/SHA-256 of the accepted `controller-health-evidence/v1` artifact and the receipt `health_observations` deterministically generated from its adverse facts;
- the complete capture receipt and trust-policy `key_id`.

The signer uses an Ed25519 private key to sign the payload's deterministic compact JSON bytes. T32Perf neither generates nor stores private keys. The attestation and deployment trust-policy schemas are:

- `schemas/v1/capture-attestation.schema.json`
- `schemas/v1/capture-trust-policy.schema.json`

Write the signed attestation to the Session's `capture/staging` directory, then run:

```text
t32perf --artifact-root ./artifacts --json session attest import-001 --staged capture-attestation.json --policy ./capture-trust-policy.json
```

Here, `--policy` is a deployment-administrator or Host Controller parameter, not ordinary user input. A Service or MCP must select the policy from a fixed allowlist and must not pass through a client-supplied path, public key, or inline JSON. Otherwise, the client can create its own key and policy and self-sign, which provides no authenticity.

The policy must be an ACL-protected regular file, cannot be a symlink or reparse point, and is limited to 1 MiB. Each key fixes the public key, producer, provider, adapter ID/version, allowed modes, target, TRACE32 identity, clocks, allowed cores, and capability ceiling. It can also constrain sink kind/ID, initial target state, RTOS awareness, timestamp, sink capacity, and exact configuration digest.

Validation binds the Session ID, operation nonce, request digest, observation ID/digest, capture-config artifact ID/exact digest/configuration digest, and, when present, the Controller health artifact ID/digest. It also requires exact agreement among the payload, receipt, catalog, and config document. A Controller health source's signed observation set must correspond exactly to the typed evidence before it enters the analyzer health gate. Config, mode, target, TRACE32, clock, core, or capability claims outside the key scope are rejected. The receipt must also contain a firmware ELF digest or a nonempty build ID. Legacy v1 JSON without the optional config claim can be parsed but cannot pass trusted external analysis.

Success adds:

```text
capture/capture-attestation.json
capture/capture-config.json
capture/capture-trust-policy.json
capture/capture-receipt.json
```

The attestation is first registered under an untrusted producer, and the policy is stored as a deployment snapshot. Only after both the signature and scope pass does Host write the capture receipt under the producer from the policy key. Ordinary `session ingest` preserves these IDs, kinds, paths, and producers and cannot impersonate them. An attestation failure is terminal; do not retry with a different policy in the same Session.

For complete key operations and the TRACE32 transaction, see the [security model](security.md) and the [real TRACE32 integration runbook](trace32-runbook.md).

## Resource input

Analysis can optionally consume one `kind=linker_map` or `kind=firmware_elf` static-RAM source, one `kind=static_ram_config` artifact, and one `kind=stack_usage` artifact. `--static-ram-flavor` must explicitly select `gnu-ld-map-v1` or `elf-sections-v1`; the format is not inferred from the extension, magic bytes, or content. If the option is omitted, the compatible default `gnu-ld-map-v1` remains in effect. The legacy `--linker-map-flavor` option is still supported, and both options must match when supplied together. A `static_ram_config` is valid only when a source for the selected flavor is also present. An external process can only write files to the Session's `capture/staging` directory before the CLI ingests them.

PowerShell example:

```powershell
$Root = Join-Path $PWD 'artifacts'
$Session = 'resource-demo-001'

.\t32perf.exe --artifact-root $Root --json capture --provider synthetic --id $Session --events 1024
Copy-Item -LiteralPath .\firmware.map -Destination (Join-Path $Root "$Session\capture\staging\firmware.map")
Copy-Item -LiteralPath .\firmware.su -Destination (Join-Path $Root "$Session\capture\staging\firmware.su")
Copy-Item -LiteralPath .\static-ram-config.json -Destination (Join-Path $Root "$Session\capture\staging\static-ram-config.json")

.\t32perf.exe --artifact-root $Root --json session ingest $Session --staged firmware.map --id input-linker-map --kind linker_map --destination capture/raw/firmware.map --media-type text/plain --producer firmware-build
.\t32perf.exe --artifact-root $Root --json session ingest $Session --staged static-ram-config.json --id input-static-ram-config --kind static_ram_config --destination capture/raw/static-ram-config.json --media-type application/json --producer firmware-build
.\t32perf.exe --artifact-root $Root --json session ingest $Session --staged firmware.su --id input-stack-usage --kind stack_usage --destination capture/raw/firmware.su --media-type text/plain --producer firmware-build
.\t32perf.exe --artifact-root $Root --json analyze $Session --static-ram-flavor gnu-ld-map-v1 --stack-usage-flavor gcc-stack-usage-v1
```

For the ELF path, register the firmware ELF as `kind=firmware_elf` with media type `application/x-elf`, change the config's `flavor` to `elf-sections-v1`, then run:

```powershell
Copy-Item -LiteralPath .\firmware.elf -Destination (Join-Path $Root "$Session\capture\staging\firmware.elf")
.\t32perf.exe --artifact-root $Root --json session ingest $Session --staged firmware.elf --id input-firmware-elf --kind firmware_elf --destination capture/raw/firmware.elf --media-type application/x-elf --producer firmware-build
.\t32perf.exe --artifact-root $Root --json analyze $Session --static-ram-flavor elf-sections-v1 --stack-usage-flavor gcc-stack-usage-v1
```

Example `static-ram-config.json`:

```json
{
  "schema": "t32perf.static-ram-config/v1",
  "flavor": "gnu-ld-map-v1",
  "additional_sections": [
    {"name": ".dma_buffers", "kind": "dma"},
    {"name": ".rtos_objects", "kind": "rtos"},
    {"name": ".project_cache", "kind": "custom"}
  ]
}
```

The current CLI resource contract is:

- `gnu-ld-map-v1` summarizes only unindented top-level `.data`, `.bss`, and `.noinit` output sections; addresses and sizes must be unsigned decimal or `0x` hexadecimal values;
- `elf-sections-v1` accepts only ELF relocatable or executable objects and explicitly supported Arm/AArch64/RISC-V 32/64 architectures or the ELF32 little-endian Siemens TriCore architecture (`e_machine=44`); the `sh_offset/sh_size` payload range is validated for each selected non-NOBITS section; any other format, object kind, architecture, corrupt section table or payload range, or input larger than 256 MiB or 65,536 sections fails closed;
- ELF analysis includes only exact-name `.data`, `.bss`, `.noinit`, and configured sections that also have `SHF_ALLOC|SHF_WRITE`; a selected section that lacks either flag, a duplicate name, an address range overflow, or a checked-total overflow causes analysis to fail; arbitrary writable sections are not classified automatically;
- `static_ram_config` is limited to 1 MiB and 4,096 entries; it only adds exact section names and explicitly classifies each as DMA, RTOS, or custom; wildcards, regular expressions, substrings, duplicate entries, and reclassification of `.data`, `.bss`, or `.noinit` are rejected;
- `gcc-stack-usage-v1` accepts tab-separated GCC `.su` records in the form `location<TAB>bytes<TAB>qualifier`; the qualifier must be `static`, `dynamic`, or `dynamic,bounded`;
- a stack-usage report retains at most 100,000 functions and 64 MiB of file/function text; each field is limited to 4,096 UTF-8 bytes, and artifact lines must increase strictly;
- multiple artifacts of the same kind are rejected, and an unknown flavor returns 20;
- `analysis/static-ram.json` and `analysis/stack-usage.json` are produced only when health is `VALID`; the static summary records the config artifact/digest and checked data/bss/noinit/dma/rtos/custom totals, the ELF report additionally records the architecture, class, endianness, and object kind, and analysis-stage references only the source and config actually consumed;
- the formal report schemas are `schemas/v1/static-ram-report.schema.json` and `schemas/v1/stack-usage-report.schema.json`, indexed in the [schema catalog](schema-catalog.md).

### Runtime resource counters

A counter producer must declare `semantic` and `subject` together in `DefineCounter`. Legacy input without them remains readable, but only as a generic counter; `heap`, `stack`, or `ram` in an ID or name does not trigger classification. Standard subjects distinguish allocators, Task/ISR/MSP/PSP/custom stacks, memory regions, and trace buffers.

Standard byte and count values must be nonnegative integers `<= 2^53`; ratios must be in `[0, 1]`. Analyzer checks monotonic and high-watermark behavior, stable capacity, `current <= peak <= capacity`, and related invariants. It derives allocation rate only from a positive-duration window without a reset, and fragmentation only from `free_bytes` and `largest_free_block_bytes` for the same allocator at the same timestamp. When evidence is missing, the result is `unavailable`; Analyzer does not infer it from IDs, names, or adjacent samples.

Runtime stack peak, compiler `.su` static frame, call depth, and linker MAP static RAM are distinct metrics. Do not add them together, and do not add independent Task/ISR/MSP/PSP peaks into a system peak.

`session ingest` cannot impersonate an internal producer. A real-capture receipt cannot gain trust through ordinary ingest; only `session attest`, after trust-policy validation, can write it.

## Bounded summaries

```text
t32perf --artifact-root ./artifacts --json summary quickstart-001 --top 20
```

`summary` is a read-only CLI view and does not add an artifact. The default Top N is 10, with an allowed range of 1..100. It always returns:

- the Session ID and requested Top N;
- `quantitative_available`;
- the health verdict, policy version, bounded issue list, and complete metric-support summary;
- analysis artifact references.

Only `VALID` adds `quantitative`, which contains bounded function and sampling hotspots, execution contexts, resource counters, call depth, and counts. Resource counters are divided into `heaps`, Task/ISR/MSP/PSP/custom `stacks`, `memory_regions`, `trace_buffers`, and `generic`; each group applies `--top` independently, and values with different units are not ranked together. Static RAM and compiler stack usage remain separate fields. `DEGRADED` and `INVALID` return only diagnostics and artifact references without exposing the ordinary quantitative summary; their exit codes are 10 and 11, respectively. At most 64 issues are returned, each support entry contains at most 8 reasons, text fields are also truncated, and truncation is marked explicitly. Read limits are 1 MiB for stage, 16 MiB for health, and 64 MiB each for hotspots and analysis summary. Exceeding a limit is an operational error; the full large file is not placed in an MCP or CLI response.

## Comparison policy

`default` and `strict` are currently identical: they use a 5% relative threshold and require exact metrics, the same request digest, the same provider/capture mode/adapter ID and version, identical nonempty covered cores, the same capture capabilities, the same health-policy and tool contracts, and complete target/clock/firmware provenance. They do not compare statistical sampling metrics.

Strict also provides lower-is-better resource rules for heap current/latest, heap peak/max, stack peak/max, memory-region peak/max, and external fragmentation/latest. Allocation/free count, allocation rate, largest allocation, capacity, and trace-buffer usage produce informational rows by default and do not affect the verdict. When the config digest and support are comparable, Static RAM compares total and data/bss/noinit/dma/rtos/custom independently; it does not generate a synthetic peak.

The default policy allows the baseline and candidate to have different but complete firmware identities, which is normal for cross-build regression analysis, but it still requires the same request digest. If the capture request itself embeds the firmware identity, set `require_matching_request=false` after review or use `relaxed`. To require the same image, explicitly set `require_same_firmware_identity=true`. The default also prohibits function-set changes. An added or removed function makes the comparison `inconclusive` unless `allow_function_set_changes=true` is set explicitly, in which case the missing side participates in comparison with a zero value.

`relaxed` uses a 10% relative threshold, permits different request digests when both are present, and permits matching non-`unavailable` support levels and statistical metrics. It still requires complete provenance, identical provider/mode/adapter/target/clock/covered cores/capabilities, the same adapter version, and the same health-policy and tool contracts, and it prohibits function-set changes by default. Like strict, it permits different firmware identities.

```text
t32perf --artifact-root ./artifacts --json compare baseline-001 candidate-001 --policy strict
t32perf --artifact-root ./artifacts --json compare baseline-001 candidate-001 --policy relaxed
t32perf --artifact-root ./artifacts --json compare baseline-001 candidate-001 --policy ./policy.json
t32perf --artifact-root ./artifacts --json compare baseline-001 candidate-001 --policy strict --allow-inconclusive
```

The first three commands treat `inconclusive` as a blocking result and return 13. Use `--allow-inconclusive` only after the caller has reviewed `report.reasons` and explicitly accepts that no comparison conclusion can be reached. This option only changes the exit code for `inconclusive` to 0; it does not change the verdict or allow `regressed`.

You can also provide inline JSON. For auditability, explicitly specify every field:

```json
{
  "relative_threshold": 0.05,
  "absolute_time_threshold_ns": 1000,
  "absolute_count_threshold": 1,
  "require_exact_metrics": true,
  "require_matching_request": true,
  "require_same_adapter_version": true,
  "require_same_firmware_identity": false,
  "require_same_health_policy_version": true,
  "require_same_tool_contract": true,
  "allow_function_set_changes": false,
  "resource_rules": [
    {
      "semantic": "heap.current_allocated_bytes",
      "aggregate": "latest",
      "direction": "lower_is_better",
      "absolute_threshold": 0,
      "relative_threshold": 0.05
    }
  ],
  "allow_resource_subject_set_changes": false,
  "compare_statistical_metrics": false,
  "require_complete_provenance": true
}
```

Compatibility defaults are `require_same_firmware_identity=false`, `require_same_health_policy_version=true`, `require_same_tool_contract=true`, `allow_function_set_changes=false`, `resource_rules=[]`, `allow_resource_subject_set_changes=false`, and `require_complete_provenance=true`. All other fields must be present. A metric without a resource rule is informational only. By default, a change in the subject set for a configured rule makes the comparison `inconclusive`. Resource identity is `(semantic, subject)`, so renaming a counter ID does not affect matching; changing the identity for the same ID causes comparison to be rejected.

The policy file is limited to 64 KiB and must be a regular file; symlinks and Windows reparse points are rejected. Unknown fields, NaN, Infinity, and negative relative thresholds are rejected.

The Compare verdict is `improved`, `unchanged`, `regressed`, or `inconclusive`. `improved` and `unchanged` return 0, `regressed` returns 12, and `inconclusive` returns 13 by default. When `--allow-inconclusive` is provided explicitly, only `inconclusive` changes to return 0. JSON `result.inconclusive_allowed` records whether the option was enabled; automation must still inspect `result.verdict` and `report.reasons`.

The full result is written to `.t32perf-control/comparisons/<SHA256>.json` as `t32perf.comparison-artifact/v1`. The envelope preserves the exact validated policy, policy SHA-256, both canonical manifest digests, the analysis-stage/health/hotspots/analysis-summary artifact digests, and the complete `t32perf.comparison/v1` report. The filename and `result.report_artifact.sha256` are bound to the file bytes. Rerunning with the same inputs and policy returns the same path and marks `publication` as `existing`. Compare does not modify a `complete` Session.

The `result.report` on stdout is a bounded projection: the capture verdict and health, at most 32 capture-wide reasons, and at most `--top` rows per category (default 20, range 1..100), prioritized as regressed → inconclusive → improved → unchanged/informational. Each category has `*_total_count`, `*_returned_count`, and `*_truncated`; `outcome_counts` preserves the complete counts. Nested lists and text have separate limits, and a row carries `projection_truncated` when projection truncation occurs. The authoritative full content can only be read from `report_artifact` after size/SHA-256 validation.

Comparison independently limits stage to 1 MiB, health to 16 MiB, and hotspots and analysis-summary to 64 MiB each. Each side can contain at most 10,000 hotspot subjects and 10,000 resource subjects; the complete report is limited to 100,000 rows and the control artifact to 64 MiB. Exceeding a limit returns explicit `UNSUPPORTED`; Comparison does not fall back to unbounded memory or place the full data on stdout.

Both `session list` and `artifacts list` return `total_count`, `returned_count`, `limit`, `after`, `truncated`, and `next_after`. A cursor is a stable, exclusive portable ID; pass it back unchanged through `--after` to continue pagination. An artifact row inlines at most 16 provenance input IDs and describes truncation through `input_artifact_ids_total_count`, `input_artifact_ids_returned_count`, and `input_artifact_ids_truncated`; the catalog and manifest remain authoritative for the complete DAG. The artifact catalog itself is limited to 16,384 entries, and an artifact-root scan accepts at most 100,000 directory entries. It fails closed above that limit to prevent unbounded root enumeration.

## Exit codes

| Exit code | Stable meaning | Typical commands |
|---:|---|---|
| 0 | Operation succeeded, health is `VALID`, comparison is `improved`/`unchanged`, or `inconclusive` was explicitly allowed | Most commands; `compare --allow-inconclusive` |
| 10 | Health is `DEGRADED` | `analyze`, `convert`, `validate` |
| 11 | Health is `INVALID` | `analyze`, `convert`, `validate` |
| 12 | Comparison verdict is `regressed` | `compare` |
| 13 | Comparison verdict is `inconclusive` and was not explicitly allowed | `compare` |
| 20 | Feature unsupported or health not yet evaluated | `doctor`, unsupported provider/format/flavor, `validate` before analysis |
| 1 | Parameter, I/O, state, integrity, or other operational error | Any command |

`DEGRADED` and `INVALID` can be successfully completed analysis results, so top-level JSON can contain `"ok": true`. `doctor` also emits `"ok": true` before returning 20. Interpret the structured result, not one Boolean value.
