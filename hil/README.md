# HIL harness

HIL tests select real boards through board TOML and enforce probe exclusivity with a cross-platform file lock. Driver commands are argv arrays; the harness never executes a shell string.

## Generic PC sampling

Boards may opt into generic sampling HIL with `[sampling] capture_request` and
its exact SHA-256 plus an independent `host.sampling_evidence_root`. The
request must be a strict `t32perf.sampling-capture-request/v1` document. The
`sampling_capabilities` wrapper reports the sidecar's actual
`target.powered/running/halted`, `pcsnoop`, and `supported_methods`; a powered-
down, unknown, halted, or non-running target produces an immutable `NOT_READY`
receipt and never invokes `sampling_capture`.
The closed wrapper order is `sampling_prepare`, `sampling_capabilities`,
`sampling_capture`, `sampling_ingest`, `sampling_analyze`, then
`sampling_summary` and `sampling_render`; capture uses the prepare-issued exact
operation and sidecar arguments. Host wrappers return the unmodified T32Perf
`ok/command/result` envelope; sidecar wrappers return the exact MCP result.
Capabilities also report `code_labels`. If PowerView has symbols loaded, the histogram may contain
up to ten `debugger_reported` dominant code locations. HIL verifies their parent buckets, hit
counts, order, four-byte refinement, bounded basenames, unchanged `unverified` firmware status,
exact propagation into address heatmap cells, canonical SVG labels, and XML escaping. Missing
symbols remain a valid address-only capture.
A PASS remains `diagnostic_only=true`: it is statistical sampling evidence,
never a trusted analysis-stage claim. This is generic infrastructure, not
hardware evidence for any named MCU.
Before PASS, HIL independently re-reads the completed Host Session through
no-follow, single-link stable snapshots: request/state plus the exact
four-artifact sampling DAG and each artifact's bytes, hash, size, media type,
producer, and direct inputs. A wrapper JSON result alone cannot establish PASS.
The receipt records an observed probe digest plus configured endpoint-class
identity (`mcu_family` and configured `probe_id`), never raw probe serials.
The target ID remains unobserved, so PASS must not be interpreted as a unique
physical-board identity.

Generic sampling has an independent board contract and does not require a
target-adapter profile or fault manifest. Copy
`boards/sampling-only.example.toml` into the private laboratory configuration,
replace every placeholder, and select it with `T32PERF_SAMPLING_HIL_BOARD`.
The configured argv bridge invokes the real two-tool sampling MCP over stdio;
it does not route capture through the TC234L adapter or the official three-tool
`t32mcp` process.

```powershell
$env:T32PERF_SAMPLING_HIL_BOARD = 'E:\lab\sampling-target.toml'
uv --directory hil run pytest -q -m hardware tests/test_sampling_hardware.py
```

The hardware gate succeeds only for a `PASS` receipt. `NOT_READY` and `FAIL`
receipts are retained but fail the test. PowerView lifecycle and the target
workload remain laboratory responsibilities: neither the sampling MCP nor the
HIL bridge launches `t32marm`, issues `SYStem.Up`, loads firmware, or sends
`Go`.

The capture request is deployment-owned. It must declare sorted, non-overlapping
program-address ranges and a bucket size appropriate to the admitted firmware image.
Do not copy a memory window from another target or infer it from the processor core.
An address-only request contains no deployed-ELF assertion and cannot prove that a
target is running any particular firmware.

## Intrusive stack flame graph

`T32PERF_STACK_HIL_BOARD` selects an independent, opt-in stack HIL profile.
It drives only the closed `prepare → capabilities → capture → capabilities → ingest → analyze
→ summary → render` wrapper chain. The second capabilities call independently verifies the same
endpoint/single-core identity and final running state before ingest. Capture requires the request's explicit
`acknowledge_intrusive=true`; every sample is a TRACE32 `Break`, frame walk,
and `Go` cycle, with at most eight frames. A PASS binds the exact capture receipt, raw
`stack-samples/v1`, folded root-to-leaf profile, and depth-64 SVG. Width is a sample count only:
neither CPU time, duration, nor call count. The outer unwind boundary remains
unverified. The `[host]` configuration pins `t32perf_bin` through a mandatory
`t32perf_sha256`: it is read through a bounded (64 MiB), final-component no-follow
descriptor and rechecked before every wrapper phase, so every PASS, FAIL, and NOT_READY receipt
records the exact Host executable digest. The remaining rehash-to-spawn race is a
laboratory deployment boundary: keep the Host build directory read-only to the HIL
account and enforce it with filesystem ACLs. A non-ready target writes a `NOT_READY` receipt and must not create
raw/profile/flame artifacts.

## Test tiers

Hardware-free tests validate the harness's failure decisions, evidence chain, and filesystem boundary:

```text
uv run --project hil pytest hil/tests -m "not hardware"
```

With no board configured, the complete suite may still run: every `hardware` test explicitly skips and never generates or fabricates hardware results.

```text
uv run --project hil pytest hil/tests
```

Run one-board hardware tests with `T32PERF_HIL_BOARD`:

```text
T32PERF_HIL_BOARD=/lab/boards/board-a.toml uv run --project hil pytest hil/tests -m hardware
```

Use `T32PERF_HIL_BOARDS` for the two-board, two-mode evidence matrix. Separate paths with the platform path separator (`;` on Windows, `:` on POSIX):

```text
T32PERF_HIL_BOARDS=/lab/boards/board-a.toml:/lab/boards/board-b.toml T32PERF_HIL_EVIDENCE_OUTPUT=/lab/evidence/run-id.json uv run --project hil pytest hil/tests/test_hardware_contract.py::test_two_board_two_mode_evidence_matrix
```

`T32PERF_HIL_EVIDENCE_OUTPUT` must name a nonexistent file. The harness writes it with exclusive create and `fsync`, and refuses to overwrite evidence.

## Driver process contract

A normal command exits zero and emits exactly one JSON object on stdout; diagnostics go to stderr. The harness continuously drains both streams but retains and accepts no more than 1 MiB each, preventing an uncontrolled driver from exhausting host memory through output. Duplicate keys in driver output or in any Session JSON/NDJSON artifact are rejected; first-wins and last-wins semantics are forbidden. A capture result's `session_id` is only a reference to validate. Driver-reported health, issues, mode, initial state, and recovery state are not conclusions.

Fault-injection commands have distinct contracts:

- `sampling_buffer_full_capture` may run only when the adapter manifest labels `sampling_buffer_full` `candidate` or `qualified`; it creates an `INVALID` Session whose only conclusion is `sampling_buffer_full`. `candidate` still collects HIL evidence and does not upgrade admission.
- `trace32_disconnect_capture` disconnects TRACE32 during capture and exits non-zero.
- `driver_disconnect_capture` disconnects or terminates the board driver during capture and exits non-zero; stdout may be empty or truncated.
- `cmm_abort_capture` aborts CMM before Session publication and exits non-zero.

Each board pins its `t32perf.trace32-fault-scenarios/v1` manifest through `trace32.fault_scenarios` and exact-byte SHA-256 `trace32.fault_scenarios_sha256`. Health/injection scenarios are explicitly `candidate`, `qualified`, or `unsupported`; only the first two expand `<scenario>_capture`. The three recovery scenarios—`trace32_disconnect`, `driver_disconnect`, and `cmm_abort`—have independent fixed fields, prohibit `support`, and are authorized by the fixed recovery contract rather than default qualification. An unsupported health/injection scenario must include a reason, configure no command with the same name, and be explicitly rejected by HIL tests. It is not an implicit “missing command, therefore skip” capability. The TC234L SNOOPer profile currently declares `trace_overflow`, `flow_error`, and `elf_mismatch` unsupported; they must not trigger board commands.

`trace32.target_adapter_profile` and `target_adapter_profile_file_sha256` likewise pin raw profile bytes through a single bounded final-component-no-follow read. Its `adapter_id`, TRACE32 release/build gate, architecture, fault manifest, and board configuration must agree exactly. After a successful `sampling_buffer_full` `INVALID` Session, the harness exclusive-creates `verification-receipt.json` under the recovery-evidence root, binding fault-manifest SHA-256, adapter ID, canonical-profile SHA-256, profile-file SHA-256, and bundle/implementation SHA-256.

Before every fault the harness invokes `prepare_recovery_fault`. The driver returns strict `t32perf.target-adapter-failure-binding/v1`, recording the real Controller's prepared transaction profile SHA-256, controller binding, failed operation, failure kind, and initial target state. Preparation must not modify the artifact root or recovery-evidence root. The harness passes validated binding through `{binding_sha256}` and rejects any command template that ignores a caller-supplied placeholder.

The harness scans the artifact root and complete recovery-evidence root before and after invocation. Failure commands must not create, remove, or modify any entry. `recover` must restore the control path and exclusive-create one `t32perf.target-adapter-recovery-evidence/v1` document at `{recovery_evidence}` in the harness-reserved directory. `host.recovery_evidence_root` cannot equal, contain, or be contained by business `host.artifact_root`. The driver may create only the reserved single-link regular file: no sidecars, and no deletion, overwrite, or mutation of historical recovery evidence.

The recovery document strictly binds:

- The board-pinned canonical `target_adapter_profile_sha256`.
- The failed operation's controller `binding_sha256`, `failed_operation`, and closed `failure_kind`.
- `initial_target_state` and identical `restored_target_state`.
- `adapter_state_restored=true`, `files_deleted=false`, and `new_session_required=true`.
- For every target-quarantine recovery, canonical `upstream_abort_confirmed=true` and the actual host abort receipt `upstream_abort_receipt_sha256`; both are required, and false/null/unpaired receipts are rejected.
- For a selected SNOOPer sampling profile, `sampling`: `real_time` / `program_counter` / `stack` / `off`, `requested_rate_ns=1000000`, `capacity_records=65536`, `auto_arm=false`, `auto_init=false`, and `zero_reset=true`. The HIL schema and Python mirror validate this closed object; Rust `TargetAdapterRun::accept_recovery` finally decides whether it is required for the selected profile.

The harness rejects duplicate JSON keys, unknown fields, symlinks, hard links, overwritten evidence, incorrect or relabelled controller binding/profile/fault point/failure kind/state, and every fail-open Boolean. Ordinary `recover` stdout JSON proves only command completion. Recovery conclusions derive from the reserved file, whose original SHA-256 is reread before generating the verification receipt. The receipt embeds the full recovery document and its SHA-256, bringing all binding/profile/failure/state/restoration/no-deletion/new-Session/abort acknowledgement facts into the canonical receipt digest. The harness exclusive-creates and rereads `verification-receipt.json` in the same reservation; recovery evidence and receipt are retained permanently. A later, directly created `VALID` Session must close recovery without repair commands such as `set_running`/`set_halted`; a driver claim of `recovered=true` is insufficient.

Other commands:

- `doctor` returns `ok`, `board_id`, TRACE32 release/build, probe ID, architecture package, licence features, capability-evidence SHA-256, and exact trace routing. Every field must equal board configuration; unknown builds or mismatched evidence fail closed.
- `set_running` and `set_halted` set the initial target state for the next capture.
- `capture` accepts `{mode}`, `{initial_state}`, and `{run}`. A successful Session manifest independently records the same `capture.mode` and `capture.target.properties.initial_state`.
- `native_stats` performs complete capture and supplies TRACE32-native statistics for differential checking.

If an adapter declares `trace_overflow` or `flow_error` executable, they remain independent scenarios. Evidence containing both in a health artifact is rejected so buffer overflow and decoder stream errors cannot collapse into one unlocalizable conclusion. The TC234L SNOOPer profile declares both unsupported.

## Host-output preflight

Before touching a board, every hardware test:

1. Uses `shutil.disk_usage` to require free space at both artifact and recovery-evidence roots of at least `host.min_free_bytes`.
2. Separately creates, flushes, `fsync`s, and deletes a temporary probe file in both roots.

Hardware-free tests inject quota/full conditions and `PermissionError` through `OutputAccess`; permission-denial testing does not depend on POSIX `chmod`, so Windows and Linux share the contract. Tests do not fill disks with large files to simulate exhaustion.

## Independent Session validation

After every successful capture the harness independently runs:

```text
<host.t32perf_bin> --artifact-root <host.artifact_root> --json validate <session_id> --deep
```

It then reads `<artifact_root>/<session_id>/manifest.json` directly and validates the unique new Session directory; no capture may delete, reuse, or create extra Sessions. It verifies manifest schema; target board/MCU family/RTOS; TRACE32 release/build/probe/architecture package/licence/capability evidence/trace routing; capture-request hash; firmware identity; every artifact's canonical relative path, file kind, size, SHA-256, producer, and `input_artifact_ids` DAG; current-Session JSON `session_id`; absence of hard-linked artifact reuse; and manifest-derived mode/initial state rather than driver JSON.

When custom-event capability is `exact` or `statistical`, the manifest must record typed instrumentation method/transport, measured overhead, baseline/instrumented duration, positive event count, measurement artifact hash/kind, capture-config input provenance, and mutually consistent config/manifest contents. Hardware manifests must contain:

```text
capture.mode
capture.target.board
capture.target.properties.initial_state
capture.target.properties.mcu_family
capture.target.properties.rtos
capture.target.properties.trace_routing
capture.trace32.build
capture.trace32.probe
capture.trace32.architecture_package
capture.trace32.properties.release
capture.trace32.properties.license_features
capture.trace32.properties.capability_evidence_sha256
capture.request_sha256
```

and at least `firmware.elf_sha256` or non-empty `firmware.build_id`.

## Native differential

`trace32.tick_ns` must be positive. Time comparison uses:

```text
abs(t32perf_time_ns - native_time_ns) <= max(native_time_ns * 0.005, tick_ns)
```

Function count/total/self/min/max/average come from T32Perf hotspots. Total is `inclusive_active_ns`; min/max/average are per-activation active time; average uses integer division `inclusive_active_ns / count`. The harness independently rejects zero count, self greater than total, invalid min/average/max, and artifacts inconsistent with that integer mean. The same function across contexts combines counts and total/self sums, global min/max, and integer `total / count`. Task counts derive from `ContextSwitch` into the Task; ISR counts derive from `InterruptEnter`; their times derive from `analysis-summary.context_cpu.active_ns`. Function, Task, and ISR ID sets and counts must match exactly, each time field uses the tolerance above, and no statistics class may be empty.

`native_stats` returns normalized T32Perf dictionary IDs:

```json
{
  "session_id": "session-id",
  "statistics": {
    "functions": [{"id": "function-id", "count": 1, "total_time_ns": 1000, "self_time_ns": 600, "min_time_ns": 1000, "max_time_ns": 1000, "average_time_ns": 1000}],
    "tasks": [{"id": "task-id", "count": 1, "time_ns": 1000}],
    "isrs": [{"id": "isr-id", "count": 1, "time_ns": 1000}]
  }
}
```

## Two-board, two-mode evidence

`CaptureEvidenceMatrix` accepts only Sessions deeply verified by `SessionAudit`. Its default exit gate requires at least two distinct `board_id`, two distinct `mcu_family`, two capture modes, one non-empty RTOS identity, ten Sessions per board/mode, and both `running` and `halted` initial-state coverage per combination. Its `t32perf.hil-evidence/v1` output records each verified Session's manifest and health SHA-256. The structure schema is [`schemas/hil-evidence.schema.json`](schemas/hil-evidence.schema.json); the harness additionally enforces the MCU-family, RTOS, repetition, and initial-state gates that JSON Schema cannot express.

The production plan uses a stronger repeatability gate: ten Sessions for every board/mode/initial-state group. The current multi-board hardware test contributes five Sessions per initial state, so it is suitable for the present software contract but must be increased before its output can satisfy production qualification. The single-board repeatability test already runs ten Sessions per mode and initial state.

Production qualification also requires evidence for at least two exact TRACE32 versions. The current matrix records release/build in every capture but fixes it as part of one `board_id` identity. It cannot test another version on the same physical board without an identity conflict. A versioned HIL contract must add release/build and adapter profile as a separate coverage dimension while preserving physical board uniqueness. The current v1 matrix cannot satisfy this production gate.

The current v1 matrix also binds only the verified Session manifest and health digests. It does not bind a qualification receipt, admission snapshot, or signed capture attestation. The production evidence contract must reject pre-admission Sessions and accept only fresh managed `perf_run` Sessions after policy and receipt installation.

This structure proves only which verified artifacts the harness accepted. It does not claim that the repository has completed real hardware validation. Without laboratory input, the associated `hardware` tests remain skipped.

## Board configuration

```toml
[board]
id = "board-a"
mcu_family = "Cortex-M7"
covered_cores = [0]
capture_modes = ["etm", "sampling"]

[trace32]
release = "2026.02"
build = 183242
validated_builds = [183242]
probe_id = "lab-probe-asset-id"
architecture_package = "arm"
license_features = ["trace", "rtos-awareness"]
capability_evidence = "capability-evidence.json"
capability_evidence_sha256 = "<64-lowercase-hex>"
fault_scenarios = "../adapter/fault-scenarios.json"
fault_scenarios_sha256 = "<64-lowercase-hex>"
target_adapter_profile = "../adapter/profile.json"
target_adapter_profile_file_sha256 = "<64-lowercase-hex>"
trace_routing = ["ETM0->TPIU0:TRACECLK,TRACED0-3"]
tick_ns = 10.0

[host]
t32perf_bin = "../../target/release/t32perf.exe"
t32perf_sha256 = "<64-lowercase-hex>"
artifact_root = "../artifacts/board-a"
min_free_bytes = 4294967296
```

`capability_evidence`, `target_adapter_profile`, and `fault_scenarios` are plain files whose configured SHA-256 must equal their exact bytes. The profile build gate, release, architecture, and adapter ID must also agree with board and manifest. `target_adapter_profile_sha256` is the canonical identity created by Rust `TargetAdapterProfile` serde rules for that profile snapshot; it is not the file digest or a caller assertion. Repository `boards/example.toml` aligns with public TC234L build-190766 adapter files and their canonical digest, but probe and driver remain explicit placeholders and cannot run board tests directly. Copy it to a laboratory-private configuration directory and provide real paths and commands. Do not commit ELF, licence, probe identifiers, capability evidence, or firmware paths to the public repository.
