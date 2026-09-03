# Real TRACE32 Onboarding Runbook

## Scope and Current Gates

This runbook onboards one explicit MCU/SoC, probe, TRACE32 build, firmware, and RTOS combination into T32Perf. It is not a general process of trying TRACE32 commands until they work.

The repository has an explicit host trust entry point for normalization and Ed25519 attestation, complete control implementation for the TC234L SNOOPer candidate, and a real stdio deployment driver for official t32mcp 0.2.2. This round does not execute a production real capture:

- The CLI built-in capture provider is still synthetic only. An external target Controller produces real raw input, normalization configuration, and signed attestation.
- TC234L SNOOPer ASCII has a build-190766 fixed mapping, strict parser, executable CMM, ELF-to-S3 /DIFF provisioning, seven-stage Controller, automatic CaptureConfig, typed fault/recovery, and qualification admission. TASKEVENTS has strict parser/mapping contracts but requires an independent qualified program-flow/ELF/ORTI adapter.
- The root CMM dispatches only the exact admitted TC234L profile; an unknown target or mode fails closed.
- The public capture chain is capabilities → configure → start → stop → health → export → cleanup.
- The driver loads exact executable/bundle identity from fixed t32perf.t32mcp-driver-config/v1 and uses a root-wide OS lease and append-only event journal for crash-safe façade drive, single-transaction drive, upstream abort/confirm, and practice-tool-free preflight.

The discovered local combination is TRACE32 R.2026.02.000190766, TriCore TC234L/core 0, PowerDebug PRO, 30 MHz JTAG, and DUALPORT. The repository supplies its exact but unqualified SNOOPer PC statistical-sampling candidate, fixed ASCII profile, canonical S3 image, Data.LOAD.S3record /DIFF, fault scripts, real t32mcp driver, and complete cleanup. No practice tool, endpoint/on-board execution, or HIL qualification receipt has been used. The candidate is only for software closure, offline audit, and future evidence collection; it cannot be promoted to a production trusted capture.

> warning
> Until the adapter, receipt policy, and HIL gates in this runbook are complete, do not manually rewrite a raw export into a canonical observation and represent it as verified capability.

## Generic PC sampling without a target package or trace IP

The separate `lauterbach-sampling-mcp` path can qualify a coarse address hotspot view when TRACE32
can access a running core but ETM, MTB, ITM, SNOOPer, or a target-specific adapter is unavailable.
It uses `PERF.Mode PC` and aggregate `PERF.PC.HITS()` ranges. It does not enter the Controller
timeline, add tools to official t32mcp, or establish device identity from `CPU()` text.

Qualification still needs an explicit platform record: dedicated loopback PowerView port, probe,
core, firmware workload, exact executable address ranges, requested bucket size/window, selected
RealTime or explicitly intrusive StopAndGo method, and repeated board evidence. Use `sampling
prepare` to issue the one-use Session request/operation capability, pass its exact arguments to the
sidecar, then use Host `sampling ingest`, address `analyze`, and `render`. A power-down, unreadable,
halted, or non-running target produces `NOT_READY` HIL evidence and no histogram. A ready capture
below the quantitative policy is `FAIL`, not `NOT_READY`.

When PowerView already has program symbols loaded, the same two-tool sidecar automatically labels
the dominant code inside at most ten high-hit coarse buckets. It performs bounded branch-and-bound
partitioning with `PERF.PC.HITS()` against the same stopped sampling result and emits only a proven
highest-hit interval no wider than four bytes; an incomplete proof is omitted. It then resolves the
interval with `sYmbol.FUNCTION/SOURCEFILE/SOURCELINE`. The address heatmap shows the
function, source basename/line, and dominant-hit fraction. Symbol lookup failure degrades to an
address-only row. These runtime labels are explicitly debugger-reported and do not establish an
ELF digest or target-image identity.

The executable HIL path uses the independent
`hil/boards/sampling-only.example.toml` contract selected by
`T32PERF_SAMPLING_HIL_BOARD`. It pins the exact TRACE32 software string,
loopback endpoint fingerprint, expected CPU, request bytes, probe lock, output
roots, and seven closed argv operations. The bridge starts a sampling-only MCP
stdio child, checks the exact two-tool inventory, and never requires or accepts
a TC234L target-adapter profile. `hil/tests/test_sampling_hardware.py` generates
a unique Session and passes only for a persisted `PASS` receipt.

PowerView startup and workload control stay outside this sampling boundary. The
MCP connects to an already listening Remote API; it does not launch `t32marm`,
execute `SYStem.Up`, load an ELF, or send `Go`. A startup script that deliberately
halts the core must therefore be followed by the laboratory's approved workload
start before sampling capabilities can pass the running/non-halted gate.

Trusted function or source attribution requires an independently verified target-image comparison
or machine-verifiable digest-bound deployment evidence whose exact artifact and ELF digests are
checked again on replay. Neither the MCU's nominal 64 MHz clock nor generic Cortex-M0+
configuration proves that binding.

For chip-agnostic diagnostic function ranking, include `deployed_firmware_elf_sha256` in the
immutable sampling request before capture, then run `sampling bind-firmware` against that exact
staged ELF. The result is `deployment_asserted` / `PrecommittedElfAssertion` and explicitly says no
target-image comparison occurred. It prevents post-capture symbol selection but is not verified
firmware; only use it when the deployment assertion is meaningful. Version 1 additionally requires
TRACE32 to report Cortex-M and the executable to be little-endian ARM ELF32.

## Intrusive stack sampling when program-flow trace is absent

`lauterbach-stack-sampling-mcp` is separate from both official `t32mcp` and the aggregate PC
sampling sidecar. It has exactly `stack_sampling_capabilities` and `stack_sampling_capture`.
Before deployment, run capabilities-only, record the endpoint fingerprint, restart with the exact
pin, and load the matching ELF/symbols when method names are required. A CPU string, a PowerView
frame window, or an address outside the loaded symbol range is not symbol evidence; such frames
may remain unnamed.

The capture request requires `acknowledge_intrusive=true`; it bounds period to 10..=1000 ms,
duration to 100..=60000 ms, samples to 512, and frames to 8. Version 1 also requires one logical
core with core 0 selected. Each sample issues `Break`, walks `Frame.Up`/`Frame.Down`, then `Go`,
and polls `STATE.RUN()` to a bounded completion. Symbol-table queries run only after `Go`; RCL waits
are capped at 100 ms and the frame walk has a 1 s software deadline. This changes
target timing and can disturb watchdogs or links. Qualify the actual workload and recovery state;
do not use it for timing, watchdog, or communications-sensitive acceptance without explicit board
approval.

Before capture and after it, capabilities must report the exact clean TRACE32 `ERROR` state
`{"occurred":false,"id":""}`. The sidecar resets only a confirmed `#emu_noframe` raised by its
own frame walk, only after the matching `Go`, and verifies the clean state afterwards. Any other
error remains uncleared and fails the run. A hardware PASS binds both independent clean readings.

Deployment-specific stack HIL must bind the Host executable, request, endpoint identity, journal,
raw samples, folded profile, and rendered graph. It must also perform independent pre/post ERROR
and target-state checks. Break-to-Go measurements describe debugger-induced halt cycles, not target
execution time or a platform guarantee; unresolved outer frames remain `terminal_unverified`.
When program-flow trace is available, use TRACE32 `Trace.FlameGraph` instead; it has stronger
execution-flow evidence.

If cleanup is quarantined, do not issue an ad-hoc `Go`. Preserve the journal and run the one-shot
`lauterbach-stack-sampling-mcp ... --recover-quarantined --recover-only` command with the same
artifact root and endpoint pin. It exits after recovering only a journal-proven unmatched Break.
The result reports but does not reset the TRACE32 `ERROR` slot; inspect it separately.

## 1. Establish an Immutable Platform Identity

Assign each onboarding unit a stable Platform ID and record:

~~~text
TRACE32 release and build
architecture package and license features
probe model and serial-safe identifier
MCU/SoC, core type, core count and covered cores
board name and revision
trace method, source, sink and pin/connector routing
firmware ELF/MAP/image/build ID/SHA-256
RTOS and ORTI/ARTI inputs with SHA-256
compiler and stack-usage flavor
workload seed and termination condition
timestamp frequency, wrap rule and same-tick ordering rule
~~~

Start as UNVERIFIED. Do not infer support from a marketing name or another board's result. Update the [platform capability matrix](platform-capability-matrix.md) after acceptance.

## 2. Isolate the Control Plane

- Run TRACE32, t32mcp, and the T32Perf Controller on the same machine or an isolated laboratory network segment.
- Use a managed stdio child for the T32Perf driver. Do not expose or forward an unauthenticated t32mcp HTTP endpoint.
- Use each t32mcp instance as a single tenant.
- Each artifact root exclusively owns its single-tenant endpoint through fixed .t32perf-control/controller/trace32-driver-execution.lock; both the in-process registry and cross-process OS file lock apply.
- Only the Controller and the trusted capture process for this run may write the artifact root.
- Store licenses, ELF files, and private board configuration in the laboratory secret/artifact store, never the repository.

See [operations](operations.md) and the [security model](security.md).

## 3. Freeze TRACE32 Version Gates

When release/build is unknown, capabilities, configure, start, stop, health, and cleanup must remain UNSUPPORTED_NEEDS_TRACE32.

| Release/build | Effect |
|---|---|
| 2025/09 build 183242 | Multiple statistic/chart suffixes changed from names such as TASKINTR to newer names such as ISR. Select by build; do not probe by trial and error. |
| 2023/09 build 162904 | Trace.STATistic only displays fifo fulls and flow errors as distinct items from this build onward. Earlier or unknown builds cannot reuse this text health parser. |
| 2022/02 build 142441 | AREA.Create behavior for a same-named, already-open protocol file changed. Fixed scripts do not manage AREA lifetime. |

A public manual release is not the deployed instance's actual build. Bind every parser/command gate to real build evidence and a fixture.

Host selection uses t32perf.adapter-descriptor/v1. The descriptor fixes adapter ID, exact format identity, and zero or more verified compatibility tuples: exact TRACE32 release, nonzero inclusive build range, and exact architecture package. A request build must be nonzero; unknown installations cannot match using 0. The registry first performs strict structural validation; the Host private trust wrapper then selects exactly one available descriptor. No match, overlapping ambiguity, and untrusted descriptors are rejected. Bundle-catalog and selected-bundle cross-binding fix profile, bundle, deployment, and implementation identity to prevent cross-bundle mixing. The TC234L SNOOPer candidate covers only its fixed tuple; no TASKEVENTS flow adapter is registered as a capturable profile. Archive the raw fixture, mapping, HIL, and native-differential evidence before adding a tuple.

The descriptor is currently an in-process host API for a trusted Controller to select a registered adapter. It is not a Session artifact, MCP wire input, or untrusted-JSON configuration, and therefore has no independently checked-in JSON Schema. If it is later persisted or sent across processes, first promote it to a formal artifact/wire contract and include schema-drift and compatibility tests.

## 4. Implement a Target-Specific Adapter

The adapter must define this behavior with fixed code and versioned configuration:

| Capability | Frozen content |
|---|---|
| capabilities | trace method/sink, covered cores, RTOS awareness, timestamps, observable health fields |
| configure | target-specific commands, filter/trigger, buffer/streaming, initial-state handling |
| start/stop | running and halted initial states, timeouts, disconnects, idempotency, failure recovery |
| export | fixed mode, output extension, actual columns, time base, same-tick ordering |
| health | build-gated evidence mapping for overflow, flow error, gap, truncation, ELF mismatch |
| cleanup | revert only capture state changed by the adapter; never delete Session files |
| attestation | sign host Session/request/observation/config digests and capture claims with deployment Ed25519 key |

The adapter must produce or verify:

~~~text
trace32_release
trace32_build
target_identifier
probe_identifier
trace_method
trace_sink
covered_cores
configuration_verified
capture_stopped
elf_loaded
orti_loaded
arti_configured
~~~

Fields without evidence must be omitted or marked unavailable; a user declaration cannot promote them to exact.

## 5. Use the Fixed t32mcp Skill

The logical skill name is trace32-perf. Only the following scripts are allowed:

| Script | TC234L SNOOPer candidate behavior |
|---|---|
| perf_get_capabilities.cmm | fixed build/target/probe/sink capability evidence |
| perf_configure.cmm | canonical S3 Data.LOAD.S3record /DIFF and SNOOPer configuration evidence |
| perf_start.cmm | starts SNOOPer; cmm_abort aborts here with its typed action |
| perf_stop.cmm | normal stop evidence; trace32_disconnect does not run this first, but runs the deployment hook at the Stop boundary |
| perf_get_health.cmm | fixed health evidence; sampling_buffer_full has a separate scenario contract |
| perf_export.cmm | normal fixed SNOOPer ASCII export. driver_disconnect executes this Export request first. Only strict pending makes the driver disconnect its exact t32mcp child; final wrappers are staged for Host determination of a missed fault. TASKEVENTS is not admitted. |
| perf_get_hotspots.cmm | HOST_PROCESSING_REQUIRED |
| perf_cleanup.cmm | restores only fixed SNOOPer baseline; it never deletes Session files |

t32mcp calls use only official execute_practice_skill, collect_practice_skill_response, and two-phase abort_practice_skill. The real driver starts the official 0.2.2 child over stdio and requires complete tools/list inventory to contain exactly these three tools. Hidden execute_practice and any extra, missing, or duplicate tool are rejected. skill_name and script_name come from the typed controller prepare request, never user paths or arbitrary PRACTICE content.

Fixed driver configuration is <ROOT>/.t32perf-control/deployment/t32mcp-driver.json, with schema `t32perf.t32mcp-driver-config/v1` in the [schema catalog](schema-catalog.md). It binds the absolute official executable and SHA-256, read-only skills root, TRACE32 port, exact version 0.2.2, bundle digest, poll/operation/stderr bounds, and optional workload/TRACE32 disconnect hooks. The Windows candidate executable SHA-256 observed by the archived preflight is 31f4983a4e7a60a5025e8334e95e6ecb4bd242ce6bc9705f81cdf081af05dec2; it does not apply to another build, and that record paired it with historical adapter implementation feb46173441d2225b522a03cfae2486031fb72c6d8170baf374038848dcb2293. Before startup, the current driver verifies every runtime-manifest member and requires the config, manifest canonical digest, installed-profile implementation_sha256, and compiled candidate constant to agree. Read the exact current digest from the installed manifest and run a fresh preflight for that pairing.

The workload and trace32_disconnect_at_stop hooks are direct executables with separate argv, each bound to executable SHA-256, never a shell. Closed placeholders come from immutable Host context; stdout must be empty, stderr/command timeouts/total driver deadline are bounded, and failure or timeout terminates the full process tree. driver_disconnect_at_export is not a hook: the driver holds the exact child handle. It executes Export first; only strict pending writes fault intent/abort plan and force-disconnects that child. It then fully reloads/reverifies deployment before starting a replacement for official abort/confirm. A failed force does not record fault_triggered or permit blind replacement. TRACE32 disconnect remains hook-first at Stop and does not first perform normal Stop. Once a durable observation records abort success, Host-confirm retries do not repeat abort/END.

Before every child or replacement startup and external tool/hook side effect, the driver rereads and verifies fixed configuration, official executable, hook executable, runtime-only bundle, and installed profile. Digests must internally agree and the current deployment must exactly equal the typed configuration loaded at this execution lease's start. Replacing it during a run with a self-consistent binary/config is rejected. Administrator read-only ACLs remain the deployment condition that removes verify-to-exec TOCTOU.

Before contacting an endpoint, run:

~~~text
t32perf --artifact-root <ROOT> --json controller driver-preflight
~~~

Preflight only verifies config/binary/bundle, runs --version, MCP initialization, exact tool inventory, and shutdown, returning tools_invoked=false. Upstream creates the RCL only in the practice-tool handler, so this does not connect to TRACE32 and cannot count as endpoint, probe, or board evidence.

t32mcp does not return the runtime-bundle digest it actually executed. At startup and every active-lifecycle revalidation, the driver recomputes all compiled endpoint-reachable bundles. Each independently verifies its runtime-only manifest, adapter-private runtime members, installed profile, compiled candidate, implementation digest, and protocol-required shared root CMM. `expected_bundle_sha256` selects only the bundle allowed to mutate the target; it cannot reduce the endpoint-dispatch verification closure. Skill guidance, agent metadata, and reference documentation are deliberately excluded because they do not alter the explicitly selected script. Production qualification additionally requires an administrator to install the binary and runtime bundle from the same release, validate release checksums, and make runtime inputs read-only. Policy `implementation_sha256` must equal the selected bundle digest. A logical skill name cannot prove that a same-privilege process has not replaced a verified runtime file; if ACL conditions are unproven, remain candidate/deny-all.

One artifact root exclusively owns one single-tenant t32mcp endpoint. Every driver entry point acquires .t32perf-control/controller/trace32-driver-execution.lock before version, MCP initialization, tool inventory, execute/collect/abort, workload/fault hooks, replacement, or child cleanup, and releases it only after full lifecycle completion. External perf_capabilities/perf_capture and lower-level provision/select/prepare/accept/abort/confirm/recovery writes use the same lock; read-only status does not. The file must be empty, plain, and not a symlink/reparse point. Same-process reentry and other-process concurrency fail closed.

Alongside this OS execution lease, controller prepare scans all Sessions under the root namespace lock. An existing active transaction returns CONTROLLER_ROOT_BUSY. Missing, pending, and oversized responses retain durable root ownership. Every bounded response other than strict pending, including malformed wrappers and invalid bindings, is first written to fixed Host staging and then passed to controller accept for authoritative rejection; raw bytes are not discarded. An accepted bound response releases only its transaction and advances one fixed phase. Confirmed abort seals failure in durable quarantine instead of clearing the root recovery gate. Accepted Cleanup must materialize authoritative capture configuration before releasing capture-completion ownership.

The real driver writes seven intent/observation classes as reserved append-only `t32perf.controller-driver-event/v1` artifacts, indexed in the [schema catalog](schema-catalog.md): dispatch_intent, fault_intent, fault_triggered, abort_attempt, abort_success_observed, workload_intent, and workload_complete. Every event binds full request binding, immutable request artifact ID/SHA-256, and operation. Fault events bind the action; fault_triggered and abort events bind exact abort-plan ID/SHA-256/reason. Workload events bind accepted initial target state and workload identity. Artifact ID/path/producer are fixed and exact retries idempotent; conflicting content and forged reserved envelopes are rejected. Events prove Host intent/observation only and do not replace accepted responses or confirmed abort receipts.

On restart, state is rebuilt from immutable request/response/abort/event artifacts without repeating one-shot effects. dispatch_intent does not re-execute or blindly collect; it enters durable abort/quarantine recovery. workload_intent without workload_complete is not rerun and returns ambiguous; with completion it may confirm --workload-complete and prepare Stop. Fault intent without trigger neither replays the fault nor aborts an unproven side effect; with trigger it only resumes abort lifecycle. abort_attempt without success observation does not repeat END and returns ambiguous; abort_success_observed retries only Host confirm. Every window that cannot distinguish not happened from happened-but-marker-not-written fails closed.

The Controller has no second drift-prone phase cache. It derives phase from immutable request/response/evidence/abort artifacts and enforces:

~~~text
capabilities → configure → start → stop → health → export → cleanup
~~~

Only accepted start advances a Session to capturing; only accepted stop advances it to captured. Export cannot run from a new Session or bypass stopped and health evidence. A completed phase is never prepared again; already staged/accepted responses rerun only idempotent controller accept, while side-effect intent follows journal recovery. Cleanup is mandatory before host processing/terminal state; Hotspots replaces no main-chain phase. If Cleanup is accepted but capture-config materialization fails, the same immutable Cleanup transaction stays pending and retains root ownership. Next accept only repairs capture configuration idempotently; it cannot jump to Complete or permit new capture.

Confirmed abort or another Controller failure makes the Session terminal failed. The host then writes no cleanup receipt and does not breach the immutable Session boundary to restore target state. A trusted laboratory Controller can restore state outside the Session with independent operations evidence; the next capture uses a new Session. External restoration is not represented as successful cleanup of the failed Session.

perf_export.cmm accepts only:

~~~text
raw_ascii
task_events_elf_orti_verified
~~~

output is allocated, normalized, and validated by the Controller under the current Session capture/staging. Ordinary spaces are supported by official quoted key=value handoff; =, quotes, ;, &, and control characters are rejected. task_events_elf_orti_verified requires an independent adapter to verify successful ELF and ORTI loading; the TC234L SNOOPer profile never selects it. Every successful target-adapter phase writes evidence_output of at most 1 MiB, conforming to the operation strict schema and matching exact operation and binding_sha256. Arbitrary JSON and vendor-custom schemas are not accepted.

Responses contain exactly one three-line frame:

~~~text
T32PERF_RESULT_BEGIN
{"protocol":"t32perf/1",...}
T32PERF_RESULT_END
~~~

Missing/duplicate markers or JSON keys, multiple payloads, unknown status/code, binding mismatch, oversized JSON, and protocol contamination outside markers fail the operation. Large traces are not returned through AREA.

The stdio reader limits each raw MCP JSON line to 1 MiB. Execute/collect accepts one text block of at most 64 KiB, abort only empty success, and Controller-frame JSON is separately limited to 4 KiB. Strict pending begins with one <NOT FINISHED>, followed by one <CONTENT>. Partial content may follow, but another <NOT FINISHED>, <FINISHED>, or second <CONTENT> is forbidden. Only this syntax continues collection. Other bounded responses, including malformed ones, are staged and then accepted/rejected by the Host.

## 6. Preserve Raw Fixtures and Freeze Mappings

Preserve at least:

~~~text
raw-trace.<validated-format>
task-events.csv
isr-events.<validated-format>
trace32-native-statistics.json
health-evidence.json
~~~

Record alongside every fixture the release/build, export command, column meanings, units, timestamp origin/frequency, wrap, same-tick order, ELF/MAP/ORTI/ARTI SHA-256, and redaction notes.

Implement an independent parser adapter for that exact format, or use fixed normalization configuration for explicit_csv_v1 only if its field contract is simple and stable:

- Never approximately match vendor variants by column count or heading.
- Never implicitly sort out-of-order data.
- Use rational conversion to session-relative integer ns.
- Same-tick multi-source events require an explicit order key; reject ambiguity otherwise.
- Produce canonical dictionary and observations.
- Keep overflow, flow error, gap, and parse errors as health observations.

Parser ID/version must enter the capture receipt and manifest. A new format has a new adapter ID or version; do not silently alter old mapping. explicit_csv_v1 supplies only strict column-to-observation mapping; selecting TRACE32 columns, units, and quality remains target-adapter responsibility.

## 7. Connect the Trusted Controller, Normalize, and Attest

Production Controller transaction sequence:

1. Create a Session and immutable request. Use controller provision-firmware <SESSION> --staged <ELF> to register firmware as a fixed firmware-elf artifact; a request path or build ID is not a substitute.
2. Deployment selects the fixed target-adapter-scenario. The public performance façade accepts only normal. sampling_buffer_full, TRACE32/driver disconnect, and CMM abort can be selected only by trusted fault/HIL flow.
3. For every fixed operation, run controller prepare, execute exact MCP handoff, write the final wrapper to the Controller-owned response path, then run controller accept.
4. The adapter strictly completes capabilities/configure/start/stop/health/export/cleanup. Every v1 success emits matching typed, binding-bound machine evidence.
5. The accepted Controller chain automatically creates and registers fixed CaptureConfigReady, binding ELF/S3, scenario, qualification vector, and phase evidence. An adapter cannot submit a second handwritten capture config.
6. Ingest Controller-allocated raw export only after accepted stop, health, export, and cleanup. Failed files remain unregistered in staging/quarantine.
7. Before normalize, production target-adapter session admission must exactly match deployment trust policy, HIL receipt, and candidate profile. Empty/uninstalled trust store is default deny.
8. Run normalize --input-artifact ... --config-artifact ... to write canonical observations.
9. Read the Session operation_id, request SHA-256, observations SHA-256, and capture-config exact/configuration SHA-256.
10. An external adapter creates t32perf.capture-attestation/v1, containing its receipt, the same config claim, accepted Controller health artifact ID/SHA-256, and typed-health-derived adverse observations, signed by deployment Ed25519 private key.
11. Write attestation to Session staging. The host chooses a fixed policy path from administrator allowlist, then runs session attest --staged ... --policy ....
12. The host verifies signer, config scope, and claim ceiling through t32perf.capture-trust-policy/v1, writes trusted receipt, then runs analyze, summary, convert, and validate --deep.

Deployment-driver entry points:

~~~text
t32perf --artifact-root <ROOT> --json controller driver-preflight
t32perf --artifact-root <ROOT> --json controller drive <SESSION> --surface capabilities
t32perf --artifact-root <ROOT> --json controller drive <SESSION> --surface capture --mode raw_ascii
t32perf --artifact-root <ROOT> --json controller drive-transaction <SESSION> <TRANSACTION>
t32perf --artifact-root <ROOT> --json controller abort-upstream <SESSION> <TRANSACTION> --reason timeout
~~~

drive advances the façade sole typed next_action, with the workload hook between accepted Start and Stop. drive-transaction handles only an existing immutable request. abort-upstream writes plan and abort_attempt, calls official abort, and persists abort_success_observed before Host confirm, so later child-shutdown failure cannot erase that success. Graceful or forced child-cleanup failure explicitly returns CONTROLLER_DRIVER_CLEANUP_FAILED, retaining raw error and durable Host state; established abort quarantine survives cleanup failure and CLI restart.

The driver-disconnect Export sequence is execute Export → classify wrapper. A final wrapper is staged and passed to Host accept, which authoritatively rejects it as fault missed; the driver does not force-disconnect afterwards. Only strict pending writes fault intent/abort plan, force-disconnects exact child, records fault triggered, and completes one abort/confirm on a fully revalidated replacement. TRACE32 disconnect stays hook-first at Stop. If hook intent exists but completion is unknown, it is not rerun. CMM abort records trigger only after exact armed marker and joins the same durable abort state machine.

A pending transaction blocks the owner Session ingest, normalize, attest, analyze, and convert. Manual lower-level abort runs controller abort to make a plan; only a trusted caller that actually observed official abort-tool success may run controller confirm-abort --acknowledge-unbound-success. The real driver atomically composes this as controller abort-upstream. Disconnect/CMM-abort retains root quarantine; a trusted laboratory Controller must submit typed recovery evidence and finish controller recover. Recovery rebuilds from the failed Session original V1/V2 request envelope, abort receipt, and exact admitted profile. profile_sha256 is the candidate-identity digest excluding the qualification-receipt claim. Successful target recovery archives linked endpoint quarantine; failed Sessions never become successful captures.

Command skeleton:

~~~text
t32perf --artifact-root <ROOT> --json normalize <SESSION> --input-artifact <RAW_ID> --config-artifact <CONFIG_ID>
t32perf --artifact-root <ROOT> --json session attest <SESSION> --staged capture-attestation.json --policy <TRUST_POLICY.json>
t32perf --artifact-root <ROOT> --json analyze <SESSION>
t32perf --artifact-root <ROOT> --json summary <SESSION> --top 20
t32perf --artifact-root <ROOT> --json convert <SESSION> --format perfetto-json
t32perf --artifact-root <ROOT> --json validate <SESSION> --deep
~~~

See [the user guide](user-guide.md) and checked-in schemas for capture/normalization configuration and attestation fields. Receipt verification binds producer, Session/operation, request digest, observation digest, capture-config exact/configuration digests, exact Controller-health artifact digest and its complete adverse-observation mapping, adapter identity, mode, target, TRACE32, clock, covered cores, firmware identity, configuration-policy scope, and capability ceiling. JSON Schema validation alone does not establish trust.

Private keys remain in external adapter deployment; T32Perf accepts only signature and public-key policy. Policy paths/public keys cannot be selected by ordinary users or MCP requests, or an attacker could create a key/policy and self-sign. The Host Controller maps platform/environment to an ACL-protected fixed policy allowlist. Complete this runbook HIL and capability review before adding a key to production policy.

## 8. Golden Firmware and HIL

Golden Firmware must satisfy the nested-function, Task/idle/preemption, ISR/nested-ISR, overflow, custom-event, and resource-verification requirements in the repository document `golden-firmware/README.md`.

Copy hil/boards/example.toml into a private laboratory directory, fill in real commands, then run:

~~~text
T32PERF_HIL_BOARD=/lab/boards/board-a.toml uv run --project hil pytest hil/tests -m hardware
~~~

The HIL harness does not trust driver-reported health. After each capture it independently runs t32perf validate --deep and audits Session/manifest/artifact/provenance.

Minimum acceptance:

- Capture 10 consecutive times from each initial running and initial halted state.
- Every run creates a unique Session; do not delete, reuse, or contaminate extra directories.
- Overflow/flow-error injection produces INVALID and its issue in the health artifact.
- Function, Task, and ISR ID sets/counts exactly equal TRACE32 native statistics.
- Function total/self/min/max/average and Task/ISR CPU time each satisfy:

~~~text
abs(t32perf_time_ns - native_time_ns) <= max(native_time_ns * 0.005, tick_ns)
~~~

- Multiple capture artifacts are not reused through hard links.
- The manifest exactly records board, TRACE32 release/build, request hash, firmware identity, and covered cores.
- Correct deployment key/policy can attest. Incorrect signature, nonce, request/observation/config digest, config scope, mode, target, clock, core, and excess capability are rejected.
- The service layer does not allow a test/client to replace allowlisted policy path or submit its own public key.

Production-wide gates additionally require two MCU families, two capture modes, and one RTOS. Synthetic tests, software mocks, and one successful board run are not substitutes.

## 9. Release and Rollback

Before release, submit:

- adapter code, version, fixtures, and parser tests;
- target-specific CMM/configuration audit records;
- HIL report, native differential, and 10-repeat results;
- updated platform capability matrix;
- signed or verified release bundle;
- applicable schema, tool, TRACE32, and firmware compatibility statement.

Rollback uses a versioned adapter and a new Session; never rewrite an old Session. Target cleanup restores only TRACE32/capture state changed by its adapter. Preserve host artifacts for audit. When rollback deletes archived material, follow the dry-run, backup, and approval process in [operations](operations.md).
