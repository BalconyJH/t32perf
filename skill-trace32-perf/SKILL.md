---
name: trace32-perf
description: Orchestrate fail-closed TRACE32 performance sessions through fixed t32mcp PRACTICE scripts and the T32Perf host CLI. Use for controller-owned export, explicit normalization, signed external capture attestation, health-gated summaries, and artifact handoff; do not guess target-specific TRACE32 configuration, run control, or health commands.
---

# TRACE32 Performance

Use fixed t32mcp PRACTICE scripts and the T32Perf host CLI for TRACE32 performance observability. This skill is the trusted Controller control plane, not a general hardware trace configurator.

## Non-negotiable boundaries

- The Host Controller creates a Session, assigns its Session ID, and allocates the sole output path under that Session's `capture/staging`. Never use a caller-provided Session, staging, or export path.
- `skill_name` is fixed as `trace32-perf`. `script_name` must come from the list below. Use only the official `execute_practice_skill`, `collect_practice_skill_response`, and two-phase `abort_practice_skill` handoff.
- Do not assemble MCP parameters directly. Prefer `controller drive`: the driver calls the exact `perf_capabilities`/`perf_capture` facade and executes only its typed `next_action`. The lower-level `controller prepare/accept` commands exist only to diagnose the facade/driver implementation.
- Derive Controller phases only from immutable request, response, evidence, and abort artifacts. The fixed order is capabilities → configure → start → stop → health → export → cleanup. Do not export directly, skip cleanup, prepare a completed phase again, or replace an idempotent accept recovery with a new transaction.
- One artifact root is bound to one single-tenant t32mcp endpoint and may have at most one durable pending PRACTICE transaction. Each public driver command must also hold a non-blocking root-wide OS execution lease on a fixed empty plain lock file, supplemented by a same-process registry for platform file-lock differences. This short-lived execution exclusion does not replace durable capture ownership reconstructed from immutable artifacts.
- The real driver reads the strict `t32perf.t32mcp-driver-config/v1` only from `ROOT/.t32perf-control/deployment/t32mcp-driver.json`. Callers cannot override the executable, skills root, TRACE32 port, deadline, workload, or fault action.
- The driver accepts only an official t32mcp `0.2.2` stdio child. Before startup, verify the exact SHA-256 and `--version` of an absolute plain executable; after initialization, verify server identity/version and require that `tools/list` contains exactly `execute_practice_skill`, `collect_practice_skill_response`, and `abort_practice_skill`.
- The driver verifies every SHA-256 in the runtime-only adapter manifest and its canonical bundle digest. Config, manifest, installed profile `implementation_sha256`, and compiled candidate must agree four ways. `SKILL.md`, agent metadata, and reference documentation are deliberately outside this runtime identity.
- Before each external side-effect boundary and replacement-child startup, the driver must fully reload and revalidate config, t32mcp/hook executables, bundle manifest/members, and installed/compiled profile from fixed root paths, requiring equality with this execution lease's initial admission.
- The driver records seven markers in strict append-only `t32perf.controller-driver-event/v1` artifacts: `dispatch_intent`, `fault_intent`, `fault_triggered`, `abort_attempt`, `abort_success_observed`, `workload_intent`, and `workload_complete`. Each marker is exactly bound to its immutable request and abort/workload context. Identical retries are idempotent; conflicting markers or missing prerequisites fail closed; a marker is not an accepted response or confirmed abort receipt.
- Execute, workload, fault action, and upstream abort are at-most-once side effects. After `dispatch_intent`, do not execute again or collect blindly. With `workload_intent` but no `workload_complete`, do not rerun the hook. With `fault_intent` but no `fault_triggered`, do not redo the fault or assume it occurred and abort. Only `fault_triggered` with a bound abort plan can continue the abort lifecycle. `abort_attempt` without `abort_success_observed` is ambiguous and forbids a second abort/`END`; once `abort_success_observed` exists, only Host confirm is permitted.
- CMM returns only one bounded response frame. Trace, derived stream, Perfetto, and other large data belong in artifact files.
- Register raw input, CSV, and C SDK wire input as immutable artifacts before producing canonical `observations` with `normalize`. Normalization proves format conversion only; it does not establish hardware trust.
- Before normalize or attest, every capture must register a strict `t32perf.capture-config/v1` artifact. The Host automatically materializes it after the Controller's seven-stage chain completes. It authoritatively records provider/adapter/mode, cores, sink, timestamp, filters, trigger, duration, workload, initial target state, RTOS awareness, and bounded adapter parameters. Never infer or guess these fields from TRACE32 output.
- Cleanup rejection or failure to prove target restoration requires a two-phase abort, terminal failed Session, and durable endpoint/target quarantine. Do not start another capture until typed recovery completes. If Cleanup is accepted but capture-config materialization fails, the Host reprojects the original Cleanup transaction as repair-pending and retains root ownership. Only idempotent `accept` may repair it with strict authoritative-config verification; do not start another transaction or construct config manually.
- External capture requires deployment-owned `t32perf.capture-trust-policy/v1` and an Ed25519-signed `t32perf.capture-attestation/v1`, followed by `session attest`. A caller request, producer string, ordinary JSON, or schema validation cannot become hardware fact.
- Target-control `OK` must produce the matching strict `t32perf.controller-*-evidence/v1` document, exactly bound to the operation and controller binding. Arbitrary JSON, vendor-specific schemas, incorrect bindings, and unconfirmed start/stop/cleanup facts cannot advance a phase.
- Accepted Controller health evidence must enter the signed attestation/receipt by artifact ID/SHA-256. The host mapping must check that adverse observations for that source are complete and have no extras before the analyzer health gate consumes them. Do not advance a phase from health evidence and discard its trust chain.
- `session attest --policy` is the deployment administrator/Host Controller trust ingress. An MCP request may reference only a preconfigured policy ID; the Controller resolves it to a fixed read-only path. Do not pass caller-provided policy paths, policy JSON, public keys, or other trust-root material.
- After `analyze` succeeds and produces a complete analysis stage, return hotspots or quantitative summaries to MCP only through `summary <SESSION> --top <N>`. `N` must be 1..100.
- Wire a static-RAM source explicitly by artifact kind and `analyze --static-ram-flavor gnu-ld-map-v1|elf-sections-v1`. Do not guess the flavor from an extension, ELF magic, section name, or TRACE32 text. The legacy `--linker-map-flavor` is compatibility-only.
- `INVALID` returns only diagnostics, metric support, and artifact references. Do not return quantitative hotspots, duration, call counts, or resource values. Do not bypass the summary gate by reading an analysis artifact directly.
- Return large artifacts only as manifest/artifact references such as ID, kind, relative path, size, SHA-256, producer, and provenance. Do not place file content in an MCP/AREA response.

## Required reading order

1. For real TRACE32 work, read [hardware-adapters.md](references/hardware-adapters.md). If no verified target adapter exists, return unsupported at the first hardware operation and do not continue.
2. Before calling a fixed script or parsing a frame, read [protocol.md](references/protocol.md).
3. When handling staging, attestation, policy, or MCP output, read [security.md](references/security.md).
4. When a TRACE32 release/build, t32mcp, or T32Perf version is known, read [version-gates.md](references/version-gates.md). Use the conservative branch for an unknown version.
5. After deployment, run `controller driver-preflight` first. It checks executable digest/version, MCP initialize, and exact `tools/list`; it does not call a PRACTICE tool or connect TRACE32.
6. Machine calls to the T32Perf CLI always use `--json` and check the exit code, top-level result, health/trust state, and artifact provenance together.

## Exact machine facade

The plan defines these fixed public entry points:

```text
perf_capabilities
perf_capture
perf_get_status
perf_get_summary
perf_list_artifacts
perf_convert
perf_compare
perf_run
```

They are T32Perf host-CLI operations, not hypothetical upstream t32mcp top-level tools. The `result` of each success conforms to the `t32perf.perf-surface/v1` closed tagged union; never accept or construct untyped payloads.

A real capture starts from an existing Session. The TC234L candidate first requires deployment-controlled firmware provisioning through a controlled staging path and then closed-scenario selection; both are permitted only while the Session is `Created` and before any Controller request:

```text
t32perf --artifact-root ROOT --json controller provision-firmware SESSION --staged FIRMWARE_ELF
t32perf --artifact-root ROOT --json controller select-scenario SESSION --scenario normal
t32perf --artifact-root ROOT --json controller driver-preflight
t32perf --artifact-root ROOT --json controller drive SESSION --surface capabilities
t32perf --artifact-root ROOT --json controller drive SESSION --surface capture --mode raw_ascii
```

To promote a candidate to qualified admission, the deployment administrator must first install a read-only trust store/policy and provision strict qualification plus an HIL receipt in the Session. These are not trust materials an MCP caller may supply. Fault scenarios (`sampling_buffer_full`, `trace32_disconnect`, `driver_disconnect`, `cmm_abort`) exist only for Controller/HIL evidence and must not take the public `perf_capture` success path.

`controller drive` loops through the typed facade under one bounded total deadline. Each control payload permits only one `next_action`:

- `execute`: persist `dispatch_intent`, then make the supplied exact official MCP call. Only the strict `<NOT FINISHED>` header remains pending; stage every other bounded wrapper unchanged at the supplied response handoff.
- `collect`: only the driver that still owns the live dispatch may make the supplied collect call. A pending wrapper may carry partial content after `<NOT FINISHED>` and a unique `<CONTENT>`, but must not contain another `<NOT FINISHED>` or `<FINISHED>` afterward. Stage any other bounded wrapper unchanged for the Host.
- `run_workload`: the target-specific Controller runs its fixed workload, then invokes `perf_capture SESSION --workload-complete`.
- `invoke`: call the specified exact facade to advance the next durable phase.
- `capture_config_ready`: after the seven-stage chain, the host automatically materializes the authoritative capture-config artifact reference. Do not describe control-chain completion as analysis/attestation completion.

Use these query and reporting commands:

```text
t32perf --artifact-root ROOT --json perf_get_status SESSION
t32perf --artifact-root ROOT --json perf_get_summary SESSION --top 10
t32perf --artifact-root ROOT --json perf_list_artifacts SESSION --limit 100
t32perf --artifact-root ROOT --json perf_convert SESSION --format perfetto-json
t32perf --artifact-root ROOT --json perf_compare BASELINE CANDIDATE --policy default
```

Summary exposes only typed health, adapter-declared Top-N sampling/function/Task/ISR metrics, and artifact references. The TC234L SNOOPer candidate declares only statistical sampling and cannot claim Task/ISR or exact function metrics. Detailed resource documents remain artifacts. Compare exposes only verdict/outcome counts and a complete content-addressed report reference, never arbitrary row objects.

## Typical request mapping

For the request "capture the next 5 seconds of function performance, including Task and ISR, generate a Perfetto report, and return the ten hottest functions", use this fixed mapping:

| Step | Fixed phase | Current generic implementation |
|---:|---|---|
| 1. Deployment binding | `controller provision-firmware`, `controller select-scenario` | Firmware S3 derivation, scenario, profile, and request provenance are immutable. |
| 2. Capability check | `perf_get_capabilities.cmm`; host `doctor` checks only the local environment | Hardware capability returns `UNSUPPORTED_NEEDS_TRACE32`. |
| 3. Trace configuration | `perf_configure.cmm` | Returns `UNSUPPORTED_NEEDS_TRACE32`; do not guess method, sink, timestamp, filter, or trigger. |
| 4. Start capture and workload | Driver runs a deployment-configured fixed workload hook between accepted Start and Stop | Fails closed when unconfigured; never execute a caller command or use sleep/a caller statement to forge completion. |
| 5. Stop capture | `perf_stop.cmm` | Returns `UNSUPPORTED_NEEDS_TRACE32`; exporting is prohibited without trusted stopped evidence. |
| 6. Health check | `perf_get_health.cmm` | Returns `UNSUPPORTED_NEEDS_TRACE32`; host analyzer health cannot substitute for hardware overflow/flow-error evidence. |
| 7. Export | `perf_export.cmm` writes a Controller-allocated staging file; host registers raw input | Execute only a confirmed export. TRACE32 vendor format still requires fixture/HIL-verified mapping. |
| 8. Cleanup and configuration | `perf_cleanup.cmm`; host materializes capture config | Cleanup is the final seven-stage operation. Failure enters abort/quarantine; if config materialization is interrupted after accepted cleanup, the original Cleanup transaction stays repair-pending until idempotent repair completes. |
| 9. Report conversion | host `normalize`, `session attest`, `analyze`, `convert --format perfetto-json` | Only a signature-verified trusted receipt can enter external-capture analysis. |
| 10. Return | host `summary --top 10`, `validate --deep`, `session status`, `artifacts list --limit 100` | Return only paged Session, manifest, and artifact references; follow `next_after` pagination and do not return large content. |

If steps 1, 2, 3, 5, or 6 return unsupported, the real hardware request cannot complete automatically. Return the missing adapter/HIL condition; do not continue the same request with synthetic data, a caller assertion, or handwritten JSON.

## Fixed scripts

| Script | Parameters | Fixed behavior |
|---|---|---|
| `perf_get_capabilities.cmm` | `binding_sha256`, `evidence_output` | The generic script is unsupported; a versioned target-adapter success is `capabilities_exported` plus bounded evidence. |
| `perf_configure.cmm` | `binding_sha256`, `evidence_output`, `firmware_s3`, `initial_target_state`, `scenario` | Root dispatch parses a closed key set; the TC234L success is `configured` plus bounded evidence. |
| `perf_start.cmm` | `binding_sha256`, `evidence_output`, `initial_target_state`, `scenario`, `capacity_records` | Root dispatch parses a closed key set. Before any SNOOPer mutation, an adapter must compare live target state with capabilities-bound `initial_target_state`, and actual SNOOPer size with scenario-bound capacity. TC234L SNOOPer success is StartV2 `capture_armed`; the workload owner is the host facade. |
| `perf_stop.cmm` | `binding_sha256`, `evidence_output`, `capacity_records` | Gate scenario-bound capacity again before Stop. TC234L success is StopV2, bound to pre-stop state, stable records/capacity, and first-record ZERO. |
| `perf_get_health.cmm` | `binding_sha256`, `evidence_output`, `stop_evidence_sha256`, `pre_stop_state`, `recorded_records`, `capacity_records`, `firmware_s3` | HealthV2 binds immutable StopV2, sampling faults, and controller-derived S3 `/DIFF` firmware identity. |
| `perf_export.cmm` | `binding_sha256`, `mode`, `output` | TC234L runs only the fixed `SNOOPer.EXPORT.Ascii` item profile; fail closed without a qualified TASKEVENTS adapter. |
| `perf_get_hotspots.cmm` | `binding_sha256` | `HOST_PROCESSING_REQUIRED / raw_trace_analysis_required` |
| `perf_cleanup.cmm` | `binding_sha256`, `evidence_output`, `initial_target_state` | Restore the canonical SNOOPer baseline and prove that target execution state still equals the Configure initial state. Do not delete Session files. |

Export mode is selected by the accepted adapter profile. The current TC234L SNOOPer candidate permits only `raw_ascii`; `task_events_elf_orti_verified` remains unsupported until an independent program-flow/ELF/ORTI qualified adapter is registered.

## Host external-capture transaction

The Controller executes the following order. Any error that cannot prove upstream completion retains pending root ownership; continue collecting or complete a two-phase abort. Retry a terminally failed Session with a new Session; never overwrite, delete, or repair an immutable artifact.

1. `session create --id SESSION --request REQUEST_JSON`.
2. Run `controller drive SESSION --surface capabilities|capture` for the public chain; run `controller drive-transaction SESSION TRANSACTION` for an existing immutable transaction. `controller prepare/accept` are only for diagnosing the driver/Host boundary.
3. Only if execute returns a strict pending wrapper with `<NOT FINISHED>` on the first line, a unique `<CONTENT>` on the second, and no later `<NOT FINISHED>`/`<FINISHED>`, may the driver call the collect tool in the immutable request. Partial content after `<CONTENT>` is permitted. Every other non-oversized wrapper, including mixed headers, malformed frames, and a fault action's unexpected final response, must be staged as original bytes at the Controller-owned response path, then authoritatively accepted or rejected by the Host. The driver must not discard or repair that input.
4. `operation_timeout_ms` is the total deadline for one drive/transaction after client initialization. It covers execute, collect, poll, workload/fault hooks, and the permitted one verified replacement abort. A hook's own timeout cannot exceed the remaining total deadline.
5. After Cleanup is accepted, the host automatically materializes authoritative capture config from accepted seven-stage evidence; the adapter/Controller registers accepted raw input and normalization config.
6. Use `session ingest` to register accepted raw input and normalization config, then run `normalize`. A pending controller transaction structurally blocks these changes.
7. An external signer creates a signed attestation. The Host runs `session attest`, then `analyze`, `summary`, and optional `convert` with an explicit resource flavor.
8. Return only the bounded summary and artifact references.

If abort is required, run `controller abort-upstream SESSION TRANSACTION --reason timeout|transport_failure|operator_request`. The driver persists an abort plan, writes `abort_attempt`, then calls official `abort_practice_skill`. It must persist tool success as `abort_success_observed` before immediately running Host confirm. If `abort_attempt` exists without a success marker, the outcome is ambiguous and a second abort/`END` is forbidden; if the success marker exists, reentry only confirms. A later child-shutdown failure must not erase observed abort success or completed Host confirmation. The low-level `controller abort`/`confirm-abort` commands are diagnostic only. An abort plan itself neither releases a root slot nor claims that upstream stopped.

`controller prepare` `fault_action` is a closed deployment-controller instruction, not an ordinary MCP parameter, and cannot be replaced by the caller:

- `trace32_disconnect_at_stop`: appears only on a Stop request whose overall scenario is `trace32_disconnect`. This is a hook-first fault. The driver persists fault intent and an abort plan, fully revalidates deployment, then runs the only permitted external hook before any Stop CMM execute. On hook success it writes `fault_triggered` and continues only with official abort/confirm. The hook executable runs by direct argv without a shell and must match its SHA-256 exactly. Do not execute normal Stop first or forge a Stop response.
- `driver_disconnect_at_export`: appears only on an Export request in `driver_disconnect`. It is not an external hook. The driver executes Export exactly once. Any bounded final is staged unchanged and the Host returns a fault-missed rejection. Only a strict pending wrapper permits persistence of fault intent and an abort plan, full deployment revalidation, and forced disconnection of the held exact t32mcp child process tree. After writing `fault_triggered`, start exactly one replacement from the same fully revalidated deployment, solely for official abort and immediate confirm. Do not elevate leftover output to an artifact.
- `cmm_abort_at_start`: appears only on a Start request in `cmm_abort`. After running the fixed abort-target CMM, complete the official two-phase abort, quarantine, and recovery described above.

The only configurable deployment commands are `workload` and `trace32_disconnect_at_stop`. Both use closed placeholders, direct argv/no shell, an independent executable SHA-256, and bounded stdout/stderr/timeout; on timeout or failure, terminate the entire process tree. On Unix, success also waits for the dedicated hook process group to become empty; trusted hooks must not move descendants into another session or process group. If deployment lacks a fixed action corresponding to `fault-scenarios.json`/HIL board config, the fault-evidence request must fail closed. Do not replace it with normal execute, a handwritten wrapper, arbitrary process termination, or a synthetic result.

## Response handling

CMM content must contain exactly:

```text
T32PERF_RESULT_BEGIN
{"protocol":"t32perf/1",...}
T32PERF_RESULT_END
```

A missing frame, duplicate key, incorrect marker order, invalid JSON, oversized payload, unknown status/code, binding mismatch, or protocol pollution outside the markers fails the operation. A pending wrapper has a strict first-line `<NOT FINISHED>`, second-line `<CONTENT>`, exactly one `<CONTENT>`, and may contain partial content afterward but no more `<NOT FINISHED>` or `<FINISHED>`; only that form continues collection. It and a local read/ingest error do not terminally complete the Session or release the global slot. Stage every other bounded wrapper unchanged, then reject it through the Host. An export failure may leave an incomplete staging file; do not ingest or attest it.

## Current runtime-evidence boundary

This iteration implements and covers with local software tests the real driver, strict ASCII/TASKEVENTS mapping contract, Controller control chain, and closed fault orchestration. It has not called any t32mcp PRACTICE tool or connected TRACE32 or a target board. RTOS/Linux runtime evidence, a second platform, and TASKEVENTS program-flow/ELF/ORTI hardware flow evidence are deferred. Do not present software validation or preflight as a completed hardware capture.

## Forbidden fallback

- Do not try `Trace.METHOD`, `Trace.ON/OFF`, `Trace.Init/Arm`, or another target-specific substitute command.
- Do not treat `Trace.STATistic` or GUI text as a stable machine protocol.
- Do not describe sampling as exact call counts, call nesting, or exact duration.
- Do not substitute a synthetic capture for a requested real TRACE32 capture.
- Do not treat the presence of `capture-receipt` JSON as attestation success; external trust comes only from the host `session attest` verification path.
- Do not use a caller-provided policy path, public key, or self-signed attestation as a deployment trust root.
- Do not construct a hotspot response outside `summary`, or return quantitative fields for `INVALID`.
