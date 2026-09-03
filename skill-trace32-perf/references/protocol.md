# T32Perf PRACTICE and Host Protocol

Read this document when constructing a t32mcp call, handling Controller paths, establishing external-capture trust, or returning results through MCP.

## Fixed t32mcp addressing

t32mcp maps a logical skill name to `skill-{skill_name}/scripts/{script_name}`. The only allowed skill is `trace32-perf`; its scripts are `perf_get_capabilities.cmm`, `perf_configure.cmm`, `perf_start.cmm`, `perf_stop.cmm`, `perf_get_health.cmm`, `perf_export.cmm`, `perf_get_hotspots.cmm`, and `perf_cleanup.cmm`.

Never accept caller-provided skill names, script names, script paths, or PRACTICE content. The execution boundary is only official `execute_practice_skill`, `collect_practice_skill_response`, and `abort_practice_skill`. Upstream exposes no `perf_*` MCP tools; the seven exact names are supplied by the T32Perf host-CLI facade.

## Real deployment driver

The sole driver-configuration ingress is `ROOT/.t32perf-control/deployment/t32mcp-driver.json`, a strict `t32perf.t32mcp-driver-config/v1` document. It closes executable identity/SHA-256, skills root, TRACE32 port, exact t32mcp version `0.2.2`, bundle SHA-256, polling/operation/stderr bounds, optional workload, and closed fault action. No CLI, Session request, or MCP payload may replace these fields.

For every deployment load, verify absolute normalized plain config/executable/root/hook/bundle paths without symlink or reparse indirection; every configured executable SHA-256; every member of the runtime-only manifest and its canonical digest; and four-way equality between config bundle digest, manifest digest, installed profile `implementation_sha256`, and compiled TC234L candidate digest. Skill guidance, agent metadata, and reference documentation are not runtime bundle members.

Launch official t32mcp by direct argv. Pre-start `--version` stdout must be exactly `t32mcp v0.2.2` with empty stderr. After MCP initialize, identity/version must be exactly `t32mcp`/`0.2.2`, tools capability must be declared, and `tools/list` must contain exactly:

```text
execute_practice_skill
collect_practice_skill_response
abort_practice_skill
```

`controller driver-preflight` performs only the digest/version/initialize/tool-inventory check and shuts down. It does not call PRACTICE or connect TRACE32. Use `controller drive` for the typed facade, `drive-transaction` for an existing immutable transaction, and `abort-upstream` for a durable abort plan plus official abort and immediate Host confirm.

Each public driver command holds a non-blocking root-wide OS execution lease on the fixed empty plain `ROOT/.t32perf-control/controller/trace32-driver-execution.lock` until child shutdown and result finalization. The cross-process file lock and same-process canonical-root registry supplement one another. The lease does not replace durable transaction/capture ownership reconstructed from immutable artifacts.

Fully reload and revalidate deployment from fixed paths before initial/replacement-child startup and every execute, collect, abort, workload/fault hook, or forced-child-disconnect side effect. Config, executable/hook digests, manifest/members, installed profile, and candidate must exactly equal initial lease admission; a valid-but-different replacement fails closed.

`operation_timeout_ms` begins after client initialization and covers execute, collect, poll, workload/fault hooks, and at most one verified replacement abort. Only a wrapper with `<NOT FINISHED>` first, exactly one `<CONTENT>` second, and no later `<NOT FINISHED>`/`<FINISHED>` remains pending; partial content is permitted. Stage every other bounded result unchanged for Host accept or immutable rejection.

The only external commands are `workload` and `trace32_disconnect_at_stop`. Both use closed placeholders, direct argv/no shell, independent executable SHA-256, empty stdout, bounded stderr/timeout, and terminate their process tree on failure. On Unix, success also waits for the dedicated hook process group to become empty; trusted hooks must not move descendants into another session or process group. `trace32_disconnect_at_stop` is hook-first. `driver_disconnect_at_export` executes Export once; only strict pending permits forced disconnection of the exact child and one fully revalidated abort-only replacement. Stage a bounded final unchanged and let the Host mark it fault-missed.

## Durable Controller transaction

One artifact root maps to one trusted single-tenant endpoint. The Host scans immutable request/response/abort receipts and driver journals across Sessions. At most one external PRACTICE transaction may be unfinished or unconfirmed-aborted. Pending ownership blocks ingest, normalize, attest, analyze, and convert.

The Host reconstructs the only valid phase order:

```text
capabilities -> configure -> start -> stop -> health -> export -> cleanup
```

Accepted Start enters `capturing`; accepted Stop enters `captured`. Completed operations cannot create a second transaction. Recovery may only rerun `controller accept` for the original transaction. Cleanup is mandatory; Hotspots require accepted cleanup plus strict authoritative capture-config materialization.

The strict append-only `t32perf.controller-driver-event/v1` journal records `dispatch_intent`, `workload_intent`, `workload_complete`, `fault_intent`, `fault_triggered`, `abort_attempt`, and `abort_success_observed`, bound to request ID/SHA-256, controller binding, operation/fault action, abort plan, and Start workload context where applicable. Equal retries are idempotent; conflicts or missing prerequisites fail closed. Events prove only Host intent/observation.

- `dispatch_intent` precedes execute; it forbids replay or blind collection through a new child.
- `workload_intent` without `workload_complete` forbids rerunning the hook.
- `fault_intent` without `fault_triggered` forbids redoing or assuming the fault, and prohibits abort.
- `fault_triggered` requires a request-bound durable abort plan and permits only that abort lifecycle.
- `abort_attempt` without `abort_success_observed` is ambiguous and forbids another abort/`END`; a success marker permits Host confirm only.

`trace32_disconnect_at_stop` follows fault intent → transport-failure abort plan → revalidation → hook → triggered → official abort/confirm, without Stop CMM. `cmm_abort_at_start` executes fixed CMM after fault and dispatch intents, then continues only on its exact abort marker. `driver_disconnect_at_export` executes Export once; only strict pending may establish a transport-failure plan, revalidate, disconnect the exact child, record triggered, and start one abort-only replacement. Ambiguous states retain root ownership and require typed recovery or operator action, never replay.

## Parameters and response frame

t32mcp 0.2.2 serializes each `script_args` entry as quoted `"key=value"`; key order is unspecified. Fixed scripts accept quoted arguments in every valid order and reject unknown, missing, extra, and duplicate arguments.

Every script requires `binding_sha256`, derived under `t32perf.controller-binding/v1` from Session ID, Session operation ID, immutable Session-request SHA-256, transaction ID, and independent nonce. Configure requires `firmware_s3`, `initial_target_state=running|halted`, and `scenario=normal|sampling_buffer_full`; Start requires initial state, `scenario=normal|cmm_abort`, and `capacity_records=32|65536`; Stop repeats capacity. Capabilities/configure/start/stop/health/cleanup require Controller-owned `evidence_output`. Health also requires exact StopV2 keys. Export requires accepted adapter `mode` and Controller-owned `output`. Values may contain ordinary spaces but never `=`, quotes, semicolon, `&`, or control characters.

`output` and `evidence_output` are never caller input. The Controller allocates a unique file under the current Session `capture/staging`, verifies normalized containment, ACL/quota/extension/plain-file/character constraints, and registers size/SHA-256/producer/provenance only after matching operation and binding. Trace uses a `trace_export` reservation; target-control evidence uses ≤1 MiB `machine_evidence`. Failed export files remain untrusted staging data.

Each CMM script emits exactly:

```text
T32PERF_RESULT_BEGIN
{"protocol":"t32perf/1",...}
T32PERF_RESULT_END
```

The parser requires one begin/end marker, one non-empty payload line, bounded bytes, no duplicate/unknown JSON keys, matching protocol/operation/status/code/binding, and no output outside markers. Missing frames, invalid JSON, duplicate keys, bad order, oversize, unknown status/code, or binding mismatch fail the operation.

Generic scripts return `UNSUPPORTED_NEEDS_TRACE32`. Verified adapters produce bounded versioned evidence such as `capabilities_exported`, `configured`, `started`, `stopped`, `health_exported`, and `cleanup_completed`. `initial_target_state_drift` is an `INVALID_ARGUMENT` closed result with unequal expected/observed states. Export failure remains unsupported and never tries a substitute command.

## Two-phase abort

Because `abort_practice_skill` has no ownership parameter and returns unbound unit success:

1. `controller abort SESSION TRANSACTION --reason ...` writes `t32perf.controller-abort-request/v1` only and returns the exact abort call.
2. A trusted single-tenant caller aborts on the same t32mcp instance and observes success.
3. The caller runs `controller confirm-abort ... --acknowledge-unbound-success`.
4. The Host writes `t32perf.controller-abort-receipt/v1`, records `unbound_single_tenant_tool_success`, quarantines endpoint/target, and fails the Session. `root_slot_released=false` until typed recovery is accepted.

Production `controller abort-upstream` writes request-bound `abort_attempt` before the tool call. Error, timeout, or crash before `abort_success_observed` leaves upstream `END` ambiguous and forbids a repeat. On empty success, persist the success observation before immediate Host confirm; later child-shutdown failure cannot erase it.

## Normalize, trust, and handoff

Export/staging files cannot enter analysis directly. Before normalize or attest, register authoritative `t32perf.capture-config/v1` for Session/provider/adapter/mode/covered cores/sink/timestamp/clock/filters/trigger/duration/workload/initial state/RTOS metadata/bounded adapter parameters. It has exact artifact SHA-256 and cross-Session `configuration_sha256`, calculated from compact canonical JSON with an empty Session-ID sentinel; do not use pretty JSON or custom canonicalization.

For a completed TC234L chain, the Host materializes config from accepted phase evidence, ELF/S3, scenario, and admission provenance. Manual JSON cannot replace it. Cleanup accepted before config-commit crash reprojects the original transaction as repair-pending; only idempotent accept may reconstruct it. Cleanup rejection or unproven restoration requires two-phase abort, terminal failure, and quarantine.

Register raw input and strict `t32perf.normalize-config/v1`, then normalize. `canonical_ndjson_v1`, `explicit_csv_v1`, and `c_wire_v1` require explicit Session/mapping/clock/origin/quality/limits as appropriate. `trace32_snooper_ascii_v1` requires a complete accepted TC234L normal capture, exact profile/build/adapter/qualification, ELF mapping, StopV2 count, and health binding. `trace32_task_events_v1` requires accepted export binding, deployment mapping artifact, ELF/ORTI metadata, profile digest, qualification, and runtime/config equality. Never infer columns, units, event kind, quality, or order. Normalization produces canonical `observations`, not capture trust.

External trust requires deployment-owned read-only `t32perf.capture-trust-policy/v1`, Ed25519 signature over deterministic compact `t32perf.capture-attestation/v1`, exact binding of Session/nonce/request/observations/config/health/claims, Controller staging, and Host `session attest`. The Host trusts a receipt only after exact signature, scope, nonce, digest, adverse-health-mapping, config/catalog, identity, firmware, and capability-ceiling checks. Caller policy paths/JSON/keys, self-signed data, ordinary JSON, schema validation, producer strings, and handwritten receipts cannot substitute. Attestation failure is terminal; retry with a new Session.

Only an attested external capture may run `analyze`, `summary`, or optional `convert`. Pass `gnu-ld-map-v1` only with `linker_map` and `elf-sections-v1` only with `firmware_elf`; no format detection occurs. `summary` accepts `N=1..100` and requires a complete analysis receipt. `VALID` may return bounded quantitative data; `DEGRADED`/`INVALID` return diagnostics, metric support, and artifact references only; `NOT_EVALUATED`/`INCOMPLETE` return missing-stage/failure information. Never bypass summary through derived artifacts.

For Perfetto, run `convert SESSION --format perfetto-json`, then `validate SESSION --deep`. MCP returns only bounded status/summary/manifest/artifact references. AREA/pipe never carries raw trace, observations, derived streams, Perfetto JSON, or complete manifests; retrieve files through the controlled artifact channel by reference.
