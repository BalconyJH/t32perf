# TRACE32, t32mcp, and T32Perf Version Gates

Read this document when a TRACE32 release/build, t32mcp, or T32Perf version is known or must be evaluated. An unknown version always takes the conservative path.

## Host integration baseline

```text
t32mcp = 0.2.2 integration model
t32perf = 0.1.0
t32mcp driver config = t32perf.t32mcp-driver-config/v1
PRACTICE response protocol = t32perf/1
normalize config = t32perf.normalize-config/v1
capture trust policy/config/attestation/receipt = t32perf.capture-{trust-policy,config,attestation,receipt}/v1
controller request/response/abort/driver-event/target-evidence = t32perf.controller-*/v1
target-adapter admission = t32perf.target-adapter-{qualification-policy,qualification-trust-store,admission-snapshot}/v1
```

t32mcp supplies only generic PRACTICE execute/collect/abort control and one global script owner. Its official 0.2.2 implementation serializes each argument as quoted `"key=value"` with unspecified `HashMap` order. Fixed CMM accepts only the quoted form and all valid permutations. `perf_*` names are fixed skill scripts, never new top-level MCP tools. A deployment lacking the same call, quoting, AREA-wrapper, or global-ownership behavior must stop for integration validation.

## Official t32mcp 0.2.2 gate

Version text is not the trust root. Strict `ROOT/.t32perf-control/deployment/t32mcp-driver.json` binds exact `expected_t32mcp_version=0.2.2`, administrator-verified `expected_executable_sha256`, and exact `expected_bundle_sha256`. No generic binary digest can replace the administrator-approved SHA-256. Verify every runtime-manifest member hash and require:

```text
config expected_bundle_sha256
= manifest bundle_sha256
= installed profile implementation_sha256
= compiled candidate implementation digest
```

The stdio child must emit exactly `t32mcp v0.2.2` with `--version`; initialize must report exactly `t32mcp`/`0.2.2`; and `tools/list` must contain exactly `execute_practice_skill`, `collect_practice_skill_response`, and `abort_practice_skill`. Extra/hidden/duplicate/missing tools, cursor anomalies, or identity/version variance fail closed. `controller driver-preflight` does only digest/version/initialize/tool inventory and never calls PRACTICE or connects TRACE32.

Every public driver command holds `ROOT/.t32perf-control/controller/trace32-driver-execution.lock` as an empty-plain-file non-blocking root-wide OS lease, plus the same-process registry. It complements durable ownership from immutable artifacts. Before every startup or external side effect, fully reload/revalidate deployment and require equality with initial admission. `operation_timeout_ms` covers the complete initialized drive/transaction, including one verified replacement abort. Only strict `<NOT FINISHED>` then one `<CONTENT>` wrappers may collect; stage every other bounded wrapper unchanged.

The closed driver-event set is `dispatch_intent`, `fault_intent`, `fault_triggered`, `abort_attempt`, `abort_success_observed`, `workload_intent`, and `workload_complete`. It makes execute, workload, fault action, and abort at most once: no replay after dispatch, no rerun without workload completion, no unproven fault abort, no second abort after ambiguous attempt, and Host confirm only after observed abort success.

The external-capture loop requires `normalize`, `session attest`, `analyze`, `summary`, `convert`, `validate`, and artifact queries. A missing command or schema-major mismatch stops the loop. Supported normalizers are `canonical_ndjson_v1`, `explicit_csv_v1`, `c_wire_v1`, `trace32_snooper_ascii_v1`, and `trace32_task_events_v1`; unknown IDs, automatic vendor-text inference, and different wire majors are unsupported. `summary --top N` requires `N=1..100` and a complete `VALID` analysis stage.

## Confirmed TRACE32 gates

### Release 2025/09, build 183242

Statistic/chart suffixes changed:

```text
.TASKINTR        -> .ISR
.TASKVSINTR      -> .TASKVSISR
.TASKORINTRState -> .TASKORISRState
.TASKSRV         -> .SeRVice
```

Future adapters choose by build; they never try multiple spellings.

### Release 2023/09, build 162904

`Trace.STATistic` exposes `fifo fulls` and `flow errors` as separate items only from this build. Earlier or unknown builds must not reuse the parser or claim trusted hardware health.

### Release 2022/02, build 142441

After `AREA.OPEN` opens a protocol file, a second `AREA.Create` of the same area no longer closes it; older versions do. Fixed scripts do not manage AREA lifecycle and rely on t32mcp's selected AREA/pipe without recreating an area.

## Public baseline and local candidate

The integration reference is General Commands Reference Guide T Release 02.2026. A public manual release does not prove deployed behavior; every real capture attests exact TRACE32 release/build and architecture package.

The local `t32mtc.exe`/`VERSION.SOFTWARE()` candidate is `R.2026.02.000190766` (release `2026.02`, build `190766`). Its gate permits only exact TriCore package, TC234L core 0, and PowerDebug PRO serial binding; it grants no production trust. Admission also requires immutable qualification policy/receipt/HIL snapshot, post-init 30 MHz/DUALPORT, fixed workload termination, and fault-scenario HIL evidence. Firmware identity is canonical sparse S3 from exact ELF physical `PT_LOAD` segments and is verified by `Data.LOAD.S3record <file> /DIFF`; runtime RAM/BSS and legacy PFlash CRC32 are not runtime authority.

This candidate is SNOOPer PC statistical sampling, not a flow decoder. Health V2 declares only buffer-full/unexpected-stop and S3 `/DIFF` firmware match; flow errors, program-flow closure, and TASKEVENTS flow export are unavailable. A different registered flow/ELF/ORTI adapter with real evidence is required to activate strict TASKEVENTS mapping.

## Rules

1. Without exact release/build evidence, capabilities/configure/start/stop/hardware-health/cleanup return `UNSUPPORTED_NEEDS_TRACE32`.
2. Confirm `Trace.EXPORT.ASCII` only by executing it; never try a substitute after failure.
3. `Trace.EXPORT.TASKEVENTS` additionally requires verified ELF/ORTI; never fall back to guessed structured data.
4. Export success is not host trust: normalize, then complete `session attest` under deployment Ed25519 policy.
5. Never auto-try an old or new command spelling.
6. New version support requires raw fixture, normalization mapping, HIL/native differential, health-fault injection, and build evidence before updating adapter, policy scope, and this document.
7. On schema-major, adapter-version, or tool-contract mismatch, create a new Session and explicitly upgrade; do not reuse a receipt or migrate in place.
8. Only `workload` and hook-first `trace32_disconnect_at_stop` are configurable external commands, using direct argv/no shell and exact executable SHA-256. `driver_disconnect_at_export` executes Export first, then only strict pending may force-disconnect and perform one fully revalidated replacement abort/confirm; bounded finals enter the Host fault-missed gate.
9. Cleanup rejection or unproven target restoration requires two-phase abort and durable quarantine. Missing authoritative config after accepted Cleanup keeps the original transaction repair-pending; only idempotent `controller accept` repairs it.

Local software validation covers driver transport/config/orchestration and strict ASCII/TASKEVENTS parser/mapping. It has not called PRACTICE or connected TRACE32/a board. RTOS/Linux, a second platform, and TASKEVENTS program-flow/ELF/ORTI hardware-flow evidence remain deferred.

## Official sources

- [Lauterbach t32mcp repository](https://gitlab.com/lauterbach/t32mcp)
- [TRACE32 Release History](https://repo.lauterbach.com/release_history.html)
- [General Commands Reference Guide T](https://www2.lauterbach.com/pdf/general_ref_t.pdf)
