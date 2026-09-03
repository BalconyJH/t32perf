# Hardware Verification Boundary

The current software and hardware status is documented in [implementation-status.md](implementation-status.md). Per-platform onboarding steps are documented in [trace32-runbook.md](trace32-runbook.md).

The following conclusions can only be verified with real TRACE32 hardware, a probe, a target board, firmware, and an RTOS environment:

- ETM, ITM, DWT, MTB, TPIU, STREAM, and RTOS Awareness capabilities.
- Configuration, start, stop, overflow, flow-error, and export commands for the applicable TRACE32 build.
- TRACE32 export columns, time origin, same-tick ordering, and version compatibility.
- At least ten independent captures for each accepted board, mode, and initial running/halted state, plus fault injection and native-statistic differentials.
- Production acceptance across at least two MCU families, two capture modes, and one RTOS.
- Production acceptance across at least two exact TRACE32 versions through version-specific admitted adapters.
- Generic PC-sampling acceptance through the independent sampling-only HIL config and real two-tool MCP bridge, including pinned endpoint/software/CPU identity, target-ready state, quantitative quality gates, and a retained PASS receipt.

Until these checks are complete, unknown target adapters and CMM scripts must return `UNSUPPORTED_NEEDS_TRACE32`. The implemented TC234L SNOOPer candidate is an evidence-only software path; synthetic fixtures, static CMM review, or the HIL harness cannot substitute for production evidence.

The current CLI retains the `synthetic` provider and implements TC234L SNOOPer-candidate firmware provisioning, ELF-to-S3 `/DIFF`, a seven-stage Controller, automatic `CaptureConfigReady`, strict ASCII/TASKEVENTS mappings, typed fault recovery, and the official t32mcp `0.2.2` real stdio deployment driver. The driver reads fixed `t32perf.t32mcp-driver-config/v1`, verifies the executable SHA-256, the exact three-tool inventory, and the runtime-only adapter bundle/profile/compiled digest. It also implements direct-argv workload/TRACE32-disconnect hooks, exact child-handle driver disconnect, a root-wide OS execution lease, and a reserved append-only crash journal. These are software implementations, not hardware execution results.

The HIL software contract also fixes the fault-manifest and profile raw-byte digests, canonical profile digest, and sampling recovery receipt. The Python harness and Rust model cross-check the same closed fields; the complete Rust execution result must be confirmed after this software test round. They constrain evidence formats and do not constitute board or fault-injection results.

The crash-safe software contract serializes version/init/tool/hook/replacement/cleanup with `.t32perf-control/controller/trace32-driver-execution.lock`, and places external perf and lower-level Controller mutations behind the same exclusion boundary. `t32perf.controller-driver-event/v1` persists dispatch/fault/abort/workload intent and observations bound to immutable request/binding/abort-plan artifacts. After a restart it does not repeat execute, blind collect, workload, fault, or abort/`END`. A workload intent without completion remains ambiguous and is not rerun; once complete, it can resume at Stop. When an abort-success observation exists, only Host confirmation is retried. This state machine, its process-tree tests, and mock transport prove only host software recovery semantics; they cannot prove that TRACE32 or board side effects occurred.

The executable SHA-256 recorded for the Windows official-mirror v0.2.2 build candidate is `31f4983a4e7a60a5025e8334e95e6ecb4bd242ce6bc9705f81cdf081af05dec2`. It identifies only that exact build artifact, not every v0.2.2 binary. The current runtime bundle digest is read from the checked-in manifest and must equal the installed profile and compiled constant; it is not interchangeable with the executable digest. The archived preflight paired the executable with historical adapter implementation `feb46173441d2225b522a03cfae2486031fb72c6d8170baf374038848dcb2293`, not the current bundle.

`controller driver-preflight` runs only the executable version probe, MCP initialization, `tools/list`, and shutdown. It does not invoke `execute_practice_skill`, `collect_practice_skill_response`, or `abort_practice_skill`. Upstream creates the RCL only in the practice-tool handler, so preflight does not connect to TRACE32. Whether it succeeds or fails, it is not evidence of an endpoint, probe, MCU, or board.

The software ordering at the fault boundary also cannot replace on-target evidence. Driver disconnect executes Export first; the final response must be staged for the Host to decide that the fault was missed. Only a strict pending response force-disconnects the exact child and starts a fully revalidated replacement to perform one abort/confirm sequence. TRACE32 disconnect remains hook-first at the Stop boundary; CMM abort requires the exact armed marker. Strict pending may contain partial content, but its `<NOT FINISHED>` and `<CONTENT>` headers must be unique. Cleanup/shutdown failures are reported explicitly and do not clear durable quarantine. If capture configuration has not materialized after accepted Cleanup, the same Cleanup remains pending and retains root ownership. All of this requires real endpoint fault injection to confirm actual target and TRACE32 state.

On 2026-08-25, Windows x86_64 preflight using the real binary above and historical adapter implementation `feb46173441d2225b522a03cfae2486031fb72c6d8170baf374038848dcb2293` completed with exit 0 and `tools_invoked=false`; after shutdown, no official t32mcp process remained. This record proves only that historical control-plane deployment/lifecycle boundary. It does not cover the current runtime bundle, which requires a fresh preflight. It must not be counted as an HIL pass, endpoint run, or board evidence; see [`t32mcp-driver-preflight-windows-x86_64-2026-08-25.json`](verification/t32mcp-driver-preflight-windows-x86_64-2026-08-25.json).

No practice tool was invoked in this round, and no TRACE32 endpoint/board capture or fault injection was executed. The deployment trust store defaults to deny; a production target adapter is admitted only after an administrator installs the exact policy and HIL receipt.

This round deliberately does not collect RTOS/Linux evidence, a second MCU platform, or real TASKEVENTS program-flow adapter/evidence. None can be inferred from the current SNOOPer PC statistical-sampling candidate.

Real-environment onboarding requires:

1. TRACE32 build, architecture package, license, and installation path.
2. Probe, MCU, core, trace pins, and board configuration.
3. ELF/MAP, Golden Firmware, workload, and RTOS information.
4. Manually preserved raw traces, function/Task/ISR exports, and TRACE32 native statistics.
5. Timestamp frequency, wrap rules, and observable overflow/flow-error fields.
6. Deployment trust-policy ID, signing-key ID, adapter scope, and signature/nonce/digest/scope negative tests.
7. The SHA-256 of the actual `t32mcp.exe`, `t32mcp v0.2.2` output, a driver-config snapshot, the exact tools inventory, matching runtime-manifest/config/profile/compiled digests, execution-lease exclusion, driver event replay/ambiguous negative tests, and child process-tree cleanup records. These are control-plane deployment evidence only and cannot substitute for the board evidence below.

The board configuration must also fix `probe_id`, the architecture package, the license-feature list, exact trace routing, and a laboratory capability-evidence file. The harness recomputes that file's SHA-256 when it loads the configuration and before every `doctor`/capture-evidence import. It rejects a replaced, modified, linked, or driver-digest-mismatched file.

Cross-platform acceptance results use `t32perf.hil-evidence/v1`; `hil/schemas/hil-evidence.schema.json` is indexed in the [schema catalog](schema-catalog.md). The default gate requires:

- At least two distinct boards, two distinct MCU families, two capture modes, and one non-empty RTOS.
- The current v1 harness requires both initial running and halted states and ten Sessions per board/mode in total. Production qualification instead requires at least ten Sessions for each board, mode, and initial state. Until the harness, schema, and matrix test enforce that stronger key, a v1 matrix cannot satisfy production qualification.
- Each current record binds TRACE32 release/build, but `CaptureEvidenceMatrix` treats it as fixed for one `board_id`. Production qualification also requires a separate release/build and adapter-profile coverage dimension for at least two exact TRACE32 versions. It must preserve physical board identity so aliases of one board cannot satisfy the two-board gate.
- `t32perf.hil-evidence/v1` binds manifest and health digests but not an explicit qualification receipt, admission snapshot, or signed capture-attestation identity. A production matrix must reject pre-admission Sessions and accept only fresh managed `perf_run` Sessions after the policy and receipt are installed.
- Every record binds deeply validated Session manifest/health SHA-256 values, plus the probe, architecture package, license, routing, and capability-evidence digest.
- Driver-reported board, mode, health, or coverage counts cannot replace evidence independently reconstructed by the host from Session artifacts.
