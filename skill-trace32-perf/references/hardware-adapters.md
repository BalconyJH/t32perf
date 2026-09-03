# TRACE32 Hardware Adapter Boundary

Read this document for capabilities, configure, start, stop, workload, hardware health, cleanup, or structured Task/ISR export.

## Confirmed generic-layer capability

The fixed generic CMM layer performs only these two file exports confirmed by official documentation:

- `Trace.EXPORT.ASCII <file>` exports raw trace text.
- `Trace.EXPORT.TASKEVENTS <file>` exports Task-event CSV when a trusted adapter has verified that ELF and ORTI are loaded.

The generic layer does not choose the trace method, source, sink, buffer, streaming mode, timestamp, filter, or trigger. It does not start, stop, or restore the target; read hardware health; or control a workload. These behaviors vary by architecture, SoC, probe, license, RTOS awareness, and TRACE32 build.

Successful export proves only that TRACE32 wrote a file. It does not prove field mapping, time base, trace completeness, or capture claims.

## Implemented real-driver boundary

The Host implements an official t32mcp `0.2.2` stdio driver. It reads strict `t32perf.t32mcp-driver-config/v1` only from `ROOT/.t32perf-control/deployment/t32mcp-driver.json` and verifies before every operation:

- the official executable's absolute plain-file identity, exact SHA-256, and exact `t32mcp v0.2.2`;
- exact MCP-initialize server identity/version and exactly the three tools `execute_practice_skill`, `collect_practice_skill_response`, and `abort_practice_skill`;
- every member digest in the runtime-only adapter manifest and its canonical bundle digest;
- four-way equality among config, manifest, installed-profile `implementation_sha256`, and compiled candidate.

`controller driver-preflight` runs only this version/initialize/tool-inventory check and shuts down. It neither calls a PRACTICE tool nor connects TRACE32. Real operations use `controller drive`, `controller drive-transaction`, and `controller abort-upstream`; upper-level callers no longer construct execute/collect/stage/accept/abort loops themselves.

Each public driver command holds a non-blocking root-wide OS execution lease on a fixed empty plain lock file for its full lifecycle, with a same-process canonical-root registry covering platform locking differences. This complements durable root capture ownership reconstructed by the Host from immutable artifacts. Before initial/replacement-child startup and every execute, collect, abort, workload/fault hook, or forced-child-disconnect side-effect boundary, the driver fully reloads and revalidates deployment and requires equality with that lease's initial admission.

The driver's only external commands are optional `workload` and `trace32_disconnect_at_stop`. Both use direct argv/no shell, closed placeholders, independent executable SHA-256, bounded output/timeout, and terminate the complete process tree on timeout or failure. On Unix, success also waits for the dedicated hook process group to become empty; trusted hooks must not move descendants into another session or process group. `trace32_disconnect_at_stop` is hook-first and does not execute Stop first. `driver_disconnect_at_export` is not an external hook: the driver executes Export once; only strict pending permits force-disconnecting the exact owning t32mcp child tree and starting exactly one fully revalidated replacement solely for official abort and immediate Host confirm. A bounded final must be staged unchanged and judged fault-missed by the Host.

Implementing the driver does not automatically grant hardware trust. Stage every bounded final wrapper, including a malformed frame, as original bytes for Host accept; only accepted versioned evidence may advance a hardware phase.

## Crash-safe real control and fault injection

The driver records `dispatch_intent`, `fault_intent`, `fault_triggered`, `abort_attempt`, `abort_success_observed`, `workload_intent`, and `workload_complete` in strict deterministic append-only `t32perf.controller-driver-event/v1` artifacts. These markers bind exactly to the immutable request and relevant abort/workload context. They supply only Host side-effect intent/observation, not adapter evidence, accepted responses, or confirmed abort receipts.

All external side effects are at most once:

- After `dispatch_intent`, if the process is interrupted, do not execute again or blindly collect through a new child; perform two-phase abort and quarantine only for the original transaction.
- With `workload_intent` and no `workload_complete`, do not rerun the workload hook.
- With `fault_intent` and no `fault_triggered`, do not redo the fault or abort without proof. Continue one abort lifecycle only if both a durable abort plan and `fault_triggered` exist.
- With `abort_attempt` and no `abort_success_observed`, the upstream `END` outcome is ambiguous and a second abort is prohibited. With a success marker, perform Host confirm only.

The hardware order for the three closed faults is fixed:

1. `trace32_disconnect_at_stop`: write fault intent and abort plan, fully revalidate deployment, then run the external TRACE32-disconnect hook first. On success write triggered, then perform official abort/confirm. Do not run ordinary Stop CMM or forge a Stop response.
2. `driver_disconnect_at_export`: write dispatch intent and execute Export once. Only a strict pending header, optionally with partial content but without `<FINISHED>`, permits fault intent/abort-plan persistence, full revalidation, and forced disconnection of the exact owning child. After triggered is written, revalidate fully again and start one abort-only replacement. Stage every bounded final and let the Host produce `CONTROLLER_FAULT_ACTION_NOT_OBSERVED`; do not inject another disconnect.
3. `cmm_abort_at_start`: write fault intent and dispatch intent, execute the fixed abort-target CMM, then establish the plan, write triggered, and continue official abort only after the exact abort marker. Pass a non-marker final to the Host unchanged.

Cleanup rejection, cleanup-evidence mismatch, or any result that cannot prove adapter-owned state restoration requires confirmed abort, a terminal failed Session, and durable endpoint/target quarantine. If Cleanup is accepted but authoritative capture-config materialization is interrupted by a crash, the Host retains the original Cleanup transaction as repair-pending and root ownership remains held. Only idempotent `controller accept` may repair config; do not start later Hotspots or a new capture.

## Target-adapter responsibility

A trusted target adapter defines with fixed code and versioned configuration:

```text
capabilities
configure
start / stop
workload ownership
export mode and exact field mapping
hardware health
cleanup of adapter-owned state
capture attestation signing
```

An adapter must emit auditable evidence:

```text
trace32_release
trace32_build
architecture_package
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
firmware_identity
clock_identity
```

A caller request, producer string, ordinary JSON, or CMM success frame cannot substitute for evidence.

## Operation gates

| Operation | Minimum condition | On failure |
|---|---|---|
| capabilities | Connected TRACE32, target, probe, and an adapter for the known build | `UNSUPPORTED_NEEDS_TRACE32` |
| configure | Target-specific fixed implementation validated by HIL | `UNSUPPORTED_NEEDS_TRACE32` |
| start/stop | Adapter defines initial running/halted state, timeout, disconnect, and failure recovery | `UNSUPPORTED_NEEDS_TRACE32` |
| workload | Controller holds the probe/Session lock and has fixed seed/termination | Stop the request; never substitute sleep or a caller statement. |
| raw ASCII export | A trusted adapter stopped capture and output is a Controller-owned staging path | `UNSUPPORTED_NEEDS_TRACE32` on export failure |
| Task-event export | Raw-export condition plus verified ELF/ORTI | `UNSUPPORTED_NEEDS_TRACE32` |
| normalize | A real fixture freezes field, clock, origin, quality, and order mapping | Host returns unsupported/error; never guess a mapping. |
| hardware health | Build-gated schema plus overflow/flow-error HIL fixture | `UNSUPPORTED_NEEDS_TRACE32` |
| cleanup | Adapter proves modified capture state and materializes strict capture config | Two-phase abort + quarantine for rejection/incomplete evidence; repair-pending original transaction when config is not ready after accepted cleanup; never delete Session files. |

The repository includes an executable candidate for TC234L SNOOPer statistical sampling: fixed CMM, real TRACE32 Controller request/response binding, S3 firmware measurement, strict ASCII mapping, a seven-stage state machine, real t32mcp driver, recovery quarantine, and closed fault scenarios are implemented. It does not have production admission: the deployment trust store rejects it by default, and an administrator must install an exact policy and provision a strict qualification/HIL receipt. Other targets fail closed. Synthetic and local-driver tests prove only the software loop, not MCU/probe/RTOS/TRACE32 capability evidence.

## TC234L build 190766 candidate

The repository contains a software candidate exactly bound to discovered deployment facts: TRACE32 `R.2026.02.000190766`, TriCore package, `TC234L`, core 0, 30 MHz JTAG, DUALPORT, `INTERFACE.NAME()=="PowerDebug PRO"`, debug/cable serial, and an ELF with SHA-256 `7daae3ae027ab270c30de38530f83458a682d3e13c45deb69217048d8f449798`. `t32perf.target-adapter-profile/v1` records the complete root/adapter-bundle digest, build range, target/probe, two initial states, scenario-specific capacity/config digest, and fault point. A candidate without a qualification receipt cannot enter the production registry.

This combination is not a program-flow adapter: the product device and license have no MCDS feature. The fixed implementation uses `SNOOPer` PC/RealTime/Stack and declares only statistical samples; function boundaries, context switches, ISR, flow errors, and TASKEVENTS flow export are unavailable. The Controller derives canonical sparse Motorola S3 from the registered exact ELF and runs `Data.LOAD.S3record <controller-path> /DIFF` during Configure/Health. This S3 contains only physical `PT_LOAD` segments, so runtime RAM/BSS is not treated as firmware image. `immutable-pflash-crc32.json` is a legacy bundle input and is not authoritative for current runtime firmware identity.

The raw ASCII export is fixed as `t32perf.trace32-ascii-profile/tc234l-build190766-v1`:

```text
SNOOPer.EXPORT.Ascii <controller-path> Address CYcle %TimeFixed TIme.Zero sYmbol /ShowRecord
```

Do not fall back to bare `Trace.EXPORT.ASCII <file>`, because official command output columns and order are determined by `<items>` and omission inherits mutable display settings.

Host `trace32_snooper_ascii_v1` accepts only a complete accepted normal Controller capture. Exact profile/release/build/architecture/target/adapter/qualification, accepted export artifact, StopV2 `recorded_records`, HealthV2, and exact firmware ELF must agree. Symbol ranges derive from the registered ELF; the mapping artifact binds health, stop, qualification, and ELF digest. The parser does not guess columns, address class, or time units.

## Ed25519 deployment trust

An adapter that passes HIL cannot gain host trust from a producer name alone. Deployment must:

1. configure an independent Ed25519 signer for the adapter; its private key must not enter the skill, artifact root, t32mcp AREA, or a caller request;
2. maintain a `t32perf.capture-trust-policy/v1` public-key allowlist in read-only configuration, resolving a preconfigured policy ID to a fixed path through the Controller;
3. scope every key to exact provider, adapter/version, mode, target, TRACE32 identity, clock, allowed cores, and capability ceiling;
4. have the signer sign only Session/request/observation bytes, strict capture config, and claims that it actually verified;
5. use host `session attest` for signature, scope, nonce, and digest verification.

A signed attestation remains untrusted input until verification. An MCP request must not provide a policy path, policy JSON, public key, or other trust-root material directly. Adding a caller-provided key to policy or passing a caller path to `session attest --policy` changes the deployment trust root and is not an ordinary request operation.

## Task, ISR, and ARTI/ORTI

ORTI profiling depends on the OS writing internal variables or a task-ID register and requires the corresponding ORTI description. Some hardware cannot cover every core simultaneously. ARTI profiling additionally requires an ECU description, instrumented trace hooks, and a Lauterbach ARTI module linked to the application.

`task_events_elf_orti_verified` means only that a trusted adapter verified ELF and ORTI; it is not a switch that lets CMM guess current state. Generic-layer support has not confirmed the ARTI MDF export command, so do not present it as supported.

The Host implements a strict TASKEVENTS profile/mapping contract (closed fields, ELF range mapping, profile digest, and provenance). However, TC234L SNOOPer does not produce program-flow/RTOS events, and this iteration does not advance RTOS/Linux or on-board flow evidence; this profile therefore cannot select TASKEVENTS export. A future flow adapter must register separately with a real raw fixture, ELF/ORTI-load evidence, mapping, and HIL.

`trace32_task_events_v1` additionally requires accepted `task_events_exported` runtime binding, a strict mapping artifact owned by the deployment-qualification stage, exact profile SHA-256, ELF digest/ranges, ORTI metadata artifact provenance, timestamp clock, and capture-config equality. Its parser/mapping software contract is implemented, but it remains structurally unsupported without a qualified flow adapter.

## Trace integrity and summary

With FIFO full, flow error, truncation, or an unexplained gap, exact function/Task/ISR metrics cannot be trusted. Sampling may produce statistical hotspots, but never exact call counts, nesting, or duration.

The generic script does not read GUI `Trace.STATistic` text. Without a build-gated parser and real fixture, hardware health remains unknown/unsupported. Host-analyzer health judges normalized-stream integrity and does not automatically prove probe/TRACE32 capture health.

Return quantitative results to MCP only through host `summary --top N`. `INVALID` returns no quantitative data; large data is exposed only as manifest/artifact references.

## HIL gate

Before production policy accepts an adapter key, require at least:

- ten consecutive captures from each initial running and initial halted state;
- the expected fail-closed result in the host health/recovery receipt for every supported fault scenario;
- a differential against TRACE32 native statistics only if the adapter claims exact function, Task, or ISR metrics; a sampling-only adapter must not invent such claims;
- a unique Session per run, no artifact reuse, and no pollution of extra directories;
- manifest/attestation binding to TRACE32 build, target, firmware, clock, request digest, and covered cores;
- a strict HIL receipt for every admission scenario in scope. Runtime evidence across MCU, RTOS/Linux, and a second capture mode is a future extension, not an existing fact for the TC234L sampling candidate.

This iteration has not called a t32mcp PRACTICE tool or connected TRACE32 or a target board. The HIL gate is therefore a pending admission requirement; RTOS/Linux, a second platform, and TASKEVENTS program-flow/ELF/ORTI hardware-flow evidence remain deferred.

## Official material

- [General Commands Reference Guide T, Release 02.2026](https://www2.lauterbach.com/pdf/general_ref_t.pdf)
- [TRACE32 Release History](https://repo.lauterbach.com/release_history.html)
- [ORTI-Compliant Profiling of AUTOSAR Classic Platform](https://repo.lauterbach.com/autosar_profile_cp_orti.html)
- [ARTI-Compliant Profiling of AUTOSAR Classic Platform](https://repo.lauterbach.com/autosar_profile_cp_arti.html)
- [OS and RTE Profiling for TriCore AURIX](https://repo.lauterbach.com/publications/os_and_rte_profiling_for_tricore_aurix.pdf)
