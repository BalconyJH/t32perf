# TRACE32 / T32MCP Performance Observability System Development and Qualification Plan

This document is the current execution baseline and incorporates the implementation
progress that exists in the repository.

This plan is not a hardware qualification record. The following documents are the
authoritative live inventories for implementation and evidence:

- [Implementation status](docs/implementation-status.md)
- [Development-plan conformance matrix](docs/plan-conformance.md)
- [Verification evidence](docs/verification-evidence.md)
- [Platform capability matrix](docs/platform-capability-matrix.md)
- [Hardware verification boundary](docs/hardware-verification.md)

Generated packages are not authoritative plan sources. The existing `dist-final/` copy
predates parts of the current worktree and its release provenance has a null source commit.
Regenerate packages from a frozen source revision after this plan update.

## 1. Status Model and Current Conclusion

T32Perf uses independent delivery, evidence, qualification, and trace-health vocabularies:

| Vocabulary | State | Meaning |
|---|---|---|
| Delivery | `IMPLEMENTED` | Production-shaped code and automated software tests exist. |
| Delivery | `IN_PROGRESS` | A contract or local component exists, but the complete product path does not. |
| Delivery | `MISSING` | Required code, a production profile, or an input mapping does not exist. |
| Evidence | `SOFTWARE_VALIDATED` | Synthetic, golden, mock, host-tool, or host-compiler evidence passed. |
| Evidence | `EXTERNAL_EVIDENCE_REQUIRED` | A real TRACE32 build, probe, board, firmware, RTOS, endpoint, native differential, or external platform run is required. |
| Evidence | `ACCEPTED` | The exact phase exit criteria passed with retained evidence. |
| Qualification | `NOT_APPLICABLE` | The item is a host-only contract and has no target qualification state. |
| Qualification | `UNSUPPORTED` | The selected adapter explicitly rejects the capability. |
| Qualification | `CANDIDATE` | An exact implementation exists, but its production evidence is incomplete. |
| Qualification | `QUALIFIED` | Exact identity, HIL receipt, trust policy, repeatability, and native differential passed. |
| Trace health | `VALID / DEGRADED / INVALID` | Trust state of one capture only; never use these words as project-progress states. |

The current conclusion is:

- The host software foundation is broadly implemented and its repository workflow passes.
- The production Definition of Done is not met.
- No current record qualifies a real MCU, probe, RTOS, TRACE32 endpoint, or target-side metric.
- The next major iteration is laboratory qualification and evidence closure, not another
  generic host rewrite.
- The only current target candidate is TC234L/core 0 on TRACE32 build 190766 with SNOOPer
  statistical sampling and Controller V1. It is not `QUALIFIED`.

### 1.1 Current phase snapshot

| Phase | Delivery state | Evidence state | Qualification state | Main remaining gate |
|---|---|---|---|---|
| P0 Platform and data feasibility | `IN_PROGRESS` | `EXTERNAL_EVIDENCE_REQUIRED` | `CANDIDATE` | Real platform identity, raw trace, clock, fields, and native exports |
| P1 Interfaces and data contracts | `IMPLEMENTED` | `SOFTWARE_VALIDATED` | `NOT_APPLICABLE` | Real vendor input mapping remains dependent on P0/P2 |
| P2 TRACE32 capture adapter | `IMPLEMENTED` candidate path | `EXTERNAL_EVIDENCE_REQUIRED` | `CANDIDATE` | Real endpoint actions, repetitions, adapter-specific faults, and recovery |
| P3 Parser validation and selection | `IN_PROGRESS` | `SOFTWARE_VALIDATED` | `CANDIDATE` | Same real TRACE32 export, production program-flow/TASKEVENTS adapter, Linux evidence |
| P4 Timeline, hotspots, and Perfetto | `IMPLEMENTED` | `SOFTWARE_VALIDATED` | `CANDIDATE` | Real TRACE32 native differential and cross-platform/UI evidence |
| P5 t32mcp integration | `IN_PROGRESS` | `SOFTWARE_VALIDATED` | `CANDIDATE` | Skill/bundle rebinding, current-bundle preflight, practice-tool invocation, RCL, and endpoint run |
| P6 RTOS, ISR, and custom events | `IN_PROGRESS` | `SOFTWARE_VALIDATED` | `CANDIDATE` | Production V2 profile, RTOS/ISR transport, loss, and overhead evidence |
| P7 Stack, heap, and RAM | `IMPLEMENTED` host path | `SOFTWARE_VALIDATED` | `CANDIDATE` | Allocator, watermark, MAP/ELF, buffer, and clock differential |
| P8 Engineering and productionization | `IN_PROGRESS` | `SOFTWARE_VALIDATED` | `CANDIDATE` | HIL gate alignment, two MCU classes, two modes, one RTOS, and retained Linux evidence |

### 1.2 Current software verification snapshot

On 2026-08-26, `cargo xtask check` passed with the current worktree:

- Rust: 674 tests passed; no failures.
- Rust formatting, Clippy with warnings denied, documentation tests, and schema drift: passed.
- C99 SDK: 2 CTest tests passed.
- HIL software tests: 149 passed; 12 hardware tests were deliberately deselected.
- Python benchmark tests: 31 passed.
- Skill validation: passed.
- A separate source Markdown local-link scan passed; no broken local link was found.

`cargo-nextest` was not available in that local environment, so the repository-owned
workflow used its defined `cargo test --workspace --all-features` fallback. These results
prove the current software baseline only.

### 1.3 Retained evidence files

| Recorded | Evidence | Scope | Limitation |
|---|---|---|---|
| 2026-08-23 | Windows parser and analyzer benchmark | Synthetic host software | No real TRACE32 input or Linux result |
| 2026-08-24 | Official Perfetto v56.1 importer check | Windows x86_64 synthetic report | No hardware metric or UI stability claim |
| 2026-08-25 | Official-mirror t32mcp 0.2.2 preflight | Version, initialization, exact tool list, shutdown | Historical adapter digest; no tool invocation, RCL, TRACE32, probe, or board |

The exact records and their limitations are indexed in
[Verification evidence](docs/verification-evidence.md).

## 2. Product Objective

Build a TRACE32-based MCU performance-observation toolchain with a workflow comparable
to VizTracer. The product must provide:

1. A function execution timeline and nested call structure.
2. Function count, total time, self time, minimum, maximum, average, and hotspots.
3. An RTOS Task scheduling timeline.
4. ISR nesting and preemption relationships.
5. Custom instant, synchronous, asynchronous, and counter events.
6. Stack, heap, static RAM, and peak resource observations with explicit semantics.
7. Perfetto/Chrome Trace export and bounded machine-readable summaries.
8. Automated capture, validation, analysis, comparison, and artifact return through
   T32Perf and `t32mcp`.
9. Qualified adapters for different MCU classes, trace methods, and TRACE32 versions.

All quantitative output must retain its capture, firmware, clock, configuration, health,
and adapter provenance.

## 3. Scope

### 3.1 Production acceptance scope

The first production acceptance must include:

- Exact capability detection for each qualified target.
- Configure, start, stop, health, export, and cleanup with defined running and halted
  initial states.
- A complete program-flow method when the target supports it.
- An explicit sampling or instrumentation path when complete program flow is unavailable.
- Function, Task, ISR, health, hotspot, resource, and Perfetto outputs.
- One-command orchestration through the public performance facade.
- Versioned golden and native-differential evidence.
- At least two MCU classes, two capture modes, and one RTOS.
- At least ten independent Sessions for every accepted board × mode × initial-state group.
- Retained Windows and Linux build, test, and package evidence.

### 3.2 Implemented software scope

The repository already contains:

- A Rust 2024 host workspace and strict versioned contracts.
- An immutable Session and artifact store with quotas, digests, locks, and recovery.
- Streaming canonical NDJSON, multi-source merge, analysis, comparison, and Perfetto JSON.
- A heap-free C99 custom-event SDK and host C-wire reader.
- Runtime resource semantics plus GNU ld MAP, bounded ELF section, and GCC `.su` input.
- A fixed t32mcp skill, Controller transactions, a deployment driver, and a qualified-adapter
  admission model that defaults to deny.
- Windows/Linux CI and package workflows, HIL contracts, diagnostics, retention, and
  release provenance.

This scope is software-validated. It does not qualify target behavior.

### 3.3 Deferred or not claimed

The current release does not claim:

- A custom ETM packet decoder.
- A custom browser UI.
- Automatic capture of arbitrary function arguments or return values.
- Zero-configuration support for all MCUs.
- Cloud trace storage.
- Distributed time synchronization across boards.
- Ready, Blocked, Suspended, queue-wait, or mutex-wait RTOS states.
- Architecture-specific exception events beyond the current ISR model. Add a versioned
  mapping to `InterruptEvent` or a new event family before claiming this scope.
- Perfetto protobuf output.
- Real-time or near-real-time analysis.
- A production Controller V2 profile.

Add any of these through a new plan revision and an explicit contract. Do not add them as
an implicit extension of an existing adapter.

## 4. System Architecture

```text
Target MCU
├── ETM / ITM / DWT / MTB / target instrumentation
├── RTOS scheduling and ISR activity
└── Resource counters
          │
          ▼
TRACE32 PowerView
├── Hardware trace configuration
├── Program-flow decoding
├── Symbol and source resolution
├── RTOS Awareness
└── PRACTICE/CMM automation
          │
          ▼
t32mcp trusted control-plane executor
├── execute_practice_skill
├── collect_practice_skill_response
└── abort_practice_skill
          │ bounded status and file handoff
          ▼
T32Perf target adapter and Controller
├── qualified profile and bundle selection
├── capabilities → configure → start → stop
├── health → export → cleanup
├── workload/fault/recovery journal
└── Host-owned staging reservations
          │
          ▼
Immutable Session artifact store
├── capture config, request, receipt, and attestation
├── raw and normalized inputs
├── health and analysis-stage evidence
├── manifest and artifact catalog
└── reports and comparison references
          │
          ▼
Host processing pipeline
├── versioned input adapters
├── canonical observations
├── streaming analysis and health gate
├── Perfetto exporter
└── content-addressed comparison
          │
          ├──────────► Perfetto UI
          └──────────► CLI / t32mcp / AI agent
```

### 4.1 Architecture rules

- TRACE32 owns target trace acquisition, program-flow decoding, symbol resolution, and
  RTOS Awareness.
- T32Perf does not decode raw ETM packets.
- `t32mcp` is a control plane. It is not a large-data transport.
- Large data is written only to Host-reserved artifact paths.
- Every input enters through a versioned adapter and a strict configuration.
- Observation, analysis, and export models remain separate.
- All internal standard time is integer nanoseconds.
- No health uncertainty can be upgraded to an exact metric.
- Target adapters are selected by exact identity and qualification evidence.
- The production qualification trust store defaults to deny.
- Offline correctness remains the first requirement. Real-time work is deferred.

### 4.2 Controller protocol variants

- Controller V1 produces one fixed `TraceExport` output. The current TC234L SNOOPer
  candidate uses V1.
- Controller V2 produces the exact ordered pair `[TraceExport, CustomEvents]` and binds a
  strict collector, shared clock, counter mapping, tie policy, and overhead evidence.
- V2 is an explicit profile choice. It is not an automatic migration from V1.
- No production V2 profile exists in the current repository.

## 5. Technology Decisions

The original plan was language-neutral. Repository evidence has now resolved the main
choices:

| Component | Current decision | Evidence boundary |
|---|---|---|
| Target event SDK | C99, heap-free wire protocol | Host compiler tests only; real MCU validation required |
| TRACE32 automation | PRACTICE/CMM | Exact target/build qualification required |
| Host Controller, Session, parser, analysis, CLI | Rust 2024 | Revalidate with real exports and retained Linux results |
| Parser candidate comparison | Rust production path and Python stdlib candidate | Current retained benchmark is synthetic Windows evidence |
| HIL and benchmark orchestration | Python with uv | Harness correctness is not hardware correctness |
| Output | Streaming Perfetto/Chrome Trace JSON | Protobuf remains deferred |
| UI | Perfetto | No custom UI in the first release |
| MCP integration | Keep upstream `t32mcp` core unchanged | Use the exact upstream three-tool surface and a fixed skill |

Accepted decisions are documented in:

- [ADR 0001: Rust for the Host](docs/adr/0001-host-language.md)
- [ADR 0002: Layer Observations and Derived Models](docs/adr/0002-parser-architecture.md)
- [ADR 0003: Perfetto/Chrome Trace JSON](docs/adr/0003-perfetto-format.md)
- [ADR 0004: Keep the t32mcp Core Unchanged](docs/adr/0004-mcp-integration.md)

### 5.1 Decision gates that remain open

- Select the capture method independently for each qualified target.
- Revalidate parser throughput and memory with the same real TRACE32 input on Windows
  and Linux.
- Add Perfetto protobuf only if real trace size or import cost proves that JSON is not
  sufficient.
- Add real-time transport only after the offline path passes hardware acceptance.
- Introduce a separate MCP service only if the fixed skill and file-artifact model cannot
  meet measured concurrency or lifecycle requirements.

## 6. Phase Plan

### P0 — Platform and Data Feasibility

Estimated new-target effort: 1 week, subject to laboratory access.

Required work:

- Fix the MCU, core, board, trace pins, probe, TRACE32 release/build, license, and
  architecture package.
- Determine ETM, ITM, DWT, MTB, TPIU, STREAM, and RTOS Awareness capability.
- Build and identify the Golden Firmware.
- Capture and retain the first valid raw trace.
- Export function, Task, ISR, and health samples.
- Fix timestamp units, wrap behavior, same-tick order, and health fields.

Required deliverables:

```text
docs/platform-capability-matrix.md
golden-firmware/
sample-trace/
sample-functions.*
sample-task-events.*
sample-isr-events.*
```

Current progress:

- `SOFTWARE_VALIDATED`: archival contracts, strict HIL board/evidence configuration,
  qualification schemas, and a fixed TC234L SNOOPer candidate exist.
- `MISSING`: the planned real sample function, Task, and ISR export files do not exist.
- `EXTERNAL_EVIDENCE_REQUIRED`: both platform-matrix rows remain pending and unverified.

Exit gate:

- At least one complete raw trace reloads repeatedly.
- ELF, function, and source mapping are correct.
- One exact capture path is selected.
- Clock and health interpretation are fixed from device evidence.
- Real parser inputs are retained with digests and provenance.

P0 is not accepted.

### P1 — Interfaces and Data Contracts

Estimated original effort: 1 week.

Required scope:

- Session lifecycle, manifest, health, capture config, receipt, attestation, and errors.
- Canonical observations and derived data.
- CLI, performance facade, Controller, and artifact boundaries.
- Version compatibility, migration policy, and path security.

Current progress:

- `IMPLEMENTED`: model types, JSON Schemas, strict JSON, Session state machine, immutable
  artifact catalog, manifest validation, health policy, Controller V1/V2, resource reports,
  comparison artifacts, and release provenance.
- Schema generation and drift checks are part of `cargo xtask check`.
- A migration inventory exists. No old Session major exists, so no migration edge is
  registered. An in-place no-op migration is prohibited.

Exit gate:

- Schemas validate automatically.
- Components depend only on explicit contracts.
- Schema families have explicit major-version behavior.
- A real vendor trace maps to the canonical model through a qualified P0/P2 adapter.

P1 software delivery is complete. Real mapping remains a P0/P2 gate.

### P2 — TRACE32 Capture Adapter

Estimated new-target effort: 2 weeks after P0.

Fixed script surface:

```text
perf_get_capabilities.cmm
perf_configure.cmm
perf_start.cmm
perf_stop.cmm
perf_get_health.cmm
perf_export.cmm
perf_cleanup.cmm
```

`perf_get_hotspots.cmm` is a compatibility façade that returns
`HOST_PROCESSING_REQUIRED`. Health-gated Host analysis is the only authoritative hotspot
aggregator.

Required behavior:

- Detect capability and select only a qualified mode.
- Configure buffer or stream, timestamp, filter, and trigger.
- Define behavior for initial running and halted states.
- Start, stop, export, collect health, and restore known capture state.
- Detect every health and fault signal declared by the selected adapter. Record unavailable
  signals as `UNSUPPORTED`; never infer them from a different counter or fault.
- Return machine-readable status only. Write large data to artifacts.

Current progress:

- `IMPLEMENTED`: seven-stage Host Controller, typed evidence, prepare/accept/status,
  two-phase abort, automatic capture config, firmware provisioning, root-wide single-flight,
  deployment driver, crash journal, process-tree control, and typed fault/recovery contracts.
- `SOFTWARE_VALIDATED`: the TC234L SNOOPer `R.2026.02.000190766` candidate fixes core 0,
  firmware conversion, profile identity, and V1 behavior.
- The TC234L capability ceiling is exact: `samples=statistical`; `function_events`,
  `context_switches`, `interrupt_events`, `custom_events`, and `counters` are unavailable.
- The TC234L candidate explicitly does not support `trace_overflow` or `flow_error`.
  `sampling_buffer_full` remains a candidate fault until exact HIL evidence exists.
- `EXTERNAL_EVIDENCE_REQUIRED`: no practice tool or TRACE32 endpoint action has passed.

Exit gate:

- The same workload succeeds at least ten times for each board × mode × initial target
  state without cross-Session contamination.
- Running and halted initial states each have retained results.
- Every adapter-declared fault is induced and independently detected. Unsupported faults
  remain explicit. Before a broad product claim, the qualified adapter portfolio must include
  retained overflow and flow-error evidence from modes that can produce those signals.
- TRACE32 and driver disconnect, CMM abort, recovery, and cleanup pass.
- Failures have machine-readable codes.
- AREA and MCP output stay bounded.

P2 is not accepted.

### P3 — Parser Validation and Production Selection

Estimated original effort: 1 to 2 weeks.

Required work:

- Run at least two parser candidates on the same inputs.
- Read real TRACE32 exports with bounded memory.
- Handle nested functions, Task, ISR, malformed data, truncation, and unknown fields.
- Select adapters by exact TRACE32 release/build and qualified profile.
- Keep parser output independent from Perfetto.

Current progress:

- `IMPLEMENTED`: the Rust streaming canonical parser, exact error locations, independent
  dictionary-entry and physical-byte quotas, deterministic output, strict versioned adapters,
  and 2-to-64-source K-way merge.
- `SOFTWARE_VALIDATED`: a Python stdlib candidate and Windows synthetic 1M, 10M, and
  multi-GB evidence support the current Rust decision.
- Strict SNOOPer ASCII and TASKEVENTS parser/mapping contracts exist.
- `MISSING`: a production program-flow/TASKEVENTS adapter and natural endpoint fixture.
- `EXTERNAL_EVIDENCE_REQUIRED`: same real export, native differential, and retained Linux
  benchmark evidence.

Exit gate:

- ADRs remain valid after real-data revalidation.
- Memory is bounded by stream state, dictionaries, and configured limits, not file size.
- Corrupt input reports an exact location and reason.
- Repeated runs are deterministic.
- Exact release/build selection is proven with real fixtures.

P3 host selection is software-complete but not externally revalidated.

### P4 — Function Timeline, Hotspots, and Perfetto MVP

Estimated original effort: 2 weeks.

Required output:

- Function intervals and call depth.
- Inclusive, self, minimum, maximum, average, and count metrics.
- Task ownership and ISR preemption.
- Health-gated hotspots.
- Perfetto function, Task, ISR, counter, and warning tracks.

Current progress:

- `IMPLEMENTED`: streaming analysis, nested activation, preemption, virtual CPU time,
  health-gated quantitative output, bounded summaries, atomic Perfetto JSON, and an
  end-to-end synthetic golden.
- `SOFTWARE_VALIDATED`: official Perfetto v56.1 imported and queried one Windows synthetic
  report successfully.
- `EXTERNAL_EVIDENCE_REQUIRED`: real TRACE32 function and CPU differential, Linux importer,
  and UI stability evidence.

Native consistency gate:

- Function count must match exactly.
- Total time error must not exceed `max(0.5%, one timestamp tick)`.
- Self, minimum, maximum, and average must meet the approved differential policy.
- Negative duration and invalid nesting are prohibited.
- ISR execution must not be charged to the preempted Task.
- Non-`VALID` input must not produce trusted hotspots or a regression verdict.
- The output must import successfully in the approved Perfetto tool.

P4 is not hardware-accepted.

### P5 — t32mcp Integration

Estimated original effort: 1 to 2 weeks.

Integration rule:

- Keep the upstream `t32mcp` core unchanged.
- Use `skill-trace32-perf` and fixed PRACTICE script names.
- Use only `execute_practice_skill`, `collect_practice_skill_response`, and
  `abort_practice_skill` upstream tools.
- Return status, health, bounded summaries, manifest paths, and artifact references.
- Never transport a complete large trace through MCP text.

Public T32Perf facade:

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

The first seven names are the original planned façades. `perf_run` is the eighth, closed
provision-to-report orchestration. None of these names is an upstream t32mcp tool.

Current progress:

- `IMPLEMENTED`: the typed Host public facade, immutable Controller transactions,
  Host-authoritative staging/accept, the real stdio deployment driver, strict tool inventory,
  execution lease, bounded transport, durable journal, and crash-safe abort/recovery.
- `IMPLEMENTED`: the Host surface and its user-facing skill expose all eight operations, including
  `perf_run`. Skill documentation and agent metadata are deliberately outside the runtime adapter
  digest. Editing guidance therefore requires normal validation but does not change the admitted
  adapter implementation. Only changes to manifest-listed runtime inputs require a new profile,
  compiled implementation digest, HIL fixture, and deployment qualification.
- `SOFTWARE_VALIDATED`: the 2026-08-25 real-binary preflight verified t32mcp 0.2.2
  initialization and tool inventory, then shut down cleanly.
- The preflight used a historical adapter digest and does not cover the current bundle.
  Use the machine record and current status page for exact digests; do not copy an old digest
  into a deployment configuration.
- The record has `tools_invoked=false` and `trace32_connection_attempted=false`.

Automated acceptance sequence:

1. Check capability.
2. Configure trace.
3. Start capture.
4. Run the workload.
5. Stop capture.
6. Collect health.
7. Export data.
8. Run cleanup, restore known capture state, close the Controller transaction, and
   materialize authoritative `CaptureConfigReady`.
9. Normalize and attest the captured data.
10. Analyze, produce a bounded summary, and create the Perfetto report.
11. Return artifact references.

Exit gate:

- Repeat preflight against the current bundle.
- Execute the practice tool through the managed driver.
- Establish RCL and connect the exact TRACE32 endpoint.
- Complete the sequence above on qualified hardware.
- Retain driver journal, Session, HIL receipt, and native-differential evidence.

P5 is not endpoint-accepted.

### P6 — RTOS, ISR, and Custom Events

Estimated original effort: 2 weeks.

Minimum RTOS scope:

- Running Task, Task switch, Task ID/name, priority, core, and idle time.

Minimum ISR scope:

- Enter, exit, number/name, priority, nesting, preempted Task, and functions in ISR context.

Minimum custom-event scope:

```text
instant
begin
end
counter
async_begin
async_end
```

Current progress:

- `IMPLEMENTED`: observation and analysis semantics, nested ISR/preemption, C99 wire SDK,
  C-wire reader, loss/gap health, Controller V2 dual-output path, receipt-bound custom-event
  mapping, shared-clock merge, and instrumentation-overhead provenance.
- `MISSING`: a production Controller V2 profile.
- `EXTERNAL_EVIDENCE_REQUIRED`: RTOS Awareness/ORTI/ARTI, real ISR nesting, target transport,
  event loss, timestamp alignment, and measured instrumentation overhead.

Exit gate:

- Task switches match RTOS reference data.
- ISR nesting and preempted ownership match native data.
- Custom counters display in Perfetto.
- Event loss is detected.
- The report records the exact instrumentation method and measured overhead.

P6 software is implemented. Hardware acceptance is not complete.

### P7 — Stack, Heap, and RAM Observability

Estimated original effort: 2 weeks.

Required sources can include:

- RTOS watermark, fill pattern, MSP/PSP sampling, compiler stack usage, and call depth.
- Allocator hooks, RTOS heap API, allocator statistics, wrappers, and periodic samples.
- ELF, MAP, and exact linker sections for static RAM.

Required separation:

- Call depth is not byte-level stack use.
- Runtime peak is not compiler static frame size.
- Static RAM, heap, Task stack, ISR stack, trace buffer, and custom regions remain separate.
- Values are not added without an ownership and synchronization contract.

Current progress:

- `IMPLEMENTED`: explicit counter semantics and subjects, bounded resource aggregation,
  heap/stack/trace-buffer invariants, rate and fragmentation gates, GCC `.su`, GNU ld MAP,
  bounded supported-architecture ELF sections, strict report schemas, comparison, and
  Perfetto counter tracks.
- `EXTERNAL_EVIDENCE_REQUIRED`: allocator native statistics, RTOS watermarks, MSP/PSP,
  real MAP/ELF differential, trace-buffer fields, device-clock alignment, and target overhead.

Exit gate:

- Heap peak matches independent allocator statistics.
- Task stack matches RTOS watermark.
- Static RAM matches the approved MAP/ELF interpretation.
- Reports preserve every resource class separately.
- Resource counters align with the function timeline under a measured clock contract.

P7 is not hardware-accepted.

### P8 — Engineering and Productionization

Estimated original effort: 3 to 5 weeks after the target path is stable.

Required scope:

- Multiple MCU and TRACE32-version adapters.
- Windows and Linux build, package, and installation.
- Explicit schema migration edges when old major versions exist.
- Retention, crash-residue quarantine, logs, diagnostics, and backup.
- Performance regression gates.
- Repeatable HIL.
- Documentation, examples, release provenance, and security review.

Current progress:

- `IMPLEMENTED`: CI and release workflows, verifiable zip/tar packages, release provenance,
  Windows static-CRT audit, content-addressed comparison, bounded diagnostics, complete-Session
  retention, incomplete-Session abandon quarantine/restore, HIL contracts, documentation site,
  benchmark regression tooling, and security bounds.
- `SOFTWARE_VALIDATED`: local Windows evidence exists.
- `EXTERNAL_EVIDENCE_REQUIRED`: successful retained Linux CI/package evidence, two MCU classes,
  two modes, one RTOS, and production target receipts.
- `IN_PROGRESS`: the single-board repeatability test runs ten captures for each initial
  state, but the current multi-board matrix runs ten captures per board/mode in total. Before
  a production HIL run, change the matrix gate to ten captures for each board × mode ×
  initial-state group and align its schema, tests, and documentation.
- `IN_PROGRESS`: each HIL capture records an exact TRACE32 release/build, but the current matrix
  treats that value as fixed for one `board_id`. It cannot qualify multiple TRACE32 versions on
  the same physical board without changing the board identity. Add a separate version/profile
  coverage dimension without allowing aliases to count one physical board twice.
- `IN_PROGRESS`: `t32perf.hil-evidence/v1` binds Session manifest and health digests but has no
  explicit qualification receipt, admission snapshot, or signed capture-attestation identity.
  It cannot distinguish pre-admission characterization from a fresh admitted `perf_run` Session.
- `IN_PROGRESS`: the current `v*` tag workflow builds packages and publishes them directly after
  software checks. It does not consume a digest-bound security approval or a protected release
  environment. It cannot prove that published archives are the exact reviewed candidate.

Exit gate:

- At least two MCU classes, two capture modes, and one RTOS pass.
- At least two exact TRACE32 versions pass through admitted version-specific adapter selections.
- Common failure scenarios have exact diagnostics and recovery evidence.
- HIL runs are repeatable and archived.
- Windows and Linux packages run without a development environment.
- A user can install, configure, capture, analyze, validate, and open the report.
- The input-immutable security and qualification review approves the exact frozen packages and
  protected evidence set.
- The protected publisher consumes the approved candidate archives without rebuilding them and
  verifies that every published digest equals the approval record.

P8 is not production-accepted.

## 7. Quality and Test Strategy

### 7.1 Repository-owned workflow

Inspect the workflow before execution:

```text
cargo xtask --help
```

Run the complete software check:

```text
cargo xtask check
```

The workflow owns formatting, Clippy, Rust tests, documentation tests, schema drift,
CMake/CTest, software-only HIL, Python benchmark tests, and skill validation.

### 7.2 Unit and contract tests

Tests must cover:

- Parser fields, limits, exact error location, clock conversion, wrap, and ordering.
- Call-stack reconstruction, self time, Task/ISR ownership, and resource aggregation.
- Schema identity, strict JSON, state transitions, paths, quotas, and digests.
- Controller sequence, qualification, transport bounds, crash journal, and recovery.

### 7.3 Golden tests

The required chain is:

```text
TRACE32 export
    ↓
canonical observations
    ↓
analysis and health
    ↓
Perfetto output and hotspots
```

The current end-to-end golden uses the synthetic provider and fixes the size and SHA-256
of each public artifact. It is software evidence only. Add a separate versioned golden for
each accepted real export format. Do not replace the synthetic golden with a hardware file.

### 7.4 Native differential

Compare Host results with TRACE32 native statistics for:

- Count, total, self, minimum, maximum, and average.
- Task CPU and ISR CPU time.
- Static RAM, allocator state, and RTOS watermark where applicable.

Store the raw native result, normalized result, policy, tolerance, and verdict.

### 7.5 Fault injection

Cover independently:

- Overflow, FIFO/buffer full, flow error, truncation, wrap, and ELF mismatch.
- TRACE32 disconnect, driver disconnect, CMM abort, and process timeout.
- Disk quota, output permission, unknown export version, and malformed response.
- Crash windows before and after execute, collect, workload, abort, and Host confirmation.

Software fault contracts do not count as hardware fault evidence.

### 7.6 Performance tests

Cover:

- 1 million and 10 million observations.
- At least one multi-GB input.
- Deep call stacks.
- High-frequency Task switches, ISR boundaries, counters, and custom events.
- Windows and Linux parser, end-to-end pipeline, and packaging runs.

Use `cargo xtask bench --input <canonical.ndjson>` for same-input parser comparison and
`cargo xtask bench --extended` for the analyzer workload matrix. Preserve the input digest
before and after each run.

## 8. Trace Health Gate

All quantitative conclusions pass through the health gate.

```text
VALID
├── hotspots and timing are permitted
├── strict comparison is permitted
└── baseline admission is permitted

DEGRADED
├── a constrained diagnostic timeline is permitted
├── every gap must be visible
└── strict comparison is prohibited

INVALID
├── trusted hotspots are prohibited
├── regression judgment is prohibited
└── diagnostic output only
```

Severe conditions include:

- Trace overflow or flow error.
- Unexplained timestamp discontinuity.
- Unclosed or impossible program flow.
- ELF/firmware mismatch.
- Severe Task-context loss.
- Truncated raw input.
- Ambiguous cross-source ordering.
- Missing or invalid qualification/capture provenance.

## 9. Security and Artifact Management

The product must enforce:

- An explicit artifact root and normalized portable paths.
- No `..` traversal, links, reparse points, or arbitrary file reads.
- Portable Session and artifact identifiers.
- Per-line, per-file, dictionary, Session, and control-document quotas.
- SHA-256 for files and immutable provenance edges.
- Create-new and atomic publication. Existing Sessions are never overwritten.
- A terminal Session state that cannot be mutated.
- Separation between user input, Controller staging, Session artifacts, and control data.
- Bounded MCP JSON, tool text, framed status, stderr, polling, and deadlines.
- A root-wide execution lease and append-only effect journal.
- Signed external capture attestation and administrator-controlled adapter qualification.
- Recoverable retention and quarantine. No implicit permanent purge.

See the [security model](docs/security.md) and
[operations guide](docs/operations.md) for the normative boundary.

The release security gate is mandatory: no open `Critical` or `High` finding can pass freeze or
release. A `Medium` or `Low` risk needs joint acceptance by the named release owner and security
reviewer, with impact, rationale, compensating controls, accountable owner, and an expiry date or
review trigger. The final input-immutable review rejects an expired, triggered, indeterminate, or
incomplete acceptance.

## 10. Release Milestones

Feature implementation and release acceptance are separate. A later feature set does not
implicitly satisfy an earlier hardware gate.

| Milestone | Intended content | Software state | Acceptance state |
|---|---|---|---|
| R0 Technical PoC | Manual trace, export, minimal Perfetto | Host path exists | Not accepted: no real trace evidence |
| R1 Function MVP | Automated CMM, function timeline, hotspots, health | Software implemented | Not accepted: no real native differential |
| R2 System Timeline | Task, ISR, and custom events | Host and SDK implemented | Not accepted: no RTOS/ISR/custom-event hardware evidence |
| R3 Resource Observability | Stack, heap, and RAM | Host path implemented | Not accepted: no native resource differential |
| R4 Production | Multi-platform, HIL, packages, documentation | Software foundation implemented | Not accepted: platform/RTOS/Linux evidence missing |

## 11. Plan Iteration Ledger

This ledger reconstructs logical development iterations from repository artifacts. It is
not a commit history and does not invent release dates.

| Iteration | Scope added or resolved | Result | Open boundary carried forward |
|---|---|---|---|
| I0 — Architecture and decisions | Language-neutral scope, accepted Rust/observation/Perfetto/t32mcp ADRs | Established artifact-first and streaming boundaries | Revalidate decisions with real exports and Linux |
| I1 — Session, artifact, and schema foundation | Durable lifecycle, locks, no-follow paths, atomic artifacts, digests, quotas, versioned schemas | P1 software contract became verifiable | Real vendor mapping and future explicit migration edges |
| I2 — Canonical ingestion and normalization | Strict NDJSON, exact errors, dual dictionary quotas, CSV/C-wire, 2-to-64-source K-way merge | Deterministic bounded parsing became verifiable | Real vendor inputs and Linux measurement |
| I3 — Analysis, health, comparison, and Perfetto | Function/Task/ISR reconstruction, health gates, bounded comparison, atomic Perfetto, golden pipeline | P4 host path became verifiable | Native differential and real report evidence |
| I4 — Resource observability | Explicit resource identity, runtime counters, MAP/ELF, GCC `.su`, comparison and tracks | P7 host path became verifiable | Device resource and clock evidence |
| I5 — Capture trust and provenance | Strict CaptureConfig, Ed25519 policy, nonce/digests, receipt, attestation, overhead provenance | Unverified external input can no longer enter analysis as trusted data | Real signer, endpoint, and HIL capture |
| I6 — Controller protocol and V2 integration | Seven-stage Controller, prepare/accept, abort, exact dual output, custom-event provisioning | P5/P6 Host control path became verifiable | Production V2 profile and endpoint execution |
| I7 — Qualified adapter and deployment driver | TC234L candidate, exact bundle/profile selection, qualification trust, stdio driver, journal and recovery | A production-shaped candidate exists and defaults to deny | Current-bundle preflight and laboratory qualification |
| I8 — Production controls and release readiness | Maintenance control plane, package provenance, CI, regression gate, HIL contracts, strict documentation | Current software baseline became auditable | Hardware, Linux, native differential, and current-bundle evidence |
| I9 — Laboratory qualification and production acceptance | Current planned iteration | Not started because required external inputs are absent | Complete the gates below |

## 12. Iteration I9 Execution Plan

### 12.1 Entry conditions

Provide and identify:

1. Two MCU classes, boards, probes, trace routing, and covered cores.
2. Two capture modes and one RTOS.
3. Every exact TRACE32 release/build, architecture package, license, and installation in the
   qualification matrix. The P8 matrix includes at least two TRACE32 versions.
4. Golden Firmware, ELF, MAP, ORTI/ARTI, stack-usage files, and digests.
5. Approved t32mcp 0.2.2 binary and all source inputs for the candidate adapter bundle.
6. Laboratory capability evidence and an administrator-installed qualification policy.
7. Workload, fault hooks, native-statistics collection, and evidence output locations.
8. Named release owner, security reviewer, qualification reviewer, and protected evidence
   locations.

### 12.2 Work package A — Complete the candidate implementation and characterization

- Inventory every board × capture-mode × TRACE32-version tuple in the acceptance matrix.
- Implement and register a candidate production adapter for each tuple. Provide exact candidate
  selections for at least two TRACE32 versions. Candidate registration is not qualification.
- Add `perf_run` to the hash-bound skill and atomically recompute the adapter manifest, profile,
  compiled implementation digest, HIL fixtures, deployment examples, and current-digest
  documentation before any preflight or qualification run.
- Add a production Controller V2 profile for each accepted path that requires the custom-event
  sidecar. Bind its collector, clock, counters, tie policy, and overhead contract explicitly.
  TASKEVENTS or ISR export alone does not require Controller V2.
- Keep unsupported outputs explicit in the adapter capability record. For example, the TC234L
  SNOOPer V1 candidate cannot produce TASKEVENTS, ISR, or custom-event evidence. Another
  candidate adapter and mode must provide those outputs before the related product claims pass.
- Align the HIL schema, coverage key, matrix test, and documentation with the ten-per-board,
  mode, and initial-state gate.
- Extend the HIL contract so physical `board_id` remains stable while exact TRACE32
  release/build and adapter profile form a separate coverage dimension. Require at least two
  version dimensions, and prevent aliases of one physical board from satisfying the two-board
  gate.
- Extend the production HIL contract to bind the qualification receipt, admission snapshot, and
  signed capture attestation for each accepted Session. Keep candidate evidence separate, and
  reject it from the post-admission repeatability matrix.
- Use authorized characterization runs to retain raw trace and each declared output. These can
  include SNOOPer ASCII, TASKEVENTS, ISR, health, and native-statistics exports. Do not require
  an output from an adapter that declares it unavailable. Do not count characterization runs as
  production qualification.
- Fix headers, columns, clocks, wrap, symbol mapping, and same-tick order.
- Add versioned golden fixtures and exact adapter selection.
- Run Rust and Python candidates on the same real input on Windows and Linux.
- Pass all profile, adapter-selection, bundle, HIL-contract, and negative-capability tests.

### 12.3 Work package B — Complete the pre-freeze security review

- Review endpoint commands, configuration, imported artifacts, path handling, process control,
  trust stores, signing keys, receipts, logs, and package provenance as release trust boundaries.
- Verify least privilege, no-follow path handling, bounded inputs, secret redaction, fail-closed
  qualification, signature verification, and cleanup after every tested failure.
- Review the dependency set and release workflow for known vulnerabilities, license conflicts,
  and untrusted build inputs.
- Split release automation into an immutable candidate-build stage and a protected publish stage.
  Define a strict approval record that binds the source commit, archive digests, release
  provenance, evidence-set digest, findings, and risk acceptances. The publisher must consume the
  same candidate artifacts and must not rebuild them. Until this gate exists, classify the direct
  `v*` tag workflow as development-only and block it from production publication.
- Apply the release security gate in [the security model](docs/security.md). Fix every `Critical`
  and `High` finding, document any jointly accepted `Medium` or `Low` risk, and re-run the complete
  repository workflow before approval to freeze.

### 12.4 Work package C — Freeze, build, package, and preflight

- Freeze an immutable committed source revision only after work packages A and B pass.
- Build the release package from that revision and require a non-null source commit in release
  provenance.
- Upload the immutable candidate archives and their digest set without publishing a production
  release.
- Run `controller driver-preflight` against the exact release executable, configuration, bundle,
  and profile. Archive all digests and the preflight record.
- Run repository checks and package smoke tests on Windows and Linux.
- Verify that no stale process remains. Do not count preflight as RCL or target evidence.
- Make no source or bundle change after this point. Any required change returns the iteration to
  work package A or B, creates a new immutable revision, and invalidates all downstream evidence.

### 12.5 Work package D — Close P0, P2, and P3 on the frozen candidate

- Connect each exact endpoint and execute the practice tool from the frozen package.
- Capture from running and halted initial states.
- Run at least ten repetitions for each board × mode × initial-state group.
- Induce every fault supported by the selected adapter, plus TRACE32 disconnect, driver
  disconnect, and CMM abort. Use another candidate adapter and mode for overflow or flow error
  when the selected adapter declares that signal unsupported.
- Prove cleanup and recovery without Session contamination.
- Retain all declared raw, structured, health, and native-statistics outputs and validate them
  against the frozen mappings and fixtures on Windows and Linux. A mismatch returns the work to
  package A; do not patch the frozen candidate.

### 12.6 Work package E — Close system and resource evidence

- Compare Task and ISR results with RTOS/TRACE32 native data only on adapters that provide the
  required events. Collect the required differential from at least one such adapter before the
  Task/ISR claims can enter final qualification.
- Measure custom-event transport loss and instrumentation overhead on the frozen Controller V2
  candidate path. Do not use the TC234L SNOOPer V1 candidate for this gate.
- Compare heap peak with allocator statistics.
- Compare stack use with RTOS watermark and MSP/PSP evidence.
- Compare static RAM with MAP/ELF interpretation.
- Prove resource/function clock alignment.
- Import representative real reports with the approved Perfetto tool on Windows and Linux.

### 12.7 Work package F — Close production evidence

- Archive the successful Windows and Linux checks, packages, and package-smoke records from the
  frozen revision.
- Run the candidate qualification suite for each exact adapter/profile and generate its HIL
  verification receipt.
- Generate each qualification receipt, bind it to the HIL receipt by SHA-256, and install the
  administrator-approved policy and receipt in the production trust store.
- After admission, use the managed driver and public `perf_run` path to create a fresh production
  Session for every production adapter. Run capabilities, configure, start, workload, stop,
  health, export, cleanup, signed capture attestation, normalize, analyze, convert, and summary.
  Retain the admission snapshot and every artifact digest. A pre-admission Session cannot satisfy
  this gate.
- Build the production repeatability matrix only from fresh admitted Sessions. Cover two MCU
  classes, two modes, one RTOS, at least two exact TRACE32 versions, and at least ten repetitions
  for each board, mode, and initial state.
- Generate evidence-derived capability, implementation-status, and DoD reports in the protected
  release evidence set. Do not edit the frozen source or hand-edit `dist-final/`.

### 12.8 Work package G — Complete the input-immutable P8 release review

- Verify the exact frozen packages, digests, trust policy, attestations, receipts, HIL evidence,
  external-platform records, dependency review, and accepted risks without changing the source,
  bundle, configuration, package, or evidence.
- Enforce the release security gate: reject any open `Critical` or `High` finding and any expired,
  triggered, indeterminate, incomplete, or singly approved `Medium` or `Low` acceptance.
- Create the final approval record bound to the immutable release revision, exact candidate
  archives, release provenance, and protected evidence-set digest. Creating this record must not
  mutate any reviewed input.
- If the review finds a required change, reject the candidate, return to work package A or B,
  freeze a new revision, and repeat all affected downstream checks and evidence collection.

### 12.9 Work package H — Publish the reviewed candidate

- Require the protected production environment and its administrator approval.
- Download only the candidate archives referenced by the final approval record.
- Recompute and verify archive, provenance, and evidence-set digests before publication.
- Publish those exact bytes without checkout, rebuild, repack, or generated-file edits.
- Retain the release identity and published-asset digests. Any mismatch rejects publication.

### 12.10 Iteration exit

Iteration I9 completes only when:

- All applicable P0–P8 exit gates have retained evidence.
- Every production adapter is admitted by an exact qualification snapshot.
- Every production adapter has a fresh, retained, admitted `perf_run` Session; no
  characterization or pre-admission Session is counted as production evidence.
- All repository checks and package smoke tests pass on Windows and Linux.
- The protected release evidence set contains an updated DoD report with no
  `EXTERNAL_EVIDENCE_REQUIRED` item.
- The exact frozen candidate has retained input-immutable security and qualification approvals.
- Every published asset digest equals the final approval record; no publish-stage rebuild occurred.

## 13. Risks and Controls

| Risk | Effect | Control |
|---|---|---|
| Hardware or license access is delayed | P0 and every downstream acceptance gate stop | Schedule the laboratory and freeze exact assets before the iteration starts |
| Adapter/profile/bundle digest drift | A preflight or receipt can refer to old code | Recompute and bind all digests; never reuse historical evidence |
| Publish rebuilds or substitutes a reviewed archive | Security approval no longer covers released bytes | Protected publish consumes only digest-bound candidate artifacts and performs no build |
| Vendor export fields change | Parser can silently mis-map data | Exact release/build selection and strict unknown-field rejection |
| Clock or same-tick order is ambiguous | Task/ISR/function attribution becomes invalid | Explicit rational clocks, tie policy, and fail-closed merge |
| Synthetic evidence is mistaken for hardware evidence | False production claim | Keep implementation and evidence axes separate in every report |
| Linux workflow exists but is not retained | Cross-platform support remains unproven | Archive the actual CI/package record and its digests |
| Resource values overlap or use different clocks | RAM totals or peaks become false | Preserve resource classes and require ownership/synchronization contracts |
| Perfetto JSON becomes too large | Import time or storage cost increases | Measure real traces before adding a separate protobuf exporter |
| Crash recovery repeats a physical side effect | Duplicate start, workload, abort, or cleanup | Append-only intent/effect journal and strict no-replay rules |

## 14. Production Definition of Done

| Requirement | Delivery | Evidence | Qualification | Required final evidence |
|---|---|---|---|---|
| Capability detection through conversion is automated | `IMPLEMENTED` | `SOFTWARE_VALIDATED` | `CANDIDATE` | Qualified endpoint run of the complete sequence |
| Health determines trustworthiness | `IMPLEMENTED` | `SOFTWARE_VALIDATED` | `CANDIDATE` | Hardware fault mappings |
| Function statistics meet the native tolerance | `IMPLEMENTED` | `EXTERNAL_EVIDENCE_REQUIRED` | `CANDIDATE` | TRACE32 native differential |
| Task and ISR attribution is correct | `IMPLEMENTED` | `SOFTWARE_VALIDATED` | `CANDIDATE` | RTOS/MCU native differential |
| Perfetto opens reliably | `IMPLEMENTED` | `SOFTWARE_VALIDATED` | `NOT_APPLICABLE` | Representative real reports on approved host platforms |
| Large traces use streaming processing | `IMPLEMENTED` | `SOFTWARE_VALIDATED` | `NOT_APPLICABLE` | Real multi-GB Windows/Linux benchmark evidence |
| MCP does not transport complete large traces | `IMPLEMENTED` | `SOFTWARE_VALIDATED` | `CANDIDATE` | Bound verification during endpoint HIL |
| At least two target platforms and one RTOS | `IN_PROGRESS` | `EXTERNAL_EVIDENCE_REQUIRED` | `CANDIDATE` | Host-verified HIL matrix, SHA-256-bound qualification receipt, and signed capture attestation |
| Multiple TRACE32 versions use exact adapters | `IN_PROGRESS` | `EXTERNAL_EVIDENCE_REQUIRED` | `CANDIDATE` | Version-aware HIL matrix and admitted adapter selection for at least two exact releases/builds |
| Final security and qualification review passes | `IN_PROGRESS` | `EXTERNAL_EVIDENCE_REQUIRED` | `CANDIDATE` | Input-immutable approval of the exact frozen packages, digests, trust policy, and protected evidence set |
| Production publish preserves reviewed bytes | `IN_PROGRESS` | `EXTERNAL_EVIDENCE_REQUIRED` | `NOT_APPLICABLE` | Protected publish record whose asset digests exactly match the final approval; no rebuild |
| Windows and Linux are supported | `IMPLEMENTED` workflow | `SOFTWARE_VALIDATED` | `NOT_APPLICABLE` | Retained successful Linux CI/package record |
| HIL is repeatable | `IN_PROGRESS` | `SOFTWARE_VALIDATED` | `CANDIDATE` | Aligned matrix gate and repeated laboratory run |
| Artifacts trace to ELF, configuration, and capture parameters | `IMPLEMENTED` | `SOFTWARE_VALIDATED` | `CANDIDATE` | Verify the chain on each accepted target |
| Installation, use, and troubleshooting documentation is complete | `IMPLEMENTED` | `SOFTWARE_VALIDATED` | `NOT_APPLICABLE` | Re-run strict docs and package smoke after acceptance updates |

Production DoD is not complete.

## 15. Planning Estimates

The original estimates assumed two full-time engineers and part-time embedded/TRACE32
support:

| Phase | Original cumulative position |
|---|---:|
| P0–P1 | Weeks 1–2 |
| P2 | Weeks 3–4 |
| P3 | Week 5 |
| P4 | Weeks 6–7 |
| P5 / R1 | Week 8 |
| P6 | Weeks 9–10 |
| P7 | Weeks 11–12 |
| P8 / R4 | Weeks 13–18 |

These estimates remain useful for a new target integration. They are not an estimate of
remaining calendar time. Iteration I9 depends on hardware, licenses, laboratory scheduling,
real exports, and administrator qualification decisions. Re-estimate it only after all
entry conditions are scheduled.

## 16. Final Execution Order

```text
Freeze exact external platform and laboratory assets
    ↓
Implement candidate adapters, Controller profiles, the HIL gate, and real-input fixtures
    ↓
Complete the pre-freeze security review, fixes, and repository checks
    ↓
Freeze an immutable committed source revision
    ↓
Build and smoke-test Windows/Linux packages; preflight the exact current bundle
    ↓
Qualify endpoint capture, recovery, clocks, exports, and parser mappings
    ↓
Validate function, Task, ISR, resources, and Perfetto against native evidence
    ↓
Complete two-MCU / two-mode / one-RTOS HIL matrix
    ↓
Bind HIL and qualification receipts; verify signed capture attestations
    ↓
Complete the input-immutable security and qualification review
    ↓
Publish the exact reviewed candidate through the protected environment
    ↓
Publish the protected evidence set and start the next plan revision
```

This order prevents a host-only implementation from becoming a hardware claim. It also
prevents a candidate adapter, synthetic fixture, preflight, or configured CI job from being
used as a substitute for the exact evidence required by the production gate.

## 17. Plan Update Protocol

For each plan iteration:

1. Collect the retained evidence and identify the next iteration boundary.
2. Update the plan, evidence cutoff, and P0–P8 delivery, evidence, and qualification states in
   a mutable working tree.
3. Link machine-readable evidence. Do not replace evidence with prose.
4. Update the critical path and remove work only after its exit gate passes.
5. Re-run `cargo xtask check`, the source local-link check, and package-content tests.
6. Freeze a committed source revision only after the plan, code, contracts, and documentation
   are stable.
7. Generate release packages from that exact revision and require a non-null source commit.
8. Never hand-edit generated package copies or reuse evidence from a different digest.

A plan or evidence-index edit after qualification creates a new source revision. Do not relabel
an earlier package as that revision. Record whether the new revision requires repeated preflight,
security review, package checks, or hardware evidence.
