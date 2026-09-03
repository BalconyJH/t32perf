# Current Implementation Status and Verification Boundary

Status definitions:

- `IMPLEMENTED`: A production implementation and automated software tests exist in the repository.
- `HIL_PASS_DIAGNOSTIC`: A real-board HIL receipt passed, but its statistical/identity limits prohibit production admission.
- `SOFTWARE_ONLY`: Validated only with synthetic, golden, or mock evidence.
- `IN_PROGRESS`: Types or local components exist, but production end-to-end wiring is not complete.
- `UNVERIFIED`: Code or an interface exists, but no evidence exists for the specified real platform.
- `UNSUPPORTED`: The implementation explicitly rejects the case; it does not guess or use a workaround.

## Software capabilities

The provenance-bound `t32perf` binary also provides an `mcp` stdio mode. Its fixed-root,
fixed-limit service exposes eight bounded `perf_*` tools and drives Controller capture work
internally; it provides neither resources/prompts nor large-artifact transport. Raw JSON lines
are limited to 1 MiB, typed result envelopes to 256 KiB, and duplicated structured/text JSON
wire representations remain subject to the 1 MiB frame limit. It provides software-only
interface coverage, not TRACE32 or HIL evidence. The upstream three-tool `t32mcp` service and
the two sampling sidecars remain independent.

| Capability | Status | Notes |
|---|---|---|
| Versioned model and JSON Schema | IMPLEMENTED | manifest/state/capture config/attestation/trust policy/receipt/normalize/health/observation/dictionary/derived/analysis summary/stage/hotspots/comparison/report/static-RAM config, `instrumentation-overhead-evidence/v1`, Controller request/response v1/v2, sampling and intrusive-stack request/raw/profile/endpoint/journal/receipt evidence, abort/driver-event, and `t32perf.t32mcp-driver-config/v1` |
| Session lifecycle and locking | IMPLEMENTED | durable state, exclusive ownership, terminal failure; the TRACE32 driver additionally has a fixed root-wide OS execution lease and in-process registry; external perf and low-level Controller mutations share the same mutual-exclusion boundary |
| Immutable artifact store | IMPLEMENTED | staging ingest, atomic commit, SHA-256, append-only catalog, manifest consistency, quotas |
| Generic PC-sampling contracts and sidecar | IMPLEMENTED | separate two-tool MCP; Host-issued request/operation capability; loopback-only dedicated endpoint; shared root/Session locks; bounded append-only journal, explicit quarantine recovery, and Host capture receipt |
| Aggregate PC heatmap pipeline | IMPLEMENTED | strict `pc-hit-histogram/v1`; persisted quantitative policy; exact address projection; automatic bounded TRACE32 symbol-table labels for dominant ≤4-byte intervals in the ten hottest buckets; request-precommitted ELF assertion and `deployment_asserted` Host evidence for diagnostic function projection; canonical replay; bounded accessible SVG and explicit statistical/non-coverage semantics; debugger labels and generic ELF binding do not claim verified firmware or target-memory comparison |
| Flat PC flame presentation | IMPLEMENTED | `sampling flame` uses Takumi to render aggregate PC/function observations; its hierarchy is synthetic and never claims call-stack or caller/callee evidence |
| Intrusive stack-sampling contracts and sidecar | IMPLEMENTED | separate two-tool, endpoint-pinned MCP; exact acknowledgement and durable one-use attempt marker; verified single core 0; eight-frame/100 ms RCL/1 s walk bounds; pre/post clean TRACE32 ERROR integrity gate (only confirmed post-Go `#emu_noframe` reset); post-Go symbolization; owned-halt/cancellation cleanup; one-shot recovery-only process; raw leaf-to-root samples; exact journal/request/Host receipt; deterministic folded profile; and bounded Takumi SVG flame graph |
| Canonical observation NDJSON | IMPLEMENTED | streaming dictionary records, strict fields and ordering, exact error locations, 1 MiB line bound, independent dictionary-entry and physical-byte quotas |
| Explicit normalization | IMPLEMENTED | canonical/explicit CSV/C-wire single-source and 2..64-source K-way merge; TASKEVENTS+C-wire uses receipt-bound mapping, a shared-clock contract, and `reject_ambiguous_ties`; clock, tie, and dictionary conflicts all fail closed |
| External capture attestation | IMPLEMENTED | Ed25519 signature, operation nonce, request/observation/config digests, strict CaptureConfig, key configuration scope, and capability ceiling |
| Derived span NDJSON | IMPLEMENTED | streaming writer/reader, span invariants, and Session/provenance validation |
| Function/Task/ISR analysis | IMPLEMENTED | nested activation, preemption, virtual CPUs, health observations, bounded span draining, and a 1M ISR activation-state test |
| Health and metric support | IMPLEMENTED | fail-closed default capabilities, `resource_counters` support, versioned policy, diagnostic truncation gate |
| Analysis summary/stage | IMPLEMENTED | complete Artifact claims; tool/analyzer/policy/schema contracts; structurally prohibits non-valid quantitative payloads and hotspots |
| Hotspots, bounded summary, and compare | IMPLEMENTED | health-gated Top-N, resource/static rules, provider/core/capability provenance, health-policy/tool contract, cross-firmware-build policy; full comparison uses a 64 MiB-bounded content-addressed control artifact, while stdout returns only counts/Top-N/reference |
| Runtime resource counter | IMPLEMENTED | explicit semantics/subject, heap/stack/memory-region/trace-buffer groups, bounded aggregation for 1M Counter records, rate/fragmentation evidence gate, and invariant health facts |
| Resource input | IMPLEMENTED | `gnu-ld-map-v1` and bounded `elf-sections-v1` (Arm/AArch64/RISC-V/ELF32 little-endian Siemens TriCore; exact allocated+writable sections), exact `static_ram_config/v1` DMA/RTOS/custom classification, strict versioned resource-report schemas, per-kind totals/provenance, and bounded `gcc-stack-usage-v1` |
| Perfetto/Chrome Trace JSON | IMPLEMENTED | streaming/atomic output, subject-stable resource-counter tracks, JSON self-validation, golden/package smoke tests, and an `INVALID` diagnostic timeline |
| Official trace_processor import check | SOFTWARE_ONLY | Official v56.1 successfully imported a synthetic report on Windows x86_64; validator and direct shell query consistently reported slice/counter/track = 32/31/3; machine-readable evidence is archived |
| Synthetic provider/fixture | SOFTWARE_ONLY | Complete CLI loop; not hardware evidence |
| C99 target SDK | SOFTWARE_ONLY | no-heap wire, callbacks, null/SPSC transport, and host-compiler tests; no real MCU result yet |
| Python parser candidate | SOFTWARE_ONLY | streaming canonical-NDJSON candidate baseline; not the production parser |
| Release packaging | IMPLEMENTED | bundle, zip, tar.gz, two-layer SHA256SUMS, and dual archive smoke tests |
| Production maintenance control plane | IMPLEMENTED | Session-external `.t32perf-control`, deep inspection, default-redacted diagnostic bundle, content-addressed comparison, schema inventory, full Session retention, and SHA-256-confirmed abandon quarantine/restore for incomplete crash residue; whole-file inventory, journal, shared maintenance lock; no permanent purge |
| Release provenance/linkage | IMPLEMENTED | `t32perf.release-provenance/v1` binds commit/Cargo.lock/binary/target/toolchain/linkage; Windows MSVC static CRT and PE-import fail-closed audit; ZIP/tar smoke revalidation |
| HIL harness | IMPLEMENTED | independent deep validation, manifest/artifact audit, repeatability/overflow/native-differential contract |
| Generic sampling HIL contract | IMPLEMENTED | independent sampling-only board config (no target-adapter profile), bounded two-tool stdio MCP bridge, pre-mutation v2 endpoint/probe pin, endpoint/software/CPU recapture gates, direct no-follow Session/catalog/artifact audit, PASS/NOT_READY/FAIL receipt, and a PASS-only hardware test entry; deployment-specific evidence is not retained in the public repository |
| Real t32mcp deployment driver | IMPLEMENTED | fixed root configuration, official `0.2.2` executable SHA/version, runtime-only bundle/manifest/profile/compiled-digest validation, stdio initialize and exact three-tool inventory, 1 MiB raw JSON/64 KiB tool text/4 KiB frame bounds, Host-authoritative staging/accept, and four driver CLIs; `.t32perf-control/controller/trace32-driver-execution.lock` covers the complete version/init/tool/hook/replacement/cleanup lifecycle |
| Driver crash journal and recovery | IMPLEMENTED | reserved `t32perf.controller-driver-event/v1` append-only dispatch/fault/abort/workload events bind request/binding/abort plan; restart never repeats execute, blind collect, workload, fault, or abort/`END`; uncertain windows fail closed |
| Deployment workload/fault process control | IMPLEMENTED | workload and TRACE32 Stop disconnect each use SHA-bound direct argv, closed placeholders, empty stdout, bounded stderr/deadline, and process-tree kill; incomplete workload intent is not replayed, while a completed one may recover Stop; driver Export disconnect executes first, and only strict pending may force the exact child and permit a fully revalidated replacement to complete abort/confirm |
| Explicit Controller protocol/collector contract | IMPLEMENTED | profile and immutable target binding explicitly select `v1`/`v2_custom_events_export`; the V2 strict collector fixes C-wire v1, source/core/shared clock/transport/mapping/overhead artifact IDs/output bound/tie policy; Export is exact `[TraceExport, CustomEvents]` and the response is all-or-nothing; software contract tests cover positive and negative cases |
| Host V2 custom-event integration | IMPLEMENTED | six-stage prepare/accept, fixed non-Export evidence, ordered Export dual-output reservation/ingest, existing-first crash resume, public Controller surface, and two-phase abort are complete; mapping/overhead are fixed by receipt-bound provisioning, while capture config/receipt/manifest record typed instrumentation and accepted output identity; no production V2 profile exists |
| Instrumentation-overhead evidence contract | IMPLEMENTED | strict `t32perf.instrumentation-overhead-evidence/v1` document fixes method, transport, measurement method, baseline/instrumented duration, and positive event count; checked conversion binds catalog artifact ID to capture config; manifest provenance requires a registered `instrumentation_overhead` JSON input |

## TRACE32 and hardware capabilities

| Capability | Status | Current boundary |
|---|---|---|
| Fixed t32mcp skill/protocol | IMPLEMENTED | official execute/collect/abort exact handoff, binding-bound framed JSON, Controller-owned file outputs, root-wide durable single-flight, two-phase unbound abort receipt; strict pending permits partial content but requires unique headers; the real stdio driver requires exactly three tools from `tools/list`, persists observation before Host confirm on abort success; t32mcp remains a trusted single-tenant control plane |
| Generic Cortex-M PC sampling without trace IP | SOFTWARE_ONLY | separate two-tool MCP, immutable Host request, endpoint pin, bounded journal and recovery, aggregate quality gate, coarse address heatmap, optional bounded debugger labels, and Takumi flat presentation are implemented; no deployment-specific HIL receipt is retained |
| Intrusive Cortex-M stack flame graph without trace IP | SOFTWARE_ONLY | separate two-tool MCP, explicit intrusion acknowledgement, durable one-use attempt marker, bounded Break/frame-walk/Go loop, pre/post debugger integrity checks, Host ingest and folded-profile analysis, outer-boundary-aware Takumi rendering, and SVG audit are implemented; no deployment-specific HIL receipt is retained |
| TC234L SNOOPer CMM and build selection | SOFTWARE_ONLY | fixed TC234L/core 0, TRACE32 `R.2026.02.000190766` profile; explicit `controller_protocol=v1`, no collector, custom events/counters unavailable; configuration uses canonical ELF32 TriCore PT_LOAD→S3 and `Data.LOAD.S3record /DIFF`. Unknown release/build, firmware, or profile is rejected |
| `Trace.EXPORT.ASCII` parser adapter | SOFTWARE_ONLY | strictly accepts the fixed SNOOPer `ShowRecord/Address/CYcle/TIme.Zero/sYmbol` fields; binds Controller, ELF symbol range, profile, and qualification provenance; no endpoint raw fixture/natural differential yet |
| `Trace.EXPORT.TASKEVENTS` parser/mapping | SOFTWARE_ONLY | strict headers, Task/ISR/runnable state machine, ELF/ORTI/marker artifact-only mapping, and full profile-digest binding are implemented; Host can normalize accepted TASKEVENTS and a C-wire sidecar using a shared clock; TC234L SNOOPer produces no program flow, so the real flow adapter/export and RTOS evidence remain fail closed |
| capabilities/configure/start/stop/health/export/cleanup | SOFTWARE_ONLY | the target Controller fixes seven stages, strict typed/binding-bound evidence, initial-state CapabilitiesV2, root-wide capture lease, abort quarantine, and canonical recovery; no real endpoint success evidence |
| Automatic CaptureConfig and firmware provision | IMPLEMENTED | `controller provision-firmware` registers the fixed ELF; Controller measures and registers S3, then automatically materializes authoritative `CaptureConfigReady` after the accepted chain; its provenance binds ELF/S3, stage evidence, scenario, and qualification vector |
| Typed fault scenario and recovery | SOFTWARE_ONLY | `sampling_buffer_full`, TRACE32 Stop hook-first disconnect, exact child-handle driver Export disconnect, and CMM Start abort each have explicit event/failure/recovery contracts; driver disconnect executes Export first, final Host judgment records missed fault, and only strict pending may force; one-shot intent is not replayed and every replacement fully reloads/reverifies; production still requires exact HIL qualification and does not treat software injection as board fault evidence |
| Qualification trust/admission | IMPLEMENTED | deployment trust store → policy → HIL receipt → qualification receipt → Session admission snapshot is strictly validated end-to-end; production target adapters default deny until an administrator installs matching policy/HIL receipt |
| Overflow/flow-error health | SOFTWARE_ONLY | `SamplingBufferFull` has an independent contract; accepted typed health artifact ID/SHA-256 enters config/receipt provenance and drives the analyzer health gate. Flow-error and similar fields still lack build-gated device evidence |
| Cleanup | SOFTWARE_ONLY | cleanup restores the target to the fixed SNOOPer baseline; child cleanup failure is returned explicitly while durable Host/quarantine state remains. After accepted Cleanup, when capture config was not materialized, it still projects the same pending Cleanup and retains root ownership; the next accept performs only idempotent repair; no device recovery evidence |
| External capture host trust path | SOFTWARE_ONLY | normalize, signed attestation, and host-issued receipt are implemented; not validated by a real TRACE32 signer/HIL |
| TRACE32 target Controller | SOFTWARE_ONLY | request, CMM handoff, evidence, OS execution lease, durable event journal, recovery, artifact binding, and t32mcp deployment driver are implemented for the real TC234L SNOOPer candidate; external low-level/perf mutations share the execution lease; this release did not call the practice tool or a TRACE32 endpoint |
| ETM/ITM/DWT/MTB/TPIU/STREAM | UNVERIFIED | no real probe/MCU/board evidence |
| RTOS Awareness/ORTI/ARTI | UNVERIFIED | no real RTOS or multicore coverage evidence |
| Allocator hook and heap native statistics | UNVERIFIED | no proof that malloc/free hooks cover all allocator, ISR/reentrant, reset, and lost-event paths |
| RTOS/ISR/MSP/PSP watermark | UNVERIFIED | fill-pattern initialization timing, shared/dedicated stack boundaries, and consistency with native watermark are unverified |
| TRACE32 trace-buffer counter | UNVERIFIED | no evidence for real capacity/usage/overflow fields or build gate; reaching capacity is not inferred to mean overflow |
| Custom-event instrumentation provenance | IMPLEMENTED | receipt-bound deployment resource provisioning fixes mapping/overhead source, derived mapping, collector ID, and accepted V2 output; capture config/manifest/summary retain typed `instrumentation-overhead-evidence/v1`, measurement identity, static configure projection, and complete provenance. HIL/device overhead remains unverified |
| Resource/function timestamp alignment | UNVERIFIED | device clock alignment and instrumentation overhead between instrumentation counters and program-flow trace are unverified |
| Two MCU classes, two modes, one RTOS | UNVERIFIED | the platform matrix remains pending |

The executable SHA-256 of the current Windows official-mirror t32mcp v0.2.2 build candidate is `31f4983a4e7a60a5025e8334e95e6ecb4bd242ce6bc9705f81cdf081af05dec2`. It identifies only that exact build artifact; a different toolchain, target, or rebuild requires a new administrator-approved digest. Adapter implementation identity does not depend on that binary digest: the runtime-only manifest is recomputed file-by-file. Its canonical digest must equal the current config claim, installed profile, and compiled constant. Documentation and agent metadata do not participate in this identity.

On 2026-08-25, `controller driver-preflight` ran successfully on Windows x86_64 with that real binary and historical adapter implementation `feb46173441d2225b522a03cfae2486031fb72c6d8170baf374038848dcb2293`: exit 0, `tools_invoked=false`, and no official t32mcp process remained after shutdown. This limited evidence covers only that fixed config/binary/bundle combination, `--version`, MCP initialization, exact tool inventory, and child lifecycle. It did not call the practice tool; upstream did not establish an RCL; and it did not connect to a TRACE32 endpoint, probe, or board. The current runtime bundle has no checked-in preflight record. The machine-readable historical record is [`t32mcp-driver-preflight-windows-x86_64-2026-08-25.json`](verification/t32mcp-driver-preflight-windows-x86_64-2026-08-25.json).

Accordingly, the current release may be used for software development, format integration, candidate-adapter audit, a newly executed real-driver preflight, and offline Controller tests. It must not treat the archived historical preflight as a pass for the current bundle or present any preflight as proof that real TRACE32 performance numbers are correct, complete, or suitable for regression comparison. `controller driver-preflight` checks only version/init/tools-list/shutdown and never calls the practice tool; upstream establishes RCL only in a tool handler, so preflight neither connects to TRACE32 nor constitutes board evidence. The Controller V2/collector Host, resource, multi-output, and multi-source software wiring is complete, but no production V2/TASKEVENTS adapter exists. This release explicitly defers board/endpoint work, RTOS/Linux, the second platform, and real TASKEVENTS/custom-event adapter and runtime evidence.

Perfetto writer JSON self-validation and release-package smoke testing passed. On 2026-08-24, Windows x86_64 imported `target/perfetto-final/perfetto-final/report/trace.json` using `perfetto==0.57.2` and official `trace_processor_shell` v56.1: the full GitHub release asset and shell SHA-256 were verified against the release API and package manifest; `tools/validate_perfetto.py` and direct shell queries consistently reported slice/counter/track = 32/31/3, with zero nonzero warning/error statistics. The full record is [`perfetto-windows-x86_64-2026-08-24.json`](verification/perfetto-windows-x86_64-2026-08-24.json). Direct download from the package-pinned GCS URL still timed out, so the identical official v56.1 GitHub release asset was used. This proves only that the official importer on a Windows host can read this synthetic report; it is not evidence of TRACE32, MCU, RTOS, hardware-metric correctness, or cross-platform/UI stability.

## Synthetic analyzer benchmark

On 2026-08-23, Criterion on a Windows 11 x86_64 host (AMD Ryzen 7 8745H, Rust 1.95.0) measured:

```text
cargo xtask bench --extended
```

| Generated function events | Criterion time | Throughput |
|---:|---:|---:|
| 1,000,000 | 767.76–795.79 ms | 1.2566–1.3025 Melem/s |
| 10,000,000 | 7.7024–7.8182 s | 1.2791–1.2983 Melem/s |

This benchmark measures only the analyzer: it generates exact in-memory `FunctionEnter`/`FunctionExit` records and drains completed spans every 4096 records. It excludes the canonical NDJSON parser, disk I/O, Session hashing, TRACE32 export, and real trace decoding; it did not collect peak RSS or cross-platform samples. The result supports only the order of magnitude and approximately linear scaling of the current synthetic analyzer path on that host; it cannot be extrapolated to real TRACE32 artifacts or production hardware.

The 1M streaming test also verifies that the resident completed-span queue is bounded while draining. An independent 1M Counter test verifies that a single counter retains only constant aggregation state and bounded per-subject invariant state. The canonical parser additionally has a generated 1M-observation + 20,000-dictionary-definition input test for both the Rust parser and Python candidate: the test does not construct a complete file in the test process and independently checks dictionary-entry and physical-byte quotas; Python also checks process peak RSS below 128 MiB. None of these are evidence for real allocator/RTOS counter correctness, real TRACE32 dictionary distribution, or overhead. The 10M Criterion data does not replace multi-GiB files, RSS, or end-to-end benchmarks. Once real samples are available, parser, complete CLI pipeline, and native differential must still be rerun on Windows/Linux.

## Canonical parser same-input benchmark

On 2026-08-23, on the same Windows 11 x86_64 / AMD Ryzen 7 8745H / Rust 1.95.0 / Python 3.13.3 host, the production Rust canonical reader and Python candidate were run in release profile. Complete machine-readable evidence is [`windows-x86_64-2026-08-23.json`](benchmarks/windows-x86_64-2026-08-23.json).

```text
cargo xtask bench --input <observations.ndjson>
```

The workflow first release-builds the Rust example, then has `run_candidates.py` pre-read the input SHA-256 to establish identical warm-cache conditions. It runs Rust and Python once each in fixed order, externally samples child working sets every 100 ms, then recomputes SHA-256 and requires the input to be unchanged. The current gate therefore measures an explicitly defined warm-cache parser throughput, not cold-storage throughput. The table below is a historical record from before that contract was tightened; it does not claim SHA-256 pre/post integrity or warm-cache conditions and must not be compared directly with current gate values.

All three inputs are canonical NDJSON generated with `capture --provider synthetic`; each dictionary contains only 4 entries:

| Events | File bytes | Rust elapsed | Rust ev/s | Rust sampled peak WS | Python elapsed | Python ev/s | Python peak RSS |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000,000 | 185,636,063 | 3.0945 s | 323,158 | 5,337,088 B | 4.8402 s | 206,601 | 19,034,112 B |
| 10,000,000 | 1,886,354,813 | 34.1135 s | 293,139 | 5,357,568 B | 48.7857 s | 204,978 | 19,406,848 B |
| 20,000,000 | 3,803,542,312 | 64.0312 s | 312,348 | 5,365,760 B | 97.7688 s | 204,564 | 19,013,632 B |

The Rust working set is obtained by external polling every 100 ms in the benchmark workflow, so short-lived peaks may fall between sampling intervals; these figures are only lower bounds for visible peak usage. Python peak values are the candidate-reported Windows process peak working set; external-sampling results are also preserved in the evidence JSON. These are local records, not cross-platform statistics, and do not control OS page cache, CPU frequency, or background load.

This benchmark only reads, strictly validates, and counts the same synthetic canonical artifact. It excludes analysis, artifact hashing, output writes, TRACE32 export, and real trace decoding. It supports only the limited claim that, on this input on 2026-08-23, the Rust reader was faster and showed a smaller visible working set; it does not replace the current release gate. Automated scale tests cover a 20,000-entry dictionary, but the measured benchmark dictionary still has only 4 entries. It therefore cannot establish real TRACE32 parser mapping, very-large real dictionary performance, cross-platform RSS, or end-to-end production throughput.

The repository provides the manually triggered `.github/workflows/benchmark.yml`: it can generate optional 1M/10M synthetic canonical inputs on Windows/Linux, run same-input parser candidates, upload JSON, and run Criterion with a 10M case and upload artifacts. Every Windows/Linux package job for a release tag also runs the 1M candidate gate after `cargo xtask check`; failure blocks packaging/publishing. Machine-readable JSON is only a separate `performance-<OS>` workflow artifact and is not a release asset. The infrastructure is implemented, but the checked-in evidence currently consists only of the local Windows record above; no GitHub Linux run evidence is archived, so workflow existence cannot be treated as a completed cross-platform measurement.

## External inputs required for hardware acceptance

To promote related rows from `UNVERIFIED/UNSUPPORTED`, at minimum provide:

1. TRACE32 release/build, architecture package, license, and installation path.
2. Probe, MCU, board, covered cores, and trace routing.
3. Golden Firmware, ELF/MAP/ORTI/ARTI/stack-usage, and their digests.
4. Raw ASCII, TASKEVENTS, ISR/health evidence, and native statistics.
5. Clock frequency, wrap, same-tick ordering, and overflow/flow-error fields.
6. Ten initial-running and ten initial-halted runs, fault injection, disconnect recovery, and native differential results.
7. Passing records for at least two MCU classes, two capture modes, and one RTOS.

Resource observability additionally requires allocator-hook coverage, heap native statistics, Task/ISR/MSP/PSP watermarks, TRACE32 buffer capacity/usage/overflow, counter-to-function-trace clock alignment, and instrumentation overhead. Runtime peak, compiler static frame, call depth, and linker-MAP static RAM must be accepted separately; they must not be added together without synchronized sampling and an ownership contract.

See the [real TRACE32 integration runbook](trace32-runbook.md) for execution steps, and [hardware-verification.md](hardware-verification.md) and the [platform capability matrix](platform-capability-matrix.md) for evidence-archival requirements.
