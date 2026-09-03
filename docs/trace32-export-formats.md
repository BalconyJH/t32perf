# TRACE32 Text Export Format Contracts

This document freezes the TRACE32 text formats accepted by host adapters. An adapter does not read TRACE32's default display settings, infer columns, or accept unregistered event or cycle tokens.

## Evidence Basis

- Local TRACE32: Release February 2026, `R.2026.02.000190766`, build `190766`.
- `general_ref_t.pdf` SHA-256: `06c831ef3c1f84a7a811d75affaf4889d44b1e81db594be512dda1b497912251`.
  - Page 208: `Trace.EXPORT.Ascii` is whitespace-delimited; column order follows the `<items>` command order, and `/ShowRecord` adds the trace record.
  - Page 220: `Trace.EXPORT.TASKEVENTS` emits task-event CSV; `/TRaceRecord` adds trace-record information.
- `app_timing_tools.pdf` SHA-256: `5e25e9eb50d00c40f381c5cf0ed056eea1a1833ab661d881f3986df6b3f5630d`.
  - Pages 4 and 19 show the three-semantic-column format without `/TRaceRecord`.
  - Pages 6 and 7 define the closed event set: `activate`, `schedule`, `start`, `stop`, `terminate`, `preempt`, `resume`, `wait`, `release`, `switch`, `runnablestart`, `runnablestop`, `isrstart`, `isrend`.
- The vendor sample bundled with the release, `demo/etc/trace/export.taskevents/temp.csv`, SHA-256: `492cc4cc481f699c56e2cb0dda03afaa167549b8d10e82b02a0edcdceb1bffed`.

The parser compatibility key uses the repository-wide canonical identity: `trace32_release="2026.02"`, `trace32_build=190766`, and `architecture_package="tricore"`. The complete `VERSION.SOFTWARE()==R.2026.02.000190766` value and TC234L target identity are verified exactly by the target-adapter profile. The parser key neither duplicates target identity nor introduces a second release spelling with the `R.` prefix.

## SNOOPer ASCII v1

Format ID: `trace32.export-ascii/snooper-single-core-show-record-address-cycle-time-zero-symbol/v1`.

The fixed command is:

```text
SNOOPer.EXPORT.Ascii <file> Address CYcle %TimeFixed TIme.Zero sYmbol /ShowRecord
```

The adapter uses the `SNOOPer` command group directly and does not modify the current global `Trace.METHOD`; this prevents mutually overwriting trace methods such as ART. Offline syntax checking with build `190766` proves that the full command parses. Adding `/NoDummy` returns `unknown command`, so v1 explicitly excludes that option. The Rust constant `TRACE_ASCII_EXPORT_ITEMS_V1` stores only the fixed items/options after `<file>`.

After sampling stops, the fixed adapter must run `SNOOPer.ZERO SNOOPer.FIRST()` before export. The Host must also treat the accepted StopV2 artifact as time-origin evidence. Independently, the parser requires the first sample's `TIme.Zero` to be exactly `0ns` and all subsequent times to be nondecreasing. Together, these checks prevent an incorrect adapter from presenting a TRACE32 global ZERO as the Session origin. The x86 simulator's default first time is `2.144468900s`; it proves only the raw dialect and cannot be normalized as Session timing input.

Physical lines are parsed in this order: `ShowRecord`, `Address`, `CYcle`, `TIme.Zero`, optional `sYmbol`. `ShowRecord` must be a signed decimal without `.` or `|` suffixes and must be strictly consecutive between lines. At EOF, the trusted host also requires the actual sample count to exactly equal StopV2 `recorded_records`; deleting a middle line, truncating complete trailing lines, or forging the stop count therefore fails. The TC234L profile is constrained by `CORE.NUMBER()=1` and injects `core_id=0` from configuration; it does not parse the empty `Run` column of single-core SNOOPer. The first four columns are separated by one or more ASCII whitespace characters. `sYmbol` consumes the remaining tail, so paths, `+offset`, and spaces in demangled symbols do not break column boundaries. Vendor CRLF and LF are accepted only in the vendor-text line mode; canonical NDJSON still accepts LF only.

This profile accepts only the official SNOOPer `CYcle=snoop` and emits only `Quality::Statistical` `Sample` records. It does not infer function entry/exit, Task/ISR context switches, or exact execution time from PC samples. Function attribution uses only deployment-owned ELF `[start,end)` address ranges, resolved through an O(log n) predecessor lookup. `sYmbol` is used only for exact conflict checking and audit; it never heuristically strips `+offset`. If no range exists, the address is retained with `function_id=None`. The target profile closes the permitted TRACE32 address classes: the x86 simulator fixture uses `C:`, while the build-`190766` TC234L simulator is frozen as `P:`.

For local build `190766`, the actual CRLF export source from an independent TRACE32 x86 simulator has SHA-256 `d5ab7417b37ae42a36640472fc47fb581d5eed93d42b2659fd92d2c966b1290d`. The repository stores the identical content with normalized line endings in `snooper-x86-simulator-build190766.txt`, SHA-256 `9d43ce61656b54ab6784180f174ee7d6d9ca21083b27ce32e88a36fd959a95af`; tests restore CRLF before parsing. It proves the ASCII dialect and parser shape, not TC234L board evidence.

The independent simulator export from the same build using `t32mtc` + `SYStem.CPU TC234L` contains 14,698 records and has SHA-256 `957b878e41e79394205316add324b42819791f8f0a331f560b304844f9fbe091`. The repository stores the first three records with normalized line endings in `snooper-tc234l-simulator-build190766.txt`, SHA-256 `a91bb88e39a23f85fe15387350e71979df6c27eb1199497299036c468bc5017b`. This evidence freezes the TC234L profile's `P:` address class, no `Run` column, `CYcle=snoop`, and path-style symbols; simulator timestamps are not on-board timing evidence.

## TASKEVENTS v1

Format ID: `trace32.export-taskevents/time-name-event-no-trace-record/v1`.

The adapter requires a four-line header: an equal-length `#` rule, a title, `# time(ns); task name; event;`, and an equal-length `#` rule. Data lines are strictly:

```text
<signed-time-ns>; <qualified-name>; <closed-event>;
```

The repository's vendor-sample subset, `taskevents-r2026.02-vendor-sample.csv`, has SHA-256 `48176357af8c70eff90c87e87269777a3e075263f7c359b96fc362681a7e50a8`. It preserves the release sample's header and five representative records byte-for-byte.

The `/TRaceRecord` variant changes the width and is therefore rejected by v1. Before the stream opens, a trusted ELF/ORTI/marker adapter must provide every Task, idle, ISR, Task/ISR entry function, and runnable; unknown names fail. The dictionary is therefore complete before observation output, and parsing uses constant memory.

The mapping is:

- `switch` and state-history-verified `schedule`, `resume`, and `release`: emit `ContextSwitch` when previous and next differ, retaining the vendor state transition in `reason`; lifecycle transitions with the same context or unknown left-boundary state remain `Instant` and do not fabricate a CPU switch.
- `start`, `stop`: `FunctionEnter`, `FunctionExit` for declared Task entry functions.
- `isrstart`, `isrend`: nested `InterruptEnter`, `InterruptExit`; if an ISR entry function is configured, also emit its function boundary.
- `runnablestart`, `runnablestop`: nested function boundaries in the current Task or innermost ISR context.
- `activate`, `preempt`, `wait`, `terminate`: retain as `Instant` with `vendor_event`; do not represent Task lifecycle state as a CPU context switch.
- The vendor public sample permits the left-boundary first record `0; ; preempt;`; every other empty name fails.

The open adapter must also prove that the trace has no overflow, flow error, gap, or truncation, and that TRACE32 ZERO equals the Session origin. Time reversal, unknown events, invalid ISR/runnable nesting, and unclosed EOF state fail with byte/line/record locations. Task/ISR entries and runnables use strict inner/outer function nesting; a runnable is bound to its concrete ISR activation and cannot close across nested activations of an ISR with the same name.

State mapping also performs closed validation: `schedule` may originate only from observed `activate`/ready state, `resume` may resume only the same preempted Task, and `release` may originate only from waiting. If the left boundary has insufficient history, retain an `Instant` with `state_validation=left_boundary_unknown`; do not claim an exact `ContextSwitch`. `stop` and `runnablestop` must occur in the active context; incomplete deschedule transitions fail at the real EOF position. The release vendor sample's first time is `478000ns`, which proves the dialect but has no Session-origin evidence, so trusted input rejects it.

## Controller Protocol and Custom-Event Sidecar

The target-adapter profile explicitly selects `controller_protocol=v1` or `v2_custom_events_export`; the Host never infers the protocol from ASCII/TASKEVENTS format, evidence schema, or capability fields. V1 is the existing single-output protocol and forbids a custom-event collector. V2 is only for profiles that emit both TASKEVENTS program flow and an adapter-owned custom-event sidecar. The `Export` slots must be ordered exactly as `[TraceExport, CustomEvents]`; no separate `Counters` or `ResourceCounters` slot may be added, and the custom-event slot byte limit must exactly match the collector contract in the profile.

The custom-event sidecar is not another TRACE32 text dialect. Its collector contract fixes C-wire v1, source/core, versioned transport, mapping artifact ID, instrumentation-overhead artifact ID, nonzero bounded output, `reject_ambiguous_ties`, and the same clock domain, frequency, modulus, wrap-forward bound, and origin as TASKEVENTS. A C-wire v1 Counter record is normalized with this sidecar, so a V2 profile requires both `custom_events` and `counters` to be `exact`; this still does not open a separate counter-file path in the Controller.

The current TC234L build-`190766` profile is explicitly V1 with `custom_event_collector=null`, `custom_events=unavailable`, and `counters=unavailable`; it allows only SNOOPer ASCII sampling. Its V1 CMM, profile, and bundle digest remain compatible. The repository does not fabricate a TASKEVENTS/custom-event collector or a production V2 profile for it. Software implementation of V2 request/response, six-stage Host prepare/accept, existing-first dual-output ingest, abort/recovery, receipt-bound mapping/overhead provisioning, capture-config generation, and TASKEVENTS+C-wire multi-source wiring is complete. Board, RTOS, and Linux execution evidence remains deferred.

## Host Normalization Trust Chain

Normalization configuration may reference only an artifact ID and an expected profile. It may not inline function/context mappings or request that an unverified registry sentinel be promoted to a verified adapter.

`trace32_snooper_ascii_v1` requires the complete accepted Controller chain, normal HealthV2, StopV2 `time_origin_zeroed_to_first_record=true`, an exact raw export, a qualified target-adapter receipt, and an authoritative capture configuration with exactly matching `export.profile`, `firmware.elf_artifact_id`, `firmware.elf_sha256`, and `snooper.time_origin`. From the registered `firmware-elf`, the Host automatically extracts non-overlapping executable ELF function ranges and registers a fixed `trace32-symbol-mapping` artifact through an internal producer using create-new semantics. After a crash, an existing artifact may be reused only when its ID, kind, path, producer, every input provenance field, and complete mapping document match exactly.

The symbol mapping also binds the firmware ELF, capture configuration, capabilities, HealthV2, StopV2, raw export, and the actual qualification-receipt artifact. `qualification_sha256=Some(...)` alone does not establish trust. The admitted TC234L profile is still an evidence-only candidate without a receipt, so production normalization explicitly returns unsupported and does not generate a mapping.

Before dictionary construction, ASCII and TASKEVENTS sources enforce `max_dictionary_entries`, `max_dictionary_bytes`, and a bound on the serialized size of one entry. A valid but stripped executable ELF with no defined nonzero-size text function is rejected; it does not degrade into a silent all-address-only symbol mapping.

`trace32_task_events_v1` defines the same strict artifact-only configuration and additionally requires deployment-owned mapping, ORTI, and marker metadata ID/SHA, single-core evidence, Health, Stop time origin, and qualification receipt to all match catalog/capture/controller evidence. Host-accepted V2 `TraceExport` and `CustomEvents` may be merged as 2..64 sources using the same receipt-bound mapping, clock domain, and `reject_ambiguous_ties` rules; same-tick cross-source events without a unique order key are rejected. Without a production V2/TASKEVENTS adapter, this entry point remains fail-closed, consistent with deferred RTOS, board, and Linux runtime evidence.
