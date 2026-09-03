# Data, Session, and Artifact Contracts

This document defines the Session/model `v1` persistence contract and the selected Controller `v1`/`v2` request protocols. JSON Schemas are in `schemas/v1`; schemas validate structure only. States, ordering, provenance, and trust gates are contractual too.

All JSON read by the Rust host (Session metadata, configurations, policies, signed payloads, receipts, control-plane documents, and canonical/derived NDJSON) is strict: duplicate object member names at any depth, including names equal after unescaping, are rejected. First-wins and last-wins behavior are prohibited. NDJSON is still checked line by line within existing bounds.

## Artifact Root and Session Identity

Each child of the T32Perf-managed allowlisted artifact root is a Session:

```text
<artifact-root>/<session-id>/
```

Session IDs are at most 64 characters: ASCII letters/digits, with `_` and `-` only in non-initial positions. Generated IDs are time-sortable UUIDv7 values. Creation is exclusive and never overwrites an existing Session.

Artifact paths are portable forward-slash paths relative to the Session. Segments are printable ASCII; Unicode is confined to non-physical fields. Drive/URI prefixes, absolute paths, backslashes, NUL, empty segments, `.`, `..`, Windows-invalid characters, reserved device names, and trailing dots/spaces are forbidden. ASCII-case-folded paths are unique per Session; final files are never symlinks, junctions, or reparse points. Serialized paths are at most 1024 bytes. This v1 ASCII profile prevents Linux Unicode-case aliases from colliding in a normally case-insensitive Windows namespace. Individual JSON control documents are at most 16 MiB.

## Standard Layout

```text
<session>/
  .session.lock
  request.json
  state.json
  manifest.json                 # only after finalization
  artifact-index/<artifact-id>.json
  ingest-intents/<artifact-id>.json
  committed-staging-sources/<artifact-id>.json
  capture/.ingest-private/
  capture/raw/
  capture/staging/
  normalized/
  analysis/
  report/
  logs/
```

| Path | Contract |
|---|---|
| `request.json` | Immutable after creation; user request, not hardware fact. |
| `state.json` | Only mutable Session document; atomically replaced locally. |
| `.session.lock` | In-process and OS-level exclusive-operation lock; do not delete. |
| `capture/staging` | Only location writable by trusted external capture; not a formal artifact. |
| `capture/.ingest-private` | Host-owned ingest copies; external capture cannot write it. |
| `artifact-index/*.json` | Append-only catalog; file name equals artifact ID. |
| `ingest-intents/*.json` | `t32perf.ingest-intent/v2` crash recovery. `preparing` persists source digest/private path/artifact claim; only `ready` allows publication. v1 and historical v2 records without private fields remain readable. |
| `committed-staging-sources/*.json` | Committed-artifact binding to retained staging path, size, and SHA-256; deeply verified and included in complete-Session retention inventory. |
| `manifest.json` | Immutable completion snapshot exactly matching the catalog. |

Default limits are 64 GiB per file and 256 GiB per Session. Quota includes regular-file payloads for request/state/artifacts/catalog/intents/manifest/lock/atomic temporaries, but not platform directory/allocation-unit overhead. Writes and ingest perform peak-capacity checks; global Controller CLI options may tighten limits.

## Session State Machine

```text
created -> capturing -> captured -> processing -> complete
    \          \           \            \
     +----------+-----------+-------------> failed
```

`normalize` and successful `session attest` add immutable artifacts in `captured` and do not advance to `processing`. Failures attempt `failed`.

| State | Meaning |
|---|---|
| `created` | Directory, request, and initial state are durable. |
| `capturing` | Capture or ingest owns the Session. |
| `captured` | Capture is durable; analysis may start. |
| `processing` | Analysis began; successful analysis waits for convert/finalize. |
| `complete` | Perfetto conversion and manifest commit completed. |
| `failed` | Current operation ended with structured `SessionError`. |

`state.json` retains immutable `created_at`, operation ID, monotonic revision, and current `updated_at`. `failed` is terminal. Partial immutable artifacts from failed analysis/conversion are failure evidence: do not overwrite or repair them; use a new Session to retry. Except while entering `failed`, lifecycle advances reject unfinished intents. Inspection classifies intents as `pending`, `resumable`, `committed_stale`, or `conflict`; only identical ingest parameters may resume the first three, and conflicts change no files. Successful analysis writes `analysis-stage` last; missing stage receipt in `processing`/`complete` is `INCOMPLETE`.

Manifests retain trusted receipt provider/mode/adapter/target/TRACE32/request digest/covered cores/capabilities/firmware/clocks, all stage records, and catalog. Target-side custom-event instrumentation also preserves typed method, transport, and measured overhead, with exact capture-config provenance. Strict comparison requires equal provider, non-empty covered cores, and capabilities, producing `capture_provider_*`, `capture_core_coverage_*`, or `capture_capabilities_*` reasons when absent or unequal.

## Artifacts, Capture, and Attestation

Catalog records contain `id`, `kind`, `relative_path`, `media_type`, `size_bytes`, `sha256`, `producer`, and `input_artifact_ids`. IDs are at most 128 ASCII characters, using letters/digits and non-initial `_`, `-`, `.`. IDs and paths are unique; an artifact references at most 1024 inputs, a manifest at most 16384 artifacts, and final provenance is acyclic.

Artifacts are either atomically written, hashed, and registered by T32Perf, or ingested from a no-follow `capture/staging` handle: calculate size/SHA-256, persist strict `preparing`, copy to host private inode, flush/sync, promote `ready`, atomically publish unique destination, append catalog. Formal artifacts never reference staging inodes. Resume is idempotent across every copy/catalog/intent crash window; any spec/digest/ID/path/catalog/unknown-control conflict fails closed. Unbound private remnants are never deleted automatically and no overwrite API exists. Deep verification hashes open handles; shallow verification checks type/size. See the [Security Model](security.md).

Built-in IDs include `observations`, `capture-attestation`, `capture-trust-policy`, `capture-receipt`, `derived`, `health`, `hotspots`, `analysis-summary`, `static-ram`, `stack-usage`, `analysis-stage`, and `perfetto`, at their conventional `normalized/`, `capture/`, `analysis/`, and `report/` paths.

`t32perf.capture-receipt/v1` separates capture fact from request: Session ID, provider/mode/adapter ID/version, optional target/TRACE32/firmware/clock provenance, covered cores, observation capabilities, health observations, and immutable request SHA-256. Declared `frequency_hz` is at least 1 Hz; strict comparison requires complete equal relevant clocks. Trust is policy-defined: either built-in synthetic receipt with fixed producer/capabilities, or `session attest` host verification of external attestation under deployment Ed25519 policy. Ordinary `session ingest` cannot claim reserved attestation/policy/receipt IDs, kinds, paths, or producers.

The `t32perf.capture-attestation/v1` signed payload contains `schema`, `key_id`, `nonce`, `receipt`, `observation_artifact_id`, `observation_sha256`, `capture_config`, and `controller_health`. `nonce` equals `state.operation_id`; receipt Session/request digest and observation/config IDs/digests match host/catalog/strict documents. Controller-health Sessions bind accepted health evidence ID/SHA-256. Host-derived adverse observations must exactly equal signed `t32perf.controller-health-evidence/v1` sources: overflow, flow, gap, truncation, timestamp, ELF, and program-flow failures are neither omitted nor invented. Ed25519 signatures cover deterministic compact JSON and are 128 lowercase hex characters.

`t32perf.capture-trust-policy/v1` is deployment-owned: each key fixes 32-byte lowercase-hex Ed25519 public key and producer; provider/adapter/modes; exact target, optional exact TRACE32, clocks, allowed cores, firmware-ELF SHA-256 allowlist, and capability ceilings. TRACE32 keys require build, architecture package, non-empty ELF allowlist; targets require architecture/device/nonzero cores; clocks nonzero frequency; cores unique/non-empty. TRACE32 receipts declare allowlisted `firmware.elf_sha256`, exactly equal to `adapter_parameters["firmware.elf_sha256"]`; build ID cannot substitute. Covered cores are non-empty allowlist subsets and capabilities do not exceed ceilings. Policy/attestation are each <=1 MiB. Only administrators/host select preconfigured regular-file policy paths; clients supply neither paths nor keys. Policy snapshot, untrusted attestation, and verified receipt are registered together. Failure terminally fails the Session.

- `schemas/v1/capture-attestation.schema.json`
- `schemas/v1/capture-trust-policy.schema.json`

## Normalization and Observations

`t32perf.normalize-config/v1` is strict and denies unknown fields. It is either `single_source` (`source`, canonical limits) or `multi_source` (2..64 `sources`, each input artifact/adapter/clock/order contract, canonical limits). Adapters are `canonical_ndjson_v1` (source ID, line limits, matching Session), `explicit_csv_v1` (explicit bindings/ignored columns/quality/rational clock/origin/limits), and `c_wire_v1` (`wire_version=1`, source/core/rational clock/origin/wire limits). Rational clocks use nonzero `numerator/denominator`; origin is first-record or explicit ticks-to-session-ns; wrap declares modulus/max forward ticks. Normalize never guesses columns, sorts, or upgrades trust.

Single-source accepts only CLI `--input-artifact`. Multi-source rejects it; each unique `input_artifact_id` declares complete adapter config, normalized `clock_domain`, and `order=reject_ambiguous_ties`. Actual and declared clocks match, all clocks match each other, source timestamp/sequence are monotonic, and same-tick cross-source records require unique order keys. Dictionaries merge by ID within namespace: equal definitions deduplicate, conflicts fail closed. Limits: default 65,536 entries/64 MiB dictionary lines, hard 1,048,576/1 GiB; lines <=16 MiB; records <=1,000,000,000; all nonzero. Dictionary bytes include LF and are charged before ID-index allocation/push. Config artifacts are `kind=normalization_config`, `media_type=application/json`, <=1 MiB. Success writes `observations` at `normalized/observations.ndjson` with all raw inputs (configuration order), config, and `capture-config` provenance. See the [schema catalog](schema-catalog.md) for `schemas/v1/normalize-config.schema.json`. CLI-private serde is not duplicated in model; `cargo xtask schemas --check` checks parse/$id only, while binary tests run corpora through checked-in schema and serde/semantic validation.

Canonical adapter `t32perf-observation-ndjson` has order `ObservationStreamHeader`, zero or more `DefineContext | DefineFunction | DefineCounter`, then zero or more `Observation`. Every UTF-8 object is one LF-terminated line; CRLF/final-LF absence is rejected. Header is `ndjson`/`ns`/`session_relative` and matching Session. Lines <=1 MiB; dictionary limits apply. Dictionary IDs are namespace-unique and precede observations. `source_seq` strictly increases; per-source/global timestamps never decrease; same ticks need stable producer order. Unknown fields and implicit sort are rejected with byte/line/record errors. Timestamps are signed session-relative `i64` ns (bounded negative pre-trigger allowed); durations nonnegative `u64` ns; quality is `exact`, `inferred`, or `statistical`.

## Generic PC-Hit Histograms and Heatmaps

`t32perf.pc-hit-histogram/v1` is a separate aggregate capture contract for TRACE32
`PERF.PC.HITS()`. It is not a canonical observation stream and carries no event timestamps,
source sequence, call ordering, or duration weight. A producer must not expand aggregate hits
into synthetic `ObservationEvent::Sample` records.

The histogram binds one portable Session, one SHA-256 endpoint fingerprint, TRACE32 and CPU
identity, address space and core, actual acquisition method, requested and observed host
duration, the last observed sample-rate snapshot, snoop failures, boundary target states,
cleanup completion, and firmware-binding evidence. Its nonempty buckets are sorted,
nonoverlapping half-open address ranges. `in_scope_hits` exactly equals the checked sum of bucket
hits. Zero hits and zero observed rate remain representable capture facts, but the quantitative
gate rejects them.

Endpoint fingerprint v2 also commits to the sidecar's observed, privacy-preserving probe
fingerprint. That probe digest covers the debug-module serial, cable serial, and selected debug
port without exposing the raw values. It proves the observed Lauterbach probe class for this
endpoint, not a target-chip identifier; HIL receipts keep `target_id_observed=false` until an
independent target identity exists.

Every object carrying this digest—endpoint binding, driver event, PC-hit histogram, capture
receipt, and firmware-binding evidence—also requires
`endpoint_fingerprint_scheme: "t32perf.endpoint-fingerprint/v2"`. The document schema remains
`/v1`; the scheme is a separate security contract and Host cross-artifact checks compare both.
Missing or mismatched schemes fail closed. The only exception is an unpublished development-v1
journal recovery path: it accepts a checked-in historical event schema solely to disable and
verify an already-owned PERF transaction after both a current v2 pin and the historical v1 digest
have matched. It cannot capture, launch MCP, or upgrade that root for v2 use.

RealTime is non-intrusive in this contract. StopAndGo is always intrusive and records both its
configured and observed retained-run-time percentages. A successful quantitative projection
uses an explicit `QuantitativePolicy` persisted inside the heatmap. The v1 Host default requires a
powered and running target at both boundaries, positive rate, at least 100 in-scope hits, at least
100 ms observed duration, zero snoop failures, confirmed cleanup, and at least 90% observed
retained runtime for StopAndGo. These are minimum admission floors, not claims that sampling is
exact or that 100 samples are sufficient for every statistical conclusion.

`t32perf.heatmap/v1` is a single-granularity projection with integer hit counts. Address-range,
function, and source-line keys cannot be mixed. The denominator equals attributed plus
unattributed in-scope hits; out-of-scope accounting is explicitly known or unknown. Shares are
derived only at presentation time. Trusted function and source-line projections require a verified
ELF digest plus machine-verifiable deployment or target-image-comparison evidence. A diagnostic
function projection may instead carry the explicit `deployment_asserted` precommitted status; every
consumer must preserve that qualifier. An address projection must reproduce every source bucket and count exactly. Every heatmap is statistical: zero hits
means "not observed in this sampling window", never "not executed" or code coverage.

`t32perf.sampling-capture-request/v1` is the immutable Host authorization for a sidecar call. It
fixes sorted address ranges, exact bucket expansion, duration, method policy, core, and the `P`
address space. It may also fix `deployed_firmware_elf_sha256`; this is an explicit deployment
assertion for later symbol attribution, not a target-memory comparison. `sampling prepare` creates a fresh Session and returns its random operation ID;
the sidecar must match both the operation ID and every normalized request field while holding the
Session lock, before it opens an RCL connection.

The sidecar histogram always remains unverified. `sampling bind-firmware` may later consume a
staged ELF whose digest exactly matches that immutable assertion, validate its executable function
ranges, and create Host-reserved ELF and `PrecommittedElfAssertion` evidence artifacts. Function
analysis derives a `deployment_asserted` in-memory binding from the original histogram plus those
two direct inputs; it never rewrites the captured histogram. `target_image_compared=false` remains
explicit, and this status must never be rendered as verified. The v1 diagnostic function mapper
also requires a TRACE32 Cortex-M CPU identity and a little-endian ARM ELF32 executable.

The histogram may carry `debugger_symbolization` without changing that firmware status. The
sidecar selects at most the ten highest-hit original buckets and uses a bounded branch-and-bound
partition of the same stopped PERF result. It emits only a proven highest-hit interval of at most
four bytes; an exhausted query budget or deadline omits that bucket. It then asks TRACE32's
currently loaded symbol table for a function and source location. Every location repeats its exact
parent bucket and hit count, records the dominant interval and its own hit count, retains only
bounded basenames, and is tagged `trace32_symbol_table` / `debugger_reported`. The Host propagates
that object only to the matching address-range heatmap cell and rechecks structural equality on
every replay. It is a display annotation for a dominant subrange, not a function projection, ELF
binding, target-image comparison, or claim that every hit in the coarse parent bucket belongs to
the displayed function.

The sampling sidecar may write only exact, no-overwrite bytes below `capture/staging`. T32Perf
reopens and hashes those bytes, checks the root endpoint binding and exact ten-event successful
`t32perf.sampling-driver-event/v1` sequence, and revalidates the Session request before creating a
Host-owned `t32perf.sampling-capture-receipt/v1`. That receipt binds the request digest, operation
ID, endpoint, transaction, histogram digest/size, and every journal-event digest. Ordinary
`session ingest` cannot claim any reserved sampling ID, kind, path, or producer. The sidecar never
writes `state.json`, artifact indexes, manifests, analysis receipts, or capture attestations. Its
root execution lease is shared with the official driver. See [ADR 0005](adr/0005-generic-pc-sampling.md).

Digest-valid malformed canonical content becomes bounded parser health (`malformed_input`, `truncated_input`, `out_of_order_sequence`, `out_of_order_timestamp`) with artifact/record/line/offset evidence. A valid prefix remains diagnostic; analysis is `INVALID`, writes derived/health/summary/stage but no hotspots/static-RAM/stack-usage/quantitative payload, and may create diagnostic Perfetto/manifest. I/O/quota/unsupported-major/writer/analyzer-contract errors and digest mismatch are operational/integrity `failed`, never consumed as health data. Types: `FunctionEnter`/`FunctionExit`; `ContextSwitch`/`InterruptEnter`/`InterruptExit`; `Sample`; `Instant`/`SpanBegin`/`SpanEnd`/`AsyncBegin`/`AsyncEnd`; `Counter`/`TraceGap`/`Metadata`. See `schemas/v1/observation.schema.json`; `dictionary.schema.json` is the full in-memory document while NDJSON uses `Define*` lines.

### Flame Profiles and Intrusive Stack Samples

`sampling flame` consumes a PC-hit histogram and renders a Takumi-backed flat sampled profile.
Its visual parent is synthetic; it is a presentation of independent PC/function aggregates, not
call-stack evidence. It must not be called a call tree or used to infer caller/callee edges.

`t32perf.stack-capture-request/v1` is a distinct authorization for intrusive stack collection. It
requires `acknowledge_intrusive: true`, a `sample_period_ms` of 10..=1000, `duration_ms` of
100..=60000, `max_samples` of 1..=512, `max_frames` of 1..=8, and `core_id: 0`. TRACE32 must
independently report one logical core with core 0 selected. The dedicated
`lauterbach-stack-sampling-mcp/v1` surface exposes exactly `stack_sampling_capabilities` and
`stack_sampling_capture`; it does not change the older PC-sampling two-tool inventory. Capture
requires a pinned endpoint fingerprint and performs bounded `Break → Frame.Up → Frame.Down → Go`
cycles with a 100 ms RCL socket-timeout ceiling, a 1 s frame-walk deadline, and bounded
`STATE.RUN()` polling. It records only PC/SP while stopped; optional symbol/source lookups occur
after the matching `Go` is observed. Python cannot preempt a native RCL call, so this is a bounded
software policy rather than a hard real-time target-stop guarantee.
Before the first Break intent, the sidecar create-new publishes
`.t32perf-control/stack-capture-attempts/<SESSION>.json`. The generated
`t32perf.stack-capture-attempt/v1` contract binds Session, operation, exact request SHA-256, endpoint,
and timestamp. It remains after success, cancellation, or failure; the same Host operation can
never authorize another capture. The directory is limited to 16,384 plain JSON entries.

Raw `t32perf.stack-samples/v1` frames are leaf-to-root and retain their observed outer boundary.
Host `stack prepare`, `stack ingest`, `stack analyze`, `stack summary`, and `stack render` derive
a deterministic root-to-leaf `t32perf.folded-stack-profile/v1`, then render a Takumi flame DAG
with deterministic IDs. `terminal_unverified`, `halt_deadline`, and other truncated reasons remain
at the outer boundary; the
Host never invents a missing parent. A frame name from the TRACE32 symbol table is
`debugger_reported`; firmware remains `unverified` unless separately proven. Source locations keep
only a basename. Rendered width is observed sample count, not CPU time, capture duration, call
count, or coverage. Canonical JSON is the evidence artifact; the SVG is an escaped, accessible
presentation overlay. The renderer retains at most 128 real visible frame nodes and aggregates
additional sibling subtrees under the same observed parent prefix as an explicit synthetic
`[other observed paths]` marker with count conservation; it never presents that marker as a frame.
The HIL reads capabilities before and after capture through separate stdio MCP children and accepts
only an identical endpoint/core identity with `powered=true`, `running=true`, `halted=false`, and
the exact clean `debugger_error_state: {"occurred":false,"id":""}`. The sidecar may reset only
the confirmed frame-walk `#emu_noframe` after its matching `Go`, then must verify that same clean
state; any other ERROR fails capture without clearing it. Both pre/post clean states are retained in
the HIL receipt.
The stack board also pins `host.t32perf_sha256`. It reads the final executable through a no-follow,
64 MiB-bounded stable file descriptor when loading the board and before every Host phase; every HIL
receipt carries the same digest. A read-only build directory/ACL is the trust boundary for the small
rehash-to-process-spawn interval.
Quarantined recovery is a separate one-shot process operation; it never starts another capture.
It reports but never resets TRACE32 `ERROR`, because journal-backed halt ownership is not evidence
that the same transaction owns the process-global error slot.

### Resource Counter Semantics

`DefineCounter.semantic` and `subject` occur together or neither. Neither is legacy generic; when present, they are the only semantic source. IDs/display names do not classify memory. Standard semantic identifiers cover heap bytes gauges/high-watermarks/counts/rate/fragmentation (`heap.current_allocated_bytes`, `heap.free_bytes`, `heap.largest_free_block_bytes`, `heap.peak_allocated_bytes`, `heap.largest_allocation_bytes`, `heap.allocation_count`, `heap.free_count`, `heap.allocation_rate_per_second`, `heap.external_fragmentation_ratio`); stack capacity/current/peak; RAM current/peak; and trace-buffer capacity/current/peak. Unknown valid identifiers remain generic. `subject.kind` covers capture, allocator, context, core, stack, memory region, trace buffer, and namespaced custom identity. Stack has unique `stack_id` and `task`/`isr`/`msp`/`psp`/`custom`; task/ISR reference matching dictionary context, MSP/PSP declares core. `(semantic, subject)` is unique.

Standard values are finite/nonnegative, with integer `bytes`/`count` <=`2^53`. Decreasing monotonic/high-watermark, capacity change, `current > peak`, `peak > capacity`, or invalid fragmentation creates health fact. Full trace buffer is not overflow absent adapter evidence. Analyzer retains only first/latest/min/max/mean/delta/window/rate/quality/support. Allocation rate needs unreset count and positive window; fragmentation needs same allocator/timestamp and `free_bytes > 0`, using `1 - largest_free_block_bytes / free_bytes`; insufficient evidence is `unavailable`.

## Analysis, Health, and Controller

`derived` uses streaming `t32perf.derived-stream/v1`: header then `FunctionSpan` lines. Each span binds source-range/core/context/function, optional frame, start/end/elapsed/active/self-active/preempted, quality/incomplete. Header Session matches; line <=1 MiB; `end-start==elapsed`; `active+preempted<=elapsed` (equality exact complete); `self_active<=active`; source end >= start. Dictionary remains in observations. Convert verifies header inputs against catalog and stage counts.

`t32perf.analysis-summary/v1` includes Session, verdict, full support, exact input claims, diagnostics, and optional `quantitative`. `VALID` requires quantitative; `DEGRADED`/`INVALID` prohibit it; counts agree with health/stage. Quantitative includes call depth, context CPU, task/ISR/idle, resources, optional static RAM/stack. Dynamic groups have independent limits and never cross-unit sort. Nonvalid Sessions retain diagnostics/derived/health/diagnostic Perfetto, never quantitative artifacts/response. Runtime stacks, `.su` frames, call depth, and linker MAP RAM are independent and never summed as “peak RAM.”

`t32perf.analysis-stage/v1` immutably binds Session/tool/version/commit, analyzer-health-policy-schema contracts, verdict/support, diagnostics, and exact full artifact claims. Claims match catalog, input/output are disjoint, inputs include `observations`/`capture-receipt`, outputs always `derived`/`health`/`analysis-summary`, and only `VALID` outputs `hotspots` plus applicable `static-ram`/`stack-usage`. Receipt provenance lists inputs then outputs. Convert/validate reverify receipt/health/summary/derived/catalog; status/summary verify at least receipt/health/summary/catalog. The [schema catalog](schema-catalog.md) indexes `analysis-summary.schema.json` and `analysis-stage.schema.json`.

Health verdict is `VALID`/`DEGRADED`/`INVALID`; support is `exact`/`inferred`/`statistical`/`unavailable`. Only `VALID` permits trusted quantitative/strict comparison. Support covers `function_timeline`, `call_count`, `elapsed`, `active`, `self`, `task_timeline`, `isr_timeline`, `resource_counters`; resources take the weakest receipt capability/observation quality/policy result. Non-exact support gives reason. Sampling cannot provide exact calls/nesting/durations. `t32perf.health-policy/v1` escalates overflow/flow/truncation/ELF mismatch/time-sequence errors/unclosed stacks to `INVALID`. Unknown nonempty codes become fatal `unknown_health_fact` with <=256 raw bytes and all quantitative support unavailable. `trace_gap`/missing scheduled context degrade support. Max 4096 observations; overflow creates `diagnostics_truncated` and `INVALID`. `NOT_EVALUATED` and `INCOMPLETE` trust status are not verdicts.

Controller has no mutable phase file: immutable request/validated response/abort receipt/evidence reconstruct `capabilities → configure → start → stop → health → export → cleanup`. Accepted `start` is `created`→`capturing`; accepted `stop` is `capturing`→`captured`; health/export require stop. Completed phases cannot prepare again; original `accept` resumes idempotently; `perf_get_hotspots` needs complete chain; cleanup precedes processing/terminal. Evidence schemas are strict, <=1 MiB, bind operation and `binding_sha256`, fix capabilities/configuration/start-stop scenario/capacity/target/workload/health/export/cleanup facts, and target-state drift permits only `INVALID_ARGUMENT / initial_target_state_drift` with expected/observed state.

`t32perf.controller-driver-event/v1` is host-owned append-only crash journal with `dispatch_intent`, `fault_intent`, `fault_triggered`, `abort_attempt`, `abort_success_observed`, `workload_intent`, `workload_complete`; every record binds request/binding and applicable abort plan. Restart never repeats execute/collect/workload/fault/abort-END; uncertainty fails closed. A workload cannot rerun without matching completion. All external/low-level/public mutations share root execution lease, retained after Cleanup until capture-config materializes.

`t32perf.perf-surface/v1` is closed typed union for `perf_capabilities`, `perf_capture`, status, summary, pages, convert, compare. `next_action` is only execute/collect/invoke/run-workload/`capture_config_ready`; no client config writeback. Bounds: 100 summary rows/family, 64 issues, 8 support reasons, 1000 artifact rows/16 inputs, and compare only bounded reasons/counts/full-report reference. See `schemas/v1/perf-surface.schema.json` in the [schema catalog](schema-catalog.md).

### Protocol, Resources, and Compatibility

Profiles explicitly select `controller_protocol` `v1` or `v2_custom_events_export`; request v1/v2 accepts its matching binding only. Endpoint `GetCapabilities`/`GetHotspots` bind full candidate catalog but do not admit target firmware/profile. Driver revalidates every endpoint bundle before execute/collect/abort/replacement; target work requires deployment-selected bundle exactly matching Session admission. Unknown firmware fails closed.

`v1` has no collector and `custom_events=unavailable`. `v2_custom_events_export` requires scenario-consistent TASKEVENTS and strict `c_wire_v1` collector contract (portable source/core, shared clock/frequency/modulus/forward step/origin, versioned transport, fixed mapping/overhead IDs, nonzero bounded output, `merge_order=reject_ambiguous_ties`). Collector core/clock match every scenario, IDs are portable/distinct, and both custom events/counters are `exact`; this does not authorize separate counter output. V2 Export is exactly `[TraceExport, CustomEvents]`; `max_bytes` matches collector and success accepts both in slot order, failure none. V2 supports exact reservation/ingest, existing-first resume, public surface, and two-phase abort; no production V2 profile exists. TC234L build `190766` is v1 with null collector and unavailable custom events/counters, only SNOOPer ASCII sampling.

`t32perf.capture-config/v1` is authoritative before normalize/attest. It stores exact SHA-256 plus cross-Session `configuration_sha256`, calculated from compact T32Perf JSON after replacing `session_id` with empty sentinel (`Properties` lexical, arrays ordered). Host `CaptureConfigReady` binds ELF/S3/scenario/qualification/evidence/configure/V2 output and rechecks digest/mode/sink/cores/timestamps/target/workload against accepted evidence. Mismatch fails closed; manifests require equal config digest. Instrumentation overhead is closed `t32perf.instrumentation-overhead-evidence/v1` with method/transport/measurement/baseline/instrumented/event count, positive events, nondecreasing duration, checked delta, and exact `kind=instrumentation_overhead` capture-config provenance. Its contract is `schemas/v1/instrumentation-overhead-evidence.schema.json` in the [schema catalog](schema-catalog.md); it is not TC234L measured overhead nor P6 evidence.

Static/report flavors are `t32perf.static-ram/gnu-ld-map-v1`, `t32perf.static-ram/elf-sections-v1`, `t32perf.stack-usage/gcc-stack-usage-v1`. Optional `t32perf.static-ram-config/v1` fixes flavor and up to 4096 exact `dma`/`rtos`/`custom` sections, never wildcard/regex/substring or `.data`/`.bss`/`.noinit` reclassification. ELF accepts executable/relocatable Arm/AArch64/RISC-V or TriCore ELF32 little-endian `e_machine=44`; validates selected `SHF_ALLOC|SHF_WRITE` sections/ranges and fails closed for invalid structure/flags/ranges/duplicates/overflow (256 MiB, 65,536 sections). Reports retain ELF provenance; readers reject inconsistent/unknown/duplicate/nonmonotonic data. Resource comparison identity is `(semantic, subject)` and preserves units/support/config; unconfigured is informational, configured subject changes inconclusive, renamed IDs allowed, changed semantic/subject incomparable, dynamic/static metrics separate.

`t32perf.comparison-artifact/v1` is immutable outside Sessions at `.t32perf-control/comparisons/<SHA256>.json`, containing validated policy/digest, exact baseline/candidate manifest/stage/health/hotspots/summary digests, and `t32perf.comparison/v1`. Deterministic final-newline JSON, filename/digest/size/bytes all agree; same content is idempotent, conflict fails closed. It is never inserted into Session catalog/manifest. The [schema catalog](schema-catalog.md) indexes `comparison.schema.json` and `comparison-artifact.schema.json`. Full reports are referenced by `result.report_artifact`, not inlined; `result.report` is bounded. Document limits are 1/16/64 MiB plus row/subject bounds and 64 MiB envelope.

Schema IDs are `<family>/v<major>`; different family/major rejects, and v1 compatibility only adds optional fields. Canonical observation readers reject unknown wire fields, requiring synchronized reader/writer release. Tool semver and schema major are independent. Before upgrade preserve archives/checksums/Sessions; run `validate --deep`; ensure `cargo xtask schemas --check`; never rewrite old artifacts (create new Session/adapter with provenance); confirm tool/adapter/target/firmware/clock/request/TRACE32 policy before compare. `t32perf.report/v1` is presentation only: stage integrity rests on `AnalysisStageReceipt`, `AnalysisSummaryDocument`, and exact catalog claims.
