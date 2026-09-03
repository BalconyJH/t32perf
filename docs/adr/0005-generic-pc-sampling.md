# ADR 0005: Isolate Generic PC Sampling from the Official t32mcp Driver

Status: Accepted

## Context

Some targets can be debugged through a generic architecture configuration even when TRACE32 has
no target-specific package, flash algorithm, or qualified trace adapter for the device. These
targets may also lack ETM, MTB, ITM, or another program-flow trace source. TRACE32 can still obtain
a statistical run-time overview by sampling the program counter through the `PERF` command group.

The existing production integration deliberately admits only the official `t32mcp` v0.2.2 three-
tool inventory and a qualified, build-specific PRACTICE adapter. Adding generic named sampling
tools to that driver would invalidate its inventory, deployment digest, controller sequence, and
qualification boundary. Treating aggregate `PERF.PC.HITS()` counts as timestamped observations
would also fabricate ordering evidence that the capture source does not provide.

The installed interactive `lauterbachdebugger-mcp` is not an adequate production boundary for this
capture. It exposes arbitrary PRACTICE commands and target mutation, owns one process-global RCL
connection, and has neither a cross-process endpoint lease nor a durable recovery transaction.

## Decision

T32Perf introduces a separate sampling-only sidecar and MCP surface for generic program-counter
sampling. The sidecar is a peer deployment service, not an extension of the official `t32mcp`
driver or its Controller protocol.

### Endpoint ownership

- One artifact root continues to own one single-tenant TRACE32 PowerView endpoint.
- The sidecar and official driver use the same root-wide TRACE32 execution lease. They cannot
  mutate one endpoint concurrently.
- Version 1 accepts only loopback TCP and a deployment-dedicated PowerView Remote API port. A
  general interactive MCP client must not share that endpoint during production sampling.
- Endpoint fingerprint v2 binds the loopback endpoint and TRACE32 software to a privacy-preserving
  digest of the observed debug-module serial, cable serial, and debug port. Raw serials are not
  emitted. An unpinned deployment is capabilities-only; capture requires an explicit startup pin
  and rejects mismatch before journal recovery or any PERF mutation.
- Production sampling uses a dedicated PowerView session in a canonical disabled `PERF` baseline.
  An interactive session with pre-existing PERF state is diagnostic-only and is rejected by the
  trusted path.
- The sidecar records operation intents before TRACE32 mutations and observed results afterwards.
  Its journal uses a new schema family and never writes the Controller driver journal.
- A restart audits incomplete sampling transactions before accepting new work. Unknown ownership or
  unreadable endpoint state quarantines the endpoint; it does not trigger a blind retry.
- Cleanup failure remains quarantined across ordinary calls. Retrying that owned cleanup requires
  the explicit deployment start option `--recover-quarantined`; it is never selected by an MCP
  caller. The option grants one recovery attempt and is consumed before that attempt, so a later
  failure requires another deployment restart.
- The append-only journal is bounded to 16,384 events and 64 MiB. Crossing either limit fails
  before a new target mutation and requires deployment retention.

### Session authorization

- `t32perf sampling prepare` is the capability issuer. It creates one `created` Session whose
  immutable `t32perf.sampling-capture-request/v1` fixes ranges, bucket size, duration, method policy,
  core, and program address space.
- The tool returns the Session's random 32-hex operation ID. `sampling_capture` requires both the
  Session ID and operation ID, takes the same cross-process Session lock as the Host, and compares
  every normalized argument with the immutable request before opening an RCL connection.
- A terminal or nonempty Session, a mismatched operation ID/request, or a prior sidecar histogram is
  rejected before TRACE32 access. One prepared Session authorizes at most one sidecar export.

### Target control

- Version 1 is a fixed-duration aggregate observation window and accepts only an already running
  target. Confirmed `RealTime` is non-intrusive; `StopAndGo` is explicitly intrusive.
- Sampling never issues `Go`, `Break`, reset, flash programming, or a workload command.
- An unexpected target halt is state drift. The sidecar leaves the target halted and rejects the
  quantitative result rather than resuming it.
- Cleanup restores only the sidecar-owned canonical PERF baseline. It does not claim to restore an
  arbitrary interactive TRACE32 configuration or the target's prior execution state.

### Acquisition methods

- `PERF.Mode PC` is the mandatory acquisition mode. ETM, MTB, ITM, SNOOPer, and `TRACE.METHOD` are
  not capability gates for this path.
- `PERF.METHOD RealTime` is the default and must be confirmed by `PERF.METHOD()==4` after
  configuration.
- `PERF.METHOD StopAndGo` is available only through explicit caller opt-in and must be confirmed by
  `PERF.METHOD()==2`. Its result is permanently marked intrusive and records the configured and
  observed retained-run-time information.
- Actual hit counts, the final sampling-rate snapshot, snoop failures, target state, method, and
  cleanup outcome are recorded. A requested sampling rate is never reported as an observation.

### Data and trust boundary

- Aggregate range counts are stored as `t32perf.pc-hit-histogram/v1`. Buckets are sorted,
  non-overlapping half-open address intervals with integer hit counts and an explicit in-scope
  denominator.
- Histograms do not enter the timestamped `ObservationEvent::Sample` pipeline. T32Perf uses a
  dedicated aggregate analysis path and emits `t32perf.heatmap/v1`.
- A histogram may embed bounded `debugger_symbolization` display metadata. For at most the ten
  highest-hit buckets, the sidecar partitions the same stopped PERF result to a dominant interval
  no wider than four bytes and records TRACE32-reported function/source basenames. Address heatmap
  cells must reproduce that object exactly. This remains `debugger_reported` metadata and neither
  changes the bucket count nor establishes firmware identity.
- The sidecar writes immutable bytes only to a host-reserved `capture/staging` location. It never
  writes Session state, artifact indexes, catalogs, manifests, analysis receipts, or attestations.
  The T32Perf host re-reads, hashes, validates, and ingests the staged bytes.
- `sampling ingest` verifies the endpoint binding and exact ten-event successful transaction,
  rechecks the immutable request and operation ID, then writes a Host-reserved
  `t32perf.sampling-capture-receipt/v1`. Ordinary `session ingest` cannot claim sampling IDs, kinds,
  paths, or producers.
- Firmware binding precedes trusted function/source projection. Trusted function or source-line attribution requires
  machine-verifiable digest-bound deployment evidence or an independently verified target-image
  comparison. An explicitly diagnostic function ranking may instead use the precommitted assertion
  below; it never becomes verified firmware.
- The optional `deployed_firmware_elf_sha256` request field commits the deployment assertion before
  capture. A later Host-only `sampling bind-firmware` step accepts only that exact ELF and creates
  `PrecommittedElfAssertion` evidence with `deployment_asserted` status; it does not claim verified
  firmware or target-memory comparison and never modifies the sidecar histogram.
- Function aliases, DWARF spans, and source-line ranges are normalized into a non-overlapping address
  partition before attribution. Ratios always use in-scope hits as the denominator, and
  unattributed hits remain explicit.

### Presentation

- Every result remains `statistical`. A zero-hit bucket means "not observed during this sample
  window", not "not executed".
- Ranked function results use a horizontal comparison chart. Address or source-line heat coloring is
  used only when the data has a defensible spatial structure.
- Reports display acquisition method, intrusiveness, duration, in-scope hits, unattributed hits,
  snoop failures, firmware binding, and the fact that the rate value is a final snapshot.
- The version-1 quantitative floor is persisted in every heatmap: at least 100 in-scope hits,
  100 ms observed duration, no snoop failures, and at least 90% observed retained runtime for
  StopAndGo. These are admission floors, not a universal accuracy or confidence guarantee.
- The result is not execution trace, code coverage, WCET, per-call timing, call count, or branch
  evidence.

## Consequences

- Unknown devices can gain a bounded address or function hotspot overview without adding a false
  target-specific adapter or requiring trace IP.
- The official `t32mcp` executable, exact three-tool inventory, Controller model, and admitted target
  adapters remain unchanged.
- Generic sampling has an independent deployment and qualification surface. Its Python and Rust
  implementations share versioned wire contracts and exact artifact bytes, not private in-process
  types or serialization assumptions.
- RealTime and StopAndGo require separate hardware qualification. A platform is not admitted merely
  because `CPU.FEATURE(PCSNOOP)` or a configured CPU name reports a theoretical capability.
- RCL 1.1.6 calls run in a blocking worker that Python cannot forcibly terminate. Loopback endpoint
  isolation and socket timeouts reduce exposure, but a future process-supervised transport is
  required for a hard wall-clock kill boundary.
- Timestamped timelines still require a qualified raw-sample source such as SNOOPer. Aggregate PERF
  histograms intentionally cannot be converted into invented timestamped samples.

## Rejected alternatives

### Add tools to the official t32mcp driver

This would pierce the exact tool inventory and bind an unqualified generic transport to the trusted
Controller path.

### Drive arbitrary commands through the interactive MCP server

This lacks endpoint ownership, bounded inputs, durable intent records, crash recovery, and a closed
mutation set.

### Expand aggregate counts into synthetic observations

Repeating aggregate hits with invented timestamps would create ordering and timeline evidence that
TRACE32 did not capture.

### Restore an arbitrary pre-existing PERF configuration

The available getters do not describe every PERF option or analyzer breakpoint. A complete and
trustworthy snapshot/restore operation is therefore not available.
