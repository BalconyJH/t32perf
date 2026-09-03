# ADR 0006: Isolate Intrusive Stack Sampling from Aggregate PC Sampling

Status: Accepted

## Context

Generic `PERF.PC.HITS()` sampling gives aggregate hotspot counts on targets without a
target-specific package or qualified trace IP. It does not preserve a stack, a caller/callee edge,
or program-flow ordering. Rendering its function buckets as a hierarchical flame graph would
invent evidence.

Some targets, including Cortex-M0+ systems without MTB or ETM, still permit TRACE32 to stop the
core and walk debugger frames. This can provide sampled stack paths, but each sample changes target
execution. It can disturb timing, watchdogs, and communications, and a failed cleanup may leave
the target halted. Therefore it cannot be hidden behind the aggregate `sampling_capture` operation.

## Decision

Introduce a separate `lauterbach-stack-sampling-mcp` surface with exactly these tools:

```text
stack_sampling_capabilities
stack_sampling_capture
```

It requires a Host-prepared `t32perf.stack-capture-request/v1`, an exact one-use Session operation
ID, a pinned endpoint fingerprint, and `acknowledge_intrusive: true`. Requests are bounded to a
10..=1000 ms period, 100..=60000 ms duration, 1..=512 samples, and 1..=8 frames. Version 1 is
single-core-only: `core_id=0`, `CORE.NUMBER()=1`, and `CORE()=0` must all agree.
The one-use property is durable: before any Break, a create-new
`t32perf.stack-capture-attempt/v1` marker binds Session, operation, exact request digest, and
endpoint. It is retained after success, cancellation, or failure; retry requires a fresh Session.

For each sample the sidecar records intent, performs `Break`, walks `Frame.Up`/`Frame.Down`, calls
`Go`, and confirms `STATE.RUN()` with a bounded poll. Only PC/SP reads and frame navigation occur
while stopped; labels are resolved after the matching `Go`. Local RCL socket waits are capped at
100 ms and further walking stops at a 1 s software deadline. It owns a separate append-only journal,
Session lease, staging namespace, quarantine state, and explicit recovery flow. Cancellation and
errors attempt owned `Go` cleanup, but unproven recovery remains quarantined.
TRACE32 `ERROR` is an explicit integrity gate: capabilities must be exactly
`{"occurred":false,"id":""}` before capture and again after it. Only a confirmed frame-walk
`#emu_noframe` may be reset, only after the matching `Go`, and it must be re-read as clean. No other
ERROR is cleared; it fails capture. HIL PASS binds the independent pre/post clean readings.
Recovery is a separate one-shot process operation: `--recover-quarantined --recover-only` consumes
authorization before journal inspection, recovers only an unmatched owned Break, and exits without
starting a capture. It preserves and reports the TRACE32 `ERROR` slot; a recovery authorization does
not prove who created that process-global state. A completed owned Go or later external stop never
authorizes another Go.

The Host exposes `stack prepare`, `stack ingest`, `stack analyze`, `stack summary`, and `stack
render`. It accepts only journal-bound staged raw samples, keeps the observed leaf-to-root frame
order, and deterministically folds it into root-to-leaf paths. `terminal_unverified` and
`truncated` remain explicit outer boundaries; a missing parent is never inferred. The Takumi SVG
renderer uses deterministic DAG identifiers and escaped accessible text; canonical JSON remains
the primary evidence. Rendering keeps at most 128 real visible frame nodes and aggregates omitted
sibling subtrees under the same observed prefix into a count-conserving synthetic marker.

Widths always represent observed sample count. They do not represent CPU time, capture duration,
call count, code coverage, or a complete execution trace. TRACE32 symbol-table names are
`debugger_reported`; firmware stays `unverified` absent separate evidence. Source labels retain a
basename only.

The existing PC path remains unchanged. Its `sampling flame` presentation is allowed only as a
flat sampled profile with an explicitly synthetic hierarchy. It cannot claim a call tree.

## Consequences

- Targets without trace IP can obtain a low-frequency sampled stack flame graph when interruption
  is accepted and debugger frame unwinding works.
- The aggregate PC-sampling two-tool inventory, its no-`Go`/no-`Break` contract, and the official
  t32mcp inventory remain intact.
- Operators must load matching ELF/symbols to obtain meaningful method labels. Addresses outside
  the loaded symbol range are valid but may remain unnamed.
- HIL acceptance must verify the final target state, clean pre/post debugger ERROR state,
  journal/recovery behavior, and repeated measurements before any deployment-specific claim.
- Qualified program-flow trace remains preferable. Where available, TRACE32 `Trace.FlameGraph`
  has stronger flow evidence than debugger-stop stack snapshots.

## Rejected alternatives

### Add stack capture to `sampling_capture`

This would mix aggregate PC collection with explicit frame-walking target mutation, weaken its
state and recovery contract, and obscure the required acknowledgement.

### Build a caller hierarchy from PC buckets or static symbols

Aggregate PCs and static call graphs do not prove the sampled dynamic path. Such a graph would
misrepresent independent hotspots as a runtime call tree.

### Treat halt-cycle duration as CPU time

Break-to-Go time includes debugger and transport effects. It is diagnostic only and cannot weight
the graph as target execution time.
