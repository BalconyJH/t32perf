# ADR 0007: Provide a Host-owned MCP service

Status: Accepted

## Decision

The provenance-bound `t32perf` binary provides an `mcp` stdio service mode. A trusted launch
configuration fixes one artifact root and response/resource limits; an MCP client cannot choose
them through tool arguments. The service exposes only these eight tools:

```text
perf_capabilities  perf_capture       perf_get_status  perf_get_summary
perf_list_artifacts perf_convert      perf_compare     perf_run
```

Each tool returns a structured result or structured tool-level error constrained by
`t32perf.perf-surface/v1`. The service exposes no resources or prompts and never transports
trace, evidence, or other large artifact bytes through MCP; results contain only bounded fields
and artifact references. A raw JSON line has a 1 MiB wire limit, a typed result envelope has a
256 KiB limit, and both structured JSON and text wire representations are subject to the 1 MiB
frame limit.

`tools/list` publishes each tool's dedicated success envelope and matching structured error arm,
rather than a union of all eight operations. Capabilities/capture return only the terminal public
projection of the server-internal drive, excluding execute, collect, workload, response handoff,
and absolute paths. Every schema range/length is also validated at runtime. A JSON-RPC request
ID has a 128-byte encoded limit; an oversized ID or an oversized/truncated frame fails closed
before dispatch. Public errors and failed Session state remove absolute paths, hook stderr, and
arbitrary diagnostic details.

`perf_capabilities` and `perf_capture` drive the Controller inside the server through a durable
transaction protocol. The server consumes upstream execute/collect/workload handoffs internally,
without exposing these low-level actions to the client; a terminal payload can still contain a
high-level Host `next_action`, such as calling `perf_capture`. `perf_run` remains the preferred
entry point for a new admitted production Session, but the MCP caller must provide a portable,
stable Session ID in advance so it can recover the query after a lost response. After
cancellation, the underlying Controller operation can continue to a durable boundary; before
retrying, the caller must query `perf_get_status` and cannot assume cancellation rolled back
external side effects.

This is a Host façade and does not modify upstream `t32mcp`. The official upstream service still
exposes only `execute_practice_skill`, `collect_practice_skill_response`, and
`abort_practice_skill`. The generic PC-sampling and intrusive-stack sidecars remain independent
services. The separate user-facing `skills/t32perf-mcp` skill describes use of the Host service;
the hash-bound `skill-trace32-perf` PRACTICE skill remains unchanged.

## Consequences

The service gives MCP clients a bounded, capability-oriented interface while retaining artifact
ownership, execution leases, provenance checks, and crash recovery in the Host. It is only a
software integration: the service and its tests do not prove a TRACE32 endpoint, probe, target,
RTOS, firmware binding, or HIL result.
