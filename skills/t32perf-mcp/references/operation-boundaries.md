# T32Perf MCP operation boundaries

The local server starts with `t32perf --artifact-root ROOT mcp`. Treat these eight tools as the complete public surface:

| Tool | Purpose |
| --- | --- |
| `perf_capabilities` | Establish or recover durable capability admission for an existing Session. |
| `perf_capture` | Complete the normal capture chain for an existing Session inside the server. |
| `perf_get_status` | Read durable Session lifecycle, health, and trust projections. |
| `perf_get_summary` | Return health-gated Top-N results after analysis. |
| `perf_list_artifacts` | List bounded artifact metadata and continue with the returned cursor when present. |
| `perf_convert` | Create a supported derived report, such as a Perfetto export. |
| `perf_compare` | Produce a bounded comparison verdict and report reference. |
| `perf_run` | Run or recover the fixed, deployment-owned production workflow. |

## Capture and evidence

For a real-hardware request, inspect capabilities first. Stop when the server reports unsupported hardware, missing admission, unavailable evidence, or an unhealthy result. Explain the reported prerequisite; do not substitute a synthetic trace, user-provided JSON, guessed TRACE32 settings, or another capture mode.

`perf_capture` drives the complete durable control chain inside the server; it is not an interface for callers to advance phase by phase. After it reaches a terminal state or returns high-level guidance, call only the next Host tool allowed by that result. Do not construct a completion signal, run an arbitrary workload, or bypass cleanup, health, or attestation boundaries.

Use `perf_run` for the fixed deployment workflow. The caller must provide a portable, stable `session_id` so durable state remains queryable after a response or connection is lost. An MCP caller cannot supply firmware, policy, signer, or other trust-root material.

## Size limits

Each raw JSON frame on stdio is limited to 1 MiB, and each structured Host result envelope is limited to 256 KiB. Request a smaller Top-N result or artifact page to remain within these limits. Do not evade a limit by splitting, repeating, or embedding artifact content.

## Retry and stopping

Read `perf_get_status` before retrying an interrupted, timed-out, or ambiguous capture or run. Resume only when the returned durable state explicitly permits it. Do not repeat capture, workload, stop, export, abort, or `perf_run` solely because a response was lost; an external side effect may already have occurred. If status cannot establish a safe continuation, stop and report the Session and the required recovery or operator action.

Use `perf_get_summary` only for a reportable, health-gated result. For an invalid or unsupported result, return diagnostics and artifact references without quantitative hotspots or metrics. `perf_list_artifacts`, `perf_convert`, and `perf_compare` return manifest or content-addressed references; do not expand large artifact contents into an MCP response.
