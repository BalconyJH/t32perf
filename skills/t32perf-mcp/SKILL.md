---
name: t32perf-mcp
description: "Run bounded, health-gated T32Perf capture and reporting through the local MCP server."
---

# T32Perf MCP

Use the configured local `t32perf` stdio MCP server for T32Perf operations. It is the public Host facade; do not replace it with shell commands, direct artifact edits, synthetic capture data, or upstream TRACE32 tool calls. Before calling `perf_run`, choose a portable, stable `session_id` and submit it with the request. Do not rely on the server to generate an unknown ID.

Unless a Session already has durable capability state, call `perf_capabilities` before a real capture. `perf_capture` then completes the normal capture chain inside the server, including the deployment-owned workload and cleanup. Do not run its internal upstream execute, collect, or workload steps yourself. Use `perf_run` for a deployment-configured end-to-end production workflow, and query status with the same `session_id` if the response is lost.

Return only bounded summaries and artifact references. Read [operation boundaries](references/operation-boundaries.md) when choosing an operation or reasoning about evidence requirements, protocol size limits, stopping, or retry behavior.
