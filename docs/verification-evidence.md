---
title: Verification evidence
description: Checked-in benchmark and software verification records with explicit limitations
icon: material/file-document-check-outline
---

# Verification evidence

This page indexes evidence committed with the repository. Each record is useful only within
its declared scope; none of the current records qualifies a production hardware capture.

## Evidence matrix

| Recorded | Evidence | Result | Scope |
|---|---|---|---|
| 2026-08-23 | [Windows parser and analyzer benchmark](benchmarks/windows-x86_64-2026-08-23.json) | Measurements recorded | Synthetic host software |
| 2026-08-24 | [Perfetto importer verification](verification/perfetto-windows-x86_64-2026-08-24.json) | `VALID` | Windows x86_64, synthetic trace |
| 2026-08-25 | [t32mcp driver preflight](verification/t32mcp-driver-preflight-windows-x86_64-2026-08-25.json) | `VALID` | Windows x86_64 control plane, historical `feb461...` adapter |

!!! warning "A valid record is not a broader claim"

    `VALID` means the checks declared by that record passed. It does not silently extend the
    record to Linux, another binary digest, another TRACE32 build, a probe, an MCU, an RTOS,
    target-side overhead, or metric correctness.

## Parser and analyzer benchmark

The Windows benchmark covers deterministic canonical NDJSON with 1 million, 10 million,
and 20 million observations. It records elapsed time, throughput, and externally sampled
resident memory for the Rust and Python parser candidates. A separate Criterion run records
the streaming analyzer at 1 million and 10 million events.

The benchmark excludes capture, normalization, artifact hashing, and Perfetto export. Its
100 ms external RSS polling can miss a shorter peak. It contains no real TRACE32 input or
hardware measurement.

## Perfetto importer verification

The Perfetto record binds an official `trace_processor_shell` from Perfetto v56.1 to both
the official release digest and the digest declared by `perfetto==0.57.2`. It imports a
synthetic T32Perf report, runs bounded SQL queries, and records 32 slices, 31 counters, and
3 tracks with no warning or error stats.

This proves importer compatibility for that Windows x86_64 synthetic artifact. It does not
prove UI stability or hardware metric accuracy.

## t32mcp driver preflight

The driver record verifies one exact official-mirror `t32mcp` v0.2.2 executable together
with historical adapter implementation
`feb46173441d2225b522a03cfae2486031fb72c6d8170baf374038848dcb2293`, MCP initialization,
the exact three-tool inventory, and graceful shutdown. It also verifies that no official
t32mcp process remains after shutdown. It does not cover the current runtime adapter bundle.

`tools_invoked` and `trace32_connection_attempted` are both `false`. The record therefore
does not exercise PRACTICE, RCL, TRACE32, a probe, firmware, or a board.

## Hardware evidence still required

Production qualification requires the evidence described by the
[hardware verification boundary](hardware-verification.md) and the
[TRACE32 integration runbook](trace32-runbook.md), including an exact platform identity,
raw capture, health evidence, repeat runs, fault handling, and native-statistic differential.
The [sampling architecture](sampling-architecture.md) describes the chip-independent PC and
stack paths without embedding a deployment-specific result.
