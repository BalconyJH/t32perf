# ADR 0001: Rust for the Host

Status: Accepted with hardware revalidation

## Decision

The production host implementation uses Rust 2024. The parser uses synchronous streaming interfaces, and the CLI shares a language and release ecosystem with Lauterbach `t32mcp`.

## Rationale

- Large-file processing needs bounded memory, exact integer time, explicit error locations, and stable cross-platform binaries.
- `t32mcp` v0.2.2 already uses Rust 2024; a shared language reduces control-plane integration and deployment cost.
- Rust's type and ownership model expresses the Session state machine, artifact lifecycle, and the observation/derived boundary well.

The repository retains a Python candidate using the same inputs and a reproducible benchmark workflow. Synthetic canonical parser/analyzer results from 2026-08-23 are available in [Implementation Status](../implementation-status.md). They support the present Rust choice, but do not include real TRACE32 mappings, Linux evidence, or an end-to-end hardware path. When real TRACE32 samples are available, rerun the 1M, 10M, and multi-GiB benchmarks. If the results overturn this decision, supersede this ADR with a new one.

## Consequences

The target-side SDK is not required to use Rust; the first release provides a heap-free C99 wire SDK. TRACE32 continues to execute PRACTICE/CMM.
