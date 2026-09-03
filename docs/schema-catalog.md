---
title: Schema catalog
description: Versioned JSON contracts generated and verified by T32Perf
icon: material/file-code-outline
---

# Schema catalog

The checked-in JSON Schemas are generated from the Rust model and verified by
`cargo xtask schemas --check`. The source of truth remains the files under
`schemas/v1/`; this catalog provides a stable documentation index without duplicating
their definitions into the site.

!!! warning

    JSON Schema validates document structure. State transitions, ordering, provenance,
    signature, digest, trust, and cross-artifact requirements documented in
    [Data and Session contracts](contracts.md) are also normative.

## Session and capture

| Repository file | Contract ID | Purpose |
|---|---|---|
| `schemas/v1/state.schema.json` | `t32perf.state/v1` | Durable Session state |
| `schemas/v1/manifest.schema.json` | `t32perf.manifest/v1` | Final immutable artifact manifest |
| `schemas/v1/capture-config.schema.json` | `t32perf.capture-config/v1` | Authoritative capture configuration |
| `schemas/v1/capture-receipt.schema.json` | `t32perf.capture-receipt/v1` | Accepted capture provenance and capabilities |
| `schemas/v1/capture-attestation.schema.json` | `t32perf.capture-attestation/v1` | Signed external-capture statement |
| `schemas/v1/capture-trust-policy.schema.json` | `t32perf.capture-trust-policy/v1` | Allowed signing keys and capability ceilings |
| `schemas/v1/attestation-signing-request.schema.json` | `t32perf.attestation-signing-request/v1` | Host-owned bytes submitted for signing |
| `schemas/v1/release-provenance.schema.json` | `t32perf.release-provenance/v1` | Release toolchain and binary provenance |

## Observation and normalization

| Repository file | Contract ID | Purpose |
|---|---|---|
| `schemas/v1/observation.schema.json` | `t32perf.observation/v1` | Canonical observation record |
| `schemas/v1/dictionary.schema.json` | `t32perf.dictionary/v1` | Versioned observation dictionary |
| `schemas/v1/normalize-config.schema.json` | `t32perf.normalize-config/v1` | Single- or multi-source normalization |
| `schemas/v1/c-wire-counter-mapping.schema.json` | `t32perf.c-wire-counter-mapping/v1` | C-wire counter semantics |
| `schemas/v1/trace32-symbol-mapping.schema.json` | `t32perf.trace32-symbol-mapping/v1` | TRACE32 symbol mapping |
| `schemas/v1/trace32-task-events-mapping-template.schema.json` | `t32perf.trace32-task-events-mapping-template/v1` | Receipt-bound mapping template |
| `schemas/v1/trace32-task-events-mapping.schema.json` | `t32perf.trace32-task-events-mapping/v1` | Accepted TASKEVENTS mapping |

## Analysis and reporting

| Repository file | Contract ID | Purpose |
|---|---|---|
| `schemas/v1/derived-stream.schema.json` | `t32perf.derived-stream/v1` | Derived NDJSON stream header |
| `schemas/v1/derived.schema.json` | `t32perf.derived/v1` | Derived span document |
| `schemas/v1/health.schema.json` | `t32perf.health/v1` | Health verdict and metric support |
| `schemas/v1/hotspots.schema.json` | `t32perf.hotspots/v1` | Health-gated hotspot aggregates |
| `schemas/v1/analysis-summary.schema.json` | `t32perf.analysis-summary/v1` | Bounded analysis summary |
| `schemas/v1/analysis-stage.schema.json` | `t32perf.analysis-stage/v1` | Immutable analysis-stage receipt |
| `schemas/v1/report.schema.json` | `t32perf.report/v1` | Analysis report |
| `schemas/v1/comparison.schema.json` | `t32perf.comparison/v1` | Comparison result |
| `schemas/v1/comparison-artifact.schema.json` | `t32perf.comparison-artifact/v1` | Content-addressed comparison envelope |
| `schemas/v1/static-ram-config.schema.json` | `t32perf.static-ram-config/v1` | Exact static-RAM classification |
| `schemas/v1/static-ram-report.schema.json` | `t32perf.static-ram-report/v1` | Static-RAM result |
| `schemas/v1/stack-usage-report.schema.json` | `t32perf.stack-usage-report/v1` | Compiler stack-usage result |
| `schemas/v1/instrumentation-overhead-evidence.schema.json` | `t32perf.instrumentation-overhead-evidence/v1` | Receipt-bound instrumentation overhead |
| `schemas/v1/pc-hit-histogram.schema.json` | `t32perf.pc-hit-histogram/v1` | TRACE32 PERF PC-hit histogram |
| `schemas/v1/heatmap.schema.json` | `t32perf.heatmap/v1` | Statistical coarse heatmap projection |
| `schemas/v1/firmware-binding-evidence.schema.json` | `t32perf.firmware-binding-evidence/v1` | Immutable firmware-to-target binding evidence |
| `schemas/v1/sampling-endpoint-binding.schema.json` | `t32perf.sampling-endpoint-binding/v1` | Sampling-only TRACE32 endpoint binding |
| `schemas/v1/sampling-driver-event.schema.json` | `t32perf.sampling-driver-event/v1` | Append-only sampling sidecar journal event |
| `schemas/v1/sampling-capture-receipt.schema.json` | `t32perf.sampling-capture-receipt/v1` | Host-derived successful sampling receipt |
| `schemas/v1/sampling-capture-request.schema.json` | `t32perf.sampling-capture-request/v1` | Bounded aggregate PC-sampling request with an explicit method policy |
| `schemas/v1/stack-capture-request.schema.json` | `t32perf.stack-capture-request/v1` | Explicitly confirmed, bounded intrusive stack-sampling request |
| `schemas/v1/stack-capture-attempt.schema.json` | `t32perf.stack-capture-attempt/v1` | Persistent one-shot Session-operation consumption marker recorded before the first Break |
| `schemas/v1/stack-samples.schema.json` | `t32perf.stack-samples/v1` | Raw leaf-to-root samples from TRACE32 halted-frame traversal |
| `schemas/v1/folded-stack-profile.schema.json` | `t32perf.folded-stack-profile/v1` | Root-to-leaf paths deterministically derived from raw samples |
| `schemas/v1/stack-driver-event.schema.json` | `t32perf.stack-driver-event/v1` | Append-only driver journal for Break/Go stack sampling |
| `schemas/v1/stack-capture-receipt.schema.json` | `t32perf.stack-capture-receipt/v1` | Host receipt binding the request, journal, and raw stack samples |

## Public performance surface

| Repository file | Contract ID | Purpose |
|---|---|---|
| `schemas/v1/perf-surface.schema.json` | `t32perf.perf-surface/v1` | Closed envelope for the public `perf_*` façade |
| `schemas/v1/performance-run-request.schema.json` | `t32perf.performance-run-request/v1` | One-shot performance-run request |
| `schemas/v1/performance-run-payload.schema.json` | `t32perf.performance-run-payload/v1` | One-shot performance-run result |

## Controller and driver

| Repository file | Contract ID | Purpose |
|---|---|---|
| `schemas/v1/controller-request.schema.json` | `t32perf.controller-request/v1` | Controller V1 request |
| `schemas/v1/controller-request-v2.schema.json` | `t32perf.controller-request/v2` | Controller V2 request |
| `schemas/v1/controller-response.schema.json` | `t32perf.controller-response/v1` | Controller V1 response |
| `schemas/v1/controller-response-v2.schema.json` | `t32perf.controller-response/v2` | Controller V2 response |
| `schemas/v1/controller-capabilities-evidence.schema.json` | `t32perf.controller-capabilities-evidence/v1` | V1 capability evidence |
| `schemas/v1/controller-capabilities-evidence-v2.schema.json` | `t32perf.controller-capabilities-evidence/v2` | V2 capability evidence |
| `schemas/v1/controller-configure-evidence.schema.json` | `t32perf.controller-configure-evidence/v1` | Configure evidence |
| `schemas/v1/controller-start-evidence.schema.json` | `t32perf.controller-start-evidence/v1` | V1 start evidence |
| `schemas/v1/controller-start-evidence-v2.schema.json` | `t32perf.controller-start-evidence/v2` | V2 start evidence |
| `schemas/v1/controller-stop-evidence.schema.json` | `t32perf.controller-stop-evidence/v1` | V1 stop evidence |
| `schemas/v1/controller-stop-evidence-v2.schema.json` | `t32perf.controller-stop-evidence/v2` | V2 stop evidence |
| `schemas/v1/controller-health-evidence.schema.json` | `t32perf.controller-health-evidence/v1` | V1 health evidence |
| `schemas/v1/controller-health-evidence-v2.schema.json` | `t32perf.controller-health-evidence/v2` | V2 health evidence |
| `schemas/v1/controller-health-evidence-v3.schema.json` | `t32perf.controller-health-evidence/v3` | Program-flow health evidence |
| `schemas/v1/controller-cleanup-evidence.schema.json` | `t32perf.controller-cleanup-evidence/v1` | V1 cleanup evidence |
| `schemas/v1/controller-cleanup-evidence-v2.schema.json` | `t32perf.controller-cleanup-evidence/v2` | V2 cleanup evidence |
| `schemas/v1/controller-abort-request.schema.json` | `t32perf.controller-abort-request/v1` | Durable abort plan |
| `schemas/v1/controller-abort-receipt.schema.json` | `t32perf.controller-abort-receipt/v1` | Confirmed abort result |
| `schemas/v1/controller-driver-event.schema.json` | `t32perf.controller-driver-event/v1` | Append-only side-effect journal event |
| `schemas/v1/t32mcp-driver-config.schema.json` | `t32perf.t32mcp-driver-config/v1` | Fixed deployment driver configuration |

## Target adapter qualification

| Repository file | Contract ID | Purpose |
|---|---|---|
| `schemas/v1/target-adapter-profile.schema.json` | `t32perf.target-adapter-profile/v1` | Installed target-adapter identity |
| `schemas/v1/target-adapter-scenario.schema.json` | `t32perf.target-adapter-scenario/v1` | Exact scenario selection |
| `schemas/v1/target-adapter-qualification-policy.schema.json` | `t32perf.target-adapter-qualification-policy/v1` | Qualification policy |
| `schemas/v1/target-adapter-qualification-receipt.schema.json` | `t32perf.target-adapter-qualification-receipt/v1` | Accepted laboratory evidence |
| `schemas/v1/target-adapter-qualification-trust-store.schema.json` | `t32perf.target-adapter-qualification-trust-store/v1` | Administrator-controlled trust store |
| `schemas/v1/target-adapter-admission-snapshot.schema.json` | `t32perf.target-adapter-admission-snapshot/v1` | Capture-time qualification snapshot |
| `schemas/v1/target-adapter-recovery-evidence.schema.json` | `t32perf.target-adapter-recovery-evidence/v1` | Recovery evidence |

## HIL harness contracts

These Python-owned schemas live under `hil/schemas/` and are cross-checked against the
Rust contracts where their boundaries overlap.

| Repository file | Contract ID | Purpose |
|---|---|---|
| `hil/schemas/hil-evidence.schema.json` | `t32perf.hil-evidence/v1` | Complete platform evidence matrix |
| `hil/schemas/hil-evidence-v2.schema.json` | `https://t32perf.dev/schemas/hil/hil-evidence-v2.schema.json` | HIL evidence V2 |
| `hil/schemas/hil-verification-receipt.schema.json` | `https://t32perf.dev/schemas/hil/hil-verification-receipt-v1.schema.json` | Independent verification receipt |
| `hil/schemas/target-adapter-failure-binding.schema.json` | `t32perf.target-adapter-failure-binding/v1` | Fault-to-adapter binding |
| `hil/schemas/target-adapter-recovery-evidence.schema.json` | `t32perf.target-adapter-recovery-evidence/v1` | Recovery scenario evidence |
| `hil/schemas/stack-hil-verification-receipt.schema.json` | `t32perf.stack-hil-verification-receipt/v1` | Independent state-verification receipt before and after intrusive stack sampling |

## Verify schema drift

```bash
cargo xtask schemas --check
```

The check verifies the exact file set, strict JSON, `$id`, generated bytes, and drift from
the Rust model. Do not edit generated schema files by hand.
