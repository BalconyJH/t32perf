# Platform Capability Matrix

For status definitions and repository-wide boundaries, see [implementation-status.md](implementation-status.md). Collect evidence for new platforms according to [trace32-runbook.md](trace32-runbook.md).

This table records only evidenced capabilities. `UNVERIFIED` does not mean unsupported; it means that verification has not yet been completed on the specified TRACE32 build, probe, board, and firmware.

| Platform ID | MCU / Core | Probe | TRACE32 build | ETM | ITM | DWT | MTB | STREAM | RTOS Awareness | Covered cores | Evidence | Status |
|---|---|---|---:|---|---|---|---|---|---|---|---|---|
| `pending-hardware-1` | To be provided | To be provided | To be provided | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | To be provided | None | UNVERIFIED |
| `pending-hardware-2` | To be provided | To be provided | To be provided | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | To be provided | None | UNVERIFIED |

Every verified entry must include:

- TRACE32 release/build, architecture package, and license.
- Probe model, board, trace pins, and core coverage.
- Firmware ELF/MAP/ORTI/ARTI version and SHA-256.
- Capture trust-policy ID, signing-key ID, adapter/version, and attested observation digest.
- Raw trace, structured export, health evidence, and at least ten independent captures for each accepted mode and initial running/halted state.
- Initial running/halted, overflow, flow-error, disconnect, and recovery tests.
- TRACE32 native-statistics differential report.
- For intrusive stack sampling: endpoint pin, exact request bounds, final target state after
  cancellation/failure, journal/recovery result, loaded ELF/symbol identity, and repeated
  Break/frame-walk/Go measurements. Do not promote one diagnostic run to platform support.
- For a real flame graph, record whether the evidence is intrusive stack sampling or qualified
  program-flow trace. `Trace.FlameGraph` requires the latter; a flat PC flame view has synthetic
  hierarchy and is not call-stack evidence.

The repository-wide R4 coverage conclusion must not be inferred from this table's row count. It must be produced from deeply validated Sessions as `t32perf.hil-evidence/v1`, validated against `hil/schemas/hil-evidence.schema.json` in the [schema catalog](schema-catalog.md), and demonstrated by the HIL harness to cover at least two MCU classes, two modes, one RTOS, and two exact TRACE32 versions through version-specific adapters. Two boards from the same MCU family do not count as “two MCU classes,” an empty RTOS does not count as RTOS coverage, and aliases of one physical board do not count as distinct boards.
