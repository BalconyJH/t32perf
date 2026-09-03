# ADR 0003: Emit Perfetto/Chrome Trace JSON in the First Release

Status: Accepted

## Decision

The first release emits streaming Chrome Trace JSON. Internal time remains session-relative integer nanoseconds; output is converted to relative microseconds. Functions use complete events; task/ISR/core warnings and counters use stable tracks; gaps appear on the warning track.

The writer first writes a temporary file, closes and self-validates it completely, then commits it atomically. An `INVALID` trace may produce a diagnostic timeline, but must not produce trusted hotspots or regression conclusions.

The repository also provides an official trace-processor validation wrapper pinned to `perfetto==0.57.2` and an Ubuntu CI job. JSON self-validation and the package smoke test do not replace official importer evidence. On 2026-08-24, the package-manifest download URL timed out, but the exact official v56.1 GitHub release asset and package-declared binary digest were verified and the synthetic Windows trace imported successfully; see [Implementation Status](../implementation-status.md) and the [checked-in verification record](../verification/perfetto-windows-x86_64-2026-08-24.json).

## Consequences

If real data proves JSON volume or parsing cost unacceptable, add Perfetto protobuf through a separate exporter. The internal model remains independent of the output format.
