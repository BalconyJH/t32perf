# lauterbach-sampling-mcp

`lauterbach-sampling-mcp` is a sampling-only MCP sidecar for TRACE32 `PERF`
PC histograms. It exposes exactly `sampling_capabilities` and
`sampling_capture`.

The server opens one RCL connection per tool call in a blocking worker and
serializes calls. It never explicitly issues Go, Break, arbitrary PRACTICE,
paths, memory access, firmware loading, reset, flash, or workload execution.
It is an RCL client, not a PowerView process manager: start `t32marm` with the
approved configuration and startup script before calling either MCP tool.

First run a capabilities-only deployment with no endpoint pin. Record its
`endpoint_fingerprint`, then stop that process and restart a capture-capable
deployment with the recorded digest:

```powershell
uv run lauterbach-sampling-mcp --host localhost --port 20001 --protocol TCP --timeout 10 --artifact-root E:\t32perf-sessions

uv run lauterbach-sampling-mcp --host localhost --port 20001 --protocol TCP --timeout 10 --artifact-root E:\t32perf-sessions --expected-endpoint-fingerprint <64-lowercase-hex-digest>
```

For a local uv tool installation, install this project as the separate executable instead of
replacing or extending the general Lauterbach MCP:

```powershell
uv tool install --editable E:\t32perf\tools\lauterbach-sampling-mcp
```

`artifact-root` is deployment configuration, not an MCP input. v1 accepts only
loopback TCP (`localhost`, `127.0.0.1`, or `::1`). The Remote API port must
belong to a dedicated PowerView process; do not share it with the general
interactive Lauterbach MCP or another artifact root. A capture names an existing
Host-created Session in `created` state, obtains its non-blocking
`.session.lock`, and then publishes exactly one new JSON document below that
Session's `capture/staging`; callers cannot choose a file path. The immutable
`request.json` must exactly authorize sorted address ranges, bucket size,
duration, method policy, core, and address space of the capture.
An optional `deployed_firmware_elf_sha256` is passed through as an immutable
deployment assertion for later Host processing; the sidecar does not inspect the
ELF or promote its own firmware status.
The MCP request must also provide the current 32-character lowercase-hex
Session `operation_id`, which the sidecar compares before connecting to TRACE32.
Create that capability with `t32perf sampling prepare` and pass its returned
`sampling_capture_arguments` object unchanged to the MCP tool.

`sampling_capture` requires an already powered and running target. It defaults
to `realtime_only`. `allow_stop_and_go` is explicit: TRACE32 StopAndGo itself
periodically halts and resumes the target, and the result is marked intrusive.
Output is always `t32perf.pc-hit-histogram/v1`; firmware is
`unverified` and the server makes no verified function, source-line, timing, or
coverage claim.

When TRACE32 has symbols loaded, `sampling_capture` also makes a best-effort
inspection of at most ten highest-hit original buckets while PERF remains in
its stopped result state. A bounded branch-and-bound search emits a label only
after proving the highest-hit interval of at most four bytes; budget, deadline,
partition, or symbol failures omit that candidate. These labels are explicitly
`trace32_symbol_table` / `debugger_reported`, retain only safe basenames, and
do not change the raw buckets or firmware status.
`sampling_capabilities.code_labels` reports this feature as supported and
exposes the read-only TRACE32 symbol-table availability as `symbols_loaded`
(`true`, `false`, or `unknown`), including when the target is powered down.

Every capture takes `.t32perf-control/controller/trace32-driver-execution.lock`,
writes only its own append-only journal below
`.t32perf-control/sampling-driver-events`, and validates histogram JSON against
`schemas/v1/pc-hit-histogram.schema.json` before no-overwrite publication.

If a sidecar-owned cleanup fails, ordinary captures remain blocked. An operator
may restart the deployment with `--recover-quarantined` to explicitly retry that
cleanup. The startup authorization is consumed by its first recovery attempt;
another failure requires another deployment restart. This is intentionally not
an MCP tool. Python cannot safely terminate a
blocked RCL worker thread, so deployment shutdown waits for its RCL call to
return; use bounded RCL timeouts and supervise the sidecar process.

`endpoint_fingerprint_scheme` is a required, fixed
`t32perf.endpoint-fingerprint/v2` field in every endpoint binding, journal
event, histogram, capture receipt, and firmware-binding evidence.  This is
independent of each document's `/v1` JSON schema family. Missing schemes fail
closed for normal capture.

An unpublished development-v1 root can only be cleaned up with the explicit,
one-shot recovery process below; it never starts an MCP server or capture, and
does not rewrite its old binding or events. It first observes software and the
probe, verifies the current v2 pin, then verifies the supplied legacy digest
using the historic unbound formula before issuing only owned PERF cleanup:

```powershell
uv run lauterbach-sampling-mcp --host localhost --port 20001 --protocol TCP --timeout 10 --artifact-root E:\t32perf-sessions --recover-legacy-only --recover-quarantined --expected-endpoint-fingerprint <current-v2-digest> --legacy-endpoint-fingerprint <legacy-v1-digest>
```

The legacy v1 formula was `SHA-256("TCP://<normalized-host>:<port>/<trimmed-software>")`.
Successful cleanup does not upgrade the root; its v1 binding remains unusable
for v2 capture and must be retained only as recovery evidence.

## Generic sampling HIL bridge

The package also contains a closed laboratory argv bridge. It launches a fresh
sampling-only stdio MCP child, verifies that its inventory is exactly
`sampling_capabilities` and `sampling_capture`, and maps the five Host steps to
the configured `t32perf` executable. It accepts no arbitrary MCP tool or shell
command:

```powershell
uv run python -m lauterbach_sampling_mcp.hil_driver `
  --host localhost --port 20001 --protocol TCP `
  --artifact-root E:\t32perf-sessions `
  --expected-endpoint-fingerprint <64-lowercase-hex-digest> `
  --t32perf-bin E:\t32perf\target\release\t32perf.exe `
  capabilities --session sampling-example
```

The complete seven-command template is in
`../../hil/boards/sampling-only.example.toml`. The bridge bounds MCP text to
64 KiB and each Host child stream to 1 MiB. Host subprocesses use direct argv,
never a shell. A capabilities result also reports a `probe_fingerprint`: a
SHA-256 digest over the observed debug-module serial, cable serial, and debug
port, without emitting those values. Its endpoint fingerprint v2 binds that
digest to the normalized loopback endpoint and actual TRACE32 software
identity. Both are `unknown` when this identity cannot be read, and capture
then refuses before issuing any `PERF` command. The HIL configuration pins and
verifies the endpoint value before capture. The HIL bridge always requires this
pin; recovery is also a capture-capable operation and therefore requires it.

## Intrusive stack-sampling HIL bridge

The independent `lauterbach-stack-sampling-mcp` executable exposes exactly
`stack_sampling_capabilities` and `stack_sampling_capture`. Version 1 accepts only a TRACE32
session that reports one logical core with core 0 selected; requests permit at most eight frames
per halt cycle. RCL socket waits are capped at 100 ms and forward frame walking stops at a 1 s
software deadline. PC/SP collection and frame navigation occur while stopped; all optional symbol
queries occur after the matching `Go` is confirmed.
Before any Break, the sidecar create-new publishes a generated
`t32perf.stack-capture-attempt/v1` marker under the root control directory. It binds the Session,
operation, exact request digest, and endpoint, and remains after cancellation or failure. Repeating
the same Host operation is rejected before another Break; use a fresh Session.

If a journal proves an unmatched sidecar-owned Break, recover without starting a new capture:

```powershell
lauterbach-stack-sampling-mcp --host localhost --port 20001 --protocol TCP --timeout 10 `
  --artifact-root E:\t32perf-sessions `
  --expected-endpoint-fingerprint <64-lowercase-hex-digest> `
  --recover-quarantined --recover-only
```

This one-shot operation consumes its authorization before attempting recovery, never resumes a
post-Go external stop, verifies the final running state, and exits. A failure requires a fresh
process invocation. Python cannot preempt a native RCL call; keep the dedicated endpoint and
supervisor cleanup grace documented by the deployment.

`stack_hil_driver` is a separate closed bridge for real call-stack evidence.
It starts this package's `stack_server` over stdio, verifies that its inventory
is exactly `stack_sampling_capabilities` and `stack_sampling_capture`, and
uses direct argv for the fixed Host phases: `prepare`, `ingest`, `analyze`,
`summary`, and `render`. `capture` accepts only the Host-generated exact stack
capture arguments, including `acknowledge_intrusive=true`; it cannot dispatch a
different MCP tool or arbitrary JSON fields.

```powershell
uv run python -m lauterbach_sampling_mcp.stack_hil_driver `
  --host localhost --port 20001 --protocol TCP --timeout 10 `
  --artifact-root E:\t32perf-sessions `
  --expected-endpoint-fingerprint <64-lowercase-hex-digest> `
  --t32perf-bin E:\t32perf\target\release\t32perf.exe `
  capabilities --session stack-example
```

The bridge requires a loopback TCP endpoint pin and bounds MCP JSON to 64 KiB
and each Host child stream to 1 MiB. It starts no shell. Stack capture is
explicitly intrusive: every sample may stop the target while TRACE32 walks
`B::Frame`, then resumes it. Its capture response is restricted to the bounded
summary and published artifact metadata; cancellation closes the MCP session
and its child before it escapes the bridge.

Stack capture fails closed unless `stack_sampling_capabilities` reports the exact clean TRACE32
ERROR object `{"occurred":false,"id":""}` both before and after capture. The sidecar may issue
`ERROR.RESet` only for a confirmed `#emu_noframe` created by its own frame walk after the matching
`Go`; it then verifies the clean object. It leaves every other error untouched and fails the
capture. The HIL bridge records both independent clean capability results in a PASS receipt.
Recovery reports the current TRACE32 `ERROR` object but never resets it: its journal proves only
halt ownership, not ownership of the process-global error slot.
