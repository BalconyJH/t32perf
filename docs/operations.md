# Operations, Secure Deployment, and Troubleshooting

## Production baseline

T32Perf CLI is the security boundary for Sessions and artifacts. A production deployment must use a verified release bundle in a read-only directory; a sufficiently large local artifact root writable only by one T32Perf Controller and required trusted capture processes; OS ACLs that deny ordinary users, web-service identities, and untrusted processes; and an isolated, same-host or laboratory-network t32mcp/TRACE32 deployment that is never exposed to untrusted clients. Each probe has one owner, with an independent lock file for real HIL.

External capture uses a separate Ed25519 signer. Its private key never enters the artifact root; the public-key trust policy comes from ACL-protected read-only configuration management, and ordinary clients cannot choose a policy path or public key. Configure production quotas explicitly rather than relying on the default 64/256 GiB. Keep TRACE32, probes, licences, ELF/MAP, ORTI/ARTI, and board-private configuration out of public repositories and generic release bundles. Run `validate --deep` before archiving every completed Session.

For the full threat model, see [security.md](security.md). The implementation rejects observed symlinks, junctions, and reparse points and recomputes digests from opened handles. It does not protect against a malicious process which has write access to the same artifact root and swaps a directory between inspection and use. Restricting write access to the trusted Controller is therefore a correctness requirement, not merely hardening.

## t32mcp deployment boundary

The deployment driver uses the official t32mcp `0.2.2` stdio transport, not its optional unauthenticated localhost HTTP endpoint. Its fixed configuration is only:

```text
<ROOT>/.t32perf-control/deployment/t32mcp-driver.json
```

It must strictly conform to `t32perf.t32mcp-driver-config/v1`, indexed in the [schema catalog](schema-catalog.md). Before each startup the driver rechecks an absolute plain t32mcp executable, exact executable SHA-256, exact `t32mcp v0.2.2` version output, and absence of symlinks/junctions/reparse points in the skills root and adapter members. The runtime-only manifest, per-file digests, canonical bundle digest, config claim, installed profile, and compiled candidate must all agree. Read the current implementation digest from the checked-in manifest rather than copying it into documentation. The Windows official-mirror v0.2.2 executable SHA-256 observed by the archived preflight is `31f4983a4e7a60a5025e8334e95e6ecb4bd242ce6bc9705f81cdf081af05dec2`; it identifies a different deployment object. That preflight used historical adapter implementation `feb46173441d2225b522a03cfae2486031fb72c6d8170baf374038848dcb2293`, so the current bundle requires a fresh preflight record. Replacing or rebuilding either deployment object requires managed-configuration updates and renewed approval.

During deployment:

1. Do not start or forward the unauthenticated HTTP endpoint.
2. Do not share one t32mcp instance across tenants or artifact roots; one root owns one endpoint.
3. Permit only driver-created stdio children. `tools/list` must be exactly `execute_practice_skill`, `collect_practice_skill_response`, and `abort_practice_skill`.
4. Invoke only the fixed `skill_name=trace32-perf` and fixed script names.
5. Take all arguments from immutable `controller prepare` requests; only Controller-created and validated staging paths may enter CMM.
6. Bound MCP JSON lines to 1 MiB, tool text to 64 KiB, and Controller JSON payloads to 4 KiB. AREA carries only this bounded frame; trace data is written directly to files.
7. Monitor durable pending transactions and the driver journal with `controller status`. When a root is busy, do not start a second script or manually invoke low-level mutations.
8. A strict pending wrapper begins with unique, ordered `<NOT FINISHED>` and `<CONTENT>` headers. Only that grammar permits collect. Every other bounded response, including malformed pending/final wrappers, is staged to the fixed response path and submitted to Host `accept`; never discard it in the driver.
9. Do not ingest staging files left by a failed export; preserve them as evidence.
10. Only trusted deployment administrators/Controller identities may write the artifact root, driver config, t32mcp binary, skills root, or hook executable.

`workload` and `fault_actions.trace32_disconnect_at_stop` are direct-argv commands. Each declares its own `expected_executable_sha256`; no shell is used and placeholders are a closed typed set. Hook stdout is empty and stderr, hook timeout, and full driver deadline are bounded. Timeout, overflow, failure, or transport failure terminates the whole process tree. On Unix, success also waits for the dedicated hook process group to become empty; trusted hooks must not move descendants into another session or process group. At the Stop boundary, persist fault intent/abort plan first; do not run the normal Stop script. On hook success write `fault_triggered` and use official abort/confirm on the original child. Never retry an ambiguous one-shot hook or END.

`driver_disconnect_at_export` accepts no external hook. Execute Export on the exact child first. A final response is staged and accepted by the Host; do not force the child. Only a strict pending response permits durable `fault_intent`/abort-plan creation, force of the exact child process tree, `fault_triggered`, and exactly one replacement child for official abort/confirm. The replacement must fully reload and reverify fixed config, binary SHA/version, skills manifest/profile/compiled digest, and exact tool inventory within the remaining deadline. Preserve journal, plan, and quarantine if force or replacement fails; do not restart indefinitely.

## Generic sampling-sidecar boundary

The generic PC-sampling sidecar is a separate uv project at
`tools/lauterbach-sampling-mcp`; it never changes the official t32mcp three-tool inventory. Run it
only against a dedicated PowerView Remote API over loopback TCP. Do not run the interactive
`lauterbachdebugger-mcp`, a second artifact root, or an ad-hoc RCL client against the same port.

The Host must issue the request with `sampling prepare`. MCP `sampling_capture` receives the exact
returned Session ID, operation ID, ranges, bucket size, duration, method policy, core, and address
space. The sidecar validates them under the Session lock before RCL connection. A plain Session ID
or ordinary `{}` Session request is not authorization.

After `PERF.OFF` and before owned cleanup, the sidecar may perform bounded read-only refinement and
symbol queries for the ten hottest original buckets. The resulting optional labels are embedded in
the same canonical histogram bytes and therefore covered by the existing export journal, digest,
Host ingest, and HIL replay. They contain no absolute source path and remain
`trace32_symbol_table` / `debugger_reported`; operators must not interpret them as verified
firmware or a function-level redistribution of the whole coarse bucket.

The sidecar uses the root-wide execution lease, a separate bounded journal at
`.t32perf-control/sampling-driver-events`, and an immutable endpoint binding. The journal permits
at most 16,384 events and 64 MiB. A pre-existing nonzero PERF state is owned by someone else and is
rejected without `PERF.DISable`. An owned cleanup failure blocks ordinary capture; only a deployment
administrator may restart the sidecar with `--recover-quarantined` to retry that cleanup. That
startup authorization is consumed by its first recovery attempt, whether it succeeds or fails; a
later quarantine requires another explicit restart. Preserve the journal before doing so.

`sampling ingest` must be the only promotion path. It verifies the exact ten-event success sequence
and produces the Host capture receipt; ordinary `session ingest` rejects sampling IDs, kinds,
paths, and producers. RCL 1.1.6 remains a blocking in-process library: socket timeout and loopback
isolation do not form a hard kill deadline if a peer continually supplies partial data. Treat a
hung worker as endpoint quarantine and move to a process-supervised deployment before admitting a
remote or hostile endpoint.

If the immutable request includes `deployed_firmware_elf_sha256`, an administrator may stage that
exact ELF and run `sampling bind-firmware` after capture. The command validates the digest and ELF,
then creates reserved precommitted-assertion evidence. It does not contact TRACE32, compare target
memory, or produce `verified` firmware status; use address-only output if the assertion is unavailable.

## Intrusive stack-sampling operations

Operate `lauterbach-stack-sampling-mcp` on a separate, endpoint-pinned deployment. It exposes
only `stack_sampling_capabilities` and `stack_sampling_capture`; it does not share the aggregate
PC-sampling inventory. Obtain the immutable request with `stack prepare`, pass the returned exact
arguments to the sidecar, then use `stack ingest`, `stack analyze`, `stack summary`, and `stack
render`. The request must contain `acknowledge_intrusive=true`; period, duration, sample, and
frame bounds are 10..=1000 ms, 100..=60000 ms, 1..=512, and 1..=8. Version 1 accepts only
`core_id=0` after TRACE32 proves one logical core and selected core 0. The sidecar caps local RCL
socket waits at 100 ms and stops further frame walking after a 1 s deadline; these are software
bounds, not a hard real-time guarantee.
Capture requires capabilities to report the exact clean TRACE32 `ERROR` object
`{"occurred":false,"id":""}`. Only a confirmed `#emu_noframe` generated by a frame walk may be
reset after the matching `Go`, and the reset must be followed by a clean-state verification. Do not
clear any other ERROR: preserve it, fail the capture, and investigate the debugger state. HIL PASS
binds independently obtained clean capabilities both before and after capture.
Before any Break, a create-new `t32perf.stack-capture-attempt/v1` marker permanently spends the
Session operation. It binds the exact request digest and endpoint under
`.t32perf-control/stack-capture-attempts/<SESSION>.json`; cancellation or failure requires a new
Host Session, never a replay of the old operation. Retain at most 16,384 markers per artifact root.

Every sample stops the target for a frame walk and then requests `Go`. Treat cancellation, RCL
failure, missing running confirmation, or journal uncertainty as a recovery event. Preserve the
sidecar journal and Session lease, inspect the final target state, and use the explicit recovery
path. Do not manually rerun a partial capture. HIL acceptance must decide whether the final target
is running; the sidecar's cleanup attempt alone is not proof.

Recovery is a one-shot process operation, not an MCP tool and not a new capture:

```powershell
lauterbach-stack-sampling-mcp --host localhost --port 20001 --protocol TCP --timeout 10 `
  --artifact-root <ROOT> --expected-endpoint-fingerprint <SHA256> `
  --recover-quarantined --recover-only
```

The command consumes its authorization before inspecting/recovering the journal, issues `Go` only
for an unmatched sidecar-owned Break, verifies the final running state, prints bounded JSON, and
exits. Recovery reports but never resets TRACE32's process-global `ERROR` slot: the journal proves
halt ownership, not error ownership. Inspect any reported error separately. Preserve the failure
marker and retry from a fresh process if recovery itself fails.

Use canonical raw/folded JSON for review and comparison. Takumi SVG is a bounded presentation
artifact; platform fonts can affect text geometry but must not affect IDs, paths, or widths.
`terminal_unverified`, `halt_deadline`, and other truncated samples require operator attention and
cannot be repaired by adding a caller. Width represents sample count only.

## Execution lease and crash journal

Every root uses this execution lease:

```text
<ROOT>/.t32perf-control/controller/trace32-driver-execution.lock
```

Acquire its OS-exclusive lock non-blockingly before reading configuration, and retain it through reload/reverification, initialization, tool calls/polls, hooks, response staging/acceptance, abort confirmation, Cleanup capture-config materialization, and child/process-tree cleanup. The file remains an empty plain file: never delete, write, or replace it with a symlink/reparse object. External `perf_capabilities`, `perf_capture`, firmware/qualification/scenario provisioning, `controller prepare/accept/abort/confirm-abort`, and recovery mutations use the same lease.

The append-only strict `t32perf.controller-driver-event/v1` journal, indexed in the [schema catalog](schema-catalog.md), lives at `logs/controller/driver-events/<TRANSACTION>/`, with kind/producer `controller_driver_event` / `t32perf-controller-driver-journal/v1`. Its closed event set is:

```text
dispatch_intent
fault_intent
fault_triggered
abort_attempt
abort_success_observed
workload_intent
workload_complete
```

Each event binds immutable request ID/SHA-256, full binding, and operation; fault/abort events bind the exact abort plan and workload events bind accepted Start state and workload identity. Events prove Host intent or observation, never accepted responses, target evidence, or confirmed receipts. Do not forge reserved kind/producer/path through ordinary ingest.

Recovery is conservative: after `dispatch_intent` with no staged response, do not repeat execute or blindly collect; recover by durable abort/quarantine. After `workload_intent` without `workload_complete`, do not rerun workload and report ambiguity; both markers allow safe Stop recovery. After `fault_intent` without `fault_triggered`, do not rerun the fault or perform an unproven abort. After `abort_attempt` without `abort_success_observed`, END is ambiguous and must not be retried; with success observed, retry Host confirmation only.

After Cleanup acceptance, retain the lease while the Host idempotently creates or recovers authoritative `capture-config` under the namespace/session lock; return `capture_config_ready` only then. Failed child shutdown/force cleanup returns `CONTROLLER_DRIVER_CLEANUP_FAILED` with the primary error, `durable_host_state_preserved=true`, and all response/journal/receipt/quarantine/ingest-intent evidence retained. `perf_export.cmm` accepting a path does not validate the host artifact root, ACLs, symlinks, quotas, or exclusive creation; manual invocation is not a security API.

## Startup and routine checks

```text
t32perf --version
t32perf --artifact-root <ROOT> --json doctor
t32perf --artifact-root <ROOT> --json controller driver-preflight
```

`doctor` currently marks real hardware probes unsupported and returns 20 even when it finds t32mcp and TRACE32. This is a conservative gate, not a failed health check. Do not turn it into exit 0 or fabricate hardware state. `controller driver-preflight` verifies fixed configuration, binary/bundle, `--version`, MCP initialize, exact tools inventory, and shutdown; success includes `tools_invoked=false`. It invokes no practice tool and therefore does not connect TRACE32. It proves only the control-plane deployment contract, not endpoint or board evidence. It holds the same root-wide lease through child shutdown; investigate the current owner when busy—never delete the lock or kill an unknown process.

```text
t32perf --artifact-root <ROOT> --json session list --limit 100
t32perf --artifact-root <ROOT> --json session status <SESSION>
t32perf --artifact-root <ROOT> --json controller status <SESSION>
t32perf --artifact-root <ROOT> --json artifacts list <SESSION> --limit 100
t32perf --artifact-root <ROOT> --json validate <SESSION> --deep
```

Automate against `state.state`, `revision`, `trust_status`, `manifest_committed`, artifact count, and exit codes—not directory existence or `report/trace.json`. For TRACE32 driver Sessions inspect `controller status` and reserved `logs/controller/driver-events/` artifacts. Intent is not success: `workload_intent` does not prove workload completion and `abort_attempt` does not prove END success. Let the driver use its full event projection for recovery rather than manually replaying a side effect.

When a list has `truncated=true`, pass `next_after` unchanged to the next `--after` until `truncated=false`. Do not evade pagination by increasing stdout limits. Per-page `--limit` is at most 1000; root enumeration beyond 100000 entries fails closed, so reduce root size through retention or deployment-side sharding.

The complete comparison report is content-addressed `t32perf.comparison-artifact/v1` at `.t32perf-control/comparisons/<SHA256>.json`, not in a terminal Session. Check compare exit code/verdict, then read the ordinary file at `result.report_artifact.control_path` and verify `size_bytes` and `sha256`. stdout is a bounded Top-N projection. A mismatch at an existing digest path is control-plane corruption: stop using the root and audit ACL/storage; never overwrite it.

For external capture, retain `session.attest` `policy_id`, `key_id`, and producer, and confirm `capture-attestation`, `capture-trust-policy`, and `capture-receipt` exist. Do not infer signature validation from receipt JSON alone. Service/MCP deployment must map a logical environment/platform to an administrator-configured allowlisted policy; never pass request policy/path/public-key input directly to `session attest`.

## Logs, benchmarks, and Perfetto validation

stdout is the command protocol; stderr contains logs and non-JSON errors. Machine callers always use `--json` and capture both streams. The default level is `warn`; temporary diagnosis may use:

```text
RUST_LOG=info t32perf --artifact-root <ROOT> --json session status <SESSION>
```

With `T32PERF_LOG_FORMAT=json`, every stderr log is a separate JSON object. Logs record stable command/error/exit fields, not CLI arguments, requests, policy paths, or artifact contents. Do not leave detailed logging enabled or export operational logs to unauthorized systems.

```text
cargo xtask bench --input <canonical-observations.ndjson>
cargo xtask bench --extended
```

The manual `.github/workflows/benchmark.yml` can run optional 1M/10M parser candidates on Windows/Linux and upload JSON or extended Criterion artifacts. Preserve commit, runner image, input size/digest, RSS sampling interval, and limitations. The repository currently has only 2026-08-23 local Windows x86_64 evidence, not GitHub Linux evidence; see [implementation-status.md](implementation-status.md). A tag release runs `cargo xtask check`, creates archives with `T32PERF_COMMIT=${{ github.sha }}`, and smoke-tests them in every package matrix job before publishing. Windows uses `+crt-static` and PE-import auditing to reject dynamic MSVC/UCRT; Linux permits dynamic system libc.

After conversion, deep-validate the Session, then validate with the official Perfetto Python wrapper:

```text
uv run --no-project --with perfetto==0.57.2 tools/validate_perfetto.py [--trace-processor <BIN>] <report/trace.json>
```

On controlled or offline networks, provide an approved, digest-verified local binary with `--trace-processor`; otherwise the package may download its pinned binary. The release bundle includes `tools/validate_perfetto.py`, not the Python `perfetto` package or `trace_processor_shell`. The 2026-08-24 Windows synthetic validation—official `google/perfetto` v56.1 asset and manifest digests verified—reported slice/counter/track = 32/31/3 and zero non-zero warning/error statistics; see [`perfetto-windows-x86_64-2026-08-24.json`](verification/perfetto-windows-x86_64-2026-08-24.json). It is not real TRACE32, hardware, cross-platform, or UI evidence.

## Backup, retention, and recovery

The CLI offers no recursive deletion. Retention moves complete Sessions to recoverable same-root quarantine:

```text
t32perf --artifact-root <ROOT> --json maintenance retention plan --session <SESSION> [--session <SESSION> ...]
t32perf --artifact-root <ROOT> --json maintenance retention apply <PLAN_ID> --confirm <PLAN_SHA256>
t32perf --artifact-root <ROOT> --json maintenance retention restore <PLAN_ID> <SESSION> --confirm <PLAN_SHA256>
```

Plans accept only explicitly named, `complete` Sessions whose `maintenance inspect --deep` checks are healthy. Intent, staging, unregistered files, links/reparse/non-regular entries, or truncated inspection reject planning. Each plan binds exact `state.json`, request, manifest, revision, artifact count, and canonical inventory of all control/artifact regular files. Plans are create-new JSON in `.t32perf-control/retention/plans`; apply matches the full SHA-256, locks active root then quarantine root, renames the complete Session to `.t32perf-control/retention/quarantine/<PLAN_ID>/<SESSION>`, and records a create-new journal. Existing malformed/conflicting journals fail closed. Repeated apply/restore is idempotent and never copies or overwrites a Session.

For abnormal, non-complete Sessions, isolate the whole Session; never delete an individual `.tmp`, staging file, or intent:

```text
t32perf --artifact-root <ROOT> --json maintenance abandon plan <SESSION>
t32perf --artifact-root <ROOT> --json maintenance abandon apply <PLAN_ID> --confirm <PLAN_SHA256>
t32perf --artifact-root <ROOT> --json maintenance abandon restore <PLAN_ID> --confirm <PLAN_SHA256>
```

Abandon requires no pending Controller transaction, no live Session lock, no link/reparse/non-regular entry, and a non-truncated scan. It deliberately inventories staging/orphan/ingest-intent crash evidence. Apply/restore locks active root → quarantine root → Session, revalidates before and after the move, and journals rename-crash recovery. Complete Sessions must use retention.

Safe retention is: choose only `complete` Sessions that pass `validate --deep`; record canonical root and exact IDs; back up the entire Session including `.session.lock`, catalog, request, state, manifest, and artifacts; deep-validate the backup; review plan IDs/SHA-256 before apply; and handle any permanent quarantine deletion outside the CLI under separate approval, backup, and exact-path validation. Never delete an individual registered artifact, catalog record, or manifest file. `.t32perf-control` shares the artifact-root ACL; ordinary MCP clients never write it.

```text
t32perf --artifact-root <ROOT> --json maintenance inspect <SESSION> --deep
t32perf --artifact-root <ROOT> --json maintenance diagnostics <SESSION>
t32perf --artifact-root <ROOT> --json maintenance schema [SESSION]
```

`inspect` reports state/request/catalog/manifest validation, intent classification, staging, unregistered files, and link/reparse risks. It reports counts, independent `*_truncated` flags, and at most 512 sorted samples; tree inspection stops at 100,000 entries and is unhealthy. `diagnostics` creates bounded (1 MiB) JSON and SHA-256 under `.t32perf-control/diagnostics`, normally excluding request body, capture trust policy, and raw payload. `artifact_root_paths_redacted: true` redacts only canonical artifact-root native/forward-slash variants, not arbitrary third-party absolute paths. `schema` lists checked-in schemas and observed artifact kinds; v1 is the sole major version, and a future migration creates a new Session plus receipt rather than rewriting in place.

Control documents publish atomically with create-new semantics. Unix synchronizes both parent directories after rename. Windows has no write-through guarantee, so recovery covers process crashes, not power loss, filesystem, or storage-controller failure. Restore only to a new empty trusted root and then run:

```text
t32perf --artifact-root <RESTORED_ROOT> --json validate <SESSION> --deep
```

Never edit a digest-mismatched file, catalog record, or manifest to “repair” restoration. Preserve the damaged copy and restore again from a trusted source or recapture.

## Failure handling and triage

Session artifacts are immutable. Failed `analyze` or `convert` marks the Session `failed`; registered partial output remains audit evidence. Save `session status` and `artifacts list`, preserve `.session.lock` and all partial artifacts, repair the external cause, create a new Session ID, and run capture/ingest, analyze, convert, and deep validation again. Do not rewrite `state.json` or retry analysis in a crashed `processing` Session. `STATE_PERSISTENCE_FAILED` means both the original operation and failed-state write may have failed: stop all root writes and run `maintenance inspect`.

Common rules: exit 20 from `doctor` means unsupported real-hardware probing; `CONTROLLER_DRIVER_TIMEOUT`, `CONTROLLER_DRIVER_LOOP_LIMIT`, dispatch/workload/fault/abort ambiguity, cleanup failure, or missing `capture_config_ready` requires preserving transaction/journal/receipt/quarantine evidence and following event-projection recovery, never manually repeating execute, collect, hook, or END. A bounded invalid final response is staged for authoritative `controller accept` rejection. `capture provider ... unavailable` means only `synthetic` is built in; real capture requires a trusted Controller. A trusted capture receipt is required for analysis. Normalization, attestation, policy-scope, ingest-intent, artifact-digest, Session-lock, path, quota, NDJSON, resource-flavor, package no-overwrite, and Perfetto-download failures all fail closed: retain evidence, correct the producer/deployment input, and use a new Session where required.

When summary, manifest, catalog, or provenance integrity is suspect: stop writes to that artifact root; save `session status`, `artifacts list`, and failed `validate --deep` output; copy the full Session as read-only evidence; audit Controller, capture process, ACLs, backup/sync tooling, and storage health; exclude the affected Session from comparisons and reporting; then restore from a trusted backup or recapture with a new Session ID.
