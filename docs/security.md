# Security Model

For deployment and failure-recovery procedures, see [operations.md](operations.md).

## Trust boundary

The T32Perf CLI is the security boundary for Sessions and artifacts. It:

- confines all output to the canonical artifact root;
- validates Session IDs and relative artifact paths;
- rejects traversal through symlinks, junctions, and reparse points;
- prevents overwrite of Sessions, artifacts, catalog records, and manifests;
- enforces quotas for individual files and total Session size;
- computes SHA-256 in a streaming manner and records provenance in the immutable `artifact-index`;
- permits an external capture process to write only to the active Session's `capture/staging`; and
- promotes files to formal artifacts only after ingestion.

For JSON crossing this trust boundary, the Rust host recursively rejects duplicate object members. Session state, requests, catalogs, manifests, capture configuration, trust policy, attestations, receipts, normalize/comparison policies, Controller transactions, retention/abandon plans and journals, release provenance, and every canonical or derived NDJSON record must not contain a duplicate object-member name. Do not rely on first-wins or last-wins parser behavior: signers, the host, Python HIL, and implementations in other languages could assign different semantics to the same bytes. JSON Schema does not perform this check, so a strict decoder must run before typed, schema, and semantic validation.

The artifact root must be writable only by the T32Perf Controller and trusted capture processes through operating-system ACLs. The current cross-platform implementation rejects symlinks, junctions, and reparse points it observes, and recomputes SHA-256 from opened artifact handles. It does not claim to defend against a malicious process with write access to the same root replacing a directory between parent-directory inspection and use. Deployments that require that adversary model need handle-relative `openat2/openat` on Unix, and native opens using directory handles with reparse traversal disabled on Windows.

`state.json` is the only mutable Session file and is replaced atomically in its containing directory. The artifact catalog is append-only; `manifest.json` is an immutable completion snapshot.

## MCP service and upstream `t32mcp`

### Host MCP service boundary

`t32perf mcp` is a Host-owned stdio façade, not a general artifact browser or a proxy for the
official upstream endpoint. Its trusted launcher fixes the artifact root and resource limits,
which tool input cannot override. It exposes only the eight documented `perf_*` operations and
returns bounded structured results or structured tool-level errors. It provides no MCP resources
or prompts and never returns large artifact bytes. A raw JSON line is limited to 1 MiB, a typed
result envelope to 256 KiB, and duplicate structured/text JSON wire representations must fit
within the 1 MiB frame limit. Each tool declares and returns only its own operation envelope;
the public terminal projection for capabilities/capture does not contain upstream execute,
collect, workload, or response handoffs. Schema range/length constraints have corresponding
runtime validation. A JSON-RPC request ID is limited to 128 encoded bytes so a response is not
lost after a Host side effect completes because its echo is oversized; an oversized ID or an
oversized/truncated frame terminates the service with a nonzero process status before dispatch.

The service retains the Controller execution lease and provenance gates. It drives
`perf_capabilities` and `perf_capture` internally, consuming upstream execute/collect/workload
handoffs without exposing these low-level actions to the client; a terminal payload can return a
high-level Host `next_action`. Cancellation can allow an operation to continue to a durable
boundary, so every client must call `perf_get_status` before retrying. MCP `perf_run` requires
the caller to provide a portable Session ID; the server does not generate an unknown random ID
for a destructive call whose response could be lost. This boundary does not expand the authority
of the trusted upstream `t32mcp` inventory or the PC-sampling/stack-sampling sidecars. Failed
MCP errors and status errors expose only stable codes and fixed safe messages. MCP-mode stderr
also omits absolute paths, external hook stderr, and arbitrary diagnostic details. Inspect full
causes only through durable operator evidence or an explicit manual CLI path.

### Upstream `t32mcp` is not an untrusted boundary

Lauterbach `t32mcp` v0.2.2 offers an unauthenticated localhost HTTP transport, runs only one PRACTICE script globally, and provides no execution ownership for collect or abort. Its default debugging skill can run the target and modify registers and memory. Do not expose a raw t32mcp endpoint to untrusted clients. The T32Perf deployment driver does not use HTTP; it owns a managed stdio child directly. This narrows exposure, but does not turn the upstream executor into an untrusted sandbox.

The driver loads configuration only from `<artifact-root>/.t32perf-control/deployment/t32mcp-driver.json`, using the fixed schema `t32perf.t32mcp-driver-config/v1`. Before startup, all of the following must hold:

- The executable is an absolute plain file, its SHA-256 exactly matches `expected_executable_sha256`, and `--version` outputs exactly `t32mcp v0.2.2`.
- The initialized server name/version is `t32mcp`/`0.2.2` and declares the tools capability.
- Paginated `tools/list` returns exactly `execute_practice_skill`, `collect_practice_skill_response`, and `abort_practice_skill`; no hidden `execute_practice`, duplicates, extras, or omissions are allowed.
- The installed adapter manifest contains only runtime inputs, stored as strictly sorted, portable-unique plain files. Skill documentation and agent metadata are excluded. Each listed SHA-256 is correct, and the canonical `path + digest` bundle SHA-256 equals the config claim, manifest claim, installed-profile `implementation_sha256`, and compiled candidate constant.

The current Windows deployment candidate is `t32mcp.exe` built from official-mirror v0.2.2 source, with recorded SHA-256 `31f4983a4e7a60a5025e8334e95e6ecb4bd242ce6bc9705f81cdf081af05dec2`. This value identifies that exact binary only. A changed toolchain, target, or rebuild requires renewed administrator approval of the digest; a version number is not a binary identity. The runtime adapter implementation digest is read from its checked-in manifest and is a separate identity from the executable digest.

Fixed CMM files may be invoked only through a typed T32Perf Controller transaction. PRACTICE scripts accept file paths, but cannot mechanically validate the host artifact root, symlinks, quotas, or exclusive creation. The Controller must authorize these properties before invocation. Calling scripts manually is not a security API.

A production deployment must satisfy one of the following:

1. t32mcp is an on-host, single-tenant trusted executor, exclusively owned by the T32Perf Controller for one artifact root; or
2. a future independent MCP service replaces path parameters with unforgeable artifact handles.

Until the second boundary exists, the skill rejects user-supplied output paths; only Controller-created staging paths may enter `script_args`.

`implementation_sha256` binds the runtime-only adapter bundle which the driver reads and recomputes on every load. It does not bind `SKILL.md`, agent metadata, or reference documentation, because those files cannot change the explicitly selected runtime script or its configuration. It is not t32mcp runtime self-attestation for parsed content. The current upstream API accepts only logical `skill_name`/`script_name` and does not return the digest of the executed bundle. The installation directory must therefore remain read-only and replaceable only by administrators, preventing an equally privileged process from swapping a runtime input after verification but before execution. Do not provision production qualification unless this ACL condition can be demonstrated. If upstream later exposes bundle identity, replace this arrangement with a digest-qualified handshake rather than continuing to trust a logical name alone.

The driver's MCP reader enforces a 1 MiB hard limit on every raw stdio JSON line and rejects truncated or invalid JSON. Official execute/collect accepts one text content block of at most 64 KiB; abort accepts only empty success. Controller framed JSON payloads have a separate 4 KiB limit. A strict pending wrapper may contain partial content, but its `<NOT FINISHED>` and `<CONTENT>` headers must each be unique and appear in the prescribed order. Every other bounded response, including a malformed response, must be written to the Host staging path specified by the immutable transaction and then passed to `controller accept` for authoritative rejection evidence. The driver must not discard raw failure evidence that an attacker could exploit before the Host sees it.

`workload` and `trace32_disconnect_at_stop` use a direct executable with separate argv, never a shell. Command templates may use only a closed set of typed placeholders, and every executable has its own SHA-256. Hook stdout must be empty; stderr, the independent timeout, and the total driver deadline are bounded. Timeout, overflow, non-zero exit, or transport failure terminates the entire process tree. Windows uses a Job Object; Unix uses a process group, both with kill-on-drop. Hook stderr is bounded diagnostics, not hardware evidence.

`driver_disconnect_at_export` accepts no external command in configuration. The driver executes Export first. If it returns a final wrapper, the raw response must be staged for the Host to determine that the fault action was missed; the child must not be forced. Only on a strict pending wrapper does the driver write `fault_intent` and a bound abort plan, consume its held handle to the exact t32mcp child, and forcibly terminate that process tree. After a successful force it writes `fault_triggered` and starts exactly one replacement child from the same fully reverified config, executable, and bundle for official abort. If force fails, it preserves the intent and plan, writes neither trigger nor confirmation, starts no replacement, and treats retry as an ambiguous fault that fails closed. The external `trace32_disconnect_at_stop` hook still runs first at the Stop boundary, before the normal Stop script. Once abort success is observed, retry only Host confirmation; never call END/abort again. A shutdown error cannot erase an observed upstream success. Cleanup failures are returned explicitly and durable quarantine is retained.

The Host supplements upstream's global one-script limit with a root namespace lock, durable full-Session scan, and the OS lease `<artifact-root>/.t32perf-control/controller/trace32-driver-execution.lock`. This lease covers config/version/init, tool calls, hooks, replacement, and shutdown/cleanup, and excludes external drivers, low-level controllers, and public performance mutations from one another. The append-only `t32perf.controller-driver-event/v1` journal records and binds `dispatch_intent`, `fault_intent`, `fault_triggered`, `abort_attempt`, `abort_success_observed`, `workload_intent`, and `workload_complete` to the request, binding, and abort plan. Restart never repeats execute, collect, workload, fault, or END; every ambiguous state fails closed. An abort plan does not release the slot: because upstream success is an unbound unit result, the deployment driver writes confirmation/receipt immediately only after official abort succeeds. Manual low-level paths still require explicit confirmation by a trusted single-tenant caller. A missing or unfinished response neither terminalizes the owner Session nor releases the slot. A bounded invalid final response is staged, rejected by the Host, and retained as evidence. The lease also remains held after Cleanup is accepted but before capture configuration is materialized. A pending transaction prevents a Session from entering normalize, attest, analysis, or finalize.

`controller driver-preflight` verifies only fixed configuration, binary/bundle, version, MCP initialization, exact tool inventory, and shutdown, and explicitly returns `tools_invoked=false`. Upstream establishes RCL only in the practice-tool handler, so this command does not connect to TRACE32. It is not safety or runtime evidence for an endpoint, probe, MCU, or board.

## Generic sampling sidecar is a separate trusted executor

`lauterbach-sampling-mcp` does not extend or weaken the official t32mcp inventory. It exposes only
capability reads and bounded PC-histogram capture, uses loopback TCP, accepts no path or free-form
command, and formats `PERF.PC.HITS()` only from validated integers. StopAndGo remains intrusive
because TRACE32 periodically halts/resumes the target; the tool never describes it as passive.

An MCP Session ID alone grants nothing. `sampling prepare` creates a fresh Created Session with a
strict immutable request and random operation ID. The capture call must present that operation ID
and exactly matching normalized ranges, bucket size, duration, method policy, core, and address
space. Before RCL connection, the sidecar obtains the Host Session lock, rechecks state/request,
requires empty artifact/intents/catalog state, and rejects a prior export. The operation ID is a
nonce/capability within this local boundary, not a remote authentication protocol; artifact-root
ACLs and the dedicated MCP transport must still prevent an untrusted process from reading Session
state or replacing request files.

The root-wide execution lease excludes cooperating official/sampling drivers. It cannot exclude a
general interactive MCP or GUI client that ignores the lease, so production sampling requires a
dedicated PowerView Remote API port and must not share it with those clients. Endpoint fingerprint
v2 binds loopback address/port, self-reported software identity, and a SHA-256 probe fingerprint
derived from the observed debug-module serial, cable serial, and debug port; raw serial values are
not emitted. It is still not cryptographic peer authentication. A deployment without
`--expected-endpoint-fingerprint` is capabilities-only. Capture requires the pinned digest and
compares it after read-only identity queries but before journal recovery or any `PERF` mutation.

Before mutation, PERF must be disabled. A pre-existing active PERF belongs to another owner and is
rejected without cleanup. Once a configure intent follows the disabled baseline, cleanup belongs to
that transaction. Cleanup failure blocks ordinary calls; only a deployment restart with
`--recover-quarantined` may retry the known-owned cleanup. This is a one-shot startup capability
consumed by the first recovery attempt, not a process-lifetime bypass. Journal event count/size and
Session export count are bounded before mutation. RCL 1.1.6 still executes in a non-killable Python worker;
loopback isolation and socket timeouts are mitigations, not a hard wall-clock termination proof.

Sidecar output remains untrusted staging. Host `sampling ingest` verifies the endpoint binding,
the exact successful journal sequence, Session operation/request digest, request-to-histogram
equivalence, and exact staged bytes before registering a reserved receipt and histogram. Generic
ingest cannot claim sampling identifiers, kinds, paths, or producers. Function attribution also
requires a reserved firmware-evidence artifact whose exact digest, Session, endpoint, proof kind,
and ELF digest agree; a producer string or histogram self-claim is insufficient.
Optional TRACE32 runtime labels remain inside the journal-bound histogram. They are limited to ten
original nonzero buckets and one dominant interval of at most four bytes per bucket; parent ranges
and counts are checked again by the Host and HIL. Published function and source values are reduced
to non-empty basenames, limited to 256 UTF-8 bytes, stripped of path separators and control
characters, and XML-escaped by the renderer. The label source is always `debugger_reported`; it
cannot promote `firmware.status`, satisfy function-projection evidence, or prove that PowerView's
loaded symbols match target memory.
The generic sampling HIL independently reopens the Session request/state, exact four-record
artifact catalog, and every bound file with no-follow, single-link, stable-snapshot checks. It
recomputes sizes and SHA-256 values and validates producer/path/input DAG before issuing PASS;
wrapper-returned artifact metadata alone is never evidence.
For the generic path, `PrecommittedElfAssertion` requires the ELF digest to have been committed in
the immutable capture request before the sidecar ran. It prevents post-capture symbol-file choice,
but remains `deployment_asserted` and is emitted with `target_image_compared=false`; it must not be
represented as verified firmware, debugger readback, or independent target-image verification.

## Intrusive stack-sampling sidecar

`lauterbach-stack-sampling-mcp` has an independent two-tool surface and its own append-only
journal, Session lease, staging namespace, and quarantine/recovery state. It requires an exact
endpoint pin before any mutating request and accepts only an immutable Host-prepared request with
`acknowledge_intrusive=true`. A Session ID alone is not authorization. The fingerprint identifies
the loopback PowerView/probe endpoint class; it does not authenticate the MCU, TARGETID, firmware,
or current program image. Version 1 therefore also fails closed unless TRACE32 reports exactly one
logical core with core 0 selected.

The mutation set is intentionally closed: bounded `Break`, at most eight frames, and `Go` with a
100 ms local RCL timeout ceiling, 1 s forward-walk deadline, and bounded `STATE.RUN()` polling.
Only PC/SP and frame navigation occur while stopped. A per-cycle ownership flag allows `Go` only
after a running-state check and durable Break intent; a stop observed after a completed owned Go is
external and is never resumed. Cancellation signals the worker before MCP teardown and prevents a
new Break. Python still cannot preempt a native RCL call, so these controls are not a hard real-time
guarantee. Failure to prove recovery leaves the endpoint quarantined. Do not erase journal files, release a lease, or
invoke `Go` through another client to make a failed transaction appear complete. The Host accepts
only journal-bound staged bytes and constructs receipts after validating the exact request,
operation, endpoint, and journal chain.

The sidecar treats TRACE32 `ERROR` as a fail-closed integrity boundary. Capabilities must expose
exactly the clean state `{"occurred":false,"id":""}` before capture and again after it. It may
issue `ERROR.RESet` only for a confirmed `#emu_noframe` caused by its own frame walk, only after the
matching owned `Go`, and only when a subsequent read proves the exact clean state. It never clears
another error ID, an unrecognised shape, or a pre-existing error; those conditions fail capture and
remain available for operator diagnosis. HIL PASS binds both independent clean observations.
The stack HIL separately pins the Host `t32perf` executable SHA-256, revalidates a no-follow,
64 MiB-bounded stable snapshot before each Host phase, and stores that digest in the receipt. The
remaining hash-to-spawn race is accepted only on a dedicated lab host where the build directory is
read-only to other principals during the run.

Break ownership relies on the dedicated single-tenant Remote API deployment: there is no TRACE32
atomic token that distinguishes a sidecar Break from an external Stop in the interval between the
last running-state read and the command. An external client on that port violates the trust model.
Append-only journal publication also performs synchronous local filesystem I/O; a hung filesystem
can outlive MCP's process-termination grace. Therefore the implementation is fail-closed and
recoverable, but it does not claim hard kill-safe or hard real-time behavior.

Recovery is not an MCP tool. `--recover-quarantined --recover-only` consumes a fresh process-level
authorization before inspecting the journal, issues `Go` only for an unmatched sidecar-owned Break,
verifies final running state, and exits. It reports but never clears the process-global TRACE32
`ERROR` slot because the journal proves halt ownership, not error ownership. Post-Go cleanup markers
never authorize an external resume.
Normal MCP startup rejects either recovery flag on its own and capture always calls journal recovery
with `authorized=false`.

Every capture authorization is spent once before any Break by an exclusive-create marker under
`.t32perf-control/stack-capture-attempts`. The marker binds Session, operation, exact immutable
request digest, and endpoint under the generated `t32perf.stack-capture-attempt/v1` contract.
Cancellation and pre-export failure do not remove it; retry requires a fresh Host Session. The
plain-file directory has a 16,384-entry ceiling and is outside Session artifact/orphan accounting.

TRACE32 symbol names and source locations are display metadata only: they are
`debugger_reported` and firmware is `unverified`. The renderer keeps source basenames, escapes
text in the SVG overlay, and makes canonical JSON the primary evidence. Takumi `2.13.3`'s Rust SVG
backend is a rendering dependency; font availability can change presentation layout and never
changes the canonical profile or its sample counts.

## External capture attestation

`session attest` provides an external trust entry point that does not depend on a producer string's self-description:

- An external adapter signs a `t32perf.capture-attestation/v1` payload with an Ed25519 private key.
- The payload binds the Session ID, the `state.operation_id` nonce, request SHA-256, canonical observation ID/SHA-256, capture-config artifact ID/exact SHA-256/configuration SHA-256, and, when present, the accepted Controller health artifact ID/SHA-256 and complete receipt. Payload and receipt must make identical config and health claims.
- Deployment-owned `t32perf.capture-trust-policy/v1` stores public keys only, limiting each key to fixed provider, adapter/version, mode, target, TRACE32 identity, clock, core, firmware ELF SHA-256 allowlist, and capability ceiling. The TRACE32 receipt ELF SHA-256 must exactly equal authoritative capture-config `adapter_parameters["firmware.elf_sha256"]`; a build ID is not a substitute. Optional configuration scope further limits sink, initial target state, RTOS awareness, timestamp, capacity, and exact configuration digest.
- The host first records the attestation as an untrusted artifact, then writes a trusted capture receipt only after signature and scope validation.
- The host does not accept a signer's free-form interpretation of Controller health. It derives one unique set of adverse observations from strict typed evidence; the signed receipt for that source must omit none and add none. This artifact enters attestation/receipt provenance and the analyzer consumes those facts from the trusted receipt.
- Analysis rereads the policy, attestation, receipt, and catalog and performs the same validation again.

The nonce prevents replaying a signed payload across Sessions or operations, but is not secret. Security derives from control of the private key, host-owned immutable request/observation/configuration digests, and strict key scope. The exact configuration digest binds current artifact bytes; the configuration digest excludes the Session ID so different Sessions can be compared for equivalent configuration.

Private keys must never enter the T32Perf artifact root, trust policy, repository, release bundle, or t32mcp AREA. The signing process should use a separate OS identity or hardware key and sign only capture that it actually verified. The CLI provides no private-key generation, custody, or signing service.

Trust policy is a privileged deployment configuration. An attacker who can replace it, or freely choose `session attest --policy FILE`, can introduce their own public key and self-sign every claim; Ed25519 provides no authenticity in that case. `--policy` may be selected only by a deployment administrator or host Controller from a fixed allowlist, never from ordinary CLI/MCP/API-client input. An MCP service must not forward a policy path, public key, or inline policy.

Policy must come from ACL-protected read-only configuration management. The Controller should map a logical policy ID to a preconfigured canonical file path before invoking the CLI. `session attest` accepts only a plain file no larger than 1 MiB and includes the exact validated copy in Session provenance. Version 1 has no online revocation, expiry, or certificate chain; the deployment system must maintain key rotation/revocation and decide whether historical policy snapshots remain acceptable.

A signature proves only that an adapter authorized by that key made these claims about these bytes. It does not automatically establish the correctness of TRACE32 commands, field mappings, or hardware capabilities. Before adding a key to production policy, complete target-specific fixture, HIL, native differential, and capability review.

## Artifact ownership

- `request.json` records a user request; it is not a hardware fact.
- Files in `capture/staging` are untrusted temporary input; failed or aborted exports must not be registered.
- `ingest-intents` is host-only crash-recovery control metadata. It binds exact operation/spec/path/size/SHA-256 and cannot be written by a capture process or MCP client.
- `controller-request/response/abort-request/abort-receipt` and the seven `controller-*-evidence/v1` kinds are host-only immutable transaction evidence. Ordinary `session ingest` preserves its ID/kind/path/producer namespace and cannot forge them. The Controller does not trust the mere existence of a JSON file: target-control success must pass the expected operation schema, duplicate-key rejection, binding match, and operation-specific semantic validation before it advances the capture phase reconstructed from artifacts.
- A registered `capture-attestation` still has an untrusted producer until verified; verification failure terminally fails the Session.
- `capture-config` is a strict authoritative artifact that must be registered before normalize/attest. It is not an independent trust source; it becomes trusted provenance only when jointly bound by a signed claim, receipt, catalog, and policy scope.
- `capture-trust-policy` is the public-key policy snapshot used for this Session; it contains no private key.
- `capture-receipt` may be written only by the synthetic Controller or the host attestation-verification path.
- Each `artifact-index/<id>.json` is created once and records size, SHA-256, producer, and input artifact IDs.
- `manifest.json` contains no absolute artifact paths. Every artifact path is a printable-ASCII, portable forward-slash relative path, unique under ASCII case folding. Unicode is allowed only in metadata that is not a physical path.
- User ELF/MAP inputs and tool-generated files must use different artifact kinds.
- The Static RAM parser does not probe or guess formats: `linker_map` and `firmware_elf` must use an explicit flavor. Before allocating its parsing buffer, ELF is limited to 256 MiB and 65,536 sections. It accepts only explicitly supported embedded architecture/object kinds and exact `SHF_ALLOC|SHF_WRITE` sections. Corrupt, duplicate, under-flagged, or arithmetic-overflowing input fails closed.

## Release security gate

Every release finding must have one severity: `Critical`, `High`, `Medium`, or `Low`. The
security reviewer assigns severity from the worst credible impact and exploitability within the
supported deployment boundary. A finding is at least `High` if it can permit untrusted command
execution, escape artifact-root or Session isolation, bypass trust-policy, signature,
qualification, or admission checks, disclose a private key or secret, forge package/source
provenance, or destructively mutate another Session. A lower severity requires retained evidence
that the path is unreachable under the supported boundary.

An open `Critical` or `High` finding blocks source freeze and release. It cannot be accepted as a
release risk. An open `Medium` or `Low` finding requires joint acceptance by the named release
owner and security reviewer. The record must contain the finding identity, severity, credible
impact, reason, compensating controls, accountable owner, and an expiry date or explicit review
trigger. An expired, triggered, indeterminate, or incomplete acceptance blocks release.

The final review keeps all reviewed inputs immutable and applies to the exact committed revision,
package and bundle
digests, policies, receipts, attestations, dependency review, and protected evidence set. The
reviewer records approval or rejects the candidate. A required change creates a new revision and
invalidates the affected preflight, package, and qualification evidence.

The current `v*` tag workflow does not implement this production gate. It publishes immediately
after software checks, does not consume a digest-bound final approval, and has no protected
production environment. Treat it as development-only until release automation separates an
immutable candidate-build stage from a protected publish stage. The publisher must verify the
approval and consume the same candidate archives without checkout, rebuild, or repack.

## CI and release supply chain

Every third-party GitHub Action in workflows is pinned to the exact 40-character commit SHA resolved from the current ref in the official repository. End-of-line `v4`, `v6`, `master`, `latest`, or `nextest` comments express upgrade intent; a mutable tag or branch is never executed directly. To update an action, resolve that ref again with `git ls-remote` against the official GitHub repository, review the upstream diff, then replace the SHA in one change. Do not supply a SHA from memory or an unofficial mirror. The current tag workflow runs software checks and package smoke tests from the exact source before its development publication; a failure prevents that publication. These checks do not satisfy the production security approval gate above.

The release bundle's `t32perf.release-provenance/v1` is create-new build evidence with a 64 KiB limit, recursive duplicate-key rejection, and closed-field semantic validation, covered by bundle `SHA256SUMS`. It binds source commit, Cargo.lock, binary, target, and the actual Rust toolchain. Windows MSVC builds require a static CRT; instead of relying on prose or environment assumptions, the packager parses PE imports and rejects dynamic VCRUNTIME/MSVCP/UCRT dependencies. Ordinary Windows system DLLs remain permitted; Linux explicitly follows a dynamic system-libc policy.

## Cleanup

`perf_cleanup.cmm` handles only target-specific capture state; the current generic implementation returns unsupported and never deletes files. Host retention first creates an immutable plan bound to the canonical root, full Session identity, exact `state.json` digest, and whole-Session file-inventory digest. Any intent, staging file, orphan, unsafe entry, or truncated inspection causes the plan to fail closed. Apply/restore must match the full plan SHA-256, acquire exclusive namespace leases in active-root → quarantine-root order, and revalidate inventory before and after moving the entire Session on the same volume to `.t32perf-control` quarantine. The CLI offers no permanent purge.

Cleanup is allowed only after the Controller's main path completes and while the Session remains `captured`. After a confirmed abort or other failure, the Session is terminal and immutable; the host adds no special cleanup-mutation branch. Necessary target recovery is a trusted operational action outside the Session, and subsequent capture must create a new Session.

Staging files, ingest intents, atomic temporaries, and orphans left by abnormal exit are neither inferred from their names nor deleted individually. `maintenance abandon` accepts only non-`complete` Sessions. Planning acquires the root namespace and Session locks, rejects a pending Controller transaction, link/reparse/non-regular entries, or a directory beyond inspection limits, and includes every regular file—including staging, orphan, and intent—in an exact inventory. After a second confirmation by plan SHA-256, apply moves the entire Session on the same volume to `.t32perf-control/abandon/quarantine`; restore can restore it completely. Complete Sessions still use the stricter retention path; neither path permanently purges.

Registered artifacts cannot be cleaned up individually, because doing so immediately corrupts the catalog, manifest, and provenance DAG. Retention's smallest unit is a complete Session. Plan, journal, diagnostic, and comparison control output live outside Sessions. Diagnostic bundles omit request bodies, trust policy, and raw artifact payload by default. Their `artifact_root_paths_redacted` claim covers only native and forward-slash representations of the canonical artifact root, not arbitrary third-party absolute paths. `.t32perf-control` and the Session root must have the same administrator ACL; ordinary MCP clients must not receive write access or submit their own confirmation digest.

A complete comparison envelope may be written only to `.t32perf-control/comparisons/<SHA256>.json`; a terminal Session must not be changed merely to reuse the Session artifact API. The envelope binds the exact policy, manifest/analysis artifact digests from both sides, and the full report. CLI/MCP returns only a bounded projection plus digest/size/path reference. Existing content at a content-addressed path whose size or digest differs from expectation is control-plane corruption. Comparison publish shares the maintenance lock with retention and diagnostics to prevent a check/publish-versus-quarantine TOCTOU.

Control documents use atomic create-new publication. An existing truncated, malformed, or field-conflicting journal is always rejected. Unix synchronizes source and destination parent directories after retention rename. Windows has no write-through guarantee, so recovery guarantees cover process crashes only, not power loss, filesystem failure, or storage-controller failure.
