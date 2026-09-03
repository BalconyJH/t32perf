# TRACE32 Performance Skill Security Boundary

Read this document when handling MCP input, Session/staging paths, capture attestation, trust policy, or artifact output.

## Trust principals

| Principal | Trusted statements | Statements it cannot establish |
|---|---|---|
| MCP caller / request | Capture intent, duration, requested metric | Hardware capability, TRACE32 state, health, clock, firmware, covered cores |
| Host Controller | Session ID, operation ownership, staging path, artifact registration, deployment-policy resolution | Hardware facts without adapter evidence |
| Deployment driver | Verified config/executable/bundle identity, exact MCP transport/tool inventory, transaction handoff | Unaccepted CMM claims or unverified hardware facts |
| Target adapter/signer | Capture claims it actually verified and signed | Capability outside its policy-key scope |
| T32Perf host | Artifact integrity, signature/scope verification, normalize/analyze/summary contract | External facts not bound by attestation and policy |

Producer strings, JSON-schema validation, filenames, and receipt content are not independent trust roots.

## Deployment driver trust root

The real driver reads only `ROOT/.t32perf-control/deployment/t32mcp-driver.json` under `t32perf.t32mcp-driver-config/v1`. Callers cannot supply config/executable/skills-root/TRACE32-port/version/digest/hook/deadline. Reject symlink/reparse paths, non-plain files/directories, non-absolute deployment executables, and bundle-member escape. Verify official executable SHA-256, exact t32mcp `0.2.2`, every runtime-manifest member digest, the canonical bundle digest, installed-profile identity, and compiled candidate identity. Documentation and agent metadata are outside runtime identity. Deployment ACLs must keep config, binaries, configured hooks, and skill root read-only for the ordinary capture identity to prevent replacement between validation and execution.

Each public driver command holds the root-wide execution lease at `ROOT/.t32perf-control/controller/trace32-driver-execution.lock`, an empty plain file protected by an exclusive OS lock and same-process canonical-root registry. It is transient exclusion, not durable artifact-based ownership. TOCTOU remains possible after initial loading, so revalidate every relevant deployment identity at child startup and every external side-effect boundary; require exact equality with initial admission.

The single-tenant stdio child must initialize as `t32mcp`/`0.2.2` and expose exactly `execute_practice_skill`, `collect_practice_skill_response`, and `abort_practice_skill`. Any extra, missing, duplicate, or hidden execute tool fails closed. `controller driver-preflight` does not call these tools or connect TRACE32.

## Driver runtime and crash safety

`controller drive` consumes only typed facade `next_action`; `drive-transaction` consumes only Host-revalidated immutable ownership. The total `operation_timeout_ms` covers execute, collect, poll, hooks, and at most one verified replacement abort. Only strict pending wrappers (`<NOT FINISHED>`, unique `<CONTENT>`, no later status marker) may collect; stage every other bounded wrapper unchanged for Host accept. Never discard evidence, replace a frame, or forge rejection before the Host.

Only `workload` and hook-first `trace32_disconnect_at_stop` are configurable external commands. They use closed placeholders, direct argv/no shell, exact SHA-256, empty stdout, bounded stderr/timeout, and process-tree termination on failure. `driver_disconnect_at_export` is not a hook: execute Export once, stage every bounded final as fault-missed, and only strict pending permits a fully revalidated forced disconnect and one abort-only replacement.

Side-effect authority exists only in strict append-only `t32perf.controller-driver-event/v1`: `dispatch_intent`, `fault_intent`, `fault_triggered`, `abort_attempt`, `abort_success_observed`, `workload_intent`, and `workload_complete`. They are request-bound intent/observation artifacts, not target evidence, accepted responses, or abort receipts. No replay after dispatch; no workload rerun without complete; no fault redo or abort before triggered plus durable plan; no second abort after an ambiguous attempt; after observed success, only Host confirm. Ambiguous state retains durable root ownership and cannot be cleared with a new transaction, deleted journal, or synthetic response.

Cleanup rejection/evidence mismatch/unproven state restoration retains the endpoint and requires two-phase abort, terminal failure, and endpoint/target quarantine. Accepted Cleanup without materialized authoritative config is repair-pending; only idempotent `controller accept` for the same transaction may reconstruct strict config. Do not manually write config, enable Hotspots, or open another transaction around the gate.

## Policy, signer, and paths

`session attest --policy` accepts only a fixed read-only deployment-owned `t32perf.capture-trust-policy/v1` resolved by the Controller from an allowlisted policy ID. Never accept a caller filesystem path, policy JSON, public key, or key scope; never import a public key from attestation or write a temporary Session policy. Rotation/revocation is an administrator operation.

Private keys remain in a separate signer identity or hardware key and never enter skill files, artifact roots, t32mcp AREA, CLI arguments, logs, or caller requests. Before Host trust, a signed `t32perf.capture-attestation/v1` is untrusted. Verify signature, policy key/producer, Session/nonce/request/observations, capture-config ID/digest/cross-Session digest/catalog equality, provider/adapter/mode, target/TRACE32 identity, clock/cores, firmware, capability ceiling, and policy-scoped sink/initial-state/RTOS/config claims. Older v1 documents without a capture-config claim may parse but cannot pass trusted external analysis. Verification failure terminally fails the Session; do not change policy, replace attestation, or overwrite artifacts in place.

Only trusted Controller and capture processes write artifact root. The Controller allocates export paths under Session `capture/staging`; callers cannot select them. Driver-to-t32mcp MCP is held-child stdio and is never exposed on a network. The configured TRACE32 RCL port is unauthenticated single-tenant lab control and must not be exposed to untrusted networks. Fixed skill/script names prohibit caller PRACTICE/CMM/arbitrary commands. Failed export files remain in staging/quarantine and are not formal artifacts.

## Output gate

MCP receives only bounded control-plane data: Session state, health-gated `summary --top N`, manifest references, and artifact-metadata references. `VALID` may return bounded quantitative data. `DEGRADED` and `INVALID` return diagnostics, metric support, and references only. `NOT_EVALUATED` and `INCOMPLETE` do not construct summaries. Raw trace, canonical NDJSON, derived stream, Perfetto, and large JSON never enter AREA/MCP responses. Never bypass the gate by directly reading or aggregating analysis artifacts.

This iteration has not called t32mcp PRACTICE or connected TRACE32/a target board. Driver preflight, software HIL, and parser fixtures prove local contracts only; they do not prove MCU/probe/TRACE32/RTOS runtime facts. RTOS/Linux, a second platform, and TASKEVENTS program-flow/ELF/ORTI hardware-flow evidence remain deferred.
