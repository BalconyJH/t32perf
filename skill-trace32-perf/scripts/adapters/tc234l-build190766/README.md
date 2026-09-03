# TC234L SNOOPer PC Adapter, Build 190766

This directory implements exact `tricore-tc234l-snooper-pc-r2026.02-b190766-v1`. It provides statistical PC samples only; it does not claim function entry/exit, task, ISR, custom-event, or resource-counter support.

The runtime gate is fixed: `VERSION.SOFTWARE()=="R.2026.02.000190766"` (canonical release `2026.02`); production TC234L with core/config/core-number `0/1/1`; `INTERFACE.NAME()=="PowerDebug PRO"`; debug serial `E17090031792`; cable serial `C23090376246`; the TriCore license family/feature; and, after target initialization, JTAG 30 MHz with DUALPORT ON. Initial target state is running or halted. The external workload owner performs the halted-path Go → window → Break and restores halted state; CMM never performs Go, Break, or WAIT itself.

The host receives exact ELF as artifact ID `firmware-elf` and binds offline symbols by SHA-256. The Controller derives canonical sparse Motorola S3 exclusively from ELF PT_LOAD physical load segments, then Configure and Health run `Data.LOAD.S3record <controller-path> /DIFF`. The comparison is therefore the loadable firmware image, not an ELF virtual layout containing runtime RAM/BSS. `immutable-pflash-crc32.json` is only a legacy bundle input and is not runtime firmware authority.

Normal configuration is SNOOPer PC + RealTime + Stack, 65,536 records, requested 1 ms rate, ERRORSTOP ON, JITTER OFF, AutoArm/AutoInit OFF. TRACE32 does not guarantee requested rate, so quality is statistical only. Start only initializes/arms and declares workload owner `target_specific_controller`. Stop records STATE/RECORDS/SIZE before OFF in v2 evidence. Health binds immutable Stop evidence and distinguishes normal Arm, Break with `records == capacity` (`sampling_buffer_full`), and Break with fewer records (`sampling_unexpected_stop`).

ASCII export is fixed:

```text
SNOOPer.EXPORT.Ascii <controller-path> Address CYcle %TimeFixed TIme.Zero sYmbol /ShowRecord
```

`trace_overflow` and `flow_error` are explicitly `unsupported`: SNOOPer PC has neither trace stream/overflow signal nor flow decoder/TASKEVENTS export. General HIL contracts and ProgramFlow fixtures validate generic paths only and are not capability or injection evidence for this production adapter. Root dispatch rejects an unknown scenario; it never falls back to `normal`. The 32-record Stack `sampling_buffer_full` injector is only a `candidate` until exact TC234L-board HIL evidence is durable. Disconnect/CMM-abort behavior is specified in [faults/README.md](faults/README.md).

`profile.json` contains no self-authenticating qualification receipt. The deployment trust store rejects by default. Only an administrator-installed exact policy followed by `controller provision-qualification` and strict qualification/HIL artifact revalidation creates a Session admission snapshot. This command set supports software closure and later HIL evidence; no board capture or fault injection was run for this repository revision. `bundle-manifest.json` binds root dispatch, every adapter/fault CMM, capture template, legacy manifest input, and adapter version. Its `files` are unique and strictly UTF-8/ASCII-bytewise path sorted; bundle digest is SHA-256 over ordered `path SP sha256 LF` lines. Skill guidance, agent metadata, and Markdown references are deliberately excluded because changing documentation cannot change the explicitly selected runtime adapter.

Required control preconditions are:

```text
t32perf --artifact-root ROOT --json controller provision-firmware SESSION --staged FIRMWARE_ELF
t32perf --artifact-root ROOT --json controller select-scenario SESSION --scenario normal
```

Closed optional fault scenarios are `sampling_buffer_full` (candidate pending hardware evidence), `trace32_disconnect`, `driver_disconnect`, and `cmm_abort`. The latter three are fixed stop/export/start fault points requiring quarantine/recovery and a new Session. They are Controller/HIL evidence paths, not successful public `perf_capture` requests. `trace_overflow` and `flow_error` are not scenarios and fail closed.
