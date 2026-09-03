from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import harness
from harness import (
    BoardConfig,
    CaptureEvidenceMatrix,
    HilOutputError,
    SessionAudit,
    VerifiedArtifact,
    VerifiedSession,
    assert_elf_mismatch_health,
    assert_flow_error_health,
    assert_overflow_health,
    build_recovery_verification,
    capture_evidence,
    reserve_recovery_evidence,
    run_expected_failure,
    run_recovery,
    verify_native_differential,
    write_capture_evidence_matrix,
    write_recovery_verification_receipt,
)
from target_adapter_recovery import TargetAdapterRecoveryEvidence
from verification_receipt import canonical_sha256


def board_config(
    tmp_path: Path,
    *,
    board_id: str = "board-1",
    mcu_family: str = "Cortex-M",
    rtos: str | None = "FreeRTOS",
) -> BoardConfig:
    tmp_path.mkdir(parents=True, exist_ok=True)
    capability_bytes = b'{"source":"fixture","verified":true}\n'
    (tmp_path / "capability-evidence.json").write_bytes(capability_bytes)
    capability_sha256 = hashlib.sha256(capability_bytes).hexdigest()
    fault_scenarios_bytes = json.dumps(
        {
            "schema": "t32perf.trace32-fault-scenarios/v1",
            "adapter_id": "fixture-adapter",
            "scenarios": [
                {
                    "scenario": "sampling_buffer_full",
                    "support": "candidate",
                    "evidence_status": "pending_hardware_evidence",
                    "reason": "fixture injector",
                    "configure_script": "faults/inject.cmm",
                    "capacity_records": 32,
                    "driver_end_condition": "records_equal_capacity",
                    "expected_health_issue": "sampling_buffer_full",
                },
                {
                    "scenario": "trace32_disconnect",
                    "fault_point": "stop",
                    "driver_action": "close_transport",
                    "recovery_requires_new_session": True,
                },
                {
                    "scenario": "driver_disconnect",
                    "fault_point": "export",
                    "driver_action": "close_transport",
                    "recovery_requires_new_session": True,
                },
                {
                    "scenario": "cmm_abort",
                    "fault_point": "start",
                    "target_script": "faults/abort.cmm",
                    "recovery_script": "faults/recover.cmm",
                    "driver_action": "abort",
                    "recovery_requires_new_session": True,
                },
                {
                    "scenario": "trace_overflow",
                    "support": "unsupported",
                    "reason": "no trace stream",
                },
                {
                    "scenario": "flow_error",
                    "support": "unsupported",
                    "reason": "no flow decoder",
                },
                {
                    "scenario": "elf_mismatch",
                    "support": "unsupported",
                    "reason": "flash mutation is deferred",
                },
                {
                    "scenario": "sampling_unexpected_stop",
                    "support": "unsupported",
                    "reason": "no deterministic injector",
                },
            ],
        },
        sort_keys=True,
    ).encode()
    (tmp_path / "fault-scenarios.json").write_bytes(fault_scenarios_bytes)
    fault_scenarios_sha256 = hashlib.sha256(fault_scenarios_bytes).hexdigest()
    profile = json.loads(
        (
            Path(__file__).parents[2]
            / "skill-trace32-perf/scripts/adapters/tc234l-build190766/profile.json"
        ).read_text(encoding="utf-8")
    )
    profile["adapter_id"] = "fixture-adapter"
    profile["implementation_sha256"] = "b" * 64
    profile["build_gate"] = {
        "trace32_release": "2026.02",
        "minimum_build": 183242,
        "maximum_build": 183242,
        "architecture_package": "fixture-arch",
    }
    profile_bytes = json.dumps(profile, indent=2).encode()
    (tmp_path / "profile.json").write_bytes(profile_bytes)
    profile_file_sha256 = hashlib.sha256(profile_bytes).hexdigest()
    profile_sha256 = harness._rust_profile_canonical_sha256(profile)
    path = tmp_path / "board.toml"
    rtos_line = "" if rtos is None else f'rtos = "{rtos}"'
    path.write_text(
        f"""
[board]
id = "{board_id}"
mcu_family = "{mcu_family}"
{rtos_line}
covered_cores = [0]
capture_modes = ["etm", "sampling"]
lock_file = "locks/probe.lock"

[trace32]
release = "2026.02"
build = 183242
validated_builds = [183242]
probe_id = "probe-{board_id}"
architecture_package = "fixture-arch"
license_features = ["trace", "rtos-awareness"]
capability_evidence = "capability-evidence.json"
capability_evidence_sha256 = "{capability_sha256}"
target_adapter_profile_sha256 = "{profile_sha256}"
target_adapter_profile = "profile.json"
target_adapter_profile_file_sha256 = "{profile_file_sha256}"
fault_scenarios = "fault-scenarios.json"
fault_scenarios_sha256 = "{fault_scenarios_sha256}"
trace_routing = ["ETM0->TPIU0:TRACECLK,TRACED0-3"]
tick_ns = 10.0

[host]
t32perf_bin = "bin/t32perf"
artifact_root = "artifacts"
recovery_evidence_root = "recovery-evidence"
min_free_bytes = 4096

[driver.commands]
capture = ["driver", "capture", "--run", "{{run}}"]
overflow_capture = ["driver", "overflow"]
native_stats = ["driver", "native"]
sampling_buffer_full_capture = ["driver", "sampling-buffer-full"]
trace32_disconnect_capture = ["driver", "trace32-disconnect"]
driver_disconnect_capture = ["driver", "driver-disconnect"]
cmm_abort_capture = ["driver", "cmm-abort"]
""".strip(),
        encoding="utf-8",
    )
    return BoardConfig.load(path)


def test_verified_json_artifact_rejects_duplicate_object_keys(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.json"
    contents = b'{"session_id":"session-a","verdict":"VALID","verdict":"INVALID"}\n'
    path.write_bytes(contents)
    artifact = VerifiedArtifact(
        artifact_id="health",
        kind="health",
        path=path,
        relative_path="analysis/health.json",
        media_type="application/json",
        size_bytes=len(contents),
        sha256=hashlib.sha256(contents).hexdigest(),
        producer="test",
        input_artifact_ids=(),
        file_identity=None,
    )
    session = VerifiedSession(
        session_id="session-a",
        path=tmp_path,
        manifest={},
        artifacts={"health": artifact},
        cli_validation={},
    )

    with pytest.raises(RuntimeError, match="duplicate JSON object key `verdict`"):
        session.read_json_artifact("health")


def install_fake_validate(
    monkeypatch: pytest.MonkeyPatch, board: BoardConfig
) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run(
        argv: list[str], *, cwd: Path, timeout_seconds: float
    ) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        assert cwd == board.path.parent
        assert timeout_seconds == 300.0
        session_id = argv[-2]
        health_path = board.artifact_root / session_id / "analysis/health.json"
        health = json.loads(health_path.read_text(encoding="utf-8"))
        verdict = health["verdict"]
        manifest = json.loads(
            (board.artifact_root / session_id / "manifest.json").read_text(
                encoding="utf-8"
            )
        )
        returncode = {"VALID": 0, "DEGRADED": 10, "INVALID": 11}[verdict]
        payload = {
            "ok": True,
            "command": "validate",
            "result": {
                "session_id": session_id,
                "status": "complete",
                "deep": True,
                "artifact_count": len(manifest["artifacts"]),
                "health_verdict": verdict,
                "valid": verdict != "INVALID",
            },
        }
        return subprocess.CompletedProcess(
            argv, returncode, stdout=json.dumps(payload), stderr=""
        )

    monkeypatch.setattr(harness, "_execute_process", fake_run)
    return calls


def create_session(
    board: BoardConfig,
    session_id: str,
    *,
    verdict: str = "VALID",
    issue_codes: tuple[str, ...] = (),
    tagged_session_id: str | None = None,
    mode: str = "etm",
    initial_state: str = "running",
    hotspot_overrides: dict[str, object] | None = None,
) -> Path:
    session_path = board.artifact_root / session_id
    (session_path / "capture").mkdir(parents=True)
    (session_path / "analysis").mkdir()
    owner = tagged_session_id or session_id
    observations = (
        "\n".join(
            [
                json.dumps(
                    {
                        "schema": "t32perf.observation/v1",
                        "session_id": owner,
                        "encoding": "ndjson",
                        "time_unit": "ns",
                        "time_origin": "session_relative",
                    }
                ),
                json.dumps(
                    {
                        "type": "DefineContext",
                        "id": "task-main",
                        "kind": "task",
                        "name": "Main",
                        "core_id": 0,
                        "priority": 5,
                    }
                ),
                json.dumps(
                    {
                        "type": "DefineContext",
                        "id": "idle",
                        "kind": "idle",
                        "name": "Idle",
                        "core_id": 0,
                        "priority": 0,
                    }
                ),
                json.dumps(
                    {
                        "type": "DefineContext",
                        "id": "irq-5",
                        "kind": "isr",
                        "name": "Timer IRQ",
                        "core_id": 0,
                        "priority": 10,
                    }
                ),
                json.dumps(
                    {
                        "type": "DefineContext",
                        "id": "irq-6",
                        "kind": "isr",
                        "name": "DMA IRQ",
                        "core_id": 0,
                        "priority": 20,
                    }
                ),
                json.dumps(
                    {
                        "source_id": "trace",
                        "source_seq": 0,
                        "quality": "exact",
                        "type": "ContextSwitch",
                        "ts_ns": 0,
                        "core_id": 0,
                        "next_context_id": "task-main",
                    }
                ),
                json.dumps(
                    {
                        "source_id": "trace",
                        "source_seq": 1,
                        "quality": "exact",
                        "type": "FunctionEnter",
                        "ts_ns": 10,
                        "core_id": 0,
                        "context_id": "task-main",
                        "function_id": "fn-main",
                    }
                ),
                json.dumps(
                    {
                        "source_id": "trace",
                        "source_seq": 2,
                        "quality": "exact",
                        "type": "InterruptEnter",
                        "ts_ns": 100,
                        "core_id": 0,
                        "interrupt_id": "irq-5",
                        "priority": 10,
                        "activation_id": "irq-5-1",
                    }
                ),
                json.dumps(
                    {
                        "source_id": "trace",
                        "source_seq": 3,
                        "quality": "exact",
                        "type": "FunctionEnter",
                        "ts_ns": 102,
                        "core_id": 0,
                        "context_id": "irq-5",
                        "function_id": "fn-isr",
                    }
                ),
                json.dumps(
                    {
                        "source_id": "trace",
                        "source_seq": 4,
                        "quality": "exact",
                        "type": "InterruptEnter",
                        "ts_ns": 110,
                        "core_id": 0,
                        "interrupt_id": "irq-6",
                        "priority": 20,
                        "activation_id": "irq-6-1",
                    }
                ),
                json.dumps(
                    {
                        "source_id": "trace",
                        "source_seq": 5,
                        "quality": "exact",
                        "type": "InterruptExit",
                        "ts_ns": 120,
                        "core_id": 0,
                        "interrupt_id": "irq-6",
                        "priority": 20,
                        "activation_id": "irq-6-1",
                    }
                ),
                json.dumps(
                    {
                        "source_id": "trace",
                        "source_seq": 6,
                        "quality": "exact",
                        "type": "InterruptExit",
                        "ts_ns": 130,
                        "core_id": 0,
                        "interrupt_id": "irq-5",
                        "priority": 10,
                        "activation_id": "irq-5-1",
                    }
                ),
                json.dumps(
                    {
                        "source_id": "trace",
                        "source_seq": 7,
                        "quality": "exact",
                        "type": "FunctionExit",
                        "ts_ns": 140,
                        "core_id": 0,
                        "context_id": "irq-5",
                        "function_id": "fn-isr",
                    }
                ),
                json.dumps(
                    {
                        "source_id": "trace",
                        "source_seq": 8,
                        "quality": "exact",
                        "type": "FunctionExit",
                        "ts_ns": 200,
                        "core_id": 0,
                        "context_id": "task-main",
                        "function_id": "fn-main",
                    }
                ),
                json.dumps(
                    {
                        "source_id": "trace",
                        "source_seq": 9,
                        "quality": "exact",
                        "type": "ContextSwitch",
                        "ts_ns": 210,
                        "core_id": 0,
                        "prev_context_id": "task-main",
                        "next_context_id": "idle",
                    }
                ),
            ]
        ).encode()
        + b"\n"
    )
    exact_support = {"support": "exact", "reasons": []}
    unavailable_support = {
        "support": "unavailable",
        "reasons": ["fixture_metric_unavailable"],
    }
    metric_support = {
        field: dict(exact_support if verdict == "VALID" else unavailable_support)
        for field in (
            "function_timeline",
            "call_count",
            "elapsed",
            "active",
            "self",
            "task_timeline",
            "isr_timeline",
        )
    }
    metric_support["resource_counters"] = dict(unavailable_support)
    capture_capabilities = {
        "function_events": dict(exact_support),
        "context_switches": dict(exact_support),
        "interrupt_events": dict(exact_support),
        "samples": dict(unavailable_support),
        "custom_events": dict(unavailable_support),
        "counters": dict(unavailable_support),
    }
    health = {
        "schema": "t32perf.health/v1",
        "session_id": owner,
        "verdict": verdict,
        "policy_version": "t32perf.health-policy/v1",
        "observations": [],
        "issues": [
            {
                "code": code,
                "severity": "fatal",
                "source": "trace32",
                "evidence": {},
                "message": code,
            }
            for code in issue_codes
        ],
        "metric_support": metric_support,
    }
    hotspots = {
        "schema": "t32perf.hotspots/v1",
        "session_id": owner,
        "quality": "exact",
        "functions": [
            {
                "function_id": "fn-main",
                "inclusive_active_ns": 1004,
                "self_active_ns": 1004,
                "count": 2,
                "min_active_ns": 500,
                "max_active_ns": 504,
                "avg_active_ns": 502,
                "incomplete_count": 0,
                "quality": "exact",
            }
        ],
        "sampling": [],
    }
    if hotspot_overrides is not None:
        hotspots["functions"][0].update(hotspot_overrides)
    summary = {
        "schema": "t32perf.analysis-summary/v1",
        "session_id": owner,
        "health_verdict": verdict,
        "metric_support": metric_support,
        "input_artifacts": [],
        "diagnostics": {
            "observation_count": 10,
            "function_span_count": 2,
            "incomplete_function_span_count": 0,
            "health_observation_count": 0,
            "health_issue_count": len(issue_codes),
        },
        "quantitative": (
            {
                "observation_count": 10,
                "function_span_count": 2,
                "incomplete_function_span_count": 0,
                "call_depth": {"max_depth": 1, "deepest_path": []},
                "context_cpu": [
                    {"context_id": "task-main", "kind": "task", "active_ns": 505},
                    {"context_id": "irq-5", "kind": "isr", "active_ns": 59},
                    {"context_id": "irq-6", "kind": "isr", "active_ns": 50},
                    {"context_id": "idle", "kind": "idle", "active_ns": 50},
                ],
                "task_cpu_ns": 505,
                "isr_cpu_ns": 109,
                "idle_cpu_ns": 50,
                "resources": {"counters": []},
            }
            if verdict == "VALID"
            else None
        ),
    }
    derived = (
        "\n".join(
            [
                json.dumps(
                    {
                        "schema": "t32perf.derived-stream/v1",
                        "session_id": owner,
                        "encoding": "ndjson",
                        "input_artifact_ids": ["observations"],
                    }
                ),
                json.dumps(
                    {
                        "source_id": "trace",
                        "source_seq_start": 1,
                        "source_seq_end": 8,
                        "core_id": 0,
                        "context_id": "task-main",
                        "function_id": "fn-main",
                        "start_ns": 10,
                        "end_ns": 200,
                        "elapsed_ns": 190,
                        "active_ns": 150,
                        "self_active_ns": 150,
                        "preempted_ns": 40,
                        "quality": "exact",
                        "incomplete": False,
                    }
                ),
                json.dumps(
                    {
                        "source_id": "trace",
                        "source_seq_start": 3,
                        "source_seq_end": 7,
                        "core_id": 0,
                        "context_id": "irq-5",
                        "function_id": "fn-isr",
                        "start_ns": 102,
                        "end_ns": 140,
                        "elapsed_ns": 38,
                        "active_ns": 28,
                        "self_active_ns": 28,
                        "preempted_ns": 10,
                        "quality": "exact",
                        "incomplete": False,
                    }
                ),
            ]
        ).encode()
        + b"\n"
    )

    artifact_documents: list[tuple[str, str, str, bytes, list[str]]] = [
        (
            "observations",
            "observations",
            "capture/observations.jsonl",
            observations,
            [],
        ),
        (
            "health",
            "health",
            "analysis/health.json",
            _json_bytes(health),
            ["observations"],
        ),
        (
            "derived",
            "derived",
            "analysis/derived.jsonl",
            derived,
            ["observations"],
        ),
        (
            "hotspots",
            "hotspots",
            "analysis/hotspots.json",
            _json_bytes(hotspots),
            ["observations", "health"],
        ),
        (
            "analysis-summary",
            "analysis_summary",
            "analysis/summary.json",
            _json_bytes(summary),
            ["observations", "health"],
        ),
    ]
    artifacts = []
    for artifact_id, kind, relative_path, contents, inputs in artifact_documents:
        path = session_path / relative_path
        path.write_bytes(contents)
        artifacts.append(
            {
                "id": artifact_id,
                "kind": kind,
                "relative_path": relative_path,
                "media_type": (
                    "application/x-ndjson"
                    if relative_path.endswith(".jsonl")
                    else "application/json"
                ),
                "size_bytes": len(contents),
                "sha256": hashlib.sha256(contents).hexdigest(),
                "producer": "fixture-driver" if not inputs else "t32perf-analysis",
                "input_artifact_ids": inputs,
            }
        )

    manifest = {
        "schema": "t32perf.manifest/v1",
        "session_id": session_id,
        "created_at": "2026-08-23T00:00:00Z",
        "tool": {"name": "t32perf", "version": "0.1.0"},
        "capture": {
            "mode": mode,
            "adapter": {"id": "lab-board", "version": "1"},
            "covered_cores": list(board.covered_cores),
            "capabilities": capture_capabilities,
            "target": {
                "board": board.board_id,
                "core_count": 1,
                "properties": {
                    "initial_state": initial_state,
                    "mcu_family": board.mcu_family,
                    "rtos": board.rtos,
                    "trace_routing": list(board.trace_routing),
                },
            },
            "trace32": {
                "build": str(board.trace32_build),
                "probe": board.probe_id,
                "architecture_package": board.architecture_package,
                "properties": {
                    "release": board.trace32_release,
                    "license_features": list(board.license_features),
                    "capability_evidence_sha256": board.capability_evidence_sha256,
                },
            },
            "request_sha256": "1" * 64,
        },
        "firmware": {"build_id": "firmware-build-1"},
        "clocks": [{"id": "trace", "frequency_hz": 100_000_000, "source": "target"}],
        "stages": [
            {
                "name": "capture",
                "status": "complete",
                "output_artifact_ids": ["observations"],
            },
            {
                "name": "analyze",
                "status": "complete",
                "input_artifact_ids": ["observations"],
                "output_artifact_ids": [
                    "health",
                    "hotspots",
                    "analysis-summary",
                ],
            },
        ],
        "artifacts": artifacts,
    }
    (session_path / "manifest.json").write_bytes(_json_bytes(manifest))
    return session_path


def add_instrumentation_contract(session_path: Path) -> None:
    manifest_path = session_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    instrumentation = {
        "method": "t32perf-c-wire/v1",
        "transport": "shared-memory-ring-buffer/v1",
        "overhead": {
            "measurement_method": "golden-overhead-benchmark/v1",
            "baseline_duration_ns": 100_000,
            "instrumented_duration_ns": 112_000,
            "emitted_event_count": 1_000,
            "evidence_artifact_id": "instrumentation-overhead",
        },
    }
    evidence = _json_bytes(
        {
            "schema": "t32perf.instrumentation-overhead-evidence/v1",
            "instrumentation_method": "t32perf-c-wire/v1",
            "transport": "shared-memory-ring-buffer/v1",
            "measurement_method": "golden-overhead-benchmark/v1",
            "baseline_duration_ns": 100_000,
            "instrumented_duration_ns": 112_000,
            "emitted_event_count": 1_000,
        }
    )
    config = _json_bytes(
        {
            "schema": "t32perf.capture-config/v1",
            "session_id": manifest["session_id"],
            "instrumentation": instrumentation,
        }
    )
    evidence_path = session_path / "capture/instrumentation-overhead.json"
    config_path = session_path / "capture/capture-config.json"
    evidence_path.write_bytes(evidence)
    config_path.write_bytes(config)
    manifest["capture"]["capabilities"] = {
        "custom_events": {"support": "exact", "reasons": []}
    }
    manifest["capture"]["instrumentation"] = instrumentation
    manifest["capture"]["capture_config"] = {
        "artifact_id": "capture-config",
        "sha256": hashlib.sha256(config).hexdigest(),
        "configuration_sha256": "2" * 64,
    }
    manifest["artifacts"].extend(
        [
            {
                "id": "instrumentation-overhead",
                "kind": "instrumentation_overhead",
                "relative_path": "capture/instrumentation-overhead.json",
                "media_type": "application/json",
                "size_bytes": len(evidence),
                "sha256": hashlib.sha256(evidence).hexdigest(),
                "producer": "firmware-benchmark",
                "input_artifact_ids": [],
            },
            {
                "id": "capture-config",
                "kind": "capture_config",
                "relative_path": "capture/capture-config.json",
                "media_type": "application/json",
                "size_bytes": len(config),
                "sha256": hashlib.sha256(config).hexdigest(),
                "producer": "fixture-driver",
                "input_artifact_ids": ["instrumentation-overhead"],
            },
        ]
    )
    manifest_path.write_bytes(_json_bytes(manifest))


def native_result(session_id: str) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "statistics": {
            "schema": "t32perf.hil-native-timeline-reference/v1",
            "functions": [
                {
                    "id": "fn-main",
                    "count": 2,
                    "total_time_ns": 1000,
                    "self_time_ns": 1000,
                    "min_time_ns": 500,
                    "max_time_ns": 500,
                    "average_time_ns": 500,
                }
            ],
            "tasks": [{"id": "task-main", "count": 1, "time_ns": 500}],
            "isrs": [
                {"id": "irq-5", "count": 1, "time_ns": 60},
                {"id": "irq-6", "count": 1, "time_ns": 50},
            ],
            "context_switches": [
                {
                    "ts_ns": 0,
                    "core_id": 0,
                    "previous_context_id": None,
                    "next_context_id": "task-main",
                    "next_name": "Main",
                    "next_kind": "task",
                    "next_priority": 5,
                },
                {
                    "ts_ns": 210,
                    "core_id": 0,
                    "previous_context_id": "task-main",
                    "next_context_id": "idle",
                    "next_name": "Idle",
                    "next_kind": "idle",
                    "next_priority": 0,
                },
            ],
            "interrupts": [
                {
                    "event": "enter",
                    "ts_ns": 100,
                    "core_id": 0,
                    "interrupt_id": "irq-5",
                    "interrupt_name": "Timer IRQ",
                    "priority": 10,
                    "activation_id": "irq-5-1",
                    "nesting_depth": 1,
                    "parent_activation_id": None,
                    "preempted_task_id": "task-main",
                },
                {
                    "event": "enter",
                    "ts_ns": 110,
                    "core_id": 0,
                    "interrupt_id": "irq-6",
                    "interrupt_name": "DMA IRQ",
                    "priority": 20,
                    "activation_id": "irq-6-1",
                    "nesting_depth": 2,
                    "parent_activation_id": "irq-5-1",
                    "preempted_task_id": "task-main",
                },
                {
                    "event": "exit",
                    "ts_ns": 120,
                    "core_id": 0,
                    "interrupt_id": "irq-6",
                    "interrupt_name": "DMA IRQ",
                    "priority": 20,
                    "activation_id": "irq-6-1",
                    "nesting_depth": 2,
                    "parent_activation_id": "irq-5-1",
                    "preempted_task_id": "task-main",
                },
                {
                    "event": "exit",
                    "ts_ns": 130,
                    "core_id": 0,
                    "interrupt_id": "irq-5",
                    "interrupt_name": "Timer IRQ",
                    "priority": 10,
                    "activation_id": "irq-5-1",
                    "nesting_depth": 1,
                    "parent_activation_id": None,
                    "preempted_task_id": "task-main",
                },
            ],
            "function_activations": [
                {
                    "source_id": "trace",
                    "source_seq_start": 1,
                    "source_seq_end": 8,
                    "function_id": "fn-main",
                    "core_id": 0,
                    "context_id": "task-main",
                    "context_kind": "task",
                    "start_ns": 10,
                    "end_ns": 200,
                    "elapsed_ns": 190,
                    "active_ns": 150,
                    "self_active_ns": 150,
                    "preempted_ns": 40,
                },
                {
                    "source_id": "trace",
                    "source_seq_start": 3,
                    "source_seq_end": 7,
                    "function_id": "fn-isr",
                    "core_id": 0,
                    "context_id": "irq-5",
                    "context_kind": "isr",
                    "start_ns": 102,
                    "end_ns": 140,
                    "elapsed_ns": 38,
                    "active_ns": 28,
                    "self_active_ns": 28,
                    "preempted_ns": 10,
                },
            ],
        },
    }


def _json_bytes(document: object) -> bytes:
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode() + b"\n"


def replace_artifact_contents(
    session_path: Path, artifact_id: str, contents: bytes
) -> None:
    manifest_path = session_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = next(row for row in manifest["artifacts"] if row["id"] == artifact_id)
    (session_path / artifact["relative_path"]).write_bytes(contents)
    artifact["size_bytes"] = len(contents)
    artifact["sha256"] = hashlib.sha256(contents).hexdigest()
    manifest_path.write_bytes(_json_bytes(manifest))


def test_session_audit_independently_validates_ten_unique_sessions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    calls = install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    for index in range(10):
        session_id = f"session-{index}"
        create_session(board, session_id)
        session = audit.verify_driver_result(
            {"ok": True, "session_id": session_id, "health": "untrusted"},
            expected_health="VALID",
        )
        assert session.session_id == session_id
    assert len(calls) == 10
    assert calls[0] == [
        str(board.t32perf_bin),
        "--artifact-root",
        str(board.artifact_root),
        "--json",
        "validate",
        "session-0",
        "--deep",
    ]


def test_session_audit_rejects_hash_tampering_and_cross_session_tags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    path = create_session(board, "tampered")
    (path / "analysis/hotspots.json").write_text("tampered", encoding="utf-8")
    with pytest.raises(RuntimeError, match="size|SHA-256"):
        audit.verify_driver_result({"session_id": "tampered"})

    board = board_config(tmp_path / "other")
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    create_session(board, "session-b", tagged_session_id="session-a")
    with pytest.raises(RuntimeError, match="belongs to session"):
        audit.verify_driver_result({"session_id": "session-b"})


def test_session_audit_rejects_unknown_trace32_build_in_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    path = create_session(board, "unknown-build")
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["capture"]["trace32"]["build"] = "199999"
    manifest_path.write_bytes(_json_bytes(manifest))

    with pytest.raises(RuntimeError, match="does not match"):
        audit.verify_driver_result(
            {"session_id": "unknown-build", "trace32_build": 183242}
        )


def test_session_audit_rejects_mismatched_or_missing_covered_cores(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for session_id, covered_cores in [
        ("wrong-cores", [1]),
        ("missing-cores", None),
    ]:
        board = board_config(tmp_path / session_id)
        install_fake_validate(monkeypatch, board)
        audit = SessionAudit(board)
        path = create_session(board, session_id)
        manifest_path = path / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if covered_cores is None:
            del manifest["capture"]["covered_cores"]
        else:
            manifest["capture"]["covered_cores"] = covered_cores
        manifest_path.write_bytes(_json_bytes(manifest))

        with pytest.raises(RuntimeError, match="covered_cores"):
            audit.verify_driver_result({"session_id": session_id})


def test_custom_event_support_requires_measured_instrumentation_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)

    missing = create_session(board, "missing-instrumentation")
    manifest_path = missing / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["capture"]["capabilities"] = {
        "custom_events": {"support": "exact", "reasons": []}
    }
    manifest_path.write_bytes(_json_bytes(manifest))
    with pytest.raises(RuntimeError, match="omits instrumentation"):
        audit.verify_driver_result({"session_id": "missing-instrumentation"})

    board = board_config(tmp_path / "measured")
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    measured = create_session(board, "measured-instrumentation")
    add_instrumentation_contract(measured)
    verified = audit.verify_driver_result({"session_id": "measured-instrumentation"})
    assert verified.session_id == "measured-instrumentation"


def test_instrumentation_measurement_and_config_binding_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    session_path = create_session(board, "bad-overhead")
    add_instrumentation_contract(session_path)
    manifest_path = session_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["capture"]["instrumentation"]["overhead"]["instrumented_duration_ns"] = (
        99_999
    )
    manifest_path.write_bytes(_json_bytes(manifest))
    with pytest.raises(RuntimeError, match="below its baseline"):
        audit.verify_driver_result({"session_id": "bad-overhead"})

    board = board_config(tmp_path / "binding")
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    session_path = create_session(board, "bad-binding")
    add_instrumentation_contract(session_path)
    manifest_path = session_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    config = next(
        artifact
        for artifact in manifest["artifacts"]
        if artifact["id"] == "capture-config"
    )
    config["input_artifact_ids"] = []
    manifest_path.write_bytes(_json_bytes(manifest))
    with pytest.raises(RuntimeError, match="does not bind exact"):
        audit.verify_driver_result({"session_id": "bad-binding"})

    board = board_config(tmp_path / "evidence-drift")
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    session_path = create_session(board, "bad-evidence-drift")
    add_instrumentation_contract(session_path)
    evidence_path = session_path / "capture/instrumentation-overhead.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["transport"] = "different-transport/v1"
    evidence_path.write_bytes(_json_bytes(evidence))
    manifest_path = session_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    evidence_artifact = next(
        artifact
        for artifact in manifest["artifacts"]
        if artifact["id"] == "instrumentation-overhead"
    )
    evidence_bytes = evidence_path.read_bytes()
    evidence_artifact["size_bytes"] = len(evidence_bytes)
    evidence_artifact["sha256"] = hashlib.sha256(evidence_bytes).hexdigest()
    manifest_path.write_bytes(_json_bytes(manifest))
    with pytest.raises(RuntimeError, match="transport differs"):
        audit.verify_driver_result({"session_id": "bad-evidence-drift"})


def test_session_audit_rejects_multiple_new_session_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    create_session(board, "session-a")
    create_session(board, "session-b")
    with pytest.raises(RuntimeError, match="exactly session"):
        audit.verify_driver_result({"session_id": "session-a"})


@pytest.mark.parametrize(
    ("fault_name", "script"),
    [
        (
            "trace32-disconnect",
            "import json,sys; print(json.dumps({'ok':False})); sys.exit(70)",
        ),
        ("driver-disconnect", "import sys; sys.exit(71)"),
        ("cmm-abort", "import sys; print('{'); sys.exit(72)"),
    ],
)
def test_fault_recovery_requires_clean_failure_then_verified_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_name: str,
    script: str,
) -> None:
    board = board_config(tmp_path)
    audit = SessionAudit(board)
    operation = {
        "trace32-disconnect": "trace32_disconnect_capture",
        "driver-disconnect": "driver_disconnect_capture",
        "cmm-abort": "cmm_abort_capture",
    }[fault_name]
    reservation = reserve_recovery_evidence(
        board,
        operation,
        initial_target_state="running",
        binding_sha256="b" * 64,
    )
    pending = run_expected_failure(
        [sys.executable, "-c", script],
        cwd=tmp_path,
        artifact_root=board.artifact_root,
        recovery_evidence=reservation,
    )
    assert pending.returncode != 0
    failed_operation, failure_kind = {
        "trace32-disconnect": ("perf_stop", "trace32_disconnect"),
        "driver-disconnect": ("perf_export", "driver_disconnect"),
        "cmm-abort": ("perf_start", "cmm_abort"),
    }[fault_name]
    recovery_document = TargetAdapterRecoveryEvidence(
        profile_sha256=board.target_adapter_profile_sha256,
        binding_sha256="b" * 64,
        failed_operation=failed_operation,
        failure_kind=failure_kind,
        initial_target_state="running",
        restored_target_state="running",
        adapter_state_restored=True,
        upstream_abort_confirmed=True,
        upstream_abort_receipt_sha256="c" * 64,
        files_deleted=False,
        new_session_required=True,
    ).to_document()
    recovery_script = (
        "import json,sys; "
        "open(sys.argv[1], 'x', encoding='utf-8').write(sys.argv[2]); "
        "print(json.dumps({'ok': True}))"
    )
    _, failure = run_recovery(
        [
            sys.executable,
            "-c",
            recovery_script,
            str(reservation.output_path),
            json.dumps(recovery_document),
        ],
        cwd=tmp_path,
        failure=pending,
    )

    install_fake_validate(monkeypatch, board)
    session_id = f"recovered-{fault_name}"
    create_session(board, session_id, mode="etm", initial_state="running")
    session = audit.verify_driver_result(
        {"session_id": session_id, "recovered": False},
        expected_health="VALID",
    )
    evidence = capture_evidence(
        board,
        session,
        expected_mode="etm",
        expected_initial_state="running",
    )
    assert evidence.session_id == session_id
    receipt = build_recovery_verification(session, operation, failure)
    assert receipt["kind"] == "fault_injection"
    assert (
        receipt["scenario"]
        == {
            "trace32-disconnect": "trace32_disconnect_recovery",
            "driver-disconnect": "driver_disconnect_recovery",
            "cmm-abort": "cmm_abort_recovery",
        }[fault_name]
    )
    assert receipt["verdict"] == "PASS"
    assert receipt["checks"] == {"total": 4, "passed": 4, "failed": 0}
    assert set(receipt["tolerance"].values()) == {0.0}
    assert receipt["recovery_evidence"] == {
        "sha256": failure.recovery_evidence_sha256,
        "document": recovery_document,
    }
    sidecar = failure.recovery_evidence_path.parent / "capture-sidecar.json"
    sidecar.write_text("{}", encoding="utf-8")
    with pytest.raises(RuntimeError, match="polluted recovery evidence root"):
        write_recovery_verification_receipt(failure, receipt)
    sidecar.unlink()
    swapped_receipt = json.loads(json.dumps(receipt))
    swapped_receipt["recovery_evidence"]["sha256"] = "d" * 64
    swapped_receipt["recovery_evidence"]["document"]["binding_sha256"] = "e" * 64
    with pytest.raises(RuntimeError, match="does not bind this reservation"):
        write_recovery_verification_receipt(failure, swapped_receipt)
    assert not failure.recovery_receipt_path.exists()
    persisted = write_recovery_verification_receipt(failure, receipt)
    assert persisted == receipt
    assert failure.recovery_receipt_path.is_file()
    changed_document = dict(recovery_document)
    changed_document["binding_sha256"] = "c" * 64
    failure.recovery_evidence_path.write_text(
        json.dumps(changed_document), encoding="utf-8"
    )
    with pytest.raises(RuntimeError, match="changed after acceptance"):
        build_recovery_verification(session, operation, failure)


def test_overflow_uses_health_artifact_not_driver_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    create_session(
        board,
        "overflow",
        verdict="INVALID",
        issue_codes=("trace_overflow",),
    )
    session = audit.verify_driver_result(
        {"session_id": "overflow", "health": "VALID", "issues": []},
        expected_health="INVALID",
    )
    assert_overflow_health(session)


def test_flow_error_is_separate_from_overflow_driver_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    create_session(
        board,
        "flow-error",
        verdict="INVALID",
        issue_codes=("flow_error",),
    )
    session = audit.verify_driver_result(
        {
            "session_id": "flow-error",
            "health": "VALID",
            "issues": ["trace_overflow"],
        },
        expected_health="INVALID",
    )
    assert_flow_error_health(session)


def test_elf_mismatch_uses_health_artifact_and_exposes_receipt_ready_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    create_session(
        board,
        "elf-mismatch",
        verdict="INVALID",
        issue_codes=("elf_mismatch",),
    )
    session = audit.verify_driver_result(
        {"session_id": "elf-mismatch", "health": "VALID"},
        expected_health="INVALID",
    )
    receipt = assert_elf_mismatch_health(
        session, {"session_id": "elf-mismatch", "native_fault": "elf_mismatch"}
    )

    assert receipt["kind"] == "fault_injection"
    assert receipt["scenario"] == "elf_mismatch"
    assert receipt["session_id"] == "elf-mismatch"
    assert receipt["verdict"] == "PASS"
    assert set(receipt["tolerance"].values()) == {0.0}
    bindings = {row["role"]: row for row in receipt["artifact_bindings"]}
    assert bindings["health"]["sha256"] == session.artifact("health").sha256
    assert (
        bindings["manifest"]["sha256"]
        == hashlib.sha256((session.path / "manifest.json").read_bytes()).hexdigest()
    )


def test_trace_loss_scenarios_reject_conflated_health_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    create_session(
        board,
        "conflated",
        verdict="INVALID",
        issue_codes=("trace_overflow", "flow_error"),
    )
    session = audit.verify_driver_result(
        {"session_id": "conflated"}, expected_health="INVALID"
    )

    with pytest.raises(AssertionError, match="conflates"):
        assert_overflow_health(session)

    board = board_config(tmp_path / "elf-conflated")
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    create_session(
        board,
        "elf-conflated",
        verdict="INVALID",
        issue_codes=("elf_mismatch", "trace_overflow"),
    )
    session = audit.verify_driver_result(
        {"session_id": "elf-conflated"}, expected_health="INVALID"
    )
    with pytest.raises(AssertionError, match="conflates"):
        assert_elf_mismatch_health(session)

    board = board_config(tmp_path / "unrelated-fault")
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    create_session(
        board,
        "unrelated-fault",
        verdict="INVALID",
        issue_codes=("elf_mismatch", "timestamp_jump"),
    )
    session = audit.verify_driver_result(
        {"session_id": "unrelated-fault"}, expected_health="INVALID"
    )
    with pytest.raises(AssertionError, match="timestamp_jump"):
        assert_elf_mismatch_health(session)


def test_native_differential_compares_complete_function_and_context_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    create_session(board, "native")
    session = audit.verify_driver_result(
        {"session_id": "native"}, expected_health="VALID"
    )
    result = native_result("native")
    receipt = verify_native_differential(result, session, tick_ns=board.tick_ns)
    assert receipt["schema"] == "t32perf.hil-verification-receipt/v1"
    assert receipt["kind"] == "native_timeline"
    assert receipt["verdict"] == "PASS"
    assert receipt["driver_reference_sha256"] == canonical_sha256(result["statistics"])
    assert receipt["tolerance"]["timestamp_absolute_ns"] == board.tick_ns
    assert receipt["tolerance"]["timestamp_relative"] == 0.005
    assert receipt["tolerance"]["continuous_absolute"] == board.tick_ns
    assert receipt["tolerance"]["continuous_relative"] == 0.005
    assert receipt["checks"] == {"total": 7, "passed": 7, "failed": 0}
    assert receipt["max_error"]["check"] is not None
    assert {row["role"] for row in receipt["artifact_bindings"]} == {
        "manifest",
        "health",
        "observations",
        "analysis_summary",
        "hotspots",
        "derived",
    }

    result["statistics"]["functions"][0]["count"] = 3
    with pytest.raises(AssertionError, match="count differs"):
        verify_native_differential(result, session, tick_ns=board.tick_ns)
    result["statistics"]["functions"][0]["count"] = 2
    result["statistics"]["tasks"][0]["time_ns"] = 450
    with pytest.raises(AssertionError, match="time_ns differs"):
        verify_native_differential(result, session, tick_ns=board.tick_ns)


def test_native_receipt_rehashes_every_bound_artifact_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    path = create_session(board, "native-binding")
    session = audit.verify_driver_result({"session_id": "native-binding"})
    hotspots_path = path / "analysis/hotspots.json"
    hotspots = json.loads(hotspots_path.read_text(encoding="utf-8"))
    hotspots_path.write_text(json.dumps(hotspots, indent=2), encoding="utf-8")

    with pytest.raises(RuntimeError, match="changed after HIL Session verification"):
        verify_native_differential(
            native_result("native-binding"), session, tick_ns=board.tick_ns
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("total_time_ns", 1100),
        ("self_time_ns", 900),
        ("min_time_ns", 400),
        ("max_time_ns", 600),
        ("average_time_ns", 514),
    ],
)
def test_native_differential_rejects_each_function_timing_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: int,
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    create_session(board, "native-functions")
    session = audit.verify_driver_result(
        {"session_id": "native-functions"}, expected_health="VALID"
    )
    result = native_result("native-functions")
    if field == "total_time_ns":
        result["statistics"]["functions"][0]["average_time_ns"] = 550
        result["statistics"]["functions"][0]["max_time_ns"] = 550
    if field == "average_time_ns":
        result["statistics"]["functions"][0]["min_time_ns"] = 490
        result["statistics"]["functions"][0]["max_time_ns"] = 514
    result["statistics"]["functions"][0][field] = value

    with pytest.raises(AssertionError, match=field):
        verify_native_differential(result, session, tick_ns=board.tick_ns)


def test_native_function_contract_requires_all_fields_and_consistent_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    create_session(board, "native-contract")
    session = audit.verify_driver_result(
        {"session_id": "native-contract"}, expected_health="VALID"
    )
    missing = native_result("native-contract")
    del missing["statistics"]["functions"][0]["self_time_ns"]
    with pytest.raises(RuntimeError, match="self_time_ns"):
        verify_native_differential(missing, session, tick_ns=board.tick_ns)

    inconsistent = native_result("native-contract")
    inconsistent["statistics"]["functions"][0]["average_time_ns"] = 600
    with pytest.raises(RuntimeError, match="inconsistent min/average/max"):
        verify_native_differential(inconsistent, session, tick_ns=board.tick_ns)

    missing_schema = native_result("native-contract")
    del missing_schema["statistics"]["schema"]
    with pytest.raises(RuntimeError, match="hil-native-timeline-reference/v1"):
        verify_native_differential(missing_schema, session, tick_ns=board.tick_ns)

    wrong_schema = native_result("native-contract")
    wrong_schema["statistics"]["schema"] = "t32perf.hil-native-timeline-reference/v2"
    with pytest.raises(RuntimeError, match="hil-native-timeline-reference/v1"):
        verify_native_differential(wrong_schema, session, tick_ns=board.tick_ns)

    unknown_field = native_result("native-contract")
    unknown_field["statistics"]["unexpected"] = True
    with pytest.raises(RuntimeError, match="field set"):
        verify_native_differential(unknown_field, session, tick_ns=board.tick_ns)

    unknown_row_field = native_result("native-contract")
    unknown_row_field["statistics"]["functions"][0]["unexpected"] = True
    with pytest.raises(RuntimeError, match="native functions row field set"):
        verify_native_differential(unknown_row_field, session, tick_ns=board.tick_ns)


@pytest.mark.parametrize(
    ("field", "support"),
    [
        ("function_events", "statistical"),
        ("context_switches", "inferred"),
        ("interrupt_events", "statistical"),
    ],
)
def test_native_receipt_requires_exact_manifest_program_flow_capabilities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    support: str,
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    path = create_session(board, "nonexact-capability")
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["capture"]["capabilities"][field] = {
        "support": support,
        "reasons": ["fixture_nonexact"],
    }
    manifest_path.write_bytes(_json_bytes(manifest))
    session = audit.verify_driver_result({"session_id": "nonexact-capability"})

    with pytest.raises(RuntimeError, match=rf"{field}\.support must be exact"):
        verify_native_differential(
            native_result("nonexact-capability"), session, tick_ns=board.tick_ns
        )


@pytest.mark.parametrize(
    ("target", "quality", "expected"),
    [
        ("document", "statistical", "exact hotspots quality"),
        ("function", "inferred", r"hotspots\.functions\[0\] quality"),
    ],
)
def test_native_receipt_requires_exact_hotspot_quality(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    quality: str,
    expected: str,
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    path = create_session(board, "nonexact-hotspots")
    hotspots_path = path / "analysis/hotspots.json"
    hotspots = json.loads(hotspots_path.read_text(encoding="utf-8"))
    if target == "document":
        hotspots["quality"] = quality
    else:
        hotspots["functions"][0]["quality"] = quality
    replace_artifact_contents(path, "hotspots", _json_bytes(hotspots))
    session = audit.verify_driver_result({"session_id": "nonexact-hotspots"})

    with pytest.raises(RuntimeError, match=expected):
        verify_native_differential(
            native_result("nonexact-hotspots"), session, tick_ns=board.tick_ns
        )


@pytest.mark.parametrize(
    "field",
    [
        "function_timeline",
        "call_count",
        "elapsed",
        "active",
        "self",
        "task_timeline",
        "isr_timeline",
    ],
)
def test_native_receipt_requires_exact_summary_and_health_metric_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    path = create_session(board, "nonexact-support")
    for artifact_id, relative_path in (
        ("health", "analysis/health.json"),
        ("analysis-summary", "analysis/summary.json"),
    ):
        artifact_path = path / relative_path
        document = json.loads(artifact_path.read_text(encoding="utf-8"))
        document["metric_support"][field] = {
            "support": "statistical",
            "reasons": ["fixture_nonexact"],
        }
        replace_artifact_contents(path, artifact_id, _json_bytes(document))
    session = audit.verify_driver_result({"session_id": "nonexact-support"})

    with pytest.raises(RuntimeError, match=rf"{field}\.support must be exact"):
        verify_native_differential(
            native_result("nonexact-support"), session, tick_ns=board.tick_ns
        )


def test_native_receipt_rejects_summary_health_support_disagreement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    path = create_session(board, "support-disagreement")
    summary_path = path / "analysis/summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["metric_support"]["call_count"] = {
        "support": "inferred",
        "reasons": ["fixture_nonexact"],
    }
    replace_artifact_contents(path, "analysis-summary", _json_bytes(summary))
    session = audit.verify_driver_result({"session_id": "support-disagreement"})

    with pytest.raises(RuntimeError, match="metric_support differs from health"):
        verify_native_differential(
            native_result("support-disagreement"), session, tick_ns=board.tick_ns
        )


def test_native_timeline_contract_checks_names_priority_core_idle_and_nesting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    create_session(board, "timeline-contract")
    session = audit.verify_driver_result({"session_id": "timeline-contract"})

    missing_name = native_result("timeline-contract")
    del missing_name["statistics"]["context_switches"][0]["next_name"]
    with pytest.raises(RuntimeError, match="next_name"):
        verify_native_differential(missing_name, session, tick_ns=board.tick_ns)

    wrong_name = native_result("timeline-contract")
    wrong_name["statistics"]["context_switches"][0]["next_name"] = "Wrong"
    with pytest.raises(AssertionError, match="next_name differs"):
        verify_native_differential(wrong_name, session, tick_ns=board.tick_ns)

    wrong_priority = native_result("timeline-contract")
    wrong_priority["statistics"]["context_switches"][0]["next_priority"] = 6
    with pytest.raises(AssertionError, match="next_priority differs"):
        verify_native_differential(wrong_priority, session, tick_ns=board.tick_ns)

    wrong_core = native_result("timeline-contract")
    for row in wrong_core["statistics"]["context_switches"]:
        row["core_id"] = 1
    with pytest.raises(AssertionError, match="core_id differs"):
        verify_native_differential(wrong_core, session, tick_ns=board.tick_ns)

    missing_idle = native_result("timeline-contract")
    missing_idle["statistics"]["context_switches"].pop()
    with pytest.raises(RuntimeError, match="Task and idle"):
        verify_native_differential(missing_idle, session, tick_ns=board.tick_ns)

    missing_isr_name = native_result("timeline-contract")
    del missing_isr_name["statistics"]["interrupts"][0]["interrupt_name"]
    with pytest.raises(RuntimeError, match="interrupt_name"):
        verify_native_differential(missing_isr_name, session, tick_ns=board.tick_ns)

    wrong_isr_name = native_result("timeline-contract")
    wrong_isr_name["statistics"]["interrupts"][0]["interrupt_name"] = "Wrong"
    with pytest.raises(AssertionError, match="interrupt_name differs"):
        verify_native_differential(wrong_isr_name, session, tick_ns=board.tick_ns)

    wrong_nesting = native_result("timeline-contract")
    wrong_nesting["statistics"]["interrupts"][1]["nesting_depth"] = 3
    with pytest.raises(RuntimeError, match="nesting"):
        verify_native_differential(wrong_nesting, session, tick_ns=board.tick_ns)

    missing_preempted_task = native_result("timeline-contract")
    for row in missing_preempted_task["statistics"]["interrupts"]:
        row["preempted_task_id"] = None
    with pytest.raises(RuntimeError, match="no preempted Task"):
        verify_native_differential(
            missing_preempted_task, session, tick_ns=board.tick_ns
        )


def test_host_timeline_requires_registered_context_display_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    path = create_session(board, "missing-context-name")
    observations_path = path / "capture/observations.jsonl"
    records = [json.loads(line) for line in observations_path.read_text().splitlines()]
    del records[1]["name"]
    replace_artifact_contents(
        path,
        "observations",
        b"".join(_json_bytes(record) for record in records),
    )
    session = audit.verify_driver_result({"session_id": "missing-context-name"})

    with pytest.raises(RuntimeError, match="DefineContext record.name"):
        verify_native_differential(
            native_result("missing-context-name"), session, tick_ns=board.tick_ns
        )


def test_host_timeline_rejects_legacy_context_switch_field_spelling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    path = create_session(board, "legacy-context-switch")
    observations_path = path / "capture/observations.jsonl"
    records = [json.loads(line) for line in observations_path.read_text().splitlines()]
    switch = next(
        record
        for record in records
        if record.get("type") == "ContextSwitch" and "prev_context_id" in record
    )
    switch["previous_context_id"] = switch.pop("prev_context_id")
    replace_artifact_contents(
        path,
        "observations",
        b"".join(_json_bytes(record) for record in records),
    )
    session = audit.verify_driver_result({"session_id": "legacy-context-switch"})

    with pytest.raises(RuntimeError, match="non-canonical `previous_context_id`"):
        verify_native_differential(
            native_result("legacy-context-switch"), session, tick_ns=board.tick_ns
        )


def test_first_context_switch_accepts_a_known_previous_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    path = create_session(board, "known-initial-context")
    observations_path = path / "capture/observations.jsonl"
    records = [json.loads(line) for line in observations_path.read_text().splitlines()]
    first_switch = next(
        record
        for record in records
        if record.get("type") == "ContextSwitch" and record.get("source_seq") == 0
    )
    first_switch["prev_context_id"] = "idle"
    replace_artifact_contents(
        path,
        "observations",
        b"".join(_json_bytes(record) for record in records),
    )
    session = audit.verify_driver_result({"session_id": "known-initial-context"})
    reference = native_result("known-initial-context")
    reference["statistics"]["context_switches"][0]["previous_context_id"] = "idle"

    receipt = verify_native_differential(reference, session, tick_ns=board.tick_ns)
    assert receipt["verdict"] == "PASS"


@pytest.mark.parametrize(
    ("previous_context_id", "mutate_idle_core", "expected"),
    [
        ("undefined", False, "undefined Task/idle"),
        ("idle", True, "affinity 1 does not match event core 0"),
    ],
)
def test_first_context_switch_rejects_invalid_known_previous_context(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    previous_context_id: str,
    mutate_idle_core: bool,
    expected: str,
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    path = create_session(board, "invalid-initial-context")
    observations_path = path / "capture/observations.jsonl"
    records = [json.loads(line) for line in observations_path.read_text().splitlines()]
    first_switch = next(
        record
        for record in records
        if record.get("type") == "ContextSwitch" and record.get("source_seq") == 0
    )
    first_switch["prev_context_id"] = previous_context_id
    if mutate_idle_core:
        idle = next(record for record in records if record.get("id") == "idle")
        idle["core_id"] = 1
    replace_artifact_contents(
        path,
        "observations",
        b"".join(_json_bytes(record) for record in records),
    )
    session = audit.verify_driver_result({"session_id": "invalid-initial-context"})

    with pytest.raises(RuntimeError, match=expected):
        verify_native_differential(
            native_result("invalid-initial-context"),
            session,
            tick_ns=board.tick_ns,
        )


def test_host_timeline_does_not_infer_missing_previous_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    path = create_session(board, "missing-previous-context")
    observations_path = path / "capture/observations.jsonl"
    records = [json.loads(line) for line in observations_path.read_text().splitlines()]
    switch = next(
        record
        for record in records
        if record.get("type") == "ContextSwitch" and "prev_context_id" in record
    )
    del switch["prev_context_id"]
    replace_artifact_contents(
        path,
        "observations",
        b"".join(_json_bytes(record) for record in records),
    )
    session = audit.verify_driver_result({"session_id": "missing-previous-context"})

    with pytest.raises(RuntimeError, match="does not match host-reconstructed"):
        verify_native_differential(
            native_result("missing-previous-context"),
            session,
            tick_ns=board.tick_ns,
        )


def test_native_function_activation_reference_checks_isr_context_core_and_interval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    create_session(board, "activation-reference")
    session = audit.verify_driver_result({"session_id": "activation-reference"})

    wrong_context = native_result("activation-reference")
    wrong_context["statistics"]["function_activations"][1]["context_id"] = "irq-6"
    with pytest.raises(AssertionError, match="context_id differs"):
        verify_native_differential(wrong_context, session, tick_ns=board.tick_ns)

    wrong_core = native_result("activation-reference")
    wrong_core["statistics"]["function_activations"][1]["core_id"] = 1
    with pytest.raises(AssertionError, match="core_id differs"):
        verify_native_differential(wrong_core, session, tick_ns=board.tick_ns)

    wrong_interval = native_result("activation-reference")
    activation = wrong_interval["statistics"]["function_activations"][1]
    activation.update(
        {
            "start_ns": 120,
            "end_ns": 160,
            "elapsed_ns": 40,
            "active_ns": 30,
            "self_active_ns": 30,
            "preempted_ns": 10,
        }
    )
    with pytest.raises(AssertionError, match="start_ns|end_ns"):
        verify_native_differential(wrong_interval, session, tick_ns=board.tick_ns)

    wrong_preempted = native_result("activation-reference")
    task_activation = wrong_preempted["statistics"]["function_activations"][0]
    task_activation.update(
        {"active_ns": 130, "self_active_ns": 130, "preempted_ns": 60}
    )
    with pytest.raises(AssertionError, match="preempted_ns"):
        verify_native_differential(wrong_preempted, session, tick_ns=board.tick_ns)

    no_isr_activation = native_result("activation-reference")
    activation = no_isr_activation["statistics"]["function_activations"][1]
    activation.update({"context_id": "task-main", "context_kind": "task"})
    with pytest.raises(RuntimeError, match="Task- and ISR-context"):
        verify_native_differential(no_isr_activation, session, tick_ns=board.tick_ns)

    no_task_activation = native_result("activation-reference")
    no_task_activation["statistics"]["function_activations"].pop(0)
    with pytest.raises(RuntimeError, match="Task- and ISR-context"):
        verify_native_differential(no_task_activation, session, tick_ns=board.tick_ns)


@pytest.mark.parametrize(
    ("record_index", "updates", "expected"),
    [
        (2, {"context_id": "task-main"}, "context_id differs"),
        (2, {"core_id": 1}, "core_id differs"),
        (
            2,
            {
                "start_ns": 120,
                "end_ns": 160,
                "elapsed_ns": 40,
                "active_ns": 30,
                "self_active_ns": 30,
                "preempted_ns": 10,
            },
            "start_ns|end_ns",
        ),
        (
            1,
            {"active_ns": 130, "self_active_ns": 130, "preempted_ns": 60},
            "preempted_ns",
        ),
    ],
)
def test_host_reconstructs_function_activation_from_registered_derived_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    record_index: int,
    updates: dict[str, object],
    expected: str,
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    path = create_session(board, "derived-attribution")
    derived_path = path / "analysis/derived.jsonl"
    records = [json.loads(line) for line in derived_path.read_text().splitlines()]
    records[record_index].update(updates)
    replace_artifact_contents(
        path,
        "derived",
        b"".join(_json_bytes(record) for record in records),
    )
    session = audit.verify_driver_result({"session_id": "derived-attribution"})

    with pytest.raises(AssertionError, match=expected):
        verify_native_differential(
            native_result("derived-attribution"), session, tick_ns=board.tick_ns
        )


def test_native_differential_requires_versioned_quantitative_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    path = create_session(board, "legacy-summary")
    summary_path = path / "analysis/summary.json"
    document = json.loads(summary_path.read_text(encoding="utf-8"))
    replace_artifact_contents(
        path,
        "analysis-summary",
        _json_bytes(document["quantitative"]),
    )
    session = audit.verify_driver_result({"session_id": "legacy-summary"})

    with pytest.raises(RuntimeError, match="t32perf.analysis-summary/v1"):
        verify_native_differential(
            native_result("legacy-summary"), session, tick_ns=board.tick_ns
        )


@pytest.mark.parametrize(
    "overrides,expected",
    [
        ({"count": 0}, "count must be positive"),
        ({"self_active_ns": 1005}, "self_active_ns exceeds"),
        ({"avg_active_ns": 501}, "expected integer mean 502"),
    ],
)
def test_t32perf_hotspot_rows_are_semantically_revalidated_before_differential(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
    expected: str,
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    create_session(board, "hotspot-contract", hotspot_overrides=overrides)
    session = audit.verify_driver_result(
        {"session_id": "hotspot-contract"}, expected_health="VALID"
    )

    with pytest.raises(RuntimeError, match=expected):
        verify_native_differential(
            native_result("hotspot-contract"), session, tick_ns=board.tick_ns
        )


def test_capture_evidence_matrix_requires_verified_two_board_two_mode_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    matrix = CaptureEvidenceMatrix()
    boards = (
        board_config(
            tmp_path / "board-a",
            board_id="board-a",
            mcu_family="Cortex-M7",
        ),
        board_config(
            tmp_path / "board-b",
            board_id="board-b",
            mcu_family="RISC-V",
        ),
    )
    for board in boards:
        install_fake_validate(monkeypatch, board)
        audit = SessionAudit(board)
        for mode in board.capture_modes:
            for initial_state in ("running", "halted"):
                for repetition in range(5):
                    session_id = f"{board.board_id}-{mode}-{initial_state}-{repetition}"
                    create_session(
                        board,
                        session_id,
                        mode=mode,
                        initial_state=initial_state,
                    )
                    session = audit.verify_driver_result(
                        {"session_id": session_id}, expected_health="VALID"
                    )
                    matrix.add(
                        board,
                        session,
                        expected_mode=mode,
                        expected_initial_state=initial_state,
                    )

    matrix.assert_coverage()
    output = tmp_path / "hil-evidence.json"
    document = write_capture_evidence_matrix(matrix, output)
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas/hil-evidence.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)
    assert document["source"] == "host-verified-session-artifacts"
    assert document["coverage"]["boards"] == ["board-a", "board-b"]
    assert document["coverage"]["mcu_families"] == ["Cortex-M7", "RISC-V"]
    assert document["coverage"]["modes"] == ["etm", "sampling"]
    assert document["coverage"]["rtoses"] == ["FreeRTOS"]
    assert document["coverage"]["probes"] == ["probe-board-a", "probe-board-b"]
    assert len(document["captures"]) == 40
    assert all(row["manifest_sha256"] for row in document["captures"])
    assert all(row["health_sha256"] for row in document["captures"])
    assert json.loads(output.read_text(encoding="utf-8")) == document
    with pytest.raises(HilOutputError, match="already exists"):
        write_capture_evidence_matrix(matrix, output)


def test_capture_evidence_matrix_requires_distinct_mcu_families_and_an_rtos(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def add_minimal(
        matrix: CaptureEvidenceMatrix, boards: tuple[BoardConfig, BoardConfig]
    ) -> None:
        for board in boards:
            install_fake_validate(monkeypatch, board)
            audit = SessionAudit(board)
            session_id = f"{board.board_id}-minimal"
            create_session(board, session_id, mode="etm", initial_state="running")
            session = audit.verify_driver_result(
                {"session_id": session_id}, expected_health="VALID"
            )
            matrix.add(
                board,
                session,
                expected_mode="etm",
                expected_initial_state="running",
            )

    same_family = CaptureEvidenceMatrix()
    add_minimal(
        same_family,
        (
            board_config(
                tmp_path / "same-a", board_id="same-a", mcu_family="Cortex-M7"
            ),
            board_config(
                tmp_path / "same-b", board_id="same-b", mcu_family="Cortex-M7"
            ),
        ),
    )
    with pytest.raises(AssertionError, match="MCU families"):
        same_family.assert_coverage(
            min_modes=1,
            min_repetitions_per_combination=1,
            required_initial_states=frozenset({"running"}),
        )

    no_rtos = CaptureEvidenceMatrix()
    add_minimal(
        no_rtos,
        (
            board_config(
                tmp_path / "no-rtos-a",
                board_id="no-rtos-a",
                mcu_family="Cortex-M7",
                rtos=None,
            ),
            board_config(
                tmp_path / "no-rtos-b",
                board_id="no-rtos-b",
                mcu_family="RISC-V",
                rtos=None,
            ),
        ),
    )
    with pytest.raises(AssertionError, match="RTOSes"):
        no_rtos.assert_coverage(
            min_modes=1,
            min_repetitions_per_combination=1,
            required_initial_states=frozenset({"running"}),
        )


def test_capture_evidence_rejects_driver_requested_state_not_in_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    board = board_config(tmp_path)
    install_fake_validate(monkeypatch, board)
    audit = SessionAudit(board)
    create_session(board, "state-mismatch", initial_state="running")
    session = audit.verify_driver_result(
        {"session_id": "state-mismatch", "initial_state": "halted"},
        expected_health="VALID",
    )
    matrix = CaptureEvidenceMatrix()

    with pytest.raises(RuntimeError, match="initial state is `running`"):
        matrix.add(
            board,
            session,
            expected_mode="etm",
            expected_initial_state="halted",
        )
