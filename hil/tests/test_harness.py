from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

import harness
from harness import (
    BoardConfig,
    HilConfigurationError,
    HilOutputError,
    ProbeLock,
    preflight_output,
    reserve_recovery_evidence,
    run_expected_failure,
    run_json,
    run_recovery,
    run_recovery_fault_preparation,
    validate_recovery_fault_preparation,
    verify_doctor_result,
)
from target_adapter_recovery import (
    TargetAdapterRecoveryEvidence,
)


def write_config(
    path: Path,
    *,
    build: int = 183242,
    validated_builds: tuple[int, ...] = (183242,),
) -> None:
    capability = path.parent / "capability-evidence.json"
    capability_bytes = b'{"source":"lab-controller","verified":true}\n'
    capability.write_bytes(capability_bytes)
    capability_sha256 = hashlib.sha256(capability_bytes).hexdigest()
    fault_scenarios = path.parent / "fault-scenarios.json"
    fault_scenarios_bytes = json.dumps(
        {
            "schema": "t32perf.trace32-fault-scenarios/v1",
            "adapter_id": "adapter-1",
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
    fault_scenarios.write_bytes(fault_scenarios_bytes)
    fault_scenarios_sha256 = hashlib.sha256(fault_scenarios_bytes).hexdigest()
    profile = json.loads(
        (
            Path(__file__).parents[2]
            / "skill-trace32-perf/scripts/adapters/tc234l-build190766/profile.json"
        ).read_text(encoding="utf-8")
    )
    profile["adapter_id"] = "adapter-1"
    profile["implementation_sha256"] = "b" * 64
    profile["build_gate"] = {
        "trace32_release": "2026.02",
        "minimum_build": build,
        "maximum_build": build,
        "architecture_package": "arm",
    }
    profile_bytes = json.dumps(profile, indent=2).encode()
    (path.parent / "profile.json").write_bytes(profile_bytes)
    profile_file_sha256 = hashlib.sha256(profile_bytes).hexdigest()
    profile_sha256 = harness._rust_profile_canonical_sha256(profile)
    validated = ", ".join(str(value) for value in validated_builds)
    path.write_text(
        f"""
[board]
id = "board-1"
mcu_family = "Cortex-M"
rtos = "FreeRTOS"
covered_cores = [0]
capture_modes = ["etm", "sampling"]
lock_file = "locks/probe.lock"

[trace32]
release = "2026.02"
build = {build}
validated_builds = [{validated}]
probe_id = "probe-asset-1"
architecture_package = "arm"
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
echo = ["tool", "--board", "{{board_id}}", "--run", "{{run}}"]
prepare_recovery_fault = ["tool", "prepare", "--fault-operation", "{{fault_operation}}", "--initial-state", "{{initial_target_state}}"]
sampling_buffer_full_capture = ["tool", "sampling-buffer-full"]
trace32_disconnect_capture = ["tool", "trace32-disconnect"]
driver_disconnect_capture = ["tool", "driver-disconnect"]
cmm_abort_capture = ["tool", "cmm-abort"]
""".strip(),
        encoding="utf-8",
    )


def pin_fault_scenarios(config_path: Path, document: bytes) -> None:
    """Replace the fixture manifest and update its board-config digest."""

    manifest_path = config_path.parent / "fault-scenarios.json"
    manifest_path.write_bytes(document)
    digest = hashlib.sha256(document).hexdigest()
    lines = config_path.read_text(encoding="utf-8").splitlines()
    config_path.write_text(
        "\n".join(
            (
                f'fault_scenarios_sha256 = "{digest}"'
                if line.startswith("fault_scenarios_sha256 =")
                else line
            )
            for line in lines
        )
        + "\n",
        encoding="utf-8",
    )


def pin_profile(config_path: Path, document: bytes) -> None:
    """Replace the fixture profile and update its board-config file digest."""

    profile_path = config_path.parent / "profile.json"
    profile_path.write_bytes(document)
    digest = hashlib.sha256(document).hexdigest()
    lines = config_path.read_text(encoding="utf-8").splitlines()
    config_path.write_text(
        "\n".join(
            (
                f'target_adapter_profile_file_sha256 = "{digest}"'
                if line.startswith("target_adapter_profile_file_sha256 =")
                else line
            )
            for line in lines
        )
        + "\n",
        encoding="utf-8",
    )


def test_board_config_resolves_paths_and_expands_argv(tmp_path: Path) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config = BoardConfig.load(config_path)

    assert config.lock_file == (tmp_path / "locks/probe.lock").resolve()
    assert config.t32perf_bin == (tmp_path / "bin/t32perf").resolve()
    assert config.recovery_evidence_root == (tmp_path / "recovery-evidence").resolve()
    assert len(config.target_adapter_profile_sha256) == 64
    assert config.fault_scenarios_path == (tmp_path / "fault-scenarios.json").resolve()
    assert config.fault_scenarios_sha256
    assert config.fault_scenarios["sampling_buffer_full"].is_executable
    assert config.tick_ns == 10.0
    assert config.capture_modes == ("etm", "sampling")
    assert config.validated_trace32_builds == (183242,)
    assert config.probe_id == "probe-asset-1"
    assert config.architecture_package == "arm"
    assert config.license_features == ("trace", "rtos-awareness")
    assert config.capability_evidence_sha256
    assert config.trace_routing == ("ETM0->TPIU0:TRACECLK,TRACED0-3",)
    assert config.min_free_bytes == 4096
    assert config.command("echo", run=4) == [
        "tool",
        "--board",
        "board-1",
        "--run",
        "4",
    ]
    assert config.fault_command("sampling_buffer_full") == [
        "tool",
        "sampling-buffer-full",
    ]


def test_board_config_rejects_unknown_placeholders(tmp_path: Path) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config = BoardConfig.load(config_path)

    with pytest.raises(HilConfigurationError, match="unknown placeholder"):
        config.command("echo")

    with pytest.raises(HilConfigurationError, match="reserved command placeholder"):
        config.command("echo", artifact_root="override", run=1)

    with pytest.raises(HilConfigurationError, match="ignores supplied placeholders"):
        config.command("echo", run=1, binding_sha256="b" * 64)


def test_board_config_rejects_unvalidated_trace32_build(tmp_path: Path) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path, build=199999)

    with pytest.raises(HilConfigurationError, match="not in trace32.validated_builds"):
        BoardConfig.load(config_path)


@pytest.mark.parametrize(
    ("source", "replacement", "expected"),
    [
        ("covered_cores = [0]", "covered_cores = [true]", "covered_cores"),
        ("covered_cores = [0]", "covered_cores = [0.5]", "covered_cores"),
        ("covered_cores = [0]", 'covered_cores = ["0"]', "covered_cores"),
        ("build = 183242", 'build = "183242"', "trace32.build"),
        ("build = 183242", "build = true", "trace32.build"),
        ("build = 183242", "build = 183242.5", "trace32.build"),
        (
            "validated_builds = [183242]",
            'validated_builds = ["183242"]',
            "validated_builds",
        ),
        (
            "validated_builds = [183242]",
            "validated_builds = [true]",
            "validated_builds",
        ),
        (
            "validated_builds = [183242]",
            "validated_builds = [183242.5]",
            "validated_builds",
        ),
        ("tick_ns = 10.0", 'tick_ns = "10.0"', "trace32.tick_ns"),
        ("tick_ns = 10.0", "tick_ns = true", "trace32.tick_ns"),
        ("min_free_bytes = 4096", "min_free_bytes = true", "min_free_bytes"),
        ("min_free_bytes = 4096", 'min_free_bytes = "4096"', "min_free_bytes"),
        ("min_free_bytes = 4096", "min_free_bytes = 4096.5", "min_free_bytes"),
    ],
)
def test_board_config_rejects_coercible_non_numeric_values(
    tmp_path: Path, source: str, replacement: str, expected: str
) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(source, replacement),
        encoding="utf-8",
    )

    with pytest.raises(HilConfigurationError, match=expected):
        BoardConfig.load(config_path)


def test_board_config_rejects_mismatched_capability_evidence(tmp_path: Path) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    text = config_path.read_text(encoding="utf-8")
    marker = 'capability_evidence_sha256 = "'
    start = text.index(marker) + len(marker)
    config_path.write_text(
        text[:start] + "0" * 64 + text[start + 64 :], encoding="utf-8"
    )

    with pytest.raises(HilConfigurationError, match="does not match"):
        BoardConfig.load(config_path)


@pytest.mark.parametrize("scenario", ["trace_overflow", "flow_error", "elf_mismatch"])
def test_unsupported_adapter_fault_is_rejected_without_a_driver_command(
    tmp_path: Path, scenario: str
) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config = BoardConfig.load(config_path)

    assert f"{scenario}_capture" not in config.commands
    with pytest.raises(HilConfigurationError, match="explicitly unsupported"):
        config.fault_command(scenario)


def test_executable_adapter_faults_require_closed_driver_commands(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(
            'sampling_buffer_full_capture = ["tool", "sampling-buffer-full"]\n',
            "",
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        HilConfigurationError, match="executable adapter fault scenario"
    ):
        BoardConfig.load(config_path)


def test_qualified_sampling_fault_uses_the_same_closed_command(tmp_path: Path) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    document = json.loads(
        (tmp_path / "fault-scenarios.json").read_text(encoding="utf-8")
    )
    for entry in document["scenarios"]:
        if entry["scenario"] == "sampling_buffer_full":
            entry["support"] = "qualified"
    pin_fault_scenarios(config_path, json.dumps(document, sort_keys=True).encode())

    config = BoardConfig.load(config_path)
    assert config.fault_scenarios["sampling_buffer_full"].is_executable
    assert config.fault_command("sampling_buffer_full") == [
        "tool",
        "sampling-buffer-full",
    ]


def test_unsupported_adapter_fault_cannot_configure_a_driver_command(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    text = config_path.read_text(encoding="utf-8")
    config_path.write_text(
        text.replace(
            'sampling_buffer_full_capture = ["tool", "sampling-buffer-full"]',
            'sampling_buffer_full_capture = ["tool", "sampling-buffer-full"]\n'
            'trace_overflow_capture = ["tool", "trace-overflow"]',
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        HilConfigurationError, match="unsupported adapter fault scenario"
    ):
        BoardConfig.load(config_path)


def test_board_config_rejects_tampered_or_duplicate_fault_manifest(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    manifest_path = tmp_path / "fault-scenarios.json"
    manifest_path.write_text("{}", encoding="utf-8")

    with pytest.raises(HilConfigurationError, match="does not match configured value"):
        BoardConfig.load(config_path)

    duplicate = (
        b'{"schema":"t32perf.trace32-fault-scenarios/v1",'
        b'"adapter_id":"adapter-1","adapter_id":"adapter-2","scenarios":[]}'
    )
    pin_fault_scenarios(config_path, duplicate)

    with pytest.raises(HilConfigurationError, match="duplicate JSON object key"):
        BoardConfig.load(config_path)


def test_board_config_rejects_nonclosed_manifest_and_profile_identity(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    document = json.loads(
        (tmp_path / "fault-scenarios.json").read_text(encoding="utf-8")
    )
    del document["scenarios"][0]["support"]
    pin_fault_scenarios(config_path, json.dumps(document, sort_keys=True).encode())
    with pytest.raises(HilConfigurationError, match="support explicitly"):
        BoardConfig.load(config_path)

    write_config(config_path)
    profile = json.loads((tmp_path / "profile.json").read_text(encoding="utf-8"))
    profile["adapter_id"] = "other-adapter"
    pin_profile(config_path, json.dumps(profile, sort_keys=True).encode())
    with pytest.raises(HilConfigurationError, match="adapter_id does not match"):
        BoardConfig.load(config_path)

    write_config(config_path)
    config_path.write_text(
        config_path.read_text(encoding="utf-8").replace(
            BoardConfig.load(config_path).target_adapter_profile_sha256,
            "0" * 64,
        ),
        encoding="utf-8",
    )
    with pytest.raises(HilConfigurationError, match="Rust canonical profile identity"):
        BoardConfig.load(config_path)


def test_current_tc234l_profile_matches_rust_canonical_identity() -> None:
    config = BoardConfig.load(Path(__file__).parents[1] / "boards" / "example.toml")
    assert config.target_adapter_profile_sha256 == (
        "5f75195dffce414c657e6fad37096e3d3926beff95dbd0a0c4ac11eeb9a6ae81"
    )


def test_recovery_manifest_variant_forbids_support_and_unknown_fields(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    document = json.loads(
        (tmp_path / "fault-scenarios.json").read_text(encoding="utf-8")
    )
    recovery = next(
        entry
        for entry in document["scenarios"]
        if entry["scenario"] == "trace32_disconnect"
    )
    recovery["support"] = "qualified"
    pin_fault_scenarios(config_path, json.dumps(document, sort_keys=True).encode())
    with pytest.raises(HilConfigurationError, match="field set is invalid"):
        BoardConfig.load(config_path)

    write_config(config_path)
    document = json.loads(
        (tmp_path / "fault-scenarios.json").read_text(encoding="utf-8")
    )
    recovery = next(
        entry
        for entry in document["scenarios"]
        if entry["scenario"] == "trace32_disconnect"
    )
    recovery["unexpected"] = True
    pin_fault_scenarios(config_path, json.dumps(document, sort_keys=True).encode())
    with pytest.raises(HilConfigurationError, match="field set is invalid"):
        BoardConfig.load(config_path)


def test_board_config_rejects_invalid_profile_digest_and_overlapping_roots(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    text = config_path.read_text(encoding="utf-8")
    profile_line = (
        'target_adapter_profile_sha256 = "'
        + BoardConfig.load(config_path).target_adapter_profile_sha256
        + '"'
    )
    config_path.write_text(
        text.replace(
            profile_line,
            'target_adapter_profile_sha256 = "ABC"',
        ),
        encoding="utf-8",
    )
    with pytest.raises(HilConfigurationError, match="target_adapter_profile_sha256"):
        BoardConfig.load(config_path)

    write_config(config_path)
    text = config_path.read_text(encoding="utf-8")
    config_path.write_text(
        text.replace(
            'recovery_evidence_root = "recovery-evidence"',
            'recovery_evidence_root = "artifacts/recovery"',
        ),
        encoding="utf-8",
    )
    with pytest.raises(HilConfigurationError, match="must be independent"):
        BoardConfig.load(config_path)


def test_doctor_rejects_unknown_or_mismatched_trace32_build(tmp_path: Path) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path, validated_builds=(183242, 183243))
    config = BoardConfig.load(config_path)
    result = {
        "ok": True,
        "board_id": "board-1",
        "trace32_release": "2026.02",
        "trace32_build": 183242,
        "probe_id": config.probe_id,
        "architecture_package": config.architecture_package,
        "license_features": list(config.license_features),
        "capability_evidence_sha256": config.capability_evidence_sha256,
        "trace_routing": list(config.trace_routing),
    }
    verify_doctor_result(config, result)

    result["trace32_build"] = 199999
    with pytest.raises(RuntimeError, match="unvalidated TRACE32 build"):
        verify_doctor_result(config, result)
    result["trace32_build"] = 183243
    with pytest.raises(RuntimeError, match="does not match configured"):
        verify_doctor_result(config, result)

    result["trace32_build"] = config.trace32_build
    config.capability_evidence.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="changed after"):
        verify_doctor_result(config, result)


def test_fault_preparation_binds_exact_controller_transaction(tmp_path: Path) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config = BoardConfig.load(config_path)
    result = {
        "schema": "t32perf.target-adapter-failure-binding/v1",
        "profile_sha256": config.target_adapter_profile_sha256,
        "binding_sha256": "b" * 64,
        "failed_operation": "perf_stop",
        "failure_kind": "trace32_disconnect",
        "initial_target_state": "running",
    }

    preparation = validate_recovery_fault_preparation(
        config,
        "trace32_disconnect_capture",
        initial_target_state="running",
        result=result,
    )
    assert preparation.binding_sha256 == "b" * 64

    result["profile_sha256"] = "c" * 64
    with pytest.raises(RuntimeError, match="selected adapter contract"):
        validate_recovery_fault_preparation(
            config,
            "trace32_disconnect_capture",
            initial_target_state="running",
            result=result,
        )


def test_fault_preparation_cannot_modify_recovery_history(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config = BoardConfig.load(config_path)
    config.artifact_root.mkdir()
    config.recovery_evidence_root.mkdir()
    history = config.recovery_evidence_root / "historical-receipt.json"
    history.write_text("trusted", encoding="utf-8")
    result = {
        "schema": "t32perf.target-adapter-failure-binding/v1",
        "profile_sha256": config.target_adapter_profile_sha256,
        "binding_sha256": "b" * 64,
        "failed_operation": "perf_stop",
        "failure_kind": "trace32_disconnect",
        "initial_target_state": "running",
    }

    def fake_execute(
        argv: list[str], *, cwd: Path, timeout_seconds: float
    ) -> subprocess.CompletedProcess[str]:
        history.write_text("altered", encoding="utf-8")
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout=json.dumps(result),
            stderr="",
        )

    monkeypatch.setattr(harness, "_execute_process", fake_execute)
    with pytest.raises(RuntimeError, match="polluted recovery evidence root"):
        run_recovery_fault_preparation(
            config,
            "trace32_disconnect_capture",
            initial_target_state="running",
        )


def test_probe_lock_is_exclusive(tmp_path: Path) -> None:
    lock_path = tmp_path / "probe.lock"
    with (
        ProbeLock(lock_path),
        pytest.raises(RuntimeError, match="already locked"),
        ProbeLock(lock_path),
    ):
        pass


def test_run_json_requires_one_object(tmp_path: Path) -> None:
    script = "import json; print(json.dumps({'ok': True}))"
    result = run_json([sys.executable, "-c", script], cwd=tmp_path)
    assert result == {"ok": True}


def test_run_json_rejects_duplicate_object_keys(tmp_path: Path) -> None:
    script = 'print(\'{"ok":true,"ok":false}\')'

    with pytest.raises(RuntimeError, match="duplicate JSON object key `ok`"):
        run_json([sys.executable, "-c", script], cwd=tmp_path)


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_run_json_bounds_process_output(tmp_path: Path, stream: str) -> None:
    script = f"import sys; sys.{stream}.write('x' * (1024 * 1024 + 1)); sys.exit(7)"

    with pytest.raises(RuntimeError, match=f"command {stream} exceeds 1048576 bytes"):
        run_json([sys.executable, "-c", script], cwd=tmp_path)


def test_run_json_rejects_non_utf8_output(tmp_path: Path) -> None:
    script = "import sys; sys.stdout.buffer.write(b'\\xff')"

    with pytest.raises(RuntimeError, match="output is not UTF-8"):
        run_json([sys.executable, "-c", script], cwd=tmp_path)


def test_run_json_kills_timed_out_process(tmp_path: Path) -> None:
    script = "import time; time.sleep(5)"

    with pytest.raises(RuntimeError, match="timed out after 0.1 seconds"):
        run_json(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            timeout_seconds=0.1,
        )


def test_run_json_reports_driver_failure(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError, match="exit 7"):
        run_json([sys.executable, "-c", "import sys; sys.exit(7)"], cwd=tmp_path)


def test_expected_failure_requires_reserved_recovery_evidence_after_disconnect(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config = BoardConfig.load(config_path)
    config.artifact_root.mkdir()
    reservation = reserve_recovery_evidence(
        config,
        "driver_disconnect_capture",
        initial_target_state="running",
        binding_sha256="b" * 64,
    )
    pending = run_expected_failure(
        [sys.executable, "-c", "import sys; sys.exit(71)"],
        cwd=tmp_path,
        artifact_root=config.artifact_root,
        recovery_evidence=reservation,
    )
    document = TargetAdapterRecoveryEvidence(
        profile_sha256=config.target_adapter_profile_sha256,
        binding_sha256="b" * 64,
        failed_operation="perf_export",
        failure_kind="driver_disconnect",
        initial_target_state="running",
        restored_target_state="running",
        adapter_state_restored=True,
        upstream_abort_confirmed=True,
        upstream_abort_receipt_sha256="c" * 64,
        files_deleted=False,
        new_session_required=True,
    ).to_document()
    script = (
        "import json,sys; "
        "open(sys.argv[1], 'x', encoding='utf-8').write(json.dumps(json.loads(sys.argv[2]))); "
        "print('{}')"
    )
    _, failure = run_recovery(
        [
            sys.executable,
            "-c",
            script,
            str(reservation.output_path),
            json.dumps(document),
        ],
        cwd=tmp_path,
        failure=pending,
    )

    assert failure.returncode == 71
    assert failure.recovery_evidence.binding_sha256 == "b" * 64
    assert failure.recovery_evidence_path == reservation.output_path.resolve()


def test_expected_failure_rejects_partial_output_pollution(tmp_path: Path) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config = BoardConfig.load(config_path)
    config.artifact_root.mkdir()
    reservation = reserve_recovery_evidence(
        config,
        "trace32_disconnect_capture",
        initial_target_state="running",
        binding_sha256="b" * 64,
    )
    script = (
        "from pathlib import Path; import sys; "
        "Path(sys.argv[1], 'partial-session').mkdir(); sys.exit(72)"
    )

    with pytest.raises(RuntimeError, match="polluted artifact root"):
        run_expected_failure(
            [sys.executable, "-c", script, str(config.artifact_root)],
            cwd=tmp_path,
            artifact_root=config.artifact_root,
            recovery_evidence=reservation,
        )


def test_recovery_requires_reserved_evidence_output(tmp_path: Path) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config = BoardConfig.load(config_path)
    config.artifact_root.mkdir()
    reservation = reserve_recovery_evidence(
        config,
        "cmm_abort_capture",
        initial_target_state="running",
        binding_sha256="b" * 64,
    )
    pending = run_expected_failure(
        [sys.executable, "-c", "import sys; sys.exit(72)"],
        cwd=tmp_path,
        artifact_root=config.artifact_root,
        recovery_evidence=reservation,
    )

    with pytest.raises(RuntimeError, match="cannot read"):
        run_recovery(
            [sys.executable, "-c", "print('{}')"],
            cwd=tmp_path,
            failure=pending,
        )


def test_recovery_cannot_mutate_business_artifact_root(tmp_path: Path) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config = BoardConfig.load(config_path)
    config.artifact_root.mkdir()
    reservation = reserve_recovery_evidence(
        config,
        "trace32_disconnect_capture",
        initial_target_state="running",
        binding_sha256="b" * 64,
    )
    pending = run_expected_failure(
        [sys.executable, "-c", "import sys; sys.exit(70)"],
        cwd=tmp_path,
        artifact_root=config.artifact_root,
        recovery_evidence=reservation,
    )
    script = (
        "from pathlib import Path; import sys; "
        "Path(sys.argv[1], 'recovery-pollution').write_text('bad'); print('{}')"
    )

    with pytest.raises(RuntimeError, match="polluted artifact root"):
        run_recovery(
            [sys.executable, "-c", script, str(config.artifact_root)],
            cwd=tmp_path,
            failure=pending,
        )


def test_fault_cannot_modify_persistent_recovery_history(tmp_path: Path) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config = BoardConfig.load(config_path)
    config.artifact_root.mkdir()
    reservation = reserve_recovery_evidence(
        config,
        "trace32_disconnect_capture",
        initial_target_state="running",
        binding_sha256="b" * 64,
    )
    history = config.recovery_evidence_root / "historical-receipt.json"
    history.write_text("trusted", encoding="utf-8")
    script = (
        "from pathlib import Path; import sys; "
        "Path(sys.argv[1]).write_text('altered'); sys.exit(70)"
    )

    with pytest.raises(RuntimeError, match="polluted recovery evidence root"):
        run_expected_failure(
            [sys.executable, "-c", script, str(history)],
            cwd=tmp_path,
            artifact_root=config.artifact_root,
            recovery_evidence=reservation,
        )


def test_recovery_can_publish_only_the_reserved_evidence_file(tmp_path: Path) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config = BoardConfig.load(config_path)
    config.artifact_root.mkdir()
    reservation = reserve_recovery_evidence(
        config,
        "trace32_disconnect_capture",
        initial_target_state="running",
        binding_sha256="b" * 64,
    )
    pending = run_expected_failure(
        [sys.executable, "-c", "import sys; sys.exit(70)"],
        cwd=tmp_path,
        artifact_root=config.artifact_root,
        recovery_evidence=reservation,
    )
    document = TargetAdapterRecoveryEvidence(
        profile_sha256=config.target_adapter_profile_sha256,
        binding_sha256="b" * 64,
        failed_operation="perf_stop",
        failure_kind="trace32_disconnect",
        initial_target_state="running",
        restored_target_state="running",
        adapter_state_restored=True,
        upstream_abort_confirmed=True,
        upstream_abort_receipt_sha256="c" * 64,
        files_deleted=False,
        new_session_required=True,
    ).to_document()
    sidecar = config.recovery_evidence_root / "driver-sidecar.json"
    script = (
        "import json,sys; "
        "open(sys.argv[1], 'x', encoding='utf-8').write(sys.argv[3]); "
        "open(sys.argv[2], 'x', encoding='utf-8').write('{}'); "
        "print(json.dumps({'ok': True}))"
    )

    with pytest.raises(RuntimeError, match="outside its reservation"):
        run_recovery(
            [
                sys.executable,
                "-c",
                script,
                str(reservation.output_path),
                str(sidecar),
                json.dumps(document),
            ],
            cwd=tmp_path,
            failure=pending,
        )


class FakeOutputAccess:
    def __init__(self, *, available: int, denial: OSError | None = None) -> None:
        self.available = available
        self.denial = denial
        self.probed = False

    def available_bytes(self, root: Path) -> int:
        return self.available

    def probe_write(self, root: Path) -> None:
        self.probed = True
        if self.denial is not None:
            raise self.denial


def test_output_preflight_models_quota_without_filling_disk(tmp_path: Path) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config = BoardConfig.load(config_path)
    access = FakeOutputAccess(available=4095)

    with pytest.raises(HilOutputError, match="requires at least 4096"):
        preflight_output(config, access=access)
    assert access.probed is False


def test_output_preflight_models_permission_denial_cross_platform(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config = BoardConfig.load(config_path)
    access = FakeOutputAccess(
        available=4096,
        denial=PermissionError("injected output denial"),
    )

    with pytest.raises(HilOutputError, match="not writable"):
        preflight_output(config, access=access)
    assert access.probed is True


def test_local_output_preflight_removes_probe(tmp_path: Path) -> None:
    config_path = tmp_path / "board.toml"
    write_config(config_path)
    config = BoardConfig.load(config_path)

    preflight_output(config)

    assert list(config.artifact_root.iterdir()) == []
    assert list(config.recovery_evidence_root.iterdir()) == []
