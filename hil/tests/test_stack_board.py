from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from harness import HilConfigurationError
from sampling_board import endpoint_fingerprint
from stack_board import StackBoardConfig


def _request() -> dict[str, object]:
    return {
        "schema": "t32perf.stack-capture-request/v1",
        "acknowledge_intrusive": True,
        "sample_period_ms": 10,
        "duration_ms": 100,
        "max_samples": 1,
        "max_frames": 1,
        "core_id": 0,
        "address_space": "P",
    }


def _write_config(tmp_path: Path, digest: str) -> Path:
    request = tmp_path / "stack-request.json"
    request.write_bytes(json.dumps(_request(), sort_keys=True).encode())
    request_digest = hashlib.sha256(request.read_bytes()).hexdigest()
    binary = tmp_path / "bin" / "t32perf.exe"
    binary.parent.mkdir()
    binary.write_bytes(b"test-host-binary\n")
    software = "R.2026.02.000190766+190766"
    probe = "0" * 64
    endpoint = endpoint_fingerprint("localhost", 20001, "TCP", software, probe)
    commands = "\n".join(
        f'{operation} = ["bridge", "{{endpoint_host}}", "{{endpoint_port}}", "{{endpoint_protocol}}", "{{endpoint_fingerprint}}", "{{artifact_root}}", "{{t32perf_bin}}"]'
        for operation in (
            "prepare",
            "capabilities",
            "capture",
            "ingest",
            "analyze",
            "summary",
            "render",
        )
    )
    path = tmp_path / "stack-board.toml"
    path.write_text(
        f'''[board]
id = "stack-board"
mcu_family = "Cortex-M"
expected_cpu = "CortexM0+"
lock_file = "locks/probe.lock"

[trace32]
software = "{software}"
probe_id = "probe-1"

[endpoint]
host = "localhost"
port = 20001
protocol = "TCP"
expected_fingerprint = "{endpoint}"
expected_probe_fingerprint = "{probe}"

[host]
t32perf_bin = "bin/t32perf.exe"
t32perf_sha256 = "{digest}"
artifact_root = "artifacts"
stack_evidence_root = "stack-evidence"
min_free_bytes = 4096

[stack]
capture_request = "{request.name}"
capture_request_sha256 = "{request_digest}"

[driver.commands]
{commands}
''',
        encoding="utf-8",
    )
    return path


def test_stack_board_binds_the_exact_host_executable(tmp_path: Path) -> None:
    expected = hashlib.sha256(b"test-host-binary\n").hexdigest()
    config = StackBoardConfig.load(_write_config(tmp_path, expected))
    assert config.t32perf_sha256 == expected
    assert config.t32perf_bin == tmp_path / "bin" / "t32perf.exe"


def test_stack_board_rejects_wrong_host_executable_digest(tmp_path: Path) -> None:
    with pytest.raises(HilConfigurationError, match="t32perf_sha256"):
        StackBoardConfig.load(_write_config(tmp_path, "0" * 64))


def test_stack_board_rechecks_host_binary_before_each_driver_command(
    tmp_path: Path,
) -> None:
    expected = hashlib.sha256(b"test-host-binary\n").hexdigest()
    config = StackBoardConfig.load(_write_config(tmp_path, expected))
    config.t32perf_bin.write_bytes(b"different-host-binary\n")
    with pytest.raises(HilConfigurationError, match="t32perf_sha256"):
        config.command("prepare")


def test_stack_board_rejects_non_lowercase_digest(tmp_path: Path) -> None:
    with pytest.raises(HilConfigurationError, match="invalid digest"):
        StackBoardConfig.load(_write_config(tmp_path, "A" * 64))


def test_stack_board_rejects_symlinked_host_executable(tmp_path: Path) -> None:
    expected = hashlib.sha256(b"test-host-binary\n").hexdigest()
    config_path = _write_config(tmp_path, expected)
    binary = tmp_path / "bin" / "t32perf.exe"
    target = tmp_path / "bin" / "real-t32perf.exe"
    binary.rename(target)
    try:
        binary.symlink_to(target.name)
    except OSError as error:
        pytest.skip(f"symlink creation is unavailable: {error}")
    with pytest.raises(HilConfigurationError, match="plain regular file"):
        StackBoardConfig.load(config_path)


def test_stack_board_rejects_host_executable_over_64_mib(tmp_path: Path) -> None:
    binary = tmp_path / "bin" / "t32perf.exe"
    expected = hashlib.sha256(b"test-host-binary\n").hexdigest()
    config_path = _write_config(tmp_path, expected)
    with binary.open("r+b") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    with pytest.raises(HilConfigurationError, match="exceeds"):
        StackBoardConfig.load(config_path)
