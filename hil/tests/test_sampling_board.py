from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from harness import HilConfigurationError
from sampling_board import SamplingBoardConfig, endpoint_fingerprint
from sampling_verification import run_sampling_hil


def request_document() -> dict[str, object]:
    return {
        "schema": "t32perf.sampling-capture-request/v1",
        "ranges": [{"start_address": 0x1000, "end_address": 0x1010}],
        "bucket_size": 0x10,
        "duration_ms": 100,
        "method_policy": "realtime_only",
        "core_id": 0,
        "address_space": "P",
    }


def write_sampling_config(tmp_path: Path) -> Path:
    request = tmp_path / "request.json"
    request.write_bytes(json.dumps(request_document()).encode("utf-8"))
    request_digest = hashlib.sha256(request.read_bytes()).hexdigest()
    software = "R.2026.02.000190766+190766"
    probe = "0" * 64
    fingerprint = endpoint_fingerprint("localhost", 20001, "TCP", software, probe)
    command_lines = "\n".join(
        [
            'sampling_prepare = ["tool", "{endpoint_host}", "{endpoint_port}", "{endpoint_protocol}", "{endpoint_fingerprint}", "{artifact_root}", "{t32perf_bin}", "sampling_prepare", "{session_id}", "{request}"]',
            'sampling_capabilities = ["tool", "{endpoint_host}", "{endpoint_port}", "{endpoint_protocol}", "{endpoint_fingerprint}", "{artifact_root}", "{t32perf_bin}", "sampling_capabilities", "{session_id}"]',
            'sampling_capture = ["tool", "{endpoint_host}", "{endpoint_port}", "{endpoint_protocol}", "{endpoint_fingerprint}", "{artifact_root}", "{t32perf_bin}", "sampling_capture", "{session_id}", "{operation_id}", "{sidecar_args}"]',
            'sampling_ingest = ["tool", "{endpoint_host}", "{endpoint_port}", "{endpoint_protocol}", "{endpoint_fingerprint}", "{artifact_root}", "{t32perf_bin}", "sampling_ingest", "{session_id}", "{staged_path}"]',
            'sampling_analyze = ["tool", "{endpoint_host}", "{endpoint_port}", "{endpoint_protocol}", "{endpoint_fingerprint}", "{artifact_root}", "{t32perf_bin}", "sampling_analyze", "{session_id}", "{histogram_artifact_id}"]',
            'sampling_summary = ["tool", "{endpoint_host}", "{endpoint_port}", "{endpoint_protocol}", "{endpoint_fingerprint}", "{artifact_root}", "{t32perf_bin}", "sampling_summary", "{session_id}", "{heatmap_artifact_id}"]',
            'sampling_render = ["tool", "{endpoint_host}", "{endpoint_port}", "{endpoint_protocol}", "{endpoint_fingerprint}", "{artifact_root}", "{t32perf_bin}", "sampling_render", "{session_id}", "{heatmap_artifact_id}"]',
        ]
    )
    config = tmp_path / "sampling-board.toml"
    config.write_text(
        f'''[board]
id = "sampling-board"
mcu_family = "Cortex-M"
expected_cpu = "CortexM0+"
covered_cores = [0]
lock_file = "locks/probe.lock"

[trace32]
release = "R.2026.02"
build = 190766
validated_builds = [190766]
software = "{software}"
probe_id = "probe-1"

[endpoint]
host = "localhost"
port = 20001
protocol = "TCP"
expected_fingerprint = "{fingerprint}"
expected_probe_fingerprint = "{probe}"

[host]
t32perf_bin = "bin/t32perf"
artifact_root = "artifacts"
sampling_evidence_root = "sampling-evidence"
min_free_bytes = 4096

[sampling]
capture_request = "{request.name}"
capture_request_sha256 = "{request_digest}"

[driver.commands]
{command_lines}
''',
        encoding="utf-8",
    )
    return config


def prepared(session_id: str) -> dict[str, object]:
    operation_id = "1" * 32
    return {
        "ok": True,
        "command": "sampling.prepare",
        "result": {
            "operation_id": operation_id,
            "request_sha256": "a" * 64,
            "sampling_capture_arguments": {
                **{
                    key: value
                    for key, value in request_document().items()
                    if key != "schema"
                },
                "session_id": session_id,
                "operation_id": operation_id,
            },
        },
    }


def capabilities(
    *,
    software: str,
    cpu: object = "CortexM0+",
    endpoint: object | None = None,
    probe: object = "0" * 64,
) -> dict[str, object]:
    return {
        "schema": "t32perf.sampling-capabilities/v1",
        "target": {"powered": True, "running": True, "halted": False},
        "cpu": cpu,
        "pcsnoop": True,
        "trace32": software,
        "endpoint_fingerprint": endpoint
        if endpoint is not None
        else endpoint_fingerprint("localhost", 20001, "TCP", software, str(probe)),
        "endpoint_fingerprint_scheme": "t32perf.endpoint-fingerprint/v2",
        "probe_fingerprint": probe,
        "supported_methods": ["realtime", "stop_and_go"],
    }


def test_sampling_board_loads_without_target_adapter_profile(tmp_path: Path) -> None:
    config = SamplingBoardConfig.load(write_sampling_config(tmp_path))
    assert config.board_id == "sampling-board"
    assert config.covered_cores == (0,)
    assert set(config.commands) == {
        "sampling_prepare",
        "sampling_capabilities",
        "sampling_capture",
        "sampling_ingest",
        "sampling_analyze",
        "sampling_summary",
        "sampling_render",
    }


@pytest.mark.parametrize(
    ("needle", "message"),
    [
        (
            'sampling_render = ["tool", "sampling_render", "{session_id}", "{heatmap_artifact_id}"]\n',
            "exactly",
        ),
        (
            'sampling_evidence_root = "sampling-evidence"',
            "artifact_root and host.sampling_evidence_root",
        ),
        ('expected_fingerprint = "', "endpoint.expected_fingerprint"),
        ('probe_id = "probe-1"', "trace32 fields are invalid"),
    ],
)
def test_sampling_board_rejects_incomplete_or_overlapping_contract(
    tmp_path: Path, needle: str, message: str
) -> None:
    path = write_sampling_config(tmp_path)
    text = path.read_text(encoding="utf-8")
    if "sampling_render" in needle:
        text = (
            "\n".join(
                line
                for line in text.splitlines()
                if not line.startswith("sampling_render =")
            )
            + "\n"
        )
    elif "sampling_evidence_root" in needle:
        text = text.replace(needle, 'sampling_evidence_root = "artifacts"')
    elif "probe_id" in needle:
        text = text.replace(needle, needle + '\nunknown = "field"')
    else:
        start = text.index(needle) + len(needle)
        text = text[:start] + "0" * 64 + text[start + 64 :]
    path.write_text(text, encoding="utf-8")
    with pytest.raises(HilConfigurationError, match=message):
        SamplingBoardConfig.load(path)


def test_sampling_command_requires_every_supplied_placeholder(tmp_path: Path) -> None:
    board = SamplingBoardConfig.load(write_sampling_config(tmp_path))
    with pytest.raises(HilConfigurationError, match="ignores supplied placeholders"):
        board.command(
            "sampling_prepare",
            session_id="s1",
            request=board.sampling_capture_request,
            unused="x",
        )
    command = board.command(
        "sampling_prepare", session_id="s1", request=board.sampling_capture_request
    )
    assert command[-3:] == [
        "sampling_prepare",
        "s1",
        str(board.sampling_capture_request),
    ]


@pytest.mark.parametrize(
    ("reply", "reason"),
    [
        ({"schema": "wrong"}, "capabilities_schema_mismatch"),
        (
            capabilities(software="R.2026.02.000190766+190765"),
            "trace32_identity_mismatch",
        ),
        (
            capabilities(software="R.2026.02.000190766+190766", endpoint="0" * 64),
            "trace32_identity_mismatch",
        ),
        (
            capabilities(software="R.2026.02.000190766+190766", cpu="CortexM4"),
            "expected_cpu_mismatch",
        ),
    ],
)
def test_sampling_identity_mismatch_never_reaches_capture(
    tmp_path: Path, reply: dict[str, object], reason: str
) -> None:
    board = SamplingBoardConfig.load(write_sampling_config(tmp_path))
    calls: list[list[str]] = []
    replies = iter([prepared("s1"), reply])
    receipt = run_sampling_hil(
        board,
        session_id="s1",
        invoke=lambda argv: calls.append(argv) or next(replies),
    )
    assert receipt["status"] == "FAIL"
    assert receipt["reason"] == reason
    assert "sampling_prepare" in calls[0]
    assert "sampling_capabilities" in calls[1]
