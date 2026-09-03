from __future__ import annotations

import asyncio
import json
import sys
from argparse import Namespace
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest
from mcp import types

from lauterbach_sampling_mcp import hil_driver
from lauterbach_sampling_mcp.model import endpoint_fingerprint, probe_fingerprint
from lauterbach_sampling_mcp.service import SamplingService


def common_args(**changes: object) -> Namespace:
    values: dict[str, object] = {
        "host": "localhost",
        "port": 20001,
        "protocol": "TCP",
        "artifact_root": "C:/artifacts",
        "t32perf_bin": "C:/bin/t32perf.exe",
        "expected_endpoint_fingerprint": "0" * 64,
    }
    values.update(changes)
    return Namespace(**values)


def test_prepare_reads_bounded_strict_request_and_passes_inline_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = tmp_path / "request.json"
    request.write_text(
        '{"schema":"t32perf.sampling-capture-request/v1"}', encoding="utf-8"
    )
    observed: list[list[str]] = []

    def fake_host(_: Namespace, command: list[str]) -> dict[str, object]:
        observed.append(command)
        return {"operation_id": "a" * 32}

    monkeypatch.setattr(hil_driver, "_host_command", fake_host)
    result = hil_driver.run(
        common_args(operation="prepare", session="s1", request=request)
    )
    assert result == {"operation_id": "a" * 32}
    assert observed == [
        [
            "sampling",
            "prepare",
            "s1",
            "--capture-request",
            '{"schema":"t32perf.sampling-capture-request/v1"}',
        ]
    ]


@pytest.mark.parametrize("raw", ["[]", '{"x":1,"x":2}'])
def test_strict_json_rejects_non_object_and_duplicate_keys(raw: str) -> None:
    with pytest.raises(hil_driver.HilDriverError):
        hil_driver._strict_object_json(raw, description="test")


def test_address_operations_validate_hil_artifact_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[list[str]] = []
    monkeypatch.setattr(
        hil_driver,
        "_host_command",
        lambda _args, command: observed.append(command) or {"ok": True},
    )
    args = common_args(
        operation="analyze", session="s1", histogram="sampling-pc-hit-histogram"
    )
    assert hil_driver.run(args) == {"ok": True}
    assert observed[-1][-2:] == ["--projection", "address"]
    with pytest.raises(hil_driver.HilDriverError, match="--histogram"):
        hil_driver.run(
            common_args(operation="analyze", session="s1", histogram="ignored")
        )
    with pytest.raises(hil_driver.HilDriverError, match="--heatmap"):
        hil_driver.run(
            common_args(operation="summary", session="s1", heatmap="ignored")
        )


def test_capture_rejects_mismatched_hil_capability_before_mcp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    async def fake_call(*_: object) -> dict[str, object]:
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(hil_driver, "_call_mcp", fake_call)
    with pytest.raises(hil_driver.HilDriverError, match="--operation"):
        hil_driver.run(
            common_args(
                operation="capture",
                session="s1",
                capture_operation_id="a" * 32,
                sidecar_args=json.dumps({"session_id": "s1", "operation_id": "b" * 32}),
            )
        )
    assert not called


def test_mcp_result_requires_single_bounded_text_object() -> None:
    assert hil_driver._mcp_result_object(
        types.CallToolResult(
            content=[types.TextContent(type="text", text='{"ok":true}')]
        )
    ) == {"ok": True}
    with pytest.raises(hil_driver.HilDriverError, match="exactly one"):
        hil_driver._mcp_result_object(types.CallToolResult(content=[]))
    with pytest.raises(hil_driver.HilDriverError, match="error result"):
        hil_driver._mcp_result_object(
            types.CallToolResult(
                content=[types.TextContent(type="text", text="{}")], isError=True
            )
        )


def test_mcp_client_uses_injected_timeout_for_session_and_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    @asynccontextmanager
    async def fake_stdio(server: object):
        observed["server"] = server
        yield object(), object()

    class FakeSession:
        def __init__(self, *_: object, read_timeout_seconds: timedelta) -> None:
            observed["session"] = read_timeout_seconds

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def initialize(self) -> None:
            return None

        async def list_tools(self):
            return types.ListToolsResult(
                tools=[
                    types.Tool(name=name, description="", inputSchema={})
                    for name in hil_driver.EXPECTED_TOOLS
                ]
            )

        async def call_tool(
            self, _: str, __: object, *, read_timeout_seconds: timedelta
        ) -> types.CallToolResult:
            observed["tool"] = read_timeout_seconds
            return types.CallToolResult(
                content=[types.TextContent(type="text", text='{"ok":true}')]
            )

    monkeypatch.setattr(hil_driver, "stdio_client", fake_stdio)
    monkeypatch.setattr(hil_driver, "ClientSession", FakeSession)
    timeout = timedelta(milliseconds=1)
    assert asyncio.run(
        hil_driver._call_mcp(
            common_args(), "sampling_capabilities", {}, read_timeout=timeout
        )
    ) == {"ok": True}
    assert observed["session"] == timeout
    assert observed["tool"] == timeout
    server_args = cast(hil_driver.StdioServerParameters, observed["server"]).args
    assert "--expected-endpoint-fingerprint" in server_args
    assert "0" * 64 in server_args


def test_mcp_timeout_is_reported_as_bounded_driver_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @asynccontextmanager
    async def fake_stdio(_: object):
        yield object(), object()

    class TimedOutSession:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def initialize(self) -> None:
            raise TimeoutError("simulated")

    monkeypatch.setattr(hil_driver, "stdio_client", fake_stdio)
    monkeypatch.setattr(hil_driver, "ClientSession", TimedOutSession)
    with pytest.raises(
        hil_driver.HilDriverError, match="transport failed or timed out"
    ):
        asyncio.run(
            hil_driver._call_mcp(
                common_args(),
                "sampling_capabilities",
                {},
                read_timeout=timedelta(milliseconds=1),
            )
        )


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_bounded_child_rejects_output_overflow(stream: str) -> None:
    code = f"import sys; sys.{stream}.write('x' * 1100000)"
    with pytest.raises(hil_driver.HilDriverError, match="exceeded 1048576"):
        hil_driver._run_bounded_child([sys.executable, "-c", code], timeout_seconds=5)


def test_bounded_child_rejects_timeout() -> None:
    with pytest.raises(hil_driver.HilDriverError, match="operation timeout"):
        hil_driver._run_bounded_child(
            [sys.executable, "-c", "import time; time.sleep(10)"], timeout_seconds=0.05
        )


def test_capabilities_emit_fingerprint_when_target_is_unreadable(
    tmp_path: Path,
) -> None:
    class Functions:
        def state_power(self) -> bool:
            return False

        def state_run(self) -> bool:
            return False

        def state_halt(self) -> bool:
            return False

        def state_processor(self) -> str:
            raise RuntimeError("down")

        def cpu_feature(self, _: str) -> bool:
            raise RuntimeError("down")

        def perf_method(self) -> int:
            return 4

        def perf_mode(self) -> int:
            return 1

        def perf_state(self) -> int:
            return 0

        def software_version(self) -> str:
            return "R.2026.02"

        def software_build(self) -> int:
            return 190766

        def __call__(self, expression: str) -> str:
            values = {
                "VERSION.SERIAL.DEBUG()": "debug-module-serial",
                "VERSION.SERIAL.CABLE()": "debug-cable-serial",
                "SYStem.CONFIG.DEBUGPORT()": "DebugCable0",
            }
            return values[expression]

    class Debugger:
        fnc = Functions()

        def __enter__(self):
            return self

        def __exit__(self, *_: object) -> None:
            return None

    service = SamplingService(
        host="localhost",
        port=20001,
        protocol="TCP",
        timeout=1,
        artifact_root=tmp_path,
        connector=lambda **_: Debugger(),
    )
    capability = service.capabilities()
    assert capability["target"]["powered"] is False
    observed_probe_fingerprint = probe_fingerprint(
        "debug-module-serial", "debug-cable-serial", "DebugCable0"
    )
    assert capability["probe_fingerprint"] == observed_probe_fingerprint
    assert capability["endpoint_fingerprint"] == endpoint_fingerprint(
        "localhost", 20001, "TCP", "R.2026.02+190766", observed_probe_fingerprint
    )
