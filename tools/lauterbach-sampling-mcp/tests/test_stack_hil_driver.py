from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from argparse import Namespace
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest
from mcp import types

from lauterbach_sampling_mcp import stack_hil_driver


def common_args(**changes: object) -> Namespace:
    values: dict[str, object] = {
        "host": "localhost",
        "port": 20001,
        "protocol": "TCP",
        "timeout": 10.0,
        "artifact_root": "C:/artifacts",
        "t32perf_bin": "C:/bin/t32perf.exe",
        "expected_endpoint_fingerprint": "0" * 64,
    }
    values.update(changes)
    return Namespace(**values)


def test_host_command_mapping_and_fixed_stack_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request = tmp_path / "request.json"
    request.write_text(
        '{"schema":"t32perf.stack-capture-request/v1"}', encoding="utf-8"
    )
    observed: list[list[str]] = []
    monkeypatch.setattr(
        stack_hil_driver,
        "_host_command",
        lambda _args, command: observed.append(command) or {"ok": True},
    )
    assert stack_hil_driver.run(
        common_args(operation="prepare", session="s1", request=request)
    ) == {"ok": True}
    assert observed[-1] == [
        "stack",
        "prepare",
        "s1",
        "--capture-request",
        '{"schema":"t32perf.stack-capture-request/v1"}',
    ]
    assert stack_hil_driver.run(
        common_args(operation="ingest", session="s1", staged="capture/staging/a.json")
    ) == {"ok": True}
    assert observed[-1] == [
        "stack",
        "ingest",
        "s1",
        "--staged",
        "capture/staging/a.json",
    ]
    assert stack_hil_driver.run(
        common_args(
            operation="analyze",
            session="s1",
            stack_samples="sampling-stack-samples",
        )
    ) == {"ok": True}
    assert observed[-1] == [
        "stack",
        "analyze",
        "s1",
        "--stack-samples-artifact",
        "sampling-stack-samples",
    ]
    for operation in ("summary", "render"):
        assert stack_hil_driver.run(common_args(operation=operation, session="s1")) == {
            "ok": True
        }
        assert observed[-1] == ["stack", operation, "s1"]
    with pytest.raises(stack_hil_driver.StackHilDriverError, match="--stack-samples"):
        stack_hil_driver.run(
            common_args(operation="analyze", session="s1", stack_samples="other")
        )


def test_capture_rejects_extra_or_mismatched_arguments_before_mcp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    async def fake_call(*_: object) -> dict[str, object]:
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(stack_hil_driver, "_call_mcp", fake_call)
    good = {
        "session_id": "s1",
        "operation_id": "a" * 32,
        "acknowledge_intrusive": True,
        "sample_period_ms": 10,
        "duration_ms": 100,
        "max_samples": 1,
        "max_frames": 1,
        "core_id": 0,
        "address_space": "P",
    }
    for changed in (
        {**good, "extra": True},
        {**good, "operation_id": "b" * 32},
        {**good, "acknowledge_intrusive": False},
    ):
        with pytest.raises(stack_hil_driver.StackHilDriverError):
            stack_hil_driver.run(
                common_args(
                    operation="capture",
                    session="s1",
                    capture_operation_id="a" * 32,
                    sidecar_args=json.dumps(changed),
                )
            )
    assert not called


def test_capture_passes_host_generated_intrusive_arguments_exactly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[str, dict[str, object]]] = []
    arguments: dict[str, object] = {
        "session_id": "s1",
        "operation_id": "a" * 32,
        "acknowledge_intrusive": True,
        "sample_period_ms": 10,
        "duration_ms": 100,
        "max_samples": 1,
        "max_frames": 1,
        "core_id": 0,
        "address_space": "P",
    }

    async def fake_call(
        _args: object, tool: str, received: dict[str, object]
    ) -> dict[str, object]:
        observed.append((tool, received))
        return {"summary": {}, "artifact": {}}

    monkeypatch.setattr(stack_hil_driver, "_call_mcp", fake_call)
    assert stack_hil_driver.run(
        common_args(
            operation="capture",
            session="s1",
            capture_operation_id="a" * 32,
            sidecar_args=json.dumps(arguments),
        )
    ) == {"summary": {}, "artifact": {}}
    assert observed == [("stack_sampling_capture", arguments)]


def test_capture_returns_only_bounded_summary_and_artifact() -> None:
    result = {
        "summary": {
            "attempted_samples": 2,
            "collected_samples": 1,
            "total_halt_cycle_duration_ns": 10,
            "cleanup_complete": True,
        },
        "artifact": {
            "relative_path": "capture/staging/stack-samples-s1-" + "a" * 32 + ".json",
            "sha256": "a" * 64,
            "size_bytes": 1,
        },
    }
    assert stack_hil_driver._bounded_capture_result(result) is result
    with pytest.raises(stack_hil_driver.StackHilDriverError, match="only summary"):
        stack_hil_driver._bounded_capture_result({**result, "extra": True})
    bad = {**result, "summary": {**result["summary"], "cleanup_complete": False}}
    with pytest.raises(stack_hil_driver.StackHilDriverError, match="invalid summary"):
        stack_hil_driver._bounded_capture_result(bad)


def test_mcp_error_result_preserves_bounded_public_diagnostic() -> None:
    result = types.CallToolResult(
        isError=True,
        content=[
            types.TextContent(
                type="text",
                text='{"error":"stack_sampling_failed","message":"PERF is active"}',
            )
        ],
    )
    with pytest.raises(
        stack_hil_driver.StackHilDriverError,
        match=r"stack_sampling_failed.*PERF is active",
    ):
        stack_hil_driver._mcp_result_object(result)


def test_stack_server_module_is_an_executable_entry_point() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "lauterbach_sampling_mcp.stack_server", "--help"],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0
    assert "Intrusive TRACE32 stack-sampling MCP server" in completed.stdout


@pytest.mark.parametrize("recovery_flag", ["--recover-only", "--recover-quarantined"])
def test_stack_server_recovery_flags_must_be_supplied_together(
    tmp_path: Path, recovery_flag: str
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "lauterbach_sampling_mcp.stack_server",
            "--artifact-root",
            str(tmp_path),
            recovery_flag,
        ],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 2
    assert "must be supplied together" in completed.stderr


def test_mcp_inventory_is_exact_and_stack_server_is_selected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    @asynccontextmanager
    async def fake_stdio(server: object):
        observed["server"] = server
        yield object(), object()

    class FakeSession:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def initialize(self) -> None:
            return None

        async def list_tools(self):
            return types.ListToolsResult(
                tools=[
                    types.Tool(
                        name="stack_sampling_capabilities",
                        description="",
                        inputSchema={},
                    )
                ]
            )

    monkeypatch.setattr(stack_hil_driver, "stdio_client", fake_stdio)
    monkeypatch.setattr(stack_hil_driver, "ClientSession", FakeSession)
    with pytest.raises(stack_hil_driver.StackHilDriverError, match="inventory"):
        asyncio.run(
            stack_hil_driver._call_mcp(
                common_args(),
                "stack_sampling_capabilities",
                {},
                read_timeout=timedelta(milliseconds=1),
            )
        )
    server_args = cast(stack_hil_driver.StdioServerParameters, observed["server"]).args
    assert server_args[:3] == ["-m", "lauterbach_sampling_mcp.stack_server", "--host"]
    assert "--timeout" in server_args


def test_mcp_cancellation_closes_session_and_stdio(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exited: list[str] = []

    @asynccontextmanager
    async def fake_stdio(_: object):
        try:
            yield object(), object()
        finally:
            exited.append("stdio")

    class BlockingSession:
        def __init__(self, *_: object, **__: object) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_: object) -> None:
            exited.append("session")

        async def initialize(self) -> None:
            return None

        async def list_tools(self):
            return types.ListToolsResult(
                tools=[
                    types.Tool(name=name, description="", inputSchema={})
                    for name in stack_hil_driver.EXPECTED_TOOLS
                ]
            )

        async def call_tool(self, *_: object, **__: object):
            await asyncio.Event().wait()

    monkeypatch.setattr(stack_hil_driver, "stdio_client", fake_stdio)
    monkeypatch.setattr(stack_hil_driver, "ClientSession", BlockingSession)

    async def cancel() -> None:
        task = asyncio.create_task(
            stack_hil_driver._call_mcp(common_args(), "stack_sampling_capabilities", {})
        )
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel())
    assert exited == ["session", "stdio"]
