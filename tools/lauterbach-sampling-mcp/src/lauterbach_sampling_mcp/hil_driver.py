"""Closed HIL driver for the sampling-only TRACE32 MCP endpoint.

This module is deliberately a small argv bridge: Host operations invoke the
configured ``t32perf`` executable directly, while TRACE32 operations always
go through a fresh stdio MCP ClientSession.  It is not a general command
runner and never accepts a caller-supplied executable, MCP tool, or endpoint.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client

from .model import SHA256_RE, InputError, normalize_loopback_tcp_endpoint

MAX_JSON_BYTES = 65_536
MAX_CHILD_OUTPUT_BYTES = 1_048_576
HOST_OPERATION_TIMEOUT_SECONDS = 30.0
MCP_READ_TIMEOUT = timedelta(seconds=90)
EXPECTED_TOOLS = frozenset({"sampling_capabilities", "sampling_capture"})
HISTOGRAM_ARTIFACT_ID = "sampling-pc-hit-histogram"
ADDRESS_HEATMAP_ARTIFACT_ID = "sampling-heatmap-address"


class HilDriverError(RuntimeError):
    """The fixed HIL adapter contract was violated."""


def _strict_object_json(raw: str | bytes, *, description: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise HilDriverError(f"{description} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HilDriverError(f"{description} is not strict JSON: {error}") from error
    if not isinstance(value, dict):
        raise HilDriverError(f"{description} must be a JSON object")
    return value


def _read_request(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_JSON_BYTES + 1)
    except OSError as error:
        raise HilDriverError(f"cannot read capture request {path}: {error}") from error
    if not data or len(data) > MAX_JSON_BYTES:
        raise HilDriverError("capture request must be 1..65536 bytes")
    return _strict_object_json(data, description="capture request")


def _json_stdout(value: dict[str, Any]) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def _run_bounded_child(
    argv: list[str], *, timeout_seconds: float = HOST_OPERATION_TIMEOUT_SECONDS
) -> tuple[int, bytes, bytes]:
    """Run a direct argv child while draining both pipes under independent caps."""
    try:
        child = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise HilDriverError(f"cannot execute t32perf: {error}") from error
    assert child.stdout is not None and child.stderr is not None
    output = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = threading.Event()
    reader_errors: list[OSError | ValueError] = []

    def drain(name: str, stream: Any) -> None:
        try:
            while chunk := stream.read(8192):
                remaining = MAX_CHILD_OUTPUT_BYTES - len(output[name])
                output[name].extend(chunk[: max(remaining, 0)])
                if len(chunk) > remaining:
                    overflow.set()
        except (OSError, ValueError) as error:
            reader_errors.append(error)

    threads = [
        threading.Thread(target=drain, args=("stdout", child.stdout), daemon=True),
        threading.Thread(target=drain, args=("stderr", child.stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout_seconds
    failure: str | None = None
    while child.poll() is None:
        if overflow.is_set():
            failure = "t32perf stdout or stderr exceeded 1048576 bytes"
            break
        if time.monotonic() >= deadline:
            failure = f"t32perf exceeded {timeout_seconds:g} second operation timeout"
            break
        time.sleep(0.01)
    if failure is not None:
        child.terminate()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)
    else:
        child.wait()
    for thread in threads:
        thread.join(timeout=2)
    if any(thread.is_alive() for thread in threads):
        for stream in (child.stdout, child.stderr):
            stream.close()
        for thread in threads:
            thread.join(timeout=2)
    if any(thread.is_alive() for thread in threads):
        raise HilDriverError("t32perf output drain did not terminate")
    if overflow.is_set() and failure is None:
        failure = "t32perf stdout or stderr exceeded 1048576 bytes"
    if reader_errors and failure is None:
        raise HilDriverError(f"cannot drain t32perf output: {reader_errors[0]}")
    if failure is not None:
        raise HilDriverError(failure)
    return child.returncode, bytes(output["stdout"]), bytes(output["stderr"])


def _host_command(args: argparse.Namespace, command: list[str]) -> dict[str, Any]:
    argv = [args.t32perf_bin, "--artifact-root", args.artifact_root, "--json", *command]
    returncode, stdout, stderr = _run_bounded_child(argv)
    if returncode != 0:
        message = (stderr or stdout).decode("utf-8", errors="replace").strip()
        raise HilDriverError(f"t32perf failed ({returncode}): {message or 'no output'}")
    return _strict_object_json(stdout, description="t32perf JSON result")


def _require_exact_artifact(value: str, expected: str, *, option: str) -> str:
    if value != expected:
        raise HilDriverError(f"{option} must be the Host artifact id {expected!r}")
    return value


def _mcp_result_object(result: types.CallToolResult) -> dict[str, Any]:
    if result.isError:
        raise HilDriverError("sampling MCP returned an error result")
    if len(result.content) != 1 or not isinstance(result.content[0], types.TextContent):
        raise HilDriverError("sampling MCP result must contain exactly one TextContent")
    text = result.content[0].text
    if len(text.encode("utf-8")) > MAX_JSON_BYTES:
        raise HilDriverError("sampling MCP TextContent exceeds 65536 bytes")
    return _strict_object_json(text, description="sampling MCP TextContent")


async def _call_mcp(
    args: argparse.Namespace,
    tool: str,
    arguments: dict[str, Any],
    *,
    read_timeout: timedelta = MCP_READ_TIMEOUT,
) -> dict[str, Any]:
    server = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "lauterbach_sampling_mcp",
            "--host",
            args.host,
            "--port",
            str(args.port),
            "--protocol",
            args.protocol,
            "--artifact-root",
            args.artifact_root,
            "--expected-endpoint-fingerprint",
            args.expected_endpoint_fingerprint,
        ],
    )
    try:
        async with (
            stdio_client(server) as (read_stream, write_stream),
            ClientSession(
                read_stream, write_stream, read_timeout_seconds=read_timeout
            ) as session,
        ):
            await session.initialize()
            inventory = await session.list_tools()
            names = {item.name for item in inventory.tools}
            if names != EXPECTED_TOOLS or len(inventory.tools) != len(EXPECTED_TOOLS):
                raise HilDriverError("sampling MCP tool inventory is not exact")
            return _mcp_result_object(
                await session.call_tool(
                    tool, arguments, read_timeout_seconds=read_timeout
                )
            )
    except HilDriverError:
        raise
    except (
        Exception
    ) as error:  # transport boundary; stdio_client closes then terminates child
        raise HilDriverError(
            f"sampling MCP transport failed or timed out: {error}"
        ) from error


def _parse_capture_arguments(
    raw: str, session_id: str, operation_id: str
) -> dict[str, Any]:
    value = _strict_object_json(raw, description="sampling capture arguments")
    if value.get("session_id") != session_id:
        raise HilDriverError("sampling capture arguments do not match --session")
    if value.get("operation_id") != operation_id:
        raise HilDriverError("sampling capture arguments do not match --operation")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Closed generic sampling HIL driver")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--protocol", required=True, choices=("TCP",))
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--t32perf-bin", required=True)
    parser.add_argument("--expected-endpoint-fingerprint", required=True)
    subcommands = parser.add_subparsers(dest="operation", required=True)
    prepare = subcommands.add_parser("prepare")
    prepare.add_argument("--session", required=True)
    prepare.add_argument("--request", required=True, type=Path)
    capabilities = subcommands.add_parser("capabilities")
    capabilities.add_argument("--session", required=True)
    capture = subcommands.add_parser("capture")
    capture.add_argument("--session", required=True)
    capture.add_argument("--operation", dest="capture_operation_id", required=True)
    capture.add_argument("sidecar_args")
    ingest = subcommands.add_parser("ingest")
    ingest.add_argument("--session", required=True)
    ingest.add_argument("--staged", required=True)
    analyze = subcommands.add_parser("analyze")
    analyze.add_argument("--session", required=True)
    analyze.add_argument("--histogram", required=True)
    summary = subcommands.add_parser("summary")
    summary.add_argument("--session", required=True)
    summary.add_argument("--heatmap", required=True)
    render = subcommands.add_parser("render")
    render.add_argument("--session", required=True)
    render.add_argument("--heatmap", required=True)
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    try:
        normalize_loopback_tcp_endpoint(args.host, args.protocol)
    except InputError as error:
        raise HilDriverError(str(error)) from error
    if not 1 <= args.port <= 65535:
        raise HilDriverError("port must be 1..65535")
    if not SHA256_RE.fullmatch(args.expected_endpoint_fingerprint):
        raise HilDriverError("--expected-endpoint-fingerprint must be a SHA-256 digest")
    if args.operation == "prepare":
        request = _read_request(args.request)
        return _host_command(
            args,
            [
                "sampling",
                "prepare",
                args.session,
                "--capture-request",
                json.dumps(request, sort_keys=True, separators=(",", ":")),
            ],
        )
    if args.operation == "capabilities":
        return asyncio.run(_call_mcp(args, "sampling_capabilities", {}))
    if args.operation == "capture":
        return asyncio.run(
            _call_mcp(
                args,
                "sampling_capture",
                _parse_capture_arguments(
                    args.sidecar_args, args.session, args.capture_operation_id
                ),
            )
        )
    if args.operation == "ingest":
        return _host_command(
            args, ["sampling", "ingest", args.session, "--staged", args.staged]
        )
    if args.operation == "analyze":
        return _host_command(
            args,
            [
                "sampling",
                "analyze",
                args.session,
                "--histogram-artifact",
                _require_exact_artifact(
                    args.histogram, HISTOGRAM_ARTIFACT_ID, option="--histogram"
                ),
                "--projection",
                "address",
            ],
        )
    heatmap = _require_exact_artifact(
        args.heatmap, ADDRESS_HEATMAP_ARTIFACT_ID, option="--heatmap"
    )
    command = ["sampling", args.operation, args.session, "--projection", "address"]
    if args.operation == "summary":
        return _host_command(args, command)
    if args.operation == "render":
        # render's CLI obtains the fixed address projection by id; validate the
        # HIL placeholder before dispatch so it cannot silently be ignored.
        del heatmap
        return _host_command(args, command)
    raise HilDriverError("unsupported HIL operation")


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        _json_stdout(run(args))
    except HilDriverError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
