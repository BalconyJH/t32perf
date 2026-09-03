"""Closed HIL argv bridge for intrusive TRACE32 stack sampling.

Host phases use the configured ``t32perf`` binary.  TRACE32 phases use a
fresh stdio child of this package's ``stack_server`` and its exact two-tool
surface.  This deliberately is not a general command runner.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client

from .hil_driver import (
    MAX_JSON_BYTES,
    HilDriverError,
    _read_request,
    _run_bounded_child,
    _strict_object_json,
)
from .model import SHA256_RE, InputError, normalize_loopback_tcp_endpoint
from .stack_model import StackCaptureRequest

HOST_OPERATION_TIMEOUT_SECONDS = 30.0
MCP_READ_TIMEOUT = timedelta(seconds=90)
EXPECTED_TOOLS = frozenset({"stack_sampling_capabilities", "stack_sampling_capture"})
STACK_SAMPLES_ARTIFACT_ID = "sampling-stack-samples"


class StackHilDriverError(HilDriverError):
    """The fixed intrusive stack HIL contract was violated."""


def _json_stdout(value: dict[str, Any]) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True))


def _host_command(args: argparse.Namespace, command: list[str]) -> dict[str, Any]:
    argv = [args.t32perf_bin, "--artifact-root", args.artifact_root, "--json", *command]
    returncode, stdout, stderr = _run_bounded_child(
        argv, timeout_seconds=HOST_OPERATION_TIMEOUT_SECONDS
    )
    if returncode != 0:
        message = (stderr or stdout).decode("utf-8", errors="replace").strip()
        raise StackHilDriverError(
            f"t32perf failed ({returncode}): {message or 'no output'}"
        )
    return _strict_object_json(stdout, description="t32perf JSON result")


def _mcp_result_object(result: types.CallToolResult) -> dict[str, Any]:
    if len(result.content) != 1 or not isinstance(result.content[0], types.TextContent):
        raise StackHilDriverError(
            "stack-sampling MCP result must contain exactly one TextContent"
        )
    text = result.content[0].text
    if len(text.encode("utf-8")) > MAX_JSON_BYTES:
        raise StackHilDriverError("stack-sampling MCP TextContent exceeds 65536 bytes")
    if result.isError:
        public = "".join(
            character
            for character in text
            if character in "\r\n\t" or ord(character) >= 32
        )
        public = public.encode("utf-8")[:1024].decode("utf-8", errors="ignore").strip()
        raise StackHilDriverError(
            "stack-sampling MCP returned an error result"
            + (f": {public}" if public else "")
        )
    return _strict_object_json(text, description="stack-sampling MCP TextContent")


def _bounded_capture_result(value: dict[str, Any]) -> dict[str, Any]:
    """Keep the HIL handoff to the Host's exact published stack artifact."""
    if set(value) != {"summary", "artifact"}:
        raise StackHilDriverError(
            "stack capture result must contain only summary and artifact"
        )
    summary, artifact = value["summary"], value["artifact"]
    if not isinstance(summary, dict) or set(summary) != {
        "attempted_samples",
        "collected_samples",
        "total_halt_cycle_duration_ns",
        "cleanup_complete",
    }:
        raise StackHilDriverError("stack capture result has an invalid summary")
    if (
        any(
            type(summary[name]) is not int or summary[name] < 0
            for name in (
                "attempted_samples",
                "collected_samples",
                "total_halt_cycle_duration_ns",
            )
        )
        or summary["collected_samples"] > summary["attempted_samples"]
        or summary["cleanup_complete"] is not True
    ):
        raise StackHilDriverError("stack capture result has an invalid summary")
    if (
        not isinstance(artifact, dict)
        or set(artifact) != {"relative_path", "sha256", "size_bytes"}
        or not isinstance(artifact["relative_path"], str)
        or len(artifact["relative_path"].encode("utf-8")) > 1024
        or not SHA256_RE.fullmatch(artifact["sha256"])
        or type(artifact["size_bytes"]) is not int
        or not 0 < artifact["size_bytes"] <= 64 * 1024 * 1024
    ):
        raise StackHilDriverError("stack capture result has an invalid artifact")
    return value


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
            "lauterbach_sampling_mcp.stack_server",
            "--host",
            args.host,
            "--port",
            str(args.port),
            "--protocol",
            args.protocol,
            "--timeout",
            str(args.timeout),
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
            inventory_valid = names == EXPECTED_TOOLS and len(inventory.tools) == len(
                EXPECTED_TOOLS
            )
            call_result = (
                await session.call_tool(
                    tool, arguments, read_timeout_seconds=read_timeout
                )
                if inventory_valid
                else None
            )
    except StackHilDriverError:
        raise
    except asyncio.CancelledError:
        # The context managers synchronously close pipes and reap the child before
        # cancellation escapes this bridge.
        raise
    except Exception as error:  # transport boundary; stdio client closes its child
        raise StackHilDriverError(
            f"stack-sampling MCP transport failed or timed out: {error}"
        ) from error
    if not inventory_valid:
        raise StackHilDriverError("stack-sampling MCP tool inventory is not exact")
    if call_result is None:
        raise StackHilDriverError("stack-sampling MCP returned no result")
    result = _mcp_result_object(call_result)
    return (
        _bounded_capture_result(result) if tool == "stack_sampling_capture" else result
    )


def _parse_capture_arguments(
    raw: str, session_id: str, operation_id: str
) -> dict[str, Any]:
    value = _strict_object_json(raw, description="stack capture arguments")
    try:
        request = StackCaptureRequest.parse(value)
    except InputError as error:
        raise StackHilDriverError(
            f"invalid stack capture arguments: {error}"
        ) from error
    if request.session_id != session_id:
        raise StackHilDriverError("stack capture arguments do not match --session")
    if request.operation_id != operation_id:
        raise StackHilDriverError("stack capture arguments do not match --operation")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Closed intrusive stack-sampling HIL driver"
    )
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--protocol", required=True, choices=("TCP",))
    parser.add_argument("--timeout", required=True, type=float)
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
    analyze.add_argument("--stack-samples", required=True)
    summary = subcommands.add_parser("summary")
    summary.add_argument("--session", required=True)
    render = subcommands.add_parser("render")
    render.add_argument("--session", required=True)
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    try:
        normalize_loopback_tcp_endpoint(args.host, args.protocol)
    except InputError as error:
        raise StackHilDriverError(str(error)) from error
    if not 1 <= args.port <= 65535:
        raise StackHilDriverError("port must be 1..65535")
    if args.timeout <= 0:
        raise StackHilDriverError("timeout must be positive")
    if not SHA256_RE.fullmatch(args.expected_endpoint_fingerprint):
        raise StackHilDriverError(
            "--expected-endpoint-fingerprint must be a SHA-256 digest"
        )
    if args.operation == "prepare":
        request = _read_request(args.request)
        return _host_command(
            args,
            [
                "stack",
                "prepare",
                args.session,
                "--capture-request",
                json.dumps(request, sort_keys=True, separators=(",", ":")),
            ],
        )
    if args.operation == "capabilities":
        return asyncio.run(_call_mcp(args, "stack_sampling_capabilities", {}))
    if args.operation == "capture":
        return asyncio.run(
            _call_mcp(
                args,
                "stack_sampling_capture",
                _parse_capture_arguments(
                    args.sidecar_args, args.session, args.capture_operation_id
                ),
            )
        )
    if args.operation == "ingest":
        return _host_command(
            args, ["stack", "ingest", args.session, "--staged", args.staged]
        )
    if args.operation == "analyze":
        if args.stack_samples != STACK_SAMPLES_ARTIFACT_ID:
            raise StackHilDriverError(
                f"--stack-samples must be the Host artifact id {STACK_SAMPLES_ARTIFACT_ID!r}"
            )
        return _host_command(
            args,
            [
                "stack",
                "analyze",
                args.session,
                "--stack-samples-artifact",
                args.stack_samples,
            ],
        )
    if args.operation in {"summary", "render"}:
        return _host_command(args, ["stack", args.operation, args.session])
    raise StackHilDriverError("unsupported HIL operation")


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        _json_stdout(run(args))
    except StackHilDriverError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()
