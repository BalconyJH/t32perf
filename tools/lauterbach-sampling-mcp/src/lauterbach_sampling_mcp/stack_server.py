"""Independent MCP entry point for explicitly intrusive stack capture."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import threading
from pathlib import Path
from typing import Any

from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from .model import InputError
from .stack_model import StackCaptureRequest
from .stack_service import StackSamplingError, StackSamplingService
from .storage import StorageError

TOOL_NAMES = ("stack_sampling_capabilities", "stack_sampling_capture")


def _public_error(error: Exception) -> dict[str, str]:
    if isinstance(error, InputError):
        return {"error": "invalid_input", "message": str(error)}
    if isinstance(error, StackSamplingError):
        return {"error": "stack_sampling_failed", "message": str(error)}
    return {
        "error": "storage_or_io_failed",
        "message": "stack sampling encountered an internal I/O failure",
    }


def create_server(service: StackSamplingService) -> Server:
    server = Server(
        "lauterbach-stack-sampling-mcp",
        instructions="Intrusive TRACE32 Break/Frame.Up stack sampling only; each sample stops and resumes the target.",
    )
    lock = asyncio.Lock()

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name=TOOL_NAMES[0],
                description="Read intrusive stack sampling capabilities without changing target state.",
                inputSchema={"type": "object", "additionalProperties": False},
                outputSchema={"type": "object"},
            ),
            types.Tool(
                name=TOOL_NAMES[1],
                description="Explicitly acknowledged, bounded Break/Frame.Up stack sampling; the target is stopped for every sample.",
                inputSchema={
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "session_id",
                        "operation_id",
                        "acknowledge_intrusive",
                        "sample_period_ms",
                        "duration_ms",
                        "max_samples",
                        "max_frames",
                        "core_id",
                        "address_space",
                    ],
                    "properties": {
                        "session_id": {
                            "type": "string",
                            "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$",
                        },
                        "operation_id": {"type": "string", "pattern": "^[0-9a-f]{32}$"},
                        "acknowledge_intrusive": {"const": True},
                        "sample_period_ms": {
                            "type": "integer",
                            "minimum": 10,
                            "maximum": 1000,
                        },
                        "duration_ms": {
                            "type": "integer",
                            "minimum": 100,
                            "maximum": 60000,
                        },
                        "max_samples": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 512,
                        },
                        "max_frames": {"type": "integer", "minimum": 1, "maximum": 8},
                        "core_id": {
                            "const": 0,
                            "type": "integer",
                        },
                        "address_space": {"const": "P"},
                        "deployed_firmware_elf_sha256": {
                            "type": "string",
                            "pattern": "^[0-9a-f]{64}$",
                        },
                    },
                },
                outputSchema={
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["summary", "artifact"],
                    "properties": {
                        "summary": {"type": "object"},
                        "artifact": {"type": "object"},
                    },
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        try:
            async with lock:
                cancelled: threading.Event | None = None
                if name == TOOL_NAMES[0]:
                    if arguments:
                        raise InputError(
                            "stack_sampling_capabilities does not accept input"
                        )
                    worker = asyncio.create_task(
                        asyncio.to_thread(service.capabilities)
                    )
                elif name == TOOL_NAMES[1]:
                    cancelled = threading.Event()
                    worker = asyncio.create_task(
                        asyncio.to_thread(
                            service.capture,
                            StackCaptureRequest.parse(arguments or {}),
                            cancelled,
                        )
                    )
                else:
                    raise InputError("unknown stack-sampling tool")
                try:
                    return await asyncio.shield(worker)
                except asyncio.CancelledError:
                    # Signal the synchronous RCL worker before awaiting it: it
                    # checks between inter-sample waits, frame operations, and
                    # post-Go symbol lookups, and never starts another Break.
                    if cancelled is not None:
                        cancelled.set()
                    with __import__("contextlib").suppress(Exception):
                        await asyncio.shield(worker)
                    raise
        except (InputError, StackSamplingError, StorageError, OSError) as error:
            raise ValueError(json.dumps(_public_error(error))) from error

    return server


async def _serve(server: Server) -> None:
    async with stdio_server() as streams:
        await server.run(streams[0], streams[1], server.create_initialization_options())


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Intrusive TRACE32 stack-sampling MCP server"
    )
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=20000)
    parser.add_argument("--protocol", choices=("TCP",), default="TCP")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--expected-endpoint-fingerprint")
    parser.add_argument("--recover-quarantined", action="store_true")
    parser.add_argument(
        "--recover-only",
        action="store_true",
        help="consume one explicit journal recovery authorization and exit",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or args.timeout <= 0:
        parser.error("port must be 1..65535 and timeout must be positive")
    if args.recover_only != args.recover_quarantined:
        parser.error(
            "--recover-only and --recover-quarantined must be supplied together"
        )
    service = StackSamplingService(
        host=args.host,
        port=args.port,
        protocol=args.protocol,
        timeout=args.timeout,
        artifact_root=Path(args.artifact_root),
        expected_endpoint_fingerprint=args.expected_endpoint_fingerprint,
        recover_quarantined=args.recover_quarantined,
    )
    if args.recover_only:
        try:
            result = service.recover_only()
        except (InputError, StackSamplingError, StorageError, OSError) as error:
            print(
                json.dumps(_public_error(error), sort_keys=True, separators=(",", ":")),
                file=sys.stderr,
            )
            raise SystemExit(2) from error
        print(
            json.dumps(
                result,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return
    asyncio.run(_serve(create_server(service)))


if __name__ == "__main__":
    main()
