"""A bounded TRACE32 PERF PC-histogram MCP server."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any

from mcp import types
from mcp.server import Server
from mcp.server.stdio import stdio_server

from .model import CaptureRequest, InputError
from .service import SamplingError, SamplingService
from .storage import StorageError

TOOL_NAMES = ("sampling_capabilities", "sampling_capture")


def _public_error(error: Exception) -> dict[str, str]:
    """Return the stable, path-free error contract at the MCP boundary."""
    if isinstance(error, InputError):
        return {"error": "invalid_input", "message": str(error)}
    if isinstance(error, SamplingError):
        return {"error": "sampling_failed", "message": str(error)}
    return {
        "error": "storage_or_io_failed",
        "message": "sampling operation encountered an internal I/O failure",
    }


def create_server(service: SamplingService) -> Server:
    if service.recover_legacy_only:
        raise InputError("legacy recovery-only service cannot start an MCP server")
    server = Server(
        "lauterbach-sampling-mcp",
        instructions=(
            "Bounded TRACE32 PERF PC histogram capture only. It never explicitly "
            "starts, resets, flashes, or runs workloads. StopAndGo periodically halts "
            "and resumes the target, and is available only with explicit policy."
        ),
    )
    lock = asyncio.Lock()

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [
            types.Tool(
                name=TOOL_NAMES[0],
                description="Read TRACE32 PC-sampling capabilities without changing target or PERF state.",
                inputSchema={
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
                outputSchema={"type": "object", "additionalProperties": True},
            ),
            types.Tool(
                name=TOOL_NAMES[1],
                description=(
                    "Capture a bounded PC-hit histogram from an already running target. "
                    "StopAndGo periodically halts/resumes it and requires explicit "
                    "allow_stop_and_go policy. TRACE32-loaded symbols may optionally "
                    "label refined high-hit locations without verifying firmware identity."
                ),
                inputSchema={
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "session_id",
                        "operation_id",
                        "ranges",
                        "bucket_size",
                        "duration_ms",
                    ],
                    "properties": {
                        "session_id": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": 64,
                            "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$",
                        },
                        "operation_id": {
                            "type": "string",
                            "pattern": "^[0-9a-f]{32}$",
                        },
                        "ranges": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": 256,
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "required": ["start_address", "end_address"],
                                "properties": {
                                    "start_address": {
                                        "type": "integer",
                                        "minimum": 0,
                                        "maximum": 18446744073709551615,
                                    },
                                    "end_address": {
                                        "type": "integer",
                                        "minimum": 0,
                                        "maximum": 18446744073709551615,
                                    },
                                },
                            },
                        },
                        "bucket_size": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 1048576,
                        },
                        "duration_ms": {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 60000,
                        },
                        "method_policy": {
                            "enum": ["realtime_only", "allow_stop_and_go"]
                        },
                        "core_id": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 4294967295,
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
                    "required": ["histogram", "artifact"],
                    "properties": {
                        "histogram": {"type": "object"},
                        "artifact": {
                            "type": "object",
                            "required": ["relative_path", "sha256", "size_bytes"],
                        },
                    },
                },
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        arguments = arguments or {}
        try:
            async with lock:
                if name == TOOL_NAMES[0]:
                    if arguments:
                        raise InputError("sampling_capabilities does not accept input")
                    worker = asyncio.create_task(
                        asyncio.to_thread(service.capabilities)
                    )
                elif name == TOOL_NAMES[1]:
                    worker = asyncio.create_task(
                        asyncio.to_thread(
                            service.capture, CaptureRequest.parse(arguments)
                        )
                    )
                else:
                    raise InputError("unknown sampling-only tool")
                try:
                    return await asyncio.shield(worker)
                except asyncio.CancelledError:
                    await asyncio.shield(worker)
                    raise
        except InputError as error:
            raise ValueError(json.dumps(_public_error(error))) from error
        except SamplingError as error:
            raise ValueError(json.dumps(_public_error(error))) from error
        except (StorageError, OSError) as error:
            raise ValueError(json.dumps(_public_error(error))) from error

    return server


async def _serve(server: Server) -> None:
    async with stdio_server() as streams:
        await server.run(streams[0], streams[1], server.create_initialization_options())


def main() -> None:
    parser = argparse.ArgumentParser(description="Sampling-only TRACE32 MCP server")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=20000)
    parser.add_argument("--protocol", choices=("TCP",), default="TCP")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--expected-endpoint-fingerprint")
    parser.add_argument(
        "--recover-quarantined",
        action="store_true",
        help="explicitly retry a previously failed sidecar PERF cleanup",
    )
    parser.add_argument(
        "--recover-legacy-only",
        action="store_true",
        help="development-v1 journal cleanup only; does not start the MCP server",
    )
    parser.add_argument(
        "--legacy-endpoint-fingerprint",
        help="development-v1 endpoint digest accepted only with --recover-legacy-only",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or args.timeout <= 0:
        parser.error("port must be 1..65535 and timeout must be positive")
    service = SamplingService(
        host=args.host,
        port=args.port,
        protocol=args.protocol,
        timeout=args.timeout,
        artifact_root=Path(args.artifact_root),
        expected_endpoint_fingerprint=args.expected_endpoint_fingerprint,
        recover_quarantined=args.recover_quarantined,
        recover_legacy_only=args.recover_legacy_only,
        legacy_endpoint_fingerprint=args.legacy_endpoint_fingerprint,
    )
    if args.recover_legacy_only:
        service.recover_legacy_only_transaction()
        return
    if args.legacy_endpoint_fingerprint is not None:
        parser.error("--legacy-endpoint-fingerprint requires --recover-legacy-only")
    asyncio.run(_serve(create_server(service)))


__all__ = ["CaptureRequest", "SamplingService", "create_server", "main"]
