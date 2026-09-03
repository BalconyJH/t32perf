"""Pinned, closed-wrapper configuration for intrusive stack-sampling HIL."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import string
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from harness import (
    HilConfigurationError,
    HilOutputError,
    LocalOutputAccess,
    OutputAccess,
    _configuration_integer,
    _nonempty_string,
    _paths_overlap,
    _read_plain_json_snapshot,
    _resolve_config_path,
    _resolve_plain_config_file,
    _strict_json_loads,
)
from sampling_board import endpoint_fingerprint

_HEX = re.compile(r"^[0-9a-f]{64}$")
_OPERATIONS = frozenset(
    {"prepare", "capabilities", "capture", "ingest", "analyze", "summary", "render"}
)
_T32PERF_BINARY_LIMIT_BYTES = 64 * 1024 * 1024


def _resolve_and_hash_t32perf_binary(base: Path, value: object, expected: str) -> Path:
    """Return a stable, bounded digest-checked Host executable path."""

    text = (
        str(value)
        if isinstance(value, Path)
        else _nonempty_string(value, "host.t32perf_bin")
    )
    candidate = Path(text)
    candidate = candidate if candidate.is_absolute() else base / candidate
    try:
        before_name = candidate.lstat()
    except OSError as error:
        raise HilConfigurationError(
            f"host.t32perf_bin is not readable: {error}"
        ) from error
    if stat.S_ISLNK(before_name.st_mode) or not stat.S_ISREG(before_name.st_mode):
        raise HilConfigurationError("host.t32perf_bin must be a plain regular file")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise HilConfigurationError(f"cannot read host.t32perf_bin: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise HilConfigurationError("host.t32perf_bin must be a regular file")
        if before.st_size > _T32PERF_BINARY_LIMIT_BYTES:
            raise HilConfigurationError(
                f"host.t32perf_bin exceeds {_T32PERF_BINARY_LIMIT_BYTES} byte limit"
            )
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 64 * 1024):
            total += len(chunk)
            if total > _T32PERF_BINARY_LIMIT_BYTES:
                raise HilConfigurationError(
                    f"host.t32perf_bin exceeds {_T32PERF_BINARY_LIMIT_BYTES} byte limit"
                )
            digest.update(chunk)
        after = os.fstat(descriptor)
        after_name = candidate.lstat()
    except OSError as error:
        raise HilConfigurationError(f"cannot read host.t32perf_bin: {error}") from error
    finally:
        os.close(descriptor)
    if (
        stat.S_ISLNK(after_name.st_mode)
        or not stat.S_ISREG(after_name.st_mode)
        or (before_name.st_dev, before_name.st_ino, before_name.st_size)
        != (before.st_dev, before.st_ino, before.st_size)
        or (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or total != before.st_size
    ):
        raise HilConfigurationError("host.t32perf_bin changed while being read")
    if digest.hexdigest() != expected:
        raise HilConfigurationError(
            "host.t32perf_sha256 does not match host.t32perf_bin"
        )
    return candidate


def _request(document: object) -> None:
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "acknowledge_intrusive",
        "sample_period_ms",
        "duration_ms",
        "max_samples",
        "max_frames",
        "core_id",
        "address_space",
    }:
        raise ValueError("stack request fields are invalid")
    if document["schema"] != "t32perf.stack-capture-request/v1":
        raise ValueError("stack request schema is invalid")
    if document["acknowledge_intrusive"] is not True:
        raise ValueError("stack request must acknowledge intrusive capture")
    if document["address_space"] != "P":
        raise ValueError("stack request address_space must be P")
    bounds = {
        "sample_period_ms": (10, 1_000),
        "duration_ms": (100, 60_000),
        "max_samples": (1, 512),
        "max_frames": (1, 8),
        "core_id": (0, 0),
    }
    for key, (minimum, maximum) in bounds.items():
        value = document[key]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not minimum <= value <= maximum
        ):
            raise ValueError(f"stack request {key} is invalid")


@dataclass(frozen=True)
class StackBoardConfig:
    path: Path
    board_id: str
    mcu_family: str
    expected_cpu: str
    lock_file: Path
    trace32_software: str
    probe_id: str
    endpoint_host: str
    endpoint_port: int
    endpoint_protocol: str
    endpoint_fingerprint: str
    probe_fingerprint: str
    t32perf_bin: Path
    t32perf_sha256: str
    artifact_root: Path
    evidence_root: Path
    min_free_bytes: int
    request_file: Path
    request_sha256: str
    commands: dict[str, tuple[str, ...]]

    @classmethod
    def load(cls, path: Path) -> Self:
        resolved = path.resolve(strict=True)
        with resolved.open("rb") as stream:
            raw = tomllib.load(stream)
        expected = {"board", "trace32", "endpoint", "host", "stack", "driver"}
        if set(raw) != expected or not all(
            isinstance(value, dict) for value in raw.values()
        ):
            raise HilConfigurationError(
                "stack board configuration table set is invalid"
            )
        fields = {
            "board": {"id", "mcu_family", "expected_cpu", "lock_file"},
            "trace32": {"software", "probe_id"},
            "endpoint": {
                "host",
                "port",
                "protocol",
                "expected_fingerprint",
                "expected_probe_fingerprint",
            },
            "host": {
                "t32perf_bin",
                "t32perf_sha256",
                "artifact_root",
                "stack_evidence_root",
                "min_free_bytes",
            },
            "stack": {"capture_request", "capture_request_sha256"},
            "driver": {"commands"},
        }
        for name, names in fields.items():
            if set(raw[name]) != names:
                raise HilConfigurationError(f"{name} fields are invalid")
        try:
            board_id = _nonempty_string(raw["board"]["id"], "board.id")
            family = _nonempty_string(raw["board"]["mcu_family"], "board.mcu_family")
            cpu = _nonempty_string(raw["board"]["expected_cpu"], "board.expected_cpu")
            software = _nonempty_string(raw["trace32"]["software"], "trace32.software")
            probe_id = _nonempty_string(raw["trace32"]["probe_id"], "trace32.probe_id")
            host = _nonempty_string(raw["endpoint"]["host"], "endpoint.host").lower()
            port = _configuration_integer(raw["endpoint"]["port"], "endpoint.port")
            protocol = _nonempty_string(
                raw["endpoint"]["protocol"], "endpoint.protocol"
            ).upper()
            endpoint = _nonempty_string(
                raw["endpoint"]["expected_fingerprint"], "endpoint.expected_fingerprint"
            )
            probe = _nonempty_string(
                raw["endpoint"]["expected_probe_fingerprint"],
                "endpoint.expected_probe_fingerprint",
            )
            request_digest = _nonempty_string(
                raw["stack"]["capture_request_sha256"], "stack.capture_request_sha256"
            )
            free = _configuration_integer(
                raw["host"]["min_free_bytes"], "host.min_free_bytes"
            )
            t32perf_digest = _nonempty_string(
                raw["host"]["t32perf_sha256"], "host.t32perf_sha256"
            )
        except (KeyError, TypeError, ValueError) as error:
            raise HilConfigurationError(
                f"missing or invalid stack board field: {error}"
            ) from error
        if (
            protocol != "TCP"
            or host not in {"localhost", "127.0.0.1", "::1"}
            or not 1 <= port <= 65535
        ):
            raise HilConfigurationError("endpoint must be a loopback TCP endpoint")
        if free < 0 or any(
            _HEX.fullmatch(value) is None
            for value in (endpoint, probe, request_digest, t32perf_digest)
        ):
            raise HilConfigurationError(
                "stack board contains an invalid digest or free-space value"
            )
        if endpoint != endpoint_fingerprint(host, port, protocol, software, probe):
            raise HilConfigurationError(
                "endpoint.expected_fingerprint does not bind endpoint identity"
            )
        base = resolved.parent
        artifact_root = _resolve_config_path(base, raw["host"]["artifact_root"])
        evidence_root = _resolve_config_path(base, raw["host"]["stack_evidence_root"])
        if _paths_overlap(artifact_root, evidence_root):
            raise HilConfigurationError(
                "host.artifact_root and host.stack_evidence_root must not overlap"
            )
        request = _resolve_plain_config_file(
            base, raw["stack"]["capture_request"], "stack.capture_request"
        )
        try:
            payload, _ = _read_plain_json_snapshot(
                request, "stack.capture_request", request_digest
            )
            _request(_strict_json_loads(payload.decode("utf-8")))
        except (OSError, UnicodeDecodeError, ValueError) as error:
            raise HilConfigurationError(
                f"stack.capture_request is invalid: {error}"
            ) from error
        t32perf_bin = _resolve_and_hash_t32perf_binary(
            base, raw["host"]["t32perf_bin"], t32perf_digest
        )
        commands_raw = raw["driver"]["commands"]
        if not isinstance(commands_raw, dict) or set(commands_raw) != _OPERATIONS:
            raise HilConfigurationError(
                "driver.commands must contain exactly seven stack operations"
            )
        commands: dict[str, tuple[str, ...]] = {}
        required = {
            "endpoint_host",
            "endpoint_port",
            "endpoint_protocol",
            "endpoint_fingerprint",
            "artifact_root",
            "t32perf_bin",
        }
        for operation, argv in commands_raw.items():
            if not isinstance(argv, list) or not argv:
                raise HilConfigurationError(f"driver.commands.{operation} must be argv")
            commands[operation] = tuple(
                _nonempty_string(value, f"driver.commands.{operation}")
                for value in argv
            )
            used = {
                field
                for arg in commands[operation]
                for _, field, _, _ in string.Formatter().parse(arg)
                if field
            }
            if not required <= used:
                raise HilConfigurationError(
                    f"driver.commands.{operation} omits a pinned endpoint argument"
                )
        return cls(
            resolved,
            board_id,
            family,
            cpu,
            _resolve_config_path(base, raw["board"]["lock_file"]),
            software,
            probe_id,
            host,
            port,
            protocol,
            endpoint,
            probe,
            t32perf_bin,
            t32perf_digest,
            artifact_root,
            evidence_root,
            free,
            request,
            request_digest,
            commands,
        )

    def command(self, operation: str, **values: object) -> list[str]:
        if operation not in self.commands:
            raise HilConfigurationError(
                f"stack driver command is not configured: {operation}"
            )
        # Re-check on every phase: the stored path is only safe to hand to the
        # bridge while its exact Host image remains pinned.
        _resolve_and_hash_t32perf_binary(
            self.path.parent, self.t32perf_bin, self.t32perf_sha256
        )
        fixed = {
            "artifact_root": str(self.artifact_root),
            "board_id": self.board_id,
            "config": str(self.path),
            "endpoint_fingerprint": self.endpoint_fingerprint,
            "endpoint_host": self.endpoint_host,
            "endpoint_port": str(self.endpoint_port),
            "endpoint_protocol": self.endpoint_protocol,
            "expected_cpu": self.expected_cpu,
            "t32perf_bin": str(self.t32perf_bin),
            "trace32_software": self.trace32_software,
        }
        if fixed.keys() & values.keys():
            raise HilConfigurationError(
                "reserved command placeholder cannot be overridden"
            )
        permitted = {**fixed, **{key: str(value) for key, value in values.items()}}
        consumed: set[str] = set()
        output = []
        for argument in self.commands[operation]:
            for _, field, _, _ in string.Formatter().parse(argument):
                if field is not None:
                    if field not in permitted:
                        raise HilConfigurationError(
                            f"unknown stack driver placeholder: {field}"
                        )
                    consumed.add(field)
            output.append(argument.format_map(permitted))
        if set(values) - consumed:
            raise HilConfigurationError(
                "stack driver command ignores supplied placeholders"
            )
        return output


def preflight_stack_output(
    board: StackBoardConfig, *, access: OutputAccess | None = None
) -> None:
    output = LocalOutputAccess() if access is None else access
    for label, root in (
        ("artifact", board.artifact_root),
        ("stack evidence", board.evidence_root),
    ):
        try:
            if output.available_bytes(root) < board.min_free_bytes:
                raise HilOutputError(f"{label} output has insufficient free bytes")
            output.probe_write(root)
        except HilOutputError:
            raise
        except OSError as error:
            raise HilOutputError(f"{label} output is not usable: {error}") from error


def selected_stack_board() -> StackBoardConfig | None:
    value = os.environ.get("T32PERF_STACK_HIL_BOARD")
    return None if not value else StackBoardConfig.load(Path(value))
