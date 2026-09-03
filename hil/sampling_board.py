"""Independent, strictly bounded configuration for generic PC-sampling HIL.

This intentionally does not reuse the target-adapter board contract.  Generic
sampling needs a live TRACE32 endpoint and a closed Host/sidecar chain, not a
chip-specific adapter profile or fault-injection manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
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
    _validate_sampling_capture_request,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAMPLING_OPERATIONS = frozenset(
    {
        "sampling_prepare",
        "sampling_capabilities",
        "sampling_capture",
        "sampling_ingest",
        "sampling_analyze",
        "sampling_summary",
        "sampling_render",
    }
)


def endpoint_fingerprint(
    host: str, port: int, protocol: str, software: str, probe_fingerprint: str
) -> str:
    """Return the sidecar-v1 identity for a loopback TCP endpoint."""

    canonical = json.dumps(
        [
            "t32perf.endpoint-fingerprint/v2",
            protocol.upper(),
            host.strip().lower(),
            port,
            software.strip(),
            probe_fingerprint,
        ],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class SamplingBoardConfig:
    """One independently pinned generic PC-sampling HIL target."""

    path: Path
    board_id: str
    mcu_family: str
    expected_cpu: str
    covered_cores: tuple[int, ...]
    lock_file: Path
    trace32_release: str
    trace32_build: int
    validated_trace32_builds: tuple[int, ...]
    trace32_software: str
    probe_id: str
    endpoint_host: str
    endpoint_port: int
    endpoint_protocol: str
    endpoint_fingerprint: str
    probe_fingerprint: str
    t32perf_bin: Path
    artifact_root: Path
    sampling_evidence_root: Path
    min_free_bytes: int
    sampling_capture_request: Path
    sampling_capture_request_sha256: str
    commands: dict[str, tuple[str, ...]]

    @classmethod
    def load(cls, path: Path) -> Self:
        resolved = path.resolve(strict=True)
        with resolved.open("rb") as stream:
            raw = tomllib.load(stream)
        if set(raw) != {"board", "trace32", "endpoint", "host", "sampling", "driver"}:
            raise HilConfigurationError(
                "sampling board configuration table set is invalid"
            )
        try:
            board = raw["board"]
            trace32 = raw["trace32"]
            endpoint = raw["endpoint"]
            host = raw["host"]
            sampling = raw["sampling"]
            driver = raw["driver"]
            if not all(isinstance(value, dict) for value in raw.values()):
                raise TypeError("top-level tables")
            board_id = _nonempty_string(board["id"], "board.id")
            mcu_family = _nonempty_string(board["mcu_family"], "board.mcu_family")
            expected_cpu = _nonempty_string(board["expected_cpu"], "board.expected_cpu")
            trace32_release = _nonempty_string(trace32["release"], "trace32.release")
            trace32_build = _configuration_integer(trace32["build"], "trace32.build")
            trace32_software = _nonempty_string(trace32["software"], "trace32.software")
            probe_id = _nonempty_string(trace32["probe_id"], "trace32.probe_id")
            endpoint_host = _nonempty_string(endpoint["host"], "endpoint.host").lower()
            endpoint_port = _configuration_integer(endpoint["port"], "endpoint.port")
            endpoint_protocol = _nonempty_string(
                endpoint["protocol"], "endpoint.protocol"
            ).upper()
            configured_fingerprint = _nonempty_string(
                endpoint["expected_fingerprint"], "endpoint.expected_fingerprint"
            )
            configured_probe_fingerprint = _nonempty_string(
                endpoint["expected_probe_fingerprint"],
                "endpoint.expected_probe_fingerprint",
            )
            min_free_bytes = _configuration_integer(
                host["min_free_bytes"], "host.min_free_bytes"
            )
            request_sha256 = _nonempty_string(
                sampling["capture_request_sha256"], "sampling.capture_request_sha256"
            )
            commands_raw = driver["commands"]
        except (KeyError, TypeError, ValueError) as error:
            raise HilConfigurationError(
                f"missing or invalid sampling board field: {error}"
            ) from error
        expected_tables = {
            "board": {"id", "mcu_family", "expected_cpu", "covered_cores", "lock_file"},
            "trace32": {"release", "build", "validated_builds", "software", "probe_id"},
            "endpoint": {
                "host",
                "port",
                "protocol",
                "expected_fingerprint",
                "expected_probe_fingerprint",
            },
            "host": {
                "t32perf_bin",
                "artifact_root",
                "sampling_evidence_root",
                "min_free_bytes",
            },
            "sampling": {"capture_request", "capture_request_sha256"},
            "driver": {"commands"},
        }
        for name, expected in expected_tables.items():
            actual = set(raw[name])
            if actual != expected:
                raise HilConfigurationError(
                    f"{name} fields are invalid: missing={sorted(expected - actual)}, "
                    f"unknown={sorted(actual - expected)}"
                )
        if endpoint_protocol != "TCP" or endpoint_host not in {
            "localhost",
            "127.0.0.1",
            "::1",
        }:
            raise HilConfigurationError("endpoint must be a loopback TCP endpoint")
        if not 1 <= endpoint_port <= 65535:
            raise HilConfigurationError("endpoint.port must be in 1..65535")
        if trace32_build <= 0:
            raise HilConfigurationError("trace32.build must be positive")
        if not (
            trace32_software.startswith(f"{trace32_release}.")
            and trace32_software.endswith(f"+{trace32_build}")
        ):
            raise HilConfigurationError(
                "trace32.software must agree with trace32.release and trace32.build"
            )
        if min_free_bytes < 0:
            raise HilConfigurationError("host.min_free_bytes must be non-negative")
        if _SHA256.fullmatch(configured_fingerprint) is None:
            raise HilConfigurationError(
                "endpoint.expected_fingerprint must be 64 lowercase hex characters"
            )
        if _SHA256.fullmatch(configured_probe_fingerprint) is None:
            raise HilConfigurationError(
                "endpoint.expected_probe_fingerprint must be 64 lowercase hex characters"
            )
        if _SHA256.fullmatch(request_sha256) is None:
            raise HilConfigurationError(
                "sampling.capture_request_sha256 must be 64 lowercase hex characters"
            )
        expected_fingerprint = endpoint_fingerprint(
            endpoint_host,
            endpoint_port,
            endpoint_protocol,
            trace32_software,
            configured_probe_fingerprint,
        )
        if configured_fingerprint != expected_fingerprint:
            raise HilConfigurationError(
                "endpoint.expected_fingerprint must bind canonical endpoint and trace32.software"
            )
        builds = trace32.get("validated_builds")
        if (
            not isinstance(builds, list)
            or not builds
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
                for value in builds
            )
            or len(set(builds)) != len(builds)
        ):
            raise HilConfigurationError(
                "trace32.validated_builds must be unique positive integers"
            )
        validated_builds = tuple(builds)
        if trace32_build not in validated_builds:
            raise HilConfigurationError(
                "TRACE32 build is not in trace32.validated_builds"
            )
        cores = board.get("covered_cores")
        if (
            not isinstance(cores, list)
            or len(cores) != 1
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in cores
            )
        ):
            raise HilConfigurationError(
                "board.covered_cores must contain exactly one non-negative core"
            )
        base = resolved.parent
        lock_file = _resolve_config_path(base, board["lock_file"])
        t32perf_bin = _resolve_config_path(base, host["t32perf_bin"])
        artifact_root = _resolve_config_path(base, host["artifact_root"])
        evidence_root = _resolve_config_path(base, host["sampling_evidence_root"])
        request = _resolve_plain_config_file(
            base, sampling["capture_request"], "sampling.capture_request"
        )
        if _paths_overlap(artifact_root, evidence_root):
            raise HilConfigurationError(
                "host.artifact_root and host.sampling_evidence_root must not overlap"
            )
        try:
            request_bytes, _ = _read_plain_json_snapshot(
                request, "sampling.capture_request", request_sha256
            )
            request_document = _strict_json_loads(request_bytes.decode("utf-8"))
        except (OSError, UnicodeDecodeError, ValueError) as error:
            raise HilConfigurationError(
                f"sampling.capture_request is invalid: {error}"
            ) from error
        _validate_sampling_capture_request(request_document)
        if request_document["core_id"] != cores[0]:
            raise HilConfigurationError(
                "sampling.capture_request core_id must equal board.covered_cores[0]"
            )
        if (
            not isinstance(commands_raw, dict)
            or set(commands_raw) != _SAMPLING_OPERATIONS
        ):
            raise HilConfigurationError(
                "driver.commands must contain exactly the seven sampling operations"
            )
        commands: dict[str, tuple[str, ...]] = {}
        for operation, argv in commands_raw.items():
            if not isinstance(argv, list) or not argv:
                raise HilConfigurationError(
                    f"driver.commands.{operation} must be a non-empty argv array"
                )
            commands[operation] = tuple(
                _nonempty_string(value, f"driver.commands.{operation}")
                for value in argv
            )
            fields = [
                field_name
                for argument in commands[operation]
                for _, field_name, _, _ in string.Formatter().parse(argument)
                if field_name is not None
            ]
            for placeholder in (
                "endpoint_host",
                "endpoint_port",
                "endpoint_protocol",
                "endpoint_fingerprint",
                "artifact_root",
                "t32perf_bin",
            ):
                if fields.count(placeholder) != 1:
                    raise HilConfigurationError(
                        f"driver.commands.{operation} must use {placeholder} exactly once"
                    )
        return cls(
            path=resolved,
            board_id=board_id,
            mcu_family=mcu_family,
            expected_cpu=expected_cpu,
            covered_cores=tuple(cores),
            lock_file=lock_file,
            trace32_release=trace32_release,
            trace32_build=trace32_build,
            validated_trace32_builds=validated_builds,
            trace32_software=trace32_software,
            probe_id=probe_id,
            endpoint_host=endpoint_host,
            endpoint_port=endpoint_port,
            endpoint_protocol=endpoint_protocol,
            endpoint_fingerprint=configured_fingerprint,
            probe_fingerprint=configured_probe_fingerprint,
            t32perf_bin=t32perf_bin,
            artifact_root=artifact_root,
            sampling_evidence_root=evidence_root,
            min_free_bytes=min_free_bytes,
            sampling_capture_request=request,
            sampling_capture_request_sha256=request_sha256,
            commands=commands,
        )

    def command(self, operation: str, **values: object) -> list[str]:
        """Expand a closed argv template; supplied values must be consumed."""

        try:
            template = self.commands[operation]
        except KeyError as error:
            raise HilConfigurationError(
                f"driver command is not configured: {operation}"
            ) from error
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
        overlap = fixed.keys() & values.keys()
        if overlap:
            raise HilConfigurationError(
                f"reserved command placeholder cannot be overridden: {min(overlap)}"
            )
        if (
            "request" in values
            and Path(str(values["request"])).resolve() != self.sampling_capture_request
        ):
            raise HilConfigurationError(
                "sampling_prepare request must be the configured capture request"
            )
        allowed = {**fixed, **{key: str(value) for key, value in values.items()}}
        used: set[str] = set()
        formatter = string.Formatter()
        result: list[str] = []
        for argument in template:
            for _, field_name, _, _ in formatter.parse(argument):
                if field_name is None:
                    continue
                if field_name not in allowed:
                    raise HilConfigurationError(
                        f"unknown placeholder {field_name!r} in driver.commands.{operation}"
                    )
                if field_name in values:
                    used.add(field_name)
            result.append(argument.format_map(allowed))
        unused = sorted(set(values) - used)
        if unused:
            raise HilConfigurationError(
                f"driver.commands.{operation} ignores supplied placeholders: {unused}"
            )
        return result


def preflight_sampling_output(
    board: SamplingBoardConfig, *, access: OutputAccess | None = None
) -> None:
    """Check both generic-sampling output roots before the probe is contacted."""

    output = LocalOutputAccess() if access is None else access
    for label, root in (
        ("artifact", board.artifact_root),
        ("sampling evidence", board.sampling_evidence_root),
    ):
        try:
            available = output.available_bytes(root)
            if (
                isinstance(available, bool)
                or not isinstance(available, int)
                or available < 0
            ):
                raise HilOutputError(
                    "output access returned an invalid available-byte count"
                )
            if available < board.min_free_bytes:
                raise HilOutputError(
                    f"{label} output has {available} free bytes; requires at least {board.min_free_bytes}"
                )
            output.probe_write(root)
        except HilOutputError:
            raise
        except OSError as error:
            raise HilOutputError(
                f"{label} output is not usable: {root}: {error}"
            ) from error


def selected_sampling_board() -> SamplingBoardConfig | None:
    """Load the independent sampling board selected by its explicit environment key."""

    value = os.environ.get("T32PERF_SAMPLING_HIL_BOARD")
    return None if not value else SamplingBoardConfig.load(Path(value))
