"""Hardware-in-the-loop support for T32Perf.

The harness never invokes a shell. Board-specific commands are explicit argv
arrays in TOML, which keeps paths and user-provided values out of shell syntax.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import stat
import string
import subprocess
import sys
import tempfile
import threading
import tomllib
from collections.abc import Iterator, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from pathlib import Path
from typing import Any, BinaryIO, Protocol, Self

from target_adapter_recovery import (
    RecoveryEvidenceExpectation,
    RecoveryEvidenceReservation,
    TargetAdapterFailureBinding,
    TargetAdapterRecoveryEvidence,
    load_target_adapter_recovery_evidence,
    reserve_target_adapter_recovery_evidence,
)

SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
MANIFEST_SCHEMA = "t32perf.manifest/v1"
HEALTH_ARTIFACT_ID = "health"
HOTSPOTS_ARTIFACT_ID = "hotspots"
SUMMARY_ARTIFACT_ID = "analysis-summary"
OBSERVATIONS_ARTIFACT_ID = "observations"
DERIVED_ARTIFACT_ID = "derived"
MAX_NATIVE_FUNCTION_ACTIVATIONS = 4_096
MAX_NATIVE_TIMELINE_EVENTS = 16_384
JSON_ARTIFACT_LIMIT_BYTES = 64 * 1024 * 1024
NDJSON_LINE_LIMIT_BYTES = 8 * 1024 * 1024
TRACE_OVERFLOW_ISSUE_CODE = "trace_overflow"
FLOW_ERROR_ISSUE_CODE = "flow_error"
ELF_MISMATCH_ISSUE_CODE = "elf_mismatch"
SAMPLING_BUFFER_FULL_ISSUE_CODE = "sampling_buffer_full"
INITIAL_TARGET_STATES = frozenset({"running", "halted"})
HIL_EVIDENCE_SCHEMA = "t32perf.hil-evidence/v1"
HIL_EVIDENCE_OUTPUT_ENV = "T32PERF_HIL_EVIDENCE_OUTPUT"
HIL_EVIDENCE_LIMIT_BYTES = 16 * 1024 * 1024
COMMAND_STDOUT_LIMIT_BYTES = 1024 * 1024
COMMAND_STDERR_LIMIT_BYTES = 1024 * 1024
COMMAND_PIPE_JOIN_TIMEOUT_SECONDS = 5.0
CONFIG_JSON_LIMIT_BYTES = 1024 * 1024
RECOVERY_FAULT_CONTRACTS = {
    "trace32_disconnect_capture": ("perf_stop", "trace32_disconnect"),
    "driver_disconnect_capture": ("perf_export", "driver_disconnect"),
    "cmm_abort_capture": ("perf_start", "cmm_abort"),
}
FAULT_SCENARIOS_SCHEMA = "t32perf.trace32-fault-scenarios/v1"
TARGET_ADAPTER_PROFILE_SCHEMA = "t32perf.target-adapter-profile/v1"
FAULT_SCENARIO_SUPPORTS = frozenset({"candidate", "qualified", "unsupported"})
RECOVERY_FAULT_SCENARIOS = frozenset(
    {"trace32_disconnect", "driver_disconnect", "cmm_abort"}
)
HEALTH_FAULT_SCENARIOS = frozenset(
    {
        "sampling_buffer_full",
        "trace_overflow",
        "flow_error",
        "sampling_unexpected_stop",
        "elf_mismatch",
    }
)
FAULT_SCENARIO_BINDINGS = {
    "sampling_buffer_full": ("sampling_buffer_full_capture", "sampling_buffer_full"),
    "trace32_disconnect": (
        "trace32_disconnect_capture",
        "trace32_disconnect_recovery",
    ),
    "driver_disconnect": (
        "driver_disconnect_capture",
        "driver_disconnect_recovery",
    ),
    "cmm_abort": ("cmm_abort_capture", "cmm_abort_recovery"),
    "trace_overflow": ("trace_overflow_capture", "trace_overflow"),
    "flow_error": ("flow_error_capture", "flow_error"),
    "sampling_unexpected_stop": (
        "sampling_unexpected_stop_capture",
        "sampling_unexpected_stop",
    ),
    "elf_mismatch": ("elf_mismatch_capture", "elf_mismatch"),
}


@dataclass(frozen=True)
class FaultScenario:
    """One adapter-owned fault scenario pinned by the board configuration."""

    name: str
    support: str
    reason: str | None
    receipt_scenario: str

    @property
    def command_operation(self) -> str:
        """Return the closed HIL command name for an executable scenario."""

        return FAULT_SCENARIO_BINDINGS[self.name][0]

    @property
    def is_executable(self) -> bool:
        """Whether this scenario may request a board-driver command."""

        return self.support in {"candidate", "qualified", "recovery"}


@dataclass(frozen=True)
class FaultScenariosManifest:
    """One exact, bounded adapter manifest snapshot."""

    adapter_id: str
    sha256: str
    scenarios: dict[str, FaultScenario]


@dataclass(frozen=True)
class AdapterProfileBinding:
    """Exact profile snapshot properties that bind HIL fault evidence."""

    adapter_id: str
    sha256: str
    canonical_sha256: str
    bundle_sha256: str


class HilConfigurationError(ValueError):
    """The selected board configuration is incomplete or inconsistent."""


class HilOutputError(RuntimeError):
    """The host output location cannot safely accept a hardware capture."""


class DuplicateJsonKeyError(ValueError):
    """A trusted JSON object repeated one member name."""


@dataclass(frozen=True)
class BoardConfig:
    """Validated, immutable board configuration."""

    path: Path
    board_id: str
    lock_file: Path
    artifact_root: Path
    recovery_evidence_root: Path
    sampling_evidence_root: Path | None
    sampling_capture_request: Path | None
    sampling_capture_request_sha256: str | None
    t32perf_bin: Path
    trace32_release: str
    trace32_build: int
    probe_id: str
    architecture_package: str
    license_features: tuple[str, ...]
    capability_evidence: Path
    capability_evidence_sha256: str
    target_adapter_profile_sha256: str
    target_adapter_profile_path: Path
    target_adapter_profile_file_sha256: str
    target_adapter_id: str
    target_adapter_bundle_sha256: str
    fault_scenarios_path: Path
    fault_scenarios_sha256: str
    fault_scenarios: dict[str, FaultScenario]
    trace_routing: tuple[str, ...]
    tick_ns: float
    mcu_family: str
    rtos: str | None
    covered_cores: tuple[int, ...]
    capture_modes: tuple[str, ...]
    validated_trace32_builds: tuple[int, ...]
    min_free_bytes: int
    commands: dict[str, tuple[str, ...]]

    @classmethod
    def load(cls, path: Path) -> BoardConfig:
        resolved = path.resolve(strict=True)
        with resolved.open("rb") as stream:
            raw = tomllib.load(stream)

        try:
            board = raw["board"]
            trace32 = raw["trace32"]
            host = raw["host"]
            driver = raw["driver"]
            commands_raw = driver["commands"]
            board_id = _nonempty_string(board["id"], "board.id")
            trace32_release = _nonempty_string(trace32["release"], "trace32.release")
            trace32_build = _configuration_integer(trace32["build"], "trace32.build")
            probe_id = _nonempty_string(trace32["probe_id"], "trace32.probe_id")
            architecture_package = _nonempty_string(
                trace32["architecture_package"], "trace32.architecture_package"
            )
            capability_evidence_sha256 = _nonempty_string(
                trace32["capability_evidence_sha256"],
                "trace32.capability_evidence_sha256",
            )
            target_adapter_profile_sha256 = _nonempty_string(
                trace32["target_adapter_profile_sha256"],
                "trace32.target_adapter_profile_sha256",
            )
            target_adapter_profile_value = trace32["target_adapter_profile"]
            target_adapter_profile_file_sha256 = _nonempty_string(
                trace32["target_adapter_profile_file_sha256"],
                "trace32.target_adapter_profile_file_sha256",
            )
            fault_scenarios_sha256 = _nonempty_string(
                trace32["fault_scenarios_sha256"],
                "trace32.fault_scenarios_sha256",
            )
            fault_scenarios_value = trace32["fault_scenarios"]
            tick_ns = _configuration_number(trace32["tick_ns"], "trace32.tick_ns")
            mcu_family = _nonempty_string(board["mcu_family"], "board.mcu_family")
            min_free_bytes = _configuration_integer(
                host["min_free_bytes"], "host.min_free_bytes"
            )
        except (KeyError, TypeError, ValueError) as error:
            raise HilConfigurationError(
                f"missing or invalid required field: {error}"
            ) from error

        base = resolved.parent
        lock_file = _resolve_config_path(base, board["lock_file"])
        artifact_root = _resolve_config_path(base, host["artifact_root"])
        recovery_evidence_root = _resolve_config_path(
            base, host["recovery_evidence_root"]
        )
        sampling = raw.get("sampling")
        sampling_capture_request: Path | None = None
        sampling_capture_request_sha256: str | None = None
        sampling_evidence_root: Path | None = None
        if sampling is not None:
            if not isinstance(sampling, dict):
                raise HilConfigurationError("sampling must be a table")
            try:
                request_value = sampling["capture_request"]
                sampling_capture_request_sha256 = _nonempty_string(
                    sampling["capture_request_sha256"],
                    "sampling.capture_request_sha256",
                )
                evidence_root_value = host["sampling_evidence_root"]
            except (KeyError, TypeError, ValueError) as error:
                raise HilConfigurationError(
                    f"missing or invalid sampling configuration: {error}"
                ) from error
            if re.fullmatch(r"[0-9a-f]{64}", sampling_capture_request_sha256) is None:
                raise HilConfigurationError(
                    "sampling.capture_request_sha256 must be 64 lowercase hex characters"
                )
            sampling_capture_request = _resolve_plain_config_file(
                base, request_value, "sampling.capture_request"
            )
            sampling_evidence_root = _resolve_config_path(base, evidence_root_value)
            try:
                actual_request_sha256 = _sha256_file(sampling_capture_request)
            except OSError as error:
                raise HilConfigurationError(
                    f"cannot hash sampling.capture_request: {error}"
                ) from error
            if actual_request_sha256 != sampling_capture_request_sha256:
                raise HilConfigurationError(
                    "sampling.capture_request_sha256 does not match the request file"
                )
            request_snapshot = _read_plain_json_snapshot(
                sampling_capture_request,
                "sampling.capture_request",
                sampling_capture_request_sha256,
            )
            try:
                request_document = _strict_json_loads(
                    request_snapshot[0].decode("utf-8")
                )
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                DuplicateJsonKeyError,
            ) as error:
                raise HilConfigurationError(
                    f"sampling.capture_request is invalid JSON: {error}"
                ) from error
            _validate_sampling_capture_request(request_document)
        t32perf_bin = _resolve_config_path(base, host["t32perf_bin"])
        capability_evidence = _resolve_plain_config_file(
            base,
            trace32["capability_evidence"],
            "trace32.capability_evidence",
        )
        fault_scenarios_path = _resolve_plain_config_file(
            base,
            fault_scenarios_value,
            "trace32.fault_scenarios",
        )
        target_adapter_profile_path = _resolve_plain_config_file(
            base,
            target_adapter_profile_value,
            "trace32.target_adapter_profile",
        )
        if re.fullmatch(r"[0-9a-f]{64}", capability_evidence_sha256) is None:
            raise HilConfigurationError(
                "trace32.capability_evidence_sha256 must be 64 lowercase hex characters"
            )
        if re.fullmatch(r"[0-9a-f]{64}", target_adapter_profile_sha256) is None:
            raise HilConfigurationError(
                "trace32.target_adapter_profile_sha256 must be 64 lowercase hex "
                "characters"
            )
        if re.fullmatch(r"[0-9a-f]{64}", fault_scenarios_sha256) is None:
            raise HilConfigurationError(
                "trace32.fault_scenarios_sha256 must be 64 lowercase hex characters"
            )
        if re.fullmatch(r"[0-9a-f]{64}", target_adapter_profile_file_sha256) is None:
            raise HilConfigurationError(
                "trace32.target_adapter_profile_file_sha256 must be 64 lowercase "
                "hex characters"
            )
        if _paths_overlap(artifact_root, recovery_evidence_root):
            raise HilConfigurationError(
                "host.recovery_evidence_root must be independent from "
                "host.artifact_root"
            )
        if sampling_evidence_root is not None and (
            _paths_overlap(artifact_root, sampling_evidence_root)
            or _paths_overlap(recovery_evidence_root, sampling_evidence_root)
        ):
            raise HilConfigurationError(
                "host.sampling_evidence_root must be independent from artifact and recovery evidence roots"
            )
        try:
            actual_capability_sha256 = _sha256_file(capability_evidence)
        except OSError as error:
            raise HilConfigurationError(
                f"cannot hash trace32.capability_evidence: {error}"
            ) from error
        if actual_capability_sha256 != capability_evidence_sha256:
            raise HilConfigurationError(
                "trace32.capability_evidence_sha256 does not match the evidence file"
            )
        fault_manifest = _load_fault_scenarios_manifest(
            _read_plain_json_snapshot(
                fault_scenarios_path,
                "trace32.fault_scenarios",
                fault_scenarios_sha256,
            )
        )
        profile = _load_target_adapter_profile(
            _read_plain_json_snapshot(
                target_adapter_profile_path,
                "trace32.target_adapter_profile",
                target_adapter_profile_file_sha256,
            ),
            expected_release=trace32_release,
            expected_build=trace32_build,
            expected_architecture=architecture_package,
        )
        if profile.adapter_id != fault_manifest.adapter_id:
            raise HilConfigurationError(
                "fault-scenarios adapter_id does not match target adapter profile"
            )
        if profile.canonical_sha256 != target_adapter_profile_sha256:
            raise HilConfigurationError(
                "trace32.target_adapter_profile_sha256 does not match Rust canonical "
                "profile identity"
            )
        license_features = _unique_nonempty_strings(
            trace32.get("license_features"), "trace32.license_features"
        )
        trace_routing = _unique_nonempty_strings(
            trace32.get("trace_routing"), "trace32.trace_routing"
        )
        rtos_value = board.get("rtos")
        rtos = (
            None if rtos_value is None else _nonempty_string(rtos_value, "board.rtos")
        )

        core_values = board.get("covered_cores", [])
        if not isinstance(core_values, list) or not core_values:
            raise HilConfigurationError("board.covered_cores must be a non-empty array")
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in core_values
        ):
            raise HilConfigurationError("board.covered_cores must contain integers")
        covered_cores = tuple(core_values)
        if any(core < 0 for core in covered_cores) or len(set(covered_cores)) != len(
            covered_cores
        ):
            raise HilConfigurationError(
                "board.covered_cores must contain unique non-negative IDs"
            )

        mode_values = board.get("capture_modes")
        if not isinstance(mode_values, list) or not mode_values:
            raise HilConfigurationError("board.capture_modes must be a non-empty array")
        capture_modes = tuple(
            _nonempty_string(value, "board.capture_modes") for value in mode_values
        )
        if len(set(capture_modes)) != len(capture_modes):
            raise HilConfigurationError(
                "board.capture_modes must contain unique values"
            )

        validated_build_values = trace32.get("validated_builds")
        if not isinstance(validated_build_values, list) or not validated_build_values:
            raise HilConfigurationError(
                "trace32.validated_builds must be a non-empty array"
            )
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in validated_build_values
        ):
            raise HilConfigurationError(
                "trace32.validated_builds must contain integers"
            )
        validated_trace32_builds = tuple(validated_build_values)
        if any(build <= 0 for build in validated_trace32_builds) or len(
            set(validated_trace32_builds)
        ) != len(validated_trace32_builds):
            raise HilConfigurationError(
                "trace32.validated_builds must contain unique positive builds"
            )

        if not isinstance(commands_raw, dict):
            raise HilConfigurationError("driver.commands must be a table")
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
        for scenario in fault_manifest.scenarios.values():
            configured = scenario.command_operation in commands
            if scenario.is_executable and not configured:
                raise HilConfigurationError(
                    "executable adapter fault scenario requires driver "
                    f"command: {scenario.command_operation}"
                )
            if not scenario.is_executable and configured:
                raise HilConfigurationError(
                    "unsupported adapter fault scenario must not configure driver "
                    f"command: {scenario.command_operation}"
                )
        if sampling_capture_request is not None:
            required_sampling_commands = {
                "sampling_prepare",
                "sampling_capabilities",
                "sampling_capture",
                "sampling_ingest",
                "sampling_analyze",
                "sampling_summary",
                "sampling_render",
            }
            missing_sampling_commands = required_sampling_commands - set(commands)
            if missing_sampling_commands:
                raise HilConfigurationError(
                    "[sampling] requires driver commands: "
                    f"{sorted(missing_sampling_commands)}"
                )

        if trace32_build <= 0:
            raise HilConfigurationError("trace32.build must be positive")
        if trace32_build not in validated_trace32_builds:
            raise HilConfigurationError(
                f"TRACE32 build {trace32_build} is not in trace32.validated_builds"
            )
        if not math.isfinite(tick_ns) or tick_ns <= 0:
            raise HilConfigurationError("trace32.tick_ns must be finite and positive")
        if min_free_bytes < 0:
            raise HilConfigurationError("host.min_free_bytes must be non-negative")

        return cls(
            path=resolved,
            board_id=board_id,
            lock_file=lock_file,
            artifact_root=artifact_root,
            recovery_evidence_root=recovery_evidence_root,
            sampling_evidence_root=sampling_evidence_root,
            sampling_capture_request=sampling_capture_request,
            sampling_capture_request_sha256=sampling_capture_request_sha256,
            t32perf_bin=t32perf_bin,
            trace32_release=trace32_release,
            trace32_build=trace32_build,
            probe_id=probe_id,
            architecture_package=architecture_package,
            license_features=license_features,
            capability_evidence=capability_evidence,
            capability_evidence_sha256=capability_evidence_sha256,
            target_adapter_profile_sha256=target_adapter_profile_sha256,
            target_adapter_profile_path=target_adapter_profile_path,
            target_adapter_profile_file_sha256=target_adapter_profile_file_sha256,
            target_adapter_id=profile.adapter_id,
            target_adapter_bundle_sha256=profile.bundle_sha256,
            fault_scenarios_path=fault_scenarios_path,
            fault_scenarios_sha256=fault_scenarios_sha256,
            fault_scenarios=fault_manifest.scenarios,
            trace_routing=trace_routing,
            tick_ns=tick_ns,
            mcu_family=mcu_family,
            rtos=rtos,
            covered_cores=covered_cores,
            capture_modes=capture_modes,
            validated_trace32_builds=validated_trace32_builds,
            min_free_bytes=min_free_bytes,
            commands=commands,
        )

    def fault_command(self, scenario_name: str, **values: object) -> list[str]:
        """Expand an exact adapter-declared executable fault command.

        Unsupported scenarios are rejected locally; their presence in the adapter
        contract is evidence of an explicit non-capability, not a request to run a
        generic driver command.
        """

        try:
            scenario = self.fault_scenarios[scenario_name]
        except KeyError as error:
            raise HilConfigurationError(
                f"adapter fault scenario is not declared: {scenario_name}"
            ) from error
        if not scenario.is_executable:
            reason = f": {scenario.reason}" if scenario.reason is not None else ""
            raise HilConfigurationError(
                f"adapter fault scenario is explicitly unsupported: {scenario_name}"
                f"{reason}"
            )
        return self.command(scenario.command_operation, **values)

    def command(self, operation: str, **values: object) -> list[str]:
        """Expand a configured argv template without invoking a shell."""

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
            "target_adapter_profile_sha256": self.target_adapter_profile_sha256,
        }
        overlap = fixed.keys() & values.keys()
        if overlap:
            raise HilConfigurationError(
                f"reserved command placeholder cannot be overridden: {min(overlap)}"
            )
        allowed = {**fixed, **{key: str(value) for key, value in values.items()}}
        result: list[str] = []
        used_values: set[str] = set()
        formatter = string.Formatter()
        for argument in template:
            for _, field_name, _, _ in formatter.parse(argument):
                if field_name is None:
                    continue
                if field_name not in allowed:
                    raise HilConfigurationError(
                        f"unknown placeholder {field_name!r} in "
                        f"driver.commands.{operation}"
                    )
                if field_name in values:
                    used_values.add(field_name)
            try:
                result.append(argument.format_map(allowed))
            except KeyError as error:
                raise HilConfigurationError(
                    f"unknown placeholder {error} in driver.commands.{operation}"
                ) from error
        unused_values = sorted(set(values) - used_values)
        if unused_values:
            raise HilConfigurationError(
                f"driver.commands.{operation} ignores supplied placeholders: "
                f"{unused_values}"
            )
        return result


class ProbeLock(AbstractContextManager["ProbeLock"]):
    """Cross-platform exclusive lock for one physical probe/board."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._stream: Any | None = None

    def __enter__(self) -> Self:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        stream = self.path.open("a+b")
        stream.seek(0)
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        try:
            if os.name == "nt":
                import msvcrt

                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            stream.close()
            raise RuntimeError(f"probe is already locked: {self.path}") from error
        self._stream = stream
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        stream = self._stream
        if stream is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        finally:
            stream.close()
            self._stream = None


class OutputAccess(Protocol):
    """Injectable host-storage boundary used by cross-platform fault tests."""

    def available_bytes(self, root: Path) -> int:
        """Return bytes that the output location can still accept."""

    def probe_write(self, root: Path) -> None:
        """Create, flush, and remove one write probe below the output root."""


class LocalOutputAccess:
    """Real local-filesystem implementation of the output access boundary."""

    def available_bytes(self, root: Path) -> int:
        root.mkdir(parents=True, exist_ok=True)
        return shutil.disk_usage(root).free

    def probe_write(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        descriptor, raw_path = tempfile.mkstemp(
            prefix=".t32perf-hil-write-probe-", dir=root
        )
        path = Path(raw_path)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(b"t32perf-hil-write-probe\n")
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            try:
                path.unlink()
            except FileNotFoundError:
                pass


def preflight_output(board: BoardConfig, *, access: OutputAccess | None = None) -> None:
    """Fail before hardware access when quota or write permission is insufficient."""

    output = LocalOutputAccess() if access is None else access
    for label, root in (
        ("artifact", board.artifact_root),
        ("recovery evidence", board.recovery_evidence_root),
    ):
        try:
            available = output.available_bytes(root)
        except OSError as error:
            raise HilOutputError(
                f"cannot inspect {label} output `{root}`: {error}"
            ) from error
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
                f"{label} output has {available} free bytes; "
                f"requires at least {board.min_free_bytes}"
            )
        try:
            output.probe_write(root)
        except OSError as error:
            raise HilOutputError(
                f"{label} output is not writable: {root}: {error}"
            ) from error


@dataclass(frozen=True)
class ArtifactRootEntry:
    """Metadata-only snapshot entry; large trace contents are not loaded."""

    kind: str
    mode: int
    size: int
    mtime_ns: int
    device: int
    inode: int


@dataclass(frozen=True)
class ArtifactRootSnapshot:
    """Artifact-root state used to prove a failed command published nothing."""

    root: Path
    existed: bool
    entries: dict[str, ArtifactRootEntry]

    @classmethod
    def capture(cls, root: Path) -> ArtifactRootSnapshot:
        resolved = root.resolve()
        if not resolved.exists():
            return cls(root=resolved, existed=False, entries={})
        if not resolved.is_dir():
            raise RuntimeError(f"artifact root is not a directory: {resolved}")
        entries: dict[str, ArtifactRootEntry] = {}
        pending = [resolved]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    info = entry.stat(follow_symlinks=False)
                    path = Path(entry.path)
                    relative = path.relative_to(resolved).as_posix()
                    if stat.S_ISLNK(info.st_mode):
                        kind = "symlink"
                    elif stat.S_ISDIR(info.st_mode):
                        kind = "directory"
                        pending.append(path)
                    elif stat.S_ISREG(info.st_mode):
                        kind = "file"
                    else:
                        kind = "other"
                    entries[relative] = ArtifactRootEntry(
                        kind=kind,
                        mode=stat.S_IMODE(info.st_mode),
                        size=info.st_size,
                        mtime_ns=info.st_mtime_ns,
                        device=info.st_dev,
                        inode=info.st_ino,
                    )
        return cls(root=resolved, existed=True, entries=entries)

    def assert_unchanged(self) -> None:
        """Reject added, removed, or metadata-modified output after a fault."""

        current = self.capture(self.root)
        if self.existed != current.existed:
            raise RuntimeError("failed command changed artifact-root existence")
        if self.entries == current.entries:
            return
        before = set(self.entries)
        after = set(current.entries)
        added = sorted(after - before)
        removed = sorted(before - after)
        changed = sorted(
            path
            for path in before & after
            if self.entries[path] != current.entries[path]
        )
        raise RuntimeError(
            "failed command polluted artifact root; "
            f"added={added}, removed={removed}, changed={changed}"
        )


@dataclass(frozen=True)
class RecoveryEvidenceRootEntry:
    """Content-sensitive entry protecting persistent recovery history."""

    kind: str
    mode: int
    size: int
    mtime_ns: int
    device: int
    inode: int
    link_count: int
    sha256: str | None


@dataclass(frozen=True)
class RecoveryEvidenceRootSnapshot:
    """Strict snapshot that permits only one reserved evidence-file creation."""

    root: Path
    root_device: int
    root_inode: int
    entries: dict[str, RecoveryEvidenceRootEntry]

    @classmethod
    def capture(cls, root: Path) -> RecoveryEvidenceRootSnapshot:
        resolved = root.resolve(strict=True)
        root_metadata = resolved.lstat()
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(
            root_metadata.st_mode
        ):
            raise RuntimeError("recovery evidence root is not a plain directory")
        entries: dict[str, RecoveryEvidenceRootEntry] = {}
        pending = [resolved]
        while pending:
            directory = pending.pop()
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    path = Path(entry.path)
                    metadata = path.lstat()
                    relative = path.relative_to(resolved).as_posix()
                    if stat.S_ISLNK(metadata.st_mode):
                        kind = "symlink"
                        sha256 = None
                    elif stat.S_ISDIR(metadata.st_mode):
                        kind = "directory"
                        sha256 = None
                        pending.append(path)
                    elif stat.S_ISREG(metadata.st_mode):
                        kind = "file"
                        sha256 = _sha256_file(path)
                    else:
                        kind = "other"
                        sha256 = None
                    entries[relative] = RecoveryEvidenceRootEntry(
                        kind=kind,
                        mode=stat.S_IMODE(metadata.st_mode),
                        size=0 if kind == "directory" else metadata.st_size,
                        mtime_ns=0 if kind == "directory" else metadata.st_mtime_ns,
                        device=metadata.st_dev,
                        inode=metadata.st_ino,
                        link_count=0 if kind == "directory" else metadata.st_nlink,
                        sha256=sha256,
                    )
        return cls(
            root=resolved,
            root_device=root_metadata.st_dev,
            root_inode=root_metadata.st_ino,
            entries=entries,
        )

    def assert_unchanged(self) -> None:
        """Reject any mutation outside the business Session tree."""

        current = self.capture(self.root)
        added, removed, changed = self._changes(current)
        if added or removed or changed:
            raise RuntimeError(
                "command polluted recovery evidence root; "
                f"added={added}, removed={removed}, changed={changed}"
            )

    def assert_only_added(self, path: Path, sha256: str) -> None:
        """Allow exactly the reserved single-link evidence file and nothing else."""

        try:
            relative = path.resolve(strict=True).relative_to(self.root).as_posix()
        except (OSError, ValueError) as error:
            raise RuntimeError(
                "recovery evidence output escaped its protected root"
            ) from error
        current = self.capture(self.root)
        added, removed, changed = self._changes(current)
        if added != [relative] or removed or changed:
            raise RuntimeError(
                "recovery command changed paths outside its reservation; "
                f"added={added}, removed={removed}, changed={changed}"
            )
        entry = current.entries[relative]
        if entry.kind != "file" or entry.link_count != 1 or entry.sha256 != sha256:
            raise RuntimeError(
                "reserved recovery evidence file identity or digest is invalid"
            )

    def _changes(
        self, current: RecoveryEvidenceRootSnapshot
    ) -> tuple[list[str], list[str], list[str]]:
        if (
            current.root_device != self.root_device
            or current.root_inode != self.root_inode
        ):
            raise RuntimeError("recovery evidence root was replaced")
        before = set(self.entries)
        after = set(current.entries)
        added = sorted(after - before)
        removed = sorted(before - after)
        changed = sorted(
            path
            for path in before & after
            if self.entries[path] != current.entries[path]
        )
        return added, removed, changed


@dataclass(frozen=True)
class JsonCommandResult:
    """One parsed JSON process result and its actual exit status."""

    payload: dict[str, Any]
    returncode: int
    stderr: str


@dataclass(frozen=True)
class PendingCommandFailure:
    """Non-zero fault result awaiting separately persisted recovery evidence."""

    returncode: int
    stderr: str
    reservation: RecoveryEvidenceReservation
    artifact_snapshot: ArtifactRootSnapshot
    recovery_root_snapshot: RecoveryEvidenceRootSnapshot


@dataclass(frozen=True)
class CommandFailure:
    """Fault result closed by strict target-adapter recovery evidence."""

    returncode: int
    stderr: str
    recovery_evidence: TargetAdapterRecoveryEvidence
    recovery_evidence_sha256: str
    recovery_evidence_path: Path
    recovery_receipt_path: Path
    recovery_root_snapshot: RecoveryEvidenceRootSnapshot


@dataclass(frozen=True)
class VerifiedArtifact:
    """Manifest artifact whose path, size, digest, and provenance were verified."""

    artifact_id: str
    kind: str
    path: Path
    relative_path: str
    media_type: str
    size_bytes: int
    sha256: str
    producer: str
    input_artifact_ids: tuple[str, ...]
    file_identity: tuple[int, int] | None


@dataclass(frozen=True)
class VerifiedSession:
    """A session independently verified by the HIL host."""

    session_id: str
    path: Path
    manifest: dict[str, Any]
    artifacts: dict[str, VerifiedArtifact]
    cli_validation: dict[str, Any]

    def artifact(self, artifact_id: str) -> VerifiedArtifact:
        """Return one required artifact by its stable manifest ID."""

        try:
            return self.artifacts[artifact_id]
        except KeyError as error:
            raise RuntimeError(
                f"session {self.session_id} has no artifact `{artifact_id}`"
            ) from error

    def read_json_artifact(self, artifact_id: str) -> dict[str, Any]:
        """Read a bounded JSON artifact and enforce session ownership when tagged."""

        artifact = self.artifact(artifact_id)
        if artifact.size_bytes > JSON_ARTIFACT_LIMIT_BYTES:
            raise RuntimeError(
                f"artifact `{artifact_id}` exceeds HIL JSON limit "
                f"{JSON_ARTIFACT_LIMIT_BYTES}"
            )
        document = _load_json_object(artifact.path, f"artifact `{artifact_id}`")
        tagged_session = document.get("session_id")
        if tagged_session is not None and tagged_session != self.session_id:
            raise RuntimeError(
                f"artifact `{artifact_id}` belongs to session `{tagged_session}`, "
                f"expected `{self.session_id}`"
            )
        return document

    def iter_ndjson_artifact(self, artifact_id: str) -> Iterator[dict[str, Any]]:
        """Stream bounded UTF-8 JSON-object lines from one verified artifact."""

        artifact = self.artifact(artifact_id)
        with artifact.path.open("rb") as stream:
            for line_number, raw in enumerate(stream, start=1):
                if len(raw) > NDJSON_LINE_LIMIT_BYTES:
                    raise RuntimeError(
                        f"artifact `{artifact_id}` line {line_number} exceeds "
                        f"{NDJSON_LINE_LIMIT_BYTES} bytes"
                    )
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise RuntimeError(
                        f"artifact `{artifact_id}` has invalid UTF-8 at line "
                        f"{line_number}, byte {error.start}"
                    ) from error
                try:
                    value = _strict_json_loads(text)
                except (json.JSONDecodeError, DuplicateJsonKeyError) as error:
                    raise RuntimeError(
                        f"artifact `{artifact_id}` has invalid JSON at line "
                        f"{line_number}, column {error.colno}"
                    ) from error
                if not isinstance(value, dict):
                    raise RuntimeError(
                        f"artifact `{artifact_id}` line {line_number} is not an object"
                    )
                yield value


@dataclass(frozen=True)
class CaptureEvidence:
    """One capture fact derived from a verified manifest and health artifact."""

    board_id: str
    mcu_family: str
    rtos: str | None
    mode: str
    initial_state: str
    session_id: str
    trace32_release: str
    trace32_build: int
    probe_id: str
    architecture_package: str
    license_features: tuple[str, ...]
    capability_evidence_sha256: str
    trace_routing: tuple[str, ...]
    manifest_sha256: str
    health_sha256: str

    def to_document(self) -> dict[str, Any]:
        return {
            "board_id": self.board_id,
            "mcu_family": self.mcu_family,
            "rtos": self.rtos,
            "mode": self.mode,
            "initial_state": self.initial_state,
            "session_id": self.session_id,
            "trace32": {
                "release": self.trace32_release,
                "build": self.trace32_build,
                "probe_id": self.probe_id,
                "architecture_package": self.architecture_package,
                "license_features": list(self.license_features),
                "capability_evidence_sha256": self.capability_evidence_sha256,
            },
            "trace_routing": list(self.trace_routing),
            "manifest_sha256": self.manifest_sha256,
            "health_sha256": self.health_sha256,
        }


class CaptureEvidenceMatrix:
    """Aggregates only host-verified captures across boards and capture modes."""

    def __init__(self) -> None:
        self._captures: list[CaptureEvidence] = []
        self._session_keys: set[tuple[str, str]] = set()
        self._board_identities: dict[
            str,
            tuple[
                str,
                str | None,
                str,
                int,
                str,
                str,
                tuple[str, ...],
                str,
                tuple[str, ...],
            ],
        ] = {}

    @property
    def captures(self) -> tuple[CaptureEvidence, ...]:
        return tuple(self._captures)

    def add(
        self,
        board: BoardConfig,
        session: VerifiedSession,
        *,
        expected_mode: str,
        expected_initial_state: str,
    ) -> CaptureEvidence:
        evidence = capture_evidence(
            board,
            session,
            expected_mode=expected_mode,
            expected_initial_state=expected_initial_state,
        )
        identity = (
            evidence.mcu_family,
            evidence.rtos,
            evidence.trace32_release,
            evidence.trace32_build,
            evidence.probe_id,
            evidence.architecture_package,
            evidence.license_features,
            evidence.capability_evidence_sha256,
            evidence.trace_routing,
        )
        previous_identity = self._board_identities.get(evidence.board_id)
        if previous_identity is not None and previous_identity != identity:
            raise RuntimeError(
                f"conflicting evidence identity for board `{evidence.board_id}`"
            )
        self._board_identities[evidence.board_id] = identity
        key = (evidence.board_id, evidence.session_id)
        if key in self._session_keys:
            raise RuntimeError(
                f"duplicate verified session evidence `{evidence.board_id}/{evidence.session_id}`"
            )
        self._session_keys.add(key)
        self._captures.append(evidence)
        return evidence

    def assert_coverage(
        self,
        *,
        min_boards: int = 2,
        min_mcu_families: int = 2,
        min_modes: int = 2,
        min_rtoses: int = 1,
        min_repetitions_per_combination: int = 10,
        required_initial_states: frozenset[str] = INITIAL_TARGET_STATES,
    ) -> None:
        if (
            min_boards <= 0
            or min_mcu_families <= 0
            or min_modes <= 0
            or min_rtoses <= 0
            or min_repetitions_per_combination <= 0
        ):
            raise ValueError("evidence coverage minima must be positive")
        boards = sorted({capture.board_id for capture in self._captures})
        mcu_families = sorted({capture.mcu_family for capture in self._captures})
        modes = sorted({capture.mode for capture in self._captures})
        rtoses = sorted(
            {capture.rtos for capture in self._captures if capture.rtos is not None}
        )
        if len(boards) < min_boards:
            raise AssertionError(
                f"HIL evidence covers {len(boards)} boards; requires {min_boards}"
            )
        if len(modes) < min_modes:
            raise AssertionError(
                f"HIL evidence covers {len(modes)} modes; requires {min_modes}"
            )
        if len(mcu_families) < min_mcu_families:
            raise AssertionError(
                "HIL evidence covers "
                f"{len(mcu_families)} MCU families; requires {min_mcu_families}"
            )
        if len(rtoses) < min_rtoses:
            raise AssertionError(
                f"HIL evidence covers {len(rtoses)} RTOSes; requires {min_rtoses}"
            )
        qualified_modes: list[str] = []
        for mode in modes:
            mode_is_qualified = True
            for board_id in boards:
                captures = [
                    capture
                    for capture in self._captures
                    if capture.board_id == board_id and capture.mode == mode
                ]
                states = {capture.initial_state for capture in captures}
                if (
                    len(captures) < min_repetitions_per_combination
                    or required_initial_states - states
                ):
                    mode_is_qualified = False
                    break
            if mode_is_qualified:
                qualified_modes.append(mode)
        if len(qualified_modes) < min_modes:
            raise AssertionError(
                "HIL evidence has only "
                f"{len(qualified_modes)} modes with complete per-board repetition/state "
                f"coverage; requires {min_modes}"
            )

    def to_document(self) -> dict[str, Any]:
        captures = sorted(
            self._captures,
            key=lambda capture: (
                capture.board_id,
                capture.mode,
                capture.initial_state,
                capture.session_id,
            ),
        )
        combinations: dict[tuple[str, str], int] = {}
        for capture in captures:
            key = (capture.board_id, capture.mode)
            combinations[key] = combinations.get(key, 0) + 1
        return {
            "schema": HIL_EVIDENCE_SCHEMA,
            "source": "host-verified-session-artifacts",
            "coverage": {
                "boards": sorted({capture.board_id for capture in captures}),
                "mcu_families": sorted({capture.mcu_family for capture in captures}),
                "modes": sorted({capture.mode for capture in captures}),
                "rtoses": sorted(
                    {capture.rtos for capture in captures if capture.rtos is not None}
                ),
                "probes": sorted({capture.probe_id for capture in captures}),
                "architecture_packages": sorted(
                    {capture.architecture_package for capture in captures}
                ),
                "combinations": [
                    {"board_id": board_id, "mode": mode, "capture_count": count}
                    for (board_id, mode), count in sorted(combinations.items())
                ],
            },
            "captures": [capture.to_document() for capture in captures],
        }


def write_capture_evidence_matrix(
    matrix: CaptureEvidenceMatrix, output_path: Path
) -> dict[str, Any]:
    """Write one complete evidence matrix without replacing existing evidence."""

    matrix.assert_coverage()
    document = matrix.to_document()
    bytes_ = (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if len(bytes_) > HIL_EVIDENCE_LIMIT_BYTES:
        raise HilOutputError(
            f"HIL evidence is {len(bytes_)} bytes; maximum is "
            f"{HIL_EVIDENCE_LIMIT_BYTES}"
        )

    path = output_path.resolve()
    parent = path.parent
    if not parent.is_dir():
        raise HilOutputError(f"HIL evidence parent is not a directory: {parent}")
    created = False
    try:
        with path.open("xb") as stream:
            created = True
            stream.write(bytes_)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise HilOutputError(f"HIL evidence already exists: {path}") from error
    except OSError as error:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise HilOutputError(f"cannot write HIL evidence `{path}`: {error}") from error
    return document


@dataclass(frozen=True)
class DifferentialMetric:
    """Count and CPU-time pair used by Task/ISR differential checks."""

    count: int
    time_ns: float


@dataclass(frozen=True)
class ContextSwitchReference:
    """One RTOS switch enriched with independently read context metadata."""

    ts_ns: float
    core_id: int
    previous_context_id: str | None
    next_context_id: str
    next_name: str
    next_kind: str
    next_priority: int


@dataclass(frozen=True)
class InterruptReference:
    """One ISR edge with host-reconstructed nesting and preemption context."""

    event: str
    ts_ns: float
    core_id: int
    interrupt_id: str
    interrupt_name: str
    priority: int
    activation_id: str
    nesting_depth: int
    parent_activation_id: str | None
    preempted_task_id: str | None


@dataclass(frozen=True)
class FunctionActivationReference:
    """One bounded derived activation selected by immutable source provenance."""

    source_id: str
    source_seq_start: int
    source_seq_end: int
    function_id: str
    core_id: int
    context_id: str
    context_kind: str
    start_ns: float
    end_ns: float
    elapsed_ns: float
    active_ns: float
    self_active_ns: float
    preempted_ns: float


@dataclass(frozen=True)
class FunctionDifferentialMetric:
    """Complete function statistic row used by native differential checks."""

    count: int
    total_time_ns: float
    self_time_ns: float
    min_time_ns: float
    max_time_ns: float
    average_time_ns: float


@dataclass(frozen=True)
class DifferentialStatistics:
    """Native or T32Perf statistics partitioned by semantic subject."""

    functions: dict[str, FunctionDifferentialMetric]
    tasks: dict[str, DifferentialMetric]
    isrs: dict[str, DifferentialMetric]
    context_switches: tuple[ContextSwitchReference, ...]
    interrupts: tuple[InterruptReference, ...]
    function_activations: tuple[FunctionActivationReference, ...]


@dataclass(frozen=True)
class _ExtractedTimeline:
    context_switches: tuple[ContextSwitchReference, ...]
    interrupts: tuple[InterruptReference, ...]
    task_counts: dict[str, int]
    isr_counts: dict[str, int]
    context_definitions: dict[str, dict[str, Any]]


class SessionAudit:
    """Tracks new HIL sessions and rejects deletion, reuse, or cross-session files."""

    def __init__(self, board: BoardConfig) -> None:
        self.board = board
        self.board.artifact_root.mkdir(parents=True, exist_ok=True)
        self._known_sessions = _session_directory_names(board.artifact_root)
        self._file_owners: dict[tuple[int, int], tuple[str, str]] = {}

    def verify_driver_result(
        self,
        driver_result: dict[str, Any],
        *,
        expected_health: str | None = None,
    ) -> VerifiedSession:
        """Verify the one new session named by a driver result."""

        session_id = _required_string(driver_result, "session_id", "driver result")
        _validate_session_id(session_id)
        current = _session_directory_names(self.board.artifact_root)
        removed = self._known_sessions - current
        if removed:
            raise RuntimeError(
                f"capture removed prior session directories: {sorted(removed)}"
            )
        new_sessions = current - self._known_sessions
        if new_sessions != {session_id}:
            raise RuntimeError(
                f"capture must create exactly session `{session_id}`; "
                f"new session directories were {sorted(new_sessions)}"
            )

        cli_validation = run_t32perf_validate(self.board, session_id)
        verified = verify_session_directory(
            self.board,
            session_id,
            cli_validation=cli_validation,
        )
        health = verified.read_json_artifact(HEALTH_ARTIFACT_ID)
        verdict = _required_string(health, "verdict", "health artifact")
        if expected_health is not None and verdict != expected_health:
            raise RuntimeError(
                f"session `{session_id}` health is {verdict}, expected {expected_health}"
            )
        if cli_validation.get("health_verdict") != verdict:
            raise RuntimeError(
                f"CLI health verdict {cli_validation.get('health_verdict')!r} "
                f"does not match health artifact {verdict!r}"
            )

        for artifact in verified.artifacts.values():
            identity = artifact.file_identity
            if identity is None:
                continue
            previous = self._file_owners.get(identity)
            if previous is not None:
                raise RuntimeError(
                    f"artifact `{artifact.artifact_id}` in `{session_id}` reuses the "
                    f"same file as artifact `{previous[1]}` in `{previous[0]}`"
                )
            self._file_owners[identity] = (session_id, artifact.artifact_id)

        self._known_sessions = current
        return verified


def capture_evidence(
    board: BoardConfig,
    session: VerifiedSession,
    *,
    expected_mode: str,
    expected_initial_state: str,
) -> CaptureEvidence:
    """Bind requested mode/state to independently verified capture artifacts."""

    verify_capability_evidence(board)

    if expected_mode not in board.capture_modes:
        raise HilConfigurationError(
            f"capture mode `{expected_mode}` is not configured for `{board.board_id}`"
        )
    if expected_initial_state not in INITIAL_TARGET_STATES:
        raise HilConfigurationError(
            f"unsupported initial target state `{expected_initial_state}`"
        )
    capture = _required_object(session.manifest, "capture", "manifest")
    mode = _required_string(capture, "mode", "manifest.capture")
    if mode != expected_mode:
        raise RuntimeError(
            f"session `{session.session_id}` capture mode is `{mode}`, "
            f"expected `{expected_mode}`"
        )
    target = _required_object(capture, "target", "manifest.capture")
    properties = _required_object(target, "properties", "manifest.capture.target")
    initial_state = _required_string(
        properties, "initial_state", "manifest.capture.target.properties"
    )
    if initial_state != expected_initial_state:
        raise RuntimeError(
            f"session `{session.session_id}` initial state is `{initial_state}`, "
            f"expected `{expected_initial_state}`"
        )
    health = session.read_json_artifact(HEALTH_ARTIFACT_ID)
    verdict = _required_string(health, "verdict", "health artifact")
    if verdict != "VALID":
        raise RuntimeError(
            f"capture evidence requires VALID health, observed `{verdict}`"
        )
    return CaptureEvidence(
        board_id=board.board_id,
        mcu_family=board.mcu_family,
        rtos=board.rtos,
        mode=mode,
        initial_state=initial_state,
        session_id=session.session_id,
        trace32_release=board.trace32_release,
        trace32_build=board.trace32_build,
        probe_id=board.probe_id,
        architecture_package=board.architecture_package,
        license_features=board.license_features,
        capability_evidence_sha256=board.capability_evidence_sha256,
        trace_routing=board.trace_routing,
        manifest_sha256=_sha256_file(session.path / "manifest.json"),
        health_sha256=session.artifact(HEALTH_ARTIFACT_ID).sha256,
    )


def verify_doctor_result(board: BoardConfig, result: dict[str, Any]) -> None:
    """Treat doctor JSON as a preflight fact and reject unknown installations."""

    verify_capability_evidence(board)

    if result.get("ok") is not True:
        raise RuntimeError("board doctor did not report success")
    if result.get("board_id") != board.board_id:
        raise RuntimeError(
            f"board doctor reported {result.get('board_id')!r}, "
            f"expected {board.board_id!r}"
        )
    build = result.get("trace32_build")
    if isinstance(build, bool) or not isinstance(build, int):
        raise RuntimeError("board doctor trace32_build must be an integer")
    if build not in board.validated_trace32_builds:
        raise RuntimeError(f"board doctor reported unvalidated TRACE32 build {build}")
    if build != board.trace32_build:
        raise RuntimeError(
            f"board doctor TRACE32 build {build} does not match configured "
            f"build {board.trace32_build}"
        )
    if result.get("trace32_release") != board.trace32_release:
        raise RuntimeError(
            f"board doctor TRACE32 release {result.get('trace32_release')!r} "
            f"does not match {board.trace32_release!r}"
        )
    for field, expected in [
        ("probe_id", board.probe_id),
        ("architecture_package", board.architecture_package),
        ("capability_evidence_sha256", board.capability_evidence_sha256),
    ]:
        if result.get(field) != expected:
            raise RuntimeError(
                f"board doctor {field} {result.get(field)!r} does not match {expected!r}"
            )
    if result.get("license_features") != list(board.license_features):
        raise RuntimeError("board doctor license_features do not match configuration")
    if result.get("trace_routing") != list(board.trace_routing):
        raise RuntimeError("board doctor trace_routing does not match configuration")


def verify_capability_evidence(board: BoardConfig) -> None:
    """Revalidate the exact lab capability evidence before accepting hardware facts."""

    try:
        metadata = board.capability_evidence.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("capability evidence is not a plain regular file")
        actual = _sha256_file(board.capability_evidence)
    except OSError as error:
        raise RuntimeError(f"cannot read capability evidence: {error}") from error
    if actual != board.capability_evidence_sha256:
        raise RuntimeError("capability evidence changed after board configuration load")


def run_t32perf_validate(board: BoardConfig, session_id: str) -> dict[str, Any]:
    """Run host-owned deep validation and verify its JSON envelope and exit code."""

    command = [
        str(board.t32perf_bin),
        "--artifact-root",
        str(board.artifact_root),
        "--json",
        "validate",
        session_id,
        "--deep",
    ]
    completed = _run_json_process(command, cwd=board.path.parent)
    payload = completed.payload
    if payload.get("ok") is not True or payload.get("command") != "validate":
        raise RuntimeError(
            "t32perf validate did not return a successful validate envelope"
        )
    result = payload.get("result")
    if not isinstance(result, dict):
        raise RuntimeError("t32perf validate result must be an object")
    if result.get("session_id") != session_id or result.get("deep") is not True:
        raise RuntimeError(
            "t32perf validate returned the wrong session or shallow result"
        )
    verdict = result.get("health_verdict")
    valid = result.get("valid")
    expected_exit = {None: 0, "VALID": 0, "DEGRADED": 10, "INVALID": 11}.get(verdict)
    if expected_exit is None:
        raise RuntimeError(
            f"t32perf validate returned unknown health verdict {verdict!r}"
        )
    if completed.returncode != expected_exit:
        raise RuntimeError(
            f"t32perf validate exited {completed.returncode}; expected {expected_exit} "
            f"for health {verdict!r}"
        )
    if valid is not (verdict != "INVALID"):
        raise RuntimeError("t32perf validate valid flag contradicts the health verdict")
    return result


def verify_session_directory(
    board: BoardConfig,
    session_id: str,
    *,
    cli_validation: dict[str, Any],
) -> VerifiedSession:
    """Independently verify manifest ownership, hashes, and provenance."""

    _validate_session_id(session_id)
    root = board.artifact_root.resolve(strict=True)
    session_path = root / session_id
    if session_path.is_symlink() or not session_path.is_dir():
        raise RuntimeError(f"session path is not a plain directory: {session_path}")
    resolved_session = session_path.resolve(strict=True)
    if resolved_session.parent != root:
        raise RuntimeError(f"session path escapes artifact root: {resolved_session}")
    manifest_path = resolved_session / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise RuntimeError(f"session manifest is not a plain file: {manifest_path}")
    manifest = _load_json_object(manifest_path, "manifest")
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise RuntimeError(f"unsupported manifest schema {manifest.get('schema')!r}")
    if manifest.get("session_id") != session_id:
        raise RuntimeError("manifest session_id does not match its directory")
    _verify_manifest_capture_provenance(board, manifest)

    raw_artifacts = manifest.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise RuntimeError("manifest artifacts must be a non-empty array")
    artifacts: dict[str, VerifiedArtifact] = {}
    relative_paths: set[str] = set()
    for raw in raw_artifacts:
        artifact = _verify_artifact(resolved_session, raw)
        if artifact.artifact_id in artifacts:
            raise RuntimeError(f"duplicate artifact ID `{artifact.artifact_id}`")
        if artifact.relative_path in relative_paths:
            raise RuntimeError(f"duplicate artifact path `{artifact.relative_path}`")
        artifacts[artifact.artifact_id] = artifact
        relative_paths.add(artifact.relative_path)
    _verify_provenance_graph(manifest, artifacts)
    _verify_instrumentation_artifact_provenance(resolved_session, manifest, artifacts)
    if cli_validation.get("artifact_count") != len(artifacts):
        raise RuntimeError(
            f"CLI reported {cli_validation.get('artifact_count')!r} artifacts, "
            f"manifest contains {len(artifacts)}"
        )
    if cli_validation.get("status") != "complete":
        raise RuntimeError(
            f"validated session status is {cli_validation.get('status')!r}, expected 'complete'"
        )
    for artifact in artifacts.values():
        if (
            artifact.media_type == "application/json"
            and artifact.size_bytes <= JSON_ARTIFACT_LIMIT_BYTES
        ):
            document = _load_json_object(
                artifact.path, f"artifact `{artifact.artifact_id}`"
            )
            tagged_session = document.get("session_id")
            if tagged_session is not None and tagged_session != session_id:
                raise RuntimeError(
                    f"artifact `{artifact.artifact_id}` belongs to session "
                    f"{tagged_session!r}, expected {session_id!r}"
                )
    return VerifiedSession(
        session_id=session_id,
        path=resolved_session,
        manifest=manifest,
        artifacts=artifacts,
        cli_validation=cli_validation,
    )


def run_json(
    argv: list[str], *, cwd: Path, timeout_seconds: float = 300.0
) -> dict[str, Any]:
    """Run one HIL driver operation and require exactly one JSON result."""

    completed = _run_json_process(argv, cwd=cwd, timeout_seconds=timeout_seconds)
    if completed.returncode != 0:
        raise RuntimeError(
            f"driver failed with exit {completed.returncode}: {completed.stderr.strip()}"
        )
    return completed.payload


def reserve_recovery_evidence(
    board: BoardConfig,
    fault_operation: str,
    *,
    initial_target_state: str,
    binding_sha256: str,
) -> RecoveryEvidenceReservation:
    """Reserve one independent recovery document for a fixed fault contract."""

    try:
        failed_operation, failure_kind = RECOVERY_FAULT_CONTRACTS[fault_operation]
    except KeyError as error:
        raise HilConfigurationError(
            f"unsupported recovery fault operation `{fault_operation}`"
        ) from error
    return reserve_target_adapter_recovery_evidence(
        board.recovery_evidence_root,
        RecoveryEvidenceExpectation(
            profile_sha256=board.target_adapter_profile_sha256,
            binding_sha256=binding_sha256,
            failed_operation=failed_operation,
            failure_kind=failure_kind,
            initial_target_state=initial_target_state,
        ),
    )


def validate_recovery_fault_preparation(
    board: BoardConfig,
    fault_operation: str,
    *,
    initial_target_state: str,
    result: Mapping[str, Any],
) -> TargetAdapterFailureBinding:
    """Validate the controller binding observed before a fault is injected."""

    try:
        failed_operation, failure_kind = RECOVERY_FAULT_CONTRACTS[fault_operation]
    except KeyError as error:
        raise HilConfigurationError(
            f"unsupported recovery fault operation `{fault_operation}`"
        ) from error
    preparation = TargetAdapterFailureBinding.from_document(result)
    expected = {
        "profile_sha256": board.target_adapter_profile_sha256,
        "failed_operation": failed_operation,
        "failure_kind": failure_kind,
        "initial_target_state": initial_target_state,
    }
    mismatches = sorted(
        field
        for field, value in expected.items()
        if getattr(preparation, field) != value
    )
    if mismatches:
        raise RuntimeError(
            "fault preparation differs from the selected adapter contract: "
            f"{mismatches}"
        )
    return preparation


def run_recovery_fault_preparation(
    board: BoardConfig,
    fault_operation: str,
    *,
    initial_target_state: str,
    timeout_seconds: float = 300.0,
) -> TargetAdapterFailureBinding:
    """Observe one controller binding without permitting host-output mutation."""

    artifact_snapshot = ArtifactRootSnapshot.capture(board.artifact_root)
    recovery_snapshot = RecoveryEvidenceRootSnapshot.capture(
        board.recovery_evidence_root
    )
    try:
        result = run_json(
            board.command(
                "prepare_recovery_fault",
                fault_operation=fault_operation,
                initial_target_state=initial_target_state,
            ),
            cwd=board.path.parent,
            timeout_seconds=timeout_seconds,
        )
    except RuntimeError:
        artifact_snapshot.assert_unchanged()
        recovery_snapshot.assert_unchanged()
        raise
    artifact_snapshot.assert_unchanged()
    recovery_snapshot.assert_unchanged()
    return validate_recovery_fault_preparation(
        board,
        fault_operation,
        initial_target_state=initial_target_state,
        result=result,
    )


def run_expected_failure(
    argv: list[str],
    *,
    cwd: Path,
    artifact_root: Path,
    recovery_evidence: RecoveryEvidenceReservation,
    timeout_seconds: float = 300.0,
) -> PendingCommandFailure:
    """Require fail-closed output and prove the business artifact root is unchanged."""

    if _paths_overlap(artifact_root.resolve(), recovery_evidence.directory.resolve()):
        raise RuntimeError(
            "recovery evidence reservation must be independent from artifact root"
        )
    if (
        recovery_evidence.output_path.parent.resolve()
        != recovery_evidence.directory.resolve()
    ):
        raise RuntimeError("recovery evidence output escaped its reservation directory")
    try:
        recovery_evidence.output_path.lstat()
    except FileNotFoundError:
        pass
    except OSError as error:
        raise RuntimeError(
            f"cannot inspect recovery evidence reservation: {error}"
        ) from error
    else:
        raise RuntimeError(
            "recovery evidence output already exists before fault injection"
        )
    snapshot = ArtifactRootSnapshot.capture(artifact_root)
    recovery_root_snapshot = RecoveryEvidenceRootSnapshot.capture(
        recovery_evidence.directory.parent
    )
    try:
        completed = _execute_process(argv, cwd=cwd, timeout_seconds=timeout_seconds)
    except RuntimeError:
        snapshot.assert_unchanged()
        recovery_root_snapshot.assert_unchanged()
        raise
    snapshot.assert_unchanged()
    recovery_root_snapshot.assert_unchanged()
    if completed.returncode == 0:
        raise RuntimeError("fault-injection command unexpectedly succeeded")
    return PendingCommandFailure(
        returncode=completed.returncode,
        stderr=completed.stderr,
        reservation=recovery_evidence,
        artifact_snapshot=snapshot,
        recovery_root_snapshot=recovery_root_snapshot,
    )


def run_recovery(
    argv: list[str],
    *,
    cwd: Path,
    failure: PendingCommandFailure,
    timeout_seconds: float = 300.0,
) -> tuple[dict[str, Any], CommandFailure]:
    """Run explicit recovery and accept only its reserved strict evidence file."""

    if failure.reservation.output_path.exists():
        raise RuntimeError("recovery evidence output exists before recovery command")
    failure.recovery_root_snapshot.assert_unchanged()
    try:
        result = run_json(argv, cwd=cwd, timeout_seconds=timeout_seconds)
    except RuntimeError:
        failure.artifact_snapshot.assert_unchanged()
        failure.recovery_root_snapshot.assert_unchanged()
        raise
    failure.artifact_snapshot.assert_unchanged()
    loaded = failure.reservation.load()
    failure.recovery_root_snapshot.assert_only_added(loaded.path, loaded.sha256)
    accepted_recovery_root = RecoveryEvidenceRootSnapshot.capture(
        failure.reservation.directory.parent
    )
    return result, CommandFailure(
        returncode=failure.returncode,
        stderr=failure.stderr,
        recovery_evidence=loaded.evidence,
        recovery_evidence_sha256=loaded.sha256,
        recovery_evidence_path=loaded.path,
        recovery_receipt_path=failure.reservation.receipt_path,
        recovery_root_snapshot=accepted_recovery_root,
    )


def _run_json_process(
    argv: list[str], *, cwd: Path, timeout_seconds: float = 300.0
) -> JsonCommandResult:
    completed = _execute_process(argv, cwd=cwd, timeout_seconds=timeout_seconds)
    output = completed.stdout.strip()
    if not output:
        if completed.returncode != 0:
            raise RuntimeError(
                f"command failed with exit {completed.returncode}: "
                f"{completed.stderr.strip()}"
            )
        raise RuntimeError("command returned no JSON result")
    try:
        result = _strict_json_loads(output)
    except (json.JSONDecodeError, DuplicateJsonKeyError) as error:
        raise RuntimeError(f"command stdout is not one JSON object: {error}") from error
    if not isinstance(result, dict):
        raise RuntimeError("command result must be a JSON object")
    return JsonCommandResult(
        payload=result,
        returncode=completed.returncode,
        stderr=completed.stderr,
    )


def _execute_process(
    argv: list[str], *, cwd: Path, timeout_seconds: float
) -> subprocess.CompletedProcess[str]:
    stdout = _BoundedPipeCapture(COMMAND_STDOUT_LIMIT_BYTES)
    stderr = _BoundedPipeCapture(COMMAND_STDERR_LIMIT_BYTES)
    try:
        process = subprocess.Popen(
            argv,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise RuntimeError(f"failed to execute JSON command: {error}") from error
    assert process.stdout is not None
    assert process.stderr is not None
    stdout_thread = threading.Thread(
        target=stdout.drain,
        args=(process.stdout,),
        name="t32perf-hil-stdout",
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=stderr.drain,
        args=(process.stderr,),
        name="t32perf-hil-stderr",
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    timed_out = False
    pipe_errors: list[RuntimeError] = []
    try:
        returncode = process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        returncode = process.wait()
    finally:
        for thread, stream, label in [
            (stdout_thread, process.stdout, "stdout"),
            (stderr_thread, process.stderr, "stderr"),
        ]:
            try:
                _join_pipe_thread(thread, stream, label)
            except RuntimeError as error:
                pipe_errors.append(error)

    if pipe_errors:
        raise pipe_errors[0]
    if timed_out:
        raise RuntimeError(f"JSON command timed out after {timeout_seconds} seconds")
    stdout.raise_if_invalid("stdout")
    stderr.raise_if_invalid("stderr")
    try:
        stdout_text = stdout.data.decode("utf-8")
        stderr_text = stderr.data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError(f"JSON command output is not UTF-8: {error}") from error
    return subprocess.CompletedProcess(
        args=argv,
        returncode=returncode,
        stdout=stdout_text,
        stderr=stderr_text,
    )


@dataclass
class _BoundedPipeCapture:
    limit: int
    data: bytearray = dataclass_field(default_factory=bytearray)
    overflow: bool = False
    error: OSError | None = None

    def drain(self, stream: BinaryIO) -> None:
        try:
            while chunk := stream.read(64 * 1024):
                remaining = max(0, self.limit - len(self.data))
                self.data.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.overflow = True
        except OSError as error:
            self.error = error

    def raise_if_invalid(self, label: str) -> None:
        if self.error is not None:
            raise RuntimeError(f"failed to read command {label}: {self.error}")
        if self.overflow:
            raise RuntimeError(f"command {label} exceeds {self.limit} bytes")


def _join_pipe_thread(thread: threading.Thread, stream: BinaryIO, label: str) -> None:
    thread.join(COMMAND_PIPE_JOIN_TIMEOUT_SECONDS)
    if thread.is_alive():
        stream.close()
        thread.join(1.0)
        raise RuntimeError(f"command {label} pipe remained open after process exit")
    stream.close()


def assert_overflow_health(
    session: VerifiedSession,
    driver_reference: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Require an overflow-only INVALID verdict from the health artifact."""

    return _assert_injected_fault_health(
        session,
        expected_code=TRACE_OVERFLOW_ISSUE_CODE,
        driver_reference=driver_reference,
    )


def assert_flow_error_health(
    session: VerifiedSession,
    driver_reference: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Require a flow-error-only INVALID verdict from the health artifact."""

    return _assert_injected_fault_health(
        session,
        expected_code=FLOW_ERROR_ISSUE_CODE,
        driver_reference=driver_reference,
    )


def assert_elf_mismatch_health(
    session: VerifiedSession,
    driver_reference: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Require an ELF-mismatch-only INVALID verdict from the health artifact."""

    return _assert_injected_fault_health(
        session,
        expected_code=ELF_MISMATCH_ISSUE_CODE,
        driver_reference=driver_reference,
    )


def assert_sampling_buffer_full_health(
    session: VerifiedSession,
    board: BoardConfig,
    driver_reference: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Require a sampling-buffer-full-only INVALID health verdict."""

    receipt = _assert_injected_fault_health(
        session,
        expected_code=SAMPLING_BUFFER_FULL_ISSUE_CODE,
        driver_reference=driver_reference,
        fault_adapter_binding=_fault_adapter_binding(board, "sampling_buffer_full"),
    )
    return write_sampling_buffer_full_verification_receipt(board, session, receipt)


def _assert_injected_fault_health(
    session: VerifiedSession,
    *,
    expected_code: str,
    driver_reference: Mapping[str, Any] | None,
    fault_adapter_binding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Keep independently injected capture-integrity faults separate."""

    health = session.read_json_artifact(HEALTH_ARTIFACT_ID)
    if health.get("verdict") != "INVALID":
        raise AssertionError(f"{expected_code} capture health artifact is not INVALID")
    issues = health.get("issues")
    if not isinstance(issues, list):
        raise AssertionError("health artifact issues must be an array")
    if any(
        not isinstance(issue, dict)
        or not isinstance(issue.get("code"), str)
        or not issue["code"].strip()
        for issue in issues
    ):
        raise AssertionError("health artifact issues must have non-empty string codes")
    code_rows = [issue["code"] for issue in issues]
    if len(code_rows) != len(set(code_rows)):
        raise AssertionError("health artifact contains duplicate issue codes")
    codes = set(code_rows)
    if expected_code not in codes:
        raise AssertionError(
            f"health artifact has no `{expected_code}` issue; "
            f"observed codes: {sorted(codes)}"
        )
    unexpected = codes - {expected_code}
    if unexpected:
        raise AssertionError(
            f"health artifact conflates `{expected_code}` with {sorted(unexpected)}"
        )
    from verification_receipt import (
        TolerancePolicy,
        VerificationCheck,
        build_verification_receipt,
        canonical_sha256,
    )

    scenario = {
        TRACE_OVERFLOW_ISSUE_CODE: "trace_overflow",
        FLOW_ERROR_ISSUE_CODE: "flow_error",
        ELF_MISMATCH_ISSUE_CODE: "elf_mismatch",
        SAMPLING_BUFFER_FULL_ISSUE_CODE: "sampling_buffer_full",
    }[expected_code]
    reference = (
        dict(driver_reference)
        if driver_reference is not None
        else {"session_id": session.session_id, "expected_issue_code": expected_code}
    )
    return build_verification_receipt(
        kind="fault_injection",
        scenario=scenario,
        board_id=_session_board_id(session),
        session_id=session.session_id,
        driver_reference_sha256=canonical_sha256(reference),
        tolerance=TolerancePolicy(
            timestamp_absolute_ns=0.0,
            timestamp_relative=0.0,
            continuous_relative=0.0,
            continuous_absolute=0.0,
            integer_absolute=0.0,
        ),
        artifact_bindings=_fault_artifact_bindings(session),
        checks=[
            VerificationCheck(
                category="artifact_binding",
                name="manifest and health artifacts were rehashed",
                passed=True,
                absolute_error=0.0,
                relative_error=0.0,
            ),
            VerificationCheck(
                category="health",
                name=f"health issue set is exactly {expected_code}",
                passed=True,
                absolute_error=0.0,
                relative_error=0.0,
            ),
            VerificationCheck(
                category="fault_publication",
                name="fault published one independently verified INVALID Session",
                passed=True,
                absolute_error=0.0,
                relative_error=0.0,
            ),
        ],
        fault_adapter_binding=fault_adapter_binding,
    )


def _fault_adapter_binding(board: BoardConfig, scenario: str) -> dict[str, str]:
    """Build the exact manifest/profile/bundle identity recorded in a fault receipt."""

    try:
        declared = board.fault_scenarios[scenario]
    except KeyError as error:
        raise RuntimeError(
            f"adapter fault scenario is not declared: {scenario}"
        ) from error
    return {
        "scenario": declared.receipt_scenario,
        "fault_scenarios_sha256": board.fault_scenarios_sha256,
        "adapter_id": board.target_adapter_id,
        "profile_sha256": board.target_adapter_profile_sha256,
        "profile_file_sha256": board.target_adapter_profile_file_sha256,
        "bundle_sha256": board.target_adapter_bundle_sha256,
    }


def write_sampling_buffer_full_verification_receipt(
    board: BoardConfig,
    session: VerifiedSession,
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    """Exclusively persist sampled-fault evidence outside the Session artifact DAG."""

    from verification_receipt import (
        load_verification_receipt,
        write_verification_receipt,
    )

    root = board.recovery_evidence_root / "sampling-buffer-full-receipts"
    root.mkdir(parents=True, exist_ok=True)
    directory = root / session.session_id
    try:
        directory.mkdir()
    except FileExistsError as error:
        raise RuntimeError(
            f"sampling_buffer_full verification receipt directory already exists: {directory}"
        ) from error
    output = directory / "verification-receipt.json"
    try:
        validated = load_verification_receipt(receipt)
        expected_binding = _fault_adapter_binding(board, "sampling_buffer_full")
        if validated.get("fault_adapter_binding") != expected_binding:
            raise RuntimeError("sampling receipt does not bind the selected adapter")
        write_verification_receipt(validated, output)
        persisted = load_verification_receipt(output)
        if persisted != validated:
            raise RuntimeError("persisted sampling receipt differs from its source")
        return persisted
    except Exception:
        try:
            directory.rmdir()
        except OSError:
            pass
        raise


def _fault_artifact_bindings(
    session: VerifiedSession,
) -> dict[str, tuple[str | None, str]]:
    manifest_path = session.path / "manifest.json"
    if _load_json_object(manifest_path, "manifest") != session.manifest:
        raise RuntimeError("manifest changed after HIL Session verification")
    health = session.artifact(HEALTH_ARTIFACT_ID)
    health_sha256 = _sha256_file(health.path)
    if health_sha256 != health.sha256:
        raise RuntimeError("health artifact changed after HIL Session verification")
    return {
        "manifest": (None, _sha256_file(manifest_path)),
        "health": (HEALTH_ARTIFACT_ID, health_sha256),
    }


def build_recovery_verification(
    session: VerifiedSession,
    fault_operation: str,
    failure: CommandFailure,
) -> dict[str, Any]:
    """Build a receipt for a clean injected failure followed by a VALID Session."""

    from verification_receipt import (
        TolerancePolicy,
        VerificationCheck,
        build_verification_receipt,
        canonical_sha256,
    )

    if fault_operation not in RECOVERY_FAULT_CONTRACTS:
        raise RuntimeError(f"unsupported recovery fault operation `{fault_operation}`")
    if failure.returncode == 0:
        raise RuntimeError("recovery verification received a successful fault command")
    loaded = load_target_adapter_recovery_evidence(failure.recovery_evidence_path)
    if (
        loaded.sha256 != failure.recovery_evidence_sha256
        or loaded.evidence != failure.recovery_evidence
    ):
        raise RuntimeError("target-adapter recovery evidence changed after acceptance")
    expected_operation, expected_kind = RECOVERY_FAULT_CONTRACTS[fault_operation]
    if (
        loaded.evidence.failed_operation != expected_operation
        or loaded.evidence.failure_kind != expected_kind
    ):
        raise RuntimeError("recovery evidence does not match the fault scenario")
    health = session.read_json_artifact(HEALTH_ARTIFACT_ID)
    if (
        health.get("schema") != "t32perf.health/v1"
        or health.get("session_id") != session.session_id
        or health.get("verdict") != "VALID"
    ):
        raise RuntimeError("recovery verification requires a subsequent VALID Session")
    failure_reference = {
        "operation": fault_operation,
        "returncode": failure.returncode,
        "stderr_sha256": hashlib.sha256(failure.stderr.encode("utf-8")).hexdigest(),
        "recovery_evidence_sha256": loaded.sha256,
        "recovery_evidence": loaded.evidence.to_document(),
        "recovered_session_id": session.session_id,
    }
    scenario = {
        "trace32_disconnect_capture": "trace32_disconnect_recovery",
        "driver_disconnect_capture": "driver_disconnect_recovery",
        "cmm_abort_capture": "cmm_abort_recovery",
    }[fault_operation]
    return build_verification_receipt(
        kind="fault_injection",
        scenario=scenario,
        board_id=_session_board_id(session),
        session_id=session.session_id,
        driver_reference_sha256=canonical_sha256(failure_reference),
        recovery_evidence=loaded.evidence.to_document(),
        recovery_evidence_sha256=loaded.sha256,
        tolerance=TolerancePolicy(
            timestamp_absolute_ns=0.0,
            timestamp_relative=0.0,
            continuous_relative=0.0,
            continuous_absolute=0.0,
            integer_absolute=0.0,
        ),
        artifact_bindings=_fault_artifact_bindings(session),
        checks=[
            VerificationCheck(
                category="artifact_binding",
                name="recovered manifest and health artifacts were rehashed",
                passed=True,
                absolute_error=0.0,
                relative_error=0.0,
            ),
            VerificationCheck(
                category="fault_publication",
                name=(
                    "fault failed without changing the artifact root and published "
                    "only reserved recovery evidence"
                ),
                passed=True,
                absolute_error=0.0,
                relative_error=0.0,
            ),
            VerificationCheck(
                category="health",
                name="subsequent Session health is VALID",
                passed=True,
                absolute_error=0.0,
                relative_error=0.0,
            ),
            VerificationCheck(
                category="recovery",
                name=(
                    f"{fault_operation} restored target and adapter state before a "
                    "new verified Session"
                ),
                passed=True,
                absolute_error=0.0,
                relative_error=0.0,
            ),
        ],
    )


def write_recovery_verification_receipt(
    failure: CommandFailure, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    """Persist and read back one immutable recovery receipt beside its evidence."""

    from verification_receipt import (
        load_verification_receipt,
        write_verification_receipt,
    )

    failure.recovery_root_snapshot.assert_unchanged()
    loaded_evidence = load_target_adapter_recovery_evidence(
        failure.recovery_evidence_path
    )
    if (
        loaded_evidence.sha256 != failure.recovery_evidence_sha256
        or loaded_evidence.evidence != failure.recovery_evidence
    ):
        raise RuntimeError(
            "target-adapter recovery evidence changed before receipt publication"
        )
    if failure.recovery_receipt_path.parent != failure.recovery_evidence_path.parent:
        raise RuntimeError("recovery receipt escaped its harness reservation")
    validated_receipt = load_verification_receipt(receipt)
    expected_binding = {
        "sha256": failure.recovery_evidence_sha256,
        "document": failure.recovery_evidence.to_document(),
    }
    if validated_receipt.get("recovery_evidence") != expected_binding:
        raise RuntimeError(
            "recovery receipt does not bind this reservation's recovery evidence"
        )
    write_verification_receipt(validated_receipt, failure.recovery_receipt_path)
    loaded_receipt = load_verification_receipt(failure.recovery_receipt_path)
    if loaded_receipt != validated_receipt:
        raise RuntimeError("persisted recovery receipt differs from its source")
    failure.recovery_root_snapshot.assert_only_added(
        failure.recovery_receipt_path,
        _sha256_file(failure.recovery_receipt_path),
    )
    return loaded_receipt


def verify_native_differential(
    driver_result: dict[str, Any],
    session: VerifiedSession,
    *,
    tick_ns: float,
) -> dict[str, Any]:
    """Compare native function statistics and Task/ISR CPU metrics."""

    if driver_result.get("session_id") != session.session_id:
        raise AssertionError("native statistics belong to a different session")
    native = _parse_native_statistics(driver_result)
    t32perf = _extract_t32perf_statistics(
        session, selected_activations=native.function_activations
    )
    _require_same_metric_ids("functions", native.functions, t32perf.functions)
    for metric_id, native_metric in native.functions.items():
        actual = t32perf.functions[metric_id]
        _compare_count("functions", metric_id, native_metric.count, actual.count)
        for field_name in (
            "total_time_ns",
            "self_time_ns",
            "min_time_ns",
            "max_time_ns",
            "average_time_ns",
        ):
            _compare_time(
                "functions",
                metric_id,
                field_name,
                getattr(native_metric, field_name),
                getattr(actual, field_name),
                tick_ns,
            )

    for category, native_rows, actual_rows in (
        ("tasks", native.tasks, t32perf.tasks),
        ("isrs", native.isrs, t32perf.isrs),
    ):
        _require_same_metric_ids(category, native_rows, actual_rows)
        for metric_id, native_metric in native_rows.items():
            actual = actual_rows[metric_id]
            _compare_count(category, metric_id, native_metric.count, actual.count)
            _compare_time(
                category,
                metric_id,
                "time_ns",
                native_metric.time_ns,
                actual.time_ns,
                tick_ns,
            )

    _compare_context_switch_sequence(
        native.context_switches, t32perf.context_switches, tick_ns=tick_ns
    )
    _compare_interrupt_sequence(native.interrupts, t32perf.interrupts, tick_ns=tick_ns)
    _compare_function_activations(
        native.function_activations,
        t32perf.function_activations,
        tick_ns=tick_ns,
    )
    return _build_native_timeline_receipt(
        driver_result,
        session,
        native,
        t32perf,
        tick_ns=tick_ns,
    )


def _build_native_timeline_receipt(
    driver_result: dict[str, Any],
    session: VerifiedSession,
    native: DifferentialStatistics,
    actual: DifferentialStatistics,
    *,
    tick_ns: float,
) -> dict[str, Any]:
    from verification_receipt import (
        TolerancePolicy,
        VerificationCheck,
        build_verification_receipt,
        canonical_sha256,
    )

    function_pairs = [
        (getattr(expected, field), getattr(actual.functions[metric_id], field))
        for metric_id, expected in native.functions.items()
        for field in (
            "total_time_ns",
            "self_time_ns",
            "min_time_ns",
            "max_time_ns",
            "average_time_ns",
        )
    ]
    task_pairs = [
        (expected.time_ns, actual.tasks[metric_id].time_ns)
        for metric_id, expected in native.tasks.items()
    ]
    isr_pairs = [
        (expected.time_ns, actual.isrs[metric_id].time_ns)
        for metric_id, expected in native.isrs.items()
    ]
    context_switch_pairs = [
        (expected.ts_ns, observed.ts_ns)
        for expected, observed in zip(
            native.context_switches, actual.context_switches, strict=True
        )
    ]
    interrupt_pairs = [
        (expected.ts_ns, observed.ts_ns)
        for expected, observed in zip(native.interrupts, actual.interrupts, strict=True)
    ]
    activation_pairs = [
        (getattr(expected, field), getattr(observed, field))
        for expected, observed in zip(
            native.function_activations, actual.function_activations, strict=True
        )
        for field in (
            "start_ns",
            "end_ns",
            "elapsed_ns",
            "preempted_ns",
            "active_ns",
            "self_active_ns",
        )
    ]

    def check(
        category: str, name: str, pairs: list[tuple[float, float]]
    ) -> VerificationCheck:
        absolute, relative = _maximum_numeric_error(pairs)
        return VerificationCheck(
            category=category,
            name=name,
            passed=True,
            absolute_error=absolute,
            relative_error=relative,
        )

    checks = [
        VerificationCheck(
            category="artifact_binding",
            name="required timeline artifacts were rehashed",
            passed=True,
            absolute_error=0.0,
            relative_error=0.0,
        ),
        check(
            "function", f"{len(native.functions)} function aggregates", function_pairs
        ),
        check("task", f"{len(native.tasks)} Task aggregates", task_pairs),
        check("isr", f"{len(native.isrs)} ISR aggregates", isr_pairs),
        check(
            "context_switch",
            f"{len(native.context_switches)} RTOS switch events",
            context_switch_pairs,
        ),
        check(
            "interrupt",
            f"{len(native.interrupts)} nested ISR edges",
            interrupt_pairs,
        ),
        check(
            "function_activation",
            f"{len(native.function_activations)} Task/ISR activations",
            activation_pairs,
        ),
    ]
    statistics = _required_object(driver_result, "statistics", "native driver result")
    return build_verification_receipt(
        kind="native_timeline",
        board_id=_session_board_id(session),
        session_id=session.session_id,
        driver_reference_sha256=canonical_sha256(statistics),
        tolerance=TolerancePolicy(
            timestamp_absolute_ns=tick_ns,
            timestamp_relative=0.005,
            continuous_relative=0.005,
            continuous_absolute=tick_ns,
        ),
        artifact_bindings=_timeline_artifact_bindings(session),
        checks=checks,
    )


def _maximum_numeric_error(pairs: list[tuple[float, float]]) -> tuple[float, float]:
    maximum_absolute = 0.0
    maximum_relative = 0.0
    for expected, actual in pairs:
        absolute = abs(actual - expected)
        relative = 0.0 if expected == 0 else absolute / abs(expected)
        maximum_absolute = max(maximum_absolute, absolute)
        maximum_relative = max(maximum_relative, relative)
    return maximum_absolute, maximum_relative


def _timeline_artifact_bindings(
    session: VerifiedSession,
) -> dict[str, tuple[str | None, str]]:
    manifest_path = session.path / "manifest.json"
    manifest_sha256 = _sha256_file(manifest_path)
    if _load_json_object(manifest_path, "manifest") != session.manifest:
        raise RuntimeError("manifest changed after HIL Session verification")
    bindings: dict[str, tuple[str | None, str]] = {"manifest": (None, manifest_sha256)}
    for role, artifact_id in (
        ("health", HEALTH_ARTIFACT_ID),
        ("observations", OBSERVATIONS_ARTIFACT_ID),
        ("analysis_summary", SUMMARY_ARTIFACT_ID),
        ("hotspots", HOTSPOTS_ARTIFACT_ID),
        ("derived", DERIVED_ARTIFACT_ID),
    ):
        artifact = session.artifact(artifact_id)
        actual_sha256 = _sha256_file(artifact.path)
        if actual_sha256 != artifact.sha256:
            raise RuntimeError(
                f"artifact `{artifact_id}` changed after HIL Session verification"
            )
        bindings[role] = (artifact_id, actual_sha256)
    return bindings


def _session_board_id(session: VerifiedSession) -> str:
    capture = _required_object(session.manifest, "capture", "manifest")
    target = _required_object(capture, "target", "manifest.capture")
    return _required_string(target, "board", "manifest.capture.target")


def _compare_context_switch_sequence(
    native: tuple[ContextSwitchReference, ...],
    actual: tuple[ContextSwitchReference, ...],
    *,
    tick_ns: float,
) -> None:
    if len(native) != len(actual):
        raise AssertionError(
            "context-switch sequence length differs: "
            f"native={len(native)}, t32perf={len(actual)}"
        )
    for index, (expected, observed) in enumerate(zip(native, actual, strict=True)):
        _compare_time(
            "context_switches",
            str(index),
            "ts_ns",
            expected.ts_ns,
            observed.ts_ns,
            tick_ns,
        )
        for field_name in (
            "core_id",
            "previous_context_id",
            "next_context_id",
            "next_name",
            "next_kind",
            "next_priority",
        ):
            expected_value = getattr(expected, field_name)
            observed_value = getattr(observed, field_name)
            if expected_value != observed_value:
                raise AssertionError(
                    f"context switch {index} {field_name} differs: "
                    f"native={expected_value!r}, t32perf={observed_value!r}"
                )


def _compare_interrupt_sequence(
    native: tuple[InterruptReference, ...],
    actual: tuple[InterruptReference, ...],
    *,
    tick_ns: float,
) -> None:
    if len(native) != len(actual):
        raise AssertionError(
            "interrupt sequence length differs: "
            f"native={len(native)}, t32perf={len(actual)}"
        )
    for index, (expected, observed) in enumerate(zip(native, actual, strict=True)):
        _compare_time(
            "interrupts",
            str(index),
            "ts_ns",
            expected.ts_ns,
            observed.ts_ns,
            tick_ns,
        )
        for field_name in (
            "event",
            "core_id",
            "interrupt_id",
            "interrupt_name",
            "priority",
            "activation_id",
            "nesting_depth",
            "parent_activation_id",
            "preempted_task_id",
        ):
            expected_value = getattr(expected, field_name)
            observed_value = getattr(observed, field_name)
            if expected_value != observed_value:
                raise AssertionError(
                    f"interrupt event {index} {field_name} differs: "
                    f"native={expected_value!r}, t32perf={observed_value!r}"
                )


def _compare_function_activations(
    native: tuple[FunctionActivationReference, ...],
    actual: tuple[FunctionActivationReference, ...],
    *,
    tick_ns: float,
) -> None:
    if len(native) != len(actual):
        raise AssertionError(
            "function activation reference length differs: "
            f"native={len(native)}, t32perf={len(actual)}"
        )
    for index, (expected, observed) in enumerate(zip(native, actual, strict=True)):
        for field_name in (
            "start_ns",
            "end_ns",
            "elapsed_ns",
            "preempted_ns",
            "active_ns",
            "self_active_ns",
        ):
            _compare_time(
                "function_activations",
                str(index),
                field_name,
                getattr(expected, field_name),
                getattr(observed, field_name),
                tick_ns,
            )
        for field_name in (
            "source_id",
            "source_seq_start",
            "source_seq_end",
            "function_id",
            "core_id",
            "context_id",
            "context_kind",
        ):
            expected_value = getattr(expected, field_name)
            observed_value = getattr(observed, field_name)
            if expected_value != observed_value:
                raise AssertionError(
                    f"function activation {index} {field_name} differs: "
                    f"native={expected_value!r}, t32perf={observed_value!r}"
                )


def _require_same_metric_ids(
    category: str,
    native_rows: Mapping[str, object],
    t32perf_rows: Mapping[str, object],
) -> None:
    if native_rows.keys() == t32perf_rows.keys():
        return
    missing = sorted(native_rows.keys() - t32perf_rows.keys())
    unexpected = sorted(t32perf_rows.keys() - native_rows.keys())
    raise AssertionError(
        f"{category} IDs differ; missing from T32Perf={missing}, "
        f"unexpected in T32Perf={unexpected}"
    )


def _compare_count(
    category: str,
    metric_id: str,
    native_count: int,
    actual_count: int,
) -> None:
    if actual_count != native_count:
        raise AssertionError(
            f"{category} `{metric_id}` count differs: "
            f"native={native_count}, t32perf={actual_count}"
        )


def _compare_time(
    category: str,
    metric_id: str,
    field_name: str,
    native_time_ns: float,
    actual_time_ns: float,
    tick_ns: float,
) -> None:
    tolerance = max(abs(native_time_ns) * 0.005, tick_ns)
    error = abs(actual_time_ns - native_time_ns)
    if error > tolerance:
        raise AssertionError(
            f"{category} `{metric_id}` {field_name} differs by {error} ns: "
            f"native={native_time_ns}, t32perf={actual_time_ns}, "
            f"tolerance={tolerance}"
        )


def _extract_t32perf_statistics(
    session: VerifiedSession,
    *,
    selected_activations: tuple[FunctionActivationReference, ...],
) -> DifferentialStatistics:
    health = session.read_json_artifact(HEALTH_ARTIFACT_ID)
    if (
        health.get("schema") != "t32perf.health/v1"
        or health.get("session_id") != session.session_id
        or health.get("verdict") != "VALID"
    ):
        raise RuntimeError("native differential requires a VALID v1 health artifact")
    hotspots = session.read_json_artifact(HOTSPOTS_ARTIFACT_ID)
    if (
        hotspots.get("schema") != "t32perf.hotspots/v1"
        or hotspots.get("session_id") != session.session_id
    ):
        raise RuntimeError(
            "native differential requires a Session-owned v1 hotspots artifact"
        )
    summary_document = session.read_json_artifact(SUMMARY_ARTIFACT_ID)
    if summary_document.get("schema") != "t32perf.analysis-summary/v1":
        raise RuntimeError(
            "analysis-summary artifact does not declare t32perf.analysis-summary/v1"
        )
    if summary_document.get("health_verdict") != "VALID":
        raise RuntimeError("native differential requires a VALID analysis-summary")
    if summary_document.get("session_id") != session.session_id:
        raise RuntimeError("analysis-summary belongs to another Session")
    _require_exact_native_evidence(
        session,
        health=health,
        hotspots=hotspots,
        summary=summary_document,
    )
    summary = _required_object(
        summary_document, "quantitative", "analysis-summary artifact"
    )

    function_totals: dict[str, dict[str, float | int]] = {}
    function_rows = hotspots.get("functions")
    if not isinstance(function_rows, list):
        raise RuntimeError("hotspots.functions must be an array")
    for row in function_rows:
        if not isinstance(row, dict):
            raise RuntimeError("hotspots function row must be an object")
        metric_id = _required_string(row, "function_id", "hotspots function")
        count = _required_nonnegative_int(row, "count", "hotspots function")
        if count == 0:
            raise RuntimeError("hotspots function count must be positive")
        total_time_ns = _required_nonnegative_int(
            row, "inclusive_active_ns", "hotspots function"
        )
        self_time_ns = _required_nonnegative_int(
            row, "self_active_ns", "hotspots function"
        )
        min_time_ns = _required_nonnegative_int(
            row, "min_active_ns", "hotspots function"
        )
        max_time_ns = _required_nonnegative_int(
            row, "max_active_ns", "hotspots function"
        )
        average_time_ns = _required_nonnegative_int(
            row, "avg_active_ns", "hotspots function"
        )
        if self_time_ns > total_time_ns:
            raise RuntimeError(
                f"hotspots function `{metric_id}` self_active_ns exceeds inclusive_active_ns"
            )
        if not min_time_ns <= average_time_ns <= max_time_ns:
            raise RuntimeError(
                f"hotspots function `{metric_id}` has inconsistent min/average/max"
            )
        expected_average = total_time_ns // count
        if average_time_ns != expected_average:
            raise RuntimeError(
                f"hotspots function `{metric_id}` avg_active_ns is {average_time_ns}, "
                f"expected integer mean {expected_average}"
            )
        aggregate = function_totals.setdefault(
            metric_id,
            {
                "count": 0,
                "total_time_ns": 0.0,
                "self_time_ns": 0.0,
                "min_time_ns": min_time_ns,
                "max_time_ns": max_time_ns,
            },
        )
        aggregate["count"] += count
        aggregate["total_time_ns"] += total_time_ns
        aggregate["self_time_ns"] += self_time_ns
        aggregate["min_time_ns"] = min(float(aggregate["min_time_ns"]), min_time_ns)
        aggregate["max_time_ns"] = max(float(aggregate["max_time_ns"]), max_time_ns)

    task_times: dict[str, float] = {}
    isr_times: dict[str, float] = {}
    context_rows = summary.get("context_cpu")
    if not isinstance(context_rows, list):
        raise RuntimeError("analysis-summary.context_cpu must be an array")
    for row in context_rows:
        if not isinstance(row, dict):
            raise RuntimeError("context_cpu row must be an object")
        metric_id = _required_string(row, "context_id", "context_cpu row")
        kind = _required_string(row, "kind", "context_cpu row")
        active_ns = _required_nonnegative_number(row, "active_ns", "context_cpu row")
        destination = (
            task_times if kind == "task" else isr_times if kind == "isr" else None
        )
        if destination is not None:
            destination[metric_id] = destination.get(metric_id, 0.0) + active_ns

    timeline = _extract_t32perf_timeline(session)

    functions = {
        metric_id: FunctionDifferentialMetric(
            count=int(values["count"]),
            total_time_ns=float(values["total_time_ns"]),
            self_time_ns=float(values["self_time_ns"]),
            min_time_ns=float(values["min_time_ns"]),
            max_time_ns=float(values["max_time_ns"]),
            average_time_ns=float(values["total_time_ns"]) / int(values["count"]),
        )
        for metric_id, values in function_totals.items()
    }
    tasks = {
        metric_id: DifferentialMetric(
            count=timeline.task_counts.get(metric_id, 0),
            time_ns=task_times.get(metric_id, 0.0),
        )
        for metric_id in timeline.task_counts.keys() | task_times.keys()
    }
    isrs = {
        metric_id: DifferentialMetric(
            count=timeline.isr_counts.get(metric_id, 0),
            time_ns=isr_times.get(metric_id, 0.0),
        )
        for metric_id in timeline.isr_counts.keys() | isr_times.keys()
    }
    result = DifferentialStatistics(
        functions=functions,
        tasks=tasks,
        isrs=isrs,
        context_switches=timeline.context_switches,
        interrupts=timeline.interrupts,
        function_activations=_extract_t32perf_function_activations(
            session,
            timeline.context_definitions,
            selected_activations,
        ),
    )
    for category, rows in (
        ("functions", result.functions),
        ("tasks", result.tasks),
        ("isrs", result.isrs),
    ):
        if not rows:
            raise RuntimeError(f"T32Perf {category} statistics are empty")
    return result


def _require_exact_native_evidence(
    session: VerifiedSession,
    *,
    health: dict[str, Any],
    hotspots: dict[str, Any],
    summary: dict[str, Any],
) -> None:
    capture = _required_object(session.manifest, "capture", "manifest")
    capabilities = _required_object(capture, "capabilities", "manifest.capture")
    for field in ("function_events", "context_switches", "interrupt_events"):
        _require_exact_support(capabilities, field, "manifest.capture.capabilities")

    if hotspots.get("quality") != "exact":
        raise RuntimeError("native differential requires exact hotspots quality")
    function_rows = hotspots.get("functions")
    if not isinstance(function_rows, list):
        raise RuntimeError("hotspots.functions must be an array")
    for index, row in enumerate(function_rows):
        if not isinstance(row, dict) or row.get("quality") != "exact":
            raise RuntimeError(
                f"native differential requires exact hotspots.functions[{index}] quality"
            )

    summary_support = _required_object(summary, "metric_support", "analysis-summary")
    health_support = _required_object(health, "metric_support", "health artifact")
    if summary_support != health_support:
        raise RuntimeError("analysis-summary metric_support differs from health")
    for field in (
        "function_timeline",
        "call_count",
        "elapsed",
        "active",
        "self",
        "task_timeline",
        "isr_timeline",
    ):
        _require_exact_support(
            summary_support, field, "analysis-summary.metric_support"
        )


def _require_exact_support(document: dict[str, Any], field: str, label: str) -> None:
    entry = _required_object(document, field, label)
    if entry.get("support") != "exact":
        raise RuntimeError(f"{label}.{field}.support must be exact")
    reasons = entry.get("reasons")
    if not isinstance(reasons, list) or any(
        not isinstance(reason, str) or not reason.strip() for reason in reasons
    ):
        raise RuntimeError(f"{label}.{field}.reasons must be an array of strings")


def _extract_t32perf_timeline(session: VerifiedSession) -> _ExtractedTimeline:
    contexts: dict[str, dict[str, Any]] = {}
    active_contexts: dict[int, str] = {}
    interrupt_stacks: dict[int, list[tuple[str, str, int, str | None]]] = {}
    context_switches: list[ContextSwitchReference] = []
    interrupts: list[InterruptReference] = []
    task_counts: dict[str, int] = {}
    isr_counts: dict[str, int] = {}
    observed_context_kinds: set[str] = set()
    maximum_interrupt_depth = 0
    observed_preempted_task = False

    for record in session.iter_ndjson_artifact(OBSERVATIONS_ARTIFACT_ID):
        tagged_session = record.get("session_id")
        if tagged_session is not None and tagged_session != session.session_id:
            raise RuntimeError(
                f"observations artifact contains session {tagged_session!r}, "
                f"expected {session.session_id!r}"
            )

        entries: list[dict[str, Any]] = []
        if record.get("type") == "DefineContext":
            entries.append(record)
        raw_entries = record.get("entries")
        if isinstance(raw_entries, list):
            entries.extend(entry for entry in raw_entries if isinstance(entry, dict))
        for entry in entries:
            if entry.get("type") != "DefineContext":
                continue
            context_id = _required_string(entry, "id", "DefineContext record")
            if context_id in contexts:
                raise RuntimeError(f"duplicate DefineContext ID `{context_id}`")
            kind = _required_string(entry, "kind", "DefineContext record")
            name = _required_string(entry, "name", "DefineContext record")
            core_id = entry.get("core_id")
            if core_id is not None and (
                isinstance(core_id, bool) or not isinstance(core_id, int) or core_id < 0
            ):
                raise RuntimeError(
                    f"DefineContext `{context_id}` core_id must be a non-negative integer"
                )
            priority = entry.get("priority")
            if priority is not None and (
                isinstance(priority, bool) or not isinstance(priority, int)
            ):
                raise RuntimeError(
                    f"DefineContext `{context_id}` priority must be an integer"
                )
            contexts[context_id] = {
                "kind": kind,
                "name": name,
                "core_id": core_id,
                "priority": priority,
            }

        event_type = record.get("type")
        if event_type == "ContextSwitch":
            if len(context_switches) >= MAX_NATIVE_TIMELINE_EVENTS:
                raise RuntimeError(
                    "T32Perf context-switch verification exceeds the bounded "
                    f"{MAX_NATIVE_TIMELINE_EVENTS}-event reference"
                )
            core_id = _required_nonnegative_int(
                record, "core_id", "ContextSwitch observation"
            )
            next_context_id = _required_string(
                record, "next_context_id", "ContextSwitch observation"
            )
            definition = contexts.get(next_context_id)
            if definition is None:
                raise RuntimeError(
                    f"ContextSwitch references undefined context `{next_context_id}`"
                )
            next_kind = definition["kind"]
            if next_kind not in {"task", "idle"}:
                raise RuntimeError(
                    f"ContextSwitch next context `{next_context_id}` is not Task or idle"
                )
            next_priority = definition["priority"]
            if not isinstance(next_priority, int) or isinstance(next_priority, bool):
                raise RuntimeError(
                    f"ContextSwitch context `{next_context_id}` has no integer priority"
                )
            affinity = definition["core_id"]
            if affinity is not None and affinity != core_id:
                raise RuntimeError(
                    f"ContextSwitch context `{next_context_id}` affinity {affinity} "
                    f"does not match event core {core_id}"
                )
            tracked_previous = active_contexts.get(core_id)
            if "previous_context_id" in record:
                raise RuntimeError(
                    "ContextSwitch observation uses non-canonical `previous_context_id`; "
                    "expected `prev_context_id`"
                )
            declared_previous = _nullable_string(
                record, "prev_context_id", "ContextSwitch observation"
            )
            if tracked_previous is None and declared_previous is not None:
                previous_definition = contexts.get(declared_previous)
                if previous_definition is None or previous_definition["kind"] not in {
                    "task",
                    "idle",
                }:
                    raise RuntimeError(
                        "the first ContextSwitch references an undefined Task/idle "
                        f"prev context `{declared_previous}`"
                    )
                previous_affinity = previous_definition["core_id"]
                if previous_affinity is not None and previous_affinity != core_id:
                    raise RuntimeError(
                        f"the first ContextSwitch prev context `{declared_previous}` "
                        f"affinity {previous_affinity} does not match event core {core_id}"
                    )
            if tracked_previous is not None and declared_previous != tracked_previous:
                raise RuntimeError(
                    f"ContextSwitch prev context `{declared_previous}` does not match "
                    f"host-reconstructed `{tracked_previous}` on core {core_id}"
                )
            context_switches.append(
                ContextSwitchReference(
                    ts_ns=float(
                        _required_int(record, "ts_ns", "ContextSwitch observation")
                    ),
                    core_id=core_id,
                    previous_context_id=declared_previous,
                    next_context_id=next_context_id,
                    next_name=definition["name"],
                    next_kind=next_kind,
                    next_priority=next_priority,
                )
            )
            active_contexts[core_id] = next_context_id
            observed_context_kinds.add(next_kind)
            if next_kind == "task":
                task_counts[next_context_id] = task_counts.get(next_context_id, 0) + 1

        elif event_type in {"InterruptEnter", "InterruptExit"}:
            if len(interrupts) >= MAX_NATIVE_TIMELINE_EVENTS:
                raise RuntimeError(
                    "T32Perf interrupt verification exceeds the bounded "
                    f"{MAX_NATIVE_TIMELINE_EVENTS}-event reference"
                )
            label = f"{event_type} observation"
            core_id = _required_nonnegative_int(record, "core_id", label)
            interrupt_id = _required_string(record, "interrupt_id", label)
            activation_id = _required_string(record, "activation_id", label)
            definition = contexts.get(interrupt_id)
            if definition is None or definition["kind"] != "isr":
                raise RuntimeError(
                    f"{event_type} references undefined ISR context `{interrupt_id}`"
                )
            affinity = definition["core_id"]
            if affinity is not None and affinity != core_id:
                raise RuntimeError(
                    f"ISR `{interrupt_id}` core affinity does not match event core {core_id}"
                )
            raw_priority = record.get("priority", definition["priority"])
            if isinstance(raw_priority, bool) or not isinstance(raw_priority, int):
                raise RuntimeError(
                    f"{event_type} `{interrupt_id}` has no integer priority"
                )
            scheduled_context_id = active_contexts.get(core_id)
            if scheduled_context_id is None:
                raise RuntimeError(
                    f"{event_type} on core {core_id} has no scheduled Task/idle context"
                )
            scheduled = contexts.get(scheduled_context_id)
            if scheduled is None or scheduled["kind"] not in {"task", "idle"}:
                raise RuntimeError(
                    f"{event_type} scheduled context `{scheduled_context_id}` is not Task/idle"
                )
            stack = interrupt_stacks.setdefault(core_id, [])
            if event_type == "InterruptEnter":
                parent_activation_id = stack[-1][1] if stack else None
                preempted_task_id = (
                    scheduled_context_id if scheduled["kind"] == "task" else None
                )
                stack.append(
                    (interrupt_id, activation_id, raw_priority, preempted_task_id)
                )
                nesting_depth = len(stack)
                maximum_interrupt_depth = max(maximum_interrupt_depth, nesting_depth)
                observed_preempted_task |= preempted_task_id is not None
                isr_counts[interrupt_id] = isr_counts.get(interrupt_id, 0) + 1
                event = "enter"
            else:
                if not stack:
                    raise RuntimeError(
                        f"InterruptExit `{interrupt_id}` has no open activation on core {core_id}"
                    )
                open_interrupt, open_activation, open_priority, preempted_task_id = (
                    stack[-1]
                )
                if (interrupt_id, activation_id) != (open_interrupt, open_activation):
                    raise RuntimeError(
                        f"InterruptExit `{interrupt_id}/{activation_id}` does not close "
                        f"top activation `{open_interrupt}/{open_activation}`"
                    )
                if raw_priority != open_priority:
                    raise RuntimeError(
                        f"InterruptExit `{interrupt_id}` priority differs from its enter"
                    )
                nesting_depth = len(stack)
                parent_activation_id = stack[-2][1] if len(stack) > 1 else None
                stack.pop()
                event = "exit"
            interrupts.append(
                InterruptReference(
                    event=event,
                    ts_ns=float(_required_int(record, "ts_ns", label)),
                    core_id=core_id,
                    interrupt_id=interrupt_id,
                    interrupt_name=definition["name"],
                    priority=raw_priority,
                    activation_id=activation_id,
                    nesting_depth=nesting_depth,
                    parent_activation_id=parent_activation_id,
                    preempted_task_id=preempted_task_id,
                )
            )

    if observed_context_kinds != {"task", "idle"}:
        raise RuntimeError(
            "RTOS reference requires observed Task and idle context switches"
        )
    if maximum_interrupt_depth < 2:
        raise RuntimeError("ISR reference requires at least one nested interrupt")
    if not observed_preempted_task:
        raise RuntimeError("ISR reference has no interrupt that preempts a Task")
    unclosed = {
        core_id: [
            (interrupt_id, activation_id) for interrupt_id, activation_id, _, _ in stack
        ]
        for core_id, stack in interrupt_stacks.items()
        if stack
    }
    if unclosed:
        raise RuntimeError(f"ISR reference has unclosed activations: {unclosed}")
    return _ExtractedTimeline(
        context_switches=tuple(context_switches),
        interrupts=tuple(interrupts),
        task_counts=task_counts,
        isr_counts=isr_counts,
        context_definitions=contexts,
    )


def _extract_t32perf_function_activations(
    session: VerifiedSession,
    contexts: dict[str, dict[str, Any]],
    selected: tuple[FunctionActivationReference, ...],
) -> tuple[FunctionActivationReference, ...]:
    requested = {
        (row.source_id, row.source_seq_start, row.source_seq_end) for row in selected
    }
    found: dict[tuple[str, int, int], FunctionActivationReference] = {}
    header_seen = False
    for index, record in enumerate(
        session.iter_ndjson_artifact(DERIVED_ARTIFACT_ID), start=1
    ):
        if index == 1:
            if (
                record.get("schema") != "t32perf.derived-stream/v1"
                or record.get("session_id") != session.session_id
                or record.get("encoding") != "ndjson"
            ):
                raise RuntimeError("derived artifact has an invalid stream header")
            header_seen = True
            continue
        source_id = _required_string(record, "source_id", "derived function span")
        source_seq_start = record.get("source_seq_start")
        source_seq_end = record.get("source_seq_end")
        if (
            isinstance(source_seq_start, bool)
            or not isinstance(source_seq_start, int)
            or source_seq_start < 0
            or isinstance(source_seq_end, bool)
            or not isinstance(source_seq_end, int)
            or source_seq_end < source_seq_start
        ):
            continue
        key = (source_id, source_seq_start, source_seq_end)
        if key not in requested:
            continue
        if key in found:
            raise RuntimeError(f"derived artifact duplicates selected activation {key}")
        context_id = _required_string(record, "context_id", "derived function span")
        definition = contexts.get(context_id)
        if definition is None or definition["kind"] not in {"task", "isr"}:
            raise RuntimeError(
                f"derived function span references undefined Task/ISR `{context_id}`"
            )
        start_ns = _required_int(record, "start_ns", "derived function span")
        end_ns = _required_int(record, "end_ns", "derived function span")
        elapsed_ns = _required_nonnegative_int(
            record, "elapsed_ns", "derived function span"
        )
        active_ns = _required_nonnegative_int(
            record, "active_ns", "derived function span"
        )
        self_active_ns = _required_nonnegative_int(
            record, "self_active_ns", "derived function span"
        )
        preempted_ns = _required_nonnegative_int(
            record, "preempted_ns", "derived function span"
        )
        if (
            end_ns < start_ns
            or elapsed_ns != end_ns - start_ns
            or active_ns + preempted_ns != elapsed_ns
            or self_active_ns > active_ns
        ):
            raise RuntimeError("derived function span has an invalid active interval")
        if record.get("quality") != "exact" or record.get("incomplete") is not False:
            raise RuntimeError(
                "selected derived function activation is not complete exact evidence"
            )
        found[key] = FunctionActivationReference(
            source_id=source_id,
            source_seq_start=source_seq_start,
            source_seq_end=source_seq_end,
            function_id=_required_string(
                record, "function_id", "derived function span"
            ),
            core_id=_required_nonnegative_int(
                record, "core_id", "derived function span"
            ),
            context_id=context_id,
            context_kind=definition["kind"],
            start_ns=float(start_ns),
            end_ns=float(end_ns),
            elapsed_ns=float(elapsed_ns),
            active_ns=float(active_ns),
            self_active_ns=float(self_active_ns),
            preempted_ns=float(preempted_ns),
        )
    if not header_seen:
        raise RuntimeError("derived artifact is empty")
    missing = requested - found.keys()
    if missing:
        raise RuntimeError(
            f"derived artifact omits selected function activations: {sorted(missing)}"
        )
    return tuple(
        found[(row.source_id, row.source_seq_start, row.source_seq_end)]
        for row in selected
    )


def _parse_native_statistics(
    driver_result: dict[str, Any],
) -> DifferentialStatistics:
    statistics = driver_result.get("statistics")
    if not isinstance(statistics, dict):
        raise RuntimeError("native driver result statistics must be an object")
    if statistics.get("schema") != "t32perf.hil-native-timeline-reference/v1":
        raise RuntimeError(
            "native statistics must declare t32perf.hil-native-timeline-reference/v1"
        )
    expected_fields = {
        "schema",
        "functions",
        "tasks",
        "isrs",
        "context_switches",
        "interrupts",
        "function_activations",
    }
    if set(statistics) != expected_fields:
        raise RuntimeError(
            "native statistics field set differs from the v1 timeline reference contract"
        )
    function_rows = statistics.get("functions")
    if not isinstance(function_rows, list) or not function_rows:
        raise RuntimeError("native statistics.functions must be a non-empty array")
    functions: dict[str, FunctionDifferentialMetric] = {}
    for raw in function_rows:
        if not isinstance(raw, dict):
            raise RuntimeError("native functions row must be an object")
        _require_exact_fields(
            raw,
            {
                "id",
                "count",
                "total_time_ns",
                "self_time_ns",
                "min_time_ns",
                "max_time_ns",
                "average_time_ns",
            },
            "native functions row",
        )
        metric_id = _required_string(raw, "id", "native functions row")
        if metric_id in functions:
            raise RuntimeError(f"duplicate native functions ID `{metric_id}`")
        count = _required_nonnegative_int(raw, "count", "native functions row")
        if count == 0:
            raise RuntimeError("native functions row count must be positive")
        metric = FunctionDifferentialMetric(
            count=count,
            total_time_ns=_required_nonnegative_number(
                raw, "total_time_ns", "native functions row"
            ),
            self_time_ns=_required_nonnegative_number(
                raw, "self_time_ns", "native functions row"
            ),
            min_time_ns=_required_nonnegative_number(
                raw, "min_time_ns", "native functions row"
            ),
            max_time_ns=_required_nonnegative_number(
                raw, "max_time_ns", "native functions row"
            ),
            average_time_ns=_required_nonnegative_number(
                raw, "average_time_ns", "native functions row"
            ),
        )
        if metric.self_time_ns > metric.total_time_ns:
            raise RuntimeError(
                f"native functions row `{metric_id}` self_time_ns exceeds total_time_ns"
            )
        if not metric.min_time_ns <= metric.average_time_ns <= metric.max_time_ns:
            raise RuntimeError(
                f"native functions row `{metric_id}` has inconsistent min/average/max"
            )
        functions[metric_id] = metric

    categories: dict[str, dict[str, DifferentialMetric]] = {}
    for category in ("tasks", "isrs"):
        raw_rows = statistics.get(category)
        if not isinstance(raw_rows, list) or not raw_rows:
            raise RuntimeError(
                f"native statistics.{category} must be a non-empty array"
            )
        rows: dict[str, DifferentialMetric] = {}
        for raw in raw_rows:
            if not isinstance(raw, dict):
                raise RuntimeError(f"native {category} row must be an object")
            _require_exact_fields(
                raw,
                {"id", "count", "time_ns"},
                f"native {category} row",
            )
            metric_id = _required_string(raw, "id", f"native {category} row")
            if metric_id in rows:
                raise RuntimeError(f"duplicate native {category} ID `{metric_id}`")
            rows[metric_id] = DifferentialMetric(
                count=_required_nonnegative_int(raw, "count", f"native {category} row"),
                time_ns=_required_nonnegative_number(
                    raw, "time_ns", f"native {category} row"
                ),
            )
        categories[category] = rows
    context_switches = _parse_native_context_switches(statistics)
    interrupts = _parse_native_interrupts(statistics)
    function_activations = _parse_native_function_activations(statistics)
    return DifferentialStatistics(
        functions=functions,
        tasks=categories["tasks"],
        isrs=categories["isrs"],
        context_switches=context_switches,
        interrupts=interrupts,
        function_activations=function_activations,
    )


def _parse_native_context_switches(
    statistics: dict[str, Any],
) -> tuple[ContextSwitchReference, ...]:
    raw_rows = statistics.get("context_switches")
    if (
        not isinstance(raw_rows, list)
        or not raw_rows
        or len(raw_rows) > MAX_NATIVE_TIMELINE_EVENTS
    ):
        raise RuntimeError(
            "native statistics.context_switches must contain "
            f"1..={MAX_NATIVE_TIMELINE_EVENTS} rows"
        )
    rows: list[ContextSwitchReference] = []
    active_contexts: dict[int, str] = {}
    observed_kinds: set[str] = set()
    for index, raw in enumerate(raw_rows):
        if not isinstance(raw, dict):
            raise RuntimeError("native context_switches row must be an object")
        label = f"native context_switches[{index}]"
        _require_exact_fields(
            raw,
            {
                "ts_ns",
                "core_id",
                "previous_context_id",
                "next_context_id",
                "next_name",
                "next_kind",
                "next_priority",
            },
            label,
        )
        core_id = _required_nonnegative_int(raw, "core_id", label)
        previous_context_id = _nullable_string(raw, "previous_context_id", label)
        tracked_previous = active_contexts.get(core_id)
        if tracked_previous is not None and previous_context_id != tracked_previous:
            raise RuntimeError(
                f"{label}.previous_context_id does not match the native sequence"
            )
        next_context_id = _required_string(raw, "next_context_id", label)
        next_kind = _required_string(raw, "next_kind", label)
        if next_kind not in {"task", "idle"}:
            raise RuntimeError(f"{label}.next_kind must be task or idle")
        row = ContextSwitchReference(
            ts_ns=_required_nonnegative_number(raw, "ts_ns", label),
            core_id=core_id,
            previous_context_id=previous_context_id,
            next_context_id=next_context_id,
            next_name=_required_string(raw, "next_name", label),
            next_kind=next_kind,
            next_priority=_required_int(raw, "next_priority", label),
        )
        rows.append(row)
        active_contexts[core_id] = next_context_id
        observed_kinds.add(next_kind)
    if observed_kinds != {"task", "idle"}:
        raise RuntimeError(
            "native context-switch reference must contain Task and idle switches"
        )
    return tuple(rows)


def _parse_native_interrupts(
    statistics: dict[str, Any],
) -> tuple[InterruptReference, ...]:
    raw_rows = statistics.get("interrupts")
    if (
        not isinstance(raw_rows, list)
        or not raw_rows
        or len(raw_rows) > MAX_NATIVE_TIMELINE_EVENTS
    ):
        raise RuntimeError(
            "native statistics.interrupts must contain "
            f"1..={MAX_NATIVE_TIMELINE_EVENTS} rows"
        )
    rows: list[InterruptReference] = []
    stacks: dict[int, list[InterruptReference]] = {}
    maximum_depth = 0
    observed_preempted_task = False
    for index, raw in enumerate(raw_rows):
        if not isinstance(raw, dict):
            raise RuntimeError("native interrupts row must be an object")
        label = f"native interrupts[{index}]"
        _require_exact_fields(
            raw,
            {
                "event",
                "ts_ns",
                "core_id",
                "interrupt_id",
                "interrupt_name",
                "priority",
                "activation_id",
                "nesting_depth",
                "parent_activation_id",
                "preempted_task_id",
            },
            label,
        )
        event = _required_string(raw, "event", label)
        if event not in {"enter", "exit"}:
            raise RuntimeError(f"{label}.event must be enter or exit")
        core_id = _required_nonnegative_int(raw, "core_id", label)
        row = InterruptReference(
            event=event,
            ts_ns=_required_nonnegative_number(raw, "ts_ns", label),
            core_id=core_id,
            interrupt_id=_required_string(raw, "interrupt_id", label),
            interrupt_name=_required_string(raw, "interrupt_name", label),
            priority=_required_int(raw, "priority", label),
            activation_id=_required_string(raw, "activation_id", label),
            nesting_depth=_required_nonnegative_int(raw, "nesting_depth", label),
            parent_activation_id=_nullable_string(raw, "parent_activation_id", label),
            preempted_task_id=_nullable_string(raw, "preempted_task_id", label),
        )
        if row.nesting_depth == 0:
            raise RuntimeError(f"{label}.nesting_depth must be positive")
        stack = stacks.setdefault(core_id, [])
        expected_parent = stack[-1].activation_id if stack else None
        if event == "enter":
            expected_depth = len(stack) + 1
            if (
                row.nesting_depth != expected_depth
                or row.parent_activation_id != expected_parent
            ):
                raise RuntimeError(f"{label} has inconsistent native ISR nesting")
            stack.append(row)
            maximum_depth = max(maximum_depth, row.nesting_depth)
            observed_preempted_task |= row.preempted_task_id is not None
        else:
            if not stack:
                raise RuntimeError(f"{label} exits without an open native ISR")
            opened = stack[-1]
            if (
                row.nesting_depth != len(stack)
                or row.parent_activation_id
                != (stack[-2].activation_id if len(stack) > 1 else None)
                or row.interrupt_id != opened.interrupt_id
                or row.activation_id != opened.activation_id
                or row.priority != opened.priority
                or row.preempted_task_id != opened.preempted_task_id
            ):
                raise RuntimeError(f"{label} does not close the top native ISR")
            stack.pop()
        rows.append(row)
    if any(stacks.values()):
        raise RuntimeError("native interrupt reference has unclosed activations")
    if maximum_depth < 2:
        raise RuntimeError("native interrupt reference requires nested ISR evidence")
    if not observed_preempted_task:
        raise RuntimeError("native interrupt reference has no preempted Task")
    return tuple(rows)


def _parse_native_function_activations(
    statistics: dict[str, Any],
) -> tuple[FunctionActivationReference, ...]:
    raw_rows = statistics.get("function_activations")
    if (
        not isinstance(raw_rows, list)
        or not raw_rows
        or len(raw_rows) > MAX_NATIVE_FUNCTION_ACTIVATIONS
    ):
        raise RuntimeError(
            "native statistics.function_activations must contain "
            f"1..={MAX_NATIVE_FUNCTION_ACTIVATIONS} rows"
        )
    rows: list[FunctionActivationReference] = []
    keys: set[tuple[str, int, int]] = set()
    observed_context_kinds: set[str] = set()
    observed_preempted_task_function = False
    for index, raw in enumerate(raw_rows):
        if not isinstance(raw, dict):
            raise RuntimeError("native function_activations row must be an object")
        label = f"native function_activations[{index}]"
        _require_exact_fields(
            raw,
            {
                "source_id",
                "source_seq_start",
                "source_seq_end",
                "function_id",
                "core_id",
                "context_id",
                "context_kind",
                "start_ns",
                "end_ns",
                "elapsed_ns",
                "active_ns",
                "self_active_ns",
                "preempted_ns",
            },
            label,
        )
        context_kind = _required_string(raw, "context_kind", label)
        if context_kind not in {"task", "isr"}:
            raise RuntimeError(f"{label}.context_kind must be task or isr")
        row = FunctionActivationReference(
            source_id=_required_string(raw, "source_id", label),
            source_seq_start=_required_nonnegative_int(raw, "source_seq_start", label),
            source_seq_end=_required_nonnegative_int(raw, "source_seq_end", label),
            function_id=_required_string(raw, "function_id", label),
            core_id=_required_nonnegative_int(raw, "core_id", label),
            context_id=_required_string(raw, "context_id", label),
            context_kind=context_kind,
            start_ns=_required_nonnegative_number(raw, "start_ns", label),
            end_ns=_required_nonnegative_number(raw, "end_ns", label),
            elapsed_ns=_required_nonnegative_number(raw, "elapsed_ns", label),
            active_ns=_required_nonnegative_number(raw, "active_ns", label),
            self_active_ns=_required_nonnegative_number(raw, "self_active_ns", label),
            preempted_ns=_required_nonnegative_number(raw, "preempted_ns", label),
        )
        if row.source_seq_end < row.source_seq_start:
            raise RuntimeError(f"{label} has a reversed source sequence range")
        elapsed = row.end_ns - row.start_ns
        if (
            elapsed < 0
            or row.elapsed_ns != elapsed
            or row.active_ns + row.preempted_ns != row.elapsed_ns
            or row.self_active_ns > row.active_ns
        ):
            raise RuntimeError(f"{label} has an invalid active interval")
        key = (row.source_id, row.source_seq_start, row.source_seq_end)
        if key in keys:
            raise RuntimeError(f"{label} duplicates source activation provenance")
        keys.add(key)
        observed_context_kinds.add(context_kind)
        observed_preempted_task_function |= (
            context_kind == "task" and row.preempted_ns > 0
        )
        rows.append(row)
    if observed_context_kinds != {"task", "isr"}:
        raise RuntimeError(
            "native function activation reference requires Task- and ISR-context functions"
        )
    if not observed_preempted_task_function:
        raise RuntimeError(
            "native function activation reference has no preempted Task function"
        )
    return tuple(rows)


def _verify_manifest_capture_provenance(
    board: BoardConfig, manifest: dict[str, Any]
) -> None:
    tool = _required_object(manifest, "tool", "manifest")
    _required_string(tool, "name", "manifest.tool")
    _required_string(tool, "version", "manifest.tool")
    capture = _required_object(manifest, "capture", "manifest")
    _required_string(capture, "mode", "manifest.capture")
    covered_cores = capture.get("covered_cores")
    if (
        not isinstance(covered_cores, list)
        or any(
            isinstance(core_id, bool) or not isinstance(core_id, int)
            for core_id in covered_cores
        )
        or len(set(covered_cores)) != len(covered_cores)
    ):
        raise RuntimeError(
            "manifest.capture.covered_cores must contain unique integer core IDs"
        )
    if set(covered_cores) != set(board.covered_cores):
        raise RuntimeError(
            "manifest capture covered_cores do not match board configuration"
        )
    adapter = _required_object(capture, "adapter", "manifest.capture")
    _required_string(adapter, "id", "manifest.capture.adapter")
    _required_string(adapter, "version", "manifest.capture.adapter")
    request_sha256 = _required_string(capture, "request_sha256", "manifest.capture")
    _validate_sha256(request_sha256, "manifest.capture.request_sha256")
    target = _required_object(capture, "target", "manifest.capture")
    if target.get("board") != board.board_id:
        raise RuntimeError(
            f"manifest target board {target.get('board')!r} does not match {board.board_id!r}"
        )
    trace32 = _required_object(capture, "trace32", "manifest.capture")
    if trace32.get("build") != str(board.trace32_build):
        raise RuntimeError(
            f"manifest TRACE32 build {trace32.get('build')!r} does not match "
            f"{board.trace32_build}"
        )
    properties = _required_object(trace32, "properties", "manifest.capture.trace32")
    if properties.get("release") != board.trace32_release:
        raise RuntimeError(
            f"manifest TRACE32 release {properties.get('release')!r} does not match "
            f"{board.trace32_release!r}"
        )
    if trace32.get("probe") != board.probe_id:
        raise RuntimeError(
            f"manifest TRACE32 probe {trace32.get('probe')!r} does not match "
            f"{board.probe_id!r}"
        )
    if trace32.get("architecture_package") != board.architecture_package:
        raise RuntimeError(
            "manifest TRACE32 architecture package does not match board configuration"
        )
    if properties.get("license_features") != list(board.license_features):
        raise RuntimeError(
            "manifest TRACE32 license_features do not match board configuration"
        )
    if properties.get("capability_evidence_sha256") != board.capability_evidence_sha256:
        raise RuntimeError(
            "manifest TRACE32 capability evidence digest does not match board configuration"
        )
    target_properties = _required_object(
        target, "properties", "manifest.capture.target"
    )
    if target_properties.get("mcu_family") != board.mcu_family:
        raise RuntimeError(
            "manifest target MCU family does not match board configuration"
        )
    if target_properties.get("rtos") != board.rtos:
        raise RuntimeError("manifest target RTOS does not match board configuration")
    if target_properties.get("trace_routing") != list(board.trace_routing):
        raise RuntimeError("manifest trace routing does not match board configuration")
    firmware = _required_object(manifest, "firmware", "manifest")
    elf_sha256 = firmware.get("elf_sha256")
    build_id = firmware.get("build_id")
    if elf_sha256 is None and (not isinstance(build_id, str) or not build_id):
        raise RuntimeError(
            "manifest firmware requires elf_sha256 or build_id provenance"
        )
    if elf_sha256 is not None:
        if not isinstance(elf_sha256, str):
            raise RuntimeError("manifest firmware elf_sha256 must be a string")
        _validate_sha256(elf_sha256, "manifest.firmware.elf_sha256")
    _verify_manifest_instrumentation(capture)


def _verify_manifest_instrumentation(capture: dict[str, Any]) -> None:
    capabilities = capture.get("capabilities")
    custom_event_support: str | None = None
    if capabilities is not None:
        if not isinstance(capabilities, dict):
            raise RuntimeError("manifest.capture.capabilities must be an object")
        custom_events = capabilities.get("custom_events")
        if not isinstance(custom_events, dict):
            raise RuntimeError(
                "manifest.capture.capabilities.custom_events must be an object"
            )
        custom_event_support = _required_string(
            custom_events,
            "support",
            "manifest.capture.capabilities.custom_events",
        )
        if custom_event_support not in {"exact", "statistical", "unavailable"}:
            raise RuntimeError(f"unknown custom-event support {custom_event_support!r}")

    instrumentation = capture.get("instrumentation")
    if custom_event_support in {"exact", "statistical"} and instrumentation is None:
        raise RuntimeError(
            "manifest with supported custom events omits instrumentation method and measured overhead"
        )
    if instrumentation is None:
        return
    if not isinstance(instrumentation, dict) or set(instrumentation) != {
        "method",
        "transport",
        "overhead",
    }:
        raise RuntimeError("manifest.capture.instrumentation has an invalid field set")
    _required_string(instrumentation, "method", "manifest.capture.instrumentation")
    _required_string(instrumentation, "transport", "manifest.capture.instrumentation")
    overhead = _required_object(
        instrumentation, "overhead", "manifest.capture.instrumentation"
    )
    if set(overhead) != {
        "measurement_method",
        "baseline_duration_ns",
        "instrumented_duration_ns",
        "emitted_event_count",
        "evidence_artifact_id",
    }:
        raise RuntimeError(
            "manifest.capture.instrumentation.overhead has an invalid field set"
        )
    _required_string(
        overhead,
        "measurement_method",
        "manifest.capture.instrumentation.overhead",
    )
    baseline = _required_nonnegative_int(
        overhead,
        "baseline_duration_ns",
        "manifest.capture.instrumentation.overhead",
    )
    instrumented = _required_nonnegative_int(
        overhead,
        "instrumented_duration_ns",
        "manifest.capture.instrumentation.overhead",
    )
    event_count = _required_nonnegative_int(
        overhead,
        "emitted_event_count",
        "manifest.capture.instrumentation.overhead",
    )
    if event_count == 0:
        raise RuntimeError(
            "instrumentation overhead emitted_event_count must be positive"
        )
    if instrumented < baseline:
        raise RuntimeError(
            "instrumentation overhead instrumented duration is below its baseline"
        )
    _required_string(
        overhead,
        "evidence_artifact_id",
        "manifest.capture.instrumentation.overhead",
    )


def _verify_instrumentation_artifact_provenance(
    session_path: Path,
    manifest: dict[str, Any],
    artifacts: dict[str, VerifiedArtifact],
) -> None:
    capture = _required_object(manifest, "capture", "manifest")
    instrumentation = capture.get("instrumentation")
    if instrumentation is None:
        return
    overhead = _required_object(
        instrumentation, "overhead", "manifest.capture.instrumentation"
    )
    evidence_id = _required_string(
        overhead,
        "evidence_artifact_id",
        "manifest.capture.instrumentation.overhead",
    )
    evidence = artifacts.get(evidence_id)
    if evidence is None:
        raise RuntimeError(
            f"instrumentation evidence artifact `{evidence_id}` is not registered"
        )
    if (
        evidence.kind != "instrumentation_overhead"
        or evidence.media_type != "application/json"
    ):
        raise RuntimeError(
            "instrumentation evidence must use kind instrumentation_overhead and application/json"
        )
    evidence_document = _load_json_object(
        session_path / evidence.relative_path,
        f"instrumentation evidence artifact `{evidence_id}`",
    )
    expected_evidence_fields = {
        "schema",
        "instrumentation_method",
        "transport",
        "measurement_method",
        "baseline_duration_ns",
        "instrumented_duration_ns",
        "emitted_event_count",
    }
    if set(evidence_document) != expected_evidence_fields:
        raise RuntimeError("instrumentation evidence has an invalid field set")
    if (
        evidence_document.get("schema")
        != "t32perf.instrumentation-overhead-evidence/v1"
    ):
        raise RuntimeError("instrumentation evidence has an unsupported schema")
    if evidence_document.get("instrumentation_method") != instrumentation["method"]:
        raise RuntimeError(
            "instrumentation evidence method differs from authoritative capture config"
        )
    if evidence_document.get("transport") != instrumentation["transport"]:
        raise RuntimeError(
            "instrumentation evidence transport differs from authoritative capture config"
        )
    for field in (
        "measurement_method",
        "baseline_duration_ns",
        "instrumented_duration_ns",
        "emitted_event_count",
    ):
        if evidence_document.get(field) != overhead[field]:
            raise RuntimeError(
                f"instrumentation evidence {field} differs from authoritative capture config"
            )
    config_claim = _required_object(capture, "capture_config", "manifest.capture")
    config_id = _required_string(
        config_claim, "artifact_id", "manifest.capture.capture_config"
    )
    config = artifacts.get(config_id)
    if config is None or config.kind != "capture_config":
        raise RuntimeError("instrumentation capture-config artifact is not registered")
    if config.input_artifact_ids.count(evidence_id) != 1:
        raise RuntimeError(
            "capture-config provenance does not bind exact instrumentation evidence"
        )
    config_document = _load_json_object(
        session_path / config.relative_path,
        f"artifact `{config_id}`",
    )
    if config_document.get("instrumentation") != instrumentation:
        raise RuntimeError(
            "manifest instrumentation differs from authoritative capture config"
        )


def _verify_artifact(session_path: Path, raw: object) -> VerifiedArtifact:
    if not isinstance(raw, dict):
        raise RuntimeError("manifest artifact entry must be an object")
    artifact_id = _required_string(raw, "id", "manifest artifact")
    kind = _required_string(raw, "kind", f"artifact `{artifact_id}`")
    relative_path = _required_string(raw, "relative_path", f"artifact `{artifact_id}`")
    _validate_artifact_path(relative_path)
    media_type = _required_string(raw, "media_type", f"artifact `{artifact_id}`")
    size_bytes = _required_nonnegative_int(
        raw, "size_bytes", f"artifact `{artifact_id}`"
    )
    sha256 = _required_string(raw, "sha256", f"artifact `{artifact_id}`")
    _validate_sha256(sha256, f"artifact `{artifact_id}`")
    producer = _required_string(raw, "producer", f"artifact `{artifact_id}`")
    raw_inputs = raw.get("input_artifact_ids")
    if not isinstance(raw_inputs, list) or not all(
        isinstance(value, str) and value for value in raw_inputs
    ):
        raise RuntimeError(
            f"artifact `{artifact_id}` input_artifact_ids must be a string array"
        )
    input_artifact_ids = tuple(raw_inputs)
    if len(set(input_artifact_ids)) != len(input_artifact_ids):
        raise RuntimeError(f"artifact `{artifact_id}` has duplicate provenance inputs")

    path = session_path
    for segment in relative_path.split("/"):
        path = path / segment
        if path.is_symlink():
            raise RuntimeError(f"artifact `{artifact_id}` traverses symlink {path}")
    if not path.is_file():
        raise RuntimeError(f"artifact `{artifact_id}` is not a plain file: {path}")
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(session_path)
    except ValueError as error:
        raise RuntimeError(f"artifact `{artifact_id}` escapes its session") from error
    stat = resolved.stat()
    if stat.st_size != size_bytes:
        raise RuntimeError(
            f"artifact `{artifact_id}` size is {stat.st_size}, manifest says {size_bytes}"
        )
    actual_sha256 = _sha256_file(resolved)
    if actual_sha256 != sha256:
        raise RuntimeError(
            f"artifact `{artifact_id}` SHA-256 is {actual_sha256}, manifest says {sha256}"
        )
    identity = None if stat.st_ino == 0 else (stat.st_dev, stat.st_ino)
    return VerifiedArtifact(
        artifact_id=artifact_id,
        kind=kind,
        path=resolved,
        relative_path=relative_path,
        media_type=media_type,
        size_bytes=size_bytes,
        sha256=sha256,
        producer=producer,
        input_artifact_ids=input_artifact_ids,
        file_identity=identity,
    )


def _verify_provenance_graph(
    manifest: dict[str, Any], artifacts: dict[str, VerifiedArtifact]
) -> None:
    artifact_ids = set(artifacts)
    for artifact in artifacts.values():
        for dependency in artifact.input_artifact_ids:
            if dependency not in artifact_ids:
                raise RuntimeError(
                    f"artifact `{artifact.artifact_id}` references unknown input `{dependency}`"
                )
            if dependency == artifact.artifact_id:
                raise RuntimeError(
                    f"artifact `{artifact.artifact_id}` references itself"
                )

    stages = manifest.get("stages")
    if not isinstance(stages, list):
        raise RuntimeError("manifest stages must be an array")
    for stage in stages:
        if not isinstance(stage, dict):
            raise RuntimeError("manifest stage must be an object")
        name = _required_string(stage, "name", "manifest stage")
        for field in ("input_artifact_ids", "output_artifact_ids"):
            references = stage.get(field, [])
            if not isinstance(references, list) or not all(
                isinstance(value, str) for value in references
            ):
                raise RuntimeError(f"manifest stage `{name}` {field} must be an array")
            unknown = set(references) - artifact_ids
            if unknown:
                raise RuntimeError(
                    f"manifest stage `{name}` references unknown artifacts {sorted(unknown)}"
                )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(artifact_id: str) -> None:
        if artifact_id in visited:
            return
        if artifact_id in visiting:
            raise RuntimeError(
                f"artifact provenance contains a cycle at `{artifact_id}`"
            )
        visiting.add(artifact_id)
        for dependency in artifacts[artifact_id].input_artifact_ids:
            visit(dependency)
        visiting.remove(artifact_id)
        visited.add(artifact_id)

    for artifact_id in artifacts:
        visit(artifact_id)


def _session_directory_names(root: Path) -> set[str]:
    if not root.exists():
        return set()
    if not root.is_dir():
        raise RuntimeError(f"artifact root is not a directory: {root}")
    return {
        entry.name
        for entry in root.iterdir()
        if entry.is_dir() and SESSION_ID_PATTERN.fullmatch(entry.name)
    }


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream, object_pairs_hook=_unique_json_object)
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        DuplicateJsonKeyError,
    ) as error:
        raise RuntimeError(f"failed to read {label} JSON: {error}") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} must be a JSON object")
    return value


def _load_fault_scenarios_manifest(
    snapshot: tuple[bytes, str],
) -> FaultScenariosManifest:
    """Load the hash-pinned adapter fault contract without fallbacks."""

    try:
        document = _strict_json_loads(snapshot[0].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, DuplicateJsonKeyError) as error:
        raise HilConfigurationError(
            f"failed to read trace32.fault_scenarios JSON: {error}"
        ) from error
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "adapter_id",
        "scenarios",
    }:
        raise HilConfigurationError("trace32.fault_scenarios field set is invalid")
    if document["schema"] != FAULT_SCENARIOS_SCHEMA:
        raise HilConfigurationError("trace32.fault_scenarios has an unsupported schema")
    try:
        adapter_id = _nonempty_string(
            document["adapter_id"], "fault-scenarios.adapter_id"
        )
        entries = document["scenarios"]
    except (KeyError, TypeError, ValueError) as error:
        raise HilConfigurationError(
            f"trace32.fault_scenarios is incomplete or invalid: {error}"
        ) from error
    if not isinstance(entries, list) or not entries:
        raise HilConfigurationError(
            "fault-scenarios.scenarios must be a non-empty array"
        )

    scenarios: dict[str, FaultScenario] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise HilConfigurationError("fault-scenarios scenarios must be objects")
        try:
            name = _nonempty_string(entry["scenario"], "fault-scenarios.scenario")
        except (KeyError, TypeError, ValueError) as error:
            raise HilConfigurationError(
                f"fault-scenarios scenario is invalid: {error}"
            ) from error
        if name in scenarios:
            raise HilConfigurationError(
                f"fault-scenarios scenario is duplicated: {name}"
            )
        if name not in FAULT_SCENARIO_BINDINGS:
            raise HilConfigurationError(
                f"fault-scenarios scenario is not closed: {name}"
            )
        if name in RECOVERY_FAULT_SCENARIOS:
            raw_support = "recovery"
            expected_fields = {
                "scenario",
                "fault_point",
                "driver_action",
                "recovery_requires_new_session",
            }
            if name == "cmm_abort":
                expected_fields |= {"target_script", "recovery_script"}
            if set(entry) != expected_fields:
                raise HilConfigurationError(
                    f"recovery fault-scenarios {name} field set is invalid"
                )
            expected_point = {
                "trace32_disconnect": "stop",
                "driver_disconnect": "export",
                "cmm_abort": "start",
            }[name]
            if entry["fault_point"] != expected_point:
                raise HilConfigurationError(
                    f"recovery fault-scenarios {name} has wrong fault_point"
                )
            if entry["recovery_requires_new_session"] is not True:
                raise HilConfigurationError(
                    f"recovery fault-scenarios {name} must require a new Session"
                )
            reason = None
        elif name in HEALTH_FAULT_SCENARIOS:
            if "support" not in entry:
                raise HilConfigurationError(
                    f"health fault-scenarios {name} must declare support explicitly"
                )
            raw_support = entry["support"]
            if (
                not isinstance(raw_support, str)
                or raw_support not in FAULT_SCENARIO_SUPPORTS
            ):
                raise HilConfigurationError(
                    f"fault-scenarios {name} has unsupported support state {raw_support!r}"
                )
            reason = _fault_scenario_reason(entry, name)
        else:
            raise HilConfigurationError(
                f"fault-scenarios scenario is not closed: {name}"
            )
        allowed_fields = {
            "scenario",
            "support",
            "evidence_status",
            "reason",
            "configure_script",
            "capacity_records",
            "driver_end_condition",
            "expected_health_issue",
            "fault_point",
            "driver_action",
            "recovery_requires_new_session",
            "target_script",
            "recovery_script",
        }
        unexpected_fields = sorted(set(entry) - allowed_fields)
        if unexpected_fields:
            raise HilConfigurationError(
                f"fault-scenarios {name} has unknown fields: {unexpected_fields}"
            )
        if raw_support == "unsupported":
            if reason is None:
                raise HilConfigurationError(
                    f"unsupported fault-scenarios {name} requires a reason"
                )
            injection_fields = {
                "configure_script",
                "target_script",
                "recovery_script",
                "driver_action",
                "fault_point",
            }
            declared_injectors = sorted(injection_fields & entry.keys())
            if declared_injectors:
                raise HilConfigurationError(
                    f"unsupported fault-scenarios {name} declares injectors: "
                    f"{declared_injectors}"
                )
        scenarios[name] = FaultScenario(
            name=name,
            support=raw_support,
            reason=reason,
            receipt_scenario=FAULT_SCENARIO_BINDINGS[name][1],
        )
    if set(scenarios) != set(FAULT_SCENARIO_BINDINGS):
        raise HilConfigurationError("fault-scenarios scenario set is incomplete")
    return FaultScenariosManifest(
        adapter_id=adapter_id,
        sha256=snapshot[1],
        scenarios=scenarios,
    )


def _load_target_adapter_profile(
    snapshot: tuple[bytes, str],
    *,
    expected_release: str,
    expected_build: int,
    expected_architecture: str,
) -> AdapterProfileBinding:
    """Validate the adapter identity and build gate from one pinned snapshot."""

    try:
        document = _strict_json_loads(snapshot[0].decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError, DuplicateJsonKeyError) as error:
        raise HilConfigurationError(
            f"failed to read trace32.target_adapter_profile JSON: {error}"
        ) from error
    if not isinstance(document, dict):
        raise HilConfigurationError("trace32.target_adapter_profile must be an object")
    required_fields = {
        "schema",
        "adapter_id",
        "implementation_sha256",
        "build_gate",
    }
    if not required_fields.issubset(document):
        raise HilConfigurationError("trace32.target_adapter_profile is incomplete")
    if document["schema"] != TARGET_ADAPTER_PROFILE_SCHEMA:
        raise HilConfigurationError(
            "trace32.target_adapter_profile has an unsupported schema"
        )
    try:
        adapter_id = _nonempty_string(document["adapter_id"], "profile.adapter_id")
        bundle_sha256 = _require_sha256_string(
            document["implementation_sha256"], "profile.implementation_sha256"
        )
        build_gate = document["build_gate"]
        if not isinstance(build_gate, dict) or set(build_gate) != {
            "trace32_release",
            "minimum_build",
            "maximum_build",
            "architecture_package",
        }:
            raise HilConfigurationError("profile.build_gate field set is invalid")
        release = _nonempty_string(
            build_gate["trace32_release"], "profile.build_gate.trace32_release"
        )
        minimum = _configuration_integer(
            build_gate["minimum_build"], "profile.build_gate.minimum_build"
        )
        maximum = _configuration_integer(
            build_gate["maximum_build"], "profile.build_gate.maximum_build"
        )
        architecture = _nonempty_string(
            build_gate["architecture_package"],
            "profile.build_gate.architecture_package",
        )
    except (KeyError, TypeError, ValueError) as error:
        raise HilConfigurationError(
            f"invalid target adapter profile: {error}"
        ) from error
    if release != expected_release or architecture != expected_architecture:
        raise HilConfigurationError(
            "target adapter profile does not match configured TRACE32 release or architecture"
        )
    if minimum > maximum or not minimum <= expected_build <= maximum:
        raise HilConfigurationError(
            "target adapter profile does not admit configured build"
        )
    return AdapterProfileBinding(
        adapter_id=adapter_id,
        sha256=snapshot[1],
        canonical_sha256=_rust_profile_canonical_sha256(document),
        bundle_sha256=bundle_sha256,
    )


def _fault_scenario_reason(entry: dict[str, Any], name: str) -> str | None:
    """Validate the closed health/injection variant and return its reason."""

    support = entry["support"]
    if name == "sampling_buffer_full" and support in {"candidate", "qualified"}:
        expected_fields = {
            "scenario",
            "support",
            "evidence_status",
            "reason",
            "configure_script",
            "capacity_records",
            "driver_end_condition",
            "expected_health_issue",
        }
        if set(entry) != expected_fields:
            raise HilConfigurationError(
                "sampling_buffer_full injection field set is invalid"
            )
        if entry["expected_health_issue"] != "sampling_buffer_full":
            raise HilConfigurationError(
                "sampling_buffer_full injector has wrong expected health issue"
            )
    elif support == "unsupported":
        if set(entry) != {"scenario", "support", "reason"}:
            raise HilConfigurationError(
                f"unsupported fault-scenarios {name} field set is invalid"
            )
    else:
        raise HilConfigurationError(
            f"fault-scenarios {name} has no closed variant for support {support!r}"
        )
    try:
        return _nonempty_string(entry["reason"], f"fault-scenarios {name}.reason")
    except (TypeError, ValueError) as error:
        raise HilConfigurationError(str(error)) from error


def _rust_profile_canonical_sha256(document: dict[str, Any]) -> str:
    """Mirror `serde_json::to_vec(TargetAdapterProfile)` for profile identity."""

    ordered_fields = (
        "schema",
        "adapter_id",
        "adapter_version",
        "implementation_sha256",
        "qualification_sha256",
        "build_gate",
        "target_identifier",
        "probe_identifier",
        "license_features",
        "trace_routing",
        "firmware_elf_sha256",
        "health_signals",
        "capabilities",
        "controller_protocol",
        "custom_event_collector",
        "scenarios",
    )
    if set(document) - set(ordered_fields):
        raise HilConfigurationError("target adapter profile has unknown fields")
    normalized: dict[str, Any] = {}
    for field_name in ordered_fields:
        if field_name not in document:
            continue
        value = document[field_name]
        if (
            field_name in {"qualification_sha256", "custom_event_collector"}
            and value is None
        ):
            continue
        if field_name == "controller_protocol" and value == "v1":
            continue
        if field_name == "scenarios":
            if not isinstance(value, list):
                raise HilConfigurationError("profile.scenarios must be an array")
            normalized[field_name] = [
                _rust_profile_scenario_document(item) for item in value
            ]
        else:
            normalized[field_name] = value
    required = set(ordered_fields) - {
        "qualification_sha256",
        "controller_protocol",
        "custom_event_collector",
    }
    if not required.issubset(normalized):
        raise HilConfigurationError("target adapter profile is incomplete")
    try:
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise HilConfigurationError(
            f"cannot canonicalize target adapter profile: {error}"
        ) from error
    return hashlib.sha256(encoded).hexdigest()


def _rust_profile_scenario_document(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) - {
        "scenario",
        "fault_point",
        "capture",
    }:
        raise HilConfigurationError("profile scenario field set is invalid")
    if "scenario" not in value or "capture" not in value:
        raise HilConfigurationError("profile scenario is incomplete")
    result: dict[str, Any] = {"scenario": value["scenario"]}
    if value.get("fault_point") is not None:
        result["fault_point"] = value["fault_point"]
    capture = value["capture"]
    if not isinstance(capture, dict):
        raise HilConfigurationError("profile scenario capture must be an object")
    capture_fields = (
        "configuration_sha256_by_initial_state",
        "capture_mode",
        "trace_sink",
        "capture_kind",
        "timestamp_enabled",
        "workload_identity",
        "covered_cores",
        "supported_initial_states",
    )
    allowed = set(capture_fields) | {"capacity_records"}
    if set(capture) - allowed:
        raise HilConfigurationError("profile capture has unknown fields")
    normalized_capture: dict[str, Any] = {}
    for field_name in capture_fields:
        if field_name == "capture_kind":
            if field_name in capture:
                normalized_capture[field_name] = capture[field_name]
            elif "capacity_records" in capture:
                normalized_capture[field_name] = {
                    "kind": "sampling",
                    "capacity_records": capture["capacity_records"],
                }
            else:
                raise HilConfigurationError("profile capture kind is missing")
        elif field_name not in capture:
            raise HilConfigurationError("profile capture is incomplete")
        else:
            normalized_capture[field_name] = capture[field_name]
    result["capture"] = normalized_capture
    return result


def _validate_sampling_capture_request(document: object) -> None:
    required = {
        "schema",
        "ranges",
        "bucket_size",
        "duration_ms",
        "method_policy",
        "core_id",
        "address_space",
    }
    allowed = required | {"deployed_firmware_elf_sha256"}
    if (
        not isinstance(document, dict)
        or not required <= set(document)
        or set(document) - allowed
    ):
        raise HilConfigurationError("sampling.capture_request fields are invalid")
    if document["schema"] != "t32perf.sampling-capture-request/v1":
        raise HilConfigurationError("sampling.capture_request schema is invalid")
    bucket_size = document["bucket_size"]
    duration_ms = document["duration_ms"]
    core_id = document["core_id"]
    if (
        not _configuration_is_integer(bucket_size)
        or not 1 <= bucket_size <= 0x10_0000
        or not _configuration_is_integer(duration_ms)
        or not 1 <= duration_ms <= 60_000
        or not _configuration_is_integer(core_id)
        or not 0 <= core_id <= 0xFFFF_FFFF
    ):
        raise HilConfigurationError(
            "sampling.capture_request numeric bounds are invalid"
        )
    if (
        document["method_policy"]
        not in {
            "realtime_only",
            "allow_stop_and_go",
        }
        or document["address_space"] != "P"
    ):
        raise HilConfigurationError(
            "sampling.capture_request method or address space is invalid"
        )
    if "deployed_firmware_elf_sha256" in document:
        deployed_firmware_elf_sha256 = document["deployed_firmware_elf_sha256"]
        if (
            not isinstance(deployed_firmware_elf_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", deployed_firmware_elf_sha256) is None
        ):
            raise HilConfigurationError(
                "sampling.capture_request deployed ELF digest is invalid"
            )
    ranges = document["ranges"]
    if not isinstance(ranges, list) or not 1 <= len(ranges) <= 256:
        raise HilConfigurationError("sampling.capture_request ranges are invalid")
    previous_end: int | None = None
    bucket_count = 0
    for item in ranges:
        if not isinstance(item, dict) or set(item) != {
            "start_address",
            "end_address",
        }:
            raise HilConfigurationError(
                "sampling.capture_request range fields are invalid"
            )
        start, end = item["start_address"], item["end_address"]
        if (
            not _configuration_is_integer(start)
            or not _configuration_is_integer(end)
            or not 0 <= start <= 0xFFFF_FFFF_FFFF_FFFF
            or not 0 <= end <= 0xFFFF_FFFF_FFFF_FFFF
            or start >= end
            or (previous_end is not None and start < previous_end)
        ):
            raise HilConfigurationError(
                "sampling.capture_request ranges must be sorted nonempty uint64 intervals"
            )
        previous_end = end
        bucket_count += (end - start + bucket_size - 1) // bucket_size
        if bucket_count > 256:
            raise HilConfigurationError(
                "sampling.capture_request expands to more than 256 buckets"
            )


def _configuration_is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _read_plain_json_snapshot(
    path: Path, label: str, expected_sha256: str
) -> tuple[bytes, str]:
    """Read one bounded regular-file snapshot without following a final symlink."""

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise HilConfigurationError(f"cannot read {label}: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise HilConfigurationError(f"{label} must be a regular file")
        if metadata.st_size > CONFIG_JSON_LIMIT_BYTES:
            raise HilConfigurationError(
                f"{label} exceeds {CONFIG_JSON_LIMIT_BYTES} byte limit"
            )
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 64 * 1024):
            total += len(chunk)
            if total > CONFIG_JSON_LIMIT_BYTES:
                raise HilConfigurationError(
                    f"{label} exceeds {CONFIG_JSON_LIMIT_BYTES} byte limit"
                )
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except OSError as error:
        raise HilConfigurationError(f"cannot read {label}: {error}") from error
    finally:
        os.close(descriptor)
    if (metadata.st_dev, metadata.st_ino, metadata.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ) or total != metadata.st_size:
        raise HilConfigurationError(f"{label} changed while being read")
    data = b"".join(chunks)
    sha256 = hashlib.sha256(data).hexdigest()
    if sha256 != expected_sha256:
        raise HilConfigurationError(f"{label} SHA-256 does not match configured value")
    return data, sha256


def _require_sha256_string(value: object, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise HilConfigurationError(f"{label} must be 64 lowercase hex characters")
    return value


def _strict_json_loads(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_unique_json_object)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON object key `{key}`")
        result[key] = value
    return result


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        _update_digest(stream, digest)
    return digest.hexdigest()


def _update_digest(stream: BinaryIO, digest: Any) -> None:
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)


def _validate_session_id(session_id: str) -> None:
    if SESSION_ID_PATTERN.fullmatch(session_id) is None:
        raise RuntimeError(f"invalid session ID `{session_id}`")


def _validate_artifact_path(path: str) -> None:
    if (
        not path
        or path.startswith(("/", "\\"))
        or ":" in path
        or "\\" in path
        or "\0" in path
        or any(segment in {"", ".", ".."} for segment in path.split("/"))
    ):
        raise RuntimeError(f"invalid portable artifact path `{path}`")


def _validate_sha256(value: str, label: str) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RuntimeError(f"{label} has an invalid SHA-256 digest")


def _required_object(
    document: dict[str, Any], field: str, label: str
) -> dict[str, Any]:
    value = document.get(field)
    if not isinstance(value, dict):
        raise RuntimeError(f"{label}.{field} must be an object")
    return value


def _require_exact_fields(
    document: dict[str, Any], expected: set[str], label: str
) -> None:
    actual = set(document)
    if actual == expected:
        return
    raise RuntimeError(
        f"{label} field set differs from the v1 contract: "
        f"missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}"
    )


def _required_string(document: dict[str, Any], field: str, label: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"{label}.{field} must be a non-empty string")
    return value


def _required_nonnegative_int(document: dict[str, Any], field: str, label: str) -> int:
    value = document.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeError(f"{label}.{field} must be a non-negative integer")
    return value


def _required_int(document: dict[str, Any], field: str, label: str) -> int:
    value = document.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError(f"{label}.{field} must be an integer")
    return value


def _nullable_string(document: dict[str, Any], field: str, label: str) -> str | None:
    value = document.get(field)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"{label}.{field} must be null or a non-empty string")
    return value


def _required_nonnegative_number(
    document: dict[str, Any], field: str, label: str
) -> float:
    value = document.get(field)
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise RuntimeError(f"{label}.{field} must be a finite non-negative number")
    return float(value)


def selected_board() -> BoardConfig | None:
    """Load the board selected by T32PERF_HIL_BOARD, if any."""

    value = os.environ.get("T32PERF_HIL_BOARD")
    return None if not value else BoardConfig.load(Path(value))


def selected_boards() -> tuple[BoardConfig, ...]:
    """Load a multi-board evidence matrix selected by T32PERF_HIL_BOARDS."""

    value = os.environ.get("T32PERF_HIL_BOARDS")
    if value is None:
        board = selected_board()
        return () if board is None else (board,)
    raw_paths = [item.strip() for item in value.split(os.pathsep) if item.strip()]
    if not raw_paths:
        raise HilConfigurationError("T32PERF_HIL_BOARDS contains no board paths")
    boards = tuple(BoardConfig.load(Path(item)) for item in raw_paths)
    board_ids = [board.board_id for board in boards]
    if len(set(board_ids)) != len(board_ids):
        raise HilConfigurationError("T32PERF_HIL_BOARDS contains duplicate board IDs")
    roots = [board.artifact_root for board in boards]
    if len(set(roots)) != len(roots):
        raise HilConfigurationError(
            "T32PERF_HIL_BOARDS must use distinct artifact roots"
        )
    return boards


def selected_evidence_output() -> Path | None:
    """Return the explicit immutable output selected for a multi-board run."""

    value = os.environ.get(HIL_EVIDENCE_OUTPUT_ENV)
    if value is None:
        return None
    if not value.strip():
        raise HilConfigurationError(
            f"{HIL_EVIDENCE_OUTPUT_ENV} must name a non-empty file path"
        )
    return Path(value).resolve()


def _resolve_config_path(base: Path, value: object) -> Path:
    text = _nonempty_string(value, "path")
    candidate = Path(text)
    return (candidate if candidate.is_absolute() else base / candidate).resolve()


def _resolve_plain_config_file(base: Path, value: object, field: str) -> Path:
    text = _nonempty_string(value, field)
    candidate = Path(text)
    candidate = candidate if candidate.is_absolute() else base / candidate
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise HilConfigurationError(f"{field} is not readable: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise HilConfigurationError(f"{field} must be a plain regular file")
    return candidate.resolve(strict=True)


def _paths_overlap(left: Path, right: Path) -> bool:
    left = left.resolve()
    right = right.resolve()
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _configuration_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise HilConfigurationError(f"{field} must be an integer")
    return value


def _configuration_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise HilConfigurationError(f"{field} must be a number")
    return float(value)


def _unique_nonempty_strings(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise HilConfigurationError(f"{field} must be a non-empty array")
    result = tuple(_nonempty_string(item, field) for item in value)
    if len(set(result)) != len(result):
        raise HilConfigurationError(f"{field} must contain unique values")
    return result


def _nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HilConfigurationError(f"{field} must be a non-empty string")
    return value


if __name__ == "__main__":
    board = selected_board()
    if board is None:
        sys.exit("T32PERF_HIL_BOARD is not set")
    print(json.dumps({"board_id": board.board_id, "config": str(board.path)}))
