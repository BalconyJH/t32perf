"""Strict host-side mirror of target-adapter recovery evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

TARGET_ADAPTER_RECOVERY_EVIDENCE_SCHEMA = "t32perf.target-adapter-recovery-evidence/v1"
TARGET_ADAPTER_FAILURE_BINDING_SCHEMA = "t32perf.target-adapter-failure-binding/v1"
MAX_TARGET_ADAPTER_RECOVERY_EVIDENCE_BYTES = 64 * 1024
PERF_OPERATIONS = frozenset(
    {
        "perf_get_capabilities",
        "perf_configure",
        "perf_start",
        "perf_stop",
        "perf_get_health",
        "perf_export",
        "perf_get_hotspots",
        "perf_cleanup",
    }
)
FAILURE_KINDS = frozenset(
    {
        "trace32_disconnect",
        "driver_disconnect",
        "cmm_abort",
        "operation_failure",
    }
)
TARGET_STATES = frozenset({"running", "halted"})
SAMPLING_METHODS = frozenset({"real_time"})
SAMPLING_OBJECTS = frozenset({"program_counter"})
SAMPLING_BUFFER_MODES = frozenset({"stack"})
SAMPLING_STATES = frozenset({"off"})
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class TargetAdapterRecoveryEvidenceError(RuntimeError):
    """Recovery evidence crossed a structure, storage, or semantic boundary."""


class DuplicateJsonKeyError(ValueError):
    """A strict recovery document repeated one member name."""


@dataclass(frozen=True)
class TargetAdapterSamplingRecoveryEvidence:
    """Canonical SNOOPer baseline restored by a sampling adapter."""

    method: str
    object: str
    buffer_mode: str
    state: str
    requested_rate_ns: int
    capacity_records: int
    auto_arm: bool
    auto_init: bool
    zero_reset: bool

    def __post_init__(self) -> None:
        _enum_string(self.method, SAMPLING_METHODS, "sampling method")
        _enum_string(self.object, SAMPLING_OBJECTS, "sampling object")
        _enum_string(self.buffer_mode, SAMPLING_BUFFER_MODES, "sampling buffer mode")
        _enum_string(self.state, SAMPLING_STATES, "sampling state")
        if (
            not isinstance(self.requested_rate_ns, int)
            or isinstance(self.requested_rate_ns, bool)
            or self.requested_rate_ns != 1_000_000
        ):
            raise TargetAdapterRecoveryEvidenceError(
                "sampling requested_rate_ns must be the canonical 1000000"
            )
        if (
            not isinstance(self.capacity_records, int)
            or isinstance(self.capacity_records, bool)
            or self.capacity_records != 65_536
        ):
            raise TargetAdapterRecoveryEvidenceError(
                "sampling capacity_records must be the canonical 65536"
            )
        _boolean(self.auto_arm, "sampling auto_arm")
        _boolean(self.auto_init, "sampling auto_init")
        _boolean(self.zero_reset, "sampling zero_reset")
        if self.auto_arm or self.auto_init or not self.zero_reset:
            raise TargetAdapterRecoveryEvidenceError(
                "sampling recovery must restore the canonical AutoArm/AutoInit/ZERO baseline"
            )

    @classmethod
    def from_document(
        cls, document: Mapping[str, Any]
    ) -> TargetAdapterSamplingRecoveryEvidence:
        """Validate the closed sampling-recovery evidence object."""

        value = _as_object(document, "sampling recovery evidence")
        _require_exact_fields(
            value,
            {
                "method",
                "object",
                "buffer_mode",
                "state",
                "requested_rate_ns",
                "capacity_records",
                "auto_arm",
                "auto_init",
                "zero_reset",
            },
            "sampling recovery evidence",
        )
        return cls(
            method=value["method"],
            object=value["object"],
            buffer_mode=value["buffer_mode"],
            state=value["state"],
            requested_rate_ns=value["requested_rate_ns"],
            capacity_records=value["capacity_records"],
            auto_arm=value["auto_arm"],
            auto_init=value["auto_init"],
            zero_reset=value["zero_reset"],
        )

    def to_document(self) -> dict[str, Any]:
        """Return the exact Rust field order for sampling recovery evidence."""

        return {
            "method": self.method,
            "object": self.object,
            "buffer_mode": self.buffer_mode,
            "state": self.state,
            "requested_rate_ns": self.requested_rate_ns,
            "capacity_records": self.capacity_records,
            "auto_arm": self.auto_arm,
            "auto_init": self.auto_init,
            "zero_reset": self.zero_reset,
        }


@dataclass(frozen=True)
class TargetAdapterRecoveryEvidence:
    """Python mirror of the Rust ``TargetAdapterRecoveryEvidence`` contract."""

    profile_sha256: str
    binding_sha256: str
    failed_operation: str
    failure_kind: str
    initial_target_state: str
    restored_target_state: str
    adapter_state_restored: bool
    upstream_abort_confirmed: bool
    upstream_abort_receipt_sha256: str
    files_deleted: bool
    new_session_required: bool
    sampling: TargetAdapterSamplingRecoveryEvidence | None = None
    schema: str = TARGET_ADAPTER_RECOVERY_EVIDENCE_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != TARGET_ADAPTER_RECOVERY_EVIDENCE_SCHEMA:
            raise TargetAdapterRecoveryEvidenceError(
                "unsupported target-adapter recovery-evidence schema"
            )
        _require_sha256(self.profile_sha256, "adapter profile digest")
        _require_sha256(self.binding_sha256, "failed controller binding digest")
        _enum_string(self.failed_operation, PERF_OPERATIONS, "failed operation")
        _enum_string(self.failure_kind, FAILURE_KINDS, "failure kind")
        _enum_string(self.initial_target_state, TARGET_STATES, "initial target state")
        _enum_string(self.restored_target_state, TARGET_STATES, "restored target state")
        _boolean(self.adapter_state_restored, "adapter_state_restored")
        if self.sampling is not None and not isinstance(
            self.sampling, TargetAdapterSamplingRecoveryEvidence
        ):
            raise TargetAdapterRecoveryEvidenceError(
                "sampling must be a TargetAdapterSamplingRecoveryEvidence object"
            )
        _boolean(self.upstream_abort_confirmed, "upstream_abort_confirmed")
        if (
            not self.upstream_abort_confirmed
            or self.upstream_abort_receipt_sha256 is None
        ):
            raise TargetAdapterRecoveryEvidenceError(
                "recovery lacks canonical upstream abort acknowledgement or receipt"
            )
        _require_sha256(
            self.upstream_abort_receipt_sha256, "upstream abort receipt digest"
        )
        _boolean(self.files_deleted, "files_deleted")
        _boolean(self.new_session_required, "new_session_required")
        if self.restored_target_state != self.initial_target_state:
            raise TargetAdapterRecoveryEvidenceError(
                "recovery did not restore the initial target state"
            )
        if not self.adapter_state_restored:
            raise TargetAdapterRecoveryEvidenceError(
                "recovery did not restore all adapter-owned state"
            )
        if self.files_deleted:
            raise TargetAdapterRecoveryEvidenceError(
                "target-adapter recovery must not delete Session files"
            )
        if not self.new_session_required:
            raise TargetAdapterRecoveryEvidenceError(
                "recovery must require a new Session"
            )

    @classmethod
    def from_document(
        cls, document: Mapping[str, Any]
    ) -> TargetAdapterRecoveryEvidence:
        """Validate and construct one closed recovery-evidence document."""

        value = _as_object(document, "target-adapter recovery evidence")
        required_fields = {
            "schema",
            "profile_sha256",
            "binding_sha256",
            "failed_operation",
            "failure_kind",
            "initial_target_state",
            "restored_target_state",
            "adapter_state_restored",
            "upstream_abort_confirmed",
            "upstream_abort_receipt_sha256",
            "files_deleted",
            "new_session_required",
        }
        optional_fields = {"sampling"}
        _require_allowed_fields(
            value,
            required_fields,
            optional_fields,
            "target-adapter recovery evidence",
        )
        return cls(
            schema=value["schema"],
            profile_sha256=value["profile_sha256"],
            binding_sha256=value["binding_sha256"],
            failed_operation=value["failed_operation"],
            failure_kind=value["failure_kind"],
            initial_target_state=value["initial_target_state"],
            restored_target_state=value["restored_target_state"],
            adapter_state_restored=value["adapter_state_restored"],
            upstream_abort_confirmed=value["upstream_abort_confirmed"],
            files_deleted=value["files_deleted"],
            new_session_required=value["new_session_required"],
            sampling=(
                TargetAdapterSamplingRecoveryEvidence.from_document(value["sampling"])
                if value.get("sampling") is not None
                else None
            ),
            upstream_abort_receipt_sha256=value["upstream_abort_receipt_sha256"],
        )

    def to_document(self) -> dict[str, Any]:
        """Return the exact JSON-compatible field set in Rust schema order."""

        document: dict[str, Any] = {
            "schema": self.schema,
            "profile_sha256": self.profile_sha256,
            "binding_sha256": self.binding_sha256,
            "failed_operation": self.failed_operation,
            "failure_kind": self.failure_kind,
            "initial_target_state": self.initial_target_state,
            "restored_target_state": self.restored_target_state,
            "adapter_state_restored": self.adapter_state_restored,
        }
        if self.sampling is not None:
            document["sampling"] = self.sampling.to_document()
        document["upstream_abort_confirmed"] = self.upstream_abort_confirmed
        document["upstream_abort_receipt_sha256"] = self.upstream_abort_receipt_sha256
        document["files_deleted"] = self.files_deleted
        document["new_session_required"] = self.new_session_required
        return document


@dataclass(frozen=True)
class TargetAdapterFailureBinding:
    """Controller transaction identity observed before the injected failure."""

    profile_sha256: str
    binding_sha256: str
    failed_operation: str
    failure_kind: str
    initial_target_state: str
    schema: str = TARGET_ADAPTER_FAILURE_BINDING_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != TARGET_ADAPTER_FAILURE_BINDING_SCHEMA:
            raise TargetAdapterRecoveryEvidenceError(
                "unsupported target-adapter failure-binding schema"
            )
        _require_sha256(self.profile_sha256, "adapter profile digest")
        _require_sha256(self.binding_sha256, "failed controller binding digest")
        _enum_string(self.failed_operation, PERF_OPERATIONS, "failed operation")
        _enum_string(self.failure_kind, FAILURE_KINDS, "failure kind")
        _enum_string(self.initial_target_state, TARGET_STATES, "initial target state")

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> TargetAdapterFailureBinding:
        """Validate one exact pre-fault controller-binding document."""

        value = _as_object(document, "target-adapter failure binding")
        _require_exact_fields(
            value,
            {
                "schema",
                "profile_sha256",
                "binding_sha256",
                "failed_operation",
                "failure_kind",
                "initial_target_state",
            },
            "target-adapter failure binding",
        )
        return cls(
            schema=value["schema"],
            profile_sha256=value["profile_sha256"],
            binding_sha256=value["binding_sha256"],
            failed_operation=value["failed_operation"],
            failure_kind=value["failure_kind"],
            initial_target_state=value["initial_target_state"],
        )

    def to_document(self) -> dict[str, str]:
        """Return the exact JSON-compatible pre-fault binding field set."""

        return {
            "schema": self.schema,
            "profile_sha256": self.profile_sha256,
            "binding_sha256": self.binding_sha256,
            "failed_operation": self.failed_operation,
            "failure_kind": self.failure_kind,
            "initial_target_state": self.initial_target_state,
        }


@dataclass(frozen=True)
class RecoveryEvidenceExpectation:
    """Trusted facts that driver-produced recovery evidence must echo."""

    profile_sha256: str
    failed_operation: str
    failure_kind: str
    initial_target_state: str
    binding_sha256: str

    def __post_init__(self) -> None:
        _require_sha256(self.profile_sha256, "expected adapter profile digest")
        _enum_string(
            self.failed_operation, PERF_OPERATIONS, "expected failed operation"
        )
        _enum_string(self.failure_kind, FAILURE_KINDS, "expected failure kind")
        _enum_string(
            self.initial_target_state, TARGET_STATES, "expected initial target state"
        )
        _require_sha256(
            self.binding_sha256, "expected failed controller binding digest"
        )

    def validate(self, evidence: TargetAdapterRecoveryEvidence) -> None:
        """Reject relabelled profiles, bindings, fault points, kinds, or states."""

        mismatches: list[str] = []
        for field, expected in (
            ("profile_sha256", self.profile_sha256),
            ("failed_operation", self.failed_operation),
            ("failure_kind", self.failure_kind),
            ("initial_target_state", self.initial_target_state),
        ):
            if getattr(evidence, field) != expected:
                mismatches.append(field)
        if evidence.restored_target_state != self.initial_target_state:
            mismatches.append("restored_target_state")
        if evidence.binding_sha256 != self.binding_sha256:
            mismatches.append("binding_sha256")
        if mismatches:
            raise TargetAdapterRecoveryEvidenceError(
                "recovery evidence differs from the harness reservation: "
                f"{sorted(mismatches)}"
            )


@dataclass(frozen=True)
class LoadedTargetAdapterRecoveryEvidence:
    """Strict evidence plus its immutable raw-file digest."""

    path: Path
    sha256: str
    evidence: TargetAdapterRecoveryEvidence


@dataclass(frozen=True)
class RecoveryEvidenceReservation:
    """Harness-owned directory and not-yet-created driver output path."""

    directory: Path
    output_path: Path
    expectation: RecoveryEvidenceExpectation
    directory_device: int
    directory_inode: int

    @property
    def receipt_path(self) -> Path:
        """Harness-owned immutable verification receipt beside driver evidence."""

        return self.directory / "verification-receipt.json"

    def load(self) -> LoadedTargetAdapterRecoveryEvidence:
        """Load the exclusively published document without removing it."""

        try:
            directory_metadata = self.directory.lstat()
        except OSError as error:
            raise TargetAdapterRecoveryEvidenceError(
                f"recovery evidence reservation disappeared: {error}"
            ) from error
        if stat.S_ISLNK(directory_metadata.st_mode) or not stat.S_ISDIR(
            directory_metadata.st_mode
        ):
            raise TargetAdapterRecoveryEvidenceError(
                "recovery evidence reservation is not a plain directory"
            )
        if (
            directory_metadata.st_dev != self.directory_device
            or directory_metadata.st_ino != self.directory_inode
        ):
            raise TargetAdapterRecoveryEvidenceError(
                "recovery evidence reservation directory was replaced"
            )
        loaded = load_target_adapter_recovery_evidence(self.output_path)
        self.expectation.validate(loaded.evidence)
        return loaded


def reserve_target_adapter_recovery_evidence(
    root: Path,
    expectation: RecoveryEvidenceExpectation,
) -> RecoveryEvidenceReservation:
    """Allocate a persistent harness-owned directory for one failed operation."""

    resolved_root = root.resolve()
    try:
        resolved_root.mkdir(parents=True, exist_ok=True)
        root_metadata = resolved_root.lstat()
    except OSError as error:
        raise TargetAdapterRecoveryEvidenceError(
            f"cannot prepare recovery evidence root: {error}"
        ) from error
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise TargetAdapterRecoveryEvidenceError(
            "recovery evidence root is not a plain directory"
        )
    try:
        directory = Path(
            tempfile.mkdtemp(prefix="target-adapter-recovery-", dir=resolved_root)
        )
        metadata = directory.lstat()
    except OSError as error:
        raise TargetAdapterRecoveryEvidenceError(
            f"cannot reserve recovery evidence output: {error}"
        ) from error
    return RecoveryEvidenceReservation(
        directory=directory,
        output_path=directory / "target-adapter-recovery-evidence.json",
        expectation=expectation,
        directory_device=metadata.st_dev,
        directory_inode=metadata.st_ino,
    )


def load_target_adapter_recovery_evidence(
    source: Path | bytes | bytearray | Mapping[str, Any],
) -> LoadedTargetAdapterRecoveryEvidence:
    """Load strict bounded evidence and retain its exact byte digest."""

    path: Path | None = None
    if isinstance(source, Path):
        path = source.resolve()
        try:
            metadata = source.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise TargetAdapterRecoveryEvidenceError(
                    "target-adapter recovery evidence is not a plain regular file"
                )
            if metadata.st_nlink != 1:
                raise TargetAdapterRecoveryEvidenceError(
                    "target-adapter recovery evidence must have exactly one link"
                )
            if metadata.st_size > MAX_TARGET_ADAPTER_RECOVERY_EVIDENCE_BYTES:
                raise TargetAdapterRecoveryEvidenceError(
                    "target-adapter recovery evidence exceeds "
                    f"{MAX_TARGET_ADAPTER_RECOVERY_EVIDENCE_BYTES} bytes"
                )
            data = source.read_bytes()
        except TargetAdapterRecoveryEvidenceError:
            raise
        except OSError as error:
            raise TargetAdapterRecoveryEvidenceError(
                f"cannot read target-adapter recovery evidence: {error}"
            ) from error
    elif isinstance(source, (bytes, bytearray)):
        data = bytes(source)
    elif isinstance(source, Mapping):
        try:
            data = json.dumps(
                source,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise TargetAdapterRecoveryEvidenceError(
                f"cannot encode target-adapter recovery evidence: {error}"
            ) from error
    else:
        raise TypeError(
            "unsupported target-adapter recovery evidence source type "
            f"{type(source).__name__}"
        )
    if len(data) > MAX_TARGET_ADAPTER_RECOVERY_EVIDENCE_BYTES:
        raise TargetAdapterRecoveryEvidenceError(
            "target-adapter recovery evidence exceeds "
            f"{MAX_TARGET_ADAPTER_RECOVERY_EVIDENCE_BYTES} bytes"
        )
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        DuplicateJsonKeyError,
        ValueError,
    ) as error:
        raise TargetAdapterRecoveryEvidenceError(
            f"target-adapter recovery evidence is not strict JSON: {error}"
        ) from error
    evidence = TargetAdapterRecoveryEvidence.from_document(
        _as_object(value, "target-adapter recovery evidence")
    )
    return LoadedTargetAdapterRecoveryEvidence(
        path=Path("<memory>") if path is None else path,
        sha256=hashlib.sha256(data).hexdigest(),
        evidence=evidence,
    )


def write_target_adapter_recovery_evidence(
    evidence: TargetAdapterRecoveryEvidence | Mapping[str, Any], output_path: Path
) -> None:
    """Exclusively persist one strict driver recovery document."""

    raw_document = (
        evidence.to_document()
        if isinstance(evidence, TargetAdapterRecoveryEvidence)
        else evidence
    )
    document = TargetAdapterRecoveryEvidence.from_document(raw_document).to_document()
    data = (
        json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    if len(data) > MAX_TARGET_ADAPTER_RECOVERY_EVIDENCE_BYTES:
        raise TargetAdapterRecoveryEvidenceError(
            "target-adapter recovery evidence exceeds "
            f"{MAX_TARGET_ADAPTER_RECOVERY_EVIDENCE_BYTES} bytes"
        )
    if not output_path.parent.is_dir():
        raise TargetAdapterRecoveryEvidenceError(
            "target-adapter recovery evidence parent is not a directory"
        )
    created = False
    try:
        with output_path.open("xb") as stream:
            created = True
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise TargetAdapterRecoveryEvidenceError(
            f"target-adapter recovery evidence already exists: {output_path}"
        ) from error
    except OSError as error:
        if created:
            try:
                output_path.unlink()
            except OSError:
                pass
        raise TargetAdapterRecoveryEvidenceError(
            f"cannot write target-adapter recovery evidence: {error}"
        ) from error


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


def _as_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TargetAdapterRecoveryEvidenceError(f"{label} must be an object")
    return value


def _require_exact_fields(
    document: Mapping[str, Any], expected: set[str], label: str
) -> None:
    actual = set(document)
    if actual != expected:
        raise TargetAdapterRecoveryEvidenceError(
            f"{label} field set is invalid; missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def _require_allowed_fields(
    document: Mapping[str, Any],
    required: set[str],
    optional: set[str],
    label: str,
) -> None:
    actual = set(document)
    allowed = required | optional
    if not required.issubset(actual) or not actual.issubset(allowed):
        raise TargetAdapterRecoveryEvidenceError(
            f"{label} field set is invalid; missing={sorted(required - actual)}, "
            f"unexpected={sorted(actual - allowed)}"
        )


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise TargetAdapterRecoveryEvidenceError(
            f"{label} must be 64 lowercase hexadecimal characters"
        )
    return value


def _enum_string(value: object, allowed: frozenset[str], label: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise TargetAdapterRecoveryEvidenceError(
            f"{label} must be one of {sorted(allowed)}"
        )
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise TargetAdapterRecoveryEvidenceError(f"{label} must be boolean")
    return value
