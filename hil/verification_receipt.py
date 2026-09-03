"""Common strict receipt envelope for complete HIL evidence v2."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from target_adapter_recovery import (
    TargetAdapterRecoveryEvidenceError,
    load_target_adapter_recovery_evidence,
)

VERIFICATION_RECEIPT_SCHEMA = "t32perf.hil-verification-receipt/v1"
MAX_RECEIPT_BYTES = 4 * 1024 * 1024
MAX_FAILURES_IN_RECEIPT = 128

RESOURCE_BINDING_ROLES = frozenset(
    {
        "manifest",
        "health",
        "observations",
        "analysis_summary",
        "hotspots",
        "static_ram_report",
        "static_ram_config",
        "static_ram_source",
        "resource_source",
        "normalize_config",
    }
)
NATIVE_TIMELINE_BINDING_ROLES = frozenset(
    {
        "manifest",
        "health",
        "observations",
        "analysis_summary",
        "hotspots",
        "derived",
    }
)
FAULT_MINIMUM_BINDING_ROLES = frozenset({"manifest", "health"})
FAULT_ALLOWED_BINDING_ROLES = frozenset(
    {"manifest", "health", "observations", "analysis_summary"}
)
ARTIFACT_BINDING_ROLES = RESOURCE_BINDING_ROLES | NATIVE_TIMELINE_BINDING_ROLES

RESOURCE_CHECK_CATEGORIES = (
    "artifact_binding",
    "allocator",
    "stack",
    "static_ram",
    "trace_buffer",
    "clock_alignment",
    "call_depth",
    "analysis_summary",
)
NATIVE_TIMELINE_CHECK_CATEGORIES = (
    "artifact_binding",
    "function",
    "task",
    "isr",
    "context_switch",
    "interrupt",
    "function_activation",
)
FAULT_CHECK_CATEGORIES = (
    "artifact_binding",
    "health",
    "fault_publication",
    "recovery",
)
KIND_CHECK_CATEGORIES = {
    "resources": RESOURCE_CHECK_CATEGORIES,
    "native_timeline": NATIVE_TIMELINE_CHECK_CATEGORIES,
    "fault_injection": FAULT_CHECK_CATEGORIES,
}
FAULT_SCENARIOS = (
    "trace_overflow",
    "flow_error",
    "sampling_buffer_full",
    "elf_mismatch",
    "trace32_disconnect_recovery",
    "driver_disconnect_recovery",
    "cmm_abort_recovery",
)
SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class VerificationReceiptError(RuntimeError):
    """A receipt crossed a structure, size, or semantic boundary."""


class DuplicateJsonKeyError(ValueError):
    """A strict JSON object repeated one member name."""


@dataclass(frozen=True)
class TolerancePolicy:
    """Closed numeric tolerance policy shared by all verification kinds."""

    timestamp_absolute_ns: float
    continuous_relative: float = 0.005
    continuous_absolute: float = 1e-12
    integer_absolute: float = 0.0
    timestamp_relative: float = 0.0

    def __post_init__(self) -> None:
        values = (
            self.timestamp_absolute_ns,
            self.continuous_relative,
            self.continuous_absolute,
            self.integer_absolute,
            self.timestamp_relative,
        )
        if any(not math.isfinite(value) or value < 0 for value in values):
            raise ValueError("verification tolerances must be finite and nonnegative")

    def to_document(self) -> dict[str, float]:
        return {
            "timestamp_absolute_ns": self.timestamp_absolute_ns,
            "timestamp_relative": self.timestamp_relative,
            "continuous_relative": self.continuous_relative,
            "continuous_absolute": self.continuous_absolute,
            "integer_absolute": self.integer_absolute,
        }


@dataclass(frozen=True)
class VerificationCheck:
    """One named check consumed by the common receipt builder."""

    category: str
    name: str
    passed: bool
    reason: str = ""
    absolute_error: float | None = None
    relative_error: float | None = None


def canonical_json_bytes(document: object) -> bytes:
    """Return deterministic JSON bytes used for canonical receipt digests."""

    try:
        return json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise VerificationReceiptError(
            f"document cannot be represented as canonical JSON: {error}"
        ) from error


def canonical_sha256(document: object) -> str:
    """Return SHA-256 of deterministic JSON bytes."""

    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()


def build_verification_receipt(
    *,
    kind: str,
    board_id: str,
    session_id: str,
    driver_reference_sha256: str,
    tolerance: TolerancePolicy,
    artifact_bindings: Mapping[str, tuple[str | None, str]],
    checks: Sequence[VerificationCheck],
    scenario: str | None = None,
    fault_adapter_binding: Mapping[str, Any] | None = None,
    recovery_evidence: Mapping[str, Any] | None = None,
    recovery_evidence_sha256: str | None = None,
) -> dict[str, Any]:
    """Build a closed, bounded PASS or FAIL receipt from named checks."""

    categories = KIND_CHECK_CATEGORIES.get(kind)
    if categories is None:
        raise VerificationReceiptError(f"unsupported verification kind {kind!r}")
    _validate_kind_scenario(kind, scenario)
    _bounded_string(board_id, "receipt board ID", 256)
    _bounded_string(session_id, "receipt Session ID", 64)
    if SESSION_ID_PATTERN.fullmatch(session_id) is None:
        raise VerificationReceiptError("receipt Session ID is not portable")
    _require_sha256(driver_reference_sha256, "driver reference digest")
    binding_rows = _binding_rows(kind, artifact_bindings)
    recovery_binding = _recovery_evidence_binding(
        kind,
        scenario,
        recovery_evidence,
        recovery_evidence_sha256,
    )

    counts = {
        category: {"total": 0, "passed": 0, "failed": 0} for category in categories
    }
    failures: list[dict[str, str]] = []
    failure_count = 0
    max_absolute = 0.0
    max_relative = 0.0
    max_error_check: str | None = None
    for check in checks:
        if check.category not in counts:
            raise VerificationReceiptError(
                f"check category {check.category!r} is invalid for {kind!r}"
            )
        _bounded_string(check.name, "verification check name", 512)
        if not isinstance(check.passed, bool):
            raise VerificationReceiptError(
                "verification check passed flag must be boolean"
            )
        if (check.absolute_error is None) is not (check.relative_error is None):
            raise VerificationReceiptError(
                "verification check errors must be both present or both absent"
            )
        absolute_error = (
            None
            if check.absolute_error is None
            else _nonnegative_number(check.absolute_error, "check absolute error")
        )
        relative_error = (
            None
            if check.relative_error is None
            else _nonnegative_number(check.relative_error, "check relative error")
        )
        category_counts = counts[check.category]
        category_counts["total"] += 1
        if check.passed:
            category_counts["passed"] += 1
        else:
            reason = _bounded_string(check.reason, "verification failure reason", 2048)
            category_counts["failed"] += 1
            failure_count += 1
            if len(failures) < MAX_FAILURES_IN_RECEIPT:
                failures.append({"check": check.name, "reason": reason})
        if absolute_error is not None and relative_error is not None:
            if relative_error > max_relative or (
                relative_error == max_relative and absolute_error > max_absolute
            ):
                max_absolute = absolute_error
                max_relative = relative_error
                max_error_check = check.name

    total = sum(row["total"] for row in counts.values())
    passed = sum(row["passed"] for row in counts.values())
    failed = sum(row["failed"] for row in counts.values())
    _validate_nonempty_category_counts(kind, scenario, counts)
    receipt = {
        "schema": VERIFICATION_RECEIPT_SCHEMA,
        "source": "host-reconstructed-session-artifacts",
        "kind": kind,
        "scenario": scenario,
        "board_id": board_id,
        "session_id": session_id,
        "driver_reference_sha256": driver_reference_sha256,
        "recovery_evidence": recovery_binding,
        "fault_adapter_binding": (
            None if fault_adapter_binding is None else dict(fault_adapter_binding)
        ),
        "tolerance": tolerance.to_document(),
        "artifact_bindings": binding_rows,
        "checks": {"total": total, "passed": passed, "failed": failed},
        "check_categories": [
            {"category": category, "counts": counts[category]}
            for category in categories
        ],
        "max_error": {
            "check": max_error_check,
            "absolute": max_absolute,
            "relative": max_relative,
        },
        "failure_count": failure_count,
        "failures": failures,
        "failures_truncated": failure_count > len(failures),
        "verdict": "PASS" if failed == 0 else "FAIL",
    }
    validate_verification_receipt(receipt)
    if len(canonical_json_bytes(receipt)) > MAX_RECEIPT_BYTES:
        raise VerificationReceiptError(
            f"verification receipt exceeds {MAX_RECEIPT_BYTES} bytes"
        )
    return receipt


def validate_verification_receipt(receipt: Mapping[str, Any]) -> None:
    """Validate schema-adjacent receipt semantics and internal counts."""

    document = _as_object(receipt, "verification receipt")
    required_fields = {
        "schema",
        "source",
        "kind",
        "scenario",
        "board_id",
        "session_id",
        "driver_reference_sha256",
        "tolerance",
        "artifact_bindings",
        "checks",
        "check_categories",
        "max_error",
        "failure_count",
        "failures",
        "failures_truncated",
        "verdict",
    }
    actual_fields = set(document)
    allowed_fields = required_fields | {"recovery_evidence", "fault_adapter_binding"}
    if not required_fields.issubset(actual_fields) or not actual_fields.issubset(
        allowed_fields
    ):
        raise VerificationReceiptError(
            "verification receipt field set is invalid; "
            f"missing={sorted(required_fields - actual_fields)}, "
            f"unexpected={sorted(actual_fields - allowed_fields)}"
        )
    if document["schema"] != VERIFICATION_RECEIPT_SCHEMA:
        raise VerificationReceiptError("unsupported verification receipt schema")
    if document["source"] != "host-reconstructed-session-artifacts":
        raise VerificationReceiptError("verification receipt source is not host-owned")
    kind = document["kind"]
    categories = KIND_CHECK_CATEGORIES.get(kind)
    if categories is None:
        raise VerificationReceiptError(f"unsupported verification kind {kind!r}")
    _validate_kind_scenario(kind, document["scenario"])
    _bounded_string(document["board_id"], "receipt board ID", 256)
    session_id = _bounded_string(document["session_id"], "receipt Session ID", 64)
    if SESSION_ID_PATTERN.fullmatch(session_id) is None:
        raise VerificationReceiptError("receipt Session ID is not portable")
    _require_sha256(document["driver_reference_sha256"], "driver reference digest")
    _validate_recovery_evidence_binding(
        kind, document["scenario"], document.get("recovery_evidence")
    )
    _validate_fault_adapter_binding(
        kind, document["scenario"], document.get("fault_adapter_binding")
    )

    tolerance = _as_object(document["tolerance"], "receipt tolerance")
    _require_exact_fields(
        tolerance,
        {
            "timestamp_absolute_ns",
            "timestamp_relative",
            "continuous_relative",
            "continuous_absolute",
            "integer_absolute",
        },
        "receipt tolerance",
    )
    try:
        TolerancePolicy(
            timestamp_absolute_ns=_nonnegative_number(
                tolerance["timestamp_absolute_ns"], "timestamp absolute tolerance"
            ),
            timestamp_relative=_nonnegative_number(
                tolerance["timestamp_relative"], "timestamp relative tolerance"
            ),
            continuous_relative=_nonnegative_number(
                tolerance["continuous_relative"], "continuous relative tolerance"
            ),
            continuous_absolute=_nonnegative_number(
                tolerance["continuous_absolute"], "continuous absolute tolerance"
            ),
            integer_absolute=_nonnegative_number(
                tolerance["integer_absolute"], "integer absolute tolerance"
            ),
        )
    except ValueError as error:
        raise VerificationReceiptError(str(error)) from error

    raw_bindings = _as_list(document["artifact_bindings"], "artifact bindings", 32)
    bindings: dict[str, tuple[str | None, str]] = {}
    for index, raw in enumerate(raw_bindings):
        binding = _as_object(raw, f"artifact binding {index}")
        _require_exact_fields(
            binding, {"role", "artifact_id", "sha256"}, f"artifact binding {index}"
        )
        role = _bounded_string(binding["role"], "artifact binding role", 64)
        if role not in ARTIFACT_BINDING_ROLES:
            raise VerificationReceiptError(
                f"unsupported artifact binding role {role!r}"
            )
        if role in bindings:
            raise VerificationReceiptError(f"duplicate artifact binding role {role!r}")
        artifact_id = binding["artifact_id"]
        if role == "manifest":
            if artifact_id is not None:
                raise VerificationReceiptError(
                    "manifest binding artifact_id must be null"
                )
        else:
            artifact_id = _bounded_string(
                artifact_id, f"artifact binding {role} ID", 256
            )
        bindings[role] = (
            artifact_id,
            _require_sha256(binding["sha256"], f"artifact binding {role} digest"),
        )
    _validate_binding_roles(kind, set(bindings))

    total_counts = _validate_check_counts(document["checks"], "receipt checks")
    category_rows = _as_list(
        document["check_categories"], "receipt check categories", 32
    )
    actual_categories: list[str] = []
    accumulated = {"total": 0, "passed": 0, "failed": 0}
    for index, raw in enumerate(category_rows):
        row = _as_object(raw, f"receipt check category {index}")
        _require_exact_fields(
            row, {"category", "counts"}, f"receipt check category {index}"
        )
        category = _bounded_string(row["category"], "receipt check category", 64)
        if category in actual_categories:
            raise VerificationReceiptError(f"duplicate receipt category {category!r}")
        actual_categories.append(category)
        counts = _validate_check_counts(row["counts"], f"category {category} counts")
        for field_name in accumulated:
            accumulated[field_name] += counts[field_name]
    if tuple(actual_categories) != categories:
        raise VerificationReceiptError(
            f"receipt categories for {kind!r} are incomplete or out of canonical order"
        )
    if accumulated != total_counts:
        raise VerificationReceiptError(
            "receipt category counts do not match total checks"
        )
    _validate_nonempty_category_counts(
        kind,
        document["scenario"],
        {
            row["category"]: _validate_check_counts(
                row["counts"], f"category {row['category']} counts"
            )
            for row in category_rows
        },
    )

    max_error = _as_object(document["max_error"], "receipt max error")
    _require_exact_fields(
        max_error, {"check", "absolute", "relative"}, "receipt max error"
    )
    if max_error["check"] is not None:
        _bounded_string(max_error["check"], "receipt max-error check", 512)
    _nonnegative_number(max_error["absolute"], "receipt max absolute error")
    _nonnegative_number(max_error["relative"], "receipt max relative error")

    failure_count = _nonnegative_int(document["failure_count"], "failure count")
    failures = _as_list(
        document["failures"], "receipt failures", MAX_FAILURES_IN_RECEIPT
    )
    for index, raw in enumerate(failures):
        failure = _as_object(raw, f"receipt failure {index}")
        _require_exact_fields(failure, {"check", "reason"}, f"receipt failure {index}")
        _bounded_string(failure["check"], "failure check", 512)
        _bounded_string(failure["reason"], "failure reason", 2048)
    truncated = document["failures_truncated"]
    if not isinstance(truncated, bool):
        raise VerificationReceiptError("failures_truncated must be boolean")
    if failure_count != total_counts["failed"]:
        raise VerificationReceiptError("failure count does not match failed checks")
    if truncated is not (failure_count > len(failures)):
        raise VerificationReceiptError("failure truncation flag is inconsistent")
    if not truncated and failure_count != len(failures):
        raise VerificationReceiptError("receipt omits untruncated failures")
    verdict = document["verdict"]
    if verdict not in {"PASS", "FAIL"}:
        raise VerificationReceiptError("receipt verdict must be PASS or FAIL")
    if (verdict == "PASS") is not (total_counts["failed"] == 0):
        raise VerificationReceiptError("receipt verdict contradicts failed checks")


def load_verification_receipt(
    source: Path | bytes | bytearray | Mapping[str, Any],
) -> dict[str, Any]:
    """Load a bounded strict receipt and reject duplicate JSON keys."""

    document = _load_json_source(source, MAX_RECEIPT_BYTES, "verification receipt")
    validate_verification_receipt(document)
    return document


def write_verification_receipt(receipt: Mapping[str, Any], output_path: Path) -> None:
    """Exclusively persist one validated receipt without overwriting evidence."""

    document = _load_json_source(receipt, MAX_RECEIPT_BYTES, "verification receipt")
    validate_verification_receipt(document)
    data = (
        json.dumps(
            document, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True
        )
        + "\n"
    ).encode("utf-8")
    if len(data) > MAX_RECEIPT_BYTES:
        raise VerificationReceiptError(
            f"verification receipt exceeds {MAX_RECEIPT_BYTES} bytes"
        )
    path = output_path.resolve()
    if not path.parent.is_dir():
        raise VerificationReceiptError("verification receipt parent is not a directory")
    created = False
    try:
        with path.open("xb") as stream:
            created = True
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise VerificationReceiptError(
            f"verification receipt already exists: {path}"
        ) from error
    except OSError as error:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise VerificationReceiptError(
            f"cannot write verification receipt: {error}"
        ) from error


def _binding_rows(
    kind: str, artifact_bindings: Mapping[str, tuple[str | None, str]]
) -> list[dict[str, str | None]]:
    roles = set(artifact_bindings)
    _validate_binding_roles(kind, roles)
    rows: list[dict[str, str | None]] = []
    for role in sorted(roles):
        if role not in ARTIFACT_BINDING_ROLES:
            raise VerificationReceiptError(
                f"unsupported artifact binding role {role!r}"
            )
        value = artifact_bindings[role]
        if not isinstance(value, tuple) or len(value) != 2:
            raise VerificationReceiptError(
                f"artifact binding {role!r} must be an (artifact_id, sha256) tuple"
            )
        artifact_id, sha256 = value
        if role == "manifest":
            if artifact_id is not None:
                raise VerificationReceiptError(
                    "manifest binding artifact_id must be null"
                )
        else:
            artifact_id = _bounded_string(
                artifact_id, f"artifact binding {role} ID", 256
            )
        rows.append(
            {
                "role": role,
                "artifact_id": artifact_id,
                "sha256": _require_sha256(sha256, f"artifact binding {role} digest"),
            }
        )
    return rows


def _validate_binding_roles(kind: str, roles: set[str]) -> None:
    if kind == "resources" and roles != RESOURCE_BINDING_ROLES:
        raise VerificationReceiptError(
            "resource receipt artifact bindings are incomplete"
        )
    if kind == "native_timeline" and roles != NATIVE_TIMELINE_BINDING_ROLES:
        raise VerificationReceiptError(
            "native timeline receipt artifact bindings are incomplete"
        )
    if kind == "fault_injection" and not FAULT_MINIMUM_BINDING_ROLES.issubset(roles):
        raise VerificationReceiptError(
            "fault receipt must bind at least manifest and health artifacts"
        )
    if kind == "fault_injection" and not roles.issubset(FAULT_ALLOWED_BINDING_ROLES):
        raise VerificationReceiptError(
            "fault receipt contains unrelated artifact bindings"
        )


def _validate_kind_scenario(kind: str, scenario: object) -> None:
    if kind == "fault_injection":
        if scenario not in FAULT_SCENARIOS:
            raise VerificationReceiptError(
                f"fault receipt scenario must be one of {list(FAULT_SCENARIOS)}"
            )
    elif scenario is not None:
        raise VerificationReceiptError(f"{kind} receipt scenario must be null")


def _validate_fault_adapter_binding(
    kind: object, scenario: object, value: object
) -> None:
    """Validate the immutable adapter identity required for sampled fault proof."""

    if value is None:
        if kind == "fault_injection" and scenario == "sampling_buffer_full":
            raise VerificationReceiptError(
                "sampling_buffer_full receipt requires fault adapter binding"
            )
        return
    if kind != "fault_injection":
        raise VerificationReceiptError(
            "non-fault receipt cannot bind an adapter fault manifest"
        )
    binding = _as_object(value, "fault adapter binding")
    _require_exact_fields(
        binding,
        {
            "scenario",
            "fault_scenarios_sha256",
            "adapter_id",
            "profile_sha256",
            "profile_file_sha256",
            "bundle_sha256",
        },
        "fault adapter binding",
    )
    if binding["scenario"] != scenario:
        raise VerificationReceiptError(
            "fault adapter binding scenario does not match receipt"
        )
    _bounded_string(binding["adapter_id"], "fault adapter ID", 256)
    for field_name in (
        "fault_scenarios_sha256",
        "profile_sha256",
        "profile_file_sha256",
        "bundle_sha256",
    ):
        _require_sha256(binding[field_name], f"fault adapter binding {field_name}")


def _recovery_evidence_binding(
    kind: str,
    scenario: object,
    recovery_evidence: Mapping[str, Any] | None,
    recovery_evidence_sha256: str | None,
) -> dict[str, Any] | None:
    is_recovery = (
        kind == "fault_injection"
        and isinstance(scenario, str)
        and scenario.endswith("_recovery")
    )
    if not is_recovery:
        if recovery_evidence is not None or recovery_evidence_sha256 is not None:
            raise VerificationReceiptError(
                "non-recovery receipt cannot bind target-adapter recovery evidence"
            )
        return None
    if recovery_evidence is None or recovery_evidence_sha256 is None:
        raise VerificationReceiptError(
            "recovery receipt must bind strict target-adapter recovery evidence"
        )
    try:
        document = load_target_adapter_recovery_evidence(
            recovery_evidence
        ).evidence.to_document()
    except TargetAdapterRecoveryEvidenceError as error:
        raise VerificationReceiptError(str(error)) from error
    expected_kind = {
        "trace32_disconnect_recovery": "trace32_disconnect",
        "driver_disconnect_recovery": "driver_disconnect",
        "cmm_abort_recovery": "cmm_abort",
    }[scenario]
    if document["failure_kind"] != expected_kind:
        raise VerificationReceiptError(
            "recovery receipt scenario and failure kind do not match"
        )
    return {
        "sha256": _require_sha256(
            recovery_evidence_sha256, "target-adapter recovery evidence digest"
        ),
        "document": document,
    }


def _validate_recovery_evidence_binding(
    kind: str, scenario: object, value: object
) -> None:
    is_recovery = (
        kind == "fault_injection"
        and isinstance(scenario, str)
        and scenario.endswith("_recovery")
    )
    if not is_recovery:
        if value is not None:
            raise VerificationReceiptError(
                "non-recovery receipt must have null recovery_evidence"
            )
        return
    binding = _as_object(value, "receipt recovery evidence binding")
    _require_exact_fields(
        binding,
        {"sha256", "document"},
        "receipt recovery evidence binding",
    )
    _recovery_evidence_binding(
        kind,
        scenario,
        _as_object(binding["document"], "receipt recovery evidence document"),
        _require_sha256(binding["sha256"], "target-adapter recovery evidence digest"),
    )


def _validate_nonempty_category_counts(
    kind: str,
    scenario: object,
    counts: Mapping[str, Mapping[str, int]],
) -> None:
    if kind in {"resources", "native_timeline"}:
        required = set(KIND_CHECK_CATEGORIES[kind])
    elif isinstance(scenario, str) and scenario.endswith("_recovery"):
        required = {
            "artifact_binding",
            "health",
            "fault_publication",
            "recovery",
        }
    else:
        required = {"artifact_binding", "health", "fault_publication"}
    empty = sorted(
        category
        for category in required
        if category not in counts or counts[category]["total"] == 0
    )
    if empty:
        raise VerificationReceiptError(
            f"{kind} receipt has empty required check categories: {empty}"
        )


def _load_json_source(
    source: Path | bytes | bytearray | Mapping[str, Any], limit: int, label: str
) -> dict[str, Any]:
    if isinstance(source, Path):
        try:
            metadata = source.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise VerificationReceiptError(f"{label} is not a plain regular file")
            if metadata.st_size > limit:
                raise VerificationReceiptError(f"{label} exceeds {limit} bytes")
            data = source.read_bytes()
        except VerificationReceiptError:
            raise
        except OSError as error:
            raise VerificationReceiptError(f"cannot read {label}: {error}") from error
    elif isinstance(source, (bytes, bytearray)):
        data = bytes(source)
    elif isinstance(source, Mapping):
        data = canonical_json_bytes(source)
    else:
        raise TypeError(f"unsupported {label} source type {type(source).__name__}")
    if len(data) > limit:
        raise VerificationReceiptError(f"{label} exceeds {limit} bytes")
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
        raise VerificationReceiptError(
            f"{label} is not strict JSON: {error}"
        ) from error
    return _as_object(value, label)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


def _validate_check_counts(raw: object, label: str) -> dict[str, int]:
    counts = _as_object(raw, label)
    _require_exact_fields(counts, {"total", "passed", "failed"}, label)
    result = {
        field_name: _nonnegative_int(counts[field_name], f"{label}.{field_name}")
        for field_name in ("total", "passed", "failed")
    }
    if result["passed"] + result["failed"] != result["total"]:
        raise VerificationReceiptError(f"{label} counts do not add up")
    return result


def _require_exact_fields(
    document: Mapping[str, Any], expected: set[str], label: str
) -> None:
    actual = set(document)
    if actual != expected:
        raise VerificationReceiptError(
            f"{label} field set is invalid; missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def _as_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise VerificationReceiptError(f"{label} must be an object")
    return value


def _as_list(value: object, label: str, maximum: int) -> list[Any]:
    if not isinstance(value, list):
        raise VerificationReceiptError(f"{label} must be an array")
    if len(value) > maximum:
        raise VerificationReceiptError(f"{label} exceeds {maximum} entries")
    return value


def _bounded_string(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise VerificationReceiptError(
            f"{label} must be a non-empty string no longer than {maximum} UTF-8 bytes"
        )
    return value


def _nonnegative_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise VerificationReceiptError(f"{label} must be a nonnegative integer")
    return value


def _nonnegative_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise VerificationReceiptError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise VerificationReceiptError(f"{label} must be finite and nonnegative")
    return result


def _require_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise VerificationReceiptError(f"{label} must be 64 lowercase hex characters")
    return value
