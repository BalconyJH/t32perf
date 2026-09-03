"""Strict, generic PC-sampling HIL verification receipts.

This module deliberately knows no board family or TRACE32 command syntax. A
board supplies closed wrappers for the Host CLI and the two sampling-sidecar
MCP operations; the HIL layer verifies their exact envelopes and evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from harness import (
    BoardConfig,
    HilConfigurationError,
    _read_plain_json_snapshot,
    _strict_json_loads,
    _validate_sampling_capture_request,
    run_json,
)
from sampling_board import SamplingBoardConfig

SCHEMA = "t32perf.hil-sampling-verification-receipt/v1"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_SESSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_MAX_CAPABILITIES = 64 * 1024
_MAX_RECEIPT = 512 * 1024
_OPERATION = re.compile(r"^[0-9a-f]{32}$")
_AUDIT_FILE_LIMIT = 64 * 1024 * 1024
_UUID4 = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_CATALOG = {
    "sampling-capture-receipt": (
        "sampling_capture_receipt",
        "capture/sampling/capture-receipt.json",
        "application/json",
        "t32perf-sampling-capture-receipt/v1",
        [],
    ),
    "sampling-pc-hit-histogram": (
        "pc_hit_histogram",
        "capture/sampling/pc-hit-histogram.json",
        "application/json",
        "lauterbach-sampling-mcp/v1",
        ["sampling-capture-receipt"],
    ),
    "sampling-heatmap-address": (
        "heatmap",
        "analysis/sampling-heatmap-address.json",
        "application/json",
        "t32perf-sampling-analysis/v1",
        ["sampling-pc-hit-histogram"],
    ),
    "sampling-heatmap-address-svg-top025": (
        "heatmap",
        "report/sampling-heatmap-address-top025.svg",
        "image/svg+xml",
        "t32perf-sampling-analysis/v1",
        ["sampling-heatmap-address", "sampling-pc-hit-histogram"],
    ),
}
_SVG_STYLE = """<style>
:root { color-scheme: light dark; --foreground: #172033; --muted: #536176; --grid: #d7deea; --bar: #1769aa; --neutral: #778397; }
@media (prefers-color-scheme: dark) { :root { --foreground: #f8fafc; --muted: #c0cad8; --grid: #455166; --bar: #6db6ff; --neutral: #a8b3c5; } }
.heading { fill: var(--foreground); font: 500 20px sans-serif; } .subtitle { fill: var(--muted); font: 400 13px sans-serif; } .metadata { fill: var(--foreground); font: 400 13px sans-serif; } .axis { fill: var(--muted); font: 500 12px sans-serif; } .label { fill: var(--foreground); font: 400 13px sans-serif; } .value { fill: var(--foreground); font: 400 12px sans-serif; } .empty { fill: var(--muted); font: italic 400 12px sans-serif; } .truncation { fill: var(--muted); font: 400 12px sans-serif; } .track { fill: none; stroke: var(--grid); stroke-width: 1; } .bar { fill: var(--bar); } .unattributed { fill: var(--neutral); }
</style>"""
_SVG_ANNOTATION_STYLE = (
    "<style>.annotation { fill: var(--muted); font: 400 11px sans-serif; }</style>"
)


class SamplingVerificationError(RuntimeError):
    """Sampling HIL evidence is missing, malformed, or contradictory."""


def canonical_bytes(document: object) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256(document: object) -> str:
    return hashlib.sha256(canonical_bytes(document)).hexdigest()


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and not isinstance(value, complex)
        and float(value) == float(value)
        and abs(float(value)) != float("inf")
    )


def build_receipt(
    *,
    board_id: str,
    session_id: str,
    status: str,
    reason: str,
    capture_request_file_sha256: str,
    session_request_sha256: str,
    capabilities: Mapping[str, Any],
    checks: list[Mapping[str, Any]],
    artifact_bindings: list[Mapping[str, str]] | None = None,
    endpoint_fingerprint: str | None = None,
    method_policy: str | None = None,
    selected_method: str | None = None,
    target_before: Mapping[str, Any] | None = None,
    target_after: Mapping[str, Any] | None = None,
    operation_id: str | None = None,
    quantitative_policy: Mapping[str, Any] | None = None,
    configured_identity: Mapping[str, Any] | None = None,
    statistical: bool = True,
    diagnostic_only: bool = False,
) -> dict[str, Any]:
    """Build a strict receipt; call :func:`write_receipt` to persist it."""

    document: dict[str, Any] = {
        "schema": SCHEMA,
        "source": "generic-pc-sampling-hil",
        "board_id": board_id,
        "session_id": session_id,
        "status": status,
        "reason": reason,
        "capture_request_file_sha256": capture_request_file_sha256,
        "session_request_sha256": session_request_sha256,
        "capabilities_sha256": sha256(capabilities),
        "capabilities": dict(capabilities),
        "checks": [dict(check) for check in checks],
        "artifact_bindings": [dict(binding) for binding in artifact_bindings or []],
        "statistical": statistical,
        "diagnostic_only": diagnostic_only,
    }
    for key, value in {
        "endpoint_fingerprint": endpoint_fingerprint,
        "method_policy": method_policy,
        "selected_method": selected_method,
        "target_before": dict(target_before) if target_before is not None else None,
        "target_after": dict(target_after) if target_after is not None else None,
        "operation_id": operation_id,
        "quantitative_policy": dict(quantitative_policy)
        if quantitative_policy is not None
        else None,
        "configured_identity": dict(configured_identity)
        if configured_identity is not None
        else None,
    }.items():
        if value is not None:
            document[key] = value
    validate_receipt(document)
    return document


def validate_receipt(document: Mapping[str, Any]) -> None:
    """Reject unbounded, forged, or incomplete receipt claims."""

    allowed = {
        "schema",
        "source",
        "board_id",
        "session_id",
        "status",
        "reason",
        "capture_request_file_sha256",
        "session_request_sha256",
        "capabilities_sha256",
        "capabilities",
        "endpoint_fingerprint",
        "method_policy",
        "selected_method",
        "target_before",
        "target_after",
        "operation_id",
        "quantitative_policy",
        "configured_identity",
        "checks",
        "artifact_bindings",
        "statistical",
        "diagnostic_only",
    }
    unknown = set(document) - allowed
    missing = {
        "schema",
        "source",
        "board_id",
        "session_id",
        "status",
        "reason",
        "capture_request_file_sha256",
        "session_request_sha256",
        "capabilities_sha256",
        "capabilities",
        "checks",
        "artifact_bindings",
        "statistical",
        "diagnostic_only",
    } - set(document)
    if unknown or missing:
        raise SamplingVerificationError(
            f"receipt fields invalid: missing={sorted(missing)}, unknown={sorted(unknown)}"
        )
    if document["schema"] != SCHEMA or document["source"] != "generic-pc-sampling-hil":
        raise SamplingVerificationError("unsupported sampling receipt schema or source")
    for key in ("board_id", "reason"):
        if (
            not isinstance(document[key], str)
            or not document[key].strip()
            or len(document[key]) > 1024
        ):
            raise SamplingVerificationError(f"{key} must be a bounded non-empty string")
    if (
        not isinstance(document["session_id"], str)
        or _SESSION.fullmatch(document["session_id"]) is None
    ):
        raise SamplingVerificationError("session_id is invalid")
    if document["status"] not in {"PASS", "NOT_READY", "FAIL"}:
        raise SamplingVerificationError("status must be PASS, NOT_READY, or FAIL")
    for key in (
        "capture_request_file_sha256",
        "session_request_sha256",
        "capabilities_sha256",
    ):
        if not isinstance(document[key], str) or _HEX.fullmatch(document[key]) is None:
            raise SamplingVerificationError(f"{key} must be lowercase SHA-256")
    capabilities = document["capabilities"]
    if (
        not isinstance(capabilities, dict)
        or len(canonical_bytes(capabilities)) > _MAX_CAPABILITIES
    ):
        raise SamplingVerificationError("capabilities must be a bounded object")
    if sha256(capabilities) != document["capabilities_sha256"]:
        raise SamplingVerificationError(
            "capabilities_sha256 does not match capabilities"
        )
    for key in ("statistical", "diagnostic_only"):
        if not isinstance(document[key], bool):
            raise SamplingVerificationError(f"{key} must be boolean")
    for key in ("target_before", "target_after"):
        if key in document:
            state = document[key]
            if not isinstance(state, dict) or set(state) != {
                "powered",
                "running",
                "halted",
            }:
                raise SamplingVerificationError(f"{key} must be a target-state object")
            if any(
                not (isinstance(value, bool) or value == "unknown")
                for value in state.values()
            ):
                raise SamplingVerificationError(
                    f"{key} contains an invalid target state"
                )
    if "operation_id" in document and (
        not isinstance(document["operation_id"], str)
        or _OPERATION.fullmatch(document["operation_id"]) is None
    ):
        raise SamplingVerificationError(
            "operation_id must be 32 lowercase hex characters"
        )
    if "endpoint_fingerprint" in document and (
        not isinstance(document["endpoint_fingerprint"], str)
        or _HEX.fullmatch(document["endpoint_fingerprint"]) is None
    ):
        raise SamplingVerificationError(
            "endpoint_fingerprint must be lowercase SHA-256"
        )
    if "configured_identity" in document:
        identity = document["configured_identity"]
        if (
            not isinstance(identity, dict)
            or set(identity)
            != {
                "mcu_family",
                "probe_id",
                "scope",
                "expected_probe_fingerprint",
                "observed_probe_fingerprint",
                "probe_identity_observed",
                "target_id_observed",
            }
            or not isinstance(identity["mcu_family"], str)
            or not identity["mcu_family"].strip()
            or not isinstance(identity["probe_id"], str)
            or not identity["probe_id"].strip()
            or identity["scope"]
            not in {"configured_endpoint_class", "observed_probe_endpoint_class"}
            or not isinstance(identity["expected_probe_fingerprint"], str)
            or (
                identity["expected_probe_fingerprint"] != "unconfigured"
                and _HEX.fullmatch(identity["expected_probe_fingerprint"]) is None
            )
            or not isinstance(identity["observed_probe_fingerprint"], str)
            or (
                identity["observed_probe_fingerprint"] != "unobserved"
                and _HEX.fullmatch(identity["observed_probe_fingerprint"]) is None
            )
            or not isinstance(identity["probe_identity_observed"], bool)
            or identity["target_id_observed"] is not False
            or (
                identity["scope"] == "observed_probe_endpoint_class"
                and (
                    identity["observed_probe_fingerprint"] == "unobserved"
                    or identity["probe_identity_observed"] is not True
                )
            )
            or (
                identity["scope"] == "configured_endpoint_class"
                and (
                    identity["observed_probe_fingerprint"] != "unobserved"
                    or identity["probe_identity_observed"] is not False
                )
            )
        ):
            raise SamplingVerificationError("configured_identity is invalid")
    if "method_policy" in document and document["method_policy"] not in {
        "realtime_only",
        "allow_stop_and_go",
    }:
        raise SamplingVerificationError("method_policy is invalid")
    if "selected_method" in document and document["selected_method"] not in {
        "realtime",
        "stop_and_go",
    }:
        raise SamplingVerificationError("selected_method is invalid")
    if "quantitative_policy" in document:
        policy = document["quantitative_policy"]
        expected = {
            "min_in_scope_hits",
            "min_observed_duration_ns",
            "min_stop_and_go_retained_runtime_percent",
            "max_snoop_failures",
        }
        if not isinstance(policy, dict) or set(policy) != expected:
            raise SamplingVerificationError("quantitative_policy fields are invalid")
        if (
            not _is_integer(policy["min_in_scope_hits"])
            or policy["min_in_scope_hits"] < 100
            or not _is_integer(policy["min_observed_duration_ns"])
            or policy["min_observed_duration_ns"] < 100_000_000
            or not _is_number(policy["min_stop_and_go_retained_runtime_percent"])
            or not 90 <= policy["min_stop_and_go_retained_runtime_percent"] <= 100
            or not _is_integer(policy["max_snoop_failures"])
            or policy["max_snoop_failures"] != 0
        ):
            raise SamplingVerificationError(
                "quantitative_policy is weaker than Host defaults"
            )
    checks = document["checks"]
    bindings = document["artifact_bindings"]
    if (
        not isinstance(checks, list)
        or len(checks) > 64
        or not isinstance(bindings, list)
        or len(bindings) > 16
    ):
        raise SamplingVerificationError("checks or artifact_bindings exceed bounds")
    if any(
        not isinstance(row, dict)
        or set(row) != {"name", "passed", "reason"}
        or not isinstance(row["name"], str)
        or not isinstance(row["passed"], bool)
        or not isinstance(row["reason"], str)
        for row in checks
    ):
        raise SamplingVerificationError(
            "checks must have exact name/passed/reason fields"
        )
    roles: set[str] = set()
    for row in bindings:
        if not isinstance(row, dict) or set(row) != {"role", "artifact_id", "sha256"}:
            raise SamplingVerificationError("artifact binding fields are invalid")
        if row["role"] in roles or row["role"] not in {
            "capture_receipt",
            "histogram",
            "address_heatmap",
            "svg",
        }:
            raise SamplingVerificationError(
                "artifact binding role is invalid or duplicated"
            )
        roles.add(row["role"])
        if (
            not isinstance(row["artifact_id"], str)
            or not row["artifact_id"]
            or not isinstance(row["sha256"], str)
            or _HEX.fullmatch(row["sha256"]) is None
        ):
            raise SamplingVerificationError("artifact binding identity is invalid")
    if document["status"] == "PASS":
        expected_running_target = {
            "powered": True,
            "running": True,
            "halted": False,
        }
        if roles != {"capture_receipt", "histogram", "address_heatmap", "svg"}:
            raise SamplingVerificationError(
                "PASS requires capture receipt, histogram, address heatmap, and SVG bindings"
            )
        if not document["statistical"] or not document["diagnostic_only"]:
            raise SamplingVerificationError(
                "PASS requires statistical=true and diagnostic_only=true"
            )
        if (
            not document.get("operation_id")
            or not document.get("quantitative_policy")
            or not document.get("endpoint_fingerprint")
            or not document.get("method_policy")
            or not document.get("selected_method")
            or "target_before" not in document
            or "target_after" not in document
            or "configured_identity" not in document
        ):
            raise SamplingVerificationError(
                "PASS requires operation, endpoint, method, target, and policy evidence"
            )
        if any(row["passed"] is not True for row in checks):
            raise SamplingVerificationError("PASS requires every check to pass")
        identity = document["configured_identity"]
        if (
            identity["scope"] != "observed_probe_endpoint_class"
            or identity["probe_identity_observed"] is not True
            or identity["expected_probe_fingerprint"]
            != identity["observed_probe_fingerprint"]
        ):
            raise SamplingVerificationError(
                "PASS requires an observed probe identity matching the configured pin"
            )
        if (
            capabilities.get("schema") != "t32perf.sampling-capabilities/v1"
            or capabilities.get("endpoint_fingerprint_scheme")
            != "t32perf.endpoint-fingerprint/v2"
            or capabilities.get("probe_fingerprint")
            != identity["observed_probe_fingerprint"]
            or capabilities.get("probe_fingerprint")
            != identity["expected_probe_fingerprint"]
            or capabilities.get("endpoint_fingerprint")
            != document["endpoint_fingerprint"]
        ):
            raise SamplingVerificationError(
                "PASS requires capabilities pinned to the observed probe and endpoint"
            )
        for key in ("target_before", "target_after"):
            if document[key] != expected_running_target:
                raise SamplingVerificationError(
                    "PASS requires target_before and target_after to show a powered, "
                    "running, non-halted target"
                )
    elif bindings:
        raise SamplingVerificationError(
            "NOT_READY and FAIL receipts cannot bind final artifacts"
        )


def write_receipt(document: Mapping[str, Any], output: Path) -> None:
    validate_receipt(document)
    data = (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True).encode(
            "utf-8"
        )
        + b"\n"
    )
    if len(data) > _MAX_RECEIPT:
        raise SamplingVerificationError("receipt exceeds size limit")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise SamplingVerificationError(f"receipt already exists: {output}") from error


def load_receipt(source: Path | bytes | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(source, Path):
        data = source.read_bytes()
    elif isinstance(source, bytes):
        data = source
    else:
        data = canonical_bytes(source)
    if len(data) > _MAX_RECEIPT:
        raise SamplingVerificationError("receipt exceeds size limit")
    try:
        document = json.loads(data)
    except json.JSONDecodeError as error:
        raise SamplingVerificationError(f"receipt is not JSON: {error}") from error
    if not isinstance(document, dict):
        raise SamplingVerificationError("receipt must be an object")
    validate_receipt(document)
    return document


def _host_result(document: Mapping[str, Any], command: str) -> dict[str, Any]:
    if set(document) != {"ok", "command", "result"}:
        raise SamplingVerificationError(f"{command} returned an invalid Host envelope")
    if document.get("ok") is not True or document.get("command") != command:
        raise SamplingVerificationError(f"{command} did not report Host success")
    result = document.get("result")
    if not isinstance(result, dict):
        raise SamplingVerificationError(f"{command} result must be an object")
    return dict(result)


def _artifact(
    value: object,
    *,
    expected_id: str | None = None,
    id_prefix: str | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SamplingVerificationError("Host artifact reference must be an object")
    artifact_id = value.get("id")
    digest = value.get("sha256")
    if (
        not isinstance(artifact_id, str)
        or not artifact_id
        or not isinstance(digest, str)
        or _HEX.fullmatch(digest) is None
    ):
        raise SamplingVerificationError("Host artifact identity is invalid")
    if expected_id is not None and artifact_id != expected_id:
        raise SamplingVerificationError(f"expected Host artifact {expected_id}")
    if id_prefix is not None and not artifact_id.startswith(id_prefix):
        raise SamplingVerificationError(f"Host artifact must start with {id_prefix}")
    return dict(value)


def _stable_regular_snapshot(
    path: Path, label: str, *, collect: bool
) -> tuple[bytes, str, int]:
    """Read one no-follow, single-link regular file and verify a stable SHA-256."""

    ancestors = _plain_ancestor_snapshots(path, label)
    try:
        before_link = path.lstat()
    except OSError as error:
        raise SamplingVerificationError(f"missing audited {label}: {error}") from error
    if (
        _is_reparse(before_link)
        or stat.S_ISLNK(before_link.st_mode)
        or not stat.S_ISREG(before_link.st_mode)
    ):
        raise SamplingVerificationError(f"audited {label} must be a plain regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SamplingVerificationError(
            f"cannot open audited {label}: {error}"
        ) from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or (before.st_dev, before.st_ino)
            != (before_link.st_dev, before_link.st_ino)
            or before.st_size > _AUDIT_FILE_LIMIT
        ):
            raise SamplingVerificationError(
                f"audited {label} is not a stable single-link file"
            )
        digest = hashlib.sha256()
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 64 * 1024):
            total += len(chunk)
            if total > _AUDIT_FILE_LIMIT:
                raise SamplingVerificationError(f"audited {label} exceeds byte limit")
            digest.update(chunk)
            if collect:
                chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (before.st_dev, before.st_ino, before.st_size, before.st_nlink) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_nlink,
    ) or total != before.st_size:
        raise SamplingVerificationError(f"audited {label} changed while being read")
    try:
        after_path = path.lstat()
    except OSError as error:
        raise SamplingVerificationError(
            f"audited {label} disappeared while being read"
        ) from error
    if (
        _is_reparse(after_path)
        or stat.S_ISLNK(after_path.st_mode)
        or (after_path.st_dev, after_path.st_ino) != (after.st_dev, after.st_ino)
    ):
        raise SamplingVerificationError(
            f"audited {label} path changed while being read"
        )
    _verify_plain_ancestors(ancestors, label)
    return (b"".join(chunks) if collect else b"", digest.hexdigest(), total)


def _is_reparse(metadata: os.stat_result) -> bool:
    """Reject Windows junctions/reparse points as well as POSIX symlinks."""

    return bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _plain_ancestor_snapshots(
    path: Path, label: str
) -> list[tuple[Path, tuple[int, int, int]]]:
    """Pin every existing ancestor against symlink/junction swaps during a read."""

    snapshots = []
    current = path.parent
    while current != current.parent:
        try:
            metadata = current.lstat()
        except OSError as error:
            raise SamplingVerificationError(
                f"missing audited {label} ancestor"
            ) from error
        if (
            _is_reparse(metadata)
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
        ):
            raise SamplingVerificationError(
                f"audited {label} ancestor must be a plain directory"
            )
        snapshots.append(
            (current, (metadata.st_dev, metadata.st_ino, metadata.st_mode))
        )
        current = current.parent
    return snapshots


def _verify_plain_ancestors(
    snapshots: list[tuple[Path, tuple[int, int, int]]], label: str
) -> None:
    for path, identity in snapshots:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise SamplingVerificationError(
                f"audited {label} ancestor changed while being read"
            ) from error
        if (
            _is_reparse(metadata)
            or stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino, metadata.st_mode) != identity
        ):
            raise SamplingVerificationError(
                f"audited {label} ancestor changed while being read"
            )


def _require_exact_object(
    value: object, fields: set[str], label: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise SamplingVerificationError(f"audited {label} fields are invalid")
    return value


def _audit_capture_receipt(
    content: bytes,
    *,
    session_id: str,
    operation_id: str,
    request_sha256: str,
    endpoint_fingerprint: str,
    histogram_digest: str,
    histogram_size: int,
) -> None:
    try:
        receipt = _strict_json_loads(content.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise SamplingVerificationError("audited capture receipt is invalid") from error
    receipt = _require_exact_object(
        receipt,
        {
            "schema",
            "session_id",
            "session_operation_id",
            "transaction_id",
            "endpoint_fingerprint",
            "endpoint_fingerprint_scheme",
            "session_request_sha256",
            "histogram_sha256",
            "histogram_size_bytes",
            "journal_event_claims",
        },
        "capture receipt",
    )
    if (
        receipt["schema"] != "t32perf.sampling-capture-receipt/v1"
        or receipt["session_id"] != session_id
        or receipt["session_operation_id"] != operation_id
        or receipt["session_request_sha256"] != request_sha256
        or receipt["endpoint_fingerprint"] != endpoint_fingerprint
        or receipt["endpoint_fingerprint_scheme"] != "t32perf.endpoint-fingerprint/v2"
        or receipt["histogram_sha256"] != histogram_digest
        or receipt["histogram_size_bytes"] != histogram_size
        or not isinstance(receipt["transaction_id"], str)
        or _UUID4.fullmatch(receipt["transaction_id"]) is None
    ):
        raise SamplingVerificationError("audited capture receipt identity is invalid")
    events = [
        "configure_intent",
        "configure_observed",
        "start_intent",
        "start_observed",
        "stop_intent",
        "stop_observed",
        "cleanup_intent",
        "cleanup_observed",
        "export_intent",
        "export_observed",
    ]
    claims = receipt["journal_event_claims"]
    if not isinstance(claims, list) or len(claims) != len(events):
        raise SamplingVerificationError("audited capture receipt journal is incomplete")
    digests: set[str] = set()
    for sequence, (claim, event) in enumerate(zip(claims, events, strict=True), 1):
        claim = _require_exact_object(
            claim, {"sequence", "event", "sha256"}, "journal claim"
        )
        digest = claim["sha256"]
        if (
            claim["sequence"] != sequence
            or claim["event"] != event
            or not isinstance(digest, str)
            or _HEX.fullmatch(digest) is None
            or digest in digests
        ):
            raise SamplingVerificationError(
                "audited capture receipt journal sequence is invalid"
            )
        digests.add(digest)


def _safe_debugger_text(value: object) -> bool:
    """Accept a bounded, display-safe debugger supplied identifier."""

    return (
        isinstance(value, str)
        and 0 < len(value.encode("utf-8")) <= 256
        and not any(
            ord(character) < 32 or 127 <= ord(character) <= 159 for character in value
        )
    )


def _debugger_locations(histogram: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Validate optional, diagnostic-only TRACE32 runtime symbol labels.

    These annotations are intentionally tied to existing PC buckets.  They do
    not establish an ELF/image identity and therefore cannot raise firmware
    trust above ``unverified``.
    """

    symbolization = histogram.get("debugger_symbolization")
    if symbolization is None:
        return []
    symbolization = _require_exact_object(
        symbolization,
        {"source", "trust", "refinement_granularity_bytes", "locations"},
        "debugger symbolization",
    )
    firmware = histogram.get("firmware")
    if (
        symbolization["source"] != "trace32_symbol_table"
        or symbolization["trust"] != "debugger_reported"
        or symbolization["refinement_granularity_bytes"] != 4
        or not isinstance(symbolization["locations"], list)
        or len(symbolization["locations"]) > 10
        or not isinstance(firmware, Mapping)
        or firmware.get("status") != "unverified"
    ):
        raise SamplingVerificationError("debugger symbolization provenance is invalid")
    buckets = histogram.get("buckets")
    if not isinstance(buckets, list):
        raise SamplingVerificationError("debugger symbolization buckets are invalid")
    bucket_by_range: dict[tuple[int, int], Mapping[str, Any]] = {}
    for bucket in buckets:
        if not isinstance(bucket, Mapping):
            raise SamplingVerificationError(
                "debugger symbolization buckets are invalid"
            )
        start, end = bucket.get("start_address"), bucket.get("end_address")
        if not _is_integer(start) or not _is_integer(end):
            raise SamplingVerificationError(
                "debugger symbolization buckets are invalid"
            )
        bucket_by_range[(start, end)] = bucket
    locations: list[dict[str, Any]] = []
    seen_buckets: set[tuple[int, int]] = set()
    previous_order: tuple[int, int, int] | None = None
    allowed = {
        "bucket_start_address",
        "bucket_end_address",
        "hits",
        "dominant_start_address",
        "dominant_end_address",
        "dominant_hits",
        "function_name",
        "source_file",
        "source_line",
    }
    required = {
        "bucket_start_address",
        "bucket_end_address",
        "hits",
        "dominant_start_address",
        "dominant_end_address",
        "dominant_hits",
    }
    for raw_location in symbolization["locations"]:
        if (
            not isinstance(raw_location, dict)
            or not required <= set(raw_location)
            or not set(raw_location) <= allowed
        ):
            raise SamplingVerificationError(
                "debugger symbolization location is invalid"
            )
        location = dict(raw_location)
        bucket_start, bucket_end = (
            location["bucket_start_address"],
            location["bucket_end_address"],
        )
        dominant_start, dominant_end = (
            location["dominant_start_address"],
            location["dominant_end_address"],
        )
        hits, dominant_hits = location["hits"], location["dominant_hits"]
        values = (
            bucket_start,
            bucket_end,
            dominant_start,
            dominant_end,
            hits,
            dominant_hits,
        )
        bucket = bucket_by_range.get((bucket_start, bucket_end))
        if (
            not all(_is_integer(value) for value in values)
            or bucket is None
            or hits != bucket.get("hits")
            or hits <= 0
            or dominant_start < bucket_start
            or dominant_end > bucket_end
            or dominant_start >= dominant_end
            or dominant_end - dominant_start
            > symbolization["refinement_granularity_bytes"]
            or dominant_hits <= 0
            or dominant_hits > hits
            or (bucket_start, bucket_end) in seen_buckets
        ):
            raise SamplingVerificationError(
                "debugger symbolization location is invalid"
            )
        has_function = "function_name" in location
        has_source_file = "source_file" in location
        has_source_line = "source_line" in location
        if has_function and (
            not _safe_debugger_text(location["function_name"])
            or "/" in location["function_name"]
            or "\\" in location["function_name"]
        ):
            raise SamplingVerificationError(
                "debugger symbolization function name is invalid"
            )
        if has_source_file != has_source_line:
            raise SamplingVerificationError(
                "debugger symbolization source location is invalid"
            )
        if has_source_file and (
            not _safe_debugger_text(location["source_file"])
            or "/" in location["source_file"]
            or "\\" in location["source_file"]
            or not _is_integer(location["source_line"])
            or location["source_line"] <= 0
        ):
            raise SamplingVerificationError(
                "debugger symbolization source location is invalid"
            )
        if not has_function and not (has_source_file and has_source_line):
            raise SamplingVerificationError(
                "debugger symbolization location is unresolved"
            )
        order = (-hits, bucket_start, bucket_end)
        if previous_order is not None and order < previous_order:
            raise SamplingVerificationError(
                "debugger symbolization locations are unordered"
            )
        previous_order = order
        seen_buckets.add((bucket_start, bucket_end))
        locations.append(location)
    return locations


def _audit_address_heatmap(
    content: bytes, *, histogram: Mapping[str, Any], histogram_digest: str
) -> dict[str, Any]:
    try:
        heatmap = _strict_json_loads(content.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise SamplingVerificationError("audited address heatmap is invalid") from error
    heatmap = _require_exact_object(
        heatmap,
        {
            "schema",
            "session_id",
            "histogram_sha256",
            "quality",
            "projection_kind",
            "quantitative_policy",
            "denominator_hits",
            "attributed_hits",
            "unattributed_hits",
            "out_of_scope_hits",
            "cells",
        },
        "address heatmap",
    )
    policy = {
        "min_in_scope_hits": 100,
        "min_observed_duration_ns": 100_000_000,
        "min_stop_and_go_retained_runtime_percent": 90.0,
        "max_snoop_failures": 0,
    }
    if (
        heatmap["schema"] != "t32perf.heatmap/v1"
        or heatmap["session_id"] != histogram.get("session_id")
        or heatmap["histogram_sha256"] != histogram_digest
        or heatmap["quality"] != "statistical"
        or heatmap["projection_kind"] != "address_range"
        or heatmap["quantitative_policy"] != policy
        or heatmap["denominator_hits"] != histogram.get("in_scope_hits")
        or heatmap["unattributed_hits"] != 0
        or heatmap["out_of_scope_hits"] != {"status": "unknown"}
        or not isinstance(heatmap["cells"], list)
    ):
        raise SamplingVerificationError("audited address heatmap provenance is invalid")
    buckets = histogram.get("buckets")
    if not isinstance(buckets, list) or len(heatmap["cells"]) != len(buckets):
        raise SamplingVerificationError("audited address heatmap coverage is invalid")
    locations = _debugger_locations(histogram)
    locations_by_bucket = {
        (item["bucket_start_address"], item["bucket_end_address"]): item
        for item in locations
    }
    attributed = 0
    for cell, bucket in zip(heatmap["cells"], buckets, strict=True):
        if (
            not isinstance(cell, dict)
            or not {"key", "display_name", "hits"} <= set(cell)
            or not set(cell) <= {"key", "display_name", "hits", "debugger_location"}
        ):
            raise SamplingVerificationError("address heatmap cell fields are invalid")
        expected_key = {
            "kind": "address_range",
            "start_address": bucket["start_address"],
            "end_address": bucket["end_address"],
        }
        expected_name = f"{bucket['start_address']:#x}..{bucket['end_address']:#x}"
        expected_location = locations_by_bucket.get(
            (bucket["start_address"], bucket["end_address"])
        )
        if (
            cell["key"] != expected_key
            or cell["display_name"] != expected_name
            or cell["hits"] != bucket["hits"]
            or not _is_integer(cell["hits"])
            or cell.get("debugger_location") != expected_location
            or (expected_location is None and "debugger_location" in cell)
        ):
            raise SamplingVerificationError(
                "audited address heatmap cell differs from histogram"
            )
        attributed += cell["hits"]
    if (
        heatmap["attributed_hits"] != attributed
        or attributed != heatmap["denominator_hits"]
    ):
        raise SamplingVerificationError("audited address heatmap accounting is invalid")
    return heatmap


def _text_values(root: ElementTree.Element) -> list[str]:
    return [
        "".join(element.itertext())
        for element in root.iter()
        if element.tag.endswith("text")
    ]


def _class_text_values(root: ElementTree.Element, class_name: str) -> list[str]:
    return [
        "".join(element.itertext())
        for element in root.iter()
        if element.tag.endswith("text") and element.attrib.get("class") == class_name
    ]


def _svg_duration(value: int) -> str:
    if value % 1_000_000_000 == 0:
        return f"{value // 1_000_000_000} s"
    if value % 1_000_000 == 0:
        return f"{value // 1_000_000} ms"
    if value % 1_000 == 0:
        return f"{value // 1_000} µs"
    return f"{value} ns"


def _svg_address_label(cell: Mapping[str, Any]) -> str:
    key = cell["key"]
    return f"{key['start_address']:#010x}..{key['end_address']:#010x}"


def _svg_debugger_annotation(cell: Mapping[str, Any]) -> str | None:
    location = cell.get("debugger_location")
    if not isinstance(location, Mapping):
        return None
    annotation = f"dominant {location['dominant_hits']}/{location['hits']}"
    label_parts: list[str] = []
    if isinstance(location.get("function_name"), str):
        label_parts.append(location["function_name"])
    if isinstance(location.get("source_file"), str) and _is_integer(
        location.get("source_line")
    ):
        label_parts.append(f"{location['source_file']}:{location['source_line']}")
    if label_parts:
        label = " · ".join(label_parts)
        annotation += f" · {label if len(label) <= 46 else f'{label[:46]}…'}"
    return annotation


def _audit_svg(
    content: bytes,
    *,
    heatmap: Mapping[str, Any],
    histogram: Mapping[str, Any],
) -> None:
    # ElementTree does not expand external entities; reject declarations before parsing
    # so a forged document cannot claim renderer provenance through a DTD.
    if len(content) > 1024 * 1024:
        raise SamplingVerificationError("audited SVG exceeds renderer output limit")
    try:
        document = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise SamplingVerificationError("audited SVG must be strict UTF-8") from error
    if "<?" in document:
        raise SamplingVerificationError(
            "audited SVG must not contain an XML declaration or processing instruction"
        )
    upper = document.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise SamplingVerificationError("audited SVG must not contain DTD or ENTITY")
    try:
        root = ElementTree.fromstring(document)
    except ElementTree.ParseError as error:
        raise SamplingVerificationError("audited SVG is not well-formed XML") from error
    namespace = "{http://www.w3.org/2000/svg}"
    if root.tag != f"{namespace}svg":
        raise SamplingVerificationError("audited SVG root is invalid")
    allowed_tags = {"svg", "title", "desc", "style", "text", "line", "rect"}
    allowed_attributes = {
        "svg": {"width", "height", "viewBox", "role", "aria-labelledby"},
        "title": {"id"},
        "desc": {"id"},
        "style": set(),
        "text": {"class", "x", "y"},
        "line": {"class", "x1", "y1", "x2", "y2"},
        "rect": {"class", "x", "y", "width", "height"},
    }
    for element in root.iter():
        if not isinstance(element.tag, str) or not element.tag.startswith(namespace):
            raise SamplingVerificationError("audited SVG contains a foreign namespace")
        tag = element.tag.removeprefix(namespace)
        if tag not in allowed_tags or set(element.attrib) != allowed_attributes[tag]:
            raise SamplingVerificationError(
                "audited SVG contains an unsupported element or attribute"
            )
        if element is not root and list(element):
            raise SamplingVerificationError(
                "audited SVG leaf elements must not have children"
            )
    height = root.attrib.get("height")
    if (
        root.attrib.get("width") != "1000"
        or not isinstance(height, str)
        or not height.isdecimal()
        or int(height) <= 0
        or root.attrib.get("viewBox") != f"0 0 1000 {height}"
        or root.attrib.get("role") != "img"
        or root.attrib.get("aria-labelledby") != "title desc"
    ):
        raise SamplingVerificationError(
            "audited SVG viewport or accessibility is invalid"
        )
    titles = [
        item
        for item in root
        if item.tag == f"{namespace}title" and item.attrib.get("id") == "title"
    ]
    descriptions = [
        item
        for item in root
        if item.tag == f"{namespace}desc" and item.attrib.get("id") == "desc"
    ]
    if len(titles) != 1 or len(descriptions) != 1:
        raise SamplingVerificationError("audited SVG title or description is missing")
    text = _text_values(root)
    cells = heatmap["cells"]
    top = sorted(
        cells,
        key=lambda row: (
            -row["hits"],
            row["display_name"],
            row["key"]["start_address"],
            row["key"]["end_address"],
        ),
    )[:25]
    has_annotations = any("debugger_location" in cell for cell in top)
    omitted = max(0, len(cells) - len(top))
    truncation = (
        "All attributed rows are shown."
        if omitted == 0
        else f"Top rows shown; {omitted} attributed row(s) omitted by max_rows."
    )
    expected_title = "Address-range statistical PC-sample hotspots"
    expected_description = (
        "Statistical PC-hit projection. "
        f"{heatmap['denominator_hits']} in-scope samples; "
        f"{heatmap['unattributed_hits']} unattributed samples. {truncation}."
    )
    if (
        "".join(titles[0].itertext()) != expected_title
        or "".join(descriptions[0].itertext()) != expected_description
    ):
        raise SamplingVerificationError("audited SVG title or description is invalid")
    firmware = histogram.get("firmware")
    firmware_status = firmware.get("status") if isinstance(firmware, dict) else None
    if firmware_status == "deployment_asserted":
        diagnostic = (
            "Evidence status: diagnostic only — ELF was precommitted, target image "
            "was not compared."
        )
    elif (
        histogram.get("snoop_failures") != 0
        or histogram.get("target_state_before", {}).get("running") is not True
        or histogram.get("target_state_after", {}).get("running") is not True
    ):
        diagnostic = (
            "Evidence status: diagnostic only — snoop failures or a non-running target "
            "boundary were observed."
        )
    else:
        diagnostic = "Evidence status: statistical estimate."
    required = {
        expected_title,
        "Statistical PC samples — not an execution-completeness or exact-time claim",
        f"In-scope hits: {heatmap['denominator_hits']}",
        diagnostic,
    }
    if not required.issubset(text):
        raise SamplingVerificationError(
            "audited SVG lacks statistical renderer provenance"
        )
    method = histogram["method"]
    method_line = (
        "RealTime"
        if method["kind"] == "realtime"
        else (
            "StopAndGo (retained runtime configured "
            f"{method['configured_retained_runtime_percent']:.1f}%, observed "
            f"{method['observed_retained_runtime_percent']:.1f}%)"
        )
    )
    firmware_status_text = {
        "verified": "verified",
        "deployment_asserted": "deployment asserted (target image not compared)",
        "unverified": "unverified",
        "mismatch": "mismatch",
    }.get(firmware_status)
    if firmware_status_text is None:
        raise SamplingVerificationError("audited SVG firmware status is invalid")
    expected_metadata = [
        f"Method: {method_line} · intrusive: {str(histogram['intrusive']).lower()}",
        f"CPU: {histogram['cpu']} · core: {histogram['core_id']} · address space: {histogram['address_space']}",
        f"Requested duration: {_svg_duration(histogram['requested_duration_ns'])} · observed duration: {_svg_duration(histogram['observed_duration_ns'])}",
        f"In-scope hits: {heatmap['denominator_hits']}",
        f"Unattributed in-scope hits: {heatmap['unattributed_hits']}",
        f"Last rate snapshot: {histogram['last_sample_rate_hz']} Hz (not an average)",
        f"PC-snoop failures: {histogram['snoop_failures']}",
        f"Firmware status: {firmware_status_text}",
        f"ELF SHA-256: {firmware.get('elf_sha256', 'unverified')}",
        "Quantitative gate: "
        f"≥{heatmap['quantitative_policy']['min_in_scope_hits']} in-scope hits · "
        f"≥{_svg_duration(heatmap['quantitative_policy']['min_observed_duration_ns'])} observed · "
        f"snoop failures ≤{heatmap['quantitative_policy']['max_snoop_failures']} · "
        "StopAndGo retained runtime ≥"
        f"{heatmap['quantitative_policy']['min_stop_and_go_retained_runtime_percent']:.1f}%",
        diagnostic,
    ]
    if has_annotations:
        expected_metadata.append(
            "TRACE32 symbol-table labels: debugger-reported; labels do not verify firmware"
        )
    metadata_nodes = [
        item
        for item in root
        if item.tag == f"{namespace}text" and item.attrib.get("class") == "metadata"
    ]
    if [
        "".join(item.itertext()) for item in metadata_nodes
    ] != expected_metadata or any(
        item.attrib != {"class": "metadata", "x": "32", "y": str(92 + (index * 20))}
        for index, item in enumerate(metadata_nodes)
    ):
        raise SamplingVerificationError("audited SVG metadata geometry is invalid")
    expected_labels = []
    expected_annotations = []
    expected_values = []
    expected_empty = []
    for cell in sorted(
        top, key=lambda row: (row["key"]["start_address"], row["key"]["end_address"])
    ):
        percent = cell["hits"] * 1000 // heatmap["denominator_hits"]
        expected_labels.append(_svg_address_label(cell))
        annotation = _svg_debugger_annotation(cell)
        if annotation is not None:
            expected_annotations.append(annotation)
        if cell["hits"] > 0:
            expected_values.append(f"{cell['hits']} / {percent // 10}.{percent % 10}%")
        else:
            expected_empty.append("not observed")
    if (
        _class_text_values(root, "label") != expected_labels
        or _class_text_values(root, "value") != expected_values
        or _class_text_values(root, "empty") != expected_empty
        or _class_text_values(root, "annotation") != expected_annotations
    ):
        raise SamplingVerificationError("audited SVG rows differ from address heatmap")
    tracks = [
        item
        for item in root.iter()
        if item.tag == f"{namespace}line" and item.attrib.get("class") == "track"
    ]
    bars = [
        item
        for item in root.iter()
        if item.tag == f"{namespace}rect" and item.attrib.get("class") == "bar"
    ]
    truncation_rows = _class_text_values(root, "truncation")
    styles = [item for item in root if item.tag == f"{namespace}style"]
    expected_styles = [_SVG_STYLE.removeprefix("<style>").removesuffix("</style>")]
    if has_annotations:
        expected_styles.append(
            _SVG_ANNOTATION_STYLE.removeprefix("<style>").removesuffix("</style>")
        )
    if (
        any(style.attrib for style in styles)
        or [style.text for style in styles] != expected_styles
    ):
        raise SamplingVerificationError("audited SVG renderer style is invalid")
    metadata_count = len(expected_metadata)
    chart_top = 110 + (metadata_count * 20)
    row_count = len(top) + int(heatmap["unattributed_hits"] > 0)
    row_height = 58 if has_annotations else 42
    expected_height = chart_top + 24 + (row_count * row_height) + (26 if omitted else 0)
    if int(height) != expected_height:
        raise SamplingVerificationError("audited SVG height is inconsistent with rows")
    texts = [item for item in root if item.tag == f"{namespace}text"]
    fixed_text = [
        ("heading", "32", "38", expected_title),
        (
            "subtitle",
            "32",
            "62",
            "Statistical PC samples — not an execution-completeness or exact-time claim",
        ),
        ("axis", "32", str(chart_top - 10), "Location"),
        ("axis", "434", str(chart_top - 10), "PC samples"),
    ]
    for class_name, x, y, value in fixed_text:
        if not any(
            item.attrib == {"class": class_name, "x": x, "y": y}
            and "".join(item.itertext()) == value
            for item in texts
        ):
            raise SamplingVerificationError(
                "audited SVG fixed text geometry is invalid"
            )
    for index, cell in enumerate(
        sorted(
            top,
            key=lambda row: (row["key"]["start_address"], row["key"]["end_address"]),
        )
    ):
        y = chart_top + (index * row_height)
        label = _svg_address_label(cell)
        if not any(
            item.attrib == {"class": "label", "x": "32", "y": str(y + 19)}
            and "".join(item.itertext()) == label
            for item in texts
        ):
            raise SamplingVerificationError("audited SVG label geometry is invalid")
        expected_track = {
            "class": "track",
            "x1": "434",
            "y1": str(y + 14),
            "x2": "814",
            "y2": str(y + 14),
        }
        if index >= len(tracks) or tracks[index].attrib != expected_track:
            raise SamplingVerificationError("audited SVG track geometry is invalid")
        if cell["hits"] > 0:
            width = cell["hits"] * 380 // heatmap["denominator_hits"]
            expected_bar = {
                "class": "bar",
                "x": "434",
                "y": str(y + 6),
                "width": str(width),
                "height": "16",
            }
            if not any(item.attrib == expected_bar for item in bars):
                raise SamplingVerificationError("audited SVG bar geometry is invalid")
            value = f"{cell['hits']} / {(cell['hits'] * 1000 // heatmap['denominator_hits']) // 10}.{(cell['hits'] * 1000 // heatmap['denominator_hits']) % 10}%"
            if not any(
                item.attrib == {"class": "value", "x": "824", "y": str(y + 19)}
                and "".join(item.itertext()) == value
                for item in texts
            ):
                raise SamplingVerificationError("audited SVG value geometry is invalid")
        annotation = _svg_debugger_annotation(cell)
        if annotation is not None and not any(
            item.attrib == {"class": "annotation", "x": "32", "y": str(y + 43)}
            and "".join(item.itertext()) == annotation
            for item in texts
        ):
            raise SamplingVerificationError(
                "audited SVG annotation geometry is invalid"
            )
    if (
        len(tracks) != len(top)
        or len(bars) != sum(cell["hits"] > 0 for cell in top)
        or truncation_rows != ([truncation] if omitted else [])
    ):
        raise SamplingVerificationError("audited SVG truncation evidence is invalid")
    expected_children = [
        ("title", None),
        ("desc", None),
        ("style", None),
        *([("style", None)] if has_annotations else []),
        ("text", "heading"),
        ("text", "subtitle"),
        *[("text", "metadata")] * metadata_count,
        ("text", "axis"),
        ("text", "axis"),
    ]
    for cell in sorted(
        top, key=lambda row: (row["key"]["start_address"], row["key"]["end_address"])
    ):
        expected_children.extend(
            [("text", "label"), ("line", "track")]
            + (
                [("rect", "bar"), ("text", "value")]
                if cell["hits"] > 0
                else [("text", "empty")]
            )
        )
        if "debugger_location" in cell:
            expected_children.append(("text", "annotation"))
    if omitted:
        expected_children.append(("text", "truncation"))
    actual_children = [
        (element.tag.removeprefix(namespace), element.attrib.get("class"))
        for element in root
    ]
    if actual_children != expected_children:
        raise SamplingVerificationError("audited SVG child sequence is invalid")


def _audit_host_session(
    board: BoardConfig | SamplingBoardConfig,
    *,
    session_id: str,
    operation_id: str,
    request_sha256: str,
    configured_request: Mapping[str, Any],
    wrapper_artifacts: Mapping[str, Mapping[str, Any]],
    expected_histogram_bytes: bytes,
    endpoint_fingerprint: str,
) -> dict[str, Any]:
    """Require durable Host files and the exact four-node sampling DAG before PASS."""

    session = board.artifact_root / session_id
    try:
        metadata = session.lstat()
    except OSError as error:
        raise SamplingVerificationError(f"missing audited session: {error}") from error
    if (
        _is_reparse(metadata)
        or stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise SamplingVerificationError("audited session must be a plain directory")
    request_bytes, request_digest, _ = _stable_regular_snapshot(
        session / "request.json", "request.json", collect=True
    )
    if request_digest != request_sha256:
        raise SamplingVerificationError(
            "audited request.json digest differs from Host request"
        )
    try:
        request = _strict_json_loads(request_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise SamplingVerificationError(
            f"audited request.json is invalid: {error}"
        ) from error
    if not isinstance(request, dict) or request != configured_request:
        raise SamplingVerificationError(
            "audited request.json differs from configured request"
        )
    state_bytes, _, _ = _stable_regular_snapshot(
        session / "state.json", "state.json", collect=True
    )
    try:
        state = _strict_json_loads(state_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise SamplingVerificationError(
            f"audited state.json is invalid: {error}"
        ) from error
    if (
        not isinstance(state, dict)
        or set(state)
        != {"schema", "created_at", "state", "operation_id", "revision", "updated_at"}
        or state.get("schema") != "t32perf.state/v1"
        or state.get("operation_id") != operation_id
        or state.get("state") != "captured"
        or not isinstance(state.get("created_at"), str)
        or not state["created_at"]
        or not isinstance(state.get("updated_at"), str)
        or not state["updated_at"]
        or not _is_integer(state.get("revision"))
        or state["revision"] < 0
    ):
        raise SamplingVerificationError(
            "audited state.json is not the captured Host operation"
        )
    index = session / "artifact-index"
    try:
        index_meta = index.lstat()
        names = sorted(entry.name for entry in index.iterdir())
    except OSError as error:
        raise SamplingVerificationError(
            f"cannot inspect audited artifact index: {error}"
        ) from error
    expected_names = sorted(f"{artifact_id}.json" for artifact_id in _CATALOG)
    if (
        _is_reparse(index_meta)
        or stat.S_ISLNK(index_meta.st_mode)
        or not stat.S_ISDIR(index_meta.st_mode)
        or names != expected_names
    ):
        raise SamplingVerificationError(
            "audited artifact index is not the exact sampling catalog"
        )
    catalog: dict[str, dict[str, Any]] = {}
    expected_fields = {
        "id",
        "kind",
        "relative_path",
        "media_type",
        "size_bytes",
        "sha256",
        "producer",
        "input_artifact_ids",
    }
    for artifact_id, expected in _CATALOG.items():
        index_bytes, _, _ = _stable_regular_snapshot(
            index / f"{artifact_id}.json", f"artifact index {artifact_id}", collect=True
        )
        try:
            artifact = _strict_json_loads(index_bytes.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as error:
            raise SamplingVerificationError(
                f"audited artifact index {artifact_id} is invalid: {error}"
            ) from error
        if not isinstance(artifact, dict) or set(artifact) != expected_fields:
            raise SamplingVerificationError(
                f"audited artifact index {artifact_id} fields are invalid"
            )
        kind, relative_path, media_type, producer, inputs = expected
        if (
            artifact.get("id"),
            artifact.get("kind"),
            artifact.get("relative_path"),
            artifact.get("media_type"),
            artifact.get("producer"),
            artifact.get("input_artifact_ids"),
        ) != (artifact_id, kind, relative_path, media_type, producer, inputs):
            raise SamplingVerificationError(
                f"audited artifact {artifact_id} DAG is invalid"
            )
        content, digest, size = _stable_regular_snapshot(
            session / relative_path, f"artifact {artifact_id}", collect=True
        )
        if artifact.get("sha256") != digest or artifact.get("size_bytes") != size:
            raise SamplingVerificationError(
                f"audited artifact {artifact_id} bytes do not match its catalog"
            )
        catalog[artifact_id] = artifact
        artifact["_audited_bytes"] = content
    for role, artifact_id in {
        "capture_receipt": "sampling-capture-receipt",
        "histogram": "sampling-pc-hit-histogram",
        "heatmap": "sampling-heatmap-address",
        "svg": "sampling-heatmap-address-svg-top025",
    }.items():
        artifact = catalog[artifact_id]
        expected_wrapper = {
            "id": artifact["id"],
            "kind": artifact["kind"],
            "path": artifact["relative_path"],
            "sha256": artifact["sha256"],
            "media_type": artifact["media_type"],
            "producer": artifact["producer"],
            "input_artifact_ids": artifact["input_artifact_ids"],
        }
        if dict(wrapper_artifacts[role]) != expected_wrapper:
            raise SamplingVerificationError(
                f"wrapper artifact {role} does not equal audited catalog"
            )
    histogram_bytes = catalog["sampling-pc-hit-histogram"]["_audited_bytes"]
    if histogram_bytes != expected_histogram_bytes:
        raise SamplingVerificationError(
            "audited histogram bytes differ from sidecar canonical export"
        )
    histogram = _strict_json_loads(histogram_bytes.decode("utf-8"))
    _audit_capture_receipt(
        catalog["sampling-capture-receipt"]["_audited_bytes"],
        session_id=session_id,
        operation_id=operation_id,
        request_sha256=request_sha256,
        endpoint_fingerprint=endpoint_fingerprint,
        histogram_digest=catalog["sampling-pc-hit-histogram"]["sha256"],
        histogram_size=catalog["sampling-pc-hit-histogram"]["size_bytes"],
    )
    heatmap = _audit_address_heatmap(
        catalog["sampling-heatmap-address"]["_audited_bytes"],
        histogram=histogram,
        histogram_digest=catalog["sampling-pc-hit-histogram"]["sha256"],
    )
    _audit_svg(
        catalog["sampling-heatmap-address-svg-top025"]["_audited_bytes"],
        heatmap=heatmap,
        histogram=histogram,
    )
    return heatmap


def _sidecar_histogram_bytes(histogram: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            histogram,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _expected_buckets(request: Mapping[str, Any]) -> list[tuple[int, int]]:
    bucket_size = request["bucket_size"]
    return [
        (start, min(start + bucket_size, item["end_address"]))
        for item in request["ranges"]
        for start in range(item["start_address"], item["end_address"], bucket_size)
    ]


def _validate_histogram(
    histogram: object,
    artifact: object,
    *,
    session_id: str,
    request: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(histogram, dict) or not isinstance(artifact, dict):
        raise SamplingVerificationError("sidecar capture result is incomplete")
    if histogram.get("schema") != "t32perf.pc-hit-histogram/v1":
        raise SamplingVerificationError("sidecar histogram schema is invalid")
    if (
        histogram.get("endpoint_fingerprint_scheme")
        != "t32perf.endpoint-fingerprint/v2"
    ):
        raise SamplingVerificationError(
            "sidecar histogram endpoint fingerprint scheme is invalid"
        )
    if (
        histogram.get("session_id") != session_id
        or histogram.get("requested_duration_ns") != request["duration_ms"] * 1_000_000
        or histogram.get("core_id") != request["core_id"]
        or histogram.get("address_space") != "P"
    ):
        raise SamplingVerificationError("sidecar histogram violates the Host request")
    buckets = histogram.get("buckets")
    expected = _expected_buckets(request)
    if not isinstance(buckets, list) or len(buckets) != len(expected):
        raise SamplingVerificationError("sidecar histogram bucket count is invalid")
    total = 0
    for bucket, (start, end) in zip(buckets, expected, strict=True):
        if (
            not isinstance(bucket, dict)
            or set(bucket) != {"start_address", "end_address", "hits"}
            or bucket.get("start_address") != start
            or bucket.get("end_address") != end
            or not _is_integer(bucket.get("hits"))
            or bucket["hits"] < 0
        ):
            raise SamplingVerificationError("sidecar histogram bucket is invalid")
        total += bucket["hits"]
    if histogram.get("in_scope_hits") != total:
        raise SamplingVerificationError("sidecar histogram hit accounting is invalid")
    _debugger_locations(histogram)
    method = histogram.get("method")
    if not isinstance(method, dict) or method.get("kind") not in {
        "realtime",
        "stop_and_go",
    }:
        raise SamplingVerificationError("sidecar histogram method is invalid")
    if (
        method["kind"] == "stop_and_go"
        and request["method_policy"] != "allow_stop_and_go"
    ):
        raise SamplingVerificationError("sidecar used unauthorized StopAndGo")
    data = _sidecar_histogram_bytes(histogram)
    digest = hashlib.sha256(data).hexdigest()
    if (
        artifact.get("sha256") != digest
        or artifact.get("size_bytes") != len(data)
        or not isinstance(artifact.get("relative_path"), str)
        or not artifact["relative_path"].startswith(
            f"capture/staging/pc-hit-histogram-{session_id}-"
        )
    ):
        raise SamplingVerificationError("sidecar artifact metadata is invalid")
    return dict(histogram), dict(artifact)


def _quantitative_capture_ready(histogram: Mapping[str, Any]) -> tuple[bool, str]:
    states = [histogram.get("target_state_before"), histogram.get("target_state_after")]
    state_ok = all(
        isinstance(state, dict)
        and state.get("powered") is True
        and state.get("running") is True
        and state.get("halted") is False
        for state in states
    )
    method = histogram["method"]
    retained_ok = method["kind"] == "realtime" or (
        _is_number(method.get("observed_retained_runtime_percent"))
        and method["observed_retained_runtime_percent"] >= 90
    )
    ready = (
        state_ok
        and histogram.get("cleanup_complete") is True
        and _is_integer(histogram.get("last_sample_rate_hz"))
        and histogram["last_sample_rate_hz"] > 0
        and _is_integer(histogram.get("in_scope_hits"))
        and histogram["in_scope_hits"] >= 100
        and _is_integer(histogram.get("observed_duration_ns"))
        and histogram["observed_duration_ns"] >= 100_000_000
        and histogram.get("snoop_failures") == 0
        and retained_ok
    )
    return (
        ready,
        "default Host quantitative policy" if ready else "insufficient_quality",
    )


def _histogram_meets_policy(
    histogram: Mapping[str, Any], policy: Mapping[str, Any]
) -> bool:
    """Apply the persisted heatmap quantitative gate to the source histogram."""

    method = histogram["method"]
    return (
        histogram["in_scope_hits"] >= policy["min_in_scope_hits"]
        and histogram["observed_duration_ns"] >= policy["min_observed_duration_ns"]
        and histogram["snoop_failures"] <= policy["max_snoop_failures"]
        and (
            method["kind"] == "realtime"
            or method.get("observed_retained_runtime_percent", -1)
            >= policy["min_stop_and_go_retained_runtime_percent"]
        )
    )


def run_sampling_hil(
    board: BoardConfig | SamplingBoardConfig,
    *,
    session_id: str,
    invoke: Callable[[list[str]], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run the closed Host/sidecar chain or emit explicit readiness evidence."""

    if board.sampling_capture_request is None or board.sampling_evidence_root is None:
        raise HilConfigurationError("board has no [sampling] HIL configuration")
    if board.sampling_capture_request_sha256 is None:
        raise HilConfigurationError("board has no sampling request digest")
    caller = invoke or (lambda argv: run_json(argv, cwd=board.path.parent))
    request_bytes, _ = _read_plain_json_snapshot(
        board.sampling_capture_request,
        "sampling.capture_request",
        board.sampling_capture_request_sha256,
    )
    try:
        request = _strict_json_loads(request_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise HilConfigurationError(
            f"sampling.capture_request is invalid JSON: {error}"
        ) from error
    _validate_sampling_capture_request(request)
    prepared = _host_result(
        caller(
            board.command(
                "sampling_prepare",
                session_id=session_id,
                request=board.sampling_capture_request,
            )
        ),
        "sampling.prepare",
    )
    operation_id = prepared.get("operation_id")
    session_request_sha256 = prepared.get("request_sha256")
    sidecar_args = prepared.get("sampling_capture_arguments")
    expected_sidecar_args = {
        **{key: value for key, value in request.items() if key != "schema"},
        "session_id": session_id,
        "operation_id": operation_id,
    }
    if (
        not isinstance(operation_id, str)
        or _OPERATION.fullmatch(operation_id) is None
        or not isinstance(session_request_sha256, str)
        or _HEX.fullmatch(session_request_sha256) is None
        or sidecar_args != expected_sidecar_args
    ):
        raise SamplingVerificationError(
            "sampling.prepare did not bind the configured request"
        )

    output = board.sampling_evidence_root / f"{session_id}.json"
    try:
        capabilities = dict(
            caller(board.command("sampling_capabilities", session_id=session_id))
        )
    except RuntimeError:
        capabilities = {
            "schema": "t32perf.sampling-capabilities-unavailable/v1",
            "target": {
                "powered": "unknown",
                "running": "unknown",
                "halted": "unknown",
            },
            "pcsnoop": "unknown",
            "supported_methods": [],
        }
    state = capabilities.get("target")
    state_readable = isinstance(state, dict) and all(
        isinstance(state.get(field), bool) for field in ("powered", "running", "halted")
    )
    powered = state_readable and state["powered"] is True
    running = state_readable and state["running"] is True
    unhalted = state_readable and state["halted"] is False
    checks = [
        {"name": "state_readable", "passed": state_readable, "reason": "target state"},
        {"name": "powered", "passed": powered, "reason": "target power"},
        {"name": "running", "passed": running, "reason": "target execution"},
        {"name": "unhalted", "passed": unhalted, "reason": "target halt state"},
    ]
    if isinstance(board, SamplingBoardConfig):
        capability_schema = (
            capabilities.get("schema") == "t32perf.sampling-capabilities/v1"
        )
        fingerprint_scheme_matches = (
            capabilities.get("endpoint_fingerprint_scheme")
            == "t32perf.endpoint-fingerprint/v2"
        )
        reported_software = capabilities.get("trace32")
        software_matches = reported_software == board.trace32_software
        endpoint_matches = (
            capabilities.get("endpoint_fingerprint") == board.endpoint_fingerprint
        )
        probe_matches = capabilities.get("probe_fingerprint") == board.probe_fingerprint
        cpu = capabilities.get("cpu")
        cpu_matches = powered and cpu == board.expected_cpu
        checks.extend(
            [
                {
                    "name": "capabilities_schema",
                    "passed": capability_schema and fingerprint_scheme_matches,
                    "reason": "sidecar capabilities and endpoint fingerprint schema",
                },
                {
                    "name": "trace32_identity",
                    "passed": software_matches and endpoint_matches and probe_matches,
                    "reason": "reported endpoint, probe, and TRACE32 software",
                },
                {
                    "name": "expected_cpu",
                    "passed": cpu_matches,
                    "reason": "configured CPU after target power is readable",
                },
            ]
        )
    observed_probe = capabilities.get("probe_fingerprint")
    probe_observed = (
        isinstance(observed_probe, str) and _HEX.fullmatch(observed_probe) is not None
    )
    expected_probe = (
        board.probe_fingerprint
        if isinstance(board, SamplingBoardConfig)
        else "unconfigured"
    )
    receipt_common = {
        "board_id": board.board_id,
        "session_id": session_id,
        "capture_request_file_sha256": board.sampling_capture_request_sha256 or "",
        "session_request_sha256": session_request_sha256,
        "capabilities": capabilities,
        "operation_id": operation_id,
        "method_policy": request["method_policy"],
        "configured_identity": {
            "mcu_family": board.mcu_family,
            "probe_id": board.probe_id,
            "scope": "observed_probe_endpoint_class"
            if probe_observed
            else "configured_endpoint_class",
            "expected_probe_fingerprint": expected_probe,
            "observed_probe_fingerprint": observed_probe
            if probe_observed
            else "unobserved",
            "probe_identity_observed": probe_observed,
            "target_id_observed": False,
        },
    }
    if not isinstance(board, SamplingBoardConfig):
        receipt = build_receipt(
            **receipt_common,
            status="FAIL",
            reason="sampling_board_config_required",
            checks=checks
            + [
                {
                    "name": "sampling_board_config",
                    "passed": False,
                    "reason": "pinned endpoint configuration required",
                }
            ],
        )
        write_receipt(receipt, output)
        return receipt
    if not all(row["passed"] for row in checks):
        reason = "target_state_unavailable"
        status = "NOT_READY"
        if isinstance(board, SamplingBoardConfig):
            if not capability_schema or not fingerprint_scheme_matches:
                reason = "capabilities_schema_mismatch"
                status = "FAIL"
            elif not (software_matches and endpoint_matches and probe_matches):
                reason = "trace32_identity_mismatch"
                status = "FAIL"
            elif powered and not cpu_matches:
                reason = "expected_cpu_mismatch"
                status = "FAIL"
        receipt = build_receipt(
            **receipt_common,
            status=status,
            reason=reason,
            checks=checks,
        )
        write_receipt(receipt, output)
        return receipt

    supported = capabilities.get("supported_methods")
    pcsnoop = capabilities.get("pcsnoop")
    if not isinstance(supported, list) or not all(
        method in {"realtime", "stop_and_go"} for method in supported
    ):
        raise SamplingVerificationError("sampling capabilities method list is invalid")
    method_available = (pcsnoop is True and "realtime" in supported) or (
        pcsnoop is False
        and request["method_policy"] == "allow_stop_and_go"
        and "stop_and_go" in supported
    )
    if not method_available:
        receipt = build_receipt(
            **receipt_common,
            status="NOT_READY",
            reason="unsupported_method",
            checks=checks
            + [
                {"name": "method_available", "passed": False, "reason": "method policy"}
            ],
        )
        write_receipt(receipt, output)
        return receipt

    capture = caller(
        board.command(
            "sampling_capture",
            session_id=session_id,
            operation_id=operation_id,
            sidecar_args=json.dumps(
                sidecar_args, sort_keys=True, separators=(",", ":")
            ),
        )
    )
    if set(capture) != {"histogram", "artifact"}:
        raise SamplingVerificationError("sampling_capture returned an invalid envelope")
    histogram, staged = _validate_histogram(
        capture["histogram"],
        capture["artifact"],
        session_id=session_id,
        request=request,
    )
    if isinstance(board, SamplingBoardConfig) and (
        histogram.get("endpoint_fingerprint") != board.endpoint_fingerprint
        or histogram.get("endpoint_fingerprint")
        != capabilities.get("endpoint_fingerprint")
        or histogram.get("trace32") != board.trace32_software
        or histogram.get("trace32") != capabilities.get("trace32")
        or histogram.get("cpu") != board.expected_cpu
        or histogram.get("cpu") != capabilities.get("cpu")
    ):
        receipt = build_receipt(
            **receipt_common,
            status="FAIL",
            reason="histogram_identity_mismatch",
            checks=checks
            + [
                {
                    "name": "histogram_identity",
                    "passed": False,
                    "reason": "capture identity differs from capabilities or configuration",
                }
            ],
            endpoint_fingerprint=histogram.get("endpoint_fingerprint"),
            selected_method=histogram["method"]["kind"],
            target_before=histogram["target_state_before"],
            target_after=histogram["target_state_after"],
            statistical=True,
            diagnostic_only=True,
        )
        write_receipt(receipt, output)
        return receipt
    ingest = _host_result(
        caller(
            board.command(
                "sampling_ingest",
                session_id=session_id,
                staged_path=staged["relative_path"],
            )
        ),
        "sampling.ingest",
    )
    histogram_artifact = _artifact(
        ingest.get("histogram_artifact"), expected_id="sampling-pc-hit-histogram"
    )
    capture_receipt = _artifact(
        ingest.get("capture_receipt_artifact"), expected_id="sampling-capture-receipt"
    )
    if histogram_artifact["sha256"] != staged["sha256"]:
        raise SamplingVerificationError(
            "Host histogram digest differs from sidecar export"
        )

    quantitative_ready, quality_reason = _quantitative_capture_ready(histogram)
    selected_method = histogram["method"]["kind"]
    if not quantitative_ready:
        receipt = build_receipt(
            **receipt_common,
            status="FAIL",
            reason=quality_reason,
            checks=checks
            + [
                {
                    "name": "quantitative_policy",
                    "passed": False,
                    "reason": quality_reason,
                }
            ],
            endpoint_fingerprint=histogram["endpoint_fingerprint"],
            selected_method=selected_method,
            target_before=histogram["target_state_before"],
            target_after=histogram["target_state_after"],
            statistical=True,
            diagnostic_only=True,
        )
        write_receipt(receipt, output)
        return receipt

    analyze = _host_result(
        caller(
            board.command(
                "sampling_analyze",
                session_id=session_id,
                histogram_artifact_id=histogram_artifact["id"],
            )
        ),
        "sampling.analyze",
    )
    heatmap_artifact = _artifact(
        analyze.get("artifact"), expected_id="sampling-heatmap-address"
    )
    summary = _host_result(
        caller(
            board.command(
                "sampling_summary",
                session_id=session_id,
                heatmap_artifact_id=heatmap_artifact["id"],
            )
        ),
        "sampling.summary",
    )
    render = _host_result(
        caller(
            board.command(
                "sampling_render",
                session_id=session_id,
                heatmap_artifact_id=heatmap_artifact["id"],
            )
        ),
        "sampling.render",
    )
    svg_artifact = _artifact(
        render.get("artifact"), id_prefix="sampling-heatmap-address-svg-top"
    )
    audited_heatmap = _audit_host_session(
        board,
        session_id=session_id,
        operation_id=operation_id,
        request_sha256=session_request_sha256,
        configured_request=request,
        wrapper_artifacts={
            "capture_receipt": capture_receipt,
            "histogram": histogram_artifact,
            "heatmap": heatmap_artifact,
            "svg": svg_artifact,
        },
        expected_histogram_bytes=_sidecar_histogram_bytes(histogram),
        endpoint_fingerprint=histogram["endpoint_fingerprint"],
    )
    policy = summary.get("quantitative_policy")
    sufficient = (
        analyze.get("statistical") is True
        and analyze.get("diagnostic_only") is True
        and summary.get("statistical") is True
        and summary.get("diagnostic_only") is True
        and render.get("statistical") is True
        and render.get("diagnostic_only") is True
        and summary.get("denominator_hits") == histogram["in_scope_hits"]
        and isinstance(policy, dict)
        and policy == audited_heatmap["quantitative_policy"]
        and _histogram_meets_policy(histogram, policy)
    )
    bindings = [
        {
            "role": "capture_receipt",
            "artifact_id": capture_receipt["id"],
            "sha256": capture_receipt["sha256"],
        },
        {
            "role": "histogram",
            "artifact_id": histogram_artifact["id"],
            "sha256": histogram_artifact["sha256"],
        },
        {
            "role": "address_heatmap",
            "artifact_id": heatmap_artifact["id"],
            "sha256": heatmap_artifact["sha256"],
        },
        {
            "role": "svg",
            "artifact_id": svg_artifact["id"],
            "sha256": svg_artifact["sha256"],
        },
    ]
    receipt = build_receipt(
        **receipt_common,
        status="PASS" if sufficient else "FAIL",
        reason="capture accepted"
        if sufficient
        else "Host projection evidence mismatch",
        checks=checks
        + [
            {
                "name": "quantitative_policy",
                "passed": sufficient,
                "reason": "Host summary",
            }
        ],
        artifact_bindings=bindings if sufficient else [],
        endpoint_fingerprint=histogram["endpoint_fingerprint"],
        selected_method=selected_method,
        target_before=histogram["target_state_before"],
        target_after=histogram["target_state_after"],
        quantitative_policy=policy if isinstance(policy, dict) else None,
        statistical=True,
        diagnostic_only=True,
    )
    write_receipt(receipt, output)
    return receipt
