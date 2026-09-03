"""Closed-wrapper HIL verification for intrusive Break/Frame.Up stack samples.

This is intentionally separate from PC sampling: stack samples have call-stack
evidence, are intrusive, and every successful receipt proves the exact four
Host artifacts rather than trusting a wrapper projection.
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
    HilConfigurationError,
    _read_plain_json_snapshot,
    _strict_json_loads,
    run_json,
)
from stack_board import StackBoardConfig

SCHEMA = "t32perf.stack-hil-verification-receipt/v1"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_SESSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_OPERATION = re.compile(r"^[0-9a-f]{32}$")
_MAX = 64 * 1024 * 1024
_CATALOG = {
    "sampling-stack-capture-receipt": (
        "stack_capture_receipt",
        "capture/sampling/stack-capture-receipt.json",
        "application/json",
        "t32perf-stack-capture-receipt/v1",
        [],
    ),
    "sampling-stack-samples": (
        "stack_samples",
        "capture/sampling/stack-samples.json",
        "application/json",
        "lauterbach-stack-sampling-mcp/v1",
        ["sampling-stack-capture-receipt"],
    ),
    "sampling-folded-stack-profile": (
        "folded_stack_profile",
        "analysis/sampling-folded-stack-profile.json",
        "application/json",
        "t32perf-stack-analysis/v1",
        ["sampling-stack-samples"],
    ),
    "sampling-flamegraph-svg-depth064": (
        "flamegraph",
        "report/sampling-flamegraph-depth064.svg",
        "image/svg+xml",
        "t32perf-stack-flamegraph/v1",
        ["sampling-folded-stack-profile"],
    ),
}


class StackVerificationError(RuntimeError):
    pass


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _state(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"powered", "running", "halted"}
        and all(type(value[field]) is bool for field in value)
    )


def _clean_debugger_error_state(value: object) -> bool:
    """Accept only the explicit clean TRACE32 ERROR state.

    Capture is a stateful debugger operation.  Absence, an extra field, or an
    unrecognised error ID are not equivalent to a clean post-Go state.
    """
    return (
        isinstance(value, dict)
        and set(value) == {"occurred", "id"}
        and value.get("occurred") is False
        and value.get("id") == ""
    )


def _read(path: Path, label: str) -> tuple[bytes, str]:
    try:
        info = path.lstat()
        if (
            stat.S_ISLNK(info.st_mode)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_size > _MAX
        ):
            raise StackVerificationError(
                f"{label} is not a bounded single-link regular file"
            )
        payload = path.read_bytes()
    except OSError as error:
        raise StackVerificationError(f"cannot read {label}: {error}") from error
    if len(payload) != info.st_size:
        raise StackVerificationError(f"{label} changed while it was read")
    return payload, hashlib.sha256(payload).hexdigest()


def _json(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = _strict_json_loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as error:
        raise StackVerificationError(f"{label} is invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise StackVerificationError(f"{label} must be an object")
    return value


def _artifact(value: object, expected: str) -> dict[str, Any]:
    fields = {
        "id",
        "kind",
        "path",
        "sha256",
        "media_type",
        "producer",
        "input_artifact_ids",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("id") != expected
        or not isinstance(value.get("sha256"), str)
        or _HEX.fullmatch(value["sha256"]) is None
    ):
        raise StackVerificationError(f"invalid wrapper artifact: {expected}")
    return value


def _raw(
    raw: dict[str, Any],
    *,
    session: str,
    request: dict[str, Any],
    endpoint: str,
    cpu: str,
) -> None:
    fields = {
        "schema",
        "session_id",
        "endpoint_fingerprint",
        "endpoint_fingerprint_scheme",
        "trace32",
        "cpu",
        "core_id",
        "address_space",
        "method",
        "intrusive",
        "frame_order",
        "requested_duration_ms",
        "observed_duration_ms",
        "requested_sample_period_ms",
        "max_samples",
        "max_frames",
        "attempted_samples",
        "collected_samples",
        "total_halt_cycle_duration_ns",
        "target_state_before",
        "target_state_after",
        "firmware",
        "cleanup_complete",
        "samples",
        "debugger_symbolization_source",
        "debugger_symbolization_trust",
    }
    if (
        set(raw) != fields
        or raw.get("schema") != "t32perf.stack-samples/v1"
        or raw.get("session_id") != session
    ):
        raise StackVerificationError("raw stack sample envelope is invalid")
    if (
        raw.get("endpoint_fingerprint") != endpoint
        or raw.get("endpoint_fingerprint_scheme") != "t32perf.endpoint-fingerprint/v2"
        or raw.get("cpu") != cpu
    ):
        raise StackVerificationError("raw stack identity differs from capabilities")
    if (
        raw.get("method") != "break_frame_walk"
        or raw.get("intrusive") is not True
        or raw.get("frame_order") != "leaf_to_root"
        or raw.get("cleanup_complete") is not True
    ):
        raise StackVerificationError(
            "raw stack capture does not prove intrusive cleanup"
        )
    if (
        raw.get("firmware") != {"status": "unverified"}
        or raw.get("debugger_symbolization_source") != "trace32_symbol_table"
        or raw.get("debugger_symbolization_trust") != "debugger_reported"
    ):
        raise StackVerificationError(
            "raw stack symbols or firmware boundary is invalid"
        )
    if not (
        _state(raw.get("target_state_before"))
        and _state(raw.get("target_state_after"))
        and raw["target_state_before"]
        == {"powered": True, "running": True, "halted": False}
        and raw["target_state_after"] == raw["target_state_before"]
    ):
        raise StackVerificationError("raw stack target state is invalid")
    for raw_name, request_name in (
        ("requested_duration_ms", "duration_ms"),
        ("requested_sample_period_ms", "sample_period_ms"),
        ("max_samples", "max_samples"),
        ("max_frames", "max_frames"),
        ("core_id", "core_id"),
        ("address_space", "address_space"),
    ):
        if raw.get(raw_name) != request[request_name]:
            raise StackVerificationError("raw stack request binding is invalid")
    samples = raw.get("samples")
    if (
        not isinstance(samples, list)
        or raw.get("collected_samples") != len(samples)
        or not isinstance(raw.get("attempted_samples"), int)
        or raw["attempted_samples"] < len(samples)
        or raw["attempted_samples"] > request["max_samples"]
        or not samples
    ):
        raise StackVerificationError("raw stack accounting is invalid")
    if raw.get("total_halt_cycle_duration_ns") != sum(
        sample.get("halt_cycle_duration_ns", 0) for sample in samples
    ):
        raise StackVerificationError("raw stack halt-cycle accounting is invalid")
    for index, sample in enumerate(samples, 1):
        if (
            not isinstance(sample, dict)
            or set(sample)
            != {"sample_index", "halt_cycle_duration_ns", "termination", "frames"}
            or sample.get("sample_index") != index
            or sample.get("termination")
            not in {
                "terminal_unverified",
                "max_frames",
                "pc_read_failed",
                "frame_cycle",
                "halt_deadline",
            }
            or not isinstance(sample.get("halt_cycle_duration_ns"), int)
            or sample["halt_cycle_duration_ns"] < 1
        ):
            raise StackVerificationError("raw stack sample is invalid")
        frames = sample.get("frames")
        if (
            not isinstance(frames, list)
            or not frames
            or len(frames) > request["max_frames"]
        ):
            raise StackVerificationError("raw stack frames are invalid")
        for depth, frame in enumerate(frames):
            if (
                not isinstance(frame, dict)
                or set(frame)
                - {"depth", "pc", "function_name", "source_file", "source_line"}
                or frame.get("depth") != depth
                or not isinstance(frame.get("pc"), int)
                or frame["pc"] < 0
            ):
                raise StackVerificationError("raw stack frame identity is invalid")
            if (
                "source_file" in frame
                and frame["source_file"] is not None
                and (
                    not isinstance(frame["source_file"], str)
                    or "/" in frame["source_file"]
                    or "\\" in frame["source_file"]
                )
            ):
                raise StackVerificationError("raw source location must be a basename")


def _profile(profile: dict[str, Any], raw: dict[str, Any], raw_digest: str) -> None:
    required = {
        "schema",
        "session_id",
        "raw_samples_sha256",
        "quality",
        "method",
        "frame_order",
        "attempted_samples",
        "collected_samples",
        "included_samples",
        "terminal_unverified_samples",
        "truncated_samples",
        "paths",
    }
    if (
        set(profile) != required
        or profile.get("schema") != "t32perf.folded-stack-profile/v1"
        or profile.get("session_id") != raw["session_id"]
        or profile.get("raw_samples_sha256") != raw_digest
        or profile.get("quality") != "intrusive_statistical"
        or profile.get("method") != "break_frame_walk"
        or profile.get("frame_order") != "root_to_leaf"
        or profile.get("attempted_samples") != raw["attempted_samples"]
    ):
        raise StackVerificationError("folded profile envelope is invalid")
    paths = profile.get("paths")
    if (
        not isinstance(paths, list)
        or profile.get("collected_samples") != raw["collected_samples"]
    ):
        raise StackVerificationError("folded profile accounting is invalid")
    expected: dict[
        tuple[str, tuple[tuple[int, str | None, str | None, int | None], ...]], int
    ] = {}
    terminal = truncated = 0
    for sample in raw["samples"]:
        terminal += sample["termination"] == "terminal_unverified"
        truncated += sample["termination"] != "terminal_unverified"
        key = tuple(
            (
                frame["pc"],
                frame.get("function_name"),
                frame.get("source_file"),
                frame.get("source_line"),
            )
            for frame in reversed(sample["frames"])
        )
        tagged = (sample["termination"], key)
        expected[tagged] = expected.get(tagged, 0) + 1
    actual: dict[
        tuple[str, tuple[tuple[int, str | None, str | None, int | None], ...]], int
    ] = {}
    for path in paths:
        if (
            not isinstance(path, dict)
            or set(path) != {"outer_boundary", "frames", "samples"}
            or path.get("outer_boundary")
            not in {
                "terminal_unverified",
                "max_frames",
                "pc_read_failed",
                "frame_cycle",
                "halt_deadline",
            }
            or not isinstance(path.get("samples"), int)
            or path["samples"] < 1
            or not isinstance(path.get("frames"), list)
        ):
            raise StackVerificationError("folded profile path is invalid")
        key = tuple(
            (
                frame.get("pc"),
                frame.get("function_name"),
                frame.get("source_file"),
                frame.get("source_line"),
            )
            for frame in path["frames"]
            if isinstance(frame, dict)
        )
        if len(key) != len(path["frames"]):
            raise StackVerificationError("folded profile frame is invalid")
        tagged = (path["outer_boundary"], key)
        actual[tagged] = actual.get(tagged, 0) + path["samples"]
    if (
        actual != expected
        or profile.get("included_samples") != raw["collected_samples"]
        or profile.get("terminal_unverified_samples") != terminal
        or profile.get("truncated_samples") != truncated
    ):
        raise StackVerificationError(
            "folded profile is not deterministically derived from raw samples"
        )


def _svg(payload: bytes, profile: dict[str, Any]) -> None:
    if len(payload) > _MAX:
        raise StackVerificationError("flame SVG exceeds limit")
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as error:
        raise StackVerificationError(f"flame SVG is malformed: {error}") from error
    if (
        root.tag.removeprefix("{http://www.w3.org/2000/svg}") != "svg"
        or root.attrib.get("role") != "img"
        or root.attrib.get("aria-labelledby") != "title desc"
    ):
        raise StackVerificationError("flame SVG role binding is invalid")
    direct = [child.tag.removeprefix("{http://www.w3.org/2000/svg}") for child in root]
    if "title" not in direct or "desc" not in direct:
        raise StackVerificationError("flame SVG must contain a title and description")
    text = " ".join("".join(item.itertext()) for item in root.iter())
    for phrase in (
        "Break",
        "Frame.Up",
        "Go",
        "outer unwind boundary may be unverified",
        "not CPU time",
        "duration",
        "call counts",
    ):
        if phrase not in text:
            raise StackVerificationError("flame SVG safety disclosure is incomplete")
    raw_binding = f"raw samples SHA-256: {profile['raw_samples_sha256']}"
    if raw_binding not in text or "profile SHA-256:" in text:
        raise StackVerificationError("flame SVG does not label its raw-sample binding")
    frames = [item for item in root.iter() if item.attrib.get("role") == "listitem"]
    if not frames:
        raise StackVerificationError("flame SVG has no frame identities")
    width = int(root.attrib.get("width", "0"))
    height = int(root.attrib.get("height", "0"))
    if not 1 <= width <= 16384 or not 1 <= height <= 16384:
        raise StackVerificationError("flame SVG viewport is not bounded")
    actual_boundaries: dict[str, int] = {}
    for item in frames:
        title = next(
            (
                child
                for child in item.iter()
                if child.tag.removeprefix("{http://www.w3.org/2000/svg}") == "title"
            ),
            None,
        )
        if (
            set(item.attrib)
            - {"role", "data-depth", "data-samples", "data-kind", "data-boundary"}
            or not item.attrib.get("data-samples", "").isdigit()
            or item.attrib.get("data-kind") not in {"frame", "boundary", "other"}
            or title is None
        ):
            raise StackVerificationError("flame SVG frame identity is invalid")
        title_text = "".join(title.itertext())
        kind = item.attrib["data-kind"]
        if kind in {"boundary", "other"} and (
            "not an inferred frame" not in title_text
        ):
            raise StackVerificationError(
                "synthetic flame marker is not explicitly disclosed"
            )
        if kind == "boundary":
            reason = item.attrib.get("data-boundary")
            if (
                item.attrib.get("data-depth") != "0"
                or reason
                not in {
                    "terminal_unverified",
                    "max_frames",
                    "pc_read_failed",
                    "frame_cycle",
                    "halt_deadline",
                }
                or f"outer unwind boundary {reason}" not in title_text
            ):
                raise StackVerificationError("flame SVG outer boundary is invalid")
            actual_boundaries[reason] = actual_boundaries.get(reason, 0) + int(
                item.attrib["data-samples"]
            )
        elif "data-boundary" in item.attrib or item.attrib.get("data-depth") == "0":
            raise StackVerificationError(
                "non-boundary flame node uses boundary metadata"
            )
    expected_boundaries: dict[str, int] = {}
    for path in profile["paths"]:
        reason = path["outer_boundary"]
        expected_boundaries[reason] = (
            expected_boundaries.get(reason, 0) + path["samples"]
        )
    if actual_boundaries != expected_boundaries:
        raise StackVerificationError("flame SVG outer-boundary counts are invalid")


def _write(path: Path, receipt: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = _canonical(receipt) + b"\n"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise StackVerificationError(
            f"refusing to overwrite HIL evidence: {path}"
        ) from error
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _receipt(
    board: StackBoardConfig,
    session: str,
    request_digest: str,
    caps: Mapping[str, Any],
    checks: list[dict[str, Any]],
    status: str,
    reason: str,
    **extra: Any,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": SCHEMA,
        "source": "intrusive-stack-sampling-hil",
        "board_id": board.board_id,
        "session_id": session,
        "t32perf_sha256": board.t32perf_sha256,
        "status": status,
        "reason": reason,
        "capture_request_file_sha256": board.request_sha256,
        "session_request_sha256": request_digest,
        "capabilities": dict(caps),
        "capabilities_sha256": _sha(caps),
        "checks": checks,
        "artifact_bindings": [],
    }
    value.update(extra)
    return value


def run_stack_hil(
    board: StackBoardConfig,
    *,
    session_id: str,
    invoke: Callable[[list[str]], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run the closed stack pipeline with capabilities before and after capture."""
    if _SESSION.fullmatch(session_id) is None:
        raise HilConfigurationError("stack session id is invalid")
    payload, _ = _read_plain_json_snapshot(
        board.request_file, "stack.capture_request", board.request_sha256
    )
    request = _json(payload, "stack capture request")
    caller = invoke or (lambda argv: run_json(argv, cwd=board.path.parent))
    prepared = caller(
        board.command("prepare", session_id=session_id, request=board.request_file)
    )
    result = prepared.get("result") if isinstance(prepared, dict) else None
    if (
        not isinstance(result, dict)
        or result.get("session_id") != session_id
        or not _OPERATION.fullmatch(str(result.get("operation_id")))
        or not isinstance(result.get("request_sha256"), str)
        or _HEX.fullmatch(result["request_sha256"]) is None
    ):
        raise StackVerificationError("stack prepare did not bind a Host operation")
    operation, request_digest = result["operation_id"], result["request_sha256"]
    caps = dict(caller(board.command("capabilities", session_id=session_id)))
    target = caps.get("target")
    debugger_error_clean = _clean_debugger_error_state(caps.get("debugger_error_state"))
    checks = [
        {
            "name": "target_state",
            "passed": _state(target),
            "reason": "readable target state",
        },
        {
            "name": "powered",
            "passed": _state(target) and target["powered"],
            "reason": "target power",
        },
        {
            "name": "running",
            "passed": _state(target) and target["running"],
            "reason": "target execution",
        },
        {
            "name": "unhalted",
            "passed": _state(target) and not target["halted"],
            "reason": "target halt state",
        },
        {
            "name": "intrusive_acknowledged",
            "passed": request.get("acknowledge_intrusive") is True,
            "reason": "request acknowledgement",
        },
        {
            "name": "debugger_error_state",
            "passed": debugger_error_clean,
            "reason": "TRACE32 ERROR state is explicitly clean before capture",
        },
    ]
    identity = (
        caps.get("schema") == "t32perf.stack-sampling-capabilities/v1"
        and caps.get("endpoint_fingerprint_scheme") == "t32perf.endpoint-fingerprint/v2"
        and caps.get("endpoint_fingerprint") == board.endpoint_fingerprint
        and caps.get("cpu") == board.expected_cpu
        and caps.get("method") == "break_frame_walk"
        and caps.get("intrusive") is True
        and caps.get("supported_core_ids") == [0]
        and caps.get("single_core_evidence")
        == {"logical_core_count": 1, "selected_core": 0}
        and caps.get("safety_budget")
        == {
            "max_rcl_timeout_ms": 100,
            "frame_walk_deadline_ms": 1_000,
            "max_frames": 8,
        }
    )
    checks.append(
        {
            "name": "endpoint_cpu_method",
            "passed": identity,
            "reason": "pinned endpoint, CPU, and intrusive method",
        }
    )
    output = board.evidence_root / f"{session_id}.json"
    if not all(check["passed"] for check in checks):
        receipt = _receipt(
            board,
            session_id,
            request_digest,
            caps,
            checks,
            "NOT_READY"
            if _state(target) is False or (_state(target) and not target["powered"])
            else "FAIL",
            "target_not_ready"
            if not all(check["passed"] for check in checks[:4])
            else "capabilities_or_acknowledgement_mismatch",
            operation_id=operation,
        )
        _write(output, receipt)
        return receipt
    capture = caller(
        board.command(
            "capture",
            session_id=session_id,
            operation_id=operation,
            sidecar_args=json.dumps(
                {
                    **{key: value for key, value in request.items() if key != "schema"},
                    "session_id": session_id,
                    "operation_id": operation,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
    )
    if not isinstance(capture, dict) or set(capture) != {"summary", "artifact"}:
        raise StackVerificationError("stack capture returned an invalid envelope")
    capture_summary = capture["summary"]
    if (
        not isinstance(capture_summary, dict)
        or set(capture_summary)
        != {
            "attempted_samples",
            "collected_samples",
            "total_halt_cycle_duration_ns",
            "cleanup_complete",
        }
        or capture_summary.get("cleanup_complete") is not True
    ):
        raise StackVerificationError("stack capture summary is invalid")
    post_caps = dict(caller(board.command("capabilities", session_id=session_id)))
    post_target = post_caps.get("target")
    post_debugger_error_clean = _clean_debugger_error_state(
        post_caps.get("debugger_error_state")
    )
    post_identity = all(
        post_caps.get(name) == caps.get(name)
        for name in (
            "schema",
            "endpoint_fingerprint_scheme",
            "endpoint_fingerprint",
            "cpu",
            "method",
            "intrusive",
            "supported_core_ids",
            "single_core_evidence",
            "safety_budget",
            "debugger_error_state",
        )
    )
    post_running = post_target == {
        "powered": True,
        "running": True,
        "halted": False,
    }
    checks.extend(
        [
            {
                "name": "post_capture_target_state",
                "passed": post_running,
                "reason": "independent target state after sidecar completion",
            },
            {
                "name": "post_capture_endpoint_identity",
                "passed": post_identity,
                "reason": "independent endpoint identity after sidecar completion",
            },
            {
                "name": "post_capture_debugger_error_state",
                "passed": post_debugger_error_clean,
                "reason": "TRACE32 ERROR state is explicitly clean after capture",
            },
        ]
    )
    if not post_running or not post_identity or not post_debugger_error_clean:
        receipt = _receipt(
            board,
            session_id,
            request_digest,
            caps,
            checks,
            "FAIL",
            "post_capture_state_or_identity_mismatch",
            operation_id=operation,
            endpoint_fingerprint=board.endpoint_fingerprint,
            target_before=target,
            target_after=post_target,
            capture_summary=capture_summary,
            post_capture_capabilities=post_caps,
            post_capture_capabilities_sha256=_sha(post_caps),
            intrusive=True,
            statistical=True,
            diagnostic_only=True,
        )
        _write(output, receipt)
        return receipt
    staged = capture["artifact"]
    if not isinstance(staged, dict) or not isinstance(staged.get("relative_path"), str):
        raise StackVerificationError("stack capture staging artifact is invalid")
    ingest = caller(
        board.command(
            "ingest", session_id=session_id, staged_path=staged["relative_path"]
        )
    )
    ingest_result = ingest.get("result") if isinstance(ingest, dict) else None
    if not isinstance(ingest_result, dict):
        raise StackVerificationError("stack ingest envelope is invalid")
    raw_artifact = _artifact(
        ingest_result.get("stack_samples_artifact"), "sampling-stack-samples"
    )
    receipt_artifact = _artifact(
        ingest_result.get("capture_receipt_artifact"), "sampling-stack-capture-receipt"
    )
    analyze = caller(
        board.command(
            "analyze", session_id=session_id, raw_artifact_id=raw_artifact["id"]
        )
    )
    profile_artifact = _artifact(
        (analyze.get("result") if isinstance(analyze, dict) else {}).get("artifact"),
        "sampling-folded-stack-profile",
    )
    summary = caller(board.command("summary", session_id=session_id))
    if (summary.get("result") if isinstance(summary, dict) else {}).get(
        "sample_measure"
    ) != "halt_cycles_not_cpu_time":
        raise StackVerificationError("stack summary does not preserve sample measure")
    render = caller(board.command("render", session_id=session_id))
    svg_artifact = _artifact(
        (render.get("result") if isinstance(render, dict) else {}).get("artifact"),
        "sampling-flamegraph-svg-depth064",
    )
    artifacts = {
        "receipt": receipt_artifact,
        "raw": raw_artifact,
        "profile": profile_artifact,
        "svg": svg_artifact,
    }
    raw = _audit_host(board, session_id, operation, request_digest, request, artifacts)
    if raw["target_state_after"] != post_target:
        raise StackVerificationError(
            "sidecar target_after differs from independent post-capture state"
        )
    receipt = _receipt(
        board,
        session_id,
        request_digest,
        caps,
        checks,
        "PASS",
        "verified_intrusive_stack_capture",
        operation_id=operation,
        endpoint_fingerprint=board.endpoint_fingerprint,
        target_before=raw["target_state_before"],
        target_after=post_target,
        post_capture_capabilities=post_caps,
        post_capture_capabilities_sha256=_sha(post_caps),
        artifact_bindings=[
            {"role": role, "artifact_id": artifact["id"], "sha256": artifact["sha256"]}
            for role, artifact in artifacts.items()
        ],
        capture_summary={
            "collected_samples": raw["collected_samples"],
            "total_halt_cycle_duration_ns": raw["total_halt_cycle_duration_ns"],
            "sample_measure": "halt_cycles_not_cpu_time",
        },
        intrusive=True,
        statistical=True,
        diagnostic_only=True,
    )
    if any(
        raw[key] != capture_summary[key]
        for key in (
            "attempted_samples",
            "collected_samples",
            "total_halt_cycle_duration_ns",
        )
    ):
        raise StackVerificationError("capture summary differs from durable raw samples")
    _write(output, receipt)
    return receipt


def _audit_host(
    board: StackBoardConfig,
    session: str,
    operation: str,
    request_digest: str,
    request: dict[str, Any],
    wrappers: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    root = board.artifact_root / session
    if not root.is_dir() or root.is_symlink():
        raise StackVerificationError("audited stack session is invalid")
    request_bytes, digest = _read(root / "request.json", "session request")
    if digest != request_digest or _json(request_bytes, "session request") != request:
        raise StackVerificationError("Host request binding differs")
    state = _json(_read(root / "state.json", "session state")[0], "session state")
    if state.get("operation_id") != operation or state.get("state") != "captured":
        raise StackVerificationError("Host state is not captured operation")
    attempt = _json(
        _read(
            board.artifact_root
            / ".t32perf-control"
            / "stack-capture-attempts"
            / f"{session}.json",
            "stack capture attempt",
        )[0],
        "stack capture attempt",
    )
    if (
        set(attempt)
        != {
            "schema",
            "session_id",
            "operation_id",
            "request_sha256",
            "endpoint_fingerprint",
            "created_at",
        }
        or attempt.get("schema") != "t32perf.stack-capture-attempt/v1"
        or attempt.get("session_id") != session
        or attempt.get("operation_id") != operation
        or attempt.get("request_sha256") != request_digest
        or attempt.get("endpoint_fingerprint") != board.endpoint_fingerprint
        or not isinstance(attempt.get("created_at"), str)
        or not attempt["created_at"]
        or len(attempt["created_at"].encode()) > 64
    ):
        raise StackVerificationError("stack capture attempt binding is invalid")
    index = root / "artifact-index"
    try:
        names = sorted(entry.name for entry in index.iterdir())
    except OSError as error:
        raise StackVerificationError(
            f"cannot inspect stack artifact catalog: {error}"
        ) from error
    if names != sorted(f"{artifact_id}.json" for artifact_id in _CATALOG):
        raise StackVerificationError(
            "stack artifact catalog is not the exact four artifacts"
        )
    catalog: dict[str, tuple[dict[str, Any], bytes]] = {}
    for artifact_id, (kind, path, media, producer, inputs) in _CATALOG.items():
        entry = _json(
            _read(root / "artifact-index" / f"{artifact_id}.json", artifact_id)[0],
            artifact_id,
        )
        if set(entry) != {
            "id",
            "kind",
            "relative_path",
            "media_type",
            "size_bytes",
            "sha256",
            "producer",
            "input_artifact_ids",
        } or (
            entry.get("id"),
            entry.get("kind"),
            entry.get("relative_path"),
            entry.get("media_type"),
            entry.get("producer"),
            entry.get("input_artifact_ids"),
        ) != (artifact_id, kind, path, media, producer, inputs):
            raise StackVerificationError("stack artifact catalog is invalid")
        content, digest = _read(root / path, artifact_id)
        if entry.get("sha256") != digest or entry.get("size_bytes") != len(content):
            raise StackVerificationError("stack artifact catalog bytes mismatch")
        catalog[artifact_id] = (entry, content)
    role_ids = {
        "receipt": "sampling-stack-capture-receipt",
        "raw": "sampling-stack-samples",
        "profile": "sampling-folded-stack-profile",
        "svg": "sampling-flamegraph-svg-depth064",
    }
    for role, artifact_id in role_ids.items():
        entry, _ = catalog[artifact_id]
        expected = {
            "id": entry["id"],
            "kind": entry["kind"],
            "path": entry["relative_path"],
            "sha256": entry["sha256"],
            "media_type": entry["media_type"],
            "producer": entry["producer"],
            "input_artifact_ids": entry["input_artifact_ids"],
        }
        if dict(wrappers[role]) != expected:
            raise StackVerificationError(
                "wrapper artifact differs from durable catalog"
            )
    raw = _json(catalog["sampling-stack-samples"][1], "raw stack samples")
    _raw(
        raw,
        session=session,
        request=request,
        endpoint=board.endpoint_fingerprint,
        cpu=board.expected_cpu,
    )
    receipt = _json(catalog["sampling-stack-capture-receipt"][1], "capture receipt")
    if (
        receipt.get("schema") != "t32perf.stack-capture-receipt/v1"
        or receipt.get("session_id") != session
        or receipt.get("session_operation_id") != operation
        or receipt.get("session_request_sha256") != request_digest
        or receipt.get("endpoint_fingerprint") != board.endpoint_fingerprint
        or receipt.get("stack_samples_sha256")
        != catalog["sampling-stack-samples"][0]["sha256"]
        or receipt.get("stack_samples_size_bytes")
        != len(catalog["sampling-stack-samples"][1])
    ):
        raise StackVerificationError("capture receipt binding is invalid")
    profile = _json(catalog["sampling-folded-stack-profile"][1], "folded profile")
    _profile(profile, raw, catalog["sampling-stack-samples"][0]["sha256"])
    _svg(catalog["sampling-flamegraph-svg-depth064"][1], profile)
    return raw
