"""Host-owned P7 resource verification for deeply verified HIL sessions.

The driver reference is an independent lab measurement.  It is never used to
reconstruct T32Perf values: this module rebuilds resource metrics from the
verified Session artifacts, checks the persisted analysis summary, and only
then compares the rebuilt values with the driver reference.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness import VerifiedArtifact, VerifiedSession
from verification_receipt import (
    MAX_FAILURES_IN_RECEIPT,
    MAX_RECEIPT_BYTES,
    RESOURCE_CHECK_CATEGORIES,
    TolerancePolicy,
    VerificationCheck,
    VerificationReceiptError,
    build_verification_receipt,
)
from verification_receipt import (
    load_verification_receipt as _load_common_receipt,
)
from verification_receipt import (
    validate_verification_receipt as _validate_common_receipt,
)
from verification_receipt import (
    write_verification_receipt as _write_common_receipt,
)

RESOURCE_REFERENCE_SCHEMA = "t32perf.hil-resource-reference/v1"
HIL_EVIDENCE_V1_SCHEMA = "t32perf.hil-evidence/v1"
HIL_EVIDENCE_V2_SCHEMA = "t32perf.hil-evidence/v2"

MAX_REFERENCE_BYTES = 1024 * 1024
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_JSON_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_REFERENCE_METRICS = 512
MAX_ALIGNMENT_ANCHORS = 128
MAX_COUNTER_DEFINITIONS = 65_536
MAX_RESOURCE_OBSERVATIONS = 1_000_000
MAX_SAFE_INTEGER = 2**53
SESSION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

_SHA256_PATTERN_LENGTH = 64
_STATIC_KINDS = ("data", "bss", "noinit", "dma", "rtos", "custom")
_STATIC_TOTAL_FIELDS = tuple(f"{kind}_bytes" for kind in _STATIC_KINDS)
_STACK_ROLES = frozenset({"task", "isr", "msp", "psp"})
_REQUIRED_STACK_ROLES = _STACK_ROLES

_HEAP_CURRENT = "heap.current_allocated_bytes"
_HEAP_PEAK = "heap.peak_allocated_bytes"
_HEAP_ALLOCATION_COUNT = "heap.allocation_count"
_HEAP_FREE_COUNT = "heap.free_count"
_HEAP_LARGEST_ALLOCATION = "heap.largest_allocation_bytes"
_HEAP_FREE_BYTES = "heap.free_bytes"
_HEAP_LARGEST_FREE = "heap.largest_free_block_bytes"
_HEAP_RATE = "heap.allocation_rate_per_second"
_HEAP_FRAGMENTATION = "heap.external_fragmentation_ratio"
_STACK_CAPACITY = "stack.capacity_bytes"
_STACK_CURRENT = "stack.current_used_bytes"
_STACK_PEAK = "stack.peak_used_bytes"
_TRACE_CAPACITY = "trace_buffer.capacity_bytes"
_TRACE_CURRENT = "trace_buffer.current_used_bytes"
_TRACE_PEAK = "trace_buffer.peak_used_bytes"

_HEAP_RAW_SEMANTICS = frozenset(
    {
        _HEAP_CURRENT,
        _HEAP_PEAK,
        _HEAP_ALLOCATION_COUNT,
        _HEAP_FREE_COUNT,
        _HEAP_LARGEST_ALLOCATION,
        _HEAP_FREE_BYTES,
        _HEAP_LARGEST_FREE,
    }
)
_HEAP_DERIVED_SEMANTICS = frozenset({_HEAP_RATE, _HEAP_FRAGMENTATION})
_STACK_SEMANTICS = frozenset({_STACK_CAPACITY, _STACK_CURRENT, _STACK_PEAK})
_TRACE_SEMANTICS = frozenset({_TRACE_CAPACITY, _TRACE_CURRENT, _TRACE_PEAK})
_RAW_SEMANTICS = _HEAP_RAW_SEMANTICS | _STACK_SEMANTICS | _TRACE_SEMANTICS
_REFERENCE_SEMANTICS = _RAW_SEMANTICS | _HEAP_DERIVED_SEMANTICS

_SEMANTIC_UNITS = {
    **{semantic: "bytes" for semantic in _HEAP_RAW_SEMANTICS},
    _HEAP_ALLOCATION_COUNT: "count",
    _HEAP_FREE_COUNT: "count",
    _HEAP_RATE: "1/s",
    _HEAP_FRAGMENTATION: "ratio",
    **{semantic: "bytes" for semantic in _STACK_SEMANTICS},
    **{semantic: "bytes" for semantic in _TRACE_SEMANTICS},
}
_SEMANTIC_CLASSES = {
    **{semantic: "heap" for semantic in _HEAP_RAW_SEMANTICS},
    **{semantic: "stack" for semantic in _STACK_SEMANTICS},
    **{semantic: "trace_buffer" for semantic in _TRACE_SEMANTICS},
}
_MONOTONIC_SEMANTICS = frozenset(
    {
        _HEAP_PEAK,
        _HEAP_ALLOCATION_COUNT,
        _HEAP_FREE_COUNT,
        _HEAP_LARGEST_ALLOCATION,
        _STACK_PEAK,
        _TRACE_PEAK,
    }
)
_CAPACITY_SEMANTICS = frozenset({_STACK_CAPACITY, _TRACE_CAPACITY})


class ResourceVerificationError(RuntimeError):
    """The verification input crossed a trust, structure, or size boundary."""


class DuplicateJsonKeyError(ValueError):
    """A strict JSON object repeated one member name."""


@dataclass(frozen=True)
class _CounterDefinition:
    counter_id: str
    semantic: str
    subject: dict[str, Any]
    subject_key: str
    unit: str


@dataclass(frozen=True)
class _CounterSample:
    ts_ns: int
    value: float
    source_id: str
    source_seq: int


@dataclass(frozen=True)
class _Metric:
    semantic: str
    subject: dict[str, Any]
    subject_key: str
    unit: str
    value: float
    first_ts_ns: int
    last_ts_ns: int
    source_counter_ids: tuple[str, ...]
    samples: tuple[_CounterSample, ...] = ()

    @property
    def identity(self) -> tuple[str, str]:
        return (self.semantic, self.subject_key)

    @property
    def category(self) -> str:
        if self.semantic.startswith("heap."):
            return "allocator"
        if self.semantic.startswith("stack."):
            return "stack"
        if self.semantic.startswith("trace_buffer."):
            return "trace_buffer"
        raise AssertionError(f"unsupported resource metric {self.semantic}")


@dataclass(frozen=True)
class _StaticRamFacts:
    flavor: str
    total_bytes: int
    totals: dict[str, int]
    report_artifact: VerifiedArtifact
    config_artifact: VerifiedArtifact
    source_artifact: VerifiedArtifact
    config_sha256: str
    source_sha256: str


@dataclass(frozen=True)
class _SourceClock:
    domain_id: str
    frequency_numerator: int
    frequency_denominator: int


@dataclass(frozen=True)
class _RebuiltFacts:
    board_id: str
    metrics: dict[tuple[str, str], _Metric]
    observations: dict[tuple[str, int], dict[str, Any]]
    clocks: dict[str, dict[str, Any]]
    source_clocks: dict[str, _SourceClock]
    resource_clock_id: str
    function_clock_id: str
    call_depth: dict[str, Any]
    trace_overflow: bool
    static_ram: _StaticRamFacts
    bindings: dict[str, tuple[str | None, str]]


@dataclass
class _CategoryCount:
    total: int = 0
    passed: int = 0
    failed: int = 0

    def to_document(self) -> dict[str, int]:
        return {"total": self.total, "passed": self.passed, "failed": self.failed}


@dataclass
class _CheckRecorder:
    tolerance: TolerancePolicy
    category_order: tuple[str, ...] = RESOURCE_CHECK_CATEGORIES
    categories: dict[str, _CategoryCount] = field(init=False)
    receipt_checks: list[VerificationCheck] = field(default_factory=list)
    failures: list[dict[str, str]] = field(default_factory=list)
    failure_count: int = 0
    max_absolute_error: float = 0.0
    max_relative_error: float = 0.0
    max_error_check: str | None = None

    def __post_init__(self) -> None:
        self.categories = {
            category: _CategoryCount() for category in self.category_order
        }

    def check(
        self,
        category: str,
        name: str,
        condition: bool,
        reason: str,
        *,
        absolute_error: float | None = None,
        relative_error: float | None = None,
    ) -> None:
        counts = self.categories[category]
        counts.total += 1
        if absolute_error is not None and relative_error is not None:
            if (
                absolute_error > self.max_absolute_error
                or relative_error > self.max_relative_error
            ):
                self.max_absolute_error = max(self.max_absolute_error, absolute_error)
                self.max_relative_error = max(self.max_relative_error, relative_error)
                self.max_error_check = name
        self.receipt_checks.append(
            VerificationCheck(
                category=category,
                name=_truncate_utf8(name, 512),
                passed=condition,
                reason="" if condition else _truncate_utf8(reason, 2048),
                absolute_error=absolute_error,
                relative_error=relative_error,
            )
        )
        if condition:
            counts.passed += 1
            return
        counts.failed += 1
        self.failure_count += 1
        if len(self.failures) < MAX_FAILURES_IN_RECEIPT:
            self.failures.append({"check": name, "reason": reason})

    def equal(
        self,
        category: str,
        name: str,
        expected: object,
        actual: object,
    ) -> None:
        self.check(
            category,
            name,
            expected == actual,
            f"expected {expected!r}, observed {actual!r}",
        )

    def number(
        self,
        category: str,
        name: str,
        expected: float,
        actual: float,
        *,
        absolute_tolerance: float,
        relative_tolerance: float,
    ) -> None:
        absolute_error = abs(actual - expected)
        scale = abs(expected)
        relative_error = absolute_error / scale if scale > 0 else 0.0
        allowed = max(absolute_tolerance, scale * relative_tolerance)
        self.check(
            category,
            name,
            absolute_error <= allowed,
            (
                f"expected {expected!r}, observed {actual!r}, "
                f"error {absolute_error!r}, tolerance {allowed!r}"
            ),
            absolute_error=absolute_error,
            relative_error=relative_error,
        )

    def to_document(self) -> dict[str, Any]:
        total = sum(count.total for count in self.categories.values())
        passed = sum(count.passed for count in self.categories.values())
        failed = sum(count.failed for count in self.categories.values())
        return {
            "counts": {"total": total, "passed": passed, "failed": failed},
            "by_category": {
                category: self.categories[category].to_document()
                for category in self.category_order
            },
            "max_error": {
                "check": self.max_error_check,
                "absolute": self.max_absolute_error,
                "relative": self.max_relative_error,
            },
            "failure_count": self.failure_count,
            "failures": self.failures,
            "failures_truncated": self.failure_count > len(self.failures),
        }


def canonical_json_bytes(document: object) -> bytes:
    """Return deterministic UTF-8 JSON bytes for provenance digests."""

    try:
        return json.dumps(
            document,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ResourceVerificationError(
            f"document cannot be represented as canonical JSON: {error}"
        ) from error


def canonical_sha256(document: object) -> str:
    """Hash canonical JSON bytes with SHA-256."""

    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()


def load_resource_reference(
    source: Path | bytes | bytearray | Mapping[str, Any],
) -> dict[str, Any]:
    """Load and semantically validate one bounded strict driver reference."""

    document = _load_json_source(source, MAX_REFERENCE_BYTES, "driver reference")
    _validate_reference(document)
    return document


def load_verification_receipt(
    source: Path | bytes | bytearray | Mapping[str, Any],
) -> dict[str, Any]:
    """Load and validate one bounded strict verification receipt."""

    try:
        return _load_common_receipt(source)
    except VerificationReceiptError as error:
        raise ResourceVerificationError(str(error)) from error


def load_hil_evidence(
    source: Path | bytes | bytearray | Mapping[str, Any],
) -> dict[str, Any]:
    """Read v1 compatibility evidence or the complete v2 DoD evidence."""

    document = _load_json_source(source, MAX_EVIDENCE_BYTES, "HIL evidence")
    schema = document.get("schema")
    if schema == HIL_EVIDENCE_V1_SCHEMA:
        _validate_v1_evidence_shape(document)
    elif schema == HIL_EVIDENCE_V2_SCHEMA:
        assert_v2_verification_coverage(document)
    else:
        raise ResourceVerificationError(f"unsupported HIL evidence schema {schema!r}")
    return document


def verify_resource_reference(
    session: VerifiedSession,
    reference: Path | bytes | bytearray | Mapping[str, Any],
    *,
    tick_ns: float,
) -> dict[str, Any]:
    """Rebuild P7 facts and return a bound PASS or FAIL receipt."""

    reference_document = load_resource_reference(reference)
    if reference_document["session_id"] != session.session_id:
        raise ResourceVerificationError(
            "driver reference belongs to a different Session"
        )
    tolerance = TolerancePolicy(timestamp_absolute_ns=float(tick_ns))
    facts = _rebuild_session_facts(session)
    recorder = _CheckRecorder(tolerance)
    _compare_reference(reference_document, facts, recorder)
    _compare_analysis_summary(session, facts, recorder)

    try:
        receipt = build_verification_receipt(
            kind="resources",
            scenario=None,
            board_id=facts.board_id,
            session_id=session.session_id,
            driver_reference_sha256=canonical_sha256(reference_document),
            tolerance=tolerance,
            artifact_bindings=facts.bindings,
            checks=recorder.receipt_checks,
        )
    except VerificationReceiptError as error:
        raise ResourceVerificationError(str(error)) from error
    if len(canonical_json_bytes(receipt)) > MAX_RECEIPT_BYTES:
        raise ResourceVerificationError(
            f"verification receipt exceeds {MAX_RECEIPT_BYTES} bytes"
        )
    return receipt


def validate_verification_receipt(receipt: Mapping[str, Any]) -> None:
    """Delegate the common envelope validation without exposing its error type."""

    try:
        _validate_common_receipt(receipt)
    except VerificationReceiptError as error:
        raise ResourceVerificationError(str(error)) from error


def build_hil_evidence_v2(
    capture_evidence: Mapping[str, Any],
    receipts: list[Mapping[str, Any]] | tuple[Mapping[str, Any], ...],
) -> dict[str, Any]:
    """Upgrade v1 captures with complete per-board v2 verification receipts."""

    base = _load_json_source(capture_evidence, MAX_EVIDENCE_BYTES, "capture evidence")
    if base.get("schema") not in {HIL_EVIDENCE_V1_SCHEMA, HIL_EVIDENCE_V2_SCHEMA}:
        raise ResourceVerificationError("capture evidence is neither v1 nor v2")
    if base["schema"] == HIL_EVIDENCE_V1_SCHEMA:
        _validate_v1_evidence_shape(base)
    else:
        assert_v2_verification_coverage(base)
        base = {
            "schema": HIL_EVIDENCE_V1_SCHEMA,
            "source": base["source"],
            "coverage": {
                key: value
                for key, value in base["coverage"].items()
                if key != "verification"
            },
            "captures": base["captures"],
        }

    entries: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str | None]] = set()
    for raw in receipts:
        receipt = _load_json_source(raw, MAX_RECEIPT_BYTES, "verification receipt")
        validate_verification_receipt(receipt)
        if receipt["verdict"] != "PASS":
            raise ResourceVerificationError(
                "FAIL receipt cannot satisfy v2 HIL coverage"
            )
        key = (
            receipt["board_id"],
            receipt["session_id"],
            receipt["kind"],
            receipt["scenario"],
        )
        if key in seen:
            raise ResourceVerificationError(
                "duplicate verification receipt for "
                f"{key[0]}/{key[1]}/{key[2]}/{key[3]}"
            )
        seen.add(key)
        entries.append(
            {
                "board_id": key[0],
                "session_id": key[1],
                "kind": key[2],
                "scenario": key[3],
                "canonical_receipt_sha256": canonical_sha256(receipt),
                "receipt": receipt,
            }
        )
    entries.sort(
        key=lambda entry: (
            entry["board_id"],
            entry["kind"],
            "" if entry["scenario"] is None else entry["scenario"],
            entry["session_id"],
        )
    )
    verified_boards = sorted({entry["board_id"] for entry in entries})
    document = {
        "schema": HIL_EVIDENCE_V2_SCHEMA,
        "source": base["source"],
        "coverage": {
            **base["coverage"],
            "verification": {
                "required_kinds": [
                    "native_timeline",
                    "resources",
                    "fault_injection",
                ],
                "required_fault_scenarios": [
                    "trace_overflow",
                    "flow_error",
                    "sampling_buffer_full",
                    "elf_mismatch",
                    "trace32_disconnect_recovery",
                    "driver_disconnect_recovery",
                    "cmm_abort_recovery",
                ],
                "boards": verified_boards,
                "receipt_count": len(entries),
            },
        },
        "captures": base["captures"],
        "verifications": entries,
    }
    assert_v2_verification_coverage(document)
    if len(canonical_json_bytes(document)) > MAX_EVIDENCE_BYTES:
        raise ResourceVerificationError(
            f"HIL evidence exceeds {MAX_EVIDENCE_BYTES} bytes"
        )
    return document


def assert_v2_verification_coverage(document: Mapping[str, Any]) -> None:
    """Require timeline, resource, and fault receipts for every capture board."""

    evidence = _as_object(document, "HIL evidence v2")
    _require_exact_fields(
        evidence,
        {"schema", "source", "coverage", "captures", "verifications"},
        "HIL evidence v2",
    )
    if evidence["schema"] != HIL_EVIDENCE_V2_SCHEMA:
        raise ResourceVerificationError("HIL evidence does not declare v2")
    if evidence["source"] != "host-verified-session-artifacts":
        raise ResourceVerificationError("HIL evidence source is not host verified")
    coverage = _as_object(evidence["coverage"], "HIL evidence coverage")
    required_coverage = {
        "boards",
        "mcu_families",
        "modes",
        "rtoses",
        "probes",
        "architecture_packages",
        "combinations",
        "verification",
    }
    _require_exact_fields(coverage, required_coverage, "HIL evidence coverage")
    _validate_v1_evidence_shape(
        {
            "schema": HIL_EVIDENCE_V1_SCHEMA,
            "source": evidence["source"],
            "coverage": {
                key: value for key, value in coverage.items() if key != "verification"
            },
            "captures": evidence["captures"],
        }
    )
    boards = _unique_strings(coverage["boards"], "coverage.boards", minimum=1)
    captures = _as_list(
        evidence["captures"], "HIL evidence captures", MAX_RESOURCE_OBSERVATIONS
    )
    capture_index: dict[tuple[str, str], dict[str, Any]] = {}
    for index, raw in enumerate(captures):
        capture = _as_object(raw, f"captures[{index}]")
        board_id = _bounded_string(capture.get("board_id"), "capture board ID", 256)
        session_id = _bounded_string(
            capture.get("session_id"), "capture Session ID", 64
        )
        key = (board_id, session_id)
        if key in capture_index:
            raise ResourceVerificationError(
                f"capture matrix repeats board/Session identity {board_id}/{session_id}"
            )
        _require_sha256(capture.get("manifest_sha256"), "capture manifest digest")
        _require_sha256(capture.get("health_sha256"), "capture health digest")
        capture_index[key] = capture
    capture_boards = {board_id for board_id, _ in capture_index}
    if capture_boards != set(boards):
        raise ResourceVerificationError(
            "capture rows do not exactly cover the declared boards"
        )
    verification_coverage = _as_object(
        coverage["verification"], "coverage.verification"
    )
    _require_exact_fields(
        verification_coverage,
        {
            "required_kinds",
            "required_fault_scenarios",
            "boards",
            "receipt_count",
        },
        "coverage.verification",
    )
    if verification_coverage["required_kinds"] != [
        "native_timeline",
        "resources",
        "fault_injection",
    ]:
        raise ResourceVerificationError(
            "v2 evidence must require native_timeline, resources, and fault_injection"
        )
    if verification_coverage["required_fault_scenarios"] != [
        "trace_overflow",
        "flow_error",
        "sampling_buffer_full",
        "elf_mismatch",
        "trace32_disconnect_recovery",
        "driver_disconnect_recovery",
        "cmm_abort_recovery",
    ]:
        raise ResourceVerificationError(
            "v2 evidence fault scenario requirements are incomplete"
        )
    declared_verified_boards = _unique_strings(
        verification_coverage["boards"], "coverage.verification.boards", minimum=1
    )
    receipt_count = _nonnegative_int(
        verification_coverage["receipt_count"], "coverage verification receipt count"
    )
    entries = _as_list(evidence["verifications"], "HIL evidence verifications", 100_000)
    if receipt_count != len(entries):
        raise ResourceVerificationError("verification receipt count is inconsistent")
    seen: set[tuple[str, str, str, str | None]] = set()
    actual_boards: set[str] = set()
    board_kinds: dict[str, set[str]] = {}
    board_faults: dict[str, set[str]] = {}
    for index, raw in enumerate(entries):
        entry = _as_object(raw, f"verifications[{index}]")
        _require_exact_fields(
            entry,
            {
                "board_id",
                "session_id",
                "kind",
                "scenario",
                "canonical_receipt_sha256",
                "receipt",
            },
            f"verifications[{index}]",
        )
        board_id = _bounded_string(entry["board_id"], "verification board ID", 256)
        session_id = _bounded_string(entry["session_id"], "verification Session ID", 64)
        kind = _bounded_string(entry["kind"], "verification kind", 64)
        scenario = entry["scenario"]
        if scenario is not None:
            scenario = _bounded_string(scenario, "verification scenario", 64)
        key = (board_id, session_id, kind, scenario)
        if key in seen:
            raise ResourceVerificationError(
                "duplicate verification entry for "
                f"{board_id}/{session_id}/{kind}/{scenario}"
            )
        seen.add(key)
        receipt = _as_object(entry["receipt"], "embedded verification receipt")
        validate_verification_receipt(receipt)
        if receipt["verdict"] != "PASS":
            raise ResourceVerificationError("v2 evidence embeds a non-PASS receipt")
        if (
            receipt["board_id"],
            receipt["session_id"],
            receipt["kind"],
            receipt["scenario"],
        ) != key:
            raise ResourceVerificationError(
                "verification entry identity differs from receipt"
            )
        _require_sha256(entry["canonical_receipt_sha256"], "canonical receipt digest")
        if entry["canonical_receipt_sha256"] != canonical_sha256(receipt):
            raise ResourceVerificationError(
                "embedded receipt canonical digest is wrong"
            )
        if kind in {"native_timeline", "resources"}:
            capture = capture_index.get((board_id, session_id))
            if capture is None:
                raise ResourceVerificationError(
                    f"{kind} receipt {board_id}/{session_id} is not a capture matrix Session"
                )
            bindings = {
                binding["role"]: binding for binding in receipt["artifact_bindings"]
            }
            if (
                bindings["manifest"]["sha256"] != capture["manifest_sha256"]
                or bindings["health"]["sha256"] != capture["health_sha256"]
            ):
                raise ResourceVerificationError(
                    f"{kind} receipt artifact digests differ from capture "
                    f"{board_id}/{session_id}"
                )
        actual_boards.add(board_id)
        board_kinds.setdefault(board_id, set()).add(kind)
        if kind == "fault_injection" and scenario is not None:
            board_faults.setdefault(board_id, set()).add(scenario)
    if set(declared_verified_boards) != actual_boards:
        raise ResourceVerificationError("declared verification boards are inconsistent")
    missing_boards = set(boards) - actual_boards
    unexpected_boards = actual_boards - set(boards)
    coverage_failures: list[str] = []
    required_kinds = {"native_timeline", "resources", "fault_injection"}
    required_faults = {
        "trace_overflow",
        "flow_error",
        "sampling_buffer_full",
        "elf_mismatch",
        "trace32_disconnect_recovery",
        "driver_disconnect_recovery",
        "cmm_abort_recovery",
    }
    for board_id in boards:
        missing_kinds = required_kinds - board_kinds.get(board_id, set())
        missing_faults = required_faults - board_faults.get(board_id, set())
        if missing_kinds or missing_faults:
            coverage_failures.append(
                f"{board_id}: kinds={sorted(missing_kinds)}, "
                f"faults={sorted(missing_faults)}"
            )
    if missing_boards or unexpected_boards or coverage_failures:
        raise ResourceVerificationError(
            "verification board coverage is incomplete; "
            f"missing={sorted(missing_boards)}, "
            f"unexpected={sorted(unexpected_boards)}, "
            f"requirements={coverage_failures}"
        )


def write_verification_receipt(receipt: Mapping[str, Any], output_path: Path) -> None:
    """Exclusively persist a validated receipt; never overwrite evidence."""

    try:
        _write_common_receipt(receipt, output_path)
    except VerificationReceiptError as error:
        raise ResourceVerificationError(str(error)) from error


def write_hil_evidence_v2(document: Mapping[str, Any], output_path: Path) -> None:
    """Exclusively persist a complete v2 evidence matrix."""

    evidence = _load_json_source(document, MAX_EVIDENCE_BYTES, "HIL evidence")
    assert_v2_verification_coverage(evidence)
    _write_exclusive_json(evidence, output_path, MAX_EVIDENCE_BYTES, "HIL evidence")


def _rebuild_session_facts(session: VerifiedSession) -> _RebuiltFacts:
    manifest_path = session.path / "manifest.json"
    manifest_bytes = _read_bounded_file(manifest_path, MAX_MANIFEST_BYTES, "manifest")
    manifest = _strict_json_object(manifest_bytes, "manifest")
    if manifest != session.manifest:
        raise ResourceVerificationError("manifest changed after Session verification")
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if manifest.get("session_id") != session.session_id:
        raise ResourceVerificationError("manifest Session identity changed")
    _verify_exact_capture_capabilities(manifest)

    health_artifact, health = _read_verified_json(session, "health")
    observations_artifact = _revalidate_artifact(session, "observations")
    summary_artifact, summary = _read_verified_json(session, "analysis-summary")
    hotspots_artifact, hotspots = _read_verified_json(session, "hotspots")
    for label, document in (
        ("health", health),
        ("analysis summary", summary),
        ("hotspots", hotspots),
    ):
        if document.get("session_id") != session.session_id:
            raise ResourceVerificationError(f"{label} belongs to another Session")
    if health.get("schema") != "t32perf.health/v1":
        raise ResourceVerificationError("health artifact has an unsupported schema")
    if health.get("verdict") != "VALID":
        raise ResourceVerificationError("resource verification requires VALID health")
    if summary.get("schema") != "t32perf.analysis-summary/v1":
        raise ResourceVerificationError("analysis summary has an unsupported schema")
    if summary.get("health_verdict") != "VALID":
        raise ResourceVerificationError(
            "analysis summary is not quantitative VALID evidence"
        )
    if hotspots.get("schema") != "t32perf.hotspots/v1":
        raise ResourceVerificationError("hotspots artifact has an unsupported schema")

    metrics, observation_index = _rebuild_dynamic_metrics(session)
    _require_complete_dynamic_coverage(metrics)
    static_ram = _rebuild_static_ram(session, summary)
    board_id, clocks = _manifest_clock_facts(manifest)
    normalize_artifact, source_clocks = _normalization_clock_facts(
        session,
        observations_artifact,
        {source_id for source_id, _ in observation_index},
    )
    resource_sources = {
        source_id
        for (source_id, sequence), record in observation_index.items()
        if record.get("type") == "Counter" and sequence >= 0
    }
    function_sources = {
        source_id
        for (source_id, sequence), record in observation_index.items()
        if record.get("type") in {"FunctionEnter", "FunctionExit"} and sequence >= 0
    }
    resource_clock_id = _single_source_domain(
        resource_sources, source_clocks, "resource"
    )
    function_clock_id = _single_source_domain(
        function_sources, source_clocks, "function"
    )
    if resource_clock_id != function_clock_id:
        raise ResourceVerificationError(
            "resource and function observations use different clock domains"
        )
    _validate_source_clocks(source_clocks, clocks)
    call_depth = _summary_call_depth(summary)
    trace_overflow = _health_has_trace_overflow(health)

    bindings = {
        "manifest": (None, manifest_sha256),
        "health": (health_artifact.artifact_id, health_artifact.sha256),
        "observations": (
            observations_artifact.artifact_id,
            observations_artifact.sha256,
        ),
        "analysis_summary": (summary_artifact.artifact_id, summary_artifact.sha256),
        "hotspots": (hotspots_artifact.artifact_id, hotspots_artifact.sha256),
        "static_ram_report": (
            static_ram.report_artifact.artifact_id,
            static_ram.report_artifact.sha256,
        ),
        "static_ram_config": (
            static_ram.config_artifact.artifact_id,
            static_ram.config_artifact.sha256,
        ),
        "static_ram_source": (
            static_ram.source_artifact.artifact_id,
            static_ram.source_artifact.sha256,
        ),
        "resource_source": (
            observations_artifact.artifact_id,
            observations_artifact.sha256,
        ),
        "normalize_config": (
            normalize_artifact.artifact_id,
            normalize_artifact.sha256,
        ),
    }
    return _RebuiltFacts(
        board_id=board_id,
        metrics=metrics,
        observations=observation_index,
        clocks=clocks,
        source_clocks=source_clocks,
        resource_clock_id=resource_clock_id,
        function_clock_id=function_clock_id,
        call_depth=call_depth,
        trace_overflow=trace_overflow,
        static_ram=static_ram,
        bindings=bindings,
    )


def _rebuild_dynamic_metrics(
    session: VerifiedSession,
) -> tuple[dict[tuple[str, str], _Metric], dict[tuple[str, int], dict[str, Any]]]:
    definitions: dict[str, _CounterDefinition] = {}
    ignored_counter_ids: set[str] = set()
    identity_to_counter: dict[tuple[str, str], str] = {}
    samples: dict[str, list[_CounterSample]] = {}
    observation_index: dict[tuple[str, int], dict[str, Any]] = {}
    header_seen = False
    observations_started = False
    resource_observation_count = 0
    function_observation_count = 0

    for line_number, record in enumerate(
        session.iter_ndjson_artifact("observations"), start=1
    ):
        if line_number == 1:
            if (
                record.get("schema") != "t32perf.observation/v1"
                or record.get("session_id") != session.session_id
                or record.get("encoding") != "ndjson"
                or record.get("time_unit") != "ns"
                or record.get("time_origin") != "session_relative"
            ):
                raise ResourceVerificationError("observations stream header is invalid")
            header_seen = True
            continue

        entries: list[dict[str, Any]] = []
        if record.get("type") in {
            "DefineContext",
            "DefineFunction",
            "DefineCounter",
        }:
            entries.append(record)
        nested_entries = record.get("entries")
        if isinstance(nested_entries, list):
            entries.extend(entry for entry in nested_entries if isinstance(entry, dict))
        if entries:
            if observations_started:
                raise ResourceVerificationError(
                    "counter dictionary entry appears after observations"
                )
            for entry in entries:
                if entry.get("type") != "DefineCounter":
                    continue
                counter_id, definition = _parse_counter_definition(entry)
                if counter_id in definitions or counter_id in ignored_counter_ids:
                    raise ResourceVerificationError(
                        f"duplicate counter definition {counter_id!r}"
                    )
                if definition is None:
                    ignored_counter_ids.add(counter_id)
                    continue
                identity = (definition.semantic, definition.subject_key)
                if identity in identity_to_counter:
                    raise ResourceVerificationError(
                        "multiple counter IDs declare the same semantic and subject"
                    )
                definitions[definition.counter_id] = definition
                identity_to_counter[identity] = definition.counter_id
                if len(definitions) > MAX_COUNTER_DEFINITIONS:
                    raise ResourceVerificationError(
                        "counter dictionary exceeds its bound"
                    )
            continue

        event_type = record.get("type")
        if event_type is None:
            continue
        observations_started = True
        if event_type not in {"Counter", "FunctionEnter", "FunctionExit"}:
            continue
        source_id = _bounded_string(
            record.get("source_id"), "observation source ID", 256
        )
        source_seq = _nonnegative_int(
            record.get("source_seq"), "observation source sequence"
        )
        key = (source_id, source_seq)
        if key in observation_index:
            raise ResourceVerificationError(f"duplicate observation identity {key!r}")
        ts_ns = _integer(record.get("ts_ns"), "observation timestamp")
        observation_index[key] = record
        if event_type in {"FunctionEnter", "FunctionExit"}:
            function_observation_count += 1
            continue
        resource_observation_count += 1
        if resource_observation_count > MAX_RESOURCE_OBSERVATIONS:
            raise ResourceVerificationError(
                "resource observation count exceeds its bound"
            )
        if record.get("quality") != "exact":
            raise ResourceVerificationError(
                "P7 verification requires exact counter evidence"
            )
        counter_id = _bounded_string(record.get("counter_id"), "counter ID", 256)
        if counter_id in ignored_counter_ids:
            continue
        definition = definitions.get(counter_id)
        if definition is None:
            raise ResourceVerificationError(
                f"resource observation references undefined counter {counter_id!r}"
            )
        value = _resource_value(
            record.get("value"), definition.unit, definition.semantic
        )
        rows = samples.setdefault(counter_id, [])
        if rows and ts_ns < rows[-1].ts_ns:
            raise ResourceVerificationError(
                f"counter {counter_id!r} timestamps are not monotonic"
            )
        if rows and ts_ns == rows[-1].ts_ns:
            raise ResourceVerificationError(
                f"counter {counter_id!r} repeats timestamp {ts_ns}"
            )
        if (
            rows
            and definition.semantic in _MONOTONIC_SEMANTICS
            and value < rows[-1].value
        ):
            raise ResourceVerificationError(
                f"counter {counter_id!r} violates monotonic/high-watermark semantics"
            )
        if (
            rows
            and definition.semantic in _CAPACITY_SEMANTICS
            and value != rows[-1].value
        ):
            raise ResourceVerificationError(
                f"counter {counter_id!r} changes a declared capacity"
            )
        rows.append(
            _CounterSample(
                ts_ns=ts_ns,
                value=value,
                source_id=source_id,
                source_seq=source_seq,
            )
        )

    if not header_seen:
        raise ResourceVerificationError("observations artifact is empty")
    if resource_observation_count == 0:
        raise ResourceVerificationError("observations contain no resource counters")
    if function_observation_count == 0:
        raise ResourceVerificationError(
            "clock alignment requires at least one function timestamp"
        )

    metrics: dict[tuple[str, str], _Metric] = {}
    for counter_id, definition in definitions.items():
        if definition.semantic not in _RAW_SEMANTICS:
            continue
        counter_samples = samples.get(counter_id)
        if not counter_samples:
            raise ResourceVerificationError(
                f"required counter {counter_id!r} has no observations"
            )
        metric = _Metric(
            semantic=definition.semantic,
            subject=definition.subject,
            subject_key=definition.subject_key,
            unit=definition.unit,
            value=counter_samples[-1].value,
            first_ts_ns=counter_samples[0].ts_ns,
            last_ts_ns=counter_samples[-1].ts_ns,
            source_counter_ids=(counter_id,),
            samples=tuple(counter_samples),
        )
        metrics[metric.identity] = metric

    allocator_subjects = {
        subject_key
        for semantic, subject_key in metrics
        if semantic in _HEAP_RAW_SEMANTICS
    }
    for subject_key in allocator_subjects:
        allocation_count = metrics[(_HEAP_ALLOCATION_COUNT, subject_key)]
        if len(allocation_count.samples) < 2:
            raise ResourceVerificationError(
                "allocation-rate verification requires at least two allocation-count samples"
            )
        window_ns = allocation_count.last_ts_ns - allocation_count.first_ts_ns
        if window_ns <= 0:
            raise ResourceVerificationError("allocation-rate window must be positive")
        rate = (
            (allocation_count.value - allocation_count.samples[0].value)
            * 1_000_000_000.0
            / window_ns
        )
        rate_metric = _Metric(
            semantic=_HEAP_RATE,
            subject=allocation_count.subject,
            subject_key=subject_key,
            unit="1/s",
            value=rate,
            first_ts_ns=allocation_count.first_ts_ns,
            last_ts_ns=allocation_count.last_ts_ns,
            source_counter_ids=allocation_count.source_counter_ids,
        )
        metrics[rate_metric.identity] = rate_metric

        free_metric = metrics[(_HEAP_FREE_BYTES, subject_key)]
        largest_metric = metrics[(_HEAP_LARGEST_FREE, subject_key)]
        free_by_ts = {sample.ts_ns: sample.value for sample in free_metric.samples}
        largest_by_ts = {
            sample.ts_ns: sample.value for sample in largest_metric.samples
        }
        synchronized = sorted(set(free_by_ts) & set(largest_by_ts))
        if not synchronized:
            raise ResourceVerificationError(
                "fragmentation verification requires synchronized allocator samples"
            )
        timestamp = synchronized[-1]
        free_bytes = free_by_ts[timestamp]
        largest_free = largest_by_ts[timestamp]
        if free_bytes <= 0 or largest_free > free_bytes:
            raise ResourceVerificationError(
                "allocator fragmentation inputs are invalid"
            )
        fragmentation = _Metric(
            semantic=_HEAP_FRAGMENTATION,
            subject=free_metric.subject,
            subject_key=subject_key,
            unit="ratio",
            value=1.0 - largest_free / free_bytes,
            first_ts_ns=timestamp,
            last_ts_ns=timestamp,
            source_counter_ids=tuple(
                sorted(
                    free_metric.source_counter_ids + largest_metric.source_counter_ids
                )
            ),
        )
        metrics[fragmentation.identity] = fragmentation

    _validate_usage_invariants(metrics)
    return metrics, observation_index


def _parse_counter_definition(
    entry: dict[str, Any],
) -> tuple[str, _CounterDefinition | None]:
    counter_id = _bounded_string(entry.get("id"), "counter definition ID", 256)
    semantic_value = entry.get("semantic")
    subject_value = entry.get("subject")
    if semantic_value is None and subject_value is None:
        return counter_id, None
    semantic = _bounded_string(semantic_value, "counter semantic", 128)
    if semantic not in _RAW_SEMANTICS:
        return counter_id, None
    subject = _validate_subject(subject_value, semantic)
    unit = _bounded_string(entry.get("unit"), "counter unit", 32)
    expected_unit = _SEMANTIC_UNITS.get(semantic)
    if expected_unit is not None and unit != expected_unit:
        raise ResourceVerificationError(
            f"counter {counter_id!r} unit {unit!r} does not match {semantic!r}"
        )
    return (
        counter_id,
        _CounterDefinition(
            counter_id=counter_id,
            semantic=semantic,
            subject=subject,
            subject_key=_subject_key(subject),
            unit=unit,
        ),
    )


def _validate_subject(raw: object, semantic: str) -> dict[str, Any]:
    subject = _as_object(raw, f"subject for {semantic}")
    kind = subject.get("kind")
    if semantic.startswith("heap."):
        _require_exact_fields(subject, {"kind", "allocator_id"}, "allocator subject")
        if kind != "allocator":
            raise ResourceVerificationError(f"{semantic} requires an allocator subject")
        _bounded_string(subject["allocator_id"], "allocator ID", 256)
    elif semantic.startswith("stack."):
        allowed = {"kind", "stack_id", "role", "context_id", "core_id"}
        if not set(subject).issubset(allowed) or not {
            "kind",
            "stack_id",
            "role",
        }.issubset(subject):
            raise ResourceVerificationError("stack subject has an invalid field set")
        if kind != "stack":
            raise ResourceVerificationError(f"{semantic} requires a stack subject")
        _bounded_string(subject["stack_id"], "stack ID", 256)
        role = subject["role"]
        if role not in _STACK_ROLES:
            raise ResourceVerificationError(f"unsupported HIL stack role {role!r}")
        context_id = subject.get("context_id")
        core_id = subject.get("core_id")
        if role in {"task", "isr"}:
            _bounded_string(context_id, f"{role} stack context ID", 256)
        elif context_id is not None:
            raise ResourceVerificationError(f"{role} stack must not name a context")
        if role in {"msp", "psp"}:
            _nonnegative_int(core_id, f"{role} stack core ID")
        elif core_id is not None:
            _nonnegative_int(core_id, f"{role} stack core ID")
    elif semantic.startswith("trace_buffer."):
        allowed = {"kind", "buffer_id", "core_id"}
        if not set(subject).issubset(allowed) or not {"kind", "buffer_id"}.issubset(
            subject
        ):
            raise ResourceVerificationError(
                "trace-buffer subject has an invalid field set"
            )
        if kind != "trace_buffer":
            raise ResourceVerificationError(
                f"{semantic} requires a trace-buffer subject"
            )
        _bounded_string(subject["buffer_id"], "trace-buffer ID", 256)
        if subject.get("core_id") is not None:
            _nonnegative_int(subject["core_id"], "trace-buffer core ID")
    elif semantic in _REFERENCE_SEMANTICS:
        raise ResourceVerificationError(
            f"unsupported subject for semantic {semantic!r}"
        )
    return dict(subject)


def _require_complete_dynamic_coverage(
    metrics: Mapping[tuple[str, str], _Metric],
) -> None:
    allocator_subjects = {
        subject for semantic, subject in metrics if semantic.startswith("heap.")
    }
    if not allocator_subjects:
        raise ResourceVerificationError("P7 evidence contains no allocator")
    for subject in allocator_subjects:
        present = {semantic for semantic, key in metrics if key == subject}
        required = _HEAP_RAW_SEMANTICS | _HEAP_DERIVED_SEMANTICS
        if not required.issubset(present):
            raise ResourceVerificationError(
                f"allocator {subject} omits semantics {sorted(required - present)}"
            )

    stack_subjects = {
        subject for semantic, subject in metrics if semantic.startswith("stack.")
    }
    roles: set[str] = set()
    for subject in stack_subjects:
        rows = [metric for metric in metrics.values() if metric.subject_key == subject]
        if not rows:
            continue
        roles.add(rows[0].subject["role"])
        present = {row.semantic for row in rows}
        if not _STACK_SEMANTICS.issubset(present):
            raise ResourceVerificationError(
                f"stack {subject} omits semantics {sorted(_STACK_SEMANTICS - present)}"
            )
    if roles != _REQUIRED_STACK_ROLES:
        raise ResourceVerificationError(
            "P7 evidence must cover Task, ISR, MSP, and PSP stacks; "
            f"observed={sorted(roles)}"
        )

    trace_subjects = {
        subject for semantic, subject in metrics if semantic.startswith("trace_buffer.")
    }
    if not trace_subjects:
        raise ResourceVerificationError("P7 evidence contains no trace buffer")
    for subject in trace_subjects:
        present = {semantic for semantic, key in metrics if key == subject}
        if not _TRACE_SEMANTICS.issubset(present):
            raise ResourceVerificationError(
                f"trace buffer {subject} omits semantics {sorted(_TRACE_SEMANTICS - present)}"
            )


def _validate_usage_invariants(metrics: Mapping[tuple[str, str], _Metric]) -> None:
    subjects = {subject for _, subject in metrics}
    for subject in subjects:
        rows = {
            semantic: metric
            for (semantic, key), metric in metrics.items()
            if key == subject
        }
        for capacity_semantic, current_semantic, peak_semantic in (
            (_STACK_CAPACITY, _STACK_CURRENT, _STACK_PEAK),
            (_TRACE_CAPACITY, _TRACE_CURRENT, _TRACE_PEAK),
        ):
            if capacity_semantic not in rows:
                continue
            capacity = rows[capacity_semantic].value
            current = rows[current_semantic].value
            peak = rows[peak_semantic].value
            if not current <= peak <= capacity:
                raise ResourceVerificationError(
                    f"resource subject {subject} violates current <= peak <= capacity"
                )
        if _HEAP_CURRENT in rows and rows[_HEAP_CURRENT].value > rows[_HEAP_PEAK].value:
            raise ResourceVerificationError(
                f"allocator {subject} current allocation exceeds its peak"
            )


def _rebuild_static_ram(
    session: VerifiedSession, summary_document: dict[str, Any]
) -> _StaticRamFacts:
    quantitative = _as_object(
        summary_document.get("quantitative"), "analysis quantitative"
    )
    static_summary = _as_object(quantitative.get("static_ram"), "static RAM summary")
    report_id = _bounded_string(
        static_summary.get("artifact_id"), "static RAM report artifact ID", 256
    )
    source_id = _bounded_string(
        static_summary.get("source_artifact_id"), "static RAM source artifact ID", 256
    )
    flavor = _bounded_string(static_summary.get("flavor"), "static RAM flavor", 64)
    if flavor not in {"gnu-ld-map-v1", "elf-sections-v1"}:
        raise ResourceVerificationError(f"unsupported static RAM flavor {flavor!r}")
    support = _as_object(static_summary.get("support"), "static RAM support")
    if support.get("support") not in {"exact", "inferred"} or not isinstance(
        support.get("reasons"), list
    ):
        raise ResourceVerificationError(
            "HIL static RAM evidence must be exact or deterministic inferred evidence"
        )
    config = _as_object(static_summary.get("config"), "static RAM config provenance")
    config_id = _bounded_string(
        config.get("artifact_id"), "static RAM config artifact ID", 256
    )
    config_sha256 = _require_sha256(config.get("sha256"), "static RAM config digest")

    report_artifact, report = _read_verified_json(session, report_id)
    config_artifact, config_document = _read_verified_json(session, config_id)
    source_artifact = _revalidate_artifact(session, source_id)
    expected_report_kind = f"static_ram:{flavor}"
    expected_source_kind = "linker_map" if flavor == "gnu-ld-map-v1" else "firmware_elf"
    if report_artifact.kind != expected_report_kind:
        raise ResourceVerificationError("static RAM report artifact has the wrong kind")
    if source_artifact.kind != expected_source_kind:
        raise ResourceVerificationError("static RAM source artifact has the wrong kind")
    if config_artifact.kind != "static_ram_config":
        raise ResourceVerificationError("static RAM config artifact has the wrong kind")
    if config_artifact.sha256 != config_sha256:
        raise ResourceVerificationError("static RAM config provenance digest is wrong")
    if config_document.get("schema") != "t32perf.static-ram-config/v1":
        raise ResourceVerificationError("static RAM config schema is unsupported")
    if config_document.get("flavor") != flavor:
        raise ResourceVerificationError("static RAM config flavor differs from summary")
    expected_report_schema = f"t32perf.static-ram/{flavor}"
    if report.get("schema") != expected_report_schema:
        raise ResourceVerificationError("static RAM report flavor differs from summary")

    expected_inputs = {source_id, config_id}
    if (
        set(report_artifact.input_artifact_ids) != expected_inputs
        or len(report_artifact.input_artifact_ids) != 2
    ):
        raise ResourceVerificationError(
            "static RAM report provenance must bind its source and config exactly"
        )
    sections = _as_list(report.get("sections"), "static RAM sections", 4099)
    totals = {field_name: 0 for field_name in _STATIC_TOTAL_FIELDS}
    for index, raw in enumerate(sections):
        section = _as_object(raw, f"static RAM section {index}")
        kind = section.get("kind")
        if kind not in _STATIC_KINDS:
            raise ResourceVerificationError(f"invalid static RAM kind {kind!r}")
        size_bytes = _nonnegative_int(
            section.get("size_bytes"), f"static RAM section {index} size"
        )
        totals[f"{kind}_bytes"] += size_bytes
    total_bytes = sum(totals.values())
    report_totals = _static_totals(report.get("totals"), "static RAM report totals")
    if report_totals != totals or report.get("total_bytes") != total_bytes:
        raise ResourceVerificationError("static RAM report totals are inconsistent")
    summary_totals = _static_totals(
        static_summary.get("totals"), "static RAM summary totals"
    )
    if summary_totals != totals or static_summary.get("total_bytes") != total_bytes:
        raise ResourceVerificationError("static RAM summary totals are inconsistent")
    return _StaticRamFacts(
        flavor=flavor,
        total_bytes=total_bytes,
        totals=totals,
        report_artifact=report_artifact,
        config_artifact=config_artifact,
        source_artifact=source_artifact,
        config_sha256=config_artifact.sha256,
        source_sha256=source_artifact.sha256,
    )


def _manifest_clock_facts(
    manifest: dict[str, Any],
) -> tuple[str, dict[str, dict[str, Any]]]:
    capture = _as_object(manifest.get("capture"), "manifest.capture")
    target = _as_object(capture.get("target"), "manifest.capture.target")
    board_id = _bounded_string(target.get("board"), "manifest target board", 256)
    raw_clocks = _as_list(manifest.get("clocks"), "manifest clocks", 256)
    clocks: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_clocks):
        clock = _as_object(raw, f"manifest clock {index}")
        clock_id = _bounded_string(clock.get("id"), "manifest clock ID", 256)
        if clock_id in clocks:
            raise ResourceVerificationError(f"duplicate manifest clock {clock_id!r}")
        frequency_hz = _positive_int(
            clock.get("frequency_hz"), f"manifest clock {clock_id} frequency"
        )
        source = _bounded_string(
            clock.get("source"), f"manifest clock {clock_id} source", 256
        )
        clocks[clock_id] = {"frequency_hz": frequency_hz, "source": source}
    return board_id, clocks


def _verify_exact_capture_capabilities(manifest: dict[str, Any]) -> None:
    capture = _as_object(manifest.get("capture"), "manifest.capture")
    capabilities = _as_object(
        capture.get("capabilities"), "manifest.capture.capabilities"
    )
    for capability_name in ("counters", "function_events"):
        capability = _as_object(
            capabilities.get(capability_name),
            f"manifest.capture.capabilities.{capability_name}",
        )
        if capability.get("support") != "exact" or capability.get("reasons") != []:
            raise ResourceVerificationError(
                f"resource verification requires exact {capability_name} capture capability"
            )


def _normalization_clock_facts(
    session: VerifiedSession,
    observations_artifact: VerifiedArtifact,
    observed_source_ids: set[str],
) -> tuple[VerifiedArtifact, dict[str, _SourceClock]]:
    config_ids = [
        artifact_id
        for artifact_id in observations_artifact.input_artifact_ids
        if artifact_id in session.artifacts
        and session.artifacts[artifact_id].kind == "normalization_config"
    ]
    if len(config_ids) != 1:
        raise ResourceVerificationError(
            "observations provenance must bind exactly one normalization_config artifact"
        )
    config_artifact, config = _read_verified_json(session, config_ids[0])
    if config.get("schema") != "t32perf.normalize-config/v1":
        raise ResourceVerificationError("normalization config schema is unsupported")
    mode = config.get("mode")
    source_clocks: dict[str, _SourceClock] = {}
    canonical_present = False
    configured_inputs: set[str] = set()
    if mode == "single_source":
        _require_exact_fields(
            config,
            {"schema", "mode", "source", "output_limits"},
            "single-source normalization config",
        )
        source_id, clock, canonical = _normalize_source_clock(
            config["source"], "normalization source"
        )
        canonical_present = canonical
        if canonical:
            for observed_source_id in observed_source_ids:
                source_clocks[observed_source_id] = clock
        else:
            source_clocks[source_id] = clock
    elif mode == "multi_source":
        _require_exact_fields(
            config,
            {"schema", "mode", "sources", "output_limits"},
            "multi-source normalization config",
        )
        sources = _as_list(config["sources"], "normalization sources", 64)
        if len(sources) < 2:
            raise ResourceVerificationError(
                "multi-source normalization requires at least two sources"
            )
        for index, raw in enumerate(sources):
            configured = _as_object(raw, f"normalization sources[{index}]")
            _require_exact_fields(
                configured,
                {"input_artifact_id", "clock_domain", "order", "source"},
                f"normalization sources[{index}]",
            )
            input_id = _bounded_string(
                configured["input_artifact_id"], "normalization input artifact ID", 256
            )
            if input_id in configured_inputs:
                raise ResourceVerificationError(
                    f"normalization config repeats input artifact {input_id!r}"
                )
            configured_inputs.add(input_id)
            if input_id not in observations_artifact.input_artifact_ids:
                raise ResourceVerificationError(
                    f"normalization input {input_id!r} is absent from observations provenance"
                )
            if configured["order"] != "reject_ambiguous_ties":
                raise ResourceVerificationError(
                    "normalization source order is unsupported"
                )
            declared_domain = _bounded_string(
                configured["clock_domain"], "declared normalization clock domain", 256
            )
            source_id, clock, canonical = _normalize_source_clock(
                configured["source"], f"normalization sources[{index}].source"
            )
            if declared_domain != clock.domain_id:
                raise ResourceVerificationError(
                    f"normalization source {source_id!r} declares clock domain "
                    f"{declared_domain!r}, embedded adapter clock is {clock.domain_id!r}"
                )
            if source_id in source_clocks:
                raise ResourceVerificationError(
                    f"normalization config repeats source ID {source_id!r}"
                )
            canonical_present = canonical_present or canonical
            if not canonical:
                source_clocks[source_id] = clock
        if canonical_present:
            session_clock = _SourceClock(
                domain_id="session",
                frequency_numerator=1_000_000_000,
                frequency_denominator=1,
            )
            for source_id in observed_source_ids - source_clocks.keys():
                source_clocks[source_id] = session_clock
    else:
        raise ResourceVerificationError(f"unsupported normalization mode {mode!r}")

    missing = observed_source_ids - source_clocks.keys()
    unexpected = source_clocks.keys() - observed_source_ids
    if missing or unexpected:
        raise ResourceVerificationError(
            "normalization config does not exactly cover observation sources; "
            f"missing={sorted(missing)}, unexpected={sorted(unexpected)}"
        )
    return config_artifact, source_clocks


def _normalize_source_clock(raw: object, label: str) -> tuple[str, _SourceClock, bool]:
    source = _as_object(raw, label)
    adapter = source.get("adapter")
    source_id = _bounded_string(source.get("source_id"), f"{label}.source_id", 256)
    if adapter == "canonical_ndjson_v1":
        _require_exact_fields(source, {"adapter", "source_id", "limits"}, label)
        return (
            source_id,
            _SourceClock(
                domain_id="session",
                frequency_numerator=1_000_000_000,
                frequency_denominator=1,
            ),
            True,
        )
    if adapter == "explicit_csv_v1":
        _require_exact_fields(
            source,
            {
                "adapter",
                "source_id",
                "columns",
                "ignored_columns",
                "clock",
                "origin",
                "quality",
                "limits",
            },
            label,
        )
    elif adapter == "c_wire_v1":
        _require_exact_fields(
            source,
            {
                "adapter",
                "wire_version",
                "source_id",
                "core_id",
                "clock",
                "origin",
                "limits",
            },
            label,
        )
        if source["wire_version"] != 1:
            raise ResourceVerificationError("c-wire normalization version must be one")
    else:
        raise ResourceVerificationError(
            f"unsupported normalization adapter {adapter!r}"
        )
    clock = _as_object(source["clock"], f"{label}.clock")
    if not set(clock).issubset({"domain_id", "frequency_hz", "wrap"}) or not {
        "domain_id",
        "frequency_hz",
    }.issubset(clock):
        raise ResourceVerificationError(f"{label}.clock has an invalid field set")
    frequency = _as_object(clock["frequency_hz"], f"{label}.clock.frequency_hz")
    _require_exact_fields(
        frequency,
        {"numerator", "denominator"},
        f"{label}.clock.frequency_hz",
    )
    return (
        source_id,
        _SourceClock(
            domain_id=_bounded_string(
                clock["domain_id"], f"{label}.clock.domain_id", 256
            ),
            frequency_numerator=_positive_int(
                frequency["numerator"], f"{label}.clock.frequency_hz.numerator"
            ),
            frequency_denominator=_positive_int(
                frequency["denominator"], f"{label}.clock.frequency_hz.denominator"
            ),
        ),
        False,
    )


def _single_source_domain(
    source_ids: set[str], source_clocks: Mapping[str, _SourceClock], label: str
) -> str:
    if not source_ids:
        raise ResourceVerificationError(f"no {label} observation sources were found")
    missing = source_ids - source_clocks.keys()
    if missing:
        raise ResourceVerificationError(
            f"{label} observation sources lack clock provenance: {sorted(missing)}"
        )
    domains = {source_clocks[source_id].domain_id for source_id in source_ids}
    if len(domains) != 1:
        raise ResourceVerificationError(
            f"{label} observations span multiple clock domains: {sorted(domains)}"
        )
    return next(iter(domains))


def _validate_source_clocks(
    source_clocks: Mapping[str, _SourceClock], clocks: Mapping[str, dict[str, Any]]
) -> None:
    for source_id, source_clock in source_clocks.items():
        manifest_clock = clocks.get(source_clock.domain_id)
        if manifest_clock is None:
            raise ResourceVerificationError(
                f"source {source_id!r} clock domain {source_clock.domain_id!r} "
                "is absent from manifest.clocks"
            )
        if (
            source_clock.frequency_numerator
            != manifest_clock["frequency_hz"] * source_clock.frequency_denominator
        ):
            raise ResourceVerificationError(
                f"source {source_id!r} normalization frequency differs from manifest clock"
            )


def _summary_call_depth(summary_document: dict[str, Any]) -> dict[str, Any]:
    quantitative = _as_object(
        summary_document.get("quantitative"), "analysis quantitative"
    )
    call_depth = _as_object(quantitative.get("call_depth"), "analysis call depth")
    if not set(call_depth).issubset(
        {"max_depth", "context_id", "deepest_path"}
    ) or not {
        "max_depth",
        "deepest_path",
    }.issubset(call_depth):
        raise ResourceVerificationError("analysis call-depth field set is invalid")
    max_depth = _nonnegative_int(call_depth["max_depth"], "maximum call depth")
    context_id = call_depth.get("context_id")
    if context_id is not None:
        context_id = _bounded_string(context_id, "call-depth context ID", 256)
    raw_path = _as_list(call_depth["deepest_path"], "deepest call path", 4096)
    deepest_path = [
        _bounded_string(value, "deepest call path function ID", 256)
        for value in raw_path
    ]
    if len(deepest_path) != max_depth:
        raise ResourceVerificationError(
            "maximum call depth does not match deepest call path length"
        )
    if max_depth > 0 and context_id is None:
        raise ResourceVerificationError("nonzero call depth requires a context ID")
    return {
        "max_depth": max_depth,
        "context_id": context_id,
        "deepest_path": deepest_path,
    }


def _health_has_trace_overflow(health: dict[str, Any]) -> bool:
    issues = _as_list(health.get("issues"), "health issues", 100_000)
    return any(
        isinstance(issue, dict) and issue.get("code") == "trace_overflow"
        for issue in issues
    )


def _compare_reference(
    reference: dict[str, Any], facts: _RebuiltFacts, recorder: _CheckRecorder
) -> None:
    reference_metrics = {
        (row["semantic"], _subject_key(row["subject"])): row
        for row in reference["metrics"]
    }
    expected_keys = set(facts.metrics)
    actual_keys = set(reference_metrics)
    recorder.equal(
        "artifact_binding",
        "reference.resource_source_artifact_id",
        facts.bindings["resource_source"][0],
        reference["resource_source_artifact_id"],
    )
    recorder.equal(
        "artifact_binding",
        "reference.metric_identity_set",
        sorted(expected_keys),
        sorted(actual_keys),
    )
    for category, prefix in (
        ("allocator", "heap."),
        ("stack", "stack."),
        ("trace_buffer", "trace_buffer."),
    ):
        recorder.equal(
            category,
            f"reference.{category}_identity_set",
            sorted(
                identity for identity in expected_keys if identity[0].startswith(prefix)
            ),
            sorted(
                identity for identity in actual_keys if identity[0].startswith(prefix)
            ),
        )
    for identity in sorted(expected_keys & actual_keys):
        rebuilt = facts.metrics[identity]
        native = reference_metrics[identity]
        category = rebuilt.category
        prefix = f"reference.metrics.{rebuilt.semantic}:{rebuilt.subject_key}"
        recorder.equal(category, f"{prefix}.unit", rebuilt.unit, native["unit"])
        recorder.number(
            category,
            f"{prefix}.value",
            float(native["value"]),
            rebuilt.value,
            absolute_tolerance=(
                recorder.tolerance.integer_absolute
                if rebuilt.unit in {"bytes", "count"}
                else recorder.tolerance.continuous_absolute
            ),
            relative_tolerance=(
                0.0
                if rebuilt.unit in {"bytes", "count"}
                else recorder.tolerance.continuous_relative
            ),
        )
        for field_name in ("first_ts_ns", "last_ts_ns"):
            recorder.number(
                category,
                f"{prefix}.{field_name}",
                float(native[field_name]),
                float(getattr(rebuilt, field_name)),
                absolute_tolerance=recorder.tolerance.timestamp_absolute_ns,
                relative_tolerance=0.0,
            )

    static_reference = reference["static_ram"]
    recorder.equal(
        "static_ram",
        "static_ram.flavor",
        facts.static_ram.flavor,
        static_reference["flavor"],
    )
    recorder.equal(
        "static_ram",
        "static_ram.config_sha256",
        facts.static_ram.config_sha256,
        static_reference["config_sha256"],
    )
    recorder.equal(
        "static_ram",
        "static_ram.source_sha256",
        facts.static_ram.source_sha256,
        static_reference["source_sha256"],
    )
    recorder.equal(
        "static_ram",
        "static_ram.total_bytes",
        facts.static_ram.total_bytes,
        static_reference["total_bytes"],
    )
    for field_name in _STATIC_TOTAL_FIELDS:
        recorder.equal(
            "static_ram",
            f"static_ram.totals.{field_name}",
            facts.static_ram.totals[field_name],
            static_reference["totals"][field_name],
        )

    recorder.equal(
        "trace_buffer",
        "trace_buffer_health.overflowed",
        facts.trace_overflow,
        reference["trace_buffer_health"]["overflowed"],
    )
    call_depth = reference["call_depth"]
    recorder.equal(
        "call_depth",
        "call_depth.max_depth",
        facts.call_depth["max_depth"],
        call_depth["max_depth"],
    )
    recorder.equal(
        "call_depth",
        "call_depth.context_id",
        facts.call_depth["context_id"],
        call_depth["context_id"],
    )
    recorder.equal(
        "call_depth",
        "call_depth.deepest_path",
        facts.call_depth["deepest_path"],
        call_depth["deepest_path"],
    )
    _compare_clock_alignment(reference["clock_alignment"], facts, recorder)


def _compare_clock_alignment(
    reference: dict[str, Any], facts: _RebuiltFacts, recorder: _CheckRecorder
) -> None:
    for role, expected_clock_id in (
        ("resource", facts.resource_clock_id),
        ("function", facts.function_clock_id),
    ):
        row = reference[role]
        recorder.equal(
            "clock_alignment",
            f"clock_alignment.{role}.id",
            expected_clock_id,
            row["id"],
        )
        actual_clock = facts.clocks.get(row["id"])
        recorder.check(
            "clock_alignment",
            f"clock_alignment.{role}.declared",
            actual_clock is not None,
            f"clock {row['id']!r} is absent from the manifest",
        )
        if actual_clock is not None:
            recorder.equal(
                "clock_alignment",
                f"clock_alignment.{role}.frequency_hz",
                actual_clock["frequency_hz"],
                row["frequency_hz"],
            )

    for index, anchor in enumerate(reference["anchors"]):
        resource_key = (anchor["resource_source_id"], anchor["resource_source_seq"])
        function_key = (anchor["function_source_id"], anchor["function_source_seq"])
        resource = facts.observations.get(resource_key)
        function = facts.observations.get(function_key)
        prefix = f"clock_alignment.anchors[{index}]"
        recorder.check(
            "clock_alignment",
            f"{prefix}.resource_identity",
            resource is not None and resource.get("type") == "Counter",
            f"resource anchor {resource_key!r} is not a Counter observation",
        )
        recorder.check(
            "clock_alignment",
            f"{prefix}.function_identity",
            function is not None
            and function.get("type") in {"FunctionEnter", "FunctionExit"},
            f"function anchor {function_key!r} is not a function observation",
        )
        if resource is None or function is None:
            continue
        resource_clock = facts.source_clocks.get(resource_key[0])
        function_clock = facts.source_clocks.get(function_key[0])
        recorder.equal(
            "clock_alignment",
            f"{prefix}.resource_clock_id",
            facts.resource_clock_id,
            None if resource_clock is None else resource_clock.domain_id,
        )
        recorder.equal(
            "clock_alignment",
            f"{prefix}.function_clock_id",
            facts.function_clock_id,
            None if function_clock is None else function_clock.domain_id,
        )
        actual_resource_ts = _integer(
            resource.get("ts_ns"), "resource anchor timestamp"
        )
        actual_function_ts = _integer(
            function.get("ts_ns"), "function anchor timestamp"
        )
        recorder.number(
            "clock_alignment",
            f"{prefix}.resource_ts_ns",
            float(anchor["resource_ts_ns"]),
            float(actual_resource_ts),
            absolute_tolerance=recorder.tolerance.timestamp_absolute_ns,
            relative_tolerance=0.0,
        )
        recorder.number(
            "clock_alignment",
            f"{prefix}.function_ts_ns",
            float(anchor["function_ts_ns"]),
            float(actual_function_ts),
            absolute_tolerance=recorder.tolerance.timestamp_absolute_ns,
            relative_tolerance=0.0,
        )
        actual_delta = actual_resource_ts - actual_function_ts
        recorder.number(
            "clock_alignment",
            f"{prefix}.delta_ns",
            float(anchor["delta_ns"]),
            float(actual_delta),
            absolute_tolerance=recorder.tolerance.timestamp_absolute_ns,
            relative_tolerance=0.0,
        )


def _compare_analysis_summary(
    session: VerifiedSession, facts: _RebuiltFacts, recorder: _CheckRecorder
) -> None:
    _, summary_document = _read_verified_json(session, "analysis-summary")
    metric_support = _as_object(
        summary_document.get("metric_support"), "analysis metric support"
    )
    resource_support = _as_object(
        metric_support.get("resource_counters"), "resource counter support"
    )
    recorder.equal(
        "analysis_summary",
        "analysis_summary.metric_support.resource_counters.support",
        "exact",
        resource_support.get("support"),
    )
    recorder.equal(
        "analysis_summary",
        "analysis_summary.metric_support.resource_counters.reasons",
        [],
        resource_support.get("reasons"),
    )
    for support_name in (
        "function_timeline",
        "call_count",
        "elapsed",
        "active",
        "self",
    ):
        support = _as_object(
            metric_support.get(support_name),
            f"analysis metric support {support_name}",
        )
        recorder.equal(
            "analysis_summary",
            f"analysis_summary.metric_support.{support_name}.support",
            "exact",
            support.get("support"),
        )
        recorder.equal(
            "analysis_summary",
            f"analysis_summary.metric_support.{support_name}.reasons",
            [],
            support.get("reasons"),
        )
    quantitative = _as_object(
        summary_document.get("quantitative"), "analysis quantitative"
    )
    resources = _as_object(quantitative.get("resources"), "analysis resources")
    raw_rows = _as_list(resources.get("counters"), "resource counter summary", 100_000)
    raw_by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    for index, raw in enumerate(raw_rows):
        row = _as_object(raw, f"resource counter summary {index}")
        semantic = row.get("semantic")
        if semantic not in _RAW_SEMANTICS:
            continue
        subject = _validate_subject(row.get("subject"), semantic)
        identity = (semantic, _subject_key(subject))
        if identity in raw_by_identity:
            raise ResourceVerificationError(
                "analysis summary duplicates a resource identity"
            )
        raw_by_identity[identity] = row
    expected_raw = {
        identity: metric
        for identity, metric in facts.metrics.items()
        if metric.semantic in _RAW_SEMANTICS
    }
    recorder.equal(
        "analysis_summary",
        "analysis_summary.raw_identity_set",
        sorted(expected_raw),
        sorted(raw_by_identity),
    )
    for identity in sorted(set(expected_raw) & set(raw_by_identity)):
        metric = expected_raw[identity]
        row = raw_by_identity[identity]
        prefix = f"analysis_summary.counters.{metric.semantic}:{metric.subject_key}"
        recorder.equal(
            "analysis_summary",
            f"{prefix}.counter_id",
            metric.source_counter_ids[0],
            row.get("counter_id"),
        )
        recorder.equal(
            "analysis_summary",
            f"{prefix}.class",
            _SEMANTIC_CLASSES[metric.semantic],
            row.get("class"),
        )
        recorder.equal(
            "analysis_summary", f"{prefix}.unit", metric.unit, row.get("unit")
        )
        recorder.equal(
            "analysis_summary", f"{prefix}.quality", "exact", row.get("quality")
        )
        support = _as_object(row.get("support"), f"{prefix}.support")
        recorder.equal(
            "analysis_summary",
            f"{prefix}.support.level",
            "exact",
            support.get("support"),
        )
        recorder.equal(
            "analysis_summary", f"{prefix}.support.reasons", [], support.get("reasons")
        )
        samples = metric.samples
        values = [sample.value for sample in samples]
        expected_fields: dict[str, float | int | None] = {
            "sample_count": len(samples),
            "first_ts_ns": metric.first_ts_ns,
            "last_ts_ns": metric.last_ts_ns,
            "first": values[0],
            "latest": values[-1],
            "min": min(values),
            "max": max(values),
            "mean": sum(values) / len(values),
            "delta": values[-1] - values[0] if len(values) >= 2 else None,
            "window_ns": (
                metric.last_ts_ns - metric.first_ts_ns
                if metric.last_ts_ns > metric.first_ts_ns
                else None
            ),
        }
        window_ns = expected_fields["window_ns"]
        expected_fields["rate_per_second"] = (
            (values[-1] - values[0]) * 1_000_000_000.0 / window_ns
            if metric.semantic in {_HEAP_ALLOCATION_COUNT, _HEAP_FREE_COUNT}
            and len(values) >= 2
            and isinstance(window_ns, int)
            else None
        )
        for field_name, expected in expected_fields.items():
            actual = row.get(field_name)
            if expected is None:
                recorder.equal(
                    "analysis_summary", f"{prefix}.{field_name}", None, actual
                )
            elif isinstance(expected, int) and field_name in {
                "sample_count",
                "first_ts_ns",
                "last_ts_ns",
                "window_ns",
            }:
                recorder.equal(
                    "analysis_summary", f"{prefix}.{field_name}", expected, actual
                )
            else:
                actual_number = _finite_number(actual, f"{prefix}.{field_name}")
                recorder.number(
                    "analysis_summary",
                    f"{prefix}.{field_name}",
                    float(expected),
                    actual_number,
                    absolute_tolerance=recorder.tolerance.continuous_absolute,
                    relative_tolerance=1e-12,
                )

    derived_rows = _as_list(
        resources.get("derived"), "derived resource summary", 100_000
    )
    derived_by_identity: dict[tuple[str, str], dict[str, Any]] = {}
    for index, raw in enumerate(derived_rows):
        row = _as_object(raw, f"derived resource summary {index}")
        semantic = row.get("semantic")
        if semantic not in _HEAP_DERIVED_SEMANTICS:
            continue
        subject = _validate_subject(row.get("subject"), semantic)
        identity = (semantic, _subject_key(subject))
        if identity in derived_by_identity:
            raise ResourceVerificationError(
                "analysis summary duplicates a derived identity"
            )
        derived_by_identity[identity] = row
    expected_derived = {
        identity: metric
        for identity, metric in facts.metrics.items()
        if metric.semantic in _HEAP_DERIVED_SEMANTICS
    }
    recorder.equal(
        "analysis_summary",
        "analysis_summary.derived_identity_set",
        sorted(expected_derived),
        sorted(derived_by_identity),
    )
    for identity in sorted(set(expected_derived) & set(derived_by_identity)):
        metric = expected_derived[identity]
        row = derived_by_identity[identity]
        prefix = f"analysis_summary.derived.{metric.semantic}:{metric.subject_key}"
        recorder.equal(
            "analysis_summary", f"{prefix}.unit", metric.unit, row.get("unit")
        )
        recorder.equal(
            "analysis_summary",
            f"{prefix}.source_counter_ids",
            list(metric.source_counter_ids),
            row.get("source_counter_ids"),
        )
        recorder.equal(
            "analysis_summary", f"{prefix}.quality", "exact", row.get("quality")
        )
        support = _as_object(row.get("support"), f"{prefix}.support")
        recorder.equal(
            "analysis_summary",
            f"{prefix}.support.level",
            "exact",
            support.get("support"),
        )
        recorder.equal(
            "analysis_summary", f"{prefix}.support.reasons", [], support.get("reasons")
        )
        recorder.number(
            "analysis_summary",
            f"{prefix}.value",
            metric.value,
            _finite_number(row.get("value"), f"{prefix}.value"),
            absolute_tolerance=recorder.tolerance.continuous_absolute,
            relative_tolerance=1e-12,
        )
        recorder.equal(
            "analysis_summary",
            f"{prefix}.first_ts_ns",
            metric.first_ts_ns,
            row.get("first_ts_ns"),
        )
        recorder.equal(
            "analysis_summary",
            f"{prefix}.last_ts_ns",
            metric.last_ts_ns,
            row.get("last_ts_ns"),
        )
        expected_window = (
            metric.last_ts_ns - metric.first_ts_ns
            if metric.semantic == _HEAP_RATE
            else None
        )
        recorder.equal(
            "analysis_summary",
            f"{prefix}.window_ns",
            expected_window,
            row.get("window_ns"),
        )


def _validate_reference(document: dict[str, Any]) -> None:
    _require_exact_fields(
        document,
        {
            "schema",
            "session_id",
            "resource_source_artifact_id",
            "metrics",
            "static_ram",
            "trace_buffer_health",
            "call_depth",
            "clock_alignment",
        },
        "driver reference",
    )
    if document["schema"] != RESOURCE_REFERENCE_SCHEMA:
        raise ResourceVerificationError("unsupported driver reference schema")
    _bounded_string(document["session_id"], "driver reference Session ID", 64)
    _bounded_string(
        document["resource_source_artifact_id"], "resource source artifact ID", 256
    )
    metrics = _as_list(
        document["metrics"], "driver reference metrics", MAX_REFERENCE_METRICS
    )
    if not metrics:
        raise ResourceVerificationError("driver reference metrics must not be empty")
    identities: set[tuple[str, str]] = set()
    for index, raw in enumerate(metrics):
        row = _as_object(raw, f"driver reference metric {index}")
        _require_exact_fields(
            row,
            {"semantic", "subject", "unit", "value", "first_ts_ns", "last_ts_ns"},
            f"driver reference metric {index}",
        )
        semantic = _bounded_string(row["semantic"], "reference semantic", 128)
        if semantic not in _REFERENCE_SEMANTICS:
            raise ResourceVerificationError(
                f"unsupported reference semantic {semantic!r}"
            )
        subject = _validate_subject(row["subject"], semantic)
        identity = (semantic, _subject_key(subject))
        if identity in identities:
            raise ResourceVerificationError(
                "driver reference repeats a metric identity"
            )
        identities.add(identity)
        unit = _bounded_string(row["unit"], "reference metric unit", 32)
        if unit != _SEMANTIC_UNITS[semantic]:
            raise ResourceVerificationError(f"reference unit is wrong for {semantic}")
        _resource_value(row["value"], unit, semantic)
        first_ts = _integer(row["first_ts_ns"], "reference first timestamp")
        last_ts = _integer(row["last_ts_ns"], "reference last timestamp")
        if last_ts < first_ts:
            raise ResourceVerificationError(
                "reference metric timestamp window is negative"
            )

    static_ram = _as_object(document["static_ram"], "reference static RAM")
    _require_exact_fields(
        static_ram,
        {"flavor", "config_sha256", "source_sha256", "total_bytes", "totals"},
        "reference static RAM",
    )
    if static_ram["flavor"] not in {"gnu-ld-map-v1", "elf-sections-v1"}:
        raise ResourceVerificationError("reference static RAM flavor is unsupported")
    _require_sha256(static_ram["config_sha256"], "reference static RAM config digest")
    _require_sha256(static_ram["source_sha256"], "reference static RAM source digest")
    _nonnegative_int(static_ram["total_bytes"], "reference static RAM total")
    totals = _static_totals(static_ram["totals"], "reference static RAM totals")
    if sum(totals.values()) != static_ram["total_bytes"]:
        raise ResourceVerificationError("reference static RAM totals do not add up")

    trace_health = _as_object(
        document["trace_buffer_health"], "reference trace-buffer health"
    )
    _require_exact_fields(trace_health, {"overflowed"}, "reference trace-buffer health")
    if not isinstance(trace_health["overflowed"], bool):
        raise ResourceVerificationError("reference trace overflow flag must be boolean")

    call_depth = _as_object(document["call_depth"], "reference call depth")
    _require_exact_fields(
        call_depth,
        {"max_depth", "context_id", "deepest_path"},
        "reference call depth",
    )
    max_depth = _nonnegative_int(
        call_depth["max_depth"], "reference maximum call depth"
    )
    if call_depth["context_id"] is not None:
        _bounded_string(call_depth["context_id"], "reference call-depth context", 256)
    deepest_path = _as_list(
        call_depth["deepest_path"], "reference deepest call path", 4096
    )
    for function_id in deepest_path:
        _bounded_string(function_id, "reference call-path function ID", 256)
    if len(deepest_path) != max_depth:
        raise ResourceVerificationError(
            "reference maximum call depth differs from deepest path length"
        )
    if max_depth > 0 and call_depth["context_id"] is None:
        raise ResourceVerificationError(
            "reference nonzero call depth requires a context ID"
        )

    alignment = _as_object(document["clock_alignment"], "reference clock alignment")
    _require_exact_fields(
        alignment, {"resource", "function", "anchors"}, "reference clock alignment"
    )
    for role in ("resource", "function"):
        clock = _as_object(alignment[role], f"reference {role} clock")
        _require_exact_fields(clock, {"id", "frequency_hz"}, f"reference {role} clock")
        _bounded_string(clock["id"], f"reference {role} clock ID", 256)
        _positive_int(clock["frequency_hz"], f"reference {role} clock frequency")
    anchors = _as_list(
        alignment["anchors"], "reference clock anchors", MAX_ALIGNMENT_ANCHORS
    )
    if not anchors:
        raise ResourceVerificationError("reference clock alignment needs an anchor")
    anchor_keys: set[tuple[str, int, str, int]] = set()
    for index, raw in enumerate(anchors):
        anchor = _as_object(raw, f"reference clock anchor {index}")
        _require_exact_fields(
            anchor,
            {
                "resource_source_id",
                "resource_source_seq",
                "function_source_id",
                "function_source_seq",
                "resource_ts_ns",
                "function_ts_ns",
                "delta_ns",
            },
            f"reference clock anchor {index}",
        )
        resource_source = _bounded_string(
            anchor["resource_source_id"], "anchor resource source ID", 256
        )
        resource_seq = _nonnegative_int(
            anchor["resource_source_seq"], "anchor resource source sequence"
        )
        function_source = _bounded_string(
            anchor["function_source_id"], "anchor function source ID", 256
        )
        function_seq = _nonnegative_int(
            anchor["function_source_seq"], "anchor function source sequence"
        )
        key = (resource_source, resource_seq, function_source, function_seq)
        if key in anchor_keys:
            raise ResourceVerificationError(
                "reference repeats a clock-alignment anchor"
            )
        anchor_keys.add(key)
        resource_ts = _integer(anchor["resource_ts_ns"], "anchor resource timestamp")
        function_ts = _integer(anchor["function_ts_ns"], "anchor function timestamp")
        delta = _integer(anchor["delta_ns"], "anchor timestamp delta")
        if resource_ts - function_ts != delta:
            raise ResourceVerificationError(
                "reference clock anchor delta is inconsistent"
            )


def _validate_v1_evidence_shape(document: dict[str, Any]) -> None:
    _require_exact_fields(
        document, {"schema", "source", "coverage", "captures"}, "HIL evidence v1"
    )
    if document["schema"] != HIL_EVIDENCE_V1_SCHEMA:
        raise ResourceVerificationError("HIL evidence does not declare v1")
    if document["source"] != "host-verified-session-artifacts":
        raise ResourceVerificationError("HIL evidence source is not host verified")
    coverage = _as_object(document["coverage"], "HIL evidence coverage")
    _require_exact_fields(
        coverage,
        {
            "boards",
            "mcu_families",
            "modes",
            "rtoses",
            "probes",
            "architecture_packages",
            "combinations",
        },
        "HIL evidence v1 coverage",
    )
    boards = _unique_strings(coverage["boards"], "coverage.boards", minimum=2)
    mcu_families = _unique_strings(
        coverage["mcu_families"], "coverage.mcu_families", minimum=2
    )
    modes = _unique_strings(coverage["modes"], "coverage.modes", minimum=2)
    rtoses = _unique_strings(coverage["rtoses"], "coverage.rtoses", minimum=1)
    probes = _unique_strings(coverage["probes"], "coverage.probes", minimum=1)
    architecture_packages = _unique_strings(
        coverage["architecture_packages"],
        "coverage.architecture_packages",
        minimum=1,
    )
    for label, rows in (
        ("coverage.boards", boards),
        ("coverage.mcu_families", mcu_families),
        ("coverage.modes", modes),
        ("coverage.rtoses", rtoses),
        ("coverage.probes", probes),
        ("coverage.architecture_packages", architecture_packages),
    ):
        if rows != sorted(rows):
            raise ResourceVerificationError(f"{label} must use canonical sorted order")

    combinations = _as_list(coverage["combinations"], "coverage.combinations", 100_000)
    declared_combinations: dict[tuple[str, str], int] = {}
    for index, raw in enumerate(combinations):
        combination = _as_object(raw, f"coverage.combinations[{index}]")
        _require_exact_fields(
            combination,
            {"board_id", "mode", "capture_count"},
            f"coverage.combinations[{index}]",
        )
        board_id = _bounded_string(combination["board_id"], "combination board ID", 256)
        mode = _bounded_string(combination["mode"], "combination mode", 256)
        count = _positive_int(combination["capture_count"], "combination count")
        key = (board_id, mode)
        if key in declared_combinations:
            raise ResourceVerificationError(
                f"coverage repeats combination {board_id}/{mode}"
            )
        declared_combinations[key] = count
    if list(declared_combinations) != sorted(declared_combinations):
        raise ResourceVerificationError(
            "coverage.combinations must use canonical board/mode order"
        )

    captures = _as_list(
        document["captures"], "HIL evidence captures", MAX_RESOURCE_OBSERVATIONS
    )
    if len(captures) < 40:
        raise ResourceVerificationError("HIL evidence requires at least 40 captures")
    capture_keys: set[tuple[str, str]] = set()
    board_identities: dict[str, tuple[Any, ...]] = {}
    actual_counts: dict[tuple[str, str], int] = {}
    actual_states: dict[tuple[str, str], set[str]] = {}
    actual_boards: set[str] = set()
    actual_mcu_families: set[str] = set()
    actual_modes: set[str] = set()
    actual_rtoses: set[str] = set()
    actual_probes: set[str] = set()
    actual_architectures: set[str] = set()
    for index, raw in enumerate(captures):
        capture = _validate_capture_evidence_row(raw, index)
        key = (capture["board_id"], capture["session_id"])
        if key in capture_keys:
            raise ResourceVerificationError(
                f"capture matrix repeats board/Session {key[0]}/{key[1]}"
            )
        capture_keys.add(key)
        board_identity = (
            capture["mcu_family"],
            capture["rtos"],
            capture["trace32"]["release"],
            capture["trace32"]["build"],
            capture["trace32"]["probe_id"],
            capture["trace32"]["architecture_package"],
            tuple(capture["trace32"]["license_features"]),
            capture["trace32"]["capability_evidence_sha256"],
            tuple(capture["trace_routing"]),
        )
        previous_identity = board_identities.setdefault(
            capture["board_id"], board_identity
        )
        if previous_identity != board_identity:
            raise ResourceVerificationError(
                f"capture identity changes within board {capture['board_id']!r}"
            )
        combination_key = (capture["board_id"], capture["mode"])
        actual_counts[combination_key] = actual_counts.get(combination_key, 0) + 1
        actual_states.setdefault(combination_key, set()).add(capture["initial_state"])
        actual_boards.add(capture["board_id"])
        actual_mcu_families.add(capture["mcu_family"])
        actual_modes.add(capture["mode"])
        if capture["rtos"] is not None:
            actual_rtoses.add(capture["rtos"])
        actual_probes.add(capture["trace32"]["probe_id"])
        actual_architectures.add(capture["trace32"]["architecture_package"])

    reconstructed = {
        "boards": sorted(actual_boards),
        "mcu_families": sorted(actual_mcu_families),
        "modes": sorted(actual_modes),
        "rtoses": sorted(actual_rtoses),
        "probes": sorted(actual_probes),
        "architecture_packages": sorted(actual_architectures),
    }
    declared = {
        "boards": boards,
        "mcu_families": mcu_families,
        "modes": modes,
        "rtoses": rtoses,
        "probes": probes,
        "architecture_packages": architecture_packages,
    }
    if reconstructed != declared:
        raise ResourceVerificationError(
            "declared HIL coverage differs from capture rows; "
            f"declared={declared}, reconstructed={reconstructed}"
        )
    if declared_combinations != actual_counts:
        raise ResourceVerificationError(
            "coverage combination counts differ from capture rows"
        )
    if any(count < 10 for count in actual_counts.values()):
        raise ResourceVerificationError(
            "every persisted coverage combination requires at least ten captures"
        )
    qualified_modes = [
        mode
        for mode in modes
        if all(
            actual_counts.get((board_id, mode), 0) >= 10
            and actual_states.get((board_id, mode), set()) == {"running", "halted"}
            for board_id in boards
        )
    ]
    if len(qualified_modes) < 2:
        raise ResourceVerificationError(
            "HIL evidence has fewer than two modes with complete per-board "
            "repetition and initial-state coverage"
        )


def _validate_capture_evidence_row(raw: object, index: int) -> dict[str, Any]:
    label = f"captures[{index}]"
    capture = _as_object(raw, label)
    _require_exact_fields(
        capture,
        {
            "board_id",
            "mcu_family",
            "rtos",
            "mode",
            "initial_state",
            "session_id",
            "trace32",
            "trace_routing",
            "manifest_sha256",
            "health_sha256",
        },
        label,
    )
    board_id = _bounded_string(capture["board_id"], f"{label}.board_id", 256)
    mcu_family = _bounded_string(capture["mcu_family"], f"{label}.mcu_family", 256)
    mode = _bounded_string(capture["mode"], f"{label}.mode", 256)
    rtos = capture["rtos"]
    if rtos is not None:
        rtos = _bounded_string(rtos, f"{label}.rtos", 256)
    initial_state = capture["initial_state"]
    if initial_state not in {"running", "halted"}:
        raise ResourceVerificationError(f"{label}.initial_state is invalid")
    session_id = _bounded_string(capture["session_id"], f"{label}.session_id", 64)
    if SESSION_ID_PATTERN.fullmatch(session_id) is None:
        raise ResourceVerificationError(f"{label}.session_id is not portable")
    trace32 = _as_object(capture["trace32"], f"{label}.trace32")
    _require_exact_fields(
        trace32,
        {
            "release",
            "build",
            "probe_id",
            "architecture_package",
            "license_features",
            "capability_evidence_sha256",
        },
        f"{label}.trace32",
    )
    release = _bounded_string(trace32["release"], f"{label}.trace32.release", 256)
    build = _positive_int(trace32["build"], f"{label}.trace32.build")
    probe_id = _bounded_string(trace32["probe_id"], f"{label}.trace32.probe_id", 256)
    architecture_package = _bounded_string(
        trace32["architecture_package"],
        f"{label}.trace32.architecture_package",
        256,
    )
    license_features = _unique_strings(
        trace32["license_features"], f"{label}.trace32.license_features", minimum=1
    )
    capability_digest = _require_sha256(
        trace32["capability_evidence_sha256"],
        f"{label}.trace32.capability_evidence_sha256",
    )
    trace_routing = _unique_strings(
        capture["trace_routing"], f"{label}.trace_routing", minimum=1
    )
    manifest_sha256 = _require_sha256(
        capture["manifest_sha256"], f"{label}.manifest_sha256"
    )
    health_sha256 = _require_sha256(capture["health_sha256"], f"{label}.health_sha256")
    return {
        "board_id": board_id,
        "mcu_family": mcu_family,
        "rtos": rtos,
        "mode": mode,
        "initial_state": initial_state,
        "session_id": session_id,
        "trace32": {
            "release": release,
            "build": build,
            "probe_id": probe_id,
            "architecture_package": architecture_package,
            "license_features": license_features,
            "capability_evidence_sha256": capability_digest,
        },
        "trace_routing": trace_routing,
        "manifest_sha256": manifest_sha256,
        "health_sha256": health_sha256,
    }


def _read_verified_json(
    session: VerifiedSession, artifact_id: str
) -> tuple[VerifiedArtifact, dict[str, Any]]:
    artifact = _revalidate_artifact(session, artifact_id)
    if artifact.media_type != "application/json":
        raise ResourceVerificationError(
            f"artifact {artifact_id!r} is not application/json"
        )
    if artifact.size_bytes > MAX_JSON_ARTIFACT_BYTES:
        raise ResourceVerificationError(
            f"artifact {artifact_id!r} exceeds {MAX_JSON_ARTIFACT_BYTES} bytes"
        )
    data = _read_bounded_file(
        artifact.path, MAX_JSON_ARTIFACT_BYTES, f"artifact {artifact_id!r}"
    )
    document = _strict_json_object(data, f"artifact {artifact_id!r}")
    return artifact, document


def _revalidate_artifact(
    session: VerifiedSession, artifact_id: str
) -> VerifiedArtifact:
    try:
        artifact = session.artifact(artifact_id)
    except RuntimeError as error:
        raise ResourceVerificationError(str(error)) from error
    try:
        metadata = artifact.path.lstat()
    except OSError as error:
        raise ResourceVerificationError(
            f"cannot inspect artifact {artifact_id!r}: {error}"
        ) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ResourceVerificationError(f"artifact {artifact_id!r} is not a plain file")
    if metadata.st_size != artifact.size_bytes:
        raise ResourceVerificationError(
            f"artifact {artifact_id!r} size changed after Session verification"
        )
    actual_sha256 = _sha256_file(artifact.path)
    if actual_sha256 != artifact.sha256:
        raise ResourceVerificationError(
            f"artifact {artifact_id!r} digest changed after Session verification"
        )
    return artifact


def _load_json_source(
    source: Path | bytes | bytearray | Mapping[str, Any], limit: int, label: str
) -> dict[str, Any]:
    if isinstance(source, Path):
        data = _read_bounded_file(source, limit, label)
        return _strict_json_object(data, label)
    if isinstance(source, (bytes, bytearray)):
        data = bytes(source)
        if len(data) > limit:
            raise ResourceVerificationError(f"{label} exceeds {limit} bytes")
        return _strict_json_object(data, label)
    if isinstance(source, Mapping):
        data = canonical_json_bytes(source)
        if len(data) > limit:
            raise ResourceVerificationError(f"{label} exceeds {limit} bytes")
        return _strict_json_object(data, label)
    raise TypeError(f"unsupported {label} source type {type(source).__name__}")


def _strict_json_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ResourceVerificationError(f"{label} is not UTF-8: {error}") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, DuplicateJsonKeyError, ValueError) as error:
        raise ResourceVerificationError(
            f"{label} is not strict JSON: {error}"
        ) from error
    if not isinstance(value, dict):
        raise ResourceVerificationError(f"{label} must be one JSON object")
    return value


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


def _read_bounded_file(path: Path, limit: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ResourceVerificationError(f"{label} is not a plain regular file")
        if metadata.st_size > limit:
            raise ResourceVerificationError(f"{label} exceeds {limit} bytes")
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
    except ResourceVerificationError:
        raise
    except OSError as error:
        raise ResourceVerificationError(f"cannot read {label}: {error}") from error
    if len(data) > limit:
        raise ResourceVerificationError(f"{label} exceeds {limit} bytes")
    return data


def _write_exclusive_json(
    document: Mapping[str, Any], output_path: Path, limit: int, label: str
) -> None:
    data = (
        json.dumps(
            document, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True
        )
        + "\n"
    ).encode("utf-8")
    if len(data) > limit:
        raise ResourceVerificationError(f"{label} exceeds {limit} bytes")
    path = output_path.resolve()
    if not path.parent.is_dir():
        raise ResourceVerificationError(f"{label} parent is not a directory")
    created = False
    try:
        with path.open("xb") as stream:
            created = True
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise ResourceVerificationError(f"{label} already exists: {path}") from error
    except OSError as error:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise ResourceVerificationError(f"cannot write {label}: {error}") from error


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _subject_key(subject: Mapping[str, Any]) -> str:
    return canonical_json_bytes(subject).decode("utf-8")


def _resource_value(value: object, unit: str, semantic: str) -> float:
    number = _nonnegative_number(value, f"value for {semantic}")
    if unit in {"bytes", "count"}:
        if not number.is_integer() or number > MAX_SAFE_INTEGER:
            raise ResourceVerificationError(
                f"{semantic} must be an integer no greater than 2^53"
            )
    if unit == "ratio" and number > 1:
        raise ResourceVerificationError(f"{semantic} ratio exceeds one")
    return number


def _static_totals(raw: object, label: str) -> dict[str, int]:
    totals = _as_object(raw, label)
    _require_exact_fields(totals, set(_STATIC_TOTAL_FIELDS), label)
    return {
        field_name: _nonnegative_int(totals[field_name], f"{label}.{field_name}")
        for field_name in _STATIC_TOTAL_FIELDS
    }


def _validate_check_counts(raw: object, label: str) -> dict[str, int]:
    counts = _as_object(raw, label)
    _require_exact_fields(counts, {"total", "passed", "failed"}, label)
    result = {
        field_name: _nonnegative_int(counts[field_name], f"{label}.{field_name}")
        for field_name in ("total", "passed", "failed")
    }
    if result["passed"] + result["failed"] != result["total"]:
        raise ResourceVerificationError(f"{label} counts do not add up")
    return result


def _require_exact_fields(
    document: Mapping[str, Any], expected: set[str], label: str
) -> None:
    actual = set(document)
    if actual != expected:
        raise ResourceVerificationError(
            f"{label} field set is invalid; missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def _as_object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ResourceVerificationError(f"{label} must be an object")
    return value


def _as_list(value: object, label: str, maximum: int) -> list[Any]:
    if not isinstance(value, list):
        raise ResourceVerificationError(f"{label} must be an array")
    if len(value) > maximum:
        raise ResourceVerificationError(f"{label} exceeds {maximum} entries")
    return value


def _bounded_string(value: object, label: str, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ResourceVerificationError(
            f"{label} must be a non-empty string no longer than {maximum} UTF-8 bytes"
        )
    return value


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ResourceVerificationError(f"{label} must be an integer")
    return value


def _nonnegative_int(value: object, label: str) -> int:
    result = _integer(value, label)
    if result < 0:
        raise ResourceVerificationError(f"{label} must be nonnegative")
    return result


def _positive_int(value: object, label: str) -> int:
    result = _integer(value, label)
    if result <= 0:
        raise ResourceVerificationError(f"{label} must be positive")
    return result


def _finite_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ResourceVerificationError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ResourceVerificationError(f"{label} must be finite")
    return result


def _nonnegative_number(value: object, label: str) -> float:
    result = _finite_number(value, label)
    if result < 0:
        raise ResourceVerificationError(f"{label} must be nonnegative")
    return result


def _require_sha256(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _SHA256_PATTERN_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ResourceVerificationError(f"{label} must be 64 lowercase hex characters")
    return value


def _unique_strings(
    value: object, label: str, *, minimum: int = 0, maximum: int = 100_000
) -> list[str]:
    rows = _as_list(value, label, maximum)
    result = [_bounded_string(row, label, 256) for row in rows]
    if len(result) < minimum:
        raise ResourceVerificationError(f"{label} requires at least {minimum} entries")
    if len(set(result)) != len(result):
        raise ResourceVerificationError(f"{label} contains duplicate entries")
    return result


def _truncate_utf8(value: str, maximum: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum:
        return value
    return encoded[:maximum].decode("utf-8", errors="ignore")
