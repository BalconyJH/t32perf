from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from harness import VerifiedArtifact, VerifiedSession
from resource_verification import (
    MAX_REFERENCE_BYTES,
    ResourceVerificationError,
    assert_v2_verification_coverage,
    build_hil_evidence_v2,
    canonical_json_bytes,
    canonical_sha256,
    load_hil_evidence,
    load_resource_reference,
    load_verification_receipt,
    validate_verification_receipt,
    verify_resource_reference,
    write_verification_receipt,
)
from target_adapter_recovery import TargetAdapterRecoveryEvidence
from verification_receipt import (
    MAX_RECEIPT_BYTES,
    TolerancePolicy,
    VerificationCheck,
    build_verification_receipt,
)

SEMANTIC_UNITS = {
    "heap.current_allocated_bytes": "bytes",
    "heap.peak_allocated_bytes": "bytes",
    "heap.allocation_count": "count",
    "heap.free_count": "count",
    "heap.largest_allocation_bytes": "bytes",
    "heap.free_bytes": "bytes",
    "heap.largest_free_block_bytes": "bytes",
    "stack.capacity_bytes": "bytes",
    "stack.current_used_bytes": "bytes",
    "stack.peak_used_bytes": "bytes",
    "trace_buffer.capacity_bytes": "bytes",
    "trace_buffer.current_used_bytes": "bytes",
    "trace_buffer.peak_used_bytes": "bytes",
}


def _json_bytes(document: object) -> bytes:
    return canonical_json_bytes(document) + b"\n"


def _artifact(
    session_path: Path,
    *,
    artifact_id: str,
    kind: str,
    relative_path: str,
    media_type: str,
    contents: bytes,
    inputs: tuple[str, ...] = (),
) -> VerifiedArtifact:
    path = session_path / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contents)
    return VerifiedArtifact(
        artifact_id=artifact_id,
        kind=kind,
        path=path,
        relative_path=relative_path,
        media_type=media_type,
        size_bytes=len(contents),
        sha256=hashlib.sha256(contents).hexdigest(),
        producer="fixture",
        input_artifact_ids=inputs,
        file_identity=None,
    )


def _replace_json_artifact(
    session: VerifiedSession, artifact_id: str, document: dict[str, Any]
) -> None:
    contents = _json_bytes(document)
    previous = session.artifacts[artifact_id]
    previous.path.write_bytes(contents)
    updated = replace(
        previous,
        size_bytes=len(contents),
        sha256=hashlib.sha256(contents).hexdigest(),
    )
    session.artifacts[artifact_id] = updated
    manifest_row = next(
        row for row in session.manifest["artifacts"] if row["id"] == artifact_id
    )
    manifest_row["size_bytes"] = updated.size_bytes
    manifest_row["sha256"] = updated.sha256
    (session.path / "manifest.json").write_bytes(_json_bytes(session.manifest))


def _subject_key(subject: dict[str, Any]) -> str:
    return canonical_json_bytes(subject).decode("utf-8")


def _counter_specifications() -> list[dict[str, Any]]:
    allocator = {"kind": "allocator", "allocator_id": "system"}
    task_stack = {
        "kind": "stack",
        "stack_id": "task-main-stack",
        "role": "task",
        "context_id": "task-main",
    }
    isr_stack = {
        "kind": "stack",
        "stack_id": "timer-isr-stack",
        "role": "isr",
        "context_id": "irq-timer",
    }
    msp_stack = {
        "kind": "stack",
        "stack_id": "msp-0",
        "role": "msp",
        "core_id": 0,
    }
    psp_stack = {
        "kind": "stack",
        "stack_id": "psp-0",
        "role": "psp",
        "core_id": 0,
    }
    trace_buffer = {"kind": "trace_buffer", "buffer_id": "etm", "core_id": 0}
    specifications = [
        ("heap-current", "heap.current_allocated_bytes", allocator, (100, 150)),
        ("heap-peak", "heap.peak_allocated_bytes", allocator, (120, 180)),
        ("heap-allocation-count", "heap.allocation_count", allocator, (10, 20)),
        ("heap-free-count", "heap.free_count", allocator, (5, 12)),
        (
            "heap-largest-allocation",
            "heap.largest_allocation_bytes",
            allocator,
            (64, 80),
        ),
        ("heap-free-bytes", "heap.free_bytes", allocator, (900, 850)),
        (
            "heap-largest-free",
            "heap.largest_free_block_bytes",
            allocator,
            (600, 500),
        ),
        ("task-capacity", "stack.capacity_bytes", task_stack, (4096, 4096)),
        ("task-current", "stack.current_used_bytes", task_stack, (500, 600)),
        ("task-peak", "stack.peak_used_bytes", task_stack, (700, 800)),
        ("isr-capacity", "stack.capacity_bytes", isr_stack, (2048, 2048)),
        ("isr-current", "stack.current_used_bytes", isr_stack, (100, 120)),
        ("isr-peak", "stack.peak_used_bytes", isr_stack, (200, 240)),
        ("msp-capacity", "stack.capacity_bytes", msp_stack, (1024, 1024)),
        ("msp-current", "stack.current_used_bytes", msp_stack, (200, 220)),
        ("msp-peak", "stack.peak_used_bytes", msp_stack, (300, 350)),
        ("psp-capacity", "stack.capacity_bytes", psp_stack, (3072, 3072)),
        ("psp-current", "stack.current_used_bytes", psp_stack, (400, 450)),
        ("psp-peak", "stack.peak_used_bytes", psp_stack, (500, 550)),
        (
            "trace-capacity",
            "trace_buffer.capacity_bytes",
            trace_buffer,
            (8192, 8192),
        ),
        (
            "trace-current",
            "trace_buffer.current_used_bytes",
            trace_buffer,
            (1000, 1200),
        ),
        (
            "trace-peak",
            "trace_buffer.peak_used_bytes",
            trace_buffer,
            (1500, 1800),
        ),
    ]
    return [
        {
            "counter_id": counter_id,
            "semantic": semantic,
            "subject": subject,
            "unit": SEMANTIC_UNITS[semantic],
            "values": values,
        }
        for counter_id, semantic, subject, values in specifications
    ]


def _counter_summary(specification: dict[str, Any]) -> dict[str, Any]:
    first, latest = specification["values"]
    semantic = specification["semantic"]
    window_ns = 100
    rate = None
    if semantic in {"heap.allocation_count", "heap.free_count"}:
        rate = (latest - first) * 1_000_000_000.0 / window_ns
    return {
        "counter_id": specification["counter_id"],
        "name": specification["counter_id"],
        "unit": specification["unit"],
        "semantic": semantic,
        "subject": specification["subject"],
        "class": (
            "heap"
            if semantic.startswith("heap.")
            else "stack"
            if semantic.startswith("stack.")
            else "trace_buffer"
        ),
        "sample_count": 2,
        "first_ts_ns": 100,
        "last_ts_ns": 200,
        "first": first,
        "latest": latest,
        "min": min(first, latest),
        "max": max(first, latest),
        "mean": (first + latest) / 2,
        "delta": latest - first,
        "window_ns": window_ns,
        "rate_per_second": rate,
        "quality": "exact",
        "support": {"support": "exact", "reasons": []},
    }


def _fixture_session(
    tmp_path: Path, *, session_id: str = "resource-session", board_id: str = "board-a"
) -> tuple[VerifiedSession, dict[str, Any]]:
    session_path = (tmp_path / session_id).resolve()
    session_path.mkdir(parents=True)
    specifications = _counter_specifications()

    observation_rows: list[dict[str, Any]] = [
        {
            "schema": "t32perf.observation/v1",
            "session_id": session_id,
            "encoding": "ndjson",
            "time_unit": "ns",
            "time_origin": "session_relative",
        }
    ]
    observation_rows.extend(
        {
            "type": "DefineCounter",
            "id": specification["counter_id"],
            "name": specification["counter_id"],
            "unit": specification["unit"],
            "semantic": specification["semantic"],
            "subject": specification["subject"],
        }
        for specification in specifications
    )
    observation_rows.append(
        {
            "source_id": "functions",
            "source_seq": 0,
            "quality": "exact",
            "type": "FunctionEnter",
            "ts_ns": 100,
            "core_id": 0,
            "context_id": "task-main",
            "function_id": "workload",
        }
    )
    resource_seq = 0
    for sample_index, timestamp in enumerate((100, 200)):
        for specification in specifications:
            observation_rows.append(
                {
                    "source_id": "resources",
                    "source_seq": resource_seq,
                    "quality": "exact",
                    "type": "Counter",
                    "ts_ns": timestamp,
                    "counter_id": specification["counter_id"],
                    "value": specification["values"][sample_index],
                }
            )
            resource_seq += 1
    observations = (
        b"\n".join(canonical_json_bytes(row) for row in observation_rows) + b"\n"
    )

    line_limits = {"max_line_bytes": 1_048_576, "max_records": 1_000_000}
    clock = {
        "domain_id": "target-clock",
        "frequency_hz": {"numerator": 100_000_000, "denominator": 1},
        "wrap": None,
    }
    normalization_config = _json_bytes(
        {
            "schema": "t32perf.normalize-config/v1",
            "mode": "multi_source",
            "sources": [
                {
                    "input_artifact_id": "raw-resources",
                    "clock_domain": "target-clock",
                    "order": "reject_ambiguous_ties",
                    "source": {
                        "adapter": "explicit_csv_v1",
                        "source_id": "resources",
                        "columns": [
                            {"field": "timestamp_ticks", "column": "tick"},
                            {"field": "source_sequence", "column": "sequence"},
                            {"field": "event_type", "column": "event"},
                        ],
                        "ignored_columns": [],
                        "clock": clock,
                        "origin": {"mode": "first_record", "session_ns": 0},
                        "quality": "exact",
                        "limits": line_limits,
                    },
                },
                {
                    "input_artifact_id": "raw-functions",
                    "clock_domain": "target-clock",
                    "order": "reject_ambiguous_ties",
                    "source": {
                        "adapter": "explicit_csv_v1",
                        "source_id": "functions",
                        "columns": [
                            {"field": "timestamp_ticks", "column": "tick"},
                            {"field": "source_sequence", "column": "sequence"},
                            {"field": "event_type", "column": "event"},
                        ],
                        "ignored_columns": [],
                        "clock": clock,
                        "origin": {"mode": "first_record", "session_ns": 0},
                        "quality": "exact",
                        "limits": line_limits,
                    },
                },
            ],
            "output_limits": line_limits,
        }
    )

    static_config = _json_bytes(
        {
            "schema": "t32perf.static-ram-config/v1",
            "flavor": "gnu-ld-map-v1",
            "additional_sections": [
                {"name": ".dma", "kind": "dma"},
                {"name": ".rtos", "kind": "rtos"},
                {"name": ".custom", "kind": "custom"},
            ],
        }
    )
    static_source = (
        b".data 0x20000000 10\n"
        b".bss 0x20000010 20\n"
        b".noinit 0x20000030 30\n"
        b".dma 0x20000050 40\n"
        b".rtos 0x20000080 50\n"
        b".custom 0x200000c0 60\n"
    )
    static_totals = {
        "data_bytes": 10,
        "bss_bytes": 20,
        "noinit_bytes": 30,
        "dma_bytes": 40,
        "rtos_bytes": 50,
        "custom_bytes": 60,
    }
    static_sections = [
        {
            "name": f".{kind}",
            "address": 0x20000000 + index * 0x20,
            "size_bytes": static_totals[f"{kind}_bytes"],
            "kind": kind,
            "source_line": index + 1,
        }
        for index, kind in enumerate(("data", "bss", "noinit", "dma", "rtos", "custom"))
    ]
    static_report = _json_bytes(
        {
            "schema": "t32perf.static-ram/gnu-ld-map-v1",
            "sections": static_sections,
            "total_bytes": sum(static_totals.values()),
            "totals": static_totals,
        }
    )
    health = _json_bytes(
        {
            "schema": "t32perf.health/v1",
            "session_id": session_id,
            "verdict": "VALID",
            "policy_version": "t32perf.health-policy/v1",
            "observations": [],
            "issues": [],
            "metric_support": {},
        }
    )
    hotspots = _json_bytes(
        {
            "schema": "t32perf.hotspots/v1",
            "session_id": session_id,
            "quality": "exact",
            "functions": [],
            "sampling": [],
        }
    )

    allocator = specifications[0]["subject"]
    allocation_rate = (20 - 10) * 1_000_000_000.0 / 100
    fragmentation = 1.0 - 500 / 850
    derived = [
        {
            "semantic": "heap.allocation_rate_per_second",
            "subject": allocator,
            "unit": "1/s",
            "value": allocation_rate,
            "source_counter_ids": ["heap-allocation-count"],
            "first_ts_ns": 100,
            "last_ts_ns": 200,
            "window_ns": 100,
            "quality": "exact",
            "support": {"support": "exact", "reasons": []},
        },
        {
            "semantic": "heap.external_fragmentation_ratio",
            "subject": allocator,
            "unit": "ratio",
            "value": fragmentation,
            "source_counter_ids": ["heap-free-bytes", "heap-largest-free"],
            "first_ts_ns": 200,
            "last_ts_ns": 200,
            "window_ns": None,
            "quality": "exact",
            "support": {"support": "exact", "reasons": []},
        },
    ]

    artifacts: dict[str, VerifiedArtifact] = {}
    for artifact in (
        _artifact(
            session_path,
            artifact_id="raw-resources",
            kind="raw_trace",
            relative_path="capture/raw/resources.csv",
            media_type="text/csv",
            contents=b"resource fixture\n",
        ),
        _artifact(
            session_path,
            artifact_id="raw-functions",
            kind="raw_trace",
            relative_path="capture/raw/functions.csv",
            media_type="text/csv",
            contents=b"function fixture\n",
        ),
        _artifact(
            session_path,
            artifact_id="normalize-config",
            kind="normalization_config",
            relative_path="capture/normalize-config.json",
            media_type="application/json",
            contents=normalization_config,
        ),
        _artifact(
            session_path,
            artifact_id="observations",
            kind="observations",
            relative_path="normalized/observations.ndjson",
            media_type="application/x-ndjson",
            contents=observations,
            inputs=("raw-resources", "raw-functions", "normalize-config"),
        ),
        _artifact(
            session_path,
            artifact_id="health",
            kind="health",
            relative_path="analysis/health.json",
            media_type="application/json",
            contents=health,
            inputs=("observations",),
        ),
        _artifact(
            session_path,
            artifact_id="hotspots",
            kind="hotspots",
            relative_path="analysis/hotspots.json",
            media_type="application/json",
            contents=hotspots,
            inputs=("observations",),
        ),
        _artifact(
            session_path,
            artifact_id="static-config",
            kind="static_ram_config",
            relative_path="inputs/static-ram-config.json",
            media_type="application/json",
            contents=static_config,
        ),
        _artifact(
            session_path,
            artifact_id="linker-map",
            kind="linker_map",
            relative_path="inputs/firmware.map",
            media_type="text/plain",
            contents=static_source,
        ),
        _artifact(
            session_path,
            artifact_id="static-ram",
            kind="static_ram:gnu-ld-map-v1",
            relative_path="analysis/static-ram.json",
            media_type="application/json",
            contents=static_report,
            inputs=("linker-map", "static-config"),
        ),
    ):
        artifacts[artifact.artifact_id] = artifact

    summary = _json_bytes(
        {
            "schema": "t32perf.analysis-summary/v1",
            "session_id": session_id,
            "health_verdict": "VALID",
            "metric_support": {
                "resource_counters": {"support": "exact", "reasons": []},
                "function_timeline": {"support": "exact", "reasons": []},
                "call_count": {"support": "exact", "reasons": []},
                "elapsed": {"support": "exact", "reasons": []},
                "active": {"support": "exact", "reasons": []},
                "self": {"support": "exact", "reasons": []},
            },
            "quantitative": {
                "call_depth": {
                    "max_depth": 3,
                    "context_id": "task-main",
                    "deepest_path": ["root", "workload", "leaf"],
                },
                "resources": {
                    "counters": [
                        _counter_summary(specification)
                        for specification in specifications
                    ],
                    "derived": derived,
                },
                "static_ram": {
                    "artifact_id": "static-ram",
                    "source_artifact_id": "linker-map",
                    "flavor": "gnu-ld-map-v1",
                    "config": {
                        "artifact_id": "static-config",
                        "sha256": artifacts["static-config"].sha256,
                    },
                    "total_bytes": sum(static_totals.values()),
                    "totals": static_totals,
                    "support": {
                        "support": "inferred",
                        "reasons": ["build_identity_unbound"],
                    },
                },
            },
        }
    )
    summary_artifact = _artifact(
        session_path,
        artifact_id="analysis-summary",
        kind="analysis_summary",
        relative_path="analysis/summary.json",
        media_type="application/json",
        contents=summary,
        inputs=("observations", "health", "static-ram"),
    )
    artifacts[summary_artifact.artifact_id] = summary_artifact

    manifest = {
        "schema": "t32perf.manifest/v1",
        "session_id": session_id,
        "capture": {
            "mode": "etm",
            "capabilities": {
                "counters": {"support": "exact", "reasons": []},
                "function_events": {"support": "exact", "reasons": []},
            },
            "target": {
                "board": board_id,
            },
        },
        "clocks": [
            {
                "id": "target-clock",
                "frequency_hz": 100_000_000,
                "source": "trace32-target-clock",
            },
        ],
        "artifacts": [
            {
                "id": artifact.artifact_id,
                "kind": artifact.kind,
                "relative_path": artifact.relative_path,
                "media_type": artifact.media_type,
                "size_bytes": artifact.size_bytes,
                "sha256": artifact.sha256,
                "producer": artifact.producer,
                "input_artifact_ids": list(artifact.input_artifact_ids),
            }
            for artifact in artifacts.values()
        ],
    }
    (session_path / "manifest.json").write_bytes(_json_bytes(manifest))
    session = VerifiedSession(
        session_id=session_id,
        path=session_path,
        manifest=manifest,
        artifacts=artifacts,
        cli_validation={"deep": True},
    )

    reference_metrics = [
        {
            "semantic": specification["semantic"],
            "subject": specification["subject"],
            "unit": specification["unit"],
            "value": specification["values"][-1],
            "first_ts_ns": 100,
            "last_ts_ns": 200,
        }
        for specification in specifications
    ]
    reference_metrics.extend(
        [
            {
                "semantic": "heap.allocation_rate_per_second",
                "subject": allocator,
                "unit": "1/s",
                "value": allocation_rate,
                "first_ts_ns": 100,
                "last_ts_ns": 200,
            },
            {
                "semantic": "heap.external_fragmentation_ratio",
                "subject": allocator,
                "unit": "ratio",
                "value": fragmentation,
                "first_ts_ns": 200,
                "last_ts_ns": 200,
            },
        ]
    )
    reference_metrics.sort(
        key=lambda row: (row["semantic"], _subject_key(row["subject"]))
    )
    reference = {
        "schema": "t32perf.hil-resource-reference/v1",
        "session_id": session_id,
        "resource_source_artifact_id": "observations",
        "metrics": reference_metrics,
        "static_ram": {
            "flavor": "gnu-ld-map-v1",
            "config_sha256": artifacts["static-config"].sha256,
            "source_sha256": artifacts["linker-map"].sha256,
            "total_bytes": sum(static_totals.values()),
            "totals": static_totals,
        },
        "trace_buffer_health": {"overflowed": False},
        "call_depth": {
            "max_depth": 3,
            "context_id": "task-main",
            "deepest_path": ["root", "workload", "leaf"],
        },
        "clock_alignment": {
            "resource": {"id": "target-clock", "frequency_hz": 100_000_000},
            "function": {"id": "target-clock", "frequency_hz": 100_000_000},
            "anchors": [
                {
                    "resource_source_id": "resources",
                    "resource_source_seq": 0,
                    "function_source_id": "functions",
                    "function_source_seq": 0,
                    "resource_ts_ns": 100,
                    "function_ts_ns": 100,
                    "delta_ns": 0,
                }
            ],
        },
    }
    return session, reference


def _receipt_schema() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "schemas/hil-verification-receipt.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _evidence_v2_schema() -> dict[str, Any]:
    path = Path(__file__).parents[1] / "schemas/hil-evidence-v2.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize_schema() -> dict[str, Any]:
    path = Path(__file__).parents[2] / "schemas/v1/normalize-config.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _category_counts(receipt: dict[str, Any], category: str) -> dict[str, int]:
    return next(
        row["counts"]
        for row in receipt["check_categories"]
        if row["category"] == category
    )


def _v1_capture_matrix() -> dict[str, Any]:
    captures: list[dict[str, Any]] = []
    combinations: list[dict[str, Any]] = []
    for board_index, board_id in enumerate(("board-a", "board-b")):
        for mode in ("etm", "itm"):
            combinations.append(
                {"board_id": board_id, "mode": mode, "capture_count": 10}
            )
            for state in ("running", "halted"):
                for repetition in range(5):
                    session_id = f"{board_id}-{mode}-{state}-{repetition}"
                    if mode == "etm" and state == "running" and repetition == 0:
                        session_id = (
                            "resource-session"
                            if board_id == "board-a"
                            else "resource-session-b"
                        )
                    captures.append(
                        {
                            "board_id": board_id,
                            "mcu_family": f"mcu-{board_index}",
                            "rtos": "FreeRTOS",
                            "mode": mode,
                            "initial_state": state,
                            "session_id": session_id,
                            "trace32": {
                                "release": "R.2026.02",
                                "build": 183242,
                                "probe_id": f"probe-{board_index}",
                                "architecture_package": f"arm-{board_index}",
                                "license_features": ["trace"],
                                "capability_evidence_sha256": "a" * 64,
                            },
                            "trace_routing": ["ETM->TPIU"],
                            "manifest_sha256": "b" * 64,
                            "health_sha256": "c" * 64,
                        }
                    )
    return {
        "schema": "t32perf.hil-evidence/v1",
        "source": "host-verified-session-artifacts",
        "coverage": {
            "boards": ["board-a", "board-b"],
            "mcu_families": ["mcu-0", "mcu-1"],
            "modes": ["etm", "itm"],
            "rtoses": ["FreeRTOS"],
            "probes": ["probe-0", "probe-1"],
            "architecture_packages": ["arm-0", "arm-1"],
            "combinations": combinations,
        },
        "captures": captures,
    }


def _receipt_binding_map(receipt: dict[str, Any]) -> dict[str, tuple[str | None, str]]:
    return {
        row["role"]: (row["artifact_id"], row["sha256"])
        for row in receipt["artifact_bindings"]
    }


def _complete_v2_receipts(
    receipt_a: dict[str, Any], receipt_b: dict[str, Any]
) -> list[dict[str, Any]]:
    receipts: list[dict[str, Any]] = []
    fault_scenarios = (
        "trace_overflow",
        "flow_error",
        "sampling_buffer_full",
        "elf_mismatch",
        "trace32_disconnect_recovery",
        "driver_disconnect_recovery",
        "cmm_abort_recovery",
    )
    for resource_receipt in (receipt_a, receipt_b):
        receipts.append(resource_receipt)
        board_id = resource_receipt["board_id"]
        session_id = resource_receipt["session_id"]
        resource_bindings = _receipt_binding_map(resource_receipt)
        native_bindings = {
            role: resource_bindings[role]
            for role in (
                "manifest",
                "health",
                "observations",
                "analysis_summary",
                "hotspots",
            )
        }
        native_bindings["derived"] = ("derived", "d" * 64)
        native_checks = [
            VerificationCheck(
                category=category, name=f"{category}.complete", passed=True
            )
            for category in (
                "artifact_binding",
                "function",
                "task",
                "isr",
                "context_switch",
                "interrupt",
                "function_activation",
            )
        ]
        receipts.append(
            build_verification_receipt(
                kind="native_timeline",
                board_id=board_id,
                session_id=session_id,
                driver_reference_sha256=hashlib.sha256(
                    f"{board_id}:native".encode()
                ).hexdigest(),
                tolerance=TolerancePolicy(timestamp_absolute_ns=10.0),
                artifact_bindings=native_bindings,
                checks=native_checks,
            )
        )
        for scenario in fault_scenarios:
            recovery_document = None
            recovery_sha256 = None
            if scenario.endswith("_recovery"):
                failed_operation, failure_kind = {
                    "trace32_disconnect_recovery": (
                        "perf_stop",
                        "trace32_disconnect",
                    ),
                    "driver_disconnect_recovery": (
                        "perf_export",
                        "driver_disconnect",
                    ),
                    "cmm_abort_recovery": ("perf_start", "cmm_abort"),
                }[scenario]
                recovery_document = TargetAdapterRecoveryEvidence(
                    profile_sha256="1" * 64,
                    binding_sha256="2" * 64,
                    failed_operation=failed_operation,
                    failure_kind=failure_kind,
                    initial_target_state="running",
                    restored_target_state="running",
                    adapter_state_restored=True,
                    upstream_abort_confirmed=True,
                    upstream_abort_receipt_sha256="3" * 64,
                    files_deleted=False,
                    new_session_required=True,
                ).to_document()
                recovery_sha256 = canonical_sha256(recovery_document)
            fault_checks = [
                VerificationCheck(
                    category=category,
                    name=f"{scenario}.{category}",
                    passed=True,
                )
                for category in (
                    "artifact_binding",
                    "health",
                    "fault_publication",
                    "recovery",
                )
            ]
            receipts.append(
                build_verification_receipt(
                    kind="fault_injection",
                    scenario=scenario,
                    board_id=board_id,
                    session_id=f"{board_id}-{scenario}",
                    driver_reference_sha256=hashlib.sha256(
                        f"{board_id}:{scenario}".encode()
                    ).hexdigest(),
                    tolerance=TolerancePolicy(timestamp_absolute_ns=10.0),
                    artifact_bindings={
                        "manifest": resource_bindings["manifest"],
                        "health": resource_bindings["health"],
                    },
                    checks=fault_checks,
                    recovery_evidence=recovery_document,
                    recovery_evidence_sha256=recovery_sha256,
                    fault_adapter_binding=(
                        {
                            "scenario": "sampling_buffer_full",
                            "fault_scenarios_sha256": "4" * 64,
                            "adapter_id": "fixture-adapter",
                            "profile_sha256": "5" * 64,
                            "profile_file_sha256": "6" * 64,
                            "bundle_sha256": "7" * 64,
                        }
                        if scenario == "sampling_buffer_full"
                        else None
                    ),
                )
            )
    return receipts


def _bind_receipts_to_capture_rows(
    matrix: dict[str, Any], receipts: list[dict[str, Any]]
) -> None:
    healthy = {
        (receipt["board_id"], receipt["session_id"]): _receipt_binding_map(receipt)
        for receipt in receipts
        if receipt["kind"] in {"resources", "native_timeline"}
    }
    for capture in matrix["captures"]:
        bindings = healthy.get((capture["board_id"], capture["session_id"]))
        if bindings is None:
            continue
        capture["manifest_sha256"] = bindings["manifest"][1]
        capture["health_sha256"] = bindings["health"][1]


def test_resource_verification_success_binds_exact_artifacts_and_schemas(
    tmp_path: Path,
) -> None:
    session, reference = _fixture_session(tmp_path)
    receipt = verify_resource_reference(session, reference, tick_ns=10.0)

    assert receipt["verdict"] == "PASS"
    assert receipt["kind"] == "resources"
    assert receipt["scenario"] is None
    assert receipt["failure_count"] == 0
    assert receipt["checks"]["total"] > 100
    assert receipt["checks"]["passed"] == receipt["checks"]["total"]
    assert receipt["driver_reference_sha256"] == canonical_sha256(reference)
    bindings = {row["role"]: row for row in receipt["artifact_bindings"]}
    assert set(bindings) == {
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
    assert bindings["manifest"]["artifact_id"] is None
    assert bindings["resource_source"] == {
        "role": "resource_source",
        "artifact_id": "observations",
        "sha256": session.artifacts["observations"].sha256,
    }
    assert (
        bindings["static_ram_source"]["sha256"]
        == session.artifacts["linker-map"].sha256
    )

    schema = _receipt_schema()
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(receipt)
    normalize_schema = _normalize_schema()
    Draft202012Validator.check_schema(normalize_schema)
    normalize_document = json.loads(
        session.artifacts["normalize-config"].path.read_text(encoding="utf-8")
    )
    Draft202012Validator(normalize_schema).validate(normalize_document)


def test_reference_rejects_missing_fields_duplicates_and_size_bound(
    tmp_path: Path,
) -> None:
    _, reference = _fixture_session(tmp_path)
    missing = copy.deepcopy(reference)
    del missing["static_ram"]
    with pytest.raises(ResourceVerificationError, match="missing=.*static_ram"):
        load_resource_reference(missing)

    duplicate = canonical_json_bytes(reference).replace(
        b'"schema":', b'"schema":"duplicate","schema":', 1
    )
    with pytest.raises(ResourceVerificationError, match="duplicate JSON key"):
        load_resource_reference(duplicate)

    oversized = b'{"schema":"' + b"x" * MAX_REFERENCE_BYTES + b'"}'
    with pytest.raises(ResourceVerificationError, match="exceeds"):
        load_resource_reference(oversized)


def test_resource_verification_rejects_wrong_session_and_artifact_tampering(
    tmp_path: Path,
) -> None:
    session, reference = _fixture_session(tmp_path)
    wrong_session = copy.deepcopy(reference)
    wrong_session["session_id"] = "another-session"
    with pytest.raises(ResourceVerificationError, match="different Session"):
        verify_resource_reference(session, wrong_session, tick_ns=10.0)

    health_path = session.artifacts["health"].path
    health_path.write_bytes(health_path.read_bytes().replace(b'"VALID"', b'"VXLID"'))
    with pytest.raises(ResourceVerificationError, match="digest changed"):
        verify_resource_reference(session, reference, tick_ns=10.0)


@pytest.mark.parametrize("mutation", ["subject", "semantic"])
def test_wrong_subject_or_semantic_produces_fail_receipt(
    tmp_path: Path, mutation: str
) -> None:
    session, reference = _fixture_session(tmp_path)
    changed = copy.deepcopy(reference)
    if mutation == "subject":
        row = next(
            row
            for row in changed["metrics"]
            if row["semantic"] == "heap.current_allocated_bytes"
        )
        row["subject"]["allocator_id"] = "wrong-allocator"
    else:
        current = next(
            row
            for row in changed["metrics"]
            if row["semantic"] == "heap.current_allocated_bytes"
        )
        peak = next(
            row
            for row in changed["metrics"]
            if row["semantic"] == "heap.peak_allocated_bytes"
        )
        current["semantic"], peak["semantic"] = peak["semantic"], current["semantic"]

    receipt = verify_resource_reference(session, changed, tick_ns=10.0)
    assert receipt["verdict"] == "FAIL"
    assert receipt["failure_count"] > 0
    assert _category_counts(receipt, "allocator")["failed"] > 0


def test_continuous_metric_over_tolerance_and_static_digest_mismatch_fail(
    tmp_path: Path,
) -> None:
    session, reference = _fixture_session(tmp_path)
    over_tolerance = copy.deepcopy(reference)
    fragmentation = next(
        row
        for row in over_tolerance["metrics"]
        if row["semantic"] == "heap.external_fragmentation_ratio"
    )
    fragmentation["value"] += 0.01
    receipt = verify_resource_reference(session, over_tolerance, tick_ns=10.0)
    assert receipt["verdict"] == "FAIL"
    assert receipt["max_error"]["absolute"] >= 0.01

    wrong_digest = copy.deepcopy(reference)
    wrong_digest["static_ram"]["source_sha256"] = "0" * 64
    receipt = verify_resource_reference(session, wrong_digest, tick_ns=10.0)
    assert receipt["verdict"] == "FAIL"
    assert _category_counts(receipt, "static_ram")["failed"] == 1


def test_clock_domain_and_timestamp_alignment_are_verified(tmp_path: Path) -> None:
    session, reference = _fixture_session(tmp_path)
    wrong_clock = copy.deepcopy(reference)
    wrong_clock["clock_alignment"]["resource"]["frequency_hz"] += 1
    receipt = verify_resource_reference(session, wrong_clock, tick_ns=10.0)
    assert receipt["verdict"] == "FAIL"
    assert _category_counts(receipt, "clock_alignment")["failed"] == 1

    aligned_within_tick = copy.deepcopy(reference)
    anchor = aligned_within_tick["clock_alignment"]["anchors"][0]
    anchor["resource_ts_ns"] += 5
    anchor["delta_ns"] += 5
    receipt = verify_resource_reference(session, aligned_within_tick, tick_ns=10.0)
    assert receipt["verdict"] == "PASS"

    outside_tick = copy.deepcopy(reference)
    anchor = outside_tick["clock_alignment"]["anchors"][0]
    anchor["resource_ts_ns"] += 11
    anchor["delta_ns"] += 11
    receipt = verify_resource_reference(session, outside_tick, tick_ns=10.0)
    assert receipt["verdict"] == "FAIL"


def test_normalization_config_provenance_is_required_and_domains_are_typed(
    tmp_path: Path,
) -> None:
    missing_session, reference = _fixture_session(tmp_path / "missing")
    observations = missing_session.artifacts["observations"]
    missing_session.artifacts["observations"] = replace(
        observations,
        input_artifact_ids=("raw-resources", "raw-functions"),
    )
    manifest_row = next(
        row
        for row in missing_session.manifest["artifacts"]
        if row["id"] == "observations"
    )
    manifest_row["input_artifact_ids"] = ["raw-resources", "raw-functions"]
    (missing_session.path / "manifest.json").write_bytes(
        _json_bytes(missing_session.manifest)
    )
    with pytest.raises(
        ResourceVerificationError, match="exactly one normalization_config"
    ):
        verify_resource_reference(missing_session, reference, tick_ns=10.0)

    wrong_session, reference = _fixture_session(tmp_path / "wrong")
    config_path = wrong_session.artifacts["normalize-config"].path
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["sources"][1]["clock_domain"] = "other-clock"
    config["sources"][1]["source"]["clock"]["domain_id"] = "other-clock"
    _replace_json_artifact(wrong_session, "normalize-config", config)
    with pytest.raises(ResourceVerificationError, match="different clock domains"):
        verify_resource_reference(wrong_session, reference, tick_ns=10.0)


@pytest.mark.parametrize("field", ["max_depth", "context_id", "deepest_path"])
def test_call_depth_is_independent_from_stack_watermarks(
    tmp_path: Path, field: str
) -> None:
    session, reference = _fixture_session(tmp_path)
    changed = copy.deepcopy(reference)
    if field == "max_depth":
        changed["call_depth"]["max_depth"] = 2
        changed["call_depth"]["deepest_path"] = ["root", "workload"]
    elif field == "context_id":
        changed["call_depth"]["context_id"] = "wrong-task"
    else:
        changed["call_depth"]["deepest_path"][-1] = "wrong-leaf"
    receipt = verify_resource_reference(session, changed, tick_ns=10.0)
    assert receipt["verdict"] == "FAIL"
    assert _category_counts(receipt, "call_depth")["failed"] > 0
    assert _category_counts(receipt, "stack")["failed"] == 0


def test_call_depth_requires_exact_function_and_counter_evidence(
    tmp_path: Path,
) -> None:
    session, reference = _fixture_session(tmp_path / "summary")
    summary_path = session.artifacts["analysis-summary"].path
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["metric_support"]["function_timeline"] = {
        "support": "inferred",
        "reasons": ["incomplete_program_flow"],
    }
    _replace_json_artifact(session, "analysis-summary", summary)
    receipt = verify_resource_reference(session, reference, tick_ns=10.0)
    assert receipt["verdict"] == "FAIL"
    assert _category_counts(receipt, "analysis_summary")["failed"] > 0

    session, reference = _fixture_session(tmp_path / "manifest")
    session.manifest["capture"]["capabilities"]["function_events"] = {
        "support": "statistical",
        "reasons": ["sampling_only"],
    }
    (session.path / "manifest.json").write_bytes(_json_bytes(session.manifest))
    with pytest.raises(ResourceVerificationError, match="exact function_events"):
        verify_resource_reference(session, reference, tick_ns=10.0)


def test_receipt_reader_is_strict_bounded_and_writer_is_exclusive(
    tmp_path: Path,
) -> None:
    session, reference = _fixture_session(tmp_path)
    receipt = verify_resource_reference(session, reference, tick_ns=10.0)
    encoded = canonical_json_bytes(receipt)
    duplicate = encoded.replace(b'"schema":', b'"schema":"duplicate","schema":', 1)
    with pytest.raises(ResourceVerificationError, match="duplicate JSON key"):
        load_verification_receipt(duplicate)
    with pytest.raises(ResourceVerificationError, match="exceeds"):
        load_verification_receipt(b"{" + b" " * MAX_RECEIPT_BYTES + b"}")

    path = tmp_path / "receipt.json"
    write_verification_receipt(receipt, path)
    assert load_verification_receipt(path) == receipt
    with pytest.raises(ResourceVerificationError, match="already exists"):
        write_verification_receipt(receipt, path)


def test_v2_matrix_embeds_receipts_and_requires_every_board(tmp_path: Path) -> None:
    session, reference = _fixture_session(tmp_path)
    receipt_a = verify_resource_reference(session, reference, tick_ns=10.0)
    receipt_b = copy.deepcopy(receipt_a)
    receipt_b["board_id"] = "board-b"
    receipt_b["session_id"] = "resource-session-b"
    validate_verification_receipt(receipt_b)

    v1 = _v1_capture_matrix()
    receipts = _complete_v2_receipts(receipt_a, receipt_b)
    _bind_receipts_to_capture_rows(v1, receipts)
    v2 = build_hil_evidence_v2(v1, receipts)
    assert v2["schema"] == "t32perf.hil-evidence/v2"
    assert v2["coverage"]["verification"] == {
        "required_kinds": ["native_timeline", "resources", "fault_injection"],
        "required_fault_scenarios": [
            "trace_overflow",
            "flow_error",
            "sampling_buffer_full",
            "elf_mismatch",
            "trace32_disconnect_recovery",
            "driver_disconnect_recovery",
            "cmm_abort_recovery",
        ],
        "boards": ["board-a", "board-b"],
        "receipt_count": 18,
    }
    resource_entry = next(
        entry
        for entry in v2["verifications"]
        if entry["board_id"] == "board-a" and entry["kind"] == "resources"
    )
    assert resource_entry["canonical_receipt_sha256"] == canonical_sha256(receipt_a)
    assert_v2_verification_coverage(v2)
    assert load_hil_evidence(canonical_json_bytes(v2)) == v2

    receipt_schema = _receipt_schema()
    evidence_schema = _evidence_v2_schema()
    registry = Registry().with_resource(
        receipt_schema["$id"], Resource.from_contents(receipt_schema)
    )
    Draft202012Validator.check_schema(evidence_schema)
    Draft202012Validator(evidence_schema, registry=registry).validate(v2)

    with pytest.raises(ResourceVerificationError, match="coverage is incomplete"):
        build_hil_evidence_v2(
            v1, [receipt for receipt in receipts if receipt["board_id"] == "board-a"]
        )


def test_v2_rejects_tampered_embedded_receipt_digest_and_v1_remains_readable(
    tmp_path: Path,
) -> None:
    session, reference = _fixture_session(tmp_path)
    receipt_a = verify_resource_reference(session, reference, tick_ns=10.0)
    receipt_b = copy.deepcopy(receipt_a)
    receipt_b["board_id"] = "board-b"
    receipt_b["session_id"] = "resource-session-b"
    v1 = _v1_capture_matrix()
    receipts = _complete_v2_receipts(receipt_a, receipt_b)
    _bind_receipts_to_capture_rows(v1, receipts)
    v2 = build_hil_evidence_v2(v1, receipts)
    v2["verifications"][0]["canonical_receipt_sha256"] = "0" * 64
    with pytest.raises(ResourceVerificationError, match="canonical digest"):
        load_hil_evidence(v2)

    assert load_hil_evidence(canonical_json_bytes(v1)) == v1


def test_v1_runtime_rebuilds_coverage_and_preserves_extra_mode_compatibility() -> None:
    v1 = _v1_capture_matrix()
    assert load_hil_evidence(v1) == v1

    wrong_count = copy.deepcopy(v1)
    wrong_count["coverage"]["combinations"][0]["capture_count"] = 11
    with pytest.raises(ResourceVerificationError, match="counts differ"):
        load_hil_evidence(wrong_count)

    wrong_family = copy.deepcopy(v1)
    wrong_family["captures"][0]["mcu_family"] = "forged-family"
    with pytest.raises(ResourceVerificationError, match="identity changes|differs"):
        load_hil_evidence(wrong_family)

    duplicate_session = copy.deepcopy(v1)
    duplicate_session["captures"][1]["session_id"] = duplicate_session["captures"][0][
        "session_id"
    ]
    with pytest.raises(ResourceVerificationError, match="repeats board/Session"):
        load_hil_evidence(duplicate_session)

    extra_mode = copy.deepcopy(v1)
    extra_mode["coverage"]["modes"].append("sampling")
    extra_mode["coverage"]["modes"].sort()
    extra_mode["coverage"]["combinations"].insert(
        2, {"board_id": "board-a", "mode": "sampling", "capture_count": 10}
    )
    template = next(
        capture
        for capture in extra_mode["captures"]
        if capture["board_id"] == "board-a"
    )
    for index in range(10):
        capture = copy.deepcopy(template)
        capture["mode"] = "sampling"
        capture["initial_state"] = "running"
        capture["session_id"] = f"board-a-sampling-{index}"
        extra_mode["captures"].append(capture)
    assert load_hil_evidence(extra_mode) == extra_mode


def test_v2_healthy_receipts_must_bind_registered_capture_digests(
    tmp_path: Path,
) -> None:
    session, reference = _fixture_session(tmp_path)
    receipt_a = verify_resource_reference(session, reference, tick_ns=10.0)
    receipt_b = copy.deepcopy(receipt_a)
    receipt_b["board_id"] = "board-b"
    receipt_b["session_id"] = "resource-session-b"
    receipts = _complete_v2_receipts(receipt_a, receipt_b)
    v1 = _v1_capture_matrix()
    _bind_receipts_to_capture_rows(v1, receipts)
    v2 = build_hil_evidence_v2(v1, receipts)

    unregistered = copy.deepcopy(v2)
    entry = next(
        row
        for row in unregistered["verifications"]
        if row["board_id"] == "board-a" and row["kind"] == "resources"
    )
    entry["session_id"] = "unregistered-session"
    entry["receipt"]["session_id"] = "unregistered-session"
    entry["canonical_receipt_sha256"] = canonical_sha256(entry["receipt"])
    with pytest.raises(ResourceVerificationError, match="not a capture matrix Session"):
        assert_v2_verification_coverage(unregistered)

    wrong_digest = copy.deepcopy(v2)
    capture = next(
        row
        for row in wrong_digest["captures"]
        if row["board_id"] == "board-a" and row["session_id"] == "resource-session"
    )
    capture["manifest_sha256"] = "0" * 64
    with pytest.raises(ResourceVerificationError, match="artifact digests differ"):
        assert_v2_verification_coverage(wrong_digest)


def test_common_receipt_rejects_empty_shells_and_unrelated_fault_bindings() -> None:
    native_bindings = {
        "manifest": (None, "a" * 64),
        "health": ("health", "b" * 64),
        "observations": ("observations", "c" * 64),
        "analysis_summary": ("analysis-summary", "d" * 64),
        "hotspots": ("hotspots", "e" * 64),
        "derived": ("derived", "f" * 64),
    }
    with pytest.raises(
        ResourceVerificationError, match="empty required check categories"
    ):
        try:
            build_verification_receipt(
                kind="native_timeline",
                board_id="board-a",
                session_id="session-a",
                driver_reference_sha256="1" * 64,
                tolerance=TolerancePolicy(timestamp_absolute_ns=10.0),
                artifact_bindings=native_bindings,
                checks=[],
            )
        except RuntimeError as error:
            raise ResourceVerificationError(str(error)) from error

    with pytest.raises(ResourceVerificationError, match="unrelated artifact bindings"):
        try:
            build_verification_receipt(
                kind="fault_injection",
                scenario="trace_overflow",
                board_id="board-a",
                session_id="fault-a",
                driver_reference_sha256="2" * 64,
                tolerance=TolerancePolicy(timestamp_absolute_ns=0.0),
                artifact_bindings={
                    "manifest": (None, "a" * 64),
                    "health": ("health", "b" * 64),
                    "hotspots": ("hotspots", "c" * 64),
                },
                checks=[
                    VerificationCheck(category=category, name=category, passed=True)
                    for category in (
                        "artifact_binding",
                        "health",
                        "fault_publication",
                        "recovery",
                    )
                ],
            )
        except RuntimeError as error:
            raise ResourceVerificationError(str(error)) from error


def test_recovery_receipt_requires_exact_bound_recovery_document() -> None:
    checks = [
        VerificationCheck(category=category, name=category, passed=True)
        for category in (
            "artifact_binding",
            "health",
            "fault_publication",
            "recovery",
        )
    ]
    bindings = {
        "manifest": (None, "a" * 64),
        "health": ("health", "b" * 64),
    }
    with pytest.raises(RuntimeError, match="must bind strict"):
        build_verification_receipt(
            kind="fault_injection",
            scenario="cmm_abort_recovery",
            board_id="board-a",
            session_id="cmm-abort",
            driver_reference_sha256="c" * 64,
            tolerance=TolerancePolicy(timestamp_absolute_ns=0.0),
            artifact_bindings=bindings,
            checks=checks,
        )

    relabelled = TargetAdapterRecoveryEvidence(
        profile_sha256="d" * 64,
        binding_sha256="e" * 64,
        failed_operation="perf_start",
        failure_kind="driver_disconnect",
        initial_target_state="running",
        restored_target_state="running",
        adapter_state_restored=True,
        upstream_abort_confirmed=True,
        upstream_abort_receipt_sha256="f" * 64,
        files_deleted=False,
        new_session_required=True,
    ).to_document()
    with pytest.raises(RuntimeError, match="scenario and failure kind"):
        build_verification_receipt(
            kind="fault_injection",
            scenario="cmm_abort_recovery",
            board_id="board-a",
            session_id="cmm-abort",
            driver_reference_sha256="c" * 64,
            tolerance=TolerancePolicy(timestamp_absolute_ns=0.0),
            artifact_bindings=bindings,
            checks=checks,
            recovery_evidence=relabelled,
            recovery_evidence_sha256="f" * 64,
        )


def test_receipt_v1_keeps_non_recovery_compatibility() -> None:
    receipt = build_verification_receipt(
        kind="fault_injection",
        scenario="trace_overflow",
        board_id="board-a",
        session_id="overflow",
        driver_reference_sha256="c" * 64,
        tolerance=TolerancePolicy(timestamp_absolute_ns=0.0),
        artifact_bindings={
            "manifest": (None, "a" * 64),
            "health": ("health", "b" * 64),
        },
        checks=[
            VerificationCheck(category=category, name=category, passed=True)
            for category in ("artifact_binding", "health", "fault_publication")
        ],
    )
    del receipt["recovery_evidence"]

    validate_verification_receipt(receipt)
    Draft202012Validator(_receipt_schema()).validate(receipt)
