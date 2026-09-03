from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from xml.sax.saxutils import escape

import pytest
from jsonschema import Draft202012Validator, ValidationError
from test_harness import write_config
from test_sampling_board import write_sampling_config

from harness import BoardConfig, HilConfigurationError
from sampling_board import SamplingBoardConfig, endpoint_fingerprint
from sampling_verification import (
    _SVG_ANNOTATION_STYLE,
    _SVG_STYLE,
    SamplingVerificationError,
    _audit_address_heatmap,
    _audit_svg,
    _validate_histogram,
    build_receipt,
    load_receipt,
    run_sampling_hil,
)


def request_document() -> dict[str, object]:
    return {
        "schema": "t32perf.sampling-capture-request/v1",
        "ranges": [{"start_address": 0x1000, "end_address": 0x1010}],
        "bucket_size": 0x10,
        "duration_ms": 100,
        "method_policy": "realtime_only",
        "core_id": 0,
        "address_space": "P",
    }


def board(tmp_path: Path) -> BoardConfig:
    config = tmp_path / "board.toml"
    write_config(config)
    request = tmp_path / "request.json"
    request.write_text(json.dumps(request_document()) + "\n", encoding="utf-8")
    digest = hashlib.sha256(request.read_bytes()).hexdigest()
    text = config.read_text(encoding="utf-8").replace(
        'recovery_evidence_root = "recovery-evidence"',
        'recovery_evidence_root = "recovery-evidence"\n'
        'sampling_evidence_root = "sampling-evidence"',
    )
    text += (
        '\nsampling_prepare = ["tool", "prepare", "{session_id}", "{request}"]\n'
        'sampling_capabilities = ["tool", "capabilities", "{session_id}"]\n'
        'sampling_capture = ["tool", "capture", "{session_id}", "{operation_id}", "{sidecar_args}"]\n'
        'sampling_ingest = ["tool", "ingest", "{session_id}", "{staged_path}"]\n'
        'sampling_analyze = ["tool", "analyze", "{session_id}", "{histogram_artifact_id}"]\n'
        'sampling_summary = ["tool", "summary", "{session_id}", "{heatmap_artifact_id}"]\n'
        'sampling_render = ["tool", "render", "{session_id}", "{heatmap_artifact_id}"]\n'
    )
    text += (
        f'\n[sampling]\ncapture_request = "{request.name}"\n'
        f'capture_request_sha256 = "{digest}"\n'
    )
    config.write_text(text, encoding="utf-8")
    return BoardConfig.load(config)


def pinned_board(tmp_path: Path) -> SamplingBoardConfig:
    return SamplingBoardConfig.load(write_sampling_config(tmp_path))


def host(command: str, result: dict[str, object]) -> dict[str, object]:
    return {"ok": True, "command": command, "result": result}


def prepared(
    config: BoardConfig | SamplingBoardConfig, session_id: str
) -> dict[str, object]:
    operation_id = "1" * 32
    return host(
        "sampling.prepare",
        {
            "operation_id": operation_id,
            "request_sha256": hashlib.sha256(
                config.sampling_capture_request.read_bytes()
            ).hexdigest(),
            "sampling_capture_arguments": {
                **{
                    key: value
                    for key, value in request_document().items()
                    if key != "schema"
                },
                "session_id": session_id,
                "operation_id": operation_id,
            },
        },
    )


def capabilities(
    powered: bool = True, pcsnoop: object = True, *, probe: object = "0" * 64
) -> dict[str, object]:
    software = "R.2026.02.000190766+190766"
    return {
        "schema": "t32perf.sampling-capabilities/v1",
        "target": {"powered": powered, "running": powered, "halted": False},
        "pcsnoop": pcsnoop,
        "trace32": software,
        "cpu": "CortexM0+",
        "probe_fingerprint": probe,
        "endpoint_fingerprint": endpoint_fingerprint(
            "localhost", 20001, "TCP", software, str(probe)
        ),
        "endpoint_fingerprint_scheme": "t32perf.endpoint-fingerprint/v2",
        "supported_methods": ["realtime"] if pcsnoop is True else ["stop_and_go"],
    }


def capture(session_id: str, hits: int = 100) -> dict[str, object]:
    histogram: dict[str, object] = {
        "schema": "t32perf.pc-hit-histogram/v1",
        "session_id": session_id,
        "endpoint_fingerprint": endpoint_fingerprint(
            "localhost", 20001, "TCP", "R.2026.02.000190766+190766", "0" * 64
        ),
        "endpoint_fingerprint_scheme": "t32perf.endpoint-fingerprint/v2",
        "trace32": "R.2026.02.000190766+190766",
        "cpu": "CortexM0+",
        "address_space": "P",
        "core_id": 0,
        "method": {"kind": "realtime"},
        "intrusive": False,
        "requested_duration_ns": 100_000_000,
        "observed_duration_ns": 100_000_000,
        "last_sample_rate_hz": 1_000,
        "snoop_failures": 0,
        "target_state_before": {"powered": True, "running": True, "halted": False},
        "target_state_after": {"powered": True, "running": True, "halted": False},
        "firmware": {"status": "unverified"},
        "cleanup_complete": True,
        "in_scope_hits": hits,
        "buckets": [{"start_address": 0x1000, "end_address": 0x1010, "hits": hits}],
    }
    payload = (
        json.dumps(histogram, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode()
    return {
        "histogram": histogram,
        "artifact": {
            "relative_path": (
                f"capture/staging/pc-hit-histogram-{session_id}-"
                "11111111111111111111111111111111.json"
            ),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
        },
    }


def debugger_location(*, hits: int = 100) -> dict[str, object]:
    return {
        "bucket_start_address": 0x1000,
        "bucket_end_address": 0x1010,
        "hits": hits,
        "dominant_start_address": 0x1004,
        "dominant_end_address": 0x1008,
        "dominant_hits": min(hits, 50),
        "function_name": "main",
        "source_file": "main.c",
        "source_line": 42,
    }


def symbolized_histogram(session_id: str = "symbolized") -> dict[str, object]:
    histogram = capture(session_id)["histogram"]
    assert isinstance(histogram, dict)
    histogram["debugger_symbolization"] = {
        "source": "trace32_symbol_table",
        "trust": "debugger_reported",
        "refinement_granularity_bytes": 4,
        "locations": [debugger_location()],
    }
    return histogram


def materialize_session(
    config: BoardConfig | SamplingBoardConfig,
    session_id: str,
    operation_id: str,
    histogram_bytes: bytes,
) -> dict[str, dict[str, object]]:
    session = config.artifact_root / session_id
    (session / "artifact-index").mkdir(parents=True)
    (session / "request.json").write_bytes(config.sampling_capture_request.read_bytes())
    (session / "state.json").write_text(
        json.dumps(
            {
                "schema": "t32perf.state/v1",
                "created_at": "2026-01-01T00:00:00Z",
                "state": "captured",
                "operation_id": operation_id,
                "revision": 1,
                "updated_at": "2026-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    histogram = json.loads(histogram_bytes)
    histogram_digest = hashlib.sha256(histogram_bytes).hexdigest()
    journal_events = [
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
    capture_receipt = {
        "schema": "t32perf.sampling-capture-receipt/v1",
        "session_id": session_id,
        "session_operation_id": operation_id,
        "transaction_id": "12345678-1234-4abc-8def-123456789abc",
        "endpoint_fingerprint": histogram["endpoint_fingerprint"],
        "endpoint_fingerprint_scheme": "t32perf.endpoint-fingerprint/v2",
        "session_request_sha256": hashlib.sha256(
            config.sampling_capture_request.read_bytes()
        ).hexdigest(),
        "histogram_sha256": histogram_digest,
        "histogram_size_bytes": len(histogram_bytes),
        "journal_event_claims": [
            {"sequence": index, "event": event, "sha256": f"{index:x}" * 64}
            for index, event in enumerate(journal_events, 1)
        ],
    }
    locations = {
        (location["bucket_start_address"], location["bucket_end_address"]): location
        for location in histogram.get("debugger_symbolization", {}).get("locations", [])
    }
    cells = []
    for item in histogram["buckets"]:
        cell = {
            "key": {
                "kind": "address_range",
                "start_address": item["start_address"],
                "end_address": item["end_address"],
            },
            "display_name": f"{item['start_address']:#x}..{item['end_address']:#x}",
            "hits": item["hits"],
        }
        location = locations.get((item["start_address"], item["end_address"]))
        if location is not None:
            cell["debugger_location"] = location
        cells.append(cell)
    heatmap = {
        "schema": "t32perf.heatmap/v1",
        "session_id": session_id,
        "histogram_sha256": histogram_digest,
        "quality": "statistical",
        "projection_kind": "address_range",
        "quantitative_policy": {
            "min_in_scope_hits": 100,
            "min_observed_duration_ns": 100_000_000,
            "min_stop_and_go_retained_runtime_percent": 90.0,
            "max_snoop_failures": 0,
        },
        "denominator_hits": histogram["in_scope_hits"],
        "attributed_hits": histogram["in_scope_hits"],
        "unattributed_hits": 0,
        "out_of_scope_hits": {"status": "unknown"},
        "cells": cells,
    }
    svg_metadata = [
        "Method: RealTime · intrusive: false",
        "CPU: CortexM0+ · core: 0 · address space: P",
        "Requested duration: 100 ms · observed duration: 100 ms",
        f"In-scope hits: {histogram['in_scope_hits']}",
        "Unattributed in-scope hits: 0",
        "Last rate snapshot: 1000 Hz (not an average)",
        "PC-snoop failures: 0",
        "Firmware status: unverified",
        "ELF SHA-256: unverified",
        "Quantitative gate: ≥100 in-scope hits · ≥100 ms observed · snoop failures ≤0 · StopAndGo retained runtime ≥90.0%",
        "Evidence status: statistical estimate.",
    ]
    if any("debugger_location" in cell for cell in cells):
        svg_metadata.append(
            "TRACE32 symbol-table labels: debugger-reported; labels do not verify firmware"
        )
    has_annotations = any("debugger_location" in cell for cell in cells)
    row_height = 58 if has_annotations else 42
    chart_top = 110 + (len(svg_metadata) * 20)
    svg_rows = []
    for index, cell in enumerate(cells):
        y = chart_top + (index * row_height)
        percentage = cell["hits"] * 1000 // histogram["in_scope_hits"]
        label = (
            f"{cell['key']['start_address']:#010x}..{cell['key']['end_address']:#010x}"
        )
        svg_rows.append(
            f'<text class="label" x="32" y="{y + 19}">{escape(label)}</text>'
        )
        svg_rows.append(
            f'<line class="track" x1="434" y1="{y + 14}" x2="814" y2="{y + 14}"/>'
        )
        if cell["hits"] > 0:
            svg_rows.append(
                f'<rect class="bar" x="434" y="{y + 6}" '
                f'width="{cell["hits"] * 380 // histogram["in_scope_hits"]}" '
                'height="16"/>'
            )
            svg_rows.append(
                f'<text class="value" x="824" y="{y + 19}">{cell["hits"]} / '
                f"{percentage // 10}.{percentage % 10}%</text>"
            )
        else:
            svg_rows.append(
                f'<text class="empty" x="434" y="{y + 34}">not observed</text>'
            )
        location = cell.get("debugger_location")
        if isinstance(location, dict):
            annotation = f"dominant {location['dominant_hits']}/{location['hits']}"
            annotation_parts = []
            if isinstance(location.get("function_name"), str):
                annotation_parts.append(location["function_name"])
            if isinstance(location.get("source_file"), str) and isinstance(
                location.get("source_line"), int
            ):
                annotation_parts.append(
                    f"{location['source_file']}:{location['source_line']}"
                )
            if annotation_parts:
                detail = " · ".join(annotation_parts)
                annotation += f" · {detail if len(detail) <= 46 else f'{detail[:46]}…'}"
            svg_rows.append(
                f'<text class="annotation" x="32" y="{y + 43}">{escape(annotation)}</text>'
            )
    svg_title = "Address-range statistical PC-sample hotspots"
    svg_description = (
        "Statistical PC-hit projection. "
        f"{histogram['in_scope_hits']} in-scope samples; 0 unattributed samples. "
        "All attributed rows are shown.."
    )
    height = chart_top + 24 + (len(cells) * row_height)
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="{height}" '
        f'viewBox="0 0 1000 {height}" role="img" aria-labelledby="title desc">'
        f'<title id="title">{svg_title}</title>'
        f'<desc id="desc">{svg_description}</desc>'
        + _SVG_STYLE
        + (_SVG_ANNOTATION_STYLE if has_annotations else "")
        + f'<text class="heading" x="32" y="38">{svg_title}</text>'
        + '<text class="subtitle" x="32" y="62">'
        + "Statistical PC samples — not an execution-completeness or exact-time claim</text>"
        + "".join(
            f'<text class="metadata" x="32" y="{92 + (index * 20)}">{escape(label)}</text>'
            for index, label in enumerate(svg_metadata)
        )
        + f'<text class="axis" x="32" y="{chart_top - 10}">Location</text>'
        + f'<text class="axis" x="434" y="{chart_top - 10}">PC samples</text>'
        + "".join(svg_rows)
        + "</svg>"
    )
    specs = [
        (
            "sampling-capture-receipt",
            "sampling_capture_receipt",
            "capture/sampling/capture-receipt.json",
            "application/json",
            "t32perf-sampling-capture-receipt/v1",
            [],
            (
                json.dumps(capture_receipt, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode(),
        ),
        (
            "sampling-pc-hit-histogram",
            "pc_hit_histogram",
            "capture/sampling/pc-hit-histogram.json",
            "application/json",
            "lauterbach-sampling-mcp/v1",
            ["sampling-capture-receipt"],
            histogram_bytes,
        ),
        (
            "sampling-heatmap-address",
            "heatmap",
            "analysis/sampling-heatmap-address.json",
            "application/json",
            "t32perf-sampling-analysis/v1",
            ["sampling-pc-hit-histogram"],
            (
                json.dumps(heatmap, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode(),
        ),
        (
            "sampling-heatmap-address-svg-top025",
            "heatmap",
            "report/sampling-heatmap-address-top025.svg",
            "image/svg+xml",
            "t32perf-sampling-analysis/v1",
            ["sampling-heatmap-address", "sampling-pc-hit-histogram"],
            svg.encode(),
        ),
    ]
    wrappers: dict[str, dict[str, object]] = {}
    for (
        artifact_id,
        kind,
        relative_path,
        media_type,
        producer,
        inputs,
        content,
    ) in specs:
        target = session / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        artifact = {
            "id": artifact_id,
            "kind": kind,
            "relative_path": relative_path,
            "media_type": media_type,
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "producer": producer,
            "input_artifact_ids": inputs,
        }
        (session / "artifact-index" / f"{artifact_id}.json").write_text(
            json.dumps(artifact), encoding="utf-8"
        )
        wrappers[artifact_id] = {
            "id": artifact_id,
            "kind": kind,
            "path": relative_path,
            "sha256": artifact["sha256"],
            "media_type": media_type,
            "producer": producer,
            "input_artifact_ids": inputs,
        }
    return wrappers


def successful_host_rows(
    wrappers: dict[str, dict[str, object]],
) -> list[dict[str, object]]:
    return [
        host(
            "sampling.ingest",
            {
                "capture_receipt_artifact": {
                    **wrappers["sampling-capture-receipt"],
                },
                "histogram_artifact": {
                    **wrappers["sampling-pc-hit-histogram"],
                },
            },
        ),
        host(
            "sampling.analyze",
            {
                "artifact": wrappers["sampling-heatmap-address"],
                "statistical": True,
                "diagnostic_only": True,
            },
        ),
        host(
            "sampling.summary",
            {
                "quantitative_policy": {
                    "min_in_scope_hits": 100,
                    "min_observed_duration_ns": 100_000_000,
                    "min_stop_and_go_retained_runtime_percent": 90.0,
                    "max_snoop_failures": 0,
                },
                "denominator_hits": 100,
                "statistical": True,
                "diagnostic_only": True,
            },
        ),
        host(
            "sampling.render",
            {
                "artifact": wrappers["sampling-heatmap-address-svg-top025"],
                "statistical": True,
                "diagnostic_only": True,
            },
        ),
    ]


def passing_receipt_kwargs() -> dict[str, object]:
    return {
        "board_id": "example",
        "session_id": "pass",
        "status": "PASS",
        "reason": "capture accepted",
        "capture_request_file_sha256": "a" * 64,
        "session_request_sha256": "b" * 64,
        "capabilities": {
            "schema": "t32perf.sampling-capabilities/v1",
            "endpoint_fingerprint_scheme": "t32perf.endpoint-fingerprint/v2",
            "probe_fingerprint": "0" * 64,
            "endpoint_fingerprint": "1" * 64,
            "pcsnoop": True,
            "supported_methods": ["realtime"],
        },
        "checks": [{"name": "target_running", "passed": True, "reason": "ok"}],
        "artifact_bindings": [
            {"role": "capture_receipt", "artifact_id": "capture", "sha256": "c" * 64},
            {"role": "histogram", "artifact_id": "histogram", "sha256": "d" * 64},
            {"role": "address_heatmap", "artifact_id": "heatmap", "sha256": "e" * 64},
            {"role": "svg", "artifact_id": "svg", "sha256": "f" * 64},
        ],
        "endpoint_fingerprint": "1" * 64,
        "configured_identity": {
            "mcu_family": "Cortex-M",
            "probe_id": "probe-1",
            "scope": "observed_probe_endpoint_class",
            "expected_probe_fingerprint": "0" * 64,
            "observed_probe_fingerprint": "0" * 64,
            "probe_identity_observed": True,
            "target_id_observed": False,
        },
        "method_policy": "realtime_only",
        "selected_method": "realtime",
        "target_before": {"powered": True, "running": True, "halted": False},
        "target_after": {"powered": True, "running": True, "halted": False},
        "operation_id": "2" * 32,
        "quantitative_policy": {
            "min_in_scope_hits": 100,
            "min_observed_duration_ns": 100_000_000,
            "min_stop_and_go_retained_runtime_percent": 90,
            "max_snoop_failures": 0,
        },
        "statistical": True,
        "diagnostic_only": True,
    }


def receipt_schema() -> Draft202012Validator:
    document = json.loads(
        (
            Path(__file__).parents[1]
            / "schemas/hil-sampling-verification-receipt.schema.json"
        ).read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(document)
    return Draft202012Validator(document)


def test_debugger_symbolization_accepts_only_bound_diagnostic_locations(
    tmp_path: Path,
) -> None:
    board(tmp_path)
    histogram = symbolized_histogram()
    payload = (
        json.dumps(histogram, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode()
    artifact = {
        "relative_path": "capture/staging/pc-hit-histogram-symbolized-"
        "11111111111111111111111111111111.json",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "size_bytes": len(payload),
    }
    accepted, _ = _validate_histogram(
        histogram,
        artifact,
        session_id="symbolized",
        request=request_document(),
    )
    assert accepted["firmware"] == {"status": "unverified"}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update({"trust": "elf_verified"}),
        lambda value: value.update({"refinement_granularity_bytes": 8}),
        lambda value: value["locations"][0].update({"hits": 99}),
        lambda value: value["locations"][0].update({"dominant_end_address": 0x1009}),
        lambda value: value["locations"][0].update({"function_name": "src/main"}),
        lambda value: value["locations"][0].update({"source_file": "src/main.c"}),
        lambda value: value["locations"][0].pop("source_line"),
    ],
)
def test_debugger_symbolization_rejects_untrusted_or_inexact_locations(
    tmp_path: Path, mutate: object
) -> None:
    board(tmp_path)
    histogram = symbolized_histogram()
    assert callable(mutate)
    mutate(histogram["debugger_symbolization"])
    with pytest.raises(SamplingVerificationError, match="debugger symbolization"):
        _validate_histogram(
            histogram,
            {"relative_path": "capture/staging/pc-hit-histogram-symbolized.json"},
            session_id="symbolized",
            request=request_document(),
        )


def test_address_heatmap_requires_exact_debugger_location() -> None:
    histogram = symbolized_histogram()
    histogram_bytes = (
        json.dumps(histogram, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode()
    location = debugger_location()
    heatmap = {
        "schema": "t32perf.heatmap/v1",
        "session_id": "symbolized",
        "histogram_sha256": hashlib.sha256(histogram_bytes).hexdigest(),
        "quality": "statistical",
        "projection_kind": "address_range",
        "quantitative_policy": {
            "min_in_scope_hits": 100,
            "min_observed_duration_ns": 100_000_000,
            "min_stop_and_go_retained_runtime_percent": 90.0,
            "max_snoop_failures": 0,
        },
        "denominator_hits": 100,
        "attributed_hits": 100,
        "unattributed_hits": 0,
        "out_of_scope_hits": {"status": "unknown"},
        "cells": [
            {
                "key": {
                    "kind": "address_range",
                    "start_address": 0x1000,
                    "end_address": 0x1010,
                },
                "display_name": "0x1000..0x1010",
                "hits": 100,
                "debugger_location": location,
            }
        ],
    }
    _audit_address_heatmap(
        (json.dumps(heatmap, separators=(",", ":"), sort_keys=True) + "\n").encode(),
        histogram=histogram,
        histogram_digest=hashlib.sha256(histogram_bytes).hexdigest(),
    )
    heatmap["cells"][0]["debugger_location"]["function_name"] = "forged"
    with pytest.raises(SamplingVerificationError, match="differs from histogram"):
        _audit_address_heatmap(
            (
                json.dumps(heatmap, separators=(",", ":"), sort_keys=True) + "\n"
            ).encode(),
            histogram=histogram,
            histogram_digest=hashlib.sha256(histogram_bytes).hexdigest(),
        )


def test_svg_audits_debugger_label_metadata_and_xml_escaping(tmp_path: Path) -> None:
    config = pinned_board(tmp_path)
    histogram = symbolized_histogram("symbolized-svg")
    symbolization = histogram["debugger_symbolization"]
    assert isinstance(symbolization, dict)
    locations = symbolization["locations"]
    assert isinstance(locations, list) and isinstance(locations[0], dict)
    locations[0]["function_name"] = "main<&>"
    histogram_bytes = (
        json.dumps(histogram, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode()
    materialize_session(config, "symbolized-svg", "1" * 32, histogram_bytes)
    session = config.artifact_root / "symbolized-svg"
    heatmap = json.loads(
        (session / "analysis/sampling-heatmap-address.json").read_text(encoding="utf-8")
    )
    svg = (session / "report/sampling-heatmap-address-top025.svg").read_bytes()
    assert b"0x00001000..0x00001010" in svg
    assert b"dominant 50/100" in svg
    _audit_svg(
        svg,
        heatmap=heatmap,
        histogram=histogram,
    )


def test_power_down_writes_not_ready_without_capture(tmp_path: Path) -> None:
    config = board(tmp_path)
    calls: list[list[str]] = []
    replies = iter([prepared(config, "down"), capabilities(False)])
    receipt = run_sampling_hil(
        config,
        session_id="down",
        invoke=lambda argv: calls.append(argv) or next(replies),
    )
    assert receipt["status"] == "FAIL"
    assert receipt["reason"] == "sampling_board_config_required"
    assert receipt["operation_id"] == "1" * 32
    assert [item[1] for item in calls] == ["prepare", "capabilities"]
    assert (
        load_receipt(config.sampling_evidence_root / "down.json")["artifact_bindings"]
        == []
    )


def test_realtime_pass_has_exact_host_chain(tmp_path: Path) -> None:
    config = pinned_board(tmp_path)
    captured = capture("pass")
    wrappers = materialize_session(
        config,
        "pass",
        "1" * 32,
        (
            json.dumps(
                captured["histogram"],
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode(),
    )
    calls: list[list[str]] = []
    replies = iter(
        [
            prepared(config, "pass"),
            capabilities(),
            captured,
            *successful_host_rows(wrappers),
        ]
    )
    receipt = run_sampling_hil(
        config,
        session_id="pass",
        invoke=lambda argv: calls.append(argv) or next(replies),
    )
    assert receipt["status"] == "PASS" and receipt["diagnostic_only"] is True
    assert receipt["capture_request_file_sha256"] == receipt["session_request_sha256"]
    assert [item[7] for item in calls] == [
        "sampling_prepare",
        "sampling_capabilities",
        "sampling_capture",
        "sampling_ingest",
        "sampling_analyze",
        "sampling_summary",
        "sampling_render",
    ]
    sidecar_arguments = json.loads(calls[2][-1])
    assert (
        sidecar_arguments
        == prepared(config, "pass")["result"]["sampling_capture_arguments"]
    )
    assert "schema" not in sidecar_arguments
    receipt_schema().validate(receipt)


def test_wrapper_artifacts_without_audited_session_cannot_produce_pass(
    tmp_path: Path,
) -> None:
    config = pinned_board(tmp_path)
    captured = capture("no-files")
    wrappers = materialize_session(
        config,
        "no-files",
        "1" * 32,
        (
            json.dumps(
                captured["histogram"],
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode(),
    )
    shutil.rmtree(config.artifact_root / "no-files")
    replies = iter(
        [
            prepared(config, "no-files"),
            capabilities(),
            captured,
            *successful_host_rows(wrappers),
        ]
    )
    with pytest.raises(SamplingVerificationError, match="missing audited session"):
        run_sampling_hil(config, session_id="no-files", invoke=lambda _: next(replies))


@pytest.mark.parametrize(
    ("relative_path", "replacement"),
    [
        ("capture/sampling/capture-receipt.json", b"{}\n"),
        ("capture/sampling/pc-hit-histogram.json", b"{}\n"),
        ("analysis/sampling-heatmap-address.json", b"{}\n"),
        ("report/sampling-heatmap-address-top025.svg", b"<svg/>"),
    ],
)
def test_semantic_artifact_tampering_cannot_produce_pass(
    tmp_path: Path, relative_path: str, replacement: bytes
) -> None:
    config = pinned_board(tmp_path)
    captured = capture("tampered-artifact")
    histogram_bytes = (
        json.dumps(
            captured["histogram"],
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()
    wrappers = materialize_session(
        config, "tampered-artifact", "1" * 32, histogram_bytes
    )
    target = config.artifact_root / "tampered-artifact" / relative_path
    target.write_bytes(replacement)
    replies = iter(
        [
            prepared(config, "tampered-artifact"),
            capabilities(),
            captured,
            *successful_host_rows(wrappers),
        ]
    )
    with pytest.raises(SamplingVerificationError):
        run_sampling_hil(
            config, session_id="tampered-artifact", invoke=lambda _: next(replies)
        )


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        ('<line class="track" x1="434"', '<line class="track" x1="0"'),
        ('width="380" height="16"', 'width="0" height="16"'),
    ],
)
def test_svg_track_or_bar_geometry_tampering_is_rejected(
    tmp_path: Path, needle: str, replacement: str
) -> None:
    config = pinned_board(tmp_path)
    captured = capture("svg-geometry")
    histogram_bytes = (
        json.dumps(
            captured["histogram"],
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()
    materialize_session(config, "svg-geometry", "1" * 32, histogram_bytes)
    session = config.artifact_root / "svg-geometry"
    svg_path = session / "report/sampling-heatmap-address-top025.svg"
    svg_path.write_text(
        svg_path.read_text(encoding="utf-8").replace(needle, replacement),
        encoding="utf-8",
    )
    heatmap = json.loads(
        (session / "analysis/sampling-heatmap-address.json").read_text()
    )
    with pytest.raises(SamplingVerificationError, match="SVG (track|bar) geometry"):
        _audit_svg(
            svg_path.read_bytes(), heatmap=heatmap, histogram=captured["histogram"]
        )


def test_svg_utf16_entity_and_oversized_payloads_are_rejected(tmp_path: Path) -> None:
    config = pinned_board(tmp_path)
    captured = capture("svg-utf16")
    histogram_bytes = (
        json.dumps(captured["histogram"], sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    materialize_session(config, "svg-utf16", "1" * 32, histogram_bytes)
    heatmap = json.loads(
        (
            config.artifact_root / "svg-utf16/analysis/sampling-heatmap-address.json"
        ).read_text()
    )
    utf16_entity = (
        '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE svg [<!ENTITY x "boom">]><svg>&x;</svg>'
    ).encode("utf-16")
    with pytest.raises(SamplingVerificationError, match="strict UTF-8"):
        _audit_svg(utf16_entity, heatmap=heatmap, histogram=captured["histogram"])
    with pytest.raises(SamplingVerificationError, match="renderer output limit"):
        _audit_svg(
            b" " * (1024 * 1024 + 1), heatmap=heatmap, histogram=captured["histogram"]
        )


@pytest.mark.parametrize(
    "payload",
    [
        "<script>alert(1)</script>",
        "<foreignObject><div/></foreignObject>",
        '<text class="heading" x="32" y="38" onload="x()">x</text>',
        '<rect class="bar" x="434" y="336" width="380" height="16"/>',
        '<text class="foo" x="1" y="1">x</text>',
    ],
)
def test_svg_active_or_extra_markup_is_rejected(tmp_path: Path, payload: str) -> None:
    config = pinned_board(tmp_path)
    captured = capture("svg-allowlist")
    histogram_bytes = (
        json.dumps(captured["histogram"], sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    materialize_session(config, "svg-allowlist", "1" * 32, histogram_bytes)
    session = config.artifact_root / "svg-allowlist"
    svg_path = session / "report/sampling-heatmap-address-top025.svg"
    svg_path.write_text(
        svg_path.read_text(encoding="utf-8").replace("</svg>", payload + "</svg>"),
        encoding="utf-8",
    )
    heatmap = json.loads(
        (session / "analysis/sampling-heatmap-address.json").read_text()
    )
    with pytest.raises(SamplingVerificationError):
        _audit_svg(
            svg_path.read_bytes(), heatmap=heatmap, histogram=captured["histogram"]
        )


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        (
            "checks",
            [{"name": "target_running", "passed": False, "reason": "not running"}],
        ),
        ("target_before", {"powered": False, "running": True, "halted": False}),
        ("target_before", {"powered": True, "running": False, "halted": False}),
        ("target_before", {"powered": True, "running": True, "halted": True}),
        ("target_after", {"powered": False, "running": True, "halted": False}),
        ("target_after", {"powered": True, "running": False, "halted": False}),
        ("target_after", {"powered": True, "running": True, "halted": True}),
    ],
)
def test_pass_invariants_reject_failed_checks_and_non_running_targets(
    field: str, invalid_value: object
) -> None:
    kwargs = passing_receipt_kwargs()
    kwargs[field] = invalid_value
    with pytest.raises(SamplingVerificationError):
        build_receipt(**kwargs)

    receipt = build_receipt(**passing_receipt_kwargs())
    receipt[field] = invalid_value
    with pytest.raises(SamplingVerificationError):
        load_receipt(receipt)
    with pytest.raises(ValidationError):
        receipt_schema().validate(receipt)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema", "wrong"),
        ("endpoint_fingerprint_scheme", "t32perf.endpoint-fingerprint/v1"),
        ("probe_fingerprint", "f" * 64),
        ("endpoint_fingerprint", "f" * 64),
    ],
)
def test_pass_rejects_unpinned_capabilities(field: str, value: object) -> None:
    kwargs = passing_receipt_kwargs()
    capability_document = kwargs["capabilities"]
    assert isinstance(capability_document, dict)
    capability_document[field] = value
    with pytest.raises(SamplingVerificationError):
        build_receipt(**kwargs)


def test_realtime_only_without_pcsnoop_never_captures(tmp_path: Path) -> None:
    config = board(tmp_path)
    calls: list[list[str]] = []
    replies = iter([prepared(config, "unsupported"), capabilities(True, False)])
    receipt = run_sampling_hil(
        config,
        session_id="unsupported",
        invoke=lambda argv: calls.append(argv) or next(replies),
    )
    assert receipt["status"] == "FAIL"
    assert receipt["reason"] == "sampling_board_config_required"
    assert [item[1] for item in calls] == ["prepare", "capabilities"]


def test_probe_mismatch_records_observed_identity_without_capture(
    tmp_path: Path,
) -> None:
    config = pinned_board(tmp_path)
    observed = "f" * 64
    replies = iter([prepared(config, "probe-mismatch"), capabilities(probe=observed)])
    receipt = run_sampling_hil(
        config, session_id="probe-mismatch", invoke=lambda _: next(replies)
    )
    assert receipt["status"] == "FAIL"
    assert receipt["reason"] == "trace32_identity_mismatch"
    assert receipt["configured_identity"] == {
        "mcu_family": "Cortex-M",
        "probe_id": "probe-1",
        "scope": "observed_probe_endpoint_class",
        "expected_probe_fingerprint": "0" * 64,
        "observed_probe_fingerprint": observed,
        "probe_identity_observed": True,
        "target_id_observed": False,
    }


def test_quality_failure_stops_after_typed_ingest(tmp_path: Path) -> None:
    config = pinned_board(tmp_path)
    captured = capture("quality", hits=10)
    calls: list[list[str]] = []
    replies = iter(
        [
            prepared(config, "quality"),
            capabilities(),
            captured,
            successful_host_rows(
                materialize_session(
                    config,
                    "quality",
                    "1" * 32,
                    (
                        json.dumps(
                            captured["histogram"],
                            ensure_ascii=True,
                            separators=(",", ":"),
                            sort_keys=True,
                        )
                        + "\n"
                    ).encode(),
                )
            )[0],
        ]
    )
    receipt = run_sampling_hil(
        config,
        session_id="quality",
        invoke=lambda argv: calls.append(argv) or next(replies),
    )
    assert receipt["status"] == "FAIL" and receipt["reason"] == "insufficient_quality"
    assert [item[7] for item in calls] == [
        "sampling_prepare",
        "sampling_capabilities",
        "sampling_capture",
        "sampling_ingest",
    ]


def test_summary_policy_stronger_than_audited_heatmap_cannot_pass(
    tmp_path: Path,
) -> None:
    config = pinned_board(tmp_path)
    captured = capture("strong-policy")
    histogram_bytes = (
        json.dumps(
            captured["histogram"],
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()
    wrappers = materialize_session(config, "strong-policy", "1" * 32, histogram_bytes)
    rows = successful_host_rows(wrappers)
    rows[2]["result"]["quantitative_policy"]["min_in_scope_hits"] = 1_000
    replies = iter([prepared(config, "strong-policy"), capabilities(), captured, *rows])
    receipt = run_sampling_hil(
        config, session_id="strong-policy", invoke=lambda _: next(replies)
    )
    assert receipt["status"] == "FAIL"
    assert receipt["reason"] == "Host projection evidence mismatch"


def test_sampling_config_and_receipt_tampering_are_rejected(tmp_path: Path) -> None:
    config = board(tmp_path)
    config.sampling_capture_request.write_text(
        '{"schema":"t32perf.sampling-capture-request/v1"}\n', encoding="utf-8"
    )
    with pytest.raises(HilConfigurationError, match="does not match"):
        BoardConfig.load(config.path)
    with pytest.raises(HilConfigurationError, match="does not match"):
        run_sampling_hil(
            config,
            session_id="tampered",
            invoke=lambda _: pytest.fail(
                "tampered request must fail before invocation"
            ),
        )
    with pytest.raises(SamplingVerificationError):
        load_receipt({"schema": "t32perf.hil-sampling-verification-receipt/v1"})


def test_sampling_config_allows_only_canonical_deployed_elf_assertion(
    tmp_path: Path,
) -> None:
    config = board(tmp_path)
    document = request_document()
    document["deployed_firmware_elf_sha256"] = "b" * 64
    payload = json.dumps(document).encode() + b"\n"
    config.sampling_capture_request.write_bytes(payload)
    valid_digest = hashlib.sha256(payload).hexdigest()
    config.path.write_text(
        config.path.read_text(encoding="utf-8").replace(
            config.sampling_capture_request_sha256,
            valid_digest,
        ),
        encoding="utf-8",
    )
    assert BoardConfig.load(config.path).sampling_capture_request_sha256 == valid_digest

    document["deployed_firmware_elf_sha256"] = "B" * 64
    payload = json.dumps(document).encode() + b"\n"
    config.sampling_capture_request.write_bytes(payload)
    malformed_digest = hashlib.sha256(payload).hexdigest()
    config.path.write_text(
        config.path.read_text(encoding="utf-8").replace(
            valid_digest,
            malformed_digest,
        ),
        encoding="utf-8",
    )
    with pytest.raises(HilConfigurationError, match="deployed ELF digest"):
        BoardConfig.load(config.path)
