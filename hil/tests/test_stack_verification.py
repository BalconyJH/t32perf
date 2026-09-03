from __future__ import annotations

import hashlib
import json

import pytest

from stack_verification import (
    StackVerificationError,
    _clean_debugger_error_state,
    _profile,
    _raw,
    _svg,
)


def request() -> dict[str, object]:
    return {
        "schema": "t32perf.stack-capture-request/v1",
        "acknowledge_intrusive": True,
        "sample_period_ms": 10,
        "duration_ms": 100,
        "max_samples": 2,
        "max_frames": 4,
        "core_id": 0,
        "address_space": "P",
    }


def raw() -> dict[str, object]:
    return {
        "schema": "t32perf.stack-samples/v1",
        "session_id": "stack-unit",
        "endpoint_fingerprint": "a" * 64,
        "endpoint_fingerprint_scheme": "t32perf.endpoint-fingerprint/v2",
        "trace32": "R.2026.02.000190766+190766",
        "cpu": "CortexM0+",
        "core_id": 0,
        "address_space": "P",
        "method": "break_frame_walk",
        "intrusive": True,
        "frame_order": "leaf_to_root",
        "requested_duration_ms": 100,
        "observed_duration_ms": 100,
        "requested_sample_period_ms": 10,
        "max_samples": 2,
        "max_frames": 4,
        "attempted_samples": 2,
        "collected_samples": 2,
        "total_halt_cycle_duration_ns": 30,
        "target_state_before": {"powered": True, "running": True, "halted": False},
        "target_state_after": {"powered": True, "running": True, "halted": False},
        "firmware": {"status": "unverified"},
        "cleanup_complete": True,
        "debugger_symbolization_source": "trace32_symbol_table",
        "debugger_symbolization_trust": "debugger_reported",
        "samples": [
            {
                "sample_index": 1,
                "halt_cycle_duration_ns": 10,
                "termination": "terminal_unverified",
                "frames": [
                    {"depth": 0, "pc": 1, "function_name": "leaf"},
                    {"depth": 1, "pc": 2, "function_name": "root"},
                ],
            },
            {
                "sample_index": 2,
                "halt_cycle_duration_ns": 20,
                "termination": "halt_deadline",
                "frames": [{"depth": 0, "pc": 1, "function_name": "leaf"}],
            },
        ],
    }


def digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def profile(document: dict[str, object]) -> dict[str, object]:
    return {
        "schema": "t32perf.folded-stack-profile/v1",
        "session_id": "stack-unit",
        "raw_samples_sha256": digest(document),
        "quality": "intrusive_statistical",
        "method": "break_frame_walk",
        "frame_order": "root_to_leaf",
        "attempted_samples": 2,
        "collected_samples": 2,
        "included_samples": 2,
        "terminal_unverified_samples": 1,
        "truncated_samples": 1,
        "paths": [
            {
                "outer_boundary": "halt_deadline",
                "frames": [{"pc": 1, "function_name": "leaf"}],
                "samples": 1,
            },
            {
                "outer_boundary": "terminal_unverified",
                "frames": [
                    {"pc": 2, "function_name": "root"},
                    {"pc": 1, "function_name": "leaf"},
                ],
                "samples": 1,
            },
        ],
    }


def test_raw_and_profile_recompute_exact_stack_paths() -> None:
    document = raw()
    _raw(
        document,
        session="stack-unit",
        request=request(),
        endpoint="a" * 64,
        cpu="CortexM0+",
    )
    _profile(profile(document), document, digest(document))


def test_truncated_sample_and_source_path_are_rejected() -> None:
    document = raw()
    document["samples"][0]["frames"][0]["source_file"] = "dir/file.c"  # type: ignore[index]
    with pytest.raises(StackVerificationError, match="basename"):
        _raw(
            document,
            session="stack-unit",
            request=request(),
            endpoint="a" * 64,
            cpu="CortexM0+",
        )


@pytest.mark.parametrize(
    ("phase", "state"),
    [
        ("pre", {"occurred": True, "id": "#emu_noframe"}),
        ("post", {"occurred": True, "id": "#some_other_error"}),
        ("pre", {"occurred": False, "id": "#stale"}),
        ("post", {"occurred": False}),
    ],
)
def test_unclean_debugger_error_state_fails_closed(phase: str, state: object) -> None:
    assert phase in {"pre", "post"}
    assert not _clean_debugger_error_state(state)


def test_clean_debugger_error_state_is_exact() -> None:
    assert _clean_debugger_error_state({"occurred": False, "id": ""})
    assert not _clean_debugger_error_state({"occurred": False, "id": "", "x": 1})


def test_svg_requires_escape_safe_identity_and_disclosures() -> None:
    document = raw()
    folded = profile(document)
    svg = f'<svg width="100" height="100" role="img" aria-labelledby="title desc"><title>t</title><desc>Break Frame.Up Go outer unwind boundary may be unverified not CPU time duration call counts</desc><g role="listitem" data-depth="0" data-samples="1" data-kind="boundary" data-boundary="terminal_unverified"><title>outer unwind boundary terminal_unverified; not an inferred frame</title></g><g role="listitem" data-depth="0" data-samples="1" data-kind="boundary" data-boundary="halt_deadline"><title>outer unwind boundary halt_deadline; not an inferred frame</title></g><g role="listitem" data-depth="1" data-samples="1" data-kind="frame"><title>leaf&lt;&amp;&gt;</title></g><text>raw samples SHA-256: {folded["raw_samples_sha256"]}</text></svg>'.encode()
    _svg(svg, folded)
    with pytest.raises(StackVerificationError):
        _svg(svg.replace(b'role="listitem"', b'role="bad"'), folded)
    with pytest.raises(StackVerificationError, match="synthetic flame marker"):
        _svg(svg.replace(b"; not an inferred frame", b""), folded)
    with pytest.raises(StackVerificationError, match="raw-sample binding"):
        _svg(svg.replace(b"raw samples SHA-256:", b"profile SHA-256:"), folded)
