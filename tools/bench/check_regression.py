#!/usr/bin/env python3
"""Apply deterministic relative performance budgets to parser candidates."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

MAX_EVIDENCE_BYTES = 1024 * 1024
RUST_CANDIDATE = "rust-t32perf-trace32"
PYTHON_CANDIDATE = "python-stdlib"
INPUT_FORMAT = "t32perf-parser-candidates-v1"
REPORT_FORMAT = "t32perf-benchmark-regression-v1"
CACHE_CONDITIONING = "sha256-prepass"
CANDIDATE_ORDER = [RUST_CANDIDATE, PYTHON_CANDIDATE]


class EvidenceError(ValueError):
    """The benchmark evidence is malformed or internally inconsistent."""


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key `{key}`")
        result[key] = value
    return result


def load_evidence(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise EvidenceError(f"cannot stat evidence: {error}") from error
    if size > MAX_EVIDENCE_BYTES:
        raise EvidenceError(
            f"evidence is {size} bytes; maximum is {MAX_EVIDENCE_BYTES} bytes"
        )
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise EvidenceError(f"cannot read UTF-8 evidence: {error}") from error
    try:
        value = json.loads(text, object_pairs_hook=reject_duplicate_pairs)
    except (json.JSONDecodeError, EvidenceError) as error:
        raise EvidenceError(f"invalid evidence JSON: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError("evidence root must be an object")
    return value


def finite_number(document: dict[str, Any], field: str) -> float:
    value = document.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceError(f"`{field}` must be a finite positive number")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise EvidenceError(f"`{field}` must be a finite positive number")
    return result


def positive_integer(document: dict[str, Any], field: str) -> int:
    value = document.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise EvidenceError(f"`{field}` must be a positive integer")
    return value


def sha256_digest(document: dict[str, Any], field: str) -> str:
    value = document.get(field)
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise EvidenceError(f"`{field}` must be a lowercase SHA-256 digest")
    return value


def nonempty_string(document: dict[str, Any], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"`{field}` must be a non-empty string")
    return value


def environment_claim(evidence: dict[str, Any]) -> dict[str, Any]:
    environment = evidence.get("environment")
    if not isinstance(environment, dict):
        raise EvidenceError("evidence `environment` must be an object")
    expected_fields = {
        "os",
        "arch",
        "python",
        "source_commit",
        "runner_image",
        "runner_image_version",
    }
    unknown_fields = set(environment) - expected_fields
    if unknown_fields:
        raise EvidenceError(
            f"environment contains unknown fields: {sorted(unknown_fields)}"
        )
    for field in ("os", "arch", "python"):
        value = environment.get(field)
        if not isinstance(value, str) or not value:
            raise EvidenceError(f"environment `{field}` must be a non-empty string")
    source_commit = environment.get("source_commit")
    if source_commit is not None and (
        not isinstance(source_commit, str)
        or len(source_commit) != 40
        or any(character not in "0123456789abcdef" for character in source_commit)
    ):
        raise EvidenceError(
            "environment `source_commit` must be null or a lowercase 40-character commit"
        )
    for field in ("runner_image", "runner_image_version"):
        value = environment.get(field)
        if value is not None and (not isinstance(value, str) or not value):
            raise EvidenceError(f"environment `{field}` must be null or a string")
    return environment


def candidate_map(evidence: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if evidence.get("format") != INPUT_FORMAT:
        raise EvidenceError(f"evidence `format` must be `{INPUT_FORMAT}`")
    if evidence.get("ok") is not True:
        raise EvidenceError("benchmark runner did not report `ok: true`")
    if evidence.get("cache_conditioning") != CACHE_CONDITIONING:
        raise EvidenceError(
            f"evidence `cache_conditioning` must be `{CACHE_CONDITIONING}`"
        )
    if evidence.get("candidate_order") != CANDIDATE_ORDER:
        raise EvidenceError(f"evidence `candidate_order` must be {CANDIDATE_ORDER!r}")
    if evidence.get("input_integrity_verified") is not True:
        raise EvidenceError("evidence must report `input_integrity_verified: true`")
    input_path = evidence.get("input")
    if not isinstance(input_path, str) or not input_path:
        raise EvidenceError("evidence `input` must be a non-empty string")
    results = evidence.get("results")
    if not isinstance(results, list) or len(results) != 2:
        raise EvidenceError("evidence must contain exactly two candidate results")
    by_name: dict[str, dict[str, Any]] = {}
    observed_order: list[str] = []
    for result in results:
        if not isinstance(result, dict):
            raise EvidenceError("candidate result must be an object")
        if result.get("ok") is not True:
            raise EvidenceError("candidate result did not report `ok: true`")
        name = result.get("candidate")
        if not isinstance(name, str) or not name:
            raise EvidenceError("candidate result must have a non-empty name")
        if name in by_name:
            raise EvidenceError(f"duplicate candidate `{name}`")
        by_name[name] = result
        observed_order.append(name)
    expected = {RUST_CANDIDATE, PYTHON_CANDIDATE}
    if set(by_name) != expected:
        raise EvidenceError(
            f"candidate set must be {sorted(expected)}, got {sorted(by_name)}"
        )
    if observed_order != CANDIDATE_ORDER:
        raise EvidenceError(
            "candidate result order differs from the declared deterministic order"
        )
    return by_name


def evaluate(
    evidence: dict[str, Any],
    *,
    minimum_observations: int,
    minimum_throughput_ratio: float,
    maximum_rss_ratio: float,
    maximum_rust_rss_bytes: int,
) -> dict[str, Any]:
    candidates = candidate_map(evidence)
    input_sha256 = sha256_digest(evidence, "input_sha256")
    environment = environment_claim(evidence)
    rust = candidates[RUST_CANDIDATE]
    python = candidates[PYTHON_CANDIDATE]
    rust_session_id = nonempty_string(rust, "session_id")
    python_session_id = nonempty_string(python, "session_id")
    if rust_session_id != python_session_id:
        raise EvidenceError(
            "candidate `session_id` claims differ: "
            f"rust={rust_session_id!r}, python={python_session_id!r}"
        )

    matching_integer_fields = (
        "observations",
        "bytes",
        "dictionary_entries",
        "dictionary_bytes",
        "max_dictionary_entries",
        "max_dictionary_bytes",
    )
    claims: dict[str, int] = {}
    for field in matching_integer_fields:
        rust_value = positive_integer(rust, field)
        python_value = positive_integer(python, field)
        if rust_value != python_value:
            raise EvidenceError(
                f"candidate `{field}` claims differ: rust={rust_value}, "
                f"python={python_value}"
            )
        claims[field] = rust_value
    root_claims = {
        "bytes": positive_integer(evidence, "input_bytes"),
        "max_dictionary_entries": positive_integer(evidence, "max_dictionary_entries"),
        "max_dictionary_bytes": positive_integer(evidence, "max_dictionary_bytes"),
    }
    for field, root_value in root_claims.items():
        if claims[field] != root_value:
            raise EvidenceError(
                f"runner `{field}` claim differs from candidates: "
                f"runner={root_value}, candidates={claims[field]}"
            )
    if claims["observations"] < minimum_observations:
        raise EvidenceError(
            f"evidence has {claims['observations']} observations; "
            f"minimum is {minimum_observations}"
        )

    sample_interval_ms = positive_integer(rust, "rss_sample_interval_ms")
    python_sample_interval_ms = positive_integer(python, "rss_sample_interval_ms")
    if sample_interval_ms != python_sample_interval_ms:
        raise EvidenceError(
            "candidate `rss_sample_interval_ms` claims differ: "
            f"rust={sample_interval_ms}, python={python_sample_interval_ms}"
        )

    rust_throughput = validated_rate(rust, claims, "observations_per_second")
    python_throughput = validated_rate(python, claims, "observations_per_second")
    validated_rate(rust, claims, "bytes_per_second")
    validated_rate(python, claims, "bytes_per_second")
    rust_rss = positive_integer(rust, "peak_rss_bytes_external")
    python_rss = positive_integer(python, "peak_rss_bytes_external")
    throughput_ratio = rust_throughput / python_throughput
    rss_ratio = rust_rss / python_rss

    checks = [
        {
            "name": "rust_throughput_relative_to_python",
            "passed": throughput_ratio >= minimum_throughput_ratio,
            "actual": throughput_ratio,
            "minimum": minimum_throughput_ratio,
        },
        {
            "name": "rust_peak_rss_relative_to_python",
            "passed": rss_ratio <= maximum_rss_ratio,
            "actual": rss_ratio,
            "maximum": maximum_rss_ratio,
        },
        {
            "name": "rust_peak_rss_absolute",
            "passed": rust_rss <= maximum_rust_rss_bytes,
            "actual_bytes": rust_rss,
            "maximum_bytes": maximum_rust_rss_bytes,
        },
    ]
    passed = all(check["passed"] for check in checks)
    return {
        "format": REPORT_FORMAT,
        "passed": passed,
        "dataset": {
            **claims,
            "session_id": rust_session_id,
            "input_sha256": input_sha256,
            "rss_sample_interval_ms": sample_interval_ms,
        },
        "environment": environment,
        "measurements": {
            "rust_observations_per_second": rust_throughput,
            "python_observations_per_second": python_throughput,
            "rust_peak_rss_bytes": rust_rss,
            "python_peak_rss_bytes": python_rss,
        },
        "checks": checks,
        "limitations": [
            "Relative budgets compare candidates in one fixed-order sequential run.",
            "A SHA-256 prepass conditions the OS page cache, so cold-storage throughput is excluded.",
            "External RSS polling can miss peaks shorter than the sampling interval.",
            "Synthetic canonical input does not validate TRACE32 compatibility.",
        ],
    }


def validated_rate(
    candidate: dict[str, Any], claims: dict[str, int], field: str
) -> float:
    """Validate a reported rate against its count and elapsed-time claims."""

    elapsed = finite_number(candidate, "elapsed_seconds")
    rate = finite_number(candidate, field)
    numerator_field = "observations" if field == "observations_per_second" else "bytes"
    expected = claims[numerator_field] / elapsed
    if not math.isclose(rate, expected, rel_tol=1e-9, abs_tol=1e-9):
        name = candidate.get("candidate", "unknown")
        raise EvidenceError(
            f"candidate `{name}` has inconsistent `{field}` and `elapsed_seconds`"
        )
    return rate


def positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite positive number")
    return parsed


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--minimum-observations", type=positive_int, default=1_000_000)
    parser.add_argument("--minimum-throughput-ratio", type=positive_float, default=1.10)
    parser.add_argument("--maximum-rss-ratio", type=positive_float, default=0.75)
    parser.add_argument(
        "--maximum-rust-rss-bytes", type=positive_int, default=64 * 1024 * 1024
    )
    arguments = parser.parse_args()
    try:
        report = evaluate(
            load_evidence(arguments.evidence),
            minimum_observations=arguments.minimum_observations,
            minimum_throughput_ratio=arguments.minimum_throughput_ratio,
            maximum_rss_ratio=arguments.maximum_rss_ratio,
            maximum_rust_rss_bytes=arguments.maximum_rust_rss_bytes,
        )
    except EvidenceError as error:
        print(
            json.dumps(
                {
                    "format": REPORT_FORMAT,
                    "passed": False,
                    "error": str(error),
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
