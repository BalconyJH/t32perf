from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from check_regression import EvidenceError, evaluate, load_evidence


def candidate(
    name: str,
    *,
    throughput: float,
    rss: int,
    observations: int = 1_000_000,
) -> dict[str, object]:
    byte_count = 180_000_000
    elapsed = observations / throughput
    return {
        "ok": True,
        "candidate": name,
        "session_id": "benchmark",
        "observations": observations,
        "bytes": byte_count,
        "dictionary_entries": 20_000,
        "dictionary_bytes": 2_000_000,
        "max_dictionary_entries": 65_536,
        "max_dictionary_bytes": 67_108_864,
        "elapsed_seconds": elapsed,
        "observations_per_second": throughput,
        "bytes_per_second": byte_count / elapsed,
        "peak_rss_bytes_external": rss,
        "rss_sample_interval_ms": 100,
    }


def evidence(*, rust_throughput: float = 300_000, rust_rss: int = 8_000_000):
    return {
        "format": "t32perf-parser-candidates-v1",
        "ok": True,
        "input": "synthetic.ndjson",
        "input_bytes": 180_000_000,
        "input_sha256": "a" * 64,
        "cache_conditioning": "sha256-prepass",
        "candidate_order": ["rust-t32perf-trace32", "python-stdlib"],
        "input_integrity_verified": True,
        "max_dictionary_entries": 65_536,
        "max_dictionary_bytes": 67_108_864,
        "environment": {
            "os": "test-os",
            "arch": "test-arch",
            "python": "3.13.3",
            "source_commit": "b" * 40,
            "runner_image": "test-image",
            "runner_image_version": "1",
        },
        "results": [
            candidate(
                "rust-t32perf-trace32",
                throughput=rust_throughput,
                rss=rust_rss,
            ),
            candidate("python-stdlib", throughput=200_000, rss=20_000_000),
        ],
    }


class RegressionGateTests(unittest.TestCase):
    def test_accepts_candidate_with_relative_and_absolute_headroom(self) -> None:
        report = evaluate(
            evidence(),
            minimum_observations=1_000_000,
            minimum_throughput_ratio=1.1,
            maximum_rss_ratio=0.75,
            maximum_rust_rss_bytes=64 * 1024 * 1024,
        )
        self.assertTrue(report["passed"])
        self.assertEqual(report["dataset"]["observations"], 1_000_000)

    def test_reports_regression_without_treating_it_as_invalid_evidence(self) -> None:
        report = evaluate(
            evidence(rust_throughput=190_000, rust_rss=18_000_000),
            minimum_observations=1_000_000,
            minimum_throughput_ratio=1.1,
            maximum_rss_ratio=0.75,
            maximum_rust_rss_bytes=64 * 1024 * 1024,
        )
        self.assertFalse(report["passed"])
        self.assertEqual(
            [check["passed"] for check in report["checks"]], [False, False, True]
        )

    def test_rejects_mismatched_dataset_claims(self) -> None:
        document = evidence()
        document["results"][1]["observations"] = 999_999
        with self.assertRaisesRegex(EvidenceError, "claims differ"):
            evaluate(
                document,
                minimum_observations=1,
                minimum_throughput_ratio=1.1,
                maximum_rss_ratio=0.75,
                maximum_rust_rss_bytes=64 * 1024 * 1024,
            )

        document = evidence()
        document["results"][1]["session_id"] = "other"
        with self.assertRaisesRegex(EvidenceError, "session_id.*claims differ"):
            evaluate(
                document,
                minimum_observations=1,
                minimum_throughput_ratio=1.1,
                maximum_rss_ratio=0.75,
                maximum_rust_rss_bytes=64 * 1024 * 1024,
            )

    def test_rejects_wrong_format_and_inconsistent_runner_claims(self) -> None:
        document = evidence()
        document["format"] = "unknown"
        with self.assertRaisesRegex(EvidenceError, "format"):
            evaluate(
                document,
                minimum_observations=1,
                minimum_throughput_ratio=1.1,
                maximum_rss_ratio=0.75,
                maximum_rust_rss_bytes=64 * 1024 * 1024,
            )

        document = evidence()
        document["cache_conditioning"] = "none"
        with self.assertRaisesRegex(EvidenceError, "cache_conditioning"):
            evaluate(
                document,
                minimum_observations=1,
                minimum_throughput_ratio=1.1,
                maximum_rss_ratio=0.75,
                maximum_rust_rss_bytes=64 * 1024 * 1024,
            )

        document = evidence()
        document["candidate_order"].reverse()
        with self.assertRaisesRegex(EvidenceError, "candidate_order"):
            evaluate(
                document,
                minimum_observations=1,
                minimum_throughput_ratio=1.1,
                maximum_rss_ratio=0.75,
                maximum_rust_rss_bytes=64 * 1024 * 1024,
            )

        document = evidence()
        document["results"].reverse()
        with self.assertRaisesRegex(EvidenceError, "result order"):
            evaluate(
                document,
                minimum_observations=1,
                minimum_throughput_ratio=1.1,
                maximum_rss_ratio=0.75,
                maximum_rust_rss_bytes=64 * 1024 * 1024,
            )

        document = evidence()
        document["input_integrity_verified"] = False
        with self.assertRaisesRegex(EvidenceError, "input_integrity_verified"):
            evaluate(
                document,
                minimum_observations=1,
                minimum_throughput_ratio=1.1,
                maximum_rss_ratio=0.75,
                maximum_rust_rss_bytes=64 * 1024 * 1024,
            )

        document = evidence()
        document["input_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(EvidenceError, "SHA-256"):
            evaluate(
                document,
                minimum_observations=1,
                minimum_throughput_ratio=1.1,
                maximum_rss_ratio=0.75,
                maximum_rust_rss_bytes=64 * 1024 * 1024,
            )

        document = evidence()
        document["environment"]["unexpected"] = True
        with self.assertRaisesRegex(EvidenceError, "unknown fields"):
            evaluate(
                document,
                minimum_observations=1,
                minimum_throughput_ratio=1.1,
                maximum_rss_ratio=0.75,
                maximum_rust_rss_bytes=64 * 1024 * 1024,
            )

        document = evidence()
        document["input_bytes"] = 1
        with self.assertRaisesRegex(EvidenceError, "runner `bytes` claim differs"):
            evaluate(
                document,
                minimum_observations=1,
                minimum_throughput_ratio=1.1,
                maximum_rss_ratio=0.75,
                maximum_rust_rss_bytes=64 * 1024 * 1024,
            )

    def test_rejects_candidate_status_sampling_and_rate_inconsistency(self) -> None:
        document = evidence()
        document["results"][0]["ok"] = False
        with self.assertRaisesRegex(EvidenceError, "ok: true"):
            evaluate(
                document,
                minimum_observations=1,
                minimum_throughput_ratio=1.1,
                maximum_rss_ratio=0.75,
                maximum_rust_rss_bytes=64 * 1024 * 1024,
            )

        document = evidence()
        document["results"][1]["rss_sample_interval_ms"] = 50
        with self.assertRaisesRegex(EvidenceError, "rss_sample_interval_ms"):
            evaluate(
                document,
                minimum_observations=1,
                minimum_throughput_ratio=1.1,
                maximum_rss_ratio=0.75,
                maximum_rust_rss_bytes=64 * 1024 * 1024,
            )

        document = evidence()
        document["results"][0]["observations_per_second"] = 1
        with self.assertRaisesRegex(EvidenceError, "inconsistent"):
            evaluate(
                document,
                minimum_observations=1,
                minimum_throughput_ratio=1.1,
                maximum_rss_ratio=0.75,
                maximum_rust_rss_bytes=64 * 1024 * 1024,
            )

    def test_loader_rejects_duplicate_keys_and_oversized_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text('{"ok":true,"ok":false}', encoding="utf-8")
            with self.assertRaisesRegex(EvidenceError, "duplicate JSON key"):
                load_evidence(duplicate)

            oversized = Path(directory) / "oversized.json"
            oversized.write_bytes(b" " * (1024 * 1024 + 1))
            with self.assertRaisesRegex(EvidenceError, "maximum"):
                load_evidence(oversized)

    def test_report_is_json_serializable(self) -> None:
        report = evaluate(
            evidence(),
            minimum_observations=1_000_000,
            minimum_throughput_ratio=1.1,
            maximum_rss_ratio=0.75,
            maximum_rust_rss_bytes=64 * 1024 * 1024,
        )
        json.dumps(report, allow_nan=False)


if __name__ == "__main__":
    unittest.main()
