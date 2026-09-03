from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from target_adapter_recovery import (
    RecoveryEvidenceExpectation,
    TargetAdapterFailureBinding,
    TargetAdapterRecoveryEvidence,
    TargetAdapterRecoveryEvidenceError,
    TargetAdapterSamplingRecoveryEvidence,
    load_target_adapter_recovery_evidence,
    reserve_target_adapter_recovery_evidence,
    write_target_adapter_recovery_evidence,
)


def recovery_document(**changes: object) -> dict[str, Any]:
    document = TargetAdapterRecoveryEvidence(
        profile_sha256="a" * 64,
        binding_sha256="b" * 64,
        failed_operation="perf_start",
        failure_kind="cmm_abort",
        initial_target_state="halted",
        restored_target_state="halted",
        adapter_state_restored=True,
        upstream_abort_confirmed=True,
        upstream_abort_receipt_sha256="c" * 64,
        files_deleted=False,
        new_session_required=True,
    ).to_document()
    document.update(changes)
    return document


def expectation(
    *,
    profile_sha256: str = "a" * 64,
    binding_sha256: str = "b" * 64,
    failed_operation: str = "perf_start",
    failure_kind: str = "cmm_abort",
    initial_target_state: str = "halted",
) -> RecoveryEvidenceExpectation:
    return RecoveryEvidenceExpectation(
        profile_sha256=profile_sha256,
        binding_sha256=binding_sha256,
        failed_operation=failed_operation,
        failure_kind=failure_kind,
        initial_target_state=initial_target_state,
    )


def test_recovery_evidence_matches_exported_json_schema(tmp_path: Path) -> None:
    document = recovery_document()
    schema_path = (
        Path(__file__).parents[1]
        / "schemas/target-adapter-recovery-evidence.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)
    loaded = load_target_adapter_recovery_evidence(document)
    assert loaded.evidence.to_document() == document


def test_failure_binding_matches_exported_json_schema() -> None:
    document = TargetAdapterFailureBinding(
        profile_sha256="a" * 64,
        binding_sha256="b" * 64,
        failed_operation="perf_start",
        failure_kind="cmm_abort",
        initial_target_state="halted",
    ).to_document()
    schema_path = (
        Path(__file__).parents[1] / "schemas/target-adapter-failure-binding.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(document)
    assert TargetAdapterFailureBinding.from_document(document).to_document() == document


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"restored_target_state": "running"}, "initial target state"),
        ({"adapter_state_restored": False}, "adapter-owned state"),
        ({"upstream_abort_confirmed": False}, "acknowledgement or receipt"),
        ({"upstream_abort_receipt_sha256": None}, "acknowledgement or receipt"),
        ({"files_deleted": True}, "must not delete"),
        ({"new_session_required": False}, "must require a new Session"),
        ({"binding_sha256": "A" * 64}, "lowercase hexadecimal"),
    ],
)
def test_recovery_evidence_rejects_invalid_semantics(
    changes: dict[str, object], message: str
) -> None:
    with pytest.raises(TargetAdapterRecoveryEvidenceError, match=message):
        load_target_adapter_recovery_evidence(recovery_document(**changes))


def test_recovery_evidence_rejects_duplicate_and_unknown_fields() -> None:
    duplicate = json.dumps(recovery_document()).replace(
        '"profile_sha256":', '"profile_sha256":"0", "profile_sha256":', 1
    )
    with pytest.raises(TargetAdapterRecoveryEvidenceError, match="duplicate JSON key"):
        load_target_adapter_recovery_evidence(duplicate.encode())

    unexpected = recovery_document(extra=True)
    with pytest.raises(TargetAdapterRecoveryEvidenceError, match="unexpected=.*extra"):
        load_target_adapter_recovery_evidence(unexpected)


def test_recovery_evidence_preserves_optional_sampling_baseline() -> None:
    sampling = TargetAdapterSamplingRecoveryEvidence(
        method="real_time",
        object="program_counter",
        buffer_mode="stack",
        state="off",
        requested_rate_ns=1_000_000,
        capacity_records=65_536,
        auto_arm=False,
        auto_init=False,
        zero_reset=True,
    )
    document = recovery_document(
        sampling=sampling.to_document(),
        failure_kind="operation_failure",
    )
    loaded = load_target_adapter_recovery_evidence(document)
    assert loaded.evidence.sampling == sampling
    assert loaded.evidence.upstream_abort_receipt_sha256 == "c" * 64


@pytest.mark.parametrize(
    "failure_kind",
    [
        "trace32_disconnect",
        "driver_disconnect",
        "cmm_abort",
        "operation_failure",
    ],
)
def test_all_recovery_kinds_require_the_canonical_abort_receipt(
    failure_kind: str,
) -> None:
    with pytest.raises(
        TargetAdapterRecoveryEvidenceError, match="acknowledgement or receipt"
    ):
        load_target_adapter_recovery_evidence(
            recovery_document(
                failure_kind=failure_kind,
                upstream_abort_receipt_sha256=None,
            )
        )


def test_recovery_rejects_unpaired_abort_receipt_claims() -> None:
    document = recovery_document(
        failure_kind="driver_disconnect",
        upstream_abort_confirmed=False,
    )
    with pytest.raises(
        TargetAdapterRecoveryEvidenceError, match="acknowledgement or receipt"
    ):
        load_target_adapter_recovery_evidence(document)


def test_optional_sampling_null_matches_rust_option_deserialization() -> None:
    document = recovery_document(sampling=None)
    assert load_target_adapter_recovery_evidence(document).evidence.sampling is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("requested_rate_ns", 999_999),
        ("capacity_records", 65_535),
        ("auto_arm", True),
        ("auto_init", True),
        ("zero_reset", False),
    ],
)
def test_sampling_recovery_requires_the_exact_canonical_baseline(
    field: str, value: object
) -> None:
    sampling = {
        "method": "real_time",
        "object": "program_counter",
        "buffer_mode": "stack",
        "state": "off",
        "requested_rate_ns": 1_000_000,
        "capacity_records": 65_536,
        "auto_arm": False,
        "auto_init": False,
        "zero_reset": True,
    }
    sampling[field] = value
    with pytest.raises(TargetAdapterRecoveryEvidenceError, match="sampling"):
        load_target_adapter_recovery_evidence(recovery_document(sampling=sampling))


def test_harness_reservation_persists_exact_exclusive_evidence(tmp_path: Path) -> None:
    reservation = reserve_target_adapter_recovery_evidence(
        tmp_path / "recovery-root", expectation()
    )
    assert reservation.directory.is_dir()
    assert not reservation.output_path.exists()

    write_target_adapter_recovery_evidence(recovery_document(), reservation.output_path)
    loaded = reservation.load()
    assert loaded.path == reservation.output_path.resolve()
    assert loaded.evidence.binding_sha256 == "b" * 64
    assert len(loaded.sha256) == 64
    assert reservation.output_path.exists()

    with pytest.raises(TargetAdapterRecoveryEvidenceError, match="already exists"):
        write_target_adapter_recovery_evidence(
            recovery_document(), reservation.output_path
        )


def test_harness_reservation_rejects_relabelled_binding_and_profile(
    tmp_path: Path,
) -> None:
    reservation = reserve_target_adapter_recovery_evidence(
        tmp_path / "recovery-root", expectation()
    )
    relabelled = copy.deepcopy(recovery_document())
    relabelled["binding_sha256"] = "c" * 64
    relabelled["profile_sha256"] = "d" * 64
    write_target_adapter_recovery_evidence(relabelled, reservation.output_path)

    with pytest.raises(
        TargetAdapterRecoveryEvidenceError,
        match="binding_sha256.*profile_sha256|profile_sha256.*binding_sha256",
    ):
        reservation.load()


def test_harness_reservation_requires_driver_output(tmp_path: Path) -> None:
    reservation = reserve_target_adapter_recovery_evidence(
        tmp_path / "recovery-root", expectation()
    )

    with pytest.raises(TargetAdapterRecoveryEvidenceError, match="cannot read"):
        reservation.load()
