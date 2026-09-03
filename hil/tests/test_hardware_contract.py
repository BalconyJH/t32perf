from __future__ import annotations

from collections.abc import Iterator

import pytest

from harness import (
    BoardConfig,
    CaptureEvidenceMatrix,
    HilConfigurationError,
    ProbeLock,
    SessionAudit,
    assert_sampling_buffer_full_health,
    build_recovery_verification,
    capture_evidence,
    preflight_output,
    reserve_recovery_evidence,
    run_expected_failure,
    run_json,
    run_recovery,
    run_recovery_fault_preparation,
    selected_board,
    selected_boards,
    selected_evidence_output,
    verify_doctor_result,
    verify_native_differential,
    write_capture_evidence_matrix,
    write_recovery_verification_receipt,
)


@pytest.fixture
def board() -> Iterator[BoardConfig]:
    config = selected_board()
    if config is None:
        pytest.skip("T32PERF_HIL_BOARD is not set")
    with ProbeLock(config.lock_file):
        preflight_output(config)
        yield config


@pytest.mark.hardware
def test_doctor_fails_closed_for_unknown_trace32_build(board: BoardConfig) -> None:
    result = run_json(board.command("doctor"), cwd=board.path.parent)
    verify_doctor_result(board, result)


@pytest.mark.hardware
@pytest.mark.parametrize("initial_state", ["running", "halted"])
def test_repeatable_capture_from_initial_state(
    board: BoardConfig, initial_state: str
) -> None:
    audit = SessionAudit(board)
    for mode in board.capture_modes:
        for run in range(10):
            run_json(board.command(f"set_{initial_state}"), cwd=board.path.parent)
            result = run_json(
                board.command(
                    "capture",
                    run=run,
                    mode=mode,
                    initial_state=initial_state,
                ),
                cwd=board.path.parent,
            )
            session = audit.verify_driver_result(result, expected_health="VALID")
            capture_evidence(
                board,
                session,
                expected_mode=mode,
                expected_initial_state=initial_state,
            )


@pytest.mark.hardware
def test_sampling_buffer_full_is_independently_invalid(board: BoardConfig) -> None:
    audit = SessionAudit(board)
    assert board.fault_scenarios["sampling_buffer_full"].is_executable
    result = run_json(
        board.fault_command("sampling_buffer_full"), cwd=board.path.parent
    )
    session = audit.verify_driver_result(result, expected_health="INVALID")
    assert_sampling_buffer_full_health(session, board, result)


@pytest.mark.hardware
@pytest.mark.parametrize("scenario", ["trace_overflow", "flow_error", "elf_mismatch"])
def test_unsupported_adapter_fault_is_rejected_without_driver_execution(
    board: BoardConfig, scenario: str
) -> None:
    assert board.fault_scenarios[scenario].support == "unsupported"
    with pytest.raises(HilConfigurationError, match="explicitly unsupported"):
        board.fault_command(scenario)


def _verify_recovery(board: BoardConfig, scenario: str) -> dict[str, object]:
    audit = SessionAudit(board)
    assert board.fault_scenarios[scenario].is_executable
    fault_operation = board.fault_scenarios[scenario].command_operation
    initial_target_state = "running"
    run_json(board.command("set_running"), cwd=board.path.parent)
    preparation = run_recovery_fault_preparation(
        board,
        fault_operation,
        initial_target_state=initial_target_state,
    )
    reservation = reserve_recovery_evidence(
        board,
        fault_operation,
        initial_target_state=initial_target_state,
        binding_sha256=preparation.binding_sha256,
    )
    failure = run_expected_failure(
        board.fault_command(
            scenario,
            binding_sha256=preparation.binding_sha256,
        ),
        cwd=board.path.parent,
        artifact_root=board.artifact_root,
        recovery_evidence=reservation,
    )
    _, recovered_failure = run_recovery(
        board.command("recover", recovery_evidence=reservation.output_path),
        cwd=board.path.parent,
        failure=failure,
    )
    mode = board.capture_modes[0]
    result = run_json(
        board.command(
            "capture",
            run=f"recovery-{fault_operation}",
            mode=mode,
            initial_state=initial_target_state,
        ),
        cwd=board.path.parent,
    )
    session = audit.verify_driver_result(result, expected_health="VALID")
    capture_evidence(
        board,
        session,
        expected_mode=mode,
        expected_initial_state=initial_target_state,
    )
    receipt = build_recovery_verification(session, fault_operation, recovered_failure)
    return write_recovery_verification_receipt(recovered_failure, receipt)


@pytest.mark.hardware
def test_trace32_disconnect_recovers_without_partial_session(
    board: BoardConfig,
) -> None:
    _verify_recovery(board, "trace32_disconnect")


@pytest.mark.hardware
def test_driver_disconnect_recovers_without_partial_session(
    board: BoardConfig,
) -> None:
    _verify_recovery(board, "driver_disconnect")


@pytest.mark.hardware
def test_cmm_abort_recovers_without_partial_session(board: BoardConfig) -> None:
    _verify_recovery(board, "cmm_abort")


@pytest.mark.hardware
def test_native_statistics_match_t32perf_artifacts(board: BoardConfig) -> None:
    audit = SessionAudit(board)
    result = run_json(board.command("native_stats"), cwd=board.path.parent)
    session = audit.verify_driver_result(result, expected_health="VALID")
    verify_native_differential(result, session, tick_ns=board.tick_ns)


@pytest.mark.hardware
def test_two_board_two_mode_evidence_matrix() -> None:
    boards = selected_boards()
    if len(boards) < 2:
        pytest.skip("T32PERF_HIL_BOARDS does not select at least two boards")
    matrix = CaptureEvidenceMatrix()
    for config in boards:
        with ProbeLock(config.lock_file):
            preflight_output(config)
            audit = SessionAudit(config)
            for mode in config.capture_modes:
                for initial_state in ("running", "halted"):
                    for repetition in range(5):
                        run_json(
                            config.command(f"set_{initial_state}"),
                            cwd=config.path.parent,
                        )
                        result = run_json(
                            config.command(
                                "capture",
                                run=f"matrix-{mode}-{initial_state}-{repetition}",
                                mode=mode,
                                initial_state=initial_state,
                            ),
                            cwd=config.path.parent,
                        )
                        session = audit.verify_driver_result(
                            result, expected_health="VALID"
                        )
                        matrix.add(
                            config,
                            session,
                            expected_mode=mode,
                            expected_initial_state=initial_state,
                        )
    matrix.assert_coverage()
    output = selected_evidence_output()
    if output is None:
        pytest.fail(
            "T32PERF_HIL_EVIDENCE_OUTPUT must select a new evidence file for "
            "the multi-board matrix"
        )
    write_capture_evidence_matrix(matrix, output)
