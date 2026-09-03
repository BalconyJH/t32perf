"""One independent hardware entry point for generic PC-sampling HIL."""

from __future__ import annotations

from collections.abc import Iterator
from uuid import uuid4

import pytest

from harness import ProbeLock
from sampling_board import (
    SamplingBoardConfig,
    preflight_sampling_output,
    selected_sampling_board,
)
from sampling_verification import run_sampling_hil


@pytest.fixture
def sampling_board() -> Iterator[SamplingBoardConfig]:
    board = selected_sampling_board()
    if board is None:
        pytest.skip("T32PERF_SAMPLING_HIL_BOARD is not set")
    with ProbeLock(board.lock_file):
        preflight_sampling_output(board)
        yield board


@pytest.mark.hardware
def test_generic_pc_sampling_hil(sampling_board: SamplingBoardConfig) -> None:
    """Capture one uniquely named session through the closed sampling chain."""

    receipt = run_sampling_hil(
        sampling_board,
        session_id=f"sampling-{uuid4().hex}",
    )
    assert receipt["status"] == "PASS"
