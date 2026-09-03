"""Opt-in real-board entry point for intrusive stack sampling."""

from __future__ import annotations

from collections.abc import Iterator
from uuid import uuid4

import pytest

from harness import ProbeLock
from stack_board import StackBoardConfig, preflight_stack_output, selected_stack_board
from stack_verification import run_stack_hil


@pytest.fixture
def stack_board() -> Iterator[StackBoardConfig]:
    board = selected_stack_board()
    if board is None:
        pytest.skip("T32PERF_STACK_HIL_BOARD is not set")
    with ProbeLock(board.lock_file):
        preflight_stack_output(board)
        yield board


@pytest.mark.hardware
def test_intrusive_stack_sampling_hil(stack_board: StackBoardConfig) -> None:
    receipt = run_stack_hil(stack_board, session_id=f"stack-{uuid4().hex}")
    assert receipt["status"] == "PASS"
