from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from lauterbach_sampling_mcp.model import (
    InputError,
    endpoint_fingerprint,
    probe_fingerprint,
)
from lauterbach_sampling_mcp.stack_model import StackCaptureRequest
from lauterbach_sampling_mcp.stack_service import (
    StackSamplingError,
    StackSamplingService,
)
from lauterbach_sampling_mcp.stack_storage import (
    MAX_STACK_DRIVER_EVENTS,
    MAX_STACK_EVENT_BYTES,
    StackJournal,
)
from lauterbach_sampling_mcp.storage import StorageError


class Functions:
    def __init__(self) -> None:
        self.running, self.index = True, 0
        self.pcs: list[int | Exception] = [0x1000, 0x2000]
        self.error_occurred, self.error_id = False, ""

    def core_number(self):
        return 1

    def core(self):
        return 0

    def state_power(self):
        return True

    def state_run(self):
        return self.running

    def state_halt(self):
        return not self.running

    def state_processor(self):
        return "CortexM0+"

    def perf_state(self):
        return 0

    def software_version(self):
        return "R.2026.02"

    def software_build(self):
        return 1

    def __call__(self, value):
        if value == "ERROR.OCCURRED()":
            return self.error_occurred
        if value == "ERROR.ID()":
            return self.error_id
        if value == "Register(PC)":
            return self.pcs[self.index]
        if value == "VERSION.SERIAL.DEBUG()":
            return "debug"
        if value == "VERSION.SERIAL.CABLE()":
            return "cable"
        if value == "SYStem.CONFIG.DEBUGPORT()":
            return "port"
        if value.startswith("sYmbol.FUNCTION"):
            return f"f{self.index}"
        if value.startswith("sYmbol.SOURCEFILE"):
            return "C:\\secret\\source.c"
        if value.startswith("sYmbol.SOURCELINE"):
            return 11 + self.index
        raise RuntimeError(value)


class Debugger:
    def __init__(self):
        self.fnc, self.commands = Functions(), []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def break_(self):
        self.fnc.running = False

    def go(self):
        self.fnc.running = True

    def cmd(self, command):
        self.commands.append(command)
        if command == "Frame.Up":
            self.fnc.index = min(self.fnc.index + 1, 1)
        elif command == "Frame.Down":
            self.fnc.index = max(self.fnc.index - 1, 0)
        elif command == "ERROR.RESet":
            self.fnc.error_occurred, self.fnc.error_id = False, ""


def request(**changes):
    value = {
        "session_id": "stack-1",
        "operation_id": "b" * 32,
        "acknowledge_intrusive": True,
        "sample_period_ms": 10,
        "duration_ms": 100,
        "max_samples": 1,
        "max_frames": 2,
        "core_id": 0,
        "address_space": "P",
    }
    value.update(changes)
    return StackCaptureRequest.parse(value)


def root(tmp_path: Path, item: StackCaptureRequest) -> Path:
    session = tmp_path / item.session_id
    for name in (
        "capture/raw",
        "capture/staging",
        "normalized",
        "analysis",
        "report",
        "logs",
        "artifact-index",
        "ingest-intents",
        "committed-staging-sources",
    ):
        (session / name).mkdir(parents=True, exist_ok=True)
    (session / ".session.lock").touch()
    (session / "state.json").write_text(
        json.dumps(
            {
                "schema": "t32perf.state/v1",
                "created_at": "2026-09-01T00:00:00Z",
                "state": "created",
                "operation_id": item.operation_id,
                "revision": 0,
                "updated_at": "2026-09-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (session / "request.json").write_text(
        json.dumps(item.authorization_document()), encoding="utf-8"
    )
    return tmp_path


def service(root: Path, debugger: Debugger, *, recover=False):
    fp = endpoint_fingerprint(
        "localhost",
        20001,
        "TCP",
        "R.2026.02+1",
        probe_fingerprint("debug", "cable", "port"),
    )
    return StackSamplingService(
        host="localhost",
        port=20001,
        protocol="TCP",
        timeout=1,
        artifact_root=root,
        expected_endpoint_fingerprint=fp,
        recover_quarantined=recover,
        connector=lambda **_: debugger,
    )


def test_capture_walks_stack_redacts_path_and_restores_running(tmp_path: Path):
    item, debugger = request(), Debugger()
    result = service(root(tmp_path, item), debugger).capture(item)
    assert result["summary"]["collected_samples"] == 1
    raw = json.loads(
        (tmp_path / item.session_id / result["artifact"]["relative_path"]).read_text()
    )
    assert [frame["pc"] for frame in raw["samples"][0]["frames"]] == [0x1000, 0x2000]
    assert raw["samples"][0]["frames"][0]["source_file"] == "source.c"
    assert debugger.fnc.running and debugger.commands.count("Frame.Down") == 1


def test_capabilities_exposes_an_inconsistent_debugger_error_state(tmp_path: Path):
    item, debugger = request(), Debugger()
    debugger.fnc.error_id = " \0 stale text \0 "
    result = service(root(tmp_path, item), debugger).capabilities()
    assert result["debugger_error_state"] == {
        "occurred": False,
        "id": "stale text",
    }

    with pytest.raises(StackSamplingError, match="stale text"):
        service(tmp_path, debugger).capture(item)
    assert debugger.commands == []
    assert debugger.fnc.running is True


def test_capture_rejects_a_preexisting_debugger_error_before_break(tmp_path: Path):
    class CountingDebugger(Debugger):
        def __init__(self):
            super().__init__()
            self.breaks = 0

        def break_(self):
            self.breaks += 1
            super().break_()

    item, debugger = request(), CountingDebugger()
    debugger.fnc.error_occurred, debugger.fnc.error_id = True, " #other\0 "
    with pytest.raises(StackSamplingError, match="#other"):
        service(root(tmp_path, item), debugger).capture(item)
    assert debugger.breaks == 0
    assert debugger.fnc.error_id == " #other\0 "


def test_expected_noframe_is_reset_only_after_owned_go(tmp_path: Path):
    class NoFrameDebugger(Debugger):
        def cmd(self, command):
            if command == "Frame.Up":
                self.commands.append(command)
                self.fnc.error_occurred, self.fnc.error_id = True, " \0#emu_noframe\0 "
                raise RuntimeError("end of frame")
            super().cmd(command)

    item, debugger = request(), NoFrameDebugger()
    result = service(root(tmp_path, item), debugger).capture(item)
    assert result["summary"]["collected_samples"] == 1
    assert debugger.fnc.running is True
    assert debugger.commands == ["Frame.Up", "ERROR.RESet"]
    assert debugger.fnc.error_occurred is False
    assert debugger.fnc.error_id == ""


def test_unexpected_frame_up_error_is_not_cleared_and_owned_go_runs(tmp_path: Path):
    class UnexpectedFrameErrorDebugger(Debugger):
        def cmd(self, command):
            if command == "Frame.Up":
                self.commands.append(command)
                self.fnc.error_occurred, self.fnc.error_id = True, "#other"
                raise RuntimeError("frame failure")
            super().cmd(command)

    item, debugger = request(), UnexpectedFrameErrorDebugger()
    with pytest.raises(StackSamplingError, match="Frame.Up failed"):
        service(root(tmp_path, item), debugger).capture(item)
    assert debugger.fnc.running is True
    assert debugger.fnc.error_occurred is True
    assert debugger.fnc.error_id == "#other"
    assert "ERROR.RESet" not in debugger.commands


def test_cancellation_after_a_successful_up_restores_frame_context_and_go(
    tmp_path: Path,
):
    event = threading.Event()

    class CancellingAfterUpDebugger(Debugger):
        def cmd(self, command):
            super().cmd(command)
            if command == "Frame.Up":
                event.set()

    item, debugger = request(max_frames=3), CancellingAfterUpDebugger()
    with pytest.raises(StackSamplingError, match="cancelled"):
        service(root(tmp_path, item), debugger).capture(item, event)
    assert debugger.fnc.running is True
    assert debugger.commands.count("Frame.Up") == 1
    assert debugger.commands.count("Frame.Down") == 1


@pytest.mark.parametrize(
    "changes",
    [{"acknowledge_intrusive": False}, {"sample_period_ms": 9}, {"max_frames": 65}],
)
def test_requires_explicit_bounded_acknowledgement(changes):
    with pytest.raises(InputError):
        request(**changes)


def test_rejects_unimplemented_core_selection():
    with pytest.raises(InputError, match="core_id is fixed to 0"):
        request(core_id=1)


@pytest.mark.parametrize("member,value", (("core_number", 2), ("core", 1)))
def test_rejects_ambiguous_trace32_core_selection(
    tmp_path: Path, member: str, value: int
):
    item, debugger = request(), Debugger()
    setattr(debugger.fnc, member, lambda: value)
    with pytest.raises(StackSamplingError, match="logical core"):
        service(root(tmp_path, item), debugger).capabilities()


def test_unfinished_journal_requires_explicit_recovery(tmp_path: Path):
    item, debugger = request(), Debugger()
    directory = root(tmp_path, item) / ".t32perf-control" / "stack-driver-events"
    directory.mkdir(parents=True)
    fp = endpoint_fingerprint(
        "localhost",
        20001,
        "TCP",
        "R.2026.02+1",
        probe_fingerprint("debug", "cable", "port"),
    )
    (directory / "x.json").write_text(
        json.dumps(
            {
                "schema": "t32perf.stack-driver-event/v1",
                "transaction_id": "x",
                "endpoint_fingerprint": fp,
                "endpoint_fingerprint_scheme": "t32perf.endpoint-fingerprint/v2",
                "owner": "lauterbach-stack-sampling-mcp/v1",
                "event": "capture_intent",
                "sequence": 1,
                "observed_at": "x",
                "details": {"initial_running": True},
            }
        )
    )
    with pytest.raises(StorageError):
        service(tmp_path, debugger).capture(item)


def test_journal_rejects_sequence_gap_after_a_later_completed_cycle(tmp_path: Path):
    item = request(max_samples=2)
    root(tmp_path, item)
    fp = endpoint_fingerprint(
        "localhost",
        20001,
        "TCP",
        "R.2026.02+1",
        probe_fingerprint("debug", "cable", "port"),
    )
    journal = StackJournal(tmp_path, fp)
    transaction = "123e4567-e89b-42d3-a456-426614174000"
    journal.reserve_transaction(transaction, 2)
    journal.append(
        transaction,
        "capture_intent",
        {
            "initial_running": True,
            "duration_ms": 100,
            "sample_period_ms": 10,
            "max_samples": 2,
            "max_frames": 2,
        },
    )
    for index in (1, 2):
        for event in ("break_intent", "break_observed", "go_intent", "go_observed"):
            journal.append(transaction, event, {"sample_index": index})
    (journal.directory / f"{transaction}-00000005.json").unlink()
    with pytest.raises(StorageError, match="sequence"):
        StackJournal(tmp_path, fp)


class FrameDebugger:
    def __init__(self, pcs: list[int | Exception]) -> None:
        self.pcs, self.index, self.commands = pcs, 0, []

    def fnc(self, expression):
        if expression == "Register(PC)":
            value = self.pcs[self.index]
            if isinstance(value, Exception):
                raise value
            return value
        raise RuntimeError(expression)

    def cmd(self, command):
        self.commands.append(command)
        if command == "Frame.Up":
            self.index += 1


def test_frame_read_failure_after_up_restores_exact_frame_count(tmp_path: Path):
    debugger = FrameDebugger([0x1000, RuntimeError("PC")])
    _, terminal = service(root(tmp_path, request()), Debugger())._frames(debugger, 2)
    assert terminal == "pc_read_failed"
    assert debugger.commands == ["Frame.Up", "Frame.Down"]


def test_max_depth_does_not_walk_beyond_last_frame(tmp_path: Path):
    debugger = FrameDebugger([0x1000, 0x2000])
    _, terminal = service(root(tmp_path, request()), Debugger())._frames(debugger, 2)
    assert terminal == "max_frames"
    assert debugger.commands == ["Frame.Up", "Frame.Down"]


def test_halt_deadline_prioritizes_go_after_a_slow_frame_operation(
    tmp_path: Path,
):
    class SlowFrameDebugger(Debugger):
        def cmd(self, command):
            if command == "Frame.Up" and not self.commands:
                time.sleep(1.1)
            super().cmd(command)

    item, debugger = request(max_frames=3), SlowFrameDebugger()
    sampler = service(root(tmp_path, item), debugger)
    result = sampler.capture(item)
    raw = json.loads(
        (tmp_path / item.session_id / result["artifact"]["relative_path"]).read_text()
    )
    assert raw["samples"][0]["termination"] == "halt_deadline"
    assert debugger.fnc.running is True
    assert debugger.commands.count("Frame.Up") == 1
    assert debugger.commands.count("Frame.Up") == debugger.commands.count("Frame.Down")


def test_fast_path_collects_the_full_v1_depth_bound(tmp_path: Path):
    item, debugger = request(max_frames=8), Debugger()
    result = service(root(tmp_path, item), debugger).capture(item)
    raw = json.loads(
        (tmp_path / item.session_id / result["artifact"]["relative_path"]).read_text()
    )
    assert len(raw["samples"][0]["frames"]) == 8
    assert debugger.commands.count("Frame.Up") == 7
    assert debugger.commands.count("Frame.Up") == debugger.commands.count("Frame.Down")


def test_multiple_slow_frame_downs_stay_inside_transport_grace(tmp_path: Path):
    class SlowDownDebugger(Debugger):
        def cmd(self, command):
            if command == "Frame.Down":
                time.sleep(0.05)
            super().cmd(command)

    item, debugger = request(max_frames=3), SlowDownDebugger()
    started = time.monotonic()
    service(root(tmp_path, item), debugger).capture(item)
    assert time.monotonic() - started < 2
    assert debugger.fnc.running is True
    assert debugger.commands.count("Frame.Up") == debugger.commands.count("Frame.Down")


def test_first_pc_failure_fails_only_after_its_owned_go(tmp_path: Path):
    class FirstFrameFailure(Debugger):
        def __init__(self):
            super().__init__()
            self.fnc.pcs = [RuntimeError("PC")]

    item, debugger = request(max_frames=1), FirstFrameFailure()
    with pytest.raises(StackSamplingError, match="without a frame"):
        service(root(tmp_path, item), debugger).capture(item)
    assert debugger.fnc.running is True


def test_deadline_before_first_pc_emits_no_frame(tmp_path: Path):
    sampler = service(root(tmp_path, request()), Debugger())
    frames, terminal = sampler._frames(
        Debugger(), 1, time.monotonic() - 1, threading.Event()
    )
    assert frames == []
    assert terminal == "halt_deadline"


def test_same_pc_with_distinct_sp_is_not_a_frame_cycle(tmp_path: Path):
    class RecursiveDebugger:
        def __init__(self):
            self.index, self.commands = 0, []

        def fnc(self, expression):
            if expression == "Register(PC)":
                return 0x1000
            if expression == "Register(SP)":
                return (0x2000, 0x1FF0)[self.index]
            raise RuntimeError(expression)

        def cmd(self, command):
            self.commands.append(command)
            if command == "Frame.Up":
                self.index += 1

    frames, terminal = service(root(tmp_path, request()), Debugger())._frames(
        RecursiveDebugger(), 2
    )
    assert terminal == "max_frames"
    assert [frame["pc"] for frame in frames] == [0x1000, 0x1000]


def test_symbol_queries_only_run_after_the_owned_halt_has_been_released(
    tmp_path: Path,
):
    class StrictFunctions(Functions):
        def __call__(self, value):
            if value.startswith("sYmbol.") and not self.running:
                raise AssertionError("symbol lookup while stopped")
            return super().__call__(value)

    debugger = Debugger()
    debugger.fnc = StrictFunctions()
    item = request()
    service(root(tmp_path, item), debugger).capture(item)
    assert debugger.fnc.running is True


def test_external_stop_after_owned_go_is_never_resumed(tmp_path: Path):
    class ExternalStopFunctions(Functions):
        def __call__(self, value):
            if value.startswith("sYmbol.FUNCTION"):
                self.running = False
            return super().__call__(value)

    debugger = Debugger()
    debugger.fnc = ExternalStopFunctions()
    item = request()
    with pytest.raises(StackSamplingError, match="externally"):
        service(root(tmp_path, item), debugger).capture(item)
    assert debugger.commands.count("Frame.Up") == 1
    assert debugger.fnc.running is False


def test_cancelled_capture_does_not_begin_a_second_break_and_restores_owned_halt(
    tmp_path: Path,
):
    class CancellingFunctions(Functions):
        def __init__(self, event):
            super().__init__()
            self.event = event

        def __call__(self, value):
            if value == "Register(PC)":
                self.event.set()
            return super().__call__(value)

    event = threading.Event()

    class CountingDebugger(Debugger):
        def __init__(self):
            super().__init__()
            self.breaks = 0

        def break_(self):
            self.breaks += 1
            super().break_()

    debugger = CountingDebugger()
    debugger.fnc = CancellingFunctions(event)
    item = request(max_samples=2, max_frames=2)
    started = time.monotonic()
    with pytest.raises(StackSamplingError, match="cancelled"):
        service(root(tmp_path, item), debugger).capture(item, event)
    assert time.monotonic() - started < 2
    assert debugger.fnc.running is True
    assert debugger.breaks == 1
    event.clear()
    debugger.fnc = Functions()
    with pytest.raises(StorageError, match="already consumed"):
        service(tmp_path, debugger).capture(item)
    assert debugger.breaks == 1


def test_capture_never_uses_recovery_authority(tmp_path: Path):
    item, debugger = request(), Debugger()
    root(tmp_path, item)
    fingerprint = endpoint_fingerprint(
        "localhost",
        20001,
        "TCP",
        "R.2026.02+1",
        probe_fingerprint("debug", "cable", "port"),
    )
    journal = StackJournal(tmp_path, fingerprint)
    transaction = "123e4567-e89b-42d3-a456-426614174000"
    journal.reserve_transaction(transaction, 1)
    journal.append(
        transaction,
        "capture_intent",
        {
            "initial_running": True,
            "duration_ms": 100,
            "sample_period_ms": 10,
            "max_samples": 1,
            "max_frames": 1,
        },
    )
    journal.append(transaction, "break_intent", {"sample_index": 1})
    debugger.fnc.running = False
    sampler = service(tmp_path, debugger, recover=True)
    with pytest.raises(StorageError, match="requires --recover-quarantined"):
        sampler.capture(item)
    assert debugger.fnc.running is False
    assert sampler.recover_quarantined is True


def test_recover_only_consumes_authority_without_starting_a_capture(tmp_path: Path):
    item, debugger = request(), Debugger()
    root(tmp_path, item)
    fingerprint = endpoint_fingerprint(
        "localhost",
        20001,
        "TCP",
        "R.2026.02+1",
        probe_fingerprint("debug", "cable", "port"),
    )
    journal = StackJournal(tmp_path, fingerprint)
    transaction = "123e4567-e89b-42d3-a456-426614174000"
    journal.reserve_transaction(transaction, 1)
    journal.append(
        transaction,
        "capture_intent",
        {
            "initial_running": True,
            "duration_ms": 100,
            "sample_period_ms": 10,
            "max_samples": 1,
            "max_frames": 1,
        },
    )
    journal.append(transaction, "break_intent", {"sample_index": 1})
    debugger.fnc.running = False
    sampler = service(tmp_path, debugger, recover=True)

    result = sampler.recover_only()
    assert result["target"] == {"powered": True, "running": True, "halted": False}
    assert result["debugger_error_state"] == {"occurred": False, "id": ""}
    assert result["recovery_authorization_consumed"] is True
    assert sampler.recover_quarantined is False
    with pytest.raises(StackSamplingError, match="fresh --recover-quarantined"):
        sampler.recover_only()


def test_recovery_restarts_owned_halt_but_preserves_expected_noframe(
    tmp_path: Path,
):
    class CountingDebugger(Debugger):
        def __init__(self):
            super().__init__()
            self.goes = 0

        def go(self):
            self.goes += 1
            super().go()

    item, debugger = request(), CountingDebugger()
    artifact_root = root(tmp_path, item)
    fingerprint = endpoint_fingerprint(
        "localhost",
        20001,
        "TCP",
        "R.2026.02+1",
        probe_fingerprint("debug", "cable", "port"),
    )
    journal = StackJournal(artifact_root, fingerprint)
    transaction = "123e4567-e89b-42d3-a456-426614174000"
    journal.reserve_transaction(transaction, 1)
    journal.append(
        transaction,
        "capture_intent",
        {
            "initial_running": True,
            "duration_ms": 100,
            "sample_period_ms": 10,
            "max_samples": 1,
            "max_frames": 1,
        },
    )
    journal.append(transaction, "break_intent", {"sample_index": 1})
    journal.append(transaction, "break_observed", {"sample_index": 1})
    debugger.fnc.running = False
    debugger.fnc.error_occurred, debugger.fnc.error_id = True, "#emu_noframe"

    result = service(artifact_root, debugger, recover=True).recover_only()

    assert result["target"] == {"powered": True, "running": True, "halted": False}
    assert result["debugger_error_state"] == {
        "occurred": True,
        "id": "#emu_noframe",
    }
    assert debugger.goes == 1
    assert debugger.commands == []
    assert debugger.fnc.error_occurred is True


def test_recovery_restarts_owned_halt_but_never_clears_unknown_error(
    tmp_path: Path,
):
    class CountingDebugger(Debugger):
        def __init__(self):
            super().__init__()
            self.goes = 0

        def go(self):
            self.goes += 1
            super().go()

    item, debugger = request(), CountingDebugger()
    artifact_root = root(tmp_path, item)
    fingerprint = endpoint_fingerprint(
        "localhost",
        20001,
        "TCP",
        "R.2026.02+1",
        probe_fingerprint("debug", "cable", "port"),
    )
    journal = StackJournal(artifact_root, fingerprint)
    transaction = "123e4567-e89b-42d3-a456-426614174000"
    journal.reserve_transaction(transaction, 1)
    journal.append(
        transaction,
        "capture_intent",
        {
            "initial_running": True,
            "duration_ms": 100,
            "sample_period_ms": 10,
            "max_samples": 1,
            "max_frames": 1,
        },
    )
    journal.append(transaction, "break_intent", {"sample_index": 1})
    journal.append(transaction, "break_observed", {"sample_index": 1})
    debugger.fnc.running = False
    debugger.fnc.error_occurred, debugger.fnc.error_id = True, "#other"

    result = service(artifact_root, debugger, recover=True).recover_only()

    assert debugger.goes == 1
    assert debugger.fnc.running is True
    assert debugger.fnc.error_occurred is True
    assert debugger.commands == []
    assert result["debugger_error_state"] == {"occurred": True, "id": "#other"}


def test_failed_recovery_attempt_cannot_reuse_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    item, debugger = request(), Debugger()
    sampler = service(root(tmp_path, item), debugger, recover=True)
    authorizations: list[bool] = []

    def fail_recovery(self, debugger, *, authorized, running):
        authorizations.append(authorized)
        raise StorageError("injected recovery failure")

    monkeypatch.setattr(StackJournal, "require_recovered", fail_recovery)
    with pytest.raises(StorageError, match="injected recovery failure"):
        sampler.recover_only()
    with pytest.raises(StackSamplingError, match="fresh --recover-quarantined"):
        sampler.recover_only()
    assert authorizations == [True]


def test_packaged_stack_schemas_are_exact_generated_assets():
    project = Path(__file__).parents[3]
    package = Path(__file__).parents[1] / "src" / "lauterbach_sampling_mcp" / "schemas"
    for name in (
        "stack-driver-event.schema.json",
        "stack-capture-attempt.schema.json",
        "stack-capture-request.schema.json",
        "stack-samples.schema.json",
    ):
        assert (package / name).read_bytes() == (
            project / "schemas" / "v1" / name
        ).read_bytes()


@pytest.mark.parametrize(
    "event,details",
    [
        ("break_intent", {"sample_index": 0}),
        ("go_observed", {"sample_index": True}),
        ("cleanup_intent", {"recovery": False}),
        ("capture_observed", {"attempted_samples": 1, "collected_samples": 2}),
    ],
)
def test_journal_rejects_invalid_generated_event_details(
    tmp_path: Path, event, details
):
    journal = StackJournal(tmp_path, "a" * 64)
    with pytest.raises(StorageError):
        journal.append("123e4567-e89b-42d3-a456-426614174000", event, details)


def test_journal_filename_must_bind_event_content(tmp_path: Path):
    journal = StackJournal(tmp_path, "a" * 64)
    tx = "123e4567-e89b-42d3-a456-426614174000"
    journal.reserve_transaction(tx, 1)
    journal.append(
        tx,
        "capture_intent",
        {
            "initial_running": True,
            "duration_ms": 100,
            "sample_period_ms": 10,
            "max_samples": 1,
            "max_frames": 1,
        },
    )
    (journal.directory / f"{tx}-00000001.json").rename(
        journal.directory / f"{tx}-00000002.json"
    )
    with pytest.raises(StorageError):
        StackJournal(tmp_path, "a" * 64)


def test_endpoint_binding_rejects_other_probe(tmp_path: Path):
    StackJournal(tmp_path, "a" * 64)
    with pytest.raises(StorageError, match="different TRACE32 endpoint"):
        StackJournal(tmp_path, "b" * 64)


def test_authorized_recovery_restarts_second_unmatched_break(tmp_path: Path):
    item, debugger = request(max_samples=2), Debugger()
    root(tmp_path, item)
    fp = endpoint_fingerprint(
        "localhost",
        20001,
        "TCP",
        "R.2026.02+1",
        probe_fingerprint("debug", "cable", "port"),
    )
    journal = StackJournal(tmp_path, fp)
    tx = "123e4567-e89b-42d3-a456-426614174000"
    journal.reserve_transaction(tx, 2)
    journal.append(
        tx,
        "capture_intent",
        {
            "initial_running": True,
            "duration_ms": 100,
            "sample_period_ms": 10,
            "max_samples": 2,
            "max_frames": 1,
        },
    )
    for event in ("break_intent", "break_observed", "go_intent", "go_observed"):
        journal.append(tx, event, {"sample_index": 1})
    journal.append(tx, "break_intent", {"sample_index": 2})
    debugger.fnc.running = False
    journal.require_recovered(
        debugger, authorized=True, running=lambda: debugger.fnc.running
    )
    assert debugger.fnc.running


def test_safe_go_observed_never_resumes_an_externally_stopped_target(tmp_path: Path):
    journal = StackJournal(tmp_path, "a" * 64)
    tx = "123e4567-e89b-42d3-a456-426614174000"
    journal.reserve_transaction(tx, 1)
    journal.append(
        tx,
        "capture_intent",
        {
            "initial_running": True,
            "duration_ms": 100,
            "sample_period_ms": 10,
            "max_samples": 1,
            "max_frames": 1,
        },
    )
    for event in ("break_intent", "break_observed", "go_intent", "go_observed"):
        journal.append(tx, event, {"sample_index": 1})
    debugger = Debugger()
    debugger.fnc.running = False
    journal.require_recovered(
        debugger, authorized=False, running=lambda: debugger.fnc.running
    )
    assert debugger.fnc.running is False


def test_post_go_cleanup_intent_never_authorizes_an_external_resume(tmp_path: Path):
    journal = StackJournal(tmp_path, "a" * 64)
    tx = "123e4567-e89b-42d3-a456-426614174000"
    journal.reserve_transaction(tx, 1)
    journal.append(
        tx,
        "capture_intent",
        {
            "initial_running": True,
            "duration_ms": 100,
            "sample_period_ms": 10,
            "max_samples": 1,
            "max_frames": 1,
        },
    )
    for event in ("break_intent", "break_observed", "go_intent", "go_observed"):
        journal.append(tx, event, {"sample_index": 1})
    journal.append(tx, "cleanup_intent", {})
    debugger = Debugger()
    debugger.fnc.running = False
    journal.require_recovered(
        debugger, authorized=True, running=lambda: debugger.fnc.running
    )
    assert debugger.fnc.running is False


def test_unmatched_break_followed_by_cleanup_intent_is_recovered(tmp_path: Path):
    journal = StackJournal(tmp_path, "a" * 64)
    tx = "123e4567-e89b-42d3-a456-426614174000"
    journal.reserve_transaction(tx, 1)
    journal.append(
        tx,
        "capture_intent",
        {
            "initial_running": True,
            "duration_ms": 100,
            "sample_period_ms": 10,
            "max_samples": 1,
            "max_frames": 1,
        },
    )
    journal.append(tx, "break_intent", {"sample_index": 1})
    journal.append(tx, "break_observed", {"sample_index": 1})
    journal.append(tx, "cleanup_intent", {})
    debugger = Debugger()
    debugger.fnc.running = False
    journal.require_recovered(
        debugger, authorized=True, running=lambda: debugger.fnc.running
    )
    assert debugger.fnc.running is True


def test_frame_down_failure_still_restores_target_running(tmp_path: Path):
    class DownFailureDebugger(Debugger):
        def cmd(self, command):
            if command == "Frame.Down":
                raise RuntimeError("down failed")
            super().cmd(command)

    item, debugger = request(), DownFailureDebugger()
    with pytest.raises(RuntimeError, match="down failed"):
        service(root(tmp_path, item), debugger).capture(item)
    assert debugger.fnc.running is True


def test_journal_append_failure_restores_target_and_sets_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    item, debugger = request(), Debugger()
    artifact_root = root(tmp_path, item)
    original = StackJournal.append
    injected = False

    def fail_break_observed(self, tx, event, details=None):
        nonlocal injected
        if event == "break_observed" and not injected:
            injected = True
            raise StorageError("injected journal failure")
        return original(self, tx, event, details)

    monkeypatch.setattr(StackJournal, "append", fail_break_observed)
    with pytest.raises(StorageError, match="injected journal failure"):
        service(artifact_root, debugger).capture(item)
    assert debugger.fnc.running is True
    assert (artifact_root / ".t32perf-control" / "stack-journal-failure.json").is_file()


def test_journal_rejects_duplicate_members_and_oversize(tmp_path: Path):
    journal = StackJournal(tmp_path, "a" * 64)
    tx = "123e4567-e89b-42d3-a456-426614174000"
    journal.reserve_transaction(tx, 1)
    journal.append(
        tx,
        "capture_intent",
        {
            "initial_running": True,
            "duration_ms": 100,
            "sample_period_ms": 10,
            "max_samples": 1,
            "max_frames": 1,
        },
    )
    event = journal.directory / f"{tx}-00000001.json"
    payload = event.read_text(encoding="utf-8")
    event.write_text(payload[:-1] + ',"sequence":1}', encoding="utf-8")
    with pytest.raises(StorageError, match="unreadable"):
        StackJournal(tmp_path, "a" * 64)

    event.write_bytes(b" " * (MAX_STACK_EVENT_BYTES + 1))
    with pytest.raises(StorageError, match="size limit|unsafe"):
        StackJournal(tmp_path, "a" * 64)


def test_journal_reserves_a_maximum_stack_capture_in_an_empty_history(tmp_path: Path):
    journal = StackJournal(tmp_path, "a" * 64)
    tx = "123e4567-e89b-42d3-a456-426614174000"
    journal.reserve_transaction(tx, 512)
    assert journal.reserved[tx] == MAX_STACK_DRIVER_EVENTS


def test_journal_rejects_link_like_entry_when_supported(tmp_path: Path):
    journal = StackJournal(tmp_path, "a" * 64)
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = journal.directory / "123e4567-e89b-42d3-a456-426614174000-00000001.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("creating symlinks is not permitted on this host")
    with pytest.raises(StorageError, match="unsafe"):
        StackJournal(tmp_path, "a" * 64)
