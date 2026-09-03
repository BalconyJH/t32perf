from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from lauterbach.trace32.rcl._rc._functions import FunctionService

from lauterbach_sampling_mcp import TOOL_NAMES, _public_error, create_server, storage
from lauterbach_sampling_mcp.model import (
    CaptureRequest,
    InputError,
    control_schema_path,
    endpoint_fingerprint,
    legacy_endpoint_fingerprint,
    probe_fingerprint,
    schema_path,
)
from lauterbach_sampling_mcp.service import SamplingError
from lauterbach_sampling_mcp.service import SamplingService as Service
from lauterbach_sampling_mcp.storage import (
    ExecutionLease,
    SamplingJournal,
    StorageError,
    _publish_new,
)


class FakeFunctions:
    def __init__(self, *, pcsnoop: bool = True, running: bool = True) -> None:
        self.pcsnoop = pcsnoop
        self.running = running
        self.perf_enabled = False
        self.fail_cleanup = False

    def state_power(self) -> bool:
        return True

    def state_run(self) -> bool:
        return self.running

    def state_halt(self) -> bool:
        return False

    def state_processor(self) -> str:
        return "CortexM0+"

    def cpu_feature(self, _: str) -> bool:
        return self.pcsnoop

    def perf_method(self) -> int:
        return 4 if self.pcsnoop else 2

    def perf_mode(self) -> int:
        return 1

    def perf_state(self) -> int:
        return 1 if self.perf_enabled else 0

    def software_version(self) -> str:
        return "R.2026.02"

    def software_build(self) -> int:
        return 190766

    def perf_rate(self) -> int:
        return 100

    def perf_runtime(self) -> str:
        return "98.5%"

    def perf_snoopfails(self) -> int:
        return 0

    def __call__(self, expression: str) -> int | str:
        if expression == "VERSION.SERIAL.DEBUG()":
            return "debug-module-serial"
        if expression == "VERSION.SERIAL.CABLE()":
            return "debug-cable-serial"
        if expression == "SYStem.CONFIG.DEBUGPORT()":
            return "DebugCable0"
        if expression == "sYmbol.List.PROGRAM.COUNT()>0":
            return 0
        if expression in {
            "PERF.PC.HITS(P:0x1000--0x100f, 0.)",
            "PERF.PC.HITS(P:0x1010--0x101f, 0.)",
        }:
            return 3
        raise RuntimeError("TRACE32 symbols unavailable")


class FakeDebugger:
    def __init__(self, functions: FakeFunctions) -> None:
        self.fnc, self.commands = functions, []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def cmd(self, command: str) -> None:
        self.commands.append(command)
        if command == "PERF.Arm":
            self.fnc.perf_enabled = True
        if command == "PERF.DISable":
            if self.fnc.fail_cleanup:
                raise RuntimeError("cleanup")
            self.fnc.perf_enabled = False


def SamplingService(**kwargs: Any) -> Service:
    """Construct a service pinned to the identity supplied by FakeFunctions."""
    kwargs.setdefault(
        "expected_endpoint_fingerprint",
        endpoint_fingerprint(
            str(kwargs.get("host", "localhost")),
            int(kwargs["port"]),
            str(kwargs.get("protocol", "TCP")),
            "R.2026.02+190766",
            probe_fingerprint(
                "debug-module-serial", "debug-cable-serial", "DebugCable0"
            ),
        ),
    )
    return Service(**kwargs)


def request(**changes: object) -> CaptureRequest:
    data: dict[str, object] = {
        "session_id": "session-1",
        "operation_id": "a" * 32,
        "ranges": [{"start_address": 0x1000, "end_address": 0x1020}],
        "bucket_size": 0x10,
        "duration_ms": 1,
    }
    data.update(changes)
    return CaptureRequest.parse(data)


def root(tmp_path: Path, authorized: CaptureRequest | None = None) -> Path:
    capture_request = authorized or request()
    session = tmp_path / capture_request.session_id
    for directory in (
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
        (session / directory).mkdir(parents=True, exist_ok=True)
    (session / ".session.lock").touch()
    (session / "request.json").write_text(
        json.dumps(capture_request.authorization_document()), encoding="utf-8"
    )
    (session / "state.json").write_text(
        json.dumps(
            {
                "schema": "t32perf.state/v1",
                "created_at": "2026-08-29T00:00:00Z",
                "state": "created",
                "operation_id": capture_request.operation_id,
                "revision": 0,
                "updated_at": "2026-08-29T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


def test_inventory_is_sampling_only() -> None:
    assert TOOL_NAMES == ("sampling_capabilities", "sampling_capture")


def test_mcp_boundary_redacts_storage_and_io_error_details() -> None:
    assert _public_error(StorageError(r"Session C:\private\session-1 failed")) == {
        "error": "storage_or_io_failed",
        "message": "sampling operation encountered an internal I/O failure",
    }
    assert _public_error(OSError(r"C:\private\session-1")) == {
        "error": "storage_or_io_failed",
        "message": "sampling operation encountered an internal I/O failure",
    }


def test_real_rcl_function_service_keeps_validated_pc_range_unquoted() -> None:
    class SpyConnection:
        def __init__(self) -> None:
            self.command = ""

        def _fnc(self, command: str) -> int:
            self.command = command
            return 3

    spy = SpyConnection()
    functions = FunctionService(spy)
    assert functions("PERF.PC.HITS(P:0x1000--0x100f, 0.)") == 3
    assert spy.command == "PERF.PC.HITS(P:0x1000--0x100f, 0.)"
    assert '"' not in spy.command


@pytest.mark.parametrize(
    "data",
    [
        {
            "session_id": "../escape",
            "ranges": [{"start_address": 0, "end_address": 1}],
            "bucket_size": 1,
            "duration_ms": 1,
        },
        {
            "session_id": "ok",
            "ranges": [
                {"start_address": 0, "end_address": 2},
                {"start_address": 1, "end_address": 3},
            ],
            "bucket_size": 1,
            "duration_ms": 1,
        },
        {
            "session_id": "ok",
            "ranges": [{"start_address": 0, "end_address": 8193}],
            "bucket_size": 1,
            "duration_ms": 1,
        },
    ],
)
def test_rejects_unbounded_or_overlapping_input(data: dict[str, object]) -> None:
    with pytest.raises(InputError):
        CaptureRequest.parse(data)


def test_range_bucketing_is_half_open() -> None:
    assert request(
        ranges=[{"start_address": 0x10, "end_address": 0x25}], bucket_size=0x10
    ).buckets() == [(0x10, 0x20), (0x20, 0x25)]


def test_deployed_firmware_assertion_is_optional_and_canonical() -> None:
    digest = "e" * 64
    with_assertion = request(deployed_firmware_elf_sha256=digest)
    assert with_assertion.deployed_firmware_elf_sha256 == digest
    assert (
        with_assertion.authorization_document()["deployed_firmware_elf_sha256"]
        == digest
    )
    assert "deployed_firmware_elf_sha256" not in request().authorization_document()


@pytest.mark.parametrize("digest", ["E" * 64, "e" * 63, "g" * 64, None, 1])
def test_rejects_malformed_deployed_firmware_assertion(digest: object) -> None:
    with pytest.raises(InputError, match="deployed_firmware_elf_sha256"):
        request(deployed_firmware_elf_sha256=digest)


def test_realtime_capture_publishes_schema_valid_no_overwrite_artifact(
    tmp_path: Path,
) -> None:
    functions = FakeFunctions()
    debugger = FakeDebugger(functions)
    service = SamplingService(
        host="localhost",
        port=20001,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path),
        connector=lambda **_: debugger,
    )
    result = service.capture(request())
    histogram = result["histogram"]
    assert histogram["method"] == {"kind": "realtime"}
    assert histogram["cleanup_complete"] is True
    assert (
        result["artifact"]["sha256"]
        == hashlib.sha256(
            json.dumps(
                histogram, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode()
            + b"\n"
        ).hexdigest()
    )
    assert debugger.commands == [
        "PERF.RESet",
        "PERF.AutoArm OFF",
        "PERF.AutoInit OFF",
        "PERF.Mode PC",
        "PERF.METHOD RealTime",
        "PERF.Init",
        "PERF.Arm",
        "PERF.OFF",
        "PERF.DISable",
    ]
    assert histogram["endpoint_fingerprint"] == endpoint_fingerprint(
        "localhost",
        20001,
        "TCP",
        "R.2026.02+190766",
        probe_fingerprint("debug-module-serial", "debug-cable-serial", "DebugCable0"),
    )
    assert (
        len(list((tmp_path / "session-1" / "capture" / "staging").glob("*.json"))) == 1
    )
    assert "debugger_symbolization" not in histogram


class SymbolizedFunctions(FakeFunctions):
    def __init__(self, *, symbols_loaded: object = 1) -> None:
        super().__init__()
        self.symbols_loaded = symbols_loaded
        self.responses: dict[str, object] = {
            "PERF.PC.HITS(P:0x1000--0x100f, 0.)": 20,
            "PERF.PC.HITS(P:0x1000--0x1007, 0.)": 15,
            "PERF.PC.HITS(P:0x1008--0x100f, 0.)": 5,
            "PERF.PC.HITS(P:0x1000--0x1003, 0.)": 10,
            "PERF.PC.HITS(P:0x1004--0x1007, 0.)": 5,
            "sYmbol.FUNCTION(P:0x1000)": r"C:\build\obj\hot_loop",
            "sYmbol.FUNCTION(P:0x1003)": r"C:\build\obj\hot_loop",
            "sYmbol.SOURCEFILE(P:0x1000)": r"D:\private\src\hot_loop.c",
            "sYmbol.SOURCEFILE(P:0x1003)": r"D:\private\src\hot_loop.c",
            "sYmbol.SOURCELINE(P:0x1000)": 27,
            "sYmbol.SOURCELINE(P:0x1003)": 27,
        }

    def __call__(self, expression: str) -> Any:
        if expression == "sYmbol.List.PROGRAM.COUNT()>0":
            if isinstance(self.symbols_loaded, Exception):
                raise self.symbols_loaded
            return self.symbols_loaded
        if expression in self.responses:
            response = self.responses[expression]
            if isinstance(response, Exception):
                raise response
            return response
        return super().__call__(expression)


def _symbolized_capture(tmp_path: Path, functions: FakeFunctions) -> dict[str, Any]:
    capture_request = request(ranges=[{"start_address": 0x1000, "end_address": 0x1010}])
    debugger = FakeDebugger(functions)
    service = SamplingService(
        host="localhost",
        port=20001,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path, capture_request),
        connector=lambda **_: debugger,
    )
    return service.capture(capture_request)


def test_capture_emits_safe_debugger_reported_hot_location(tmp_path: Path) -> None:
    histogram = _symbolized_capture(tmp_path, SymbolizedFunctions())["histogram"]
    assert histogram["firmware"] == {"status": "unverified"}
    assert histogram["debugger_symbolization"] == {
        "source": "trace32_symbol_table",
        "trust": "debugger_reported",
        "refinement_granularity_bytes": 4,
        "locations": [
            {
                "bucket_start_address": 0x1000,
                "bucket_end_address": 0x1010,
                "hits": 20,
                "dominant_start_address": 0x1000,
                "dominant_end_address": 0x1004,
                "dominant_hits": 10,
                "function_name": "hot_loop",
                "source_file": "hot_loop.c",
                "source_line": 27,
            }
        ],
    }


def test_symbolization_finds_global_hottest_leaf_not_greedy_half(
    tmp_path: Path,
) -> None:
    functions = SymbolizedFunctions()
    functions.responses.update(
        {
            "PERF.PC.HITS(P:0x1000--0x100f, 0.)": 100,
            "PERF.PC.HITS(P:0x1000--0x1007, 0.)": 60,
            "PERF.PC.HITS(P:0x1008--0x100f, 0.)": 40,
            "PERF.PC.HITS(P:0x1000--0x1003, 0.)": 30,
            "PERF.PC.HITS(P:0x1004--0x1007, 0.)": 30,
            "PERF.PC.HITS(P:0x1008--0x100b, 0.)": 40,
            "PERF.PC.HITS(P:0x100c--0x100f, 0.)": 0,
            "sYmbol.FUNCTION(P:0x1008)": "right_hot",
            "sYmbol.FUNCTION(P:0x100b)": "right_hot",
            "sYmbol.SOURCEFILE(P:0x1008)": "right.c",
            "sYmbol.SOURCEFILE(P:0x100b)": "right.c",
            "sYmbol.SOURCELINE(P:0x1008)": 31,
            "sYmbol.SOURCELINE(P:0x100b)": 31,
        }
    )
    histogram = _symbolized_capture(tmp_path, functions)["histogram"]
    location = histogram["debugger_symbolization"]["locations"][0]
    assert location["dominant_start_address"] == 0x1008
    assert location["dominant_end_address"] == 0x100C
    assert location["dominant_hits"] == 40


def test_symbol_component_removes_path_and_rejects_controls_safely() -> None:
    assert Service._safe_symbol_component(r"C:\private\src\main.c") == "main.c"
    assert Service._safe_symbol_component("bad\u0085name") is None
    component = Service._safe_symbol_component("é" * 129)
    assert component is not None
    assert len(component.encode("utf-8")) <= 256


def test_cross_function_refinement_is_not_mislabeled(tmp_path: Path) -> None:
    functions = SymbolizedFunctions()
    functions.responses["sYmbol.FUNCTION(P:0x1003)"] = "other_function"
    functions.responses["sYmbol.SOURCEFILE(P:0x1003)"] = "other.c"
    functions.responses["sYmbol.SOURCELINE(P:0x1003)"] = 28
    histogram = _symbolized_capture(tmp_path, functions)["histogram"]
    assert "debugger_symbolization" not in histogram


def test_symbolization_query_failure_does_not_fail_capture(tmp_path: Path) -> None:
    functions = SymbolizedFunctions()
    functions.responses["sYmbol.FUNCTION(P:0x1000)"] = RuntimeError("unavailable")
    histogram = _symbolized_capture(tmp_path, functions)["histogram"]
    assert histogram["buckets"] == [
        {"start_address": 0x1000, "end_address": 0x1010, "hits": 20}
    ]
    location = histogram["debugger_symbolization"]["locations"][0]
    assert "function_name" not in location
    assert location["source_file"] == "hot_loop.c"


def test_source_query_failure_retains_function_label(tmp_path: Path) -> None:
    functions = SymbolizedFunctions()
    functions.responses["sYmbol.SOURCEFILE(P:0x1000)"] = RuntimeError("unavailable")
    histogram = _symbolized_capture(tmp_path, functions)["histogram"]
    location = histogram["debugger_symbolization"]["locations"][0]
    assert location["function_name"] == "hot_loop"
    assert "source_file" not in location


@pytest.mark.parametrize(
    ("symbols_loaded", "expected"),
    [(1, True), (0, False), ("invalid", "unknown"), (RuntimeError(), "unknown")],
)
def test_code_labels_capability_is_stable(
    tmp_path: Path, symbols_loaded: object, expected: bool | str
) -> None:
    functions = SymbolizedFunctions(symbols_loaded=symbols_loaded)
    service = SamplingService(
        host="localhost",
        port=20001,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path),
        connector=lambda **_: FakeDebugger(functions),
    )
    assert service.capabilities()["code_labels"] == {
        "supported": True,
        "source": "trace32_symbol_table",
        "trust": "debugger_reported",
        "symbols_loaded": expected,
    }


def test_capture_without_pin_does_not_connect(tmp_path: Path) -> None:
    connected = False

    def connector(**_: object) -> FakeDebugger:
        nonlocal connected
        connected = True
        return FakeDebugger(FakeFunctions())

    service = Service(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path),
        connector=connector,
    )
    with pytest.raises(SamplingError, match="pinned expected endpoint"):
        service.capture(request())
    assert not connected


def test_mismatched_pin_only_reads_identity_before_failing(tmp_path: Path) -> None:
    functions = FakeFunctions()
    debugger = FakeDebugger(functions)
    service = Service(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path),
        expected_endpoint_fingerprint="0" * 64,
        connector=lambda **_: debugger,
    )
    with pytest.raises(SamplingError, match="does not match"):
        service.capture(request())
    assert debugger.commands == []
    assert not (tmp_path / ".t32perf-control" / "sampling-driver-events").exists()


@pytest.mark.parametrize("value", ["", " " * 257, None, RuntimeError])
def test_unreadable_probe_identity_is_unknown_and_blocks_capture_before_perf_mutation(
    tmp_path: Path, value: object
) -> None:
    class UnreadableProbeFunctions(FakeFunctions):
        def __call__(self, expression: str) -> Any:
            if expression == "VERSION.SERIAL.CABLE()":
                if value is RuntimeError:
                    raise RuntimeError("unreadable")
                return value
            return super().__call__(expression)

    functions = UnreadableProbeFunctions()
    debugger = FakeDebugger(functions)
    service = SamplingService(
        host="localhost",
        port=20001,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path),
        connector=lambda **_: debugger,
    )
    capability = service.capabilities()
    assert capability["probe_fingerprint"] == "unknown"
    assert capability["endpoint_fingerprint"] == "unknown"
    with pytest.raises(SamplingError, match="readable TRACE32 probe fingerprint"):
        service.capture(request())
    assert debugger.commands == []


def test_probe_change_changes_endpoint_fingerprint(tmp_path: Path) -> None:
    class AlternateProbeFunctions(FakeFunctions):
        def __call__(self, expression: str) -> int | str:
            if expression == "VERSION.SERIAL.CABLE()":
                return "other-debug-cable-serial"
            return super().__call__(expression)

    def fingerprint(functions: FakeFunctions) -> str:
        artifact_root = tmp_path / "artifacts"
        artifact_root.mkdir(exist_ok=True)
        service = SamplingService(
            host="localhost",
            port=20001,
            protocol="TCP",
            timeout=1,
            artifact_root=artifact_root,
            connector=lambda **_: FakeDebugger(functions),
        )
        result = service.capabilities()
        assert isinstance(result["endpoint_fingerprint"], str)
        return result["endpoint_fingerprint"]

    assert fingerprint(FakeFunctions()) != fingerprint(AlternateProbeFunctions())


def test_capture_requires_host_created_session_before_rcl_connection(
    tmp_path: Path,
) -> None:
    root_path = root(tmp_path)
    state_path = root_path / "session-1" / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["state"] = "captured"
    state_path.write_text(json.dumps(state), encoding="utf-8")
    connected = False

    def connector(**_: object) -> FakeDebugger:
        nonlocal connected
        connected = True
        return FakeDebugger(FakeFunctions())

    service = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=root_path,
        connector=connector,
    )
    with pytest.raises(StorageError, match="Host-created"):
        service.capture(request())
    assert not connected


def test_capture_rejects_unbound_or_mismatched_request_before_rcl(
    tmp_path: Path,
) -> None:
    root_path = root(tmp_path)
    request_path = root_path / "session-1" / "request.json"
    request_path.write_text("{}\n", encoding="utf-8")
    connected = False

    def connector(**_: object) -> FakeDebugger:
        nonlocal connected
        connected = True
        return FakeDebugger(FakeFunctions())

    service = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=root_path,
        connector=connector,
    )
    with pytest.raises(StorageError, match="authorization"):
        service.capture(request())
    assert not connected

    request_path.write_text(
        json.dumps(request().authorization_document()), encoding="utf-8"
    )
    with pytest.raises(StorageError, match="Host-created"):
        service.capture(request(operation_id="b" * 32))
    assert not connected

    for changed in (
        request(duration_ms=2),
        request(method_policy="allow_stop_and_go"),
        request(ranges=[{"start_address": 0x1010, "end_address": 0x1020}]),
    ):
        request_path.write_text(
            json.dumps(changed.authorization_document()), encoding="utf-8"
        )
        with pytest.raises(StorageError, match="authorization"):
            service.capture(request())
    assert not connected


def test_active_perf_is_rejected_without_non_owned_cleanup(tmp_path: Path) -> None:
    functions = FakeFunctions()
    functions.perf_enabled = True
    debugger = FakeDebugger(functions)
    service = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path),
        connector=lambda **_: debugger,
    )
    with pytest.raises(SamplingError, match="non-owned cleanup"):
        service.capture(request())
    assert debugger.commands == []


def test_transaction_headroom_rejects_before_debugger_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(storage, "MAX_JOURNAL_EVENTS", 11)
    functions = FakeFunctions()
    debugger = FakeDebugger(functions)
    service = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path),
        connector=lambda **_: debugger,
    )
    with pytest.raises(StorageError, match="headroom"):
        service.capture(request())
    assert debugger.commands == []


def test_start_journal_failure_still_disables_perf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    functions = FakeFunctions()
    debugger = FakeDebugger(functions)
    original_append = SamplingJournal.append
    failed = False

    def fail_start_observed(
        self: SamplingJournal,
        transaction_id: str,
        event: str,
        details: dict[str, object] | None = None,
    ) -> None:
        nonlocal failed
        if event == "start_observed" and not failed:
            failed = True
            raise StorageError("injected append failure")
        original_append(self, transaction_id, event, details)

    monkeypatch.setattr(SamplingJournal, "append", fail_start_observed)
    service = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path),
        connector=lambda **_: debugger,
    )
    with pytest.raises(StorageError, match="injected append failure"):
        service.capture(request())
    assert "PERF.DISable" in debugger.commands
    assert not functions.perf_enabled
    with pytest.raises(SamplingError, match="previously failed"):
        service.capture(request())


def test_cleanup_marker_failure_still_disables_perf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    functions = FakeFunctions()
    debugger = FakeDebugger(functions)
    original_append = SamplingJournal.append

    def fail_cleanup_intent(
        self: SamplingJournal,
        transaction_id: str,
        event: str,
        details: dict[str, object] | None = None,
    ) -> None:
        if event == "cleanup_intent":
            raise StorageError("injected cleanup marker failure")
        original_append(self, transaction_id, event, details)

    monkeypatch.setattr(SamplingJournal, "append", fail_cleanup_intent)
    service = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path),
        connector=lambda **_: debugger,
    )
    with pytest.raises(SamplingError, match="cleanup requires recovery"):
        service.capture(request())
    assert "PERF.DISable" in debugger.commands
    assert not functions.perf_enabled
    monkeypatch.setattr(SamplingJournal, "append", original_append)
    blocked = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=tmp_path,
        connector=lambda **_: debugger,
    )
    with pytest.raises(StorageError, match="previously failed"):
        blocked.capture(request())
    recovered = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=tmp_path,
        recover_quarantined=True,
        connector=lambda **_: debugger,
    )
    recovered.capture(request())
    records = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(
            (tmp_path / ".t32perf-control" / "sampling-driver-events").glob("*.json")
        )
    ]
    recovery = [record for record in records if record["event"] == "recovery_observed"]
    assert len(recovery) == 1
    sequence = recovery[0]["sequence"]
    intent = next(
        record
        for record in records
        if record["transaction_id"] == recovery[0]["transaction_id"]
        and record["sequence"] == sequence - 1
    )
    assert intent["event"] == "cleanup_intent"
    assert intent["details"] == {"recovery": True}


@pytest.mark.parametrize("event", ["start_observed", "cleanup_intent"])
def test_raw_journal_oserror_and_marker_oserror_still_disable_perf(
    event: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    functions = FakeFunctions()
    debugger = FakeDebugger(functions)
    original_append = SamplingJournal.append

    def fail_event(
        self: SamplingJournal,
        transaction_id: str,
        candidate: str,
        details: dict[str, object] | None = None,
    ) -> None:
        if candidate == event:
            raise OSError("injected raw journal I/O failure")
        original_append(self, transaction_id, candidate, details)

    def fail_marker(self: SamplingJournal, error: Exception) -> None:
        raise OSError("injected raw marker I/O failure")

    monkeypatch.setattr(SamplingJournal, "append", fail_event)
    monkeypatch.setattr(SamplingJournal, "mark_failure", fail_marker)
    service = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path),
        connector=lambda **_: debugger,
    )
    with pytest.raises((OSError, SamplingError)):
        service.capture(request())
    assert "PERF.DISable" in debugger.commands
    assert not functions.perf_enabled
    with pytest.raises(SamplingError, match="previously failed"):
        service.capture(request())


@pytest.mark.parametrize(
    "host, protocol", [("example.com", "TCP"), ("localhost", "UDP")]
)
def test_v1_rejects_remote_or_udp_endpoint(
    host: str, protocol: str, tmp_path: Path
) -> None:
    with pytest.raises(InputError):
        SamplingService(
            host=host,
            port=1,
            protocol=protocol,
            timeout=1,
            artifact_root=root(tmp_path),
        )


@pytest.mark.parametrize("operation_id", ["A" * 32, "a" * 31, "g" * 32])
def test_operation_id_is_required_and_canonical(operation_id: str) -> None:
    with pytest.raises(InputError, match="operation_id"):
        CaptureRequest.parse(
            {
                "session_id": "session-1",
                "operation_id": operation_id,
                "ranges": [{"start_address": 0x1000, "end_address": 0x1020}],
                "bucket_size": 0x10,
                "duration_ms": 1,
            }
        )


def test_stop_and_go_requires_explicit_policy_and_is_marked_intrusive(
    tmp_path: Path,
) -> None:
    functions = FakeFunctions(pcsnoop=False)
    debugger = FakeDebugger(functions)
    service = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path / "realtime-only"),
        connector=lambda **_: debugger,
    )
    with pytest.raises(SamplingError):
        service.capture(request())
    service = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=root(
            tmp_path / "allow-stop-and-go", request(method_policy="allow_stop_and_go")
        ),
        connector=lambda **_: debugger,
    )
    result = service.capture(request(method_policy="allow_stop_and_go"))
    assert result["histogram"]["intrusive"] is True
    assert result["histogram"]["method"]["kind"] == "stop_and_go"
    assert "PERF.RunTimeLimit 99." in debugger.commands


def test_target_state_drift_and_cleanup_failure_fail_closed(tmp_path: Path) -> None:
    functions = FakeFunctions()
    debugger = FakeDebugger(functions)
    service = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path / "cleanup-failure"),
        connector=lambda **_: debugger,
    )
    original = functions.state_run
    calls = 0

    def drifting() -> bool:
        nonlocal calls
        calls += 1
        return original() if calls < 3 else False

    functions.state_run = drifting
    with pytest.raises(SamplingError, match="capture failed"):
        service.capture(request())
    functions = FakeFunctions()
    functions.fail_cleanup = True
    debugger = FakeDebugger(functions)
    service = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path / "cleanup-error"),
        connector=lambda **_: debugger,
    )
    with pytest.raises(SamplingError, match="cleanup"):
        service.capture(request())
    assert debugger.commands.count("PERF.DISable") == 1
    blocked = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=tmp_path / "cleanup-error",
        connector=lambda **_: debugger,
    )
    with pytest.raises(StorageError, match="cleanup previously failed"):
        blocked.capture(request())
    functions.fail_cleanup = False
    recovered = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=tmp_path / "cleanup-error",
        recover_quarantined=True,
        connector=lambda **_: debugger,
    )
    recovered.capture(request())
    second = request(session_id="session-2", operation_id="b" * 32)
    root(tmp_path / "cleanup-error", second)
    functions.fail_cleanup = True
    with pytest.raises(SamplingError, match="cleanup"):
        recovered.capture(second)
    functions.fail_cleanup = False
    third = request(session_id="session-3", operation_id="c" * 32)
    root(tmp_path / "cleanup-error", third)
    with pytest.raises(StorageError, match="cleanup previously failed"):
        recovered.capture(third)


def test_execution_lease_excludes_same_process_and_schema_is_packaged(
    tmp_path: Path,
) -> None:
    with (
        ExecutionLease(tmp_path),
        pytest.raises(StorageError),
        ExecutionLease(tmp_path),
    ):
        pass
    packaged_schema = json.loads(schema_path().read_text(encoding="utf-8"))
    assert (
        packaged_schema["$defs"]["DebuggerSymbolization"]["properties"][
            "refinement_granularity_bytes"
        ]["const"]
        == 4
    )
    for name in (
        "sampling-driver-event.schema.json",
        "sampling-endpoint-binding.schema.json",
        "sampling-capture-request.schema.json",
    ):
        assert (
            control_schema_path(name).read_bytes()
            == (
                Path(__file__).resolve().parents[3] / "schemas" / "v1" / name
            ).read_bytes()
        )


def test_journal_recovers_only_sidecar_owned_started_transaction(
    tmp_path: Path,
) -> None:
    journal = SamplingJournal(tmp_path, "0" * 64)
    transaction = "123e4567-e89b-42d3-a456-426614174000"
    journal.append(transaction, "configure_intent", {"method": "realtime"})
    journal.append(transaction, "configure_observed", {"method": "realtime"})
    journal.append(transaction, "start_intent", {"duration_ms": 1})
    recovered = 0

    def cleanup() -> None:
        nonlocal recovered
        recovered += 1

    journal.recover(cleanup)
    assert recovered == 1


def test_legacy_recovery_is_pinned_cleanup_only_and_cannot_upgrade_root(
    tmp_path: Path,
) -> None:
    artifact_root = root(tmp_path)
    legacy = legacy_endpoint_fingerprint("localhost", 1, "TCP", "R.2026.02+190766")
    control = artifact_root / ".t32perf-control"
    events = control / "sampling-driver-events"
    events.mkdir(parents=True)
    (control / "sampling-endpoint-binding.json").write_text(
        json.dumps(
            {
                "schema": "t32perf.sampling-endpoint-binding/v1",
                "endpoint_fingerprint": legacy,
            }
        ),
        encoding="utf-8",
    )
    journal = SamplingJournal(artifact_root, legacy, legacy_v1=True)
    transaction = "123e4567-e89b-42d3-a456-426614174099"
    journal.append(transaction, "configure_intent", {"method": "realtime"})
    journal.append(transaction, "configure_observed", {"method": "realtime"})
    journal.append(transaction, "start_intent", {"duration_ms": 1})
    journal.append(transaction, "start_observed")
    functions = FakeFunctions()
    functions.perf_enabled = True
    debugger = FakeDebugger(functions)
    current = endpoint_fingerprint(
        "localhost",
        1,
        "TCP",
        "R.2026.02+190766",
        probe_fingerprint("debug-module-serial", "debug-cable-serial", "DebugCable0"),
    )
    service = Service(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=artifact_root,
        expected_endpoint_fingerprint=current,
        recover_quarantined=True,
        recover_legacy_only=True,
        legacy_endpoint_fingerprint=legacy,
        connector=lambda **_: debugger,
    )
    service.recover_legacy_only_transaction()
    assert debugger.commands == ["PERF.DISable"]
    assert any(
        json.loads(path.read_text())["event"] == "recovery_observed"
        for path in events.iterdir()
    )
    with pytest.raises(StorageError, match="different TRACE32 endpoint"):
        SamplingJournal(artifact_root, current)


def test_recovery_only_service_rejects_capture_and_mcp_before_connector(
    tmp_path: Path,
) -> None:
    calls = 0

    def connector(**_: Any) -> FakeDebugger:
        nonlocal calls
        calls += 1
        return FakeDebugger(FakeFunctions())

    service = Service(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path),
        expected_endpoint_fingerprint="0" * 64,
        recover_quarantined=True,
        recover_legacy_only=True,
        legacy_endpoint_fingerprint="1" * 64,
        connector=connector,
    )
    with pytest.raises(SamplingError, match="recovery-only"):
        service.capture(request())
    with pytest.raises(InputError, match="recovery-only"):
        create_server(service)
    assert calls == 0


def test_legacy_recovery_rejects_bad_current_pin_before_perf_mutation(
    tmp_path: Path,
) -> None:
    artifact_root = root(tmp_path)
    control = artifact_root / ".t32perf-control"
    (control / "sampling-driver-events").mkdir(parents=True)
    (control / "sampling-endpoint-binding.json").write_text(
        json.dumps(
            {
                "schema": "t32perf.sampling-endpoint-binding/v1",
                "endpoint_fingerprint": "1" * 64,
            }
        ),
        encoding="utf-8",
    )
    functions = FakeFunctions()
    debugger = FakeDebugger(functions)
    service = Service(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=artifact_root,
        expected_endpoint_fingerprint="0" * 64,
        recover_quarantined=True,
        recover_legacy_only=True,
        legacy_endpoint_fingerprint="1" * 64,
        connector=lambda **_: debugger,
    )
    with pytest.raises(SamplingError, match="pinned fingerprint"):
        service.recover_legacy_only_transaction()
    assert debugger.commands == []
    assert (
        artifact_root / ".t32perf-control" / "sampling-endpoint-binding.json"
    ).exists()


def test_legacy_recovery_requires_existing_binding_before_connector(
    tmp_path: Path,
) -> None:
    artifact_root = root(tmp_path)
    events = artifact_root / ".t32perf-control" / "sampling-driver-events"
    events.mkdir(parents=True)
    transaction = "123e4567-e89b-42d3-a456-426614174098"
    (events / f"{transaction}-00000001.json").write_text(
        json.dumps(
            {
                "schema": "t32perf.sampling-driver-event/v1",
                "transaction_id": transaction,
                "endpoint_fingerprint": "1" * 64,
                "owner": "lauterbach-sampling-mcp/v1",
                "event": "configure_intent",
                "sequence": 1,
                "observed_at": "2026-08-29T00:00:00+00:00",
                "details": {"method": "realtime"},
            }
        ),
        encoding="utf-8",
    )
    calls = 0

    def connector(**_: Any) -> FakeDebugger:
        nonlocal calls
        calls += 1
        return FakeDebugger(FakeFunctions())

    service = Service(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=artifact_root,
        expected_endpoint_fingerprint="0" * 64,
        recover_quarantined=True,
        recover_legacy_only=True,
        legacy_endpoint_fingerprint="1" * 64,
        connector=connector,
    )
    with pytest.raises(StorageError, match="existing endpoint binding"):
        service.recover_legacy_only_transaction()
    assert calls == 0
    assert not (
        artifact_root / ".t32perf-control" / "sampling-endpoint-binding.json"
    ).exists()


def test_journal_projects_cleanup_before_export_and_recovers_cleanup_failed(
    tmp_path: Path,
) -> None:
    transaction = "123e4567-e89b-42d3-a456-426614174001"
    journal = SamplingJournal(tmp_path, "1" * 64)
    journal.append(transaction, "configure_intent", {"method": "realtime"})
    journal.append(transaction, "configure_observed", {"method": "realtime"})
    journal.append(transaction, "cleanup_intent")
    journal.append(transaction, "cleanup_observed")
    journal.append(transaction, "export_intent")
    journal.append(
        transaction,
        "export_observed",
        {
            "relative_path": "capture/staging/histogram.json",
            "sha256": "0" * 64,
            "size_bytes": 1,
        },
    )
    calls = 0
    journal.recover(
        lambda: (_ for _ in ()).throw(
            AssertionError("must not recover a safe transaction")
        )
    )
    failed = "123e4567-e89b-42d3-a456-426614174002"
    journal.append(failed, "configure_intent", {"method": "realtime"})
    journal.append(failed, "configure_observed", {"method": "realtime"})
    journal.append(failed, "cleanup_intent")
    journal.append(failed, "cleanup_failed", {"error": "RuntimeError"})

    def disable() -> None:
        nonlocal calls
        calls += 1

    with pytest.raises(StorageError, match="recover-quarantined"):
        journal.recover(disable)
    journal.recover(disable, recover_quarantined=True)
    assert calls == 1


def test_journal_rejects_invalid_order(tmp_path: Path) -> None:
    journal = SamplingJournal(tmp_path, "2" * 64)
    transaction = "123e4567-e89b-42d3-a456-426614174003"
    journal.append(transaction, "configure_intent", {"method": "realtime"})
    journal.append(transaction, "start_observed")
    with pytest.raises(StorageError, match="invalid event"):
        journal.recover(lambda: None)


def test_journal_rejects_duplicate_configure_and_post_cleanup_mutation(
    tmp_path: Path,
) -> None:
    duplicate = SamplingJournal(tmp_path / "duplicate", "4" * 64)
    transaction = "123e4567-e89b-42d3-a456-426614174004"
    duplicate.append(transaction, "configure_intent", {"method": "realtime"})
    duplicate.append(transaction, "configure_observed", {"method": "realtime"})
    duplicate.append(transaction, "configure_intent", {"method": "realtime"})
    with pytest.raises(StorageError, match="after configuration"):
        duplicate.recover(lambda: None)

    terminal = SamplingJournal(tmp_path / "terminal", "5" * 64)
    transaction = "123e4567-e89b-42d3-a456-426614174005"
    terminal.append(transaction, "configure_intent", {"method": "realtime"})
    terminal.append(transaction, "configure_observed", {"method": "realtime"})
    terminal.append(transaction, "cleanup_intent")
    terminal.append(transaction, "cleanup_observed")
    terminal.append(transaction, "start_intent", {"duration_ms": 1})
    with pytest.raises(StorageError, match="mutation after cleanup"):
        terminal.recover(lambda: None)


def test_journal_rejects_crash_temporary_entry(tmp_path: Path) -> None:
    journal = SamplingJournal(tmp_path, "3" * 64)
    (journal.directory / ".crashed-write.tmp").write_bytes(b"partial")
    with pytest.raises(StorageError, match="unsafe event"):
        SamplingJournal(tmp_path, "3" * 64)


def test_artifact_publication_never_overwrites_and_zero_rate_is_rejected(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "histogram.json"
    _publish_new(destination, b"one")
    with pytest.raises(StorageError):
        _publish_new(destination, b"two")
    functions = FakeFunctions()
    functions.perf_rate = lambda: 0
    debugger = FakeDebugger(functions)
    service = SamplingService(
        host="localhost",
        port=1,
        protocol="TCP",
        timeout=1,
        artifact_root=root(tmp_path / "zero-rate"),
        connector=lambda **_: debugger,
    )
    with pytest.raises(SamplingError, match="sampling rate"):
        service.capture(request())
    assert not list(
        (tmp_path / "zero-rate" / "session-1" / "capture" / "staging").glob("*.json")
    )
