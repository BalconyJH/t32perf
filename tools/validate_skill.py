#!/usr/bin/env python3
"""Validate the repository-owned TRACE32 performance skill structure."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

NAME_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
LINK_PATTERN = re.compile(r"\[[^]]+\]\(([^)]+)\)")
SCRIPT_PATTERN = re.compile(r"`([^`]+\.cmm)`")
TC234L_ADAPTER_ID = "tricore-tc234l-snooper-pc-r2026.02-b190766-v1"
ADAPTERS_DIRECTORY = Path("scripts/adapters")
ADAPTER_PROFILE_FILE = "profile.json"
ADAPTER_MANIFEST_FILE = "bundle-manifest.json"
BUNDLE_MANIFEST_FORMAT = "t32perf-target-adapter-bundle-manifest-v1"
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
UNSUPPORTED_TC234L_SCENARIOS = {"trace_overflow", "flow_error"}
V2_CONTROL_ARGUMENTS = {
    "perf_configure_v2.cmm": {
        "binding_sha256",
        "machine_evidence_output",
        "firmware_s3",
        "initial_target_state",
        "scenario",
    },
    "perf_start_v2.cmm": {
        "binding_sha256",
        "machine_evidence_output",
        "initial_target_state",
        "scenario",
    },
    "perf_stop_v2.cmm": {"binding_sha256", "machine_evidence_output"},
    "perf_get_health_v2.cmm": {
        "binding_sha256",
        "machine_evidence_output",
        "stop_evidence_sha256",
        "firmware_s3",
    },
    "perf_cleanup_v2.cmm": {
        "binding_sha256",
        "machine_evidence_output",
        "initial_target_state",
    },
}
V2_EXPORT_ARGUMENTS = {
    "binding_sha256",
    "mode",
    "trace_export_output",
    "custom_events_output",
}
MCP_SKILL_NAME = "t32perf-mcp"
MCP_TOOL_NAMES = {
    "perf_capabilities",
    "perf_capture",
    "perf_get_status",
    "perf_get_summary",
    "perf_list_artifacts",
    "perf_convert",
    "perf_compare",
    "perf_run",
}
SHARED_BUNDLE_RUNTIME_FILES = {
    "scripts/perf_cleanup.cmm",
    "scripts/perf_cleanup_v2.cmm",
    "scripts/perf_configure.cmm",
    "scripts/perf_configure_v2.cmm",
    "scripts/perf_export.cmm",
    "scripts/perf_export_v2.cmm",
    "scripts/perf_get_capabilities.cmm",
    "scripts/perf_get_health.cmm",
    "scripts/perf_get_health_v2.cmm",
    "scripts/perf_get_hotspots.cmm",
    "scripts/perf_start.cmm",
    "scripts/perf_start_v2.cmm",
    "scripts/perf_stop.cmm",
    "scripts/perf_stop_v2.cmm",
}


def parse_simple_mapping(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line.startswith((" ", "\t")):
            continue
        key, separator, value = line.partition(":")
        if not separator:
            raise ValueError(f"invalid mapping line: {line!r}")
        values[key.strip()] = value.strip().strip("\"'")
    return values


def _no_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def read_json_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_json_keys
        )
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid JSON in {path.name}: {error.msg}") from error
    if not isinstance(value, dict):
        raise TypeError(f"{path.name} must contain a JSON object")
    return value


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


def require_plain_directory(path: Path, label: str) -> None:
    try:
        mode = os.lstat(path).st_mode
    except OSError as error:
        raise ValueError(f"{label} is not accessible: {path}") from error
    if path.is_symlink() or not stat.S_ISDIR(mode):
        raise ValueError(f"{label} must be a plain directory: {path}")


def require_plain_file(path: Path, label: str) -> None:
    try:
        mode = os.lstat(path).st_mode
    except OSError as error:
        raise ValueError(f"{label} is not accessible: {path}") from error
    if path.is_symlink() or not stat.S_ISREG(mode):
        raise ValueError(f"{label} must be a plain file: {path}")


def require_plain_path_within(root: Path, path: Path, label: str) -> None:
    canonical_root = root.resolve(strict=True)
    canonical_path = path.resolve(strict=True)
    try:
        relative = canonical_path.relative_to(canonical_root)
    except ValueError as error:
        raise ValueError(
            f"{label} resolves outside the skill directory: {path}"
        ) from error
    current = canonical_root
    require_plain_directory(current, "skill directory")
    for part in relative.parts[:-1]:
        current = current / part
        require_plain_directory(current, label)
    require_plain_file(canonical_path, label)


def resolve_bundle_member(adapter: Path, skill: Path, relative: str) -> Path:
    parts = relative.split("/")
    if any(part in {"", "."} for part in parts) or parts[-1] == "..":
        raise ValueError(f"bundle member path is not canonical: {relative}")
    candidate = adapter
    for index, part in enumerate(parts):
        if part == "..":
            require_plain_directory(candidate, f"bundle member parent for {relative}")
            candidate = candidate.parent
            continue
        require_plain_directory(candidate, f"bundle member parent for {relative}")
        candidate = candidate / part
        if index == len(parts) - 1:
            require_plain_file(candidate, f"bundle member {relative}")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(skill.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise ValueError(
            f"bundle member path escapes skill directory: {relative}"
        ) from error
    require_plain_path_within(skill, resolved, f"bundle member {relative}")
    if resolved.suffix.lower() == ".md":
        raise ValueError(
            f"bundle member is documentation, not runtime input: {relative}"
        )
    try:
        resolved.relative_to(adapter.resolve(strict=True))
    except ValueError:
        skill_relative = resolved.relative_to(skill.resolve(strict=True)).as_posix()
        if skill_relative not in SHARED_BUNDLE_RUNTIME_FILES:
            raise ValueError(
                "bundle member is outside the adapter subtree and shared runtime "
                f"script set: {relative}"
            )
    return resolved


def validate_adapter_bundle(skill: Path, adapter: Path) -> dict[str, object]:
    """Validate one self-describing adapter candidate without selecting a protocol."""
    require_plain_directory(adapter, "adapter directory")
    profile_path = adapter / ADAPTER_PROFILE_FILE
    manifest_path = adapter / ADAPTER_MANIFEST_FILE
    require_plain_file(profile_path, "adapter profile")
    require_plain_file(manifest_path, "adapter bundle manifest")
    profile = read_json_object(profile_path)
    manifest = read_json_object(manifest_path)

    if profile.get("schema") != "t32perf.target-adapter-profile/v1":
        raise ValueError(f"{adapter.name} profile has an unexpected schema")
    adapter_id = profile.get("adapter_id")
    adapter_version = profile.get("adapter_version")
    if not isinstance(adapter_id, str) or not adapter_id:
        raise ValueError(f"{adapter.name} profile requires a non-empty adapter_id")
    if not isinstance(adapter_version, str) or not adapter_version:
        raise ValueError(f"{adapter.name} profile requires a non-empty adapter_version")
    implementation = require_sha256(
        profile.get("implementation_sha256"),
        f"{adapter.name} profile implementation_sha256",
    )

    if set(manifest) != {"format", "files", "bundle_sha256"}:
        raise ValueError(f"{adapter.name} bundle manifest has unexpected fields")
    if manifest.get("format") != BUNDLE_MANIFEST_FORMAT:
        raise ValueError(f"{adapter.name} bundle manifest has an unexpected format")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ValueError(
            f"{adapter.name} bundle manifest requires a non-empty files array"
        )
    bundle_digest = require_sha256(
        manifest.get("bundle_sha256"), "bundle manifest bundle_sha256"
    )

    canonical_lines: list[str] = []
    previous_path: str | None = None
    portable_paths: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise ValueError(
                f"{adapter.name} bundle manifest member is not an exact path/SHA object"
            )
        path = entry.get("path")
        if (
            not isinstance(path, str)
            or not path
            or "\\" in path
            or path.startswith("/")
        ):
            raise ValueError(
                f"{adapter.name} bundle member path is not canonical: {path!r}"
            )
        if previous_path is not None and previous_path >= path:
            raise ValueError(
                f"{adapter.name} bundle paths must be strictly bytewise sorted and unique"
            )
        if path.lower() in portable_paths:
            raise ValueError(
                f"{adapter.name} bundle member path is not portable-unique: {path}"
            )
        previous_path = path
        portable_paths.add(path.lower())
        claimed = require_sha256(entry.get("sha256"), f"bundle member {path} SHA-256")
        member = resolve_bundle_member(adapter, skill, path)
        actual = hashlib.sha256(member.read_bytes()).hexdigest()
        if actual != claimed:
            raise ValueError(
                f"{adapter.name} bundle member {path} has SHA-256 {actual}, expected {claimed}"
            )
        canonical_lines.append(f"{path} {claimed}")

    actual_bundle = hashlib.sha256(
        ("\n".join(canonical_lines) + "\n").encode()
    ).hexdigest()
    if actual_bundle != bundle_digest:
        raise ValueError(
            f"{adapter.name} canonical bundle digest is {actual_bundle}, manifest declares {bundle_digest}"
        )
    if implementation != bundle_digest:
        raise ValueError(
            f"{adapter.name} profile implementation digest does not match verified bundle"
        )

    version_path = adapter / "ADAPTER_VERSION"
    template_path = adapter / "capture-config-template.json"
    require_plain_file(version_path, "adapter version")
    require_plain_file(template_path, "adapter capture-config template")
    if version_path.read_text(encoding="utf-8").strip() != adapter_version:
        raise ValueError(
            f"{adapter.name} ADAPTER_VERSION does not match profile adapter_version"
        )
    template = read_json_object(template_path)
    identity = template.get("adapter")
    if (
        not isinstance(identity, dict)
        or identity.get("id") != adapter_id
        or identity.get("version") != adapter_version
    ):
        raise ValueError(
            f"{adapter.name} capture-config template does not match profile identity"
        )
    return profile


def discover_adapter_profiles(skill: Path) -> list[tuple[Path, dict[str, object]]]:
    adapters_root = skill / ADAPTERS_DIRECTORY
    require_plain_directory(adapters_root, "adapter catalog directory")
    adapters: list[tuple[Path, dict[str, object]]] = []
    adapter_ids: set[str] = set()
    for adapter in sorted(adapters_root.iterdir(), key=lambda path: path.name):
        if not adapter.is_dir() or adapter.is_symlink():
            raise ValueError(
                f"adapter catalog member must be a plain directory: {adapter.name}"
            )
        profile = validate_adapter_bundle(skill, adapter)
        adapter_id = profile["adapter_id"]
        assert isinstance(adapter_id, str)
        if adapter_id in adapter_ids:
            raise ValueError(f"adapter profile identity is duplicated: {adapter_id}")
        adapter_ids.add(adapter_id)
        adapters.append((adapter, profile))
    if not adapters:
        raise ValueError("adapter catalog must contain at least one adapter")
    return adapters


def validate_tc234l_fault_contract(
    skill: Path, adapter: Path, profile: dict[str, object]
) -> None:
    """Keep the fixed SNOOPer sampling bundle from advertising flow-only faults."""
    faults = read_json_object(adapter.joinpath("fault-scenarios.json"))
    if faults.get("schema") != "t32perf.trace32-fault-scenarios/v1":
        raise ValueError("TC234L fault scenarios have an unexpected schema")
    if faults.get("adapter_id") != TC234L_ADAPTER_ID:
        raise ValueError("TC234L fault scenarios target an unexpected adapter")
    if profile.get("adapter_id") != TC234L_ADAPTER_ID:
        raise ValueError("TC234L profile targets an unexpected adapter")
    if profile.get("controller_protocol") != "v1":
        raise ValueError("TC234L profile must remain on Controller protocol V1")
    if profile.get("custom_event_collector") is not None:
        raise ValueError("TC234L profile must not declare a custom-event collector")
    capabilities = profile.get("capabilities")
    if not isinstance(capabilities, dict):
        raise TypeError("TC234L profile capabilities must be an object")
    custom_events = capabilities.get("custom_events")
    if (
        not isinstance(custom_events, dict)
        or custom_events.get("support") != "unavailable"
    ):
        raise ValueError("TC234L custom_events capability must remain unavailable")

    scenarios = faults.get("scenarios")
    if not isinstance(scenarios, list):
        raise TypeError("TC234L fault scenarios must be an array")
    by_name: dict[str, dict[str, object]] = {}
    for entry in scenarios:
        if not isinstance(entry, dict) or not isinstance(entry.get("scenario"), str):
            raise TypeError("TC234L fault scenario entries require a string scenario")
        name = entry["scenario"]
        if name in by_name:
            raise ValueError(f"TC234L fault scenario is duplicated: {name}")
        by_name[name] = entry

    for name in UNSUPPORTED_TC234L_SCENARIOS:
        entry = by_name.get(name)
        if entry is None or entry.get("support") != "unsupported":
            raise ValueError(f"TC234L {name} must be explicitly unsupported")
        if not isinstance(entry.get("reason"), str) or not entry["reason"]:
            raise ValueError(f"TC234L {name} requires an unsupported reason")
        if "script" in entry or "driver_action" in entry or "fault_point" in entry:
            raise ValueError(f"TC234L {name} must not declare an injector")

    buffer_full = by_name.get("sampling_buffer_full")
    if buffer_full is None or buffer_full.get("support") != "candidate":
        raise ValueError("TC234L sampling_buffer_full must remain a candidate")
    if buffer_full.get("evidence_status") != "pending_hardware_evidence":
        raise ValueError(
            "TC234L sampling_buffer_full requires pending hardware evidence"
        )

    profile_scenarios = profile.get("scenarios")
    if not isinstance(profile_scenarios, list):
        raise TypeError("TC234L profile scenarios must be an array")
    profile_names: set[str] = set()
    for entry in profile_scenarios:
        if not isinstance(entry, dict) or not isinstance(entry.get("scenario"), str):
            raise TypeError("TC234L profile scenario entries require a string scenario")
        name = entry["scenario"]
        if name in profile_names:
            raise ValueError(f"TC234L profile scenario is duplicated: {name}")
        profile_names.add(name)
        if name in UNSUPPORTED_TC234L_SCENARIOS:
            raise ValueError(f"TC234L profile must not advertise unsupported {name}")
        if name != "normal" and by_name.get(name, {}).get("support") == "unsupported":
            raise ValueError(f"TC234L profile advertises unsupported scenario {name}")

    for script_name, allowed_scenarios in {
        "perf_configure.cmm": {"normal", "sampling_buffer_full"},
        "perf_start.cmm": {"normal", "cmm_abort"},
    }.items():
        script = skill.joinpath("scripts", script_name).read_text(encoding="utf-8")
        for name in allowed_scenarios:
            if f'"&scenario"=="{name}"' not in script:
                raise ValueError(f"{script_name} does not explicitly dispatch {name}")
        for name in UNSUPPORTED_TC234L_SCENARIOS:
            if f'"&scenario"=="{name}"' in script:
                raise ValueError(f"{script_name} dispatches unsupported {name}")
        if not all(f'("&scenario"!="{name}")' in script for name in allowed_scenarios):
            raise ValueError(
                f"{script_name} must reject unknown scenarios before dispatch"
            )


def validate_common_skill(skill: Path) -> tuple[Path, str, str, str]:
    skill = skill.resolve(strict=True)
    require_plain_directory(skill, "skill directory")
    skill_document = skill.joinpath("SKILL.md")
    require_plain_file(skill_document, "SKILL.md")
    document = skill_document.read_text(encoding="utf-8")
    lines = document.splitlines()
    if len(lines) < 4 or lines[0] != "---":
        raise ValueError("SKILL.md must start with YAML frontmatter")
    try:
        end = lines.index("---", 1)
    except ValueError as error:
        raise ValueError("SKILL.md frontmatter is not closed") from error
    frontmatter = parse_simple_mapping("\n".join(lines[1:end]))
    if set(frontmatter) != {"name", "description"}:
        raise ValueError("SKILL.md frontmatter must contain only name and description")
    name = frontmatter["name"]
    description = frontmatter["description"]
    if not NAME_PATTERN.fullmatch(name) or len(name) > 64:
        raise ValueError("skill name is not a valid lowercase hyphenated identifier")
    if skill.name not in {name, f"skill-{name}"}:
        raise ValueError("skill directory name does not match frontmatter name")
    if (
        not description
        or len(description) > 1024
        or "<" in description
        or ">" in description
    ):
        raise ValueError(
            "skill description is empty, oversized, or contains angle brackets"
        )
    if "[TODO:" in document:
        raise ValueError("skill instructions contain an unfinished TODO placeholder")

    body = "\n".join(lines[end + 1 :])
    for target in LINK_PATTERN.findall(body):
        if "://" in target or target.startswith("#"):
            continue
        relative, _, _fragment = target.partition("#")
        try:
            path = skill.joinpath(relative).resolve(strict=True)
        except OSError as error:
            raise ValueError(f"skill link target is missing: {target}") from error
        if skill not in path.parents:
            raise ValueError(f"skill link escapes the skill directory: {target}")
    agent_path = skill.joinpath("agents", "openai.yaml")
    require_plain_file(agent_path, "agents/openai.yaml")
    agent = agent_path.read_text(encoding="utf-8")
    for required in [
        "interface:",
        "display_name:",
        "short_description:",
        "default_prompt:",
    ]:
        if required not in agent:
            raise ValueError(f"agents/openai.yaml is missing {required}")
    if f"${name}" not in agent:
        raise ValueError("default_prompt must explicitly invoke the skill")
    return skill, name, body, agent


def validate_t32perf_mcp_skill(skill: Path, body: str, agent: str) -> None:
    for tool in MCP_TOOL_NAMES:
        if f"`{tool}`" not in body and f"`{tool}`" not in skill.joinpath(
            "references", "operation-boundaries.md"
        ).read_text(encoding="utf-8"):
            raise ValueError(f"t32perf-mcp does not document {tool}")
    if not re.search(
        r'^\s*- type: "mcp"\s*$\n^\s+value: "t32perf"\s*$[\s\S]*?^\s+transport: "stdio"\s*$',
        agent,
        re.MULTILINE,
    ):
        raise ValueError("t32perf-mcp requires the local t32perf stdio MCP dependency")
    if re.search(r"^\s+url:\s*", agent, re.MULTILINE):
        raise ValueError("t32perf-mcp stdio MCP dependency must not declare a URL")


def validate(skill: Path) -> None:
    skill, name, _body, agent = validate_common_skill(skill)
    if name == MCP_SKILL_NAME:
        validate_t32perf_mcp_skill(skill, _body, agent)
        return
    if name != "trace32-perf":
        return

    document = skill.joinpath("SKILL.md").read_text(encoding="utf-8")
    lines = document.splitlines()
    end = lines.index("---", 1)
    body = "\n".join(lines[end + 1 :])
    declared_scripts = set(SCRIPT_PATTERN.findall(body))
    actual_scripts = {
        path.name
        for path in skill.joinpath("scripts").glob("*.cmm")
        if not path.stem.endswith("_v2")
    }
    if declared_scripts != actual_scripts:
        raise ValueError(
            f"script inventory differs: declared={sorted(declared_scripts)!r}, "
            f"actual={sorted(actual_scripts)!r}"
        )

    evidence_scripts = {
        "perf_get_capabilities.cmm",
        "perf_configure.cmm",
        "perf_start.cmm",
        "perf_stop.cmm",
        "perf_get_health.cmm",
        "perf_cleanup.cmm",
    }
    for script_name in sorted(actual_scripts):
        script = skill.joinpath("scripts", script_name).read_text(encoding="utf-8")
        if "binding_sha256" not in script:
            raise ValueError(f"{script_name} is missing controller binding")
        for line in script.splitlines():
            if (
                '""protocol"":""t32perf/1""' in line
                and '""binding_sha256""' not in line
            ):
                raise ValueError(f"{script_name} has an unbound response frame")
        if script_name in evidence_scripts and "evidence_output" not in script:
            raise ValueError(f"{script_name} is missing machine-evidence output")
        if "&plain=" in script or 'IF "&line"=="&plain"' in script:
            raise ValueError(f"{script_name} accepts an unquoted key=value handoff")

    # Controller V2 uses distinct argument names and output arity.  Root CMM
    # scripts cannot select an adapter from a binding digest, so they must stop
    # at the explicit adapter-owned hook rather than accidentally invoke TC234L.
    for script_name, required in V2_CONTROL_ARGUMENTS.items():
        script = skill.joinpath("scripts", script_name).read_text(encoding="utf-8")
        missing = sorted(
            key
            for key in required
            if key != "binding_sha256"
            and f'STRing.SCANAndExtract("&argument","{key}=","")' not in script
        )
        if missing:
            raise ValueError(f"{script_name} is missing V2 arguments: {missing}")
        if "V2AdapterHook:" not in script or "v2_adapter_hook_required" not in script:
            raise ValueError(f"{script_name} lacks the fail-closed V2 adapter hook")

    export = skill.joinpath("scripts", "perf_export_v2.cmm").read_text(encoding="utf-8")
    missing = sorted(
        key
        for key in V2_EXPORT_ARGUMENTS
        if key != "binding_sha256"
        and f'STRing.SCANAndExtract("&argument","{key}=","")' not in export
    )
    if missing:
        raise ValueError(f"perf_export_v2.cmm is missing V2 arguments: {missing}")
    if "V2AdapterHook:" not in export or "v2_adapter_hook_required" not in export:
        raise ValueError("perf_export_v2.cmm lacks the fail-closed V2 adapter hook")

    tc234l_profiles = [
        (adapter, profile)
        for adapter, profile in discover_adapter_profiles(skill)
        if profile["adapter_id"] == TC234L_ADAPTER_ID
    ]
    if len(tc234l_profiles) != 1:
        raise ValueError(
            "adapter catalog must contain exactly one TC234L profile identity"
        )
    validate_tc234l_fault_contract(skill, *tc234l_profiles[0])


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_skill.py <skill-directory>", file=sys.stderr)
        return 2
    try:
        validate(Path(sys.argv[1]))
    except (OSError, TypeError, ValueError) as error:
        print(f"skill validation failed: {error}", file=sys.stderr)
        return 1
    skill = Path(sys.argv[1]).resolve(strict=True).name
    print(json.dumps({"ok": True, "skill": skill.removeprefix("skill-")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
