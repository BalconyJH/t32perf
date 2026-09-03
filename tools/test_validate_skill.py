"""Regression tests for static production-skill safety checks."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from tools.validate_skill import validate

ROOT = Path(__file__).resolve().parents[1]

SOURCE_SKILL = ROOT / "skill-trace32-perf"
MCP_SKILL = ROOT / "skills" / "t32perf-mcp"
FAULTS = Path("scripts/adapters/tc234l-build190766/fault-scenarios.json")
PROFILE = Path("scripts/adapters/tc234l-build190766/profile.json")


class Tc234lFaultContractTests(unittest.TestCase):
    def copied_skill(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        target = Path(temporary.name) / SOURCE_SKILL.name
        shutil.copytree(SOURCE_SKILL, target)
        return target

    def refresh_bundle(self, skill: Path, adapter: Path = PROFILE.parent) -> None:
        manifest_path = skill / adapter / "bundle-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        lines: list[str] = []
        for entry in manifest["files"]:
            payload = (skill / adapter / entry["path"]).read_bytes()
            entry["sha256"] = hashlib.sha256(payload).hexdigest()
            lines.append(f"{entry['path']} {entry['sha256']}")
        manifest["bundle_sha256"] = hashlib.sha256(
            ("\n".join(lines) + "\n").encode("utf-8")
        ).hexdigest()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        profile_path = skill / adapter / "profile.json"
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        profile["implementation_sha256"] = manifest["bundle_sha256"]
        profile_path.write_text(json.dumps(profile), encoding="utf-8")

    def add_second_software_adapter(self, skill: Path) -> Path:
        source = skill / PROFILE.parent
        adapter = source.parent / "software-candidate"
        shutil.copytree(source, adapter)
        profile_path = adapter / "profile.json"
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        profile["adapter_id"] = "software-candidate-v1"
        profile["adapter_version"] = "2.0.0"
        self.assertIsNone(profile.get("qualification_sha256"))
        profile_path.write_text(json.dumps(profile), encoding="utf-8")
        (adapter / "ADAPTER_VERSION").write_text("2.0.0\n", encoding="utf-8")
        template_path = adapter / "capture-config-template.json"
        template = json.loads(template_path.read_text(encoding="utf-8"))
        template["adapter"] = {"id": "software-candidate-v1", "version": "2.0.0"}
        template_path.write_text(json.dumps(template), encoding="utf-8")
        self.refresh_bundle(skill, adapter.relative_to(skill))
        return adapter

    def test_checked_in_bundle_is_fail_closed(self) -> None:
        validate(SOURCE_SKILL)

    def test_runtime_bundle_rejects_skill_documentation(self) -> None:
        skill = self.copied_skill()
        manifest_path = skill / PROFILE.parent / "bundle-manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["files"].insert(
            0,
            {
                "path": "../../../SKILL.md",
                "sha256": hashlib.sha256(
                    (skill / "SKILL.md").read_bytes()
                ).hexdigest(),
            },
        )
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.refresh_bundle(skill)
        with self.assertRaisesRegex(ValueError, "documentation, not runtime input"):
            validate(skill)

    def test_rejects_advertised_flow_error(self) -> None:
        skill = self.copied_skill()
        path = skill / FAULTS
        document = json.loads(path.read_text(encoding="utf-8"))
        next(
            item for item in document["scenarios"] if item["scenario"] == "flow_error"
        )["support"] = "candidate"
        path.write_text(json.dumps(document), encoding="utf-8")
        self.refresh_bundle(skill)
        with self.assertRaisesRegex(
            ValueError, "flow_error must be explicitly unsupported"
        ):
            validate(skill)


    def test_rejects_buffer_full_without_pending_hardware_evidence(self) -> None:
        skill = self.copied_skill()
        path = skill / FAULTS
        document = json.loads(path.read_text(encoding="utf-8"))
        next(
            item
            for item in document["scenarios"]
            if item["scenario"] == "sampling_buffer_full"
        )["evidence_status"] = "qualified"
        path.write_text(json.dumps(document), encoding="utf-8")
        self.refresh_bundle(skill)
        with self.assertRaisesRegex(ValueError, "pending hardware evidence"):
            validate(skill)

    def test_rejects_unknown_scenario_fallback(self) -> None:
        skill = self.copied_skill()
        script = skill / "scripts/perf_configure.cmm"
        script.write_text(
            script.read_text(encoding="utf-8").replace(
                'IF ("&scenario"!="normal")&&("&scenario"!="sampling_buffer_full")',
                "IF 0.",
            ),
            encoding="utf-8",
        )
        self.refresh_bundle(skill)
        with self.assertRaisesRegex(ValueError, "reject unknown scenarios"):
            validate(skill)

    def test_rejects_tc234l_controller_v2_or_custom_collector_claims(self) -> None:
        for field, value, expected in [
            ("controller_protocol", "v2_custom_events_export", "protocol V1"),
            (
                "custom_event_collector",
                {"wire_protocol": "c_wire_v1"},
                "must not declare",
            ),
        ]:
            with self.subTest(field=field):
                skill = self.copied_skill()
                path = skill / PROFILE
                document = json.loads(path.read_text(encoding="utf-8"))
                document[field] = value
                path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, expected):
                    validate(skill)

    def test_rejects_missing_v2_machine_evidence_hook(self) -> None:
        skill = self.copied_skill()
        path = skill / "scripts/perf_stop_v2.cmm"
        path.write_text(
            path.read_text(encoding="utf-8").replace("V2AdapterHook:", "RemovedHook:"),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "fail-closed V2 adapter hook"):
            validate(skill)

    def test_rejects_missing_v2_export_output_slot(self) -> None:
        skill = self.copied_skill()
        path = skill / "scripts/perf_export_v2.cmm"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "custom_events_output=", "removed_custom_events_output=", 1
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "missing V2 arguments"):
            validate(skill)

    def test_validates_a_second_unqualified_software_adapter(self) -> None:
        skill = self.copied_skill()
        self.add_second_software_adapter(skill)
        validate(skill)

    def test_rejects_second_adapter_identity_mismatch(self) -> None:
        skill = self.copied_skill()
        adapter = self.add_second_software_adapter(skill)
        template_path = adapter / "capture-config-template.json"
        template = json.loads(template_path.read_text(encoding="utf-8"))
        template["adapter"]["id"] = "wrong-adapter"
        template_path.write_text(json.dumps(template), encoding="utf-8")
        self.refresh_bundle(skill, adapter.relative_to(skill))
        with self.assertRaisesRegex(ValueError, "does not match profile identity"):
            validate(skill)

    def test_rejects_duplicate_or_tampered_generic_bundle_claims(self) -> None:
        skill = self.copied_skill()
        adapter = self.add_second_software_adapter(skill)
        profile_path = adapter / "profile.json"
        profile_path.write_text(
            profile_path.read_text(encoding="utf-8").replace(
                '"adapter_id": "software-candidate-v1",',
                '"adapter_id": "software-candidate-v1", "adapter_id": "duplicate",',
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
            validate(skill)

        skill = self.copied_skill()
        adapter = self.add_second_software_adapter(skill)
        member = adapter / "perf_export.cmm"
        member.write_text(
            member.read_text(encoding="utf-8") + "\n; tampered\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(ValueError, "has SHA-256"):
            validate(skill)


class T32perfMcpSkillTests(unittest.TestCase):
    def copied_skill(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        target = Path(temporary.name) / MCP_SKILL.name
        shutil.copytree(MCP_SKILL, target)
        return target

    def test_checked_in_mcp_skill_is_valid(self) -> None:
        validate(MCP_SKILL)

    def test_rejects_scaffold_todo(self) -> None:
        skill = self.copied_skill()
        path = skill / "SKILL.md"
        path.write_text(
            path.read_text(encoding="utf-8") + "\n[TODO: finish]\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "unfinished TODO"):
            validate(skill)

    def test_rejects_link_outside_the_skill(self) -> None:
        skill = self.copied_skill()
        path = skill / "SKILL.md"
        path.write_text(
            path.read_text(encoding="utf-8") + "\n[invalid](../outside.md)\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "link target is missing|link escapes"):
            validate(skill)

    def test_rejects_non_stdio_mcp_dependency(self) -> None:
        skill = self.copied_skill()
        path = skill / "agents" / "openai.yaml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                'transport: "stdio"', 'transport: "streamable_http"'
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "local t32perf stdio"):
            validate(skill)


if __name__ == "__main__":
    unittest.main()
