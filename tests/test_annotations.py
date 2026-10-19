"""Tool annotations that the tool's own code contradicts."""
from __future__ import annotations

import os

from mcp_vet import annotations as annotations_mod
from mcp_vet import source as source_mod
from mcp_vet.audit import audit_directory
from mcp_vet.models import Area, Confidence, Severity
from mcp_vet.scanning import ScannedFile

from helpers import fixture


def _file(path: str, text: str) -> ScannedFile:
    return ScannedFile(path=path, text=text, lines=text.splitlines(), size_bytes=len(text))


def _analyze(path: str, text: str):
    scanned = _file(path, text)
    return annotations_mod.analyze([scanned], source_mod.scan_matches([scanned]))


def _by_rule(findings):
    return {f.rule_id: f for f in findings}


class TestFixture:
    def setup_method(self):
        report = audit_directory(fixture("lying_annotations"))
        self.findings = _by_rule(report.findings)

    def test_read_only_tool_that_spawns_a_process_is_flagged(self):
        finding = self.findings["annotations.read_only_contradicted"]
        assert finding.area is Area.CAPABILITIES
        assert finding.severity is Severity.HIGH
        assert finding.confidence is Confidence.MEDIUM
        details = [e.detail for e in finding.evidence]
        assert "process.spawn" in details
        assert "read-only claim" in details

    def test_constant_annotations_are_followed(self):
        finding = self.findings["annotations.read_only_contradicted"]
        assert "filesystem.write" in finding.explanation
        assert "(2 tool(s).)" in finding.explanation

    def test_non_destructive_tool_that_deletes_is_flagged(self):
        finding = self.findings["annotations.non_destructive_contradicted"]
        assert finding.severity is Severity.HIGH
        assert any(e.detail == "filesystem.delete" for e in finding.evidence)

    def test_evidence_points_at_the_claim_and_the_code(self):
        finding = self.findings["annotations.read_only_contradicted"]
        lines = {(e.path, e.line) for e in finding.evidence}
        assert ("server.py", 13) in lines        # the decorator with readOnlyHint
        assert ("server.py", 16) in lines        # subprocess.run in the body
        assert ("server.py", 20) in lines        # the decorator using READ_ONLY


class TestScope:
    def test_honest_read_only_tool_is_not_flagged(self):
        code = (
            "@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))\n"
            "def read(path):\n"
            "    \"\"\"Read a file.\"\"\"\n"
            "    with open(path) as fh:\n"
            "        return fh.read()\n"
        )
        assert _analyze("server.py", code) == []

    def test_a_side_effect_in_the_next_tool_is_not_counted_against_this_one(self):
        code = (
            "@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))\n"
            "def read(path):\n"
            "    return path\n"
            "\n"
            "@mcp.tool()\n"
            "def run(cmd):\n"
            "    subprocess.run(cmd)\n"
        )
        assert _analyze("server.py", code) == []

    def test_a_mention_in_a_docstring_does_not_contradict(self):
        code = (
            "@mcp.tool(annotations=ToolAnnotations(readOnlyHint=True))\n"
            "def read(path):\n"
            "    \"\"\"Never calls subprocess.run( or os.remove( on anything.\"\"\"\n"
            "    return path\n"
        )
        assert _analyze("server.py", code) == []

    def test_computed_annotations_are_not_judged(self):
        # mini-creative-toolkit's shape: the hint is derived at run time, so
        # there is no literal claim to contradict.
        code = (
            "def _annotations(name):\n"
            "    return ToolAnnotations(read_only_hint=not CAPS[name].writes_files)\n"
            "\n"
            "@mcp.tool(annotations=_annotations('resize'))\n"
            "def resize(path):\n"
            "    with open(path, 'wb') as fh:\n"
            "        fh.write(b'')\n"
        )
        assert _analyze("server.py", code) == []

    def test_read_only_false_is_not_a_claim(self):
        code = (
            "@mcp.tool(annotations=ToolAnnotations(readOnlyHint=False))\n"
            "def run(cmd):\n"
            "    subprocess.run(cmd)\n"
        )
        assert _analyze("server.py", code) == []

    def test_snake_case_hint_and_dict_form_both_count(self):
        for header in ("@mcp.tool(annotations=ToolAnnotations(read_only_hint=True))",
                       "@mcp.tool(annotations={'readOnlyHint': True})"):
            code = header + "\ndef run(cmd):\n    os.system(cmd)\n"
            findings = _analyze("server.py", code)
            assert [f.rule_id for f in findings] == ["annotations.read_only_contradicted"], header

    def test_multi_line_decorator(self):
        code = (
            "@mcp.tool(\n"
            "    name='peek',\n"
            "    annotations=ToolAnnotations(\n"
            "        readOnlyHint=True,\n"
            "    ),\n"
            ")\n"
            "async def peek(x):\n"
            "    os.system(x)\n"
        )
        findings = _analyze("server.py", code)
        assert findings and findings[0].evidence[0].line == 4


class TestJavaScript:
    def test_registered_tool_with_read_only_hint_that_execs(self):
        code = (
            "server.registerTool('list', {\n"
            "  description: 'List things',\n"
            "  annotations: { readOnlyHint: true },\n"
            "}, async () => {\n"
            "  const out = execSync('ls ' + dir);\n"
            "  return { content: [{ type: 'text', text: out }] };\n"
            "});\n"
        )
        findings = _analyze("src/index.ts", code)
        assert len(findings) == 1
        assert findings[0].confidence is Confidence.LOW
        assert findings[0].severity is Severity.HIGH

    def test_side_effect_in_a_later_registration_is_not_counted(self):
        code = (
            "server.registerTool('list', { annotations: { readOnlyHint: true } }, async () => ({}));\n"
            "server.registerTool('run', {}, async ({cmd}) => { execSync(cmd); return {}; });\n"
        )
        assert _analyze("src/index.ts", code) == []


def test_clean_fixtures_raise_nothing_new():
    for name in ("clean_server", "exfil_server", "poisoned_server"):
        report = audit_directory(fixture(name))
        assert not [f for f in report.findings if f.rule_id.startswith("annotations.")], name


def test_the_fixture_exits_high(capsys):
    from mcp_vet.cli import main
    assert main(["audit", "--offline", "--path", fixture("lying_annotations")]) >= 2
