"""The GitHub Action's body (scripts/action_run.py) and its action.yml."""
from __future__ import annotations

import importlib.util
import io
import json
import os

import pytest

from mcp_vet import risk

from helpers import fixture

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_spec = importlib.util.spec_from_file_location(
    "action_run", os.path.join(ROOT, "scripts", "action_run.py"))
action_run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(action_run)


def _env(tmp_path, path, fail_on="high", **extra):
    env = {
        "MV_PATH": path,
        "MV_FAIL_ON": fail_on,
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_OUTPUT": str(tmp_path / "output.txt"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
    }
    env.update(extra)
    return env


def _outputs(tmp_path):
    text = (tmp_path / "output.txt").read_text(encoding="utf-8")
    return dict(line.split("=", 1) for line in text.splitlines() if line)


class TestGate:
    @pytest.mark.parametrize("exit_code,fail_on,expected", [
        (0, "high", False),
        (1, "high", False),
        (2, "high", True),
        (3, "high", True),
        (2, "critical", False),
        (3, "critical", True),
        (1, "medium", True),
        (1, "low", True),
        (0, "low", False),
        (3, "none", False),
    ])
    def test_thresholds(self, exit_code, fail_on, expected):
        assert action_run.gate_fails(exit_code, fail_on) is expected

    @pytest.mark.parametrize("fail_on", ["critical", "high", "medium", "low", "none"])
    def test_could_not_look_always_fails(self, fail_on):
        assert action_run.gate_fails(risk.EXIT_ERROR, fail_on) is True


class TestRun:
    def test_poisoned_server_writes_sarif_summary_and_fails_the_gate(self, tmp_path):
        assert action_run.run(_env(tmp_path, fixture("poisoned_server"))) == 0
        out = _outputs(tmp_path)
        assert out["exit-code"] == "3"
        assert out["overall"] == "CRITICAL"
        assert out["failed"] == "true"
        log = json.loads((tmp_path / "mcp-vet.sarif").read_text(encoding="utf-8"))
        assert log["version"] == "2.1.0"
        assert len(log["runs"][0]["results"]) == int(out["findings"])
        summary = (tmp_path / "summary.md").read_text(encoding="utf-8")
        assert "CRITICAL" in summary and "**failed**" in summary
        assert "does not mean the server is safe" in summary

    def test_clean_server_passes(self, tmp_path):
        assert action_run.run(_env(tmp_path, fixture("clean_server"))) == 0
        out = _outputs(tmp_path)
        assert out["exit-code"] == "0"
        assert out["failed"] == "false"

    def test_fail_on_none_reports_but_does_not_fail(self, tmp_path):
        action_run.run(_env(tmp_path, fixture("exfil_server"), fail_on="none"))
        out = _outputs(tmp_path)
        assert out["exit-code"] == "2"
        assert out["failed"] == "false"

    def test_custom_sarif_location(self, tmp_path):
        target = tmp_path / "nested" / "out.sarif"
        action_run.run(_env(tmp_path, fixture("clean_server"), MV_SARIF=str(target)))
        assert target.exists()
        assert _outputs(tmp_path)["sarif-file"] == str(target)

    def test_missing_path_is_could_not_look(self, tmp_path):
        stderr = io.StringIO()
        code = action_run.run(_env(tmp_path, str(tmp_path / "missing")), stderr=stderr)
        assert code == risk.EXIT_ERROR
        assert _outputs(tmp_path)["failed"] == "true"
        assert "not a directory" in stderr.getvalue()
        assert not (tmp_path / "mcp-vet.sarif").exists()

    def test_empty_directory_is_could_not_look(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        assert action_run.run(_env(tmp_path, str(empty)), stderr=io.StringIO()) == risk.EXIT_ERROR

    def test_unknown_fail_on_is_a_usage_error(self, tmp_path):
        stderr = io.StringIO()
        code = action_run.run(_env(tmp_path, fixture("clean_server"), fail_on="sometimes"),
                              stderr=stderr)
        assert code == risk.EXIT_ERROR
        assert "fail-on must be one of" in stderr.getvalue()


class TestSummaryIsInert:
    def test_repository_text_cannot_become_markup(self):
        hostile = "[click](https://evil.example) <img src=x> | `code` ![i](x)"
        rendered = action_run._md(hostile)
        assert "<img" not in rendered
        assert "](" not in rendered
        assert "| " not in rendered.replace("\\| ", "")
        assert "\n" not in action_run._md("a\nb")


class TestActionYml:
    def _text(self):
        with open(os.path.join(ROOT, "action.yml"), encoding="utf-8") as handle:
            return handle.read()

    def test_it_runs_the_bundled_script(self):
        text = self._text()
        assert "scripts/action_run.py" in text
        assert os.path.exists(os.path.join(ROOT, "scripts", "action_run.py"))

    def test_inputs_reach_the_shell_through_env_only(self):
        # `${{ inputs.x }}` inside a `run:` block would be executed as shell.
        for block in self._text().split("run:")[1:]:
            body = block.split("\n    - ", 1)[0]
            assert "${{ inputs." not in body

    def test_every_input_the_script_reads_is_wired(self):
        text = self._text()
        for name in ("MV_PATH", "MV_FAIL_ON", "MV_SARIF", "MV_PURPOSE"):
            assert f"{name}:" in text

    def test_fail_on_values_match(self):
        text = self._text()
        for value in action_run.FAIL_ON_THRESHOLD:
            assert value in text
