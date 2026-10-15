#!/usr/bin/env python3
"""The body of the mcp-vet GitHub Action (action.yml at the repository root).

Kept in Python rather than in the action's shell step so that it runs the same
on Linux, macOS and Windows runners, and so the gate logic has tests
(tests/test_action_run.py) instead of living untested in YAML.

One audit, three outputs from it: the SARIF file for code scanning, a Markdown
summary for the job page, and the gate decision. Running the audit once means
the three cannot disagree.

Inputs arrive as environment variables, never interpolated into a script:

    MV_PATH      directory to audit (default ".")
    MV_FAIL_ON   critical | high | medium | low | none   (default "high")
    MV_SARIF     where to write the SARIF file (default $RUNNER_TEMP/mcp-vet.sarif)
    MV_PURPOSE   what the server claims to do (optional)

Outputs go to $GITHUB_OUTPUT: exit-code, overall, findings, sarif-file and
failed ("true"/"false"). The script itself exits 0 whenever it produced a
report, so the SARIF upload step still runs on a failing audit; the action's
last step reads `failed` and fails the job. "Could not look" (exit code 4)
always fails, whatever fail-on says: a gate that cannot see must not pass.
"""
from __future__ import annotations

import os
import sys
from typing import Dict, Optional, TextIO

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from mcp_vet import risk  # noqa: E402
from mcp_vet.audit import audit_directory  # noqa: E402
from mcp_vet.cli import _nothing_read, _path_problem  # noqa: E402
from mcp_vet.models import AuditReport, Severity  # noqa: E402
from mcp_vet.risk import finding_sets_headline  # noqa: E402
from mcp_vet.sarif import render_sarif  # noqa: E402

# The lowest exit code that fails the gate for each fail-on value. LOW and
# MEDIUM share exit code 1, so "low" and "medium" are the same threshold.
FAIL_ON_THRESHOLD: Dict[str, Optional[int]] = {
    "critical": risk.EXIT_CRITICAL,
    "high": risk.EXIT_HIGH,
    "medium": risk.EXIT_WARNINGS,
    "low": risk.EXIT_WARNINGS,
    "none": None,
}

MAX_SUMMARY_ROWS = 25


def gate_fails(exit_code: int, fail_on: str) -> bool:
    """Should the job fail? Exit code 4 always does."""
    if exit_code == risk.EXIT_ERROR:
        return True
    threshold = FAIL_ON_THRESHOLD[fail_on]
    return threshold is not None and exit_code >= threshold


def _md(text: str) -> str:
    """Repository-derived text, made inert for a Markdown job summary.

    The summary renders Markdown and some HTML, and paths and snippets come
    from the repository under audit, so nothing in them may become a link,
    an image, a table break or a tag.
    """
    out = []
    for ch in text:
        if ch in "<>&":
            out.append({"<": "&lt;", ">": "&gt;", "&": "&amp;"}[ch])
        elif ch in "\\`*_{}[]()#+!|~":
            out.append("\\" + ch)
        elif ch in "\r\n":
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


def summary_markdown(report: AuditReport, exit_code: int, fail_on: str, failed: bool) -> str:
    lines = [
        "## mcp-vet",
        "",
        f"**Overall:** `{report.overall.value}` (exit code {exit_code}, fail-on `{fail_on}`, "
        f"{'**failed**' if failed else 'passed'})",
        "",
        "`NOT_FLAGGED` means these checks found nothing. It does not mean the server is safe.",
        "",
    ]
    findings = report.sorted_findings()
    if findings:
        lines += ["| Severity | Confidence | Rule | Where | Sets verdict |", "|---|---|---|---|---|"]
        for finding in findings[:MAX_SUMMARY_ROWS]:
            where = ""
            for evidence in finding.evidence:
                if evidence.path:
                    where = evidence.path + (f":{evidence.line}" if evidence.line else "")
                    break
            lines.append(
                f"| {finding.severity.value} | {finding.confidence.value} | "
                f"{_md(finding.rule_id or finding.title)} | {_md(where)} | "
                f"{'yes' if finding_sets_headline(finding) else 'no'} |"
            )
        if len(findings) > MAX_SUMMARY_ROWS:
            lines.append("")
            lines.append(f"{len(findings) - MAX_SUMMARY_ROWS} more finding(s) are in the SARIF file.")
        lines.append("")
    else:
        lines += ["No findings from the checks that ran.", ""]
    if report.limitations:
        lines.append("**What this did not check**")
        lines.append("")
        lines += [f"- {_md(item)}" for item in report.limitations]
        lines.append("")
    return "\n".join(lines)


def _append(path: Optional[str], text: str) -> None:
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text)


def _outputs(path: Optional[str], values: Dict[str, str]) -> None:
    _append(path, "".join(f"{key}={value}\n" for key, value in values.items()))


def run(environ: Dict[str, str], stderr: TextIO = sys.stderr) -> int:
    path = environ.get("MV_PATH") or "."
    fail_on = (environ.get("MV_FAIL_ON") or "high").strip().lower()
    purpose = environ.get("MV_PURPOSE") or ""
    temp = environ.get("RUNNER_TEMP") or "."
    sarif_path = environ.get("MV_SARIF") or os.path.join(temp, "mcp-vet.sarif")
    output_file = environ.get("GITHUB_OUTPUT")
    summary_file = environ.get("GITHUB_STEP_SUMMARY")

    if fail_on not in FAIL_ON_THRESHOLD:
        print(f"error: fail-on must be one of {', '.join(FAIL_ON_THRESHOLD)}, got {fail_on!r}",
              file=stderr)
        _outputs(output_file, {"exit-code": str(risk.EXIT_ERROR), "failed": "true"})
        return risk.EXIT_ERROR

    problem = _path_problem(path)
    if problem:
        print(f"error: {problem}", file=stderr)
        _outputs(output_file, {"exit-code": str(risk.EXIT_ERROR), "failed": "true"})
        return risk.EXIT_ERROR

    report = audit_directory(path, purpose=purpose, target=path)
    problem = _nothing_read(report)
    if problem:
        print(f"error: {problem}", file=stderr)
        _outputs(output_file, {"exit-code": str(risk.EXIT_ERROR), "failed": "true"})
        return risk.EXIT_ERROR

    exit_code = risk.exit_code_for(report.overall)
    failed = gate_fails(exit_code, fail_on)

    os.makedirs(os.path.dirname(os.path.abspath(sarif_path)), exist_ok=True)
    with open(sarif_path, "w", encoding="utf-8") as handle:
        handle.write(render_sarif(report))

    _append(summary_file, summary_markdown(report, exit_code, fail_on, failed))
    _outputs(output_file, {
        "exit-code": str(exit_code),
        "overall": report.overall.value,
        "findings": str(len(report.findings)),
        "sarif-file": sarif_path,
        "failed": "true" if failed else "false",
    })
    print(f"mcp-vet: {report.overall.value} (exit code {exit_code}); SARIF written to {sarif_path}")
    return 0


if __name__ == "__main__":
    sys.exit(run(dict(os.environ)))
