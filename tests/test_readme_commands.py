"""The commands in the README are commands the parser accepts.

A README whose first command is rejected is the worst place for a tool to fail:
the reader has done nothing wrong yet. This does not run them (several need the
network); it checks each `mcp-vet ...` line in a bash block against the real
argument parser, so a renamed flag or a subcommand that no longer exists fails
here instead of in a stranger's terminal.
"""
from __future__ import annotations

import os
import re
import shlex

import pytest

from mcp_vet.cli import build_parser
from mcp_vet.patterns import ALL_RULES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name: str) -> str:
    with open(os.path.join(ROOT, name), encoding="utf-8") as handle:
        return handle.read()


def _bash_commands(markdown: str):
    for block in re.findall(r"```bash\n(.*?)```", markdown, re.S):
        for line in block.splitlines():
            line = line.strip()
            if not line.startswith("mcp-vet "):
                continue
            # what a shell would not hand to mcp-vet: a comment, a redirect, a pipe
            line = re.split(r"\s+(?:#|>|\|)\s*", line, maxsplit=1)[0]
            yield line


COMMANDS = sorted(set(_bash_commands(_read("README.md"))) | set(_bash_commands(_read("SKILL.md"))))


def test_the_readme_has_commands_to_check():
    assert len(COMMANDS) >= 10, COMMANDS


@pytest.mark.parametrize("line", COMMANDS)
def test_the_parser_accepts_it(line, capsys):
    words = shlex.split(line.replace("<owner>/<repo>", "owner/repo"))[1:]
    try:
        build_parser().parse_args(words)
    except SystemExit as exc:  # --help and --version exit 0 by design
        assert exc.code == 0, f"parser rejected: {line}\n{capsys.readouterr().err}"


def test_the_rule_count_in_the_readme_is_the_real_one():
    text = _read("README.md")
    assert f"all {len(ALL_RULES)} detection rules" in text
    assert f"{len(ALL_RULES)} rules" in _read("project-meta.json")


def test_the_first_screen_names_a_one_command_install():
    first_screen = _read("README.md").split("## What is this")[0]
    assert "pipx install git+https://github.com/Furkiozknn/mcp-vet" in first_screen
    assert "uvx --from git+https://github.com/Furkiozknn/mcp-vet mcp-vet" in first_screen
    assert "--offline --path ./checkout" in first_screen


def test_every_image_the_readme_shows_exists():
    text = _read("README.md")
    for target in re.findall(r'(?:src="|\]\()((?:assets|docs)/[^"\)]+)', text):
        assert os.path.exists(os.path.join(ROOT, target)), f"README points at a missing file: {target}"


def test_the_demo_record_matches_the_commands_the_readme_promises():
    record = _read(os.path.join("docs", "demo", "komutlar.txt"))
    assert "$ mcp-vet audit --offline --path ./checkout --quiet" in record
    # every recorded command has an exit code and none is a placeholder
    assert record.count("[cikis kodu") == record.count("\n$ ") + record.startswith("$ ")
    assert not [line for line in record.splitlines() if line.startswith("$ ") and "<" in line]
