#!/usr/bin/env python3
"""vet.py - the mcp-vet command line, bundled with the skill.

This file stays at the path SKILL.md and the README have always named, so an
existing install keeps working. The analysis itself lives in the `mcp_vet`
package next to it: source scanning, capability and credential detection,
data-flow correlation, dependency and installation analysis, tool-poisoning
checks and MCP Registry provenance are far more than one script should hold,
and a rule set nobody can read is a rule set nobody can audit.

Still zero third-party dependencies - standard library only - so
`python3 scripts/vet.py ...` works with no pip install step.

Still read-only and side-effect-free:

  * It never clones a repository.
  * It never writes to `.mcp.json` or `~/.claude/skills/`.
  * It never installs anything.
  * It never executes any code from the repository it is analyzing.

It reports evidence. Deciding whether to trust a server remains a judgement
call it does not attempt to make for you.

Usage:
    python3 scripts/vet.py search "<need> mcp"
    python3 scripts/vet.py registry "<need>"
    python3 scripts/vet.py check <owner>/<repo>
    python3 scripts/vet.py audit <owner>/<repo> --path <checkout>
    python3 scripts/vet.py audit --offline --path <checkout>
    python3 scripts/vet.py report <owner>/<repo> --path <checkout>   # JSON
"""
from __future__ import annotations

import os
import sys

# Allow running as a plain script (`python3 scripts/vet.py`) as well as from an
# installed package: the repository root has to be importable either way.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from mcp_vet.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
