"""The detection catalogue: every pattern mcp-vet looks for, in one file.

Kept as data rather than scattered `if` statements so the whole rule set can be
read, reviewed and argued with in one sitting. A security tool whose rules
cannot be audited is asking for the same trust it exists to withhold.

Design constraints, all deliberate:

* **Regexes stay simple.** No nested quantifiers, no backtracking traps. These
  run over attacker-supplied text, so a pattern that can be made to hang is a
  denial-of-service bug in the analyzer itself.
* **Matching a pattern is not proof.** `subprocess.run` is how a legitimate git
  MCP server does its job. Severity says how bad it would be if it is what it
  looks like; confidence says how sure the match is. Nothing here decides.
* **Language-scoped.** A rule that only makes sense for Python does not fire on
  a README that happens to contain the word.

The genuinely interesting signals are combinations, not single matches - those
live in `source.py`, which correlates what this file finds.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import FrozenSet, List, Optional, Pattern

from .models import Area, Confidence, Severity

PY = frozenset({".py"})
JS = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"})
SH = frozenset({".sh", ".bash", ".zsh"})
ANY_SOURCE = PY | JS | SH | frozenset({".rb", ".go", ".rs", ".php", ".ps1", ".pl", ".lua"})
ANY = frozenset()  # empty means "every scanned file, including config and docs"

# Roles a match can play in a data-flow chain. A rule that is neither is just
# an observation.
ROLE_SOURCE = "source"   # reads something sensitive
ROLE_SINK = "sink"       # can send something outward
ROLE_EXEC = "exec"       # can run something


@dataclass(frozen=True)
class Rule:
    rule_id: str
    regex: Pattern
    title: str
    explanation: str
    severity: Severity
    confidence: Confidence
    area: Area = Area.SOURCE_CODE
    extensions: FrozenSet[str] = ANY_SOURCE
    capability: Optional[str] = None
    remediation: Optional[str] = None
    role: Optional[str] = None
    # Findings this noisy are only worth reporting in aggregate, or as part of
    # a combination. They still create capabilities.
    informational_only: bool = False

    def applies_to(self, extension: str) -> bool:
        return not self.extensions or extension in self.extensions


def _c(pattern: str) -> Pattern:
    return re.compile(pattern)


# --------------------------------------------------------------------------
# Command and code execution
# --------------------------------------------------------------------------

EXECUTION_RULES: List[Rule] = [
    Rule(
        rule_id="source.shell_true",
        regex=_c(r"shell\s*=\s*True"),
        extensions=PY,
        title="Subprocess invoked through a shell",
        explanation=(
            "shell=True hands the command string to /bin/sh, so any part of it that "
            "comes from tool input becomes shell syntax rather than a literal argument. "
            "For an MCP server this matters more than usual: tool arguments are chosen "
            "by a model that a third party may be able to influence."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        capability="shell.execute",
        remediation=(
            "Prefer a list argument with shell=False. If a shell really is required, "
            "confirm every interpolated value is validated against an allowlist."
        ),
        role=ROLE_EXEC,
    ),
    Rule(
        rule_id="source.os_system",
        regex=_c(r"\bos\.system\s*\("),
        extensions=PY,
        title="os.system() executes a shell command string",
        explanation=(
            "os.system always goes through a shell and offers no way to pass arguments "
            "safely, so any interpolated value is shell syntax."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        capability="shell.execute",
        remediation="Replace with subprocess.run([...], shell=False).",
        role=ROLE_EXEC,
    ),
    Rule(
        rule_id="source.os_popen",
        regex=_c(r"\bos\.popen\s*\("),
        extensions=PY,
        title="os.popen() executes a shell command string",
        explanation="Same shell-injection surface as os.system, with a pipe attached.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        capability="shell.execute",
        remediation="Replace with subprocess.run([...], shell=False, capture_output=True).",
        role=ROLE_EXEC,
    ),
    Rule(
        rule_id="source.subprocess",
        regex=_c(r"\bsubprocess\.(?:run|call|check_call|check_output|Popen)\s*\("),
        extensions=PY,
        title="Spawns external processes",
        explanation=(
            "The server runs other programs. That is normal for a git, docker or "
            "ffmpeg server and abnormal for one that only talks to an HTTP API - "
            "judge it against what the server claims to do."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        capability="process.spawn",
        remediation="Confirm the executable and arguments cannot be steered by tool input.",
        role=ROLE_EXEC,
    ),
    Rule(
        rule_id="source.node_exec",
        regex=_c(r"\b(?:child_process\s*\.\s*)?exec(?:Sync)?\s*\("),
        extensions=JS,
        title="child_process.exec() runs a command through a shell",
        explanation=(
            "exec/execSync interpret their argument as a shell command line, so "
            "interpolated values become shell syntax."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        capability="shell.execute",
        remediation="Use execFile or spawn with an argument array instead.",
        role=ROLE_EXEC,
    ),
    Rule(
        rule_id="source.node_spawn",
        regex=_c(r"\bspawn(?:Sync)?\s*\(|\bexecFile(?:Sync)?\s*\("),
        extensions=JS,
        title="Spawns external processes",
        explanation="The server runs other programs; weigh that against its stated purpose.",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        capability="process.spawn",
        role=ROLE_EXEC,
    ),
    Rule(
        rule_id="source.python_eval",
        regex=_c(r"(?<![\w.])eval\s*\("),
        extensions=PY,
        title="eval() evaluates code at runtime",
        explanation=(
            "Whatever reaches eval becomes executable code. If any of it derives from "
            "tool input or a network response, that is remote code execution."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        capability="code.eval",
        remediation="Replace with explicit parsing (ast.literal_eval, json.loads).",
        role=ROLE_EXEC,
    ),
    Rule(
        rule_id="source.python_exec",
        regex=_c(r"(?<![\w.])exec\s*\("),
        extensions=PY,
        title="exec() executes code at runtime",
        explanation="Executes a constructed string as Python. Same exposure as eval().",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        capability="code.eval",
        role=ROLE_EXEC,
    ),
    Rule(
        rule_id="source.js_function_ctor",
        regex=_c(r"new\s+Function\s*\(|(?<![\w.])eval\s*\("),
        extensions=JS,
        title="Runtime code construction (eval / new Function)",
        explanation="Turns a string into executable code at runtime.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        capability="code.eval",
        role=ROLE_EXEC,
    ),
    Rule(
        rule_id="source.dynamic_import",
        regex=_c(r"__import__\s*\(|importlib\.import_module\s*\("),
        extensions=PY,
        title="Imports modules chosen at runtime",
        explanation=(
            "A module name computed at runtime can load code the reader never sees "
            "named in the source."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        capability="code.dynamic_import",
    ),
    Rule(
        rule_id="source.pickle_load",
        regex=_c(r"\bpickle\.loads?\s*\(|\bmarshal\.loads\s*\("),
        extensions=PY,
        title="Deserializes pickle data",
        explanation=(
            "Unpickling untrusted data is arbitrary code execution by design - the "
            "format can name a callable to invoke."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        capability="code.eval",
        remediation="Use JSON, or only unpickle data you produced yourself.",
    ),
    Rule(
        rule_id="source.curl_pipe_shell",
        regex=_c(r"(?:curl|wget)[^\n|;]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|d)?sh"),
        extensions=ANY,
        title="Downloads a script and pipes it straight into a shell",
        explanation=(
            "curl | sh executes whatever the server returns at that moment, with no "
            "signature, no pinned hash and nothing for a reader to review. Whoever "
            "controls that URL - or the network path to it - controls your machine."
        ),
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        capability="code.remote_execution",
        remediation=(
            "Download to a file, verify a published checksum or signature, read it, "
            "then run it as a separate step."
        ),
        role=ROLE_EXEC,
    ),
]


# --------------------------------------------------------------------------
# Filesystem
# --------------------------------------------------------------------------

FILESYSTEM_RULES: List[Rule] = [
    Rule(
        rule_id="source.fs_read",
        regex=_c(r"\bopen\s*\(|\.read_text\s*\(|\.read_bytes\s*\(|readFileSync?\s*\(|fs\.promises\.readFile"),
        extensions=PY | JS,
        title="Reads files from disk",
        explanation="The server reads local files.",
        severity=Severity.INFO,
        confidence=Confidence.MEDIUM,
        capability="filesystem.read",
        role=ROLE_SOURCE,
        informational_only=True,
    ),
    Rule(
        rule_id="source.fs_write",
        regex=_c(r"\.write_text\s*\(|\.write_bytes\s*\(|writeFileSync?\s*\(|fs\.promises\.writeFile|\bopen\s*\([^)\n]{0,120}[\"'][wax]"),
        extensions=PY | JS,
        title="Writes files to disk",
        explanation="The server creates or modifies local files.",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        capability="filesystem.write",
        informational_only=True,
    ),
    Rule(
        rule_id="source.fs_delete",
        regex=_c(r"shutil\.rmtree\s*\(|\bos\.remove\s*\(|\bos\.unlink\s*\(|fs\.rmSync\s*\(|fs\.unlinkSync?\s*\(|rm\s+-rf\b"),
        extensions=ANY,
        title="Deletes files or directories",
        explanation=(
            "Recursive deletion driven by a computed path is how an accident becomes "
            "data loss. Check what determines the path."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        capability="filesystem.delete",
        remediation="Confirm the deletion root is fixed, not derived from tool input.",
    ),
    Rule(
        rule_id="source.chmod_exec",
        regex=_c(r"chmod\s+(?:\+x|[0-7]*7[0-7]*)\b|os\.chmod\s*\([^)\n]{0,80}0o7"),
        extensions=ANY,
        title="Marks a file executable",
        explanation=(
            "Making a file executable is a normal build step and also the step right "
            "before running a downloaded binary. Check which one this is."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        capability="filesystem.chmod",
    ),
]


# --------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------

NETWORK_RULES: List[Rule] = [
    Rule(
        rule_id="source.http_client",
        regex=_c(
            r"\brequests\.(?:get|post|put|patch|delete|request)\s*\(|"
            r"\bhttpx\.(?:get|post|put|patch|delete|request|AsyncClient|Client)\s*\(|"
            r"urllib\.request\.urlopen\s*\(|"
            r"\bfetch\s*\(|\baxios\.|\bgot\s*\(|http\.request\s*\("
        ),
        extensions=PY | JS,
        title="Makes outbound HTTP requests",
        explanation="The server can send data to network destinations.",
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        capability="network.external",
        role=ROLE_SINK,
        informational_only=True,
    ),
    Rule(
        rule_id="source.raw_socket",
        regex=_c(r"socket\.socket\s*\(|net\.createConnection\s*\(|new\s+WebSocket\s*\("),
        extensions=PY | JS,
        title="Opens raw sockets",
        explanation=(
            "Raw socket use bypasses the HTTP libraries most servers rely on, and is "
            "unusual unless the server implements a protocol of its own."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        capability="network.socket",
        role=ROLE_SINK,
    ),
    Rule(
        rule_id="source.dns_exfil_shape",
        regex=_c(r"socket\.gethostbyname\s*\(|dns\.(?:resolve|lookup)\s*\("),
        extensions=PY | JS,
        title="Performs DNS lookups on constructed names",
        explanation=(
            "DNS is a common covert channel: data encoded into a hostname leaves the "
            "machine even when outbound HTTP is blocked."
        ),
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        capability="network.dns",
        role=ROLE_SINK,
    ),
]


# --------------------------------------------------------------------------
# Credentials and secrets
# --------------------------------------------------------------------------

CREDENTIAL_RULES: List[Rule] = [
    Rule(
        rule_id="source.env_read",
        regex=_c(r"\bos\.environ\b|\bos\.getenv\s*\(|\bprocess\.env\b|\bENV\[" ),
        extensions=PY | JS,
        title="Reads environment variables",
        explanation=(
            "Normal for reading an API key. It matters because the environment of an "
            "MCP server usually holds every credential the host process was given, "
            "not only the one this server needs."
        ),
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        capability="environment.read",
        role=ROLE_SOURCE,
        informational_only=True,
    ),
    Rule(
        rule_id="source.ssh_key_access",
        regex=_c(r"\.ssh/id_[a-z0-9_]+|\.ssh/authorized_keys|id_rsa\b|known_hosts\b"),
        extensions=ANY,
        title="References SSH key material",
        explanation=(
            "Touching ~/.ssh is hard to justify for anything but an SSH client. A "
            "private key read here is a key that can leave."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        capability="credentials.ssh",
        remediation="Do not run this server with access to your real SSH keys until the use is explained.",
        role=ROLE_SOURCE,
    ),
    Rule(
        rule_id="source.cloud_credentials",
        regex=_c(r"\.aws/credentials|AWS_SECRET_ACCESS_KEY|\.config/gcloud|AZURE_CLIENT_SECRET|\.kube/config"),
        extensions=ANY,
        title="References cloud credential stores",
        explanation=(
            "Reads credentials that typically grant access to infrastructure far "
            "beyond this machine."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        capability="credentials.cloud",
        role=ROLE_SOURCE,
    ),
    Rule(
        rule_id="source.browser_secrets",
        regex=_c(r"Login\s+Data\b|cookies\.sqlite|Local\s+State\b|key4\.db|logins\.json"),
        extensions=ANY,
        title="References browser credential or cookie stores",
        explanation=(
            "These paths hold saved passwords and session cookies. There is close to "
            "no legitimate reason for an MCP server to read them."
        ),
        severity=Severity.CRITICAL,
        confidence=Confidence.MEDIUM,
        capability="credentials.browser",
        remediation="Treat as hostile unless the server's entire stated purpose is browser data.",
        role=ROLE_SOURCE,
    ),
    Rule(
        rule_id="source.netrc_access",
        regex=_c(r"\.netrc\b|_netrc\b"),
        extensions=ANY,
        title="References .netrc credentials",
        explanation="Reads stored machine credentials used by curl, git and similar tools.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        capability="credentials.netrc",
        role=ROLE_SOURCE,
    ),
    Rule(
        rule_id="source.keychain_access",
        regex=_c(r"\bsecurity\s+find-generic-password\b|\bkeyring\.get_password\s*\(|libsecret"),
        extensions=ANY,
        title="Reads from an OS credential store",
        explanation="Pulls secrets out of the system keychain rather than being handed one.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        capability="credentials.keychain",
        role=ROLE_SOURCE,
    ),
]


# --------------------------------------------------------------------------
# Obfuscation
# --------------------------------------------------------------------------

OBFUSCATION_RULES: List[Rule] = [
    Rule(
        rule_id="source.base64_decode",
        regex=_c(r"b64decode\s*\(|base64\.b64decode|\batob\s*\(|Buffer\.from\s*\([^)\n]{0,80}base64"),
        extensions=PY | JS,
        title="Decodes base64 at runtime",
        explanation=(
            "Ordinary for binary payloads and images. It only becomes interesting "
            "when what comes out is executed."
        ),
        severity=Severity.INFO,
        confidence=Confidence.HIGH,
        capability="encoding.base64",
        informational_only=True,
    ),
    Rule(
        rule_id="source.hex_decode",
        regex=_c(r"bytes\.fromhex\s*\(|codecs\.decode\s*\([^)\n]{0,60}hex"),
        extensions=PY,
        title="Decodes hex-encoded data at runtime",
        explanation="Another way to keep a payload unreadable in source.",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        capability="encoding.hex",
    ),
    Rule(
        rule_id="source.reversed_string_call",
        regex=_c(r"\[::-1\]\s*\)|split\(['\"]{2}\)\.reverse\(\)\.join"),
        extensions=PY | JS,
        title="Builds strings by reversing them",
        explanation=(
            "A common trick to keep an identifier like 'os.system' from appearing "
            "literally in the source, defeating a plain text search."
        ),
        severity=Severity.LOW,
        confidence=Confidence.LOW,
    ),
]


# --------------------------------------------------------------------------
# Persistence and system modification
# --------------------------------------------------------------------------

PERSISTENCE_RULES: List[Rule] = [
    Rule(
        rule_id="source.cron_persistence",
        regex=_c(r"\bcrontab\b|/etc/cron\.|\bschtasks\b"),
        extensions=ANY,
        title="Touches scheduled-task configuration",
        explanation=(
            "Scheduling work outside the server's own lifetime means it keeps running "
            "after you stop using it."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        capability="persistence.scheduler",
        remediation="A server should not need to survive its own process. Ask why it does.",
    ),
    Rule(
        rule_id="source.startup_persistence",
        regex=_c(r"\.bashrc\b|\.zshrc\b|\.bash_profile\b|LaunchAgents|systemctl\s+enable|/etc/systemd/system"),
        extensions=ANY,
        title="Modifies shell or service startup configuration",
        explanation=(
            "Writing to a startup file makes code run on every login or boot, "
            "independent of whether the MCP server is in use."
        ),
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        capability="persistence.startup",
    ),
    Rule(
        rule_id="source.package_install",
        regex=_c(r"\bpip\s+install\b|\bnpm\s+(?:i|install)\b|\buv\s+pip\s+install\b|\bpipx\s+install\b"),
        extensions=ANY,
        title="Invokes a package manager at runtime",
        explanation=(
            "Installing packages while running pulls in code that was never part of "
            "what you reviewed, resolved at the moment of execution."
        ),
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        capability="package.install",
    ),
]


ALL_RULES: List[Rule] = (
    EXECUTION_RULES
    + FILESYSTEM_RULES
    + NETWORK_RULES
    + CREDENTIAL_RULES
    + OBFUSCATION_RULES
    + PERSISTENCE_RULES
)

# Fail fast on a duplicated identifier: consumers key off rule_id, and two
# rules answering to one name would make a report ambiguous.
_seen = set()
for _rule in ALL_RULES:
    if _rule.rule_id in _seen:
        raise AssertionError(f"duplicate rule_id: {_rule.rule_id}")
    _seen.add(_rule.rule_id)
del _seen, _rule


def rules_for(extension: str) -> List[Rule]:
    return [r for r in ALL_RULES if r.applies_to(extension)]
