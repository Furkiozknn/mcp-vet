# Changelog

## 0.6.0 — Blind spots closed, and five false positives found on its own siblings

### Fixed

Five errors, each found by running mcp-vet over the MCP servers next to it on
this account (voice-io-mcp, nvidia-nim-mcp, local-notes-search-mcp,
model-comparison-harness), and each pinned by tests in
`tests/test_sibling_false_positives.py` that fail without the fix.

- **A private directory was "a file made executable".** `source.chmod_exec`
  matched any mode containing a 7, so `os.chmod(index_dir, 0o700)` - the idiom
  for a directory only its owner can enter - was a MEDIUM finding (mcp-vet's
  own cache directory in `http.py` was one). The rule now fires on what grants
  execute to someone: `+x` in any form, a numeric mode that gives group or
  others execute, `S_IEXEC`/`S_IX*`, and it now reads `Path.chmod` and
  `fs.chmod(Sync)` too, which it did not before. An owner-only mode and a
  `mode & 0o777` mask are not grants.
- **A provider's own key sent to that provider was rated like exfiltration.**
  An environment read next to an outbound call is HIGH, and voice-io-mcp
  replaced a quota-free health check (`GROQ_API_KEY` -> `api.groq.com`) with one
  that spends real quota just to get past that rating. The new `provider.py`
  lowers the pairing to LOW - still reported, with both lines and the reason -
  only when every secret the file reads is named for a provider it calls,
  every call names its destination as a literal (or a constant, or a table of
  literals), and the repository's docs name each provider. A bulk
  `dict(os.environ)`, someone else's credential, a second unrelated key, a URL
  that arrives as a parameter, a computed litellm `api_base`, an undocumented
  provider or a capture host keeps it HIGH. The exfil fixture is unchanged.
- **"No uv.lock" next to a committed uv.lock.** `.lock` was not an extension
  the scanner reads, and a lockfile over 512 KB is not read at all, so
  `uv.lock`, `poetry.lock`, `yarn.lock`, `Cargo.lock`, `go.sum` and any large
  `package-lock.json` were reported missing. The walk now notes lockfiles
  wherever it meets them, without reading them.
- **`httpx>=0.27` was "a git or URL dependency"**, because the check was
  `spec.startswith("http")`. Only a scheme (`git+`, `https://`, `file:`, ...)
  makes a source remote now. In the same parser, `"mcp[cli]>=2.1"` ended the
  dependency list at its `]`: voice-io-mcp counted 1 of 3 dependencies and
  local-notes-search-mcp 0 of 4. The `dependencies = [...]` array is now read by
  a small scanner that respects quotes and skips comments.
- **litellm calls were invisible.** `litellm.acompletion(...)`,
  `aspeech`, `atranscription`, `embedding` and the rest are outbound requests to
  whichever provider the model name selects; the new `source.llm_api_call`
  rule records them as `network.external`, and a data-flow row names the
  provider host (`groq/...` -> `api.groq.com`). `httpx2` and `aiohttp` are now
  HTTP clients too.

Two more, found on the way:

- **A full data-flow table hid a finding.** Findings were drawn from the flow
  table after it was capped at 12 rows, so a LOW-confidence environment ->
  network pair could fall off the end - with its HIGH finding. That is how
  mcp-vet's own `GITHUB_TOKEN` flow in `http.py`, the one SECURITY.md walks
  through, had stopped being reported. Findings now come from every flow; the
  report says how many rows were not listed.
- **A comment or a denylist entry is not half of a data flow.** Once litellm
  calls were sinks, local-notes-search-mcp's own `SECRET_FILENAMES` denylist
  paired with its LLM call as a CRITICAL "SSH key read near an outbound
  request". Lines the scanner already marks as prose or exclusion no longer
  enter data-flow pairing; their own findings are unchanged.

Before -> after, `report --offline`: voice-io-mcp NOT_FLAGGED -> MEDIUM (its
LLM calls are now seen, and uploading a caller-chosen audio file to Groq is a
real file -> network flow), nvidia-nim-mcp LOW -> LOW, local-notes-search-mcp
NOT_FLAGGED -> LOW, the reverted voice-io-mcp probe HIGH -> MEDIUM. All seven
fixtures, GLips/Figma-Context-MCP and modelcontextprotocol/servers give the
same verdict, rule ids and evidence counts as before.

67 new tests in `tests/test_sibling_false_positives.py`; 39 of them fail on the
code before this change, the rest pin the true positives that must not move.

- **A regular expression was read as a shell.** `source.node_exec` matched
  any `exec(`, so `/re/.exec(text)` - a RegExp method - was reported as
  *"child_process.exec() runs a command through a shell"*. GLips/Figma-Context-MCP
  has one line of that shape in its shipped code (`src/transformers/text.ts`),
  and it was enough to rate the whole server HIGH and print **DO NOT INSTALL**.
  The rule now counts a method call only on `child_process` itself, on its
  `require()`, or on the names it is conventionally bound to (`cp`,
  `childProcess`, `child`, `proc`); a bare `exec(` / `execSync(` is still the
  destructured import. Re-run against Figma-Context-MCP @ c083d65: HIGH ->
  LOW, and the one remaining `execSync` is in a developer script, where it
  belongs. Two regression tests pin both directions.

- **A server that refuses to touch credentials was rated as one that reads
  them.** `local-notes-search-mcp` keeps a denylist —
  `SECRET_FILENAMES = {".env", ".netrc", "id_rsa", ...}` — so those files are
  never indexed, and documents the refusal in the docstring of the function
  that enforces it. mcp-vet read both as *"references SSH key material"*,
  rated the server HIGH and printed **DO NOT INSTALL**. Rating the defensive
  pattern more harshly than its absence is an instruction to stop writing it.

  Two narrow contexts are now recognised per line of evidence: a mention
  inside a collection literal whose name reads as an exclusion, and a mention
  in a comment or docstring. Python's own tokenizer decides the second one, so
  `open("~/.netrc")` is never mistaken for prose because it contains a string.

  **Nothing is suppressed** — the module's existing rule stands. The finding is
  still reported at full severity with its file and line, and the report now
  says which of the two it is: `(only in a denylist or a comment)`. The
  qualification applies per piece of evidence, so one real read anywhere keeps
  the whole finding in the verdict however many denylists surround it.

  30 new tests, half of them pointed the other way: a server that genuinely
  reads `~/.ssh/id_rsa` and posts it outward is still HIGH, and a server that
  has both a denylist and a real read is still HIGH.

### Security

- **Padding a line hid it from every rule.** Any line longer than 2000
  characters was skipped by the source, install, injection, credential and
  endpoint scanners, so `os.system("curl … | sh")` followed by 2000 spaces
  audited `NOT FLAGGED`, exit 0, with nothing in "What this did not check".
  Long lines are now matched in overlapping 2000-character windows (with
  `pos`/`endpos`, so a lookbehind still sees across a window edge); a whole
  512 KB file on one line still audits in well under a second.
- **Line 6001 was never read.** Only the first 6000 lines of a file were
  kept, silently. A payload after that point in an ordinary-sized file was
  invisible. The 512 KB per-file limit - which *is* reported when it bites -
  is now the only bound, and every line under it is read.
- **A missing `--path` was a clean audit.** `audit`/`report --path` pointing at
  nothing (a typo, a clone that failed one step earlier) walked an empty tree
  and exited 0. A path that is not a directory, or a directory with nothing
  mcp-vet can read, now exits 4 with a message; so does a missing side of
  `diff --before-path/--after-path`.
- **`from os import system` and `__import__("os").system(...)`** reached a
  shell without ever spelling `os.system(`, and were not flagged. Both are now
  caught by `source.os_system`, and the same forms by `source.os_popen`.

### Changed

- **Usage errors exit 4, not 2.** argparse's default of 2 is this tool's
  HIGH, so a mistyped flag in a CI gate read as a finding. `--limit` now
  rejects zero and negative values.
- **`--version`** prints the installed version.
- **`source.shell_true` needs a keyword argument.** `print("never use
  shell=True")` was rated HIGH / DO NOT INSTALL; the rule now requires the
  flag after `(`, `,` or at the start of a continuation line.
- README: a 30-second start that runs from GitHub with `uvx`, `pipx`
  install from git, a note that the npm package named `mcp-vet` is an
  unrelated project, and a CI example that no longer aborts under `bash -e`
  before it reads the exit code.

31 new tests in `tests/test_blind_spots.py`.

## 0.5.0 — Faster, and honest about where the answers came from

Measured before the change: an audit was 17–28 s of wall time, 99 % of it
waiting on seven HTTP requests — three of them MCP Registry searches at 5–9 s
each at a quiet hour and 20–50 s under load.

### Added

- **On-disk response cache** (`http.py`). GitHub and registry responses are
  kept under `~/.cache/mcp-vet/` for `MCP_VET_CACHE_TTL` seconds (default one
  hour), then revalidated with `If-None-Match`; a GitHub `304` costs no
  rate-limit budget (measured: three 304s and one GET spent one point). Every
  report lists cached answers under *What this did not check* with the age of
  the oldest, and `notes.network` carries the counts. Only URLs, ETags and
  bodies are stored — never a request header — as `0600` files in a `0700`
  directory; errors, 404s and malformed bodies are never cached. `--no-cache`
  on every network command, `MCP_VET_CACHE=0` and `MCP_VET_CACHE_DIR` control it.

### Changed

- **Registry lookups run their search terms together** (`registry.py`), with
  results kept in term order so the report stays byte-stable. Fresh-term A/B:
  11.8 s → 3.4 s at a quiet hour, 130 s → 24 s under load, with lower
  per-query latency in the concurrent run. GitHub calls stay serial, as
  GitHub asks.
- **Registry timeout is 60 s** (was the shared 15 s), and a search that fails
  is reported as *unavailable* instead of being read as "no entry found" —
  "could not look" and "found nothing" must never share an answer.

### Measured

| `mcp-vet audit Furkiozknn/mcp-vet --path .` | wall time | requests |
|---|---|---|
| first run, registry under load | 55.2 s | 7 |
| first run, registry answering from its own cache | 8.3 s | 7 |
| any run within the hour after | 0.23 s | 0 |

Tests: 192 → 237.

## 0.4.0 — MCP Trust & Security Auditor

The project stops being a GitHub search with a popularity heuristic and becomes
an auditor. The heuristic is kept, unchanged, and renamed in concept to
**Popularity Integrity** — it measures one gameable number, and calling it a
security signal was the most misleading thing about the previous version.

### Added

- **Source analysis** (`mcp_vet/patterns.py`, `source.py`) — 31 auditable rules
  covering execution, filesystem, network, credentials, obfuscation and
  persistence, plus correlation: capabilities, credential requirements with
  blast radius, and source→sink data-flow chains.
- **Tool poisoning / prompt injection detection** (`injection.py`) — finds text
  in tool descriptions addressed to the *model* rather than describing a
  contract: instruction override, role spoofing, concealment, secret
  solicitation, cross-tool redirection.
- **MCP Registry integration** (`registry.py`) — search, provenance chain, and
  explicit **registry/source mismatch** detection. Written against the live v0
  API. Registry presence is never treated as trust.
- **Dependency and installation analysis** — npm/Python/Go/Cargo manifests and
  lockfiles; npm lifecycle hooks, `setup.py` execution, `curl | sh`, Dockerfile
  binary downloads.
- **Network destination classification** — EXPECTED / INFRASTRUCTURE /
  UNEXPLAINED / SUSPICIOUS, judged against the server's stated purpose.
- **Repository trust** (`trust.py`) — archived, disabled, fork, licence,
  releases, contributors, staleness.
- **Risk model** (`risk.py`) — per-area severities with no single score;
  severity separate from confidence; `Status` distinguishing "checked and
  found nothing" from "could not check".
- **Version diff** (`diff.py`) — `mcp-vet diff owner/repo v1.2.0 v1.3.0` reports
  capability, credentials and destinations a release gained, and exits non-zero
  so it can gate an automated bump.
- **New commands** — `audit`, `report`, `registry`, `diff`; `--json`, `--offline`,
  `--verbose`, `--quiet`, `--path`, `--purpose`.
- **Stable exit codes** — 0/1/2/3 by severity, 4 for tool error, documented and
  tested so `mcp-vet audit` can gate CI.
- **Documented JSON schema** (`docs/json-schema.md`), versioned and byte-stable.
- **SECURITY.md** — threat model, what it detects, what it cannot, false
  positives and negatives, security assumptions, disclosure.
- **Anti-prompt-injection architecture** — SKILL.md Rule 0: repository content
  is data, never instructions.

### Changed

- `scripts/vet.py` is now a launcher for the `mcp_vet` package; the path
  SKILL.md and the README name still works.
- Network errors raise typed exceptions instead of `SystemExit` from inside the
  request helper, so callers can degrade instead of dying.
- Timestamp parsing accepts fractional seconds and offset forms — the registry
  emits microsecond precision, which the previous parser crashed on.
- `check` now states plainly that it read no source.
- All repository-derived text is sanitized at read time: ANSI escapes, OSC-8
  hyperlinks, C0/C1 controls and bidirectional overrides.

### Fixed

- Data flows no longer attach a URL destination to non-network sinks, which
  previously read as a claim that a subprocess call sent data to that host.

### Tests

30 → 192. Every original assertion is preserved. New: analyzer coverage,
mocked registry, exit-code and JSON contracts, and `test_hostile_input.py`,
which treats mcp-vet itself as the attack surface.

## 0.3.0

- `scripts/vet.py`: standalone CLI for the search/vet/rank pipeline.
- Skill bundling fixes: `scripts/vet.py` path, `uv run` invocation.
