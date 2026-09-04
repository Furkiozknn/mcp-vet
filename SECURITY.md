# Security policy

## The claim, stated precisely

mcp-vet gathers evidence about MCP servers. It does not certify them.

**No static analyzer can prove that an MCP server is safe.** mcp-vet matches
known patterns and correlates what it finds. A server that is not flagged has
not been shown to be dangerous by these particular checks — which is a much
weaker statement than "safe", and the tool is written to never blur the two.

Every report ends with what it did not check. That section is not boilerplate;
it is the part that tells you how much the rest is worth.

---

## Threat model

### Who mcp-vet is defending against

1. **An author who published something harmful** — credential theft, a backdoor,
   a data-collection channel the README does not mention.
2. **A supply-chain attacker** — a compromised maintainer account, a
   typosquatted or forked package, a malicious transitive dependency, an
   install hook.
3. **A tool-poisoning attacker** — someone who writes tool descriptions aimed at
   the *model* rather than at the user: instructions to conceal activity, to
   fetch secrets, or to call other tools.
4. **An attacker targeting mcp-vet itself** — repository content crafted to
   manipulate the analyzer, or the agent reading its output.

### Who it is not defending against

- **A malicious remote endpoint.** For a remote server, the code you can read
  is not the code that runs. mcp-vet says so and stops there.
- **A compromised local machine.** If your environment is already hostile,
  nothing here helps.
- **Runtime behaviour.** mcp-vet performs no dynamic analysis. It never
  executes what it examines — which is deliberate, and also a limit.
- **Compiled artifacts.** Binaries and minified bundles are not analysed.

### Trust boundaries

| Input | Treated as |
|---|---|
| Repository files | Untrusted data. Never executed, never followed as instructions. |
| GitHub API responses | Untrusted text. Sanitized before display. |
| MCP Registry responses | Untrusted text. Sanitized before display. |
| `GITHUB_TOKEN` | Read from the environment, sent only to `api.github.com`. |
| Response cache (`~/.cache/mcp-vet/`) | Holds URLs, ETags and JSON bodies only — never the token or any request header. Files `0600` in a `0700` directory; `MCP_VET_CACHE=0` disables it. |

---

## What mcp-vet detects

- Command and code execution: `shell=True`, `os.system`, `child_process.exec`,
  `eval`/`exec`, `new Function`, pickle deserialization, `curl | sh`
- Filesystem read, write, delete, and `chmod +x`
- Network egress: HTTP clients, raw sockets, DNS; destinations extracted and
  classified
- Credential access: environment variables, SSH keys, cloud credential files,
  browser credential stores, `.netrc`, OS keychains
- Obfuscation: base64/hex decoding, and the decode-then-execute combination
- Persistence: cron, systemd, shell startup files, LaunchAgents
- Install-time execution: npm lifecycle hooks, `setup.py` execution, remote
  script piping, Dockerfile binary downloads
- Dependency shape: counts, pinning, git/URL sources, missing lockfiles
- Data-flow proximity: a sensitive read near an outbound call, in one file
- Tool poisoning: instruction override, role spoofing, concealment, secret
  solicitation, cross-tool redirection
- Provenance: registry/source mismatch, missing repository, remote-only servers
- Repository trust: archived, disabled, fork, licence, releases, staleness
- Popularity integrity: the original star/fork/age relationship

## What mcp-vet cannot detect

- **Novel techniques.** The catalogue matches what it knows.
- **Deliberate obfuscation.** Code assembled from fragments, fetched at
  runtime, or hidden past the file-size limit can evade it. The limits are
  reported for exactly this reason.
- **Intent.** `subprocess.run` is a git server working correctly and a backdoor
  executing, and they look identical to a regex.
- **Semantics of a data flow.** Findings report co-location, not proven taint.
- **Anything a remote endpoint does.**
- **Whether a dependency is vulnerable.** No advisory database is consulted, so
  the report says "vulnerability status unavailable" and means it.
- **Compiled or minified code.**

---

## False positives and false negatives

Both exist, and the design trades between them deliberately.

**False positives.** `subprocess` in a git server, `os.environ` in a server that
legitimately needs an API key, an UNEXPLAINED host that is simply an API
mcp-vet does not recognise. These are expected: the tool is tuned to under-claim
rather than over-suppress, so it reports the capability and lets you judge.
`UNEXPLAINED` is the normal verdict for a legitimate destination, not an
accusation.

**False negatives.** Anything novel, obfuscated, in a skipped file, in a binary,
or in a dependency. **A clean report is not evidence of safety.**

Severity and confidence are separate for this reason. HIGH severity with LOW
confidence means "this would be serious if real, and static analysis cannot
settle whether it is real". That combination is an instruction to go and look,
not a verdict.

### Worked example: mcp-vet flags itself CRITICAL

Run mcp-vet on its own repository and it returns `CRITICAL`, exit code 3. This
is not a bug, and it is left uncorrected on purpose — it is the clearest
available illustration of what the paragraphs above mean.

Three separate causes, and they are worth telling apart:

1. **Self-reference.** `mcp_vet/patterns.py` contains the patterns it searches
   for, as string literals: `os.system`, `shell=True`, `curl … | sh`,
   `.aws/credentials`. A scanner reading its own rule catalogue matches it.
   Unavoidable for any tool of this kind.

2. **Adversarial test fixtures.** `tests/fixtures/` contains a server that
   pipes `curl` into a shell, one whose tool description instructs the model to
   conceal its activity, and one that reads the environment and POSTs it away.
   They exist to prove the detectors fire. **mcp-vet does not exclude test
   directories**, and that is a deliberate trade: excluding them would quieten
   this report and simultaneously create an obvious place for an attacker to
   hide a payload. The paths are shown, so a reader can dismiss them in a
   second.

3. **A true positive.** `mcp_vet/http.py` reads `GITHUB_TOKEN` from the
   environment in `github_token()` and makes outbound requests in `get_json()`
   — the same file. mcp-vet reports that as a possible exfiltration path, at
   HIGH severity and MEDIUM confidence. It is correct: mcp-vet really does read
   your token and send it somewhere. The destination is `api.github.com`, which
   is the whole point, and confirming that took reading two functions.

That third one is the tool working exactly as intended. It found a real data
flow, refused to guess whether it was benign, and handed a human two line
numbers. The answer took ten seconds to establish — and it would have taken the
same ten seconds if the destination had not been GitHub.

**The lesson to take from this: do not tune a rule until the scanner stops
seeing something real.** A quieter report is not a safer server.

---

## Security assumptions

1. mcp-vet never executes analyzed code — no import, no compile, no eval.
2. Repository content is sanitized once, at read time, before it can reach any
   output: ANSI escapes, OSC-8 hyperlinks, C0/C1 controls and bidirectional
   overrides are removed.
3. mcp-vet emits no escape sequences of its own, so a reader can always tell
   the tool's formatting from a repository's injected formatting.
4. Work is bounded (file size, file count, line count) and whatever is skipped
   is reported.
5. Symlinks are not followed; vendored directories are not scanned.
6. All network access is GET, to `api.github.com` and
   `registry.modelcontextprotocol.io`.
7. Credential *values* are never read. Only variable names appear in a report,
   and the data model has nowhere to put a value.

## Reporting a vulnerability

If you find a way to make mcp-vet execute analyzed code, emit unsanitized
terminal escapes, leak a credential value, hang on crafted input, or report
CRITICAL findings as clean, please open a security advisory on the repository
rather than a public issue.

Especially interesting:

- analyzer evasion that a reasonable rule would have caught
- output that manipulates the terminal or an agent reading it
- any path where repository content changes mcp-vet's behaviour

## Scope of this policy

This covers mcp-vet itself. It says nothing about the security of any server
mcp-vet reports on — establishing that is the user's job, which is the entire
premise of the tool.
