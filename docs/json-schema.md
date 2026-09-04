# JSON output schema

`mcp-vet report <target>` and `mcp-vet audit ... --json` emit this shape. The
schema is versioned so a consumer can detect a breaking change.

```
mcp-vet report owner/repo --path ./checkout > report.json
mcp-vet audit --offline --path ./checkout --json | jq '.findings[] | select(.severity=="CRITICAL")'
```

## Versioning

`schema_version` is currently **`"1.0"`**. The major number changes when a
field is removed or its meaning changes; the minor number when a field is
added. Consumers should tolerate unknown fields.

## Top level

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | e.g. `"1.0"` |
| `target` | string | `owner/repo`, or the directory audited |
| `source_url` | string \| null | Repository URL when known |
| `version` | string \| null | Version from the registry, when found |
| `overall` | severity | Worst area, after confidence weighting |
| `recommendation` | string | Plain-language next step |
| `areas` | array | One row per assessed dimension |
| `findings` | array | Most severe first, then by confidence, then rule id |
| `capabilities` | array | What the code reaches for |
| `endpoints` | array | Network destinations, classified |
| `credentials` | array | Secrets expected — **names only, never values** |
| `dataflows` | array | Source→sink proximity chains |
| `limitations` | array of string | What this run did not check |
| `notes` | object | Free-form context; not scored on |

`notes.network` (0.5.0+) records `requests` (round trips, failed ones included),
`cache_hits` (answers served without asking a server — the only ones that can be
stale), `revalidated` (confirmed current by a `304`) and `cache_oldest_seconds`.
A consumer that needs live data checks `cache_hits == 0`, or runs with `--no-cache`.

## Enumerations

**severity** — `NOT_FLAGGED`, `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
`NOT_FLAGGED` means a check ran and found nothing. There is deliberately no
`SAFE`.

**confidence** — `LOW`, `MEDIUM`, `HIGH`. How sure the tool is that a finding is
what it appears to be. Independent of severity: a finding may be HIGH severity
and LOW confidence at once. `LOW` means static analysis cannot settle it and a
human must look — never that the finding was dismissed.

**status** — `VERIFIED` (the check ran), `UNAVAILABLE` (data source
unreachable), `NOT_APPLICABLE` (nothing to check), `NOT_CHECKED` (deliberately
skipped, e.g. `--offline`). **An area that is not `VERIFIED` has not been
cleared.**

**area** — `popularity_integrity`, `repository_trust`, `source_code`,
`dependencies`, `installation`, `capabilities`, `network`, `prompt_injection`,
`maintenance`, `provenance`.

**endpoint classification** — `EXPECTED`, `INFRASTRUCTURE`, `UNEXPLAINED`,
`SUSPICIOUS`. `UNEXPLAINED` is the common case for a legitimate API mcp-vet
does not recognise; it is not an accusation.

## Objects

### finding

```json
{
  "rule_id": "source.shell_true",
  "area": "source_code",
  "severity": "HIGH",
  "confidence": "HIGH",
  "title": "Subprocess invoked through a shell",
  "explanation": "...",
  "evidence": [{"path": "server.py", "line": 23, "snippet": "..."}],
  "remediation": "..."
}
```

`rule_id` is the stable key — match on it, not on `title`.

### evidence

`path`, `line`, `snippet`, `detail` — all optional, absent keys omitted.
Snippets are sanitized and length-capped.

### credential

```json
{
  "name": "GITHUB_TOKEN",
  "required": true,
  "source": "environment",
  "blast_radius": "Inherits every permission the token was issued with...",
  "sent_externally": false,
  "evidence": [{"path": "server.py", "line": 13, "snippet": "..."}]
}
```

Only the **name** is ever recorded. mcp-vet does not read credential values.

### dataflow

```json
{
  "source": "environment.read",
  "sink": "network.external",
  "destination": "telemetry-collect.example.net",
  "confidence": "MEDIUM",
  "evidence": [...]
}
```

Reports co-location within one file, **not proven taint**. `destination` is
present only for network sinks; it is `null` for shell and process sinks.
Confidence never exceeds `MEDIUM`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing above INFO |
| 1 | LOW or MEDIUM findings |
| 2 | HIGH findings |
| 3 | CRITICAL findings |
| 4 | mcp-vet could not complete (network, bad arguments, unreadable target) |

**0 and 4 are deliberately distinct**: "found nothing" and "could not look"
must never share an exit code, or a broken CI gate reads as a passing one.

## Stability

Output is byte-stable across runs for the same input: findings sort by
severity, then confidence, then `rule_id`, then title. Two reports can be
diffed directly.
