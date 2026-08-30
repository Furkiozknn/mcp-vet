![mcp-vet](assets/banner.svg)

# 🔍 mcp-vet

A [Claude Code](https://claude.com/claude-code) skill that discovers, vets, and safely installs MCP (Model Context Protocol) servers.

Most "find me an MCP server" tools stop at discovery. This one adds the two steps that actually matter before you run someone else's code on your machine:

1. 📊 **Vets popularity signals** — flags repos whose star count looks inflated relative to their fork count and age, instead of trusting raw star count.
2. 🕵️ **Reviews source before install** — clones the candidate to a scratch directory, reads the actual executable code, and flags anything that looks like it does more than the README claims.

🚦 Nothing gets installed without an explicit approval step.

## 📥 Install

Copy `SKILL.md` into your Claude Code skills directory:

```bash
mkdir -p ~/.claude/skills/mcp-vet
cp SKILL.md ~/.claude/skills/mcp-vet/
```

(Or drop it in a project's `.claude/skills/mcp-vet/` for project-only scope.)

## 💬 Use

Ask Claude Code things like:

- "Is there an MCP server for Discord?"
- "Find me an MCP server that can control OBS."
- "I need an MCP for X — find and vet one, don't just install the first result."

The skill triggers automatically on requests like these once installed.

## ⚖️ The vetting heuristic

A repo is flagged as **suspicious** when all three hold:

- `stars > 3000`
- age `< 180 days`
- `forks / stars < 0.12`

This isn't a hard rule that disqualifies a repo — it's a disclosed flag. Young, official-org projects sometimes grow fast for legitimate reasons. The point is you find out about the pattern instead of it being silently absorbed into a star-count-sorted recommendation.

## 📄 License

MIT
