# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-02

### Added
- **Core Engine & Architecture:** Deterministic, zero-runtime-dependency lifecycle firewall (`src/agent_redline/engine.py`) with `audit`, `balanced` (default), and `strict` modes. Sub-millisecond evaluation latency (<1ms).
- **Deep Shell Parser:** Full AST pipeline normalizer (`src/agent_redline/shellparse.py`) supporting pipeline chaining (`;`, `&&`, `||`, `|`, newlines), subshells (`$(...)`, `` `...` ``), wrappers (`sudo`, `env`), inline scripts (`bash -c`, `sh -c`), and base64 decoding pipelines.
- **Rules Suite:**
  - `fs.destructive`: Protects system root, `$HOME`, `.git`, block devices (`dd`), `mkfs`, `shred`, `chmod -R 777`, and `find -delete`.
  - `git.destructive`: Safeguards protected branches (`main`, `master`, `prod`, `release`) against force-pushing (`--force`, `-f`, `+branch`), refspec deletion (`:main`), `git reset --hard`, `git clean -fdx`, and branch force-deletions.
  - `data.destructive`: Prevents raw `DROP DATABASE`, `TRUNCATE`, unbounded `DELETE FROM` without `WHERE` via `psql`/`mysql`/`sqlite3`, and ORM wipes (`prisma migrate reset`, `artisan migrate:fresh`, `artisan db:wipe`).
  - `secrets.read`: Intercepts attempts to read or inspect credentials (`.env*`, `~/.ssh/*`, `~/.aws/*`, `gcloud`, certificates, auth tokens, shell histories) while exempting non-sensitive templates (`.env.example`).
  - `network.exfiltration`: Halts pipelines coupling secret sources with network sinks (`curl`, `wget`, `nc`, `scp`, `rsync`, Python one-liners) targeting untrusted endpoints.
  - `exec.rce`: Blocks piping remote scripts directly into shell interpreters (`curl | sh`, `wget | bash`, `eval $(curl ...)`).
  - `system.defense`: Prevents crontab tampering, shell rc file modifications (`.bashrc`), firewall tampering, and hard-blocks tool calls attempting to modify or uninstall redline hooks.
- **Content Prompt Injection Scanner:** Multi-signal heuristic scoring engine (`src/agent_redline/injection.py`) flagging instruction overrides, exfiltration directives, hidden HTML comments, zero-width obfuscation, and Unicode tag plane characters.
- **Plain TOML Presets:** Ready-to-use security profiles for `core`, `laravel`, `node`, `python`, and `git` with per-project `guard.toml` overrides.
- **Multi-Agent Adapters:** Adapters for Google Antigravity (`PreToolUse`/`PostToolUse`), Claude Code (`PreToolUse`), Cursor (`beforeShellExecution`, `failClosed: true`), and OpenAI Codex CLI.
- **CLI Commands:**
  - `redline check "<command>"`: Dry-run evaluation with agent-oriented explain-backs.
  - `redline hook`: Native lifecycle hook entrypoint reading JSON from stdin.
  - `redline bench`: Precision/recall benchmark against labeled corpus.
  - `redline init`: Reversible hook installer with automated `.bak` backups.
  - `redline uninstall`: Restores original configs cleanly.
  - `redline doctor`: Diagnostic matrix of hook health and fail modes.
  - `redline explain <rule_id>`: Rule documentation.
- **Empirical Labeled Corpus:** 184 malicious attack payloads and 151 benign realistic developer commands in `corpus/` with 100% recall, 100% precision, and 0% false positives.
- **Agent Skill & Specs:** Canonical Agent Skill in `skills/agent-safety/SKILL.md` compatible with `npx skills add` and vendor directories.
- **Media & Evidence:** Real terminal animated demonstration `demo.gif` and live Antigravity verification evidence log.
