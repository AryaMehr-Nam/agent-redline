# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Plain TOML presets in `src/agent_redline/presets/` for `laravel`, `node`, `python`, and `git` with curated allowlists, denylists, and trusted registries.
- Content Prompt Injection Scanner (`src/agent_redline/injection.py`) using multi-signal heuristic scoring (instruction overrides, exfiltration directives, hidden HTML comments, zero-width obfuscation, and Unicode tag characters) to add visible safety warning banners into agent context.
- Labeled evaluation corpus in `corpus/`: 184 malicious attack/destruction payloads (`corpus/malicious.jsonl`) and 151 benign realistic developer commands (`corpus/benign.jsonl`).
- Empirical benchmark engine (`src/agent_redline/bench.py`) measuring Precision (100.00%), Recall (100.00%), False Positive Rate (0.00%), and per-call evaluation latency (mean 0.82ms, p95 1.23ms).
- CLI command `redline bench` generating formatted terminal benchmark reports and enforcing automated CI quality gates.
- Secret read interception rule (`src/agent_redline/rules/secrets.py`) protecting `.env*`, `~/.ssh/*`, `~/.aws/*`, `gcloud`, certificates (`*.pem`, `*.key`), npm/pypi tokens, shell history, and browser profiles across direct read tools and shell commands (`cat`, `less`, `head`, `base64`, `grep`), while exempting non-sensitive templates (`.env.example`, `.env.sample`).
- Exfiltration correlation rule (`src/agent_redline/rules/exfiltration.py`) identifying pipelines that link secret sources or sensitive environment variables with network sinks (`curl`, `wget`, `nc`, `scp`, `rsync`, Python/Node network one-liners) targeting untrusted domains.
- Remote Code Execution protection rule (`src/agent_redline/rules/rce.py`) halting `curl | sh`, `wget | bash`, `eval $(curl ...)`, and untrusted package index/URL installations.
- Persistence and Self-Defense rule (`src/agent_redline/rules/defense.py`) preventing scheduled task additions (`crontab`), shell rc file poisoning (`.bashrc`), firewall tampering (`ufw`, `iptables`), and hard-blocking any tool call attempting to modify, delete, or uninstall redline lifecycle hooks or configuration.
- Deep shell parser and AST normalizer (`src/agent_redline/shellparse.py`) supporting pipeline splitting (`;`, `&&`, `||`, `|`, newlines), subshells (`$(...)`, `` `...` ``), command wrappers (`sudo`, `env`), inline script invocations (`bash -c`, `sh -c`), and base64 decoding pipelines.
- Destructive filesystem rule (`src/agent_redline/rules/filesystem.py`) protecting root, `$HOME`, `.git`, system directories, raw block devices (`dd`), `mkfs`, `shred`, `chmod -R 777`, and `find -delete`.
- Destructive git rule (`src/agent_redline/rules/git.py`) safeguarding protected branches (`main`, `master`, `prod`, `release`) against force-pushing, refspec deletions, `git reset --hard`, `git clean -fdx`, and branch force-deletions.
- Destructive data rule (`src/agent_redline/rules/data.py`) preventing raw `DROP DATABASE`, `TRUNCATE`, unbounded `DELETE FROM` without `WHERE` via `psql`/`mysql`/`sqlite3`, and ORM/framework database wipes (`prisma migrate reset`, `artisan migrate:fresh`, `artisan db:wipe`).
- Security engine (`src/agent_redline/engine.py`) with operational modes (`audit`, `balanced`, `strict`), priority allowlists/denylists, and fail-safe exception isolation.
- CLI `redline check "<command>"` for dry-run security evaluations with human and agent explanations.
- Initial project foundation and core domain models (`ToolCall`, `Verdict`, `Decision`, `ToolKind`, `RiskLevel`, `RedlineConfig`).
