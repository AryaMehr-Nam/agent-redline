# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Deep shell parser and AST normalizer (`src/agent_redline/shellparse.py`) supporting pipeline splitting (`;`, `&&`, `||`, `|`, newlines), subshells (`$(...)`, `` `...` ``), command wrappers (`sudo`, `env`), inline script invocations (`bash -c`, `sh -c`), and base64 decoding pipelines.
- Destructive filesystem rule (`src/agent_redline/rules/filesystem.py`) protecting root, `$HOME`, `.git`, system directories, raw block devices (`dd`), `mkfs`, `shred`, `chmod -R 777`, and `find -delete`.
- Destructive git rule (`src/agent_redline/rules/git.py`) safeguarding protected branches (`main`, `master`, `prod`, `release`) against force-pushing, refspec deletions, `git reset --hard`, `git clean -fdx`, and branch force-deletions.
- Destructive data rule (`src/agent_redline/rules/data.py`) preventing raw `DROP DATABASE`, `TRUNCATE`, unbounded `DELETE FROM` without `WHERE` via `psql`/`mysql`/`sqlite3`, and ORM/framework database wipes (`prisma migrate reset`, `artisan migrate:fresh`, `artisan db:wipe`).
- Security engine (`src/agent_redline/engine.py`) with operational modes (`audit`, `balanced`, `strict`), priority allowlists/denylists, and fail-safe exception isolation.
- CLI `redline check "<command>"` for dry-run security evaluations with human and agent explanations.
- Initial project foundation and core domain models (`ToolCall`, `Verdict`, `Decision`, `ToolKind`, `RiskLevel`, `RedlineConfig`).
