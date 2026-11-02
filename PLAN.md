# PLAN.md: agent-redline (Deterministic Safety Guardrail for AI Coding Agents)

## Executive Summary
`agent-redline` is an open-source, deterministic, zero-runtime-dependency safety firewall and Agent Skill for AI coding agents (Claude Code, Google Antigravity, Cursor, OpenAI Codex). It runs offline as a `PreToolUse` / `beforeShellExecution` lifecycle hook, inspecting shell commands, file reads, and tool calls before execution. It prevents destructive accidents (e.g., `rm -rf /`, `DROP DATABASE`, `git push --force`), secret leaks (`.env`, `~/.ssh`), exfiltration pipelines, and malicious prompt injections without requiring an LLM in the decision loop.

---

## Architectural Principles & Hard Constraints
1. **Zero Runtime Dependencies:** Python 3.10+ standard library exclusively. Dev dependencies: `pytest`, `ruff`.
2. **Deterministic & Offline:** Same input yields the identical `Verdict` every time. Sub-5ms hook execution.
3. **Fail-Closed by Design:** On internal parse errors or script failures, default to `ask` or `deny`, never a silent `allow`. Enforce `failClosed: true` on Cursor.
4. **Safety Boundary:** The guard itself never executes shell commands with `shell=True`, `eval`, or makes outbound network calls.
5. **Agent-Facing Explanations:** Every denial delivers actionable feedback: what rule tripped, why it is dangerous, and the safe alternative command.
6. **Empirical Verification (Honesty Rule):** Metrics in documentation are directly computed from running `redline bench` against the labeled 300+ item corpus (`corpus/malicious.jsonl` and `corpus/benign.jsonl`).

---

## Milestone Breakdown

### Milestone 0: Foundation & Core Domain Models
- **Deliverables:**
  - `pyproject.toml` with console scripts `redline` and `guard`, zero runtime dependencies, dev dependencies (`pytest`, `ruff`).
  - `.gitignore`, MIT `LICENSE`, `CHANGELOG.md`.
  - Canonical domain models in `src/agent_redline/models.py`:
    - `ToolKind`: `SHELL`, `READ`, `WRITE`, `FETCH`, `MCP`.
    - `ToolCall`: normalized representation (`kind`, `command`, `paths`, `raw_payload`, `agent`).
    - `Decision`: `ALLOW`, `ASK`, `DENY`.
    - `Verdict`: `decision`, `rule_id`, `reason`, `suggested_alternative`, `risk_level`.
    - `Config`: mode (`audit`, `balanced`, `strict`), presets, custom allow/deny patterns, trusted domains.
  - Unit tests for domain models & baseline serialization.

### Milestone 1: Deep Shell Parser & Destructive Action Rules
- **Deliverables:**
  - `src/agent_redline/shellparse.py`:
    - Chain splitting: `;`, `&&`, `||`, `|`, `&`, newlines.
    - Command prefixes & wrappers: `sudo`, `env VAR=val`, `doas`, `nohup`, `time`, `exec`.
    - Subshells & substitutions: `$(...)`, `` `...` ``, `<(...)`.
    - Nested shells: `bash -c "..."`, `sh -c "..."`, `zsh -c "..."`, `cmd.exe /c`, `powershell -Command`.
    - Obfuscation detection: base64 decoders (`base64 -d | sh`), hex unpacking (`xxd -r | bash`), `eval`.
    - Path normalization: `~`, `$HOME`, `/`, `..`, relative and absolute paths.
  - Rules Suite in `src/agent_redline/rules/`:
    - `filesystem.py`: `rm -rf` on `/`, `~`, `$HOME`, project root, `.git`, system roots; `dd` to raw disks; `mkfs`; `shred`; `chmod -R 777` on broad targets; `find -delete`.
    - `git.py`: `git push --force` to main/master/production; `git reset --hard`; `git clean -fdx`; branch deletions.
    - `data.py`: Raw destructive SQL (`DROP`, `TRUNCATE`, `DELETE` without `WHERE`) via `psql`, `mysql`, `sqlite3`; `prisma migrate reset`; Laravel DB wipes.
  - Comprehensive unit tests covering parser edge cases and rule triggers.

### Milestone 2: Secret Interception, Exfiltration Sinks, & Self-Defense
- **Deliverables:**
  - `src/agent_redline/rules/secrets.py`:
    - Sensitive files: `.env*`, `~/.ssh/*`, `~/.aws/*`, `~/.config/gcloud/*`, `*.pem`, `*.key`, `~/.npmrc`, `~/.pypirc`, `kubeconfig`, browser profiles, shell histories (`.bash_history`).
    - Multi-tool coverage: shell commands (`cat`, `less`, `head`, `tail`, `grep`, `cp`, `tar`, `base64`) AND agent file read tools (`read_file`, `FileRead`, `Grep`, `Glob`).
  - `src/agent_redline/rules/exfiltration.py`:
    - Correlation between secret sources (files or env vars like `$AWS_SECRET_ACCESS_KEY`, `printenv`) and network sinks (`curl`, `wget`, `nc`, `scp`, `rsync`, `ssh`, `git remote add`, python network one-liners).
    - Configurable trusted domain allowlist.
  - `src/agent_redline/rules/rce.py`:
    - Remote Code Execution pipelines (`curl ... | sh`, `wget ... | bash`, `pip install <url>`, strict npm git URLs).
  - `src/agent_redline/rules/defense.py`:
    - Crontab alterations, shell rc poisoning (`.bashrc`, `.zshrc`), `authorized_keys` tampering.
    - **Self-Defense Rule:** Hard-blocks any tool attempting to edit or delete `agent-redline` hook configs or `guard.toml`.
  - Unit tests for secret leak attempts and exfiltration pipelines.

### Milestone 3: Corpus Construction & Benchmark Engine
- **Deliverables:**
  - `corpus/malicious.jsonl`: >= 150 diverse, realistic attack and accident commands with metadata (`tool`, `input`, `expected_verdict`, `category`, `rule_id`).
  - `corpus/benign.jsonl`: >= 150 realistic developer commands across languages and frameworks (builds, tests, dev servers, standard git ops, normal file inspections).
  - `src/agent_redline/bench.py`:
    - Benchmark execution engine measuring True Positives, False Positives, True Negatives, False Negatives.
    - Computes Precision, Recall, False Positive Rate (FPR), and per-command evaluation latency.
    - Formats reproducible ASCII benchmark report for CLI and documentation.
  - Automated CI test asserting minimum quality thresholds (Recall >= 98%, FPR <= 2%, Latency < 10ms).

### Milestone 4: TOML Presets, Per-Project Overrides, & Prompt Injection Scanner
- **Deliverables:**
  - Standard TOML presets in `src/agent_redline/presets/`:
    - `core.toml`: Essential filesystem, git, secret, and defense rules.
    - `laravel.toml`: Adds protections for `artisan migrate:fresh`, `db:wipe`, destructive Tinker queries, `.env`, `storage/` deletions.
    - `node.toml`: Package manager hygiene, `.npmrc` protection, safe `node_modules` cleanup.
    - `python.toml`: Virtualenv management, `.pypirc` protection, untrusted pip indices.
    - `git.toml`: Stricter git protections (rebase, force pushes, branch wipes).
  - Per-project configuration loader (`guard.toml`): allowlists/denylists with glob matching.
  - Content Injection Scanner (`src/agent_redline/injection.py`):
    - Multi-signal heuristic scoring:
      - Instruction override tokens ("ignore previous instructions", "disregard prior prompt").
      - Exfiltration directives ("send this file to http://").
      - Hidden HTML comments embedding prompt instructions.
      - Unicode obfuscation (zero-width spaces, invisible format characters, unicode tag blocks).
    - Produces structured safety warning for agent context.
  - Unit tests for preset loading, config overriding, and prompt injection detection.

### Milestone 5: Multi-Agent Adapters, Installer & Doctor CLI
- **Deliverables:**
  - Adapters in `src/agent_redline/adapters/`:
    - `ClaudeAdapter`: Stdin normalization for Claude Code `PreToolUse`; outputs exit code 0/2 and JSON `permissionDecision`.
    - `AntigravityAdapter`: Normalizes Antigravity `toolCall` / `run_command`; outputs JSON `decision` (`allow`, `deny`, `ask`) and `reason`. Implements `PostToolUse` for injection warnings.
    - `CursorAdapter`: Normalizes `beforeShellExecution`; outputs JSON `permission` (`allow`/`deny`) and `agentMessage`; configures `failClosed: true`.
    - `CodexAdapter`: Normalizes Codex `PreToolUse`; handles exit code 2 and stderr reason.
  - Installer & Doctor in `src/agent_redline/installer.py` & `cli.py`:
    - `redline init [--agent claude|antigravity|cursor|codex|all] [--preset laravel] [--mode balanced|audit|strict]`: safe merge, backup `.bak` generation.
    - `redline uninstall [--agent ...]`: clean reversal from `.bak`.
    - `redline doctor`: runs per-agent self-tests, verifies hook presence, tests firing with benign/malicious probe, reports fail mode and injection scanner status.
    - `redline check "<command>"`: dry-run inspection tool for humans and CI.
  - Tests with real recorded hook payload fixtures for every supported agent.

### Milestone 6: SKILL.md, Comprehensive Tests, Honest Documentation & v0.1.0 Release
- **Deliverables:**
  - Agent Skill: `skill/agent-safety/SKILL.md` (and root `skills/` for `npx skills add` compatibility).
  - Tests: Complete test suite (>150 tests), 100% green, 0 ruff errors.
  - Documentation:
    - High-impact `README.md` with 1-screen pitch, 10-second demo GIF, 2-command install, live benchmark table from `redline bench`.
    - Honest threat model (what it stops and what it cannot stop; "Is this a sandbox? No!").
    - Multi-agent compatibility matrix with evidence status.
    - Comparison table with Redstamp, MCPWall, MCP-Guard.
    - "How to report a bypass" security policy.
  - `SECURITY.md`, `CONTRIBUTING.md`, draft launch posts for r/ClaudeAI, r/Python, Show HN.
  - Git tag `v0.1.0`.
