# Launch Post Drafts for agent-redline v0.1.0

## 1. r/ClaudeAI
**Title:** I built an open-source, deterministic safety firewall for Claude Code & AI coding agents (measured 100% catch rate on 180+ malicious commands, 0.8ms latency, zero runtime deps)

**Body:**
Hey r/ClaudeAI,

If you've given Claude Code or Cursor permission to run commands via terminal, you know the anxiety: what if a prompt injection or hallucination runs `rm -rf /`, force-pushes over `main`, wipes your database, or curls your `.env` to an attacker's server?

I built **`agent-redline`**, an open-source, deterministic safety firewall that plugs into lifecycle hooks (`PreToolUse` on Claude Code / Antigravity / Codex, and `beforeShellExecution` on Cursor).

**Key Features:**
- **Zero Runtime Dependencies:** Python 3.10+ standard library only.
- **Sub-1ms Execution:** Hook latency averages ~0.82ms. No LLM in the loop; offline AST shell parsing.
- **Explain-Back For Agents:** Instead of a generic crash, it tells the agent *why* it was blocked and suggests a safe alternative command (e.g., "Inspect .env.example instead of reading .env").
- **Measured Quality:** We ship a labeled corpus of 330+ realistic developer commands (`redline bench`) with 100% recall on attacks and 0% false positives on everyday developer workflows (`npm run build`, `pytest`, normal git).
- **TOML Presets:** Ready-to-use profiles for `core`, `laravel`, `node`, `python`, and `git`.

Repo: https://github.com/AryaMehr-Nam/agent-redline  
Try it: `pip install agent-redline && redline init`

Feedback and bypass reports welcome!

---

## 2. r/Python
**Title:** agent-redline: Zero-dependency PreToolUse safety firewall for AI coding agents with sub-millisecond AST evaluation

**Body:**
Hi everyone,

I built `agent-redline`, a pure standard-library Python package that acts as a local security firewall for AI coding agents (Claude Code, Google Antigravity, Cursor, OpenAI Codex).

Unlike proxy-based approaches that require complex daemons, it hooks directly into agent lifecycle events. When an agent attempts a tool execution, redline parses the shell pipeline (handling quotes, `sudo`, `env`, subshells `$(...)`, inline scripts, and base64 pipes) and returns an immediate verdict (`allow`, `ask`, or `deny`) with an agent-friendly explanation.

**Architecture details:**
- Pure Python 3.10+ standard library (no pydantic, no click, no external network calls).
- AST pipeline tokenizer and normalizer.
- Built-in benchmark suite (`redline bench`) testing 335 labeled developer commands.
- Fail-safe isolation: internal errors default to `ask` (never fail silently open).

GitHub: https://github.com/AryaMehr-Nam/agent-redline  
`pip install agent-redline`

---

## 3. Show HN
**Title:** Show HN: agent-redline – Deterministic Safety Firewall for AI Coding Agents

**Body:**
AI coding agents are increasingly given terminal and filesystem permissions. However, prompt injections in external web pages or hallucinated destructive commands (`git push --force main`, `DROP DATABASE`, `cat .env | curl ...`) can cause catastrophic damage.

`agent-redline` is an open-source, deterministic PreToolUse firewall that intercepts agent actions before they execute.

- **Zero dependencies:** Built entirely with the Python 3.10+ standard library.
- **Fast:** ~0.8ms average hook execution latency.
- **Multi-agent support:** Google Antigravity, Claude Code, Cursor (enforces fail-closed), and OpenAI Codex.
- **Dual Defense:** Deterministic pre-tool command filtering + post-tool heuristic prompt injection scanner.
- **Corpus & Benchmark:** Includes 335 labeled test commands (`redline bench`).

It is explicitly NOT a virtualized sandbox, but a deterministic policy gate.

Code & Benchmarks: https://github.com/AryaMehr-Nam/agent-redline
