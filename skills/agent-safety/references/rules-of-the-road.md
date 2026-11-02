# Detailed Reference: Security Rules & Explain-Back Mechanics

When `agent-redline` evaluates tool calls, each finding maps to a deterministic rule identifier:

| Rule ID | Risk Level | Description | Recommended Safe Alternative |
| :--- | :--- | :--- | :--- |
| `fs.destructive` | CRITICAL | Catastrophic deletion of `/`, `~`, `.git`, or raw `dd`/`mkfs`/`chmod -R 777` | Target build directories (`build/`, `dist/`, `node_modules/`) |
| `git.destructive` | CRITICAL / HIGH | Force push to protected branches (`main`, `master`), `clean -fdx`, `reset --hard` | Pull and merge commits, run `git clean -ndx` first, use `git stash` |
| `data.destructive` | CRITICAL / HIGH | Raw `DROP DATABASE`, `TRUNCATE`, unbounded `DELETE FROM`, DB wipe migrations | Use versioned schema migrations, supply explicit `WHERE` clauses |
| `secrets.read` | CRITICAL | Access to `.env`, `.env.*`, `~/.ssh/`, `~/.aws/`, cloud tokens, history | Reference `.env.example`, inspect template files |
| `network.exfiltration` | CRITICAL | Pipeline coupling a secret source with an external network sink | Never upload secrets or environment dumps to external servers |
| `exec.rce` | CRITICAL | Piping remote scripts directly into shell interpreters (`curl \| sh`) | Download script, inspect contents manually, and execute with permission |
| `system.defense` | CRITICAL | Altering crontabs, shell profiles (`.bashrc`), firewalls, or redline config | Keep configuration changes local and developer-approved |
