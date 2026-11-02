# Contributing to agent-redline

Thank you for helping improve `agent-redline`! We welcome contributions, new presets, and corpus test cases.

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/AryaMehr-Nam/agent-redline.git
   cd agent-redline
   ```

2. **Install dev dependencies:**
   ```bash
   pip install -e ".[dev]"
   ```

3. **Run the test suite:**
   ```bash
   pytest tests/
   ```

4. **Run the benchmark:**
   ```bash
   redline bench
   ```

5. **Lint and format:**
   ```bash
   ruff check .
   ruff format .
   ```

## Contributing a Preset

To add a new preset (e.g., `ruby`, `rust`, `go`):
1. Create `src/agent_redline/presets/<name>.toml`.
2. Define `allow_globs`, `deny_globs`, `allow_commands`, `deny_commands`, and `trusted_domains`.
3. Add at least 5 realistic tests in `tests/test_presets.py`.
4. Submit a pull request.
