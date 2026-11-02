"""Unit tests for agent hook adapters using official schema fixtures."""

import json
from pathlib import Path

from agent_redline.adapters import detect_adapter, get_adapter
from agent_redline.adapters.antigravity import AntigravityAdapter
from agent_redline.adapters.claude import ClaudeAdapter
from agent_redline.adapters.codex import CodexAdapter
from agent_redline.adapters.cursor import CursorAdapter
from agent_redline.engine import Engine
from agent_redline.models import Decision, ToolKind

FIXTURES_DIR = Path("tests/fixtures/adapters")


def test_antigravity_adapter_fixture():
    payload = json.loads((FIXTURES_DIR / "antigravity_pre_tool.json").read_text(encoding="utf-8"))
    adapter = get_adapter("antigravity")
    assert isinstance(adapter, AntigravityAdapter)

    tool_call = adapter.normalize(payload)
    assert tool_call.kind == ToolKind.SHELL
    assert tool_call.command == "rm -rf /"
    assert tool_call.agent == "antigravity"

    engine = Engine()
    verdict = engine.evaluate(tool_call)
    assert verdict.decision == Decision.DENY

    exit_code, stdout_data, stderr_str = adapter.encode(verdict)
    assert exit_code == 0
    assert stdout_data["decision"] == "deny"
    assert "REDLINE SECURITY BLOCK" in stdout_data["reason"]


def test_claude_adapter_fixture():
    payload = json.loads((FIXTURES_DIR / "claude_pre_tool.json").read_text(encoding="utf-8"))
    adapter = get_adapter("claude")
    assert isinstance(adapter, ClaudeAdapter)

    tool_call = adapter.normalize(payload)
    assert tool_call.kind == ToolKind.SHELL
    assert tool_call.command == "git push origin --force main"

    engine = Engine()
    verdict = engine.evaluate(tool_call)
    assert verdict.decision == Decision.DENY

    exit_code, stdout_data, stderr_str = adapter.encode(verdict)
    assert exit_code == 0
    assert stdout_data["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "REDLINE SECURITY BLOCK" in stderr_str


def test_cursor_adapter_fixture():
    payload = json.loads((FIXTURES_DIR / "cursor_before_shell.json").read_text(encoding="utf-8"))
    adapter = get_adapter("cursor")
    assert isinstance(adapter, CursorAdapter)

    tool_call = adapter.normalize(payload)
    assert tool_call.kind == ToolKind.SHELL

    engine = Engine()
    verdict = engine.evaluate(tool_call)
    assert verdict.decision == Decision.DENY

    exit_code, stdout_data, stderr_str = adapter.encode(verdict)
    assert exit_code == 0
    assert stdout_data["permission"] == "deny"
    assert "agentMessage" in stdout_data


def test_codex_adapter_fixture():
    payload = json.loads((FIXTURES_DIR / "codex_pre_tool.json").read_text(encoding="utf-8"))
    adapter = get_adapter("codex")
    assert isinstance(adapter, CodexAdapter)

    tool_call = adapter.normalize(payload)
    assert tool_call.kind == ToolKind.SHELL

    engine = Engine()
    verdict = engine.evaluate(tool_call)
    assert verdict.decision == Decision.DENY

    exit_code, stdout_data, stderr_str = adapter.encode(verdict)
    assert exit_code == 2  # Hard block exit code
    assert "REDLINE SECURITY BLOCK" in stderr_str


def test_detect_adapter_auto_detection():
    ag_payload = json.loads(
        (FIXTURES_DIR / "antigravity_pre_tool.json").read_text(encoding="utf-8")
    )
    assert detect_adapter(ag_payload).agent_name == "antigravity"

    cl_payload = json.loads((FIXTURES_DIR / "claude_pre_tool.json").read_text(encoding="utf-8"))
    assert detect_adapter(cl_payload).agent_name == "claude"

    cur_payload = json.loads(
        (FIXTURES_DIR / "cursor_before_shell.json").read_text(encoding="utf-8")
    )
    assert detect_adapter(cur_payload).agent_name == "cursor"
