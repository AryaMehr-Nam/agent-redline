"""Unit tests for agent-redline domain models."""

from agent_redline.models import (
    Decision,
    Mode,
    RedlineConfig,
    RiskLevel,
    ToolCall,
    ToolKind,
    Verdict,
)


def test_tool_call_defaults_and_dict():
    tc = ToolCall(
        kind=ToolKind.SHELL,
        command="rm -rf /",
        tool_name="Bash",
        agent="claude",
        cwd="/workspace",
    )
    assert tc.kind == ToolKind.SHELL
    assert tc.command == "rm -rf /"
    d = tc.to_dict()
    assert d["kind"] == "shell"
    assert d["command"] == "rm -rf /"
    assert d["agent"] == "claude"
    assert d["cwd"] == "/workspace"


def test_verdict_allow_properties():
    v = Verdict(
        decision=Decision.ALLOW,
        rule_id="allow.default",
        reason="Permitted operation",
        risk_level=RiskLevel.SAFE,
    )
    assert not v.is_blocked
    assert v.format_agent_feedback() == "Operation permitted."
    assert v.to_dict()["decision"] == "allow"


def test_verdict_deny_properties():
    v = Verdict(
        decision=Decision.DENY,
        rule_id="fs.destructive_root",
        reason="Recursive deletion of system root prohibited.",
        suggested_alternative="Target a specific build directory such as build/ or dist/.",
        risk_level=RiskLevel.CRITICAL,
    )
    assert v.is_blocked
    feedback = v.format_agent_feedback()
    assert "[REDLINE SECURITY BLOCK]" in feedback
    assert "fs.destructive_root (CRITICAL)" in feedback
    assert "Safe Alternative:" in feedback


def test_redline_config_defaults():
    cfg = RedlineConfig()
    assert cfg.mode == Mode.BALANCED
    assert cfg.fail_mode == Decision.ASK
    assert "core" in cfg.presets
    assert "github.com" in cfg.trusted_domains
