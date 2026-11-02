"""Unit tests for persistence, security disabling, and self-defense rules."""

from agent_redline.engine import Engine
from agent_redline.models import Decision, ToolCall, ToolKind


def test_self_defense_write_hook_file_denied():
    engine = Engine()
    for hook_file in [
        ".claude/settings.json",
        ".agents/hooks.json",
        ".cursor/hooks.json",
        "guard.toml",
    ]:
        tc = ToolCall(kind=ToolKind.WRITE, paths=[hook_file])
        v = engine.evaluate(tc)
        assert v.decision == Decision.DENY, f"Expected write to {hook_file} to be denied"
        assert "system.defense" in v.rule_id


def test_self_defense_uninstall_via_tool_denied():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command="redline uninstall --agent all")
    v = engine.evaluate(tc)
    assert v.decision == Decision.DENY
    assert "system.defense" in v.rule_id


def test_crontab_tampering_denied():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command="crontab -e")
    v = engine.evaluate(tc)
    assert v.decision == Decision.DENY


def test_shell_rc_poisoning_denied():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command='echo "alias sudo=evil" >> ~/.bashrc')
    v = engine.evaluate(tc)
    assert v.decision == Decision.DENY


def test_firewall_disabling_denied():
    engine = Engine()
    for cmd in ["ufw disable", "setenforce 0", "iptables -F"]:
        tc = ToolCall(kind=ToolKind.SHELL, command=cmd)
        v = engine.evaluate(tc)
        assert v.decision == Decision.DENY, f"Expected '{cmd}' to be denied"
