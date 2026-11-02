"""Unit tests for engine operational modes, allowlists, and denylists."""

from agent_redline.engine import Engine
from agent_redline.models import Decision, Mode, RedlineConfig, ToolCall, ToolKind


def test_engine_audit_mode_logs_without_blocking():
    cfg = RedlineConfig(mode=Mode.AUDIT)
    engine = Engine(config=cfg)
    tc = ToolCall(kind=ToolKind.SHELL, command="rm -rf /")
    v = engine.evaluate(tc)
    assert v.decision == Decision.ALLOW
    assert "[AUDIT]" in v.reason
    assert "Would block" in v.reason


def test_engine_allow_command_override():
    cfg = RedlineConfig(allow_commands=["rm -rf /"])  # User explicitly allowed
    engine = Engine(config=cfg)
    tc = ToolCall(kind=ToolKind.SHELL, command="rm -rf /")
    v = engine.evaluate(tc)
    assert v.decision == Decision.ALLOW
    assert v.rule_id == "allow.user_override"


def test_engine_deny_command_override():
    cfg = RedlineConfig(deny_commands=["git status"])  # User explicitly denied
    engine = Engine(config=cfg)
    tc = ToolCall(kind=ToolKind.SHELL, command="git status")
    v = engine.evaluate(tc)
    assert v.decision == Decision.DENY
    assert v.rule_id == "deny.user_override"


def test_engine_allow_glob_override():
    cfg = RedlineConfig(allow_globs=["storage/framework/cache/**"])
    engine = Engine(config=cfg)
    tc = ToolCall(kind=ToolKind.WRITE, paths=["storage/framework/cache/data.tmp"])
    v = engine.evaluate(tc)
    assert v.decision == Decision.ALLOW
    assert v.rule_id == "allow.user_override"
