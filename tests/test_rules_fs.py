"""Unit tests for destructive filesystem protection rules."""

from agent_redline.engine import Engine
from agent_redline.models import Decision, RiskLevel, ToolCall, ToolKind


def test_destructive_rm_rf_root():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command="rm -rf /")
    v = engine.evaluate(tc)
    assert v.decision == Decision.DENY
    assert v.risk_level == RiskLevel.CRITICAL
    assert "fs.destructive" in v.rule_id


def test_destructive_rm_rf_home_and_git():
    engine = Engine()
    for cmd in ["rm -rf ~", "rm -rf $HOME", "rm -rf .git", "rm -rf .", "rm -rf ./*"]:
        tc = ToolCall(kind=ToolKind.SHELL, command=cmd)
        v = engine.evaluate(tc)
        assert v.decision == Decision.DENY, f"Expected {cmd} to be denied"


def test_destructive_nested_and_sudo():
    engine = Engine()
    tc1 = ToolCall(kind=ToolKind.SHELL, command="sudo rm -rf /")
    assert engine.evaluate(tc1).decision == Decision.DENY

    tc2 = ToolCall(kind=ToolKind.SHELL, command='bash -c "rm -rf /"')
    assert engine.evaluate(tc2).decision == Decision.DENY

    tc3 = ToolCall(kind=ToolKind.SHELL, command="echo 'cm0gLXJmIC8=' | base64 -d | sh")
    assert engine.evaluate(tc3).decision == Decision.DENY


def test_benign_rm_commands_allowed():
    engine = Engine()
    benign = [
        "rm -rf node_modules",
        "rm -rf vendor",
        "rm -rf build/",
        "rm -rf dist/",
        "rm file.txt",
        "mkdir -p src/",
    ]
    for cmd in benign:
        tc = ToolCall(kind=ToolKind.SHELL, command=cmd)
        v = engine.evaluate(tc)
        assert v.decision == Decision.ALLOW, f"Expected {cmd} to be allowed, got {v.decision}"


def test_block_device_dd():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command="dd if=/dev/zero of=/dev/sda bs=1M")
    v = engine.evaluate(tc)
    assert v.decision == Decision.DENY
    assert "block device" in v.reason.lower()


def test_mkfs():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command="mkfs.ext4 /dev/sdb1")
    v = engine.evaluate(tc)
    assert v.decision == Decision.DENY
    assert "mkfs" in v.reason.lower()


def test_chmod_777_broad():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command="chmod -R 777 /")
    v = engine.evaluate(tc)
    assert v.decision == Decision.DENY


def test_find_delete_broad():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command="find / -type f -delete")
    v = engine.evaluate(tc)
    assert v.decision == Decision.DENY
