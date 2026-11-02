"""Unit tests for destructive git operation rules."""

from agent_redline.engine import Engine
from agent_redline.models import Decision, Mode, RedlineConfig, RiskLevel, ToolCall, ToolKind


def test_git_force_push_main_denied():
    engine = Engine()
    blocked_pushes = [
        "git push origin --force main",
        "git push origin -f master",
        "git push --force origin prod",
        "git push origin +main",
        "git push origin :main",
        "git push origin --delete master",
    ]
    for cmd in blocked_pushes:
        tc = ToolCall(kind=ToolKind.SHELL, command=cmd)
        v = engine.evaluate(tc)
        assert v.decision == Decision.DENY, f"Expected {cmd} to be denied"
        assert v.risk_level == RiskLevel.CRITICAL


def test_git_force_push_feature_branch_balanced_asks():
    engine = Engine()  # Balanced mode default
    tc = ToolCall(kind=ToolKind.SHELL, command="git push origin --force feature/auth")
    v = engine.evaluate(tc)
    assert v.decision == Decision.ASK


def test_git_force_push_feature_branch_strict_denies():
    cfg = RedlineConfig(mode=Mode.STRICT)
    engine = Engine(config=cfg)
    tc = ToolCall(kind=ToolKind.SHELL, command="git push origin --force feature/auth")
    v = engine.evaluate(tc)
    assert v.decision == Decision.DENY


def test_git_reset_hard():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command="git reset --hard HEAD~1")
    v = engine.evaluate(tc)
    assert v.decision == Decision.ASK
    assert "git stash" in v.suggested_alternative.lower()


def test_git_clean_fdx():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command="git clean -fdx")
    v = engine.evaluate(tc)
    assert v.decision == Decision.DENY
    assert "git clean -ndx" in v.suggested_alternative.lower()


def test_git_branch_force_delete_main():
    engine = Engine()
    tc = ToolCall(kind=ToolKind.SHELL, command="git branch -D main")
    v = engine.evaluate(tc)
    assert v.decision == Decision.DENY


def test_benign_git_operations():
    engine = Engine()
    benign = [
        "git status",
        "git log -n 5",
        "git diff HEAD",
        "git add .",
        "git commit -m 'feat: add security'",
        "git push origin feature/login",
        "git pull origin main",
        "git checkout -b new-branch",
    ]
    for cmd in benign:
        tc = ToolCall(kind=ToolKind.SHELL, command=cmd)
        v = engine.evaluate(tc)
        assert v.decision == Decision.ALLOW, f"Expected {cmd} to be allowed"
