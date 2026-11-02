"""Unit tests for secret and credential read protection rules."""

from agent_redline.engine import Engine
from agent_redline.models import Decision, ToolCall, ToolKind


def test_secret_read_tool():
    engine = Engine()
    secret_paths = [
        ".env",
        ".env.local",
        ".env.production",
        "~/.ssh/id_rsa",
        "~/.ssh/id_ed25519",
        "~/.aws/credentials",
        "certs/server.pem",
        "config/app.key",
        "~/.npmrc",
        "~/.pypirc",
        "~/.bash_history",
    ]
    for path in secret_paths:
        tc = ToolCall(kind=ToolKind.READ, paths=[path])
        v = engine.evaluate(tc)
        assert v.decision == Decision.DENY, f"Expected read of {path} to be denied"
        assert "secrets.read" in v.rule_id


def test_secret_read_shell_commands():
    engine = Engine()
    commands = [
        "cat .env",
        "less ~/.ssh/id_rsa",
        "head -n 20 .env.local",
        "grep SECRET .env",
        "base64 ~/.aws/credentials",
        "tar -czf backup.tar.gz .env",
    ]
    for cmd in commands:
        tc = ToolCall(kind=ToolKind.SHELL, command=cmd)
        v = engine.evaluate(tc)
        assert v.decision == Decision.DENY, f"Expected shell command '{cmd}' to be denied"


def test_benign_non_secret_reads():
    engine = Engine()
    benign = [
        "cat .env.example",
        "cat package.json",
        "cat composer.json",
        "head README.md",
        "grep 'function' src/index.ts",
    ]
    for cmd in benign:
        tc = ToolCall(kind=ToolKind.SHELL, command=cmd)
        v = engine.evaluate(tc)
        assert v.decision == Decision.ALLOW, f"Expected '{cmd}' to be allowed"
