"""Unit tests for shellparse tokenizer, pipeline splitter, and AST parser."""

from agent_redline.shellparse import (
    extract_base64_payload,
    normalize_path,
    parse_shell_command,
    split_pipeline_segments,
)


def test_split_pipeline_segments_operators():
    cmd = "echo 1 && git status || ls -la; cat README.md | grep test\npytest"
    segments = split_pipeline_segments(cmd)
    raws = [s[0] for s in segments]
    assert "echo 1" in raws
    assert "git status" in raws
    assert "ls -la" in raws
    assert "cat README.md" in raws
    assert "grep test" in raws
    assert "pytest" in raws


def test_split_pipeline_segments_respects_quotes():
    cmd = "bash -c 'echo 1; rm -rf /' && git push"
    segments = split_pipeline_segments(cmd)
    raws = [s[0] for s in segments]
    assert len(raws) == 2
    assert raws[0] == "bash -c 'echo 1; rm -rf /'"
    assert raws[1] == "git push"


def test_parse_shell_command_with_wrappers():
    cmd = "sudo env FOO=bar rm -rf /"
    parsed = parse_shell_command(cmd)
    assert len(parsed) == 1
    p = parsed[0]
    assert p.executable == "rm"
    assert p.is_sudo is True
    assert p.env_vars.get("FOO") == "bar"
    assert "-r" in p.flags
    assert "-f" in p.flags
    assert "/" in p.targets


def test_parse_shell_command_nested_bash_c():
    cmd = 'bash -c "rm -rf /"'
    parsed = parse_shell_command(cmd)
    assert len(parsed) == 1
    assert parsed[0].executable == "bash"
    assert len(parsed[0].nested_commands) == 1
    nested = parsed[0].nested_commands[0]
    assert nested.executable == "rm"
    assert "/" in nested.targets


def test_extract_base64_payload():
    # cm0gLXJmIC8= decodes to: rm -rf /
    raw = "echo 'cm0gLXJmIC8=' | base64 -d"
    decoded = extract_base64_payload(raw)
    assert decoded == "rm -rf /"


def test_normalize_path():
    assert normalize_path("/") == "/"
    assert normalize_path("//") == "/"
    assert normalize_path("/*") == "/"
    assert normalize_path(".git") == ".git"
    assert normalize_path("./.git") == ".git"
