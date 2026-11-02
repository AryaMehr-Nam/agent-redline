"""Unit tests for TOML presets (laravel, node, python, git)."""

from pathlib import Path

from agent_redline.config import load_config
from agent_redline.engine import Engine
from agent_redline.models import Decision, ToolCall, ToolKind


def test_laravel_preset_protections(tmp_path: Path):
    guard = tmp_path / "guard.toml"
    guard.write_text('presets = ["core", "laravel"]\n', encoding="utf-8")
    cfg = load_config(project_dir=tmp_path)

    assert "laravel" in cfg.presets
    assert "packagist.org" in cfg.trusted_domains
    assert "storage/framework/cache/**" in cfg.allow_globs

    engine = Engine(config=cfg)

    # Allowed cache deletion in laravel
    tc_cache = ToolCall(kind=ToolKind.WRITE, paths=["storage/framework/cache/data.cache"])
    assert engine.evaluate(tc_cache).decision == Decision.ALLOW

    # Denied migrate:fresh
    tc_wipe = ToolCall(kind=ToolKind.SHELL, command="php artisan migrate:fresh")
    assert engine.evaluate(tc_wipe).decision == Decision.DENY


def test_node_preset_protections(tmp_path: Path):
    guard = tmp_path / "guard.toml"
    guard.write_text('presets = ["core", "node"]\n', encoding="utf-8")
    cfg = load_config(project_dir=tmp_path)

    assert "node_modules/**" in cfg.allow_globs
    assert "npmjs.com" in cfg.trusted_domains

    engine = Engine(config=cfg)
    tc_build = ToolCall(kind=ToolKind.SHELL, command="npm run build")
    assert engine.evaluate(tc_build).decision == Decision.ALLOW


def test_python_preset_protections(tmp_path: Path):
    guard = tmp_path / "guard.toml"
    guard.write_text('presets = ["core", "python"]\n', encoding="utf-8")
    cfg = load_config(project_dir=tmp_path)

    assert ".venv/**" in cfg.allow_globs
    assert "pypi.org" in cfg.trusted_domains

    engine = Engine(config=cfg)
    tc_pytest = ToolCall(kind=ToolKind.SHELL, command="pytest")
    assert engine.evaluate(tc_pytest).decision == Decision.ALLOW


def test_git_preset_protections(tmp_path: Path):
    guard = tmp_path / "guard.toml"
    guard.write_text('presets = ["core", "git"]\n', encoding="utf-8")
    cfg = load_config(project_dir=tmp_path)

    engine = Engine(config=cfg)
    tc_status = ToolCall(kind=ToolKind.SHELL, command="git status")
    assert engine.evaluate(tc_status).decision == Decision.ALLOW

    tc_clean = ToolCall(kind=ToolKind.SHELL, command="git clean -fdx")
    assert engine.evaluate(tc_clean).decision == Decision.DENY
