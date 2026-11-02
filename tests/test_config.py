"""Unit tests for agent-redline configuration and preset loading."""

from pathlib import Path

from agent_redline.config import load_config, merge_config_dicts, parse_config_dict
from agent_redline.models import Decision, Mode


def test_parse_config_dict_defaults():
    cfg = parse_config_dict({})
    assert cfg.mode == Mode.BALANCED
    assert cfg.fail_mode == Decision.ASK
    assert cfg.presets == ["core"]


def test_parse_config_dict_custom():
    data = {
        "mode": "strict",
        "fail_mode": "deny",
        "presets": ["core", "laravel"],
        "allow_globs": ["vendor/**"],
        "deny_globs": [".env*"],
        "trusted_domains": ["custom.internal"],
    }
    cfg = parse_config_dict(data)
    assert cfg.mode == Mode.STRICT
    assert cfg.fail_mode == Decision.DENY
    assert cfg.presets == ["core", "laravel"]
    assert cfg.allow_globs == ["vendor/**"]
    assert cfg.deny_globs == [".env*"]
    assert cfg.trusted_domains == ["custom.internal"]


def test_merge_config_dicts_nested_and_lists():
    base = {
        "mode": "balanced",
        "allow_globs": ["dist/**"],
        "nested": {"a": 1, "b": 2},
    }
    override = {
        "mode": "strict",
        "allow_globs": ["build/**"],
        "nested": {"b": 99, "c": 3},
    }
    merged = merge_config_dicts(base, override)
    assert merged["mode"] == "strict"
    assert merged["allow_globs"] == ["dist/**", "build/**"]
    assert merged["nested"] == {"a": 1, "b": 99, "c": 3}


def test_load_config_with_bundled_core_preset(tmp_path: Path):
    cfg = load_config(project_dir=tmp_path)
    assert cfg.mode == Mode.BALANCED
    assert "github.com" in cfg.trusted_domains
    assert "git status" in cfg.allow_commands


def test_load_config_with_project_guard_toml(tmp_path: Path):
    guard_file = tmp_path / "guard.toml"
    guard_file.write_text(
        """
mode = "strict"
allow_globs = ["temp/**"]
trusted_domains = ["api.example.com"]
""",
        encoding="utf-8",
    )
    cfg = load_config(project_dir=tmp_path)
    assert cfg.mode == Mode.STRICT
    assert "temp/**" in cfg.allow_globs
    assert "api.example.com" in cfg.trusted_domains
