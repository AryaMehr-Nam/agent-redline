"""Unit tests for reversible installer and doctor diagnostic."""

import json
from pathlib import Path

from agent_redline.installer import (
    doctor_diagnostic,
    init_agent_hooks,
    uninstall_agent_hooks,
)


def test_installer_init_and_uninstall_all(tmp_path: Path):
    installed = init_agent_hooks(tmp_path, agent_target="all", preset="laravel", mode="balanced")
    assert len(installed) == 4

    # Verify Antigravity hooks
    ag_hooks = tmp_path / ".agents" / "hooks.json"
    assert ag_hooks.is_file()
    ag_data = json.loads(ag_hooks.read_text(encoding="utf-8"))
    assert "redline-safety-gate" in ag_data

    # Verify Claude settings
    cl_settings = tmp_path / ".claude" / "settings.json"
    assert cl_settings.is_file()
    cl_data = json.loads(cl_settings.read_text(encoding="utf-8"))
    assert "PreToolUse" in cl_data["hooks"]

    # Verify Cursor hooks with failClosed: true
    cur_hooks = tmp_path / ".cursor" / "hooks.json"
    assert cur_hooks.is_file()
    cur_data = json.loads(cur_hooks.read_text(encoding="utf-8"))
    assert cur_data["hooks"]["beforeShellExecution"][0]["failClosed"] is True

    # Verify Codex hooks
    cdx_hooks = tmp_path / ".codex" / "hooks.json"
    assert cdx_hooks.is_file()

    # Verify guard.toml
    guard_toml = tmp_path / "guard.toml"
    assert guard_toml.is_file()
    assert 'presets = ["laravel"]' in guard_toml.read_text(encoding="utf-8")

    # Verify Doctor report
    doc_res = doctor_diagnostic(tmp_path)
    assert len(doc_res) == 4
    for r in doc_res:
        assert r["installed"] is True
        assert r["engine_firing"] is True
        if r["agent"] == "cursor":
            assert r["fail_mode"] == "fail-closed"

    # Verify Uninstall
    uninstalled = uninstall_agent_hooks(tmp_path, agent_target="all")
    assert len(uninstalled) == 4

    doc_after = doctor_diagnostic(tmp_path)
    for r in doc_after:
        assert r["installed"] is False
