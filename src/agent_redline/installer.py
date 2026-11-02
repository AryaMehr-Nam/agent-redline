"""Reversible installer and diagnostic doctor for AI agent lifecycle hooks."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from agent_redline.engine import Engine
from agent_redline.models import Decision, ToolCall, ToolKind

HOOK_COMMAND_BASE = "python -m agent_redline.cli hook"


def backup_file(path: Path) -> Path | None:
    """Create a .bak copy of a file if it exists and backup doesn't already exist."""
    if path.is_file():
        bak_path = path.with_suffix(path.suffix + ".bak")
        if not bak_path.exists():
            shutil.copy2(path, bak_path)
            return bak_path
    return None


def restore_backup(path: Path) -> bool:
    """Restore from a .bak file if available."""
    bak_path = path.with_suffix(path.suffix + ".bak")
    if bak_path.is_file():
        shutil.copy2(bak_path, path)
        bak_path.unlink()
        return True
    return False


def install_antigravity(project_dir: Path) -> str:
    """Install redline hook into .agents/hooks.json."""
    agents_dir = project_dir / ".agents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    hooks_file = agents_dir / "hooks.json"
    backup_file(hooks_file)

    data: dict[str, Any] = {}
    if hooks_file.is_file():
        try:
            data = json.loads(hooks_file.read_text(encoding="utf-8"))
        except Exception:
            data = {}

    hook_entry = {
        "PreToolUse": [
          {
            "matcher": "run_command|read_file|view_file|write_file|edit_file",
            "hooks": [
              {
                "type": "command",
                "command": f"{HOOK_COMMAND_BASE} --agent antigravity",
              }
            ],
          }
        ]
    }
    data["redline-safety-gate"] = hook_entry
    hooks_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return str(hooks_file)


def install_claude(project_dir: Path) -> str:
    """Install redline hook into .claude/settings.json."""
    claude_dir = project_dir / ".claude"
    claude_dir.mkdir(parents=True, exist_ok=True)
    settings_file = claude_dir / "settings.json"
    backup_file(settings_file)

    data: dict[str, Any] = {}
    if settings_file.is_file():
        try:
            data = json.loads(settings_file.read_text(encoding="utf-8"))
        except Exception:
            data = {}

    hooks = data.setdefault("hooks", {})
    pre_tool_list = hooks.setdefault("PreToolUse", [])

    pre_tool_list = [
        item for item in pre_tool_list
        if not any("agent_redline" in h.get("command", "") for h in item.get("hooks", []))
    ]

    pre_tool_list.append({
        "matcher": "Bash|FileRead|View|FileEdit|Write",
        "hooks": [
            {
                "type": "command",
                "command": f"{HOOK_COMMAND_BASE} --agent claude",
            }
        ],
    })
    hooks["PreToolUse"] = pre_tool_list
    settings_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return str(settings_file)


def install_cursor(project_dir: Path) -> str:
    """Install redline hook into .cursor/hooks.json with explicit failClosed: true."""
    cursor_dir = project_dir / ".cursor"
    cursor_dir.mkdir(parents=True, exist_ok=True)
    hooks_file = cursor_dir / "hooks.json"
    backup_file(hooks_file)

    data: dict[str, Any] = {"version": 1, "hooks": {}}
    if hooks_file.is_file():
        try:
            data = json.loads(hooks_file.read_text(encoding="utf-8"))
        except Exception:
            data = {"version": 1, "hooks": {}}

    hooks_dict = data.setdefault("hooks", {})
    shell_hooks = hooks_dict.setdefault("beforeShellExecution", [])

    shell_hooks = [h for h in shell_hooks if "agent_redline" not in h.get("command", "")]

    shell_hooks.append({
        "command": f"{HOOK_COMMAND_BASE} --agent cursor",
        "failClosed": True,
    })
    hooks_dict["beforeShellExecution"] = shell_hooks
    hooks_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return str(hooks_file)


def install_codex(project_dir: Path) -> str:
    """Install redline hook into .codex/hooks.json."""
    codex_dir = project_dir / ".codex"
    codex_dir.mkdir(parents=True, exist_ok=True)
    hooks_file = codex_dir / "hooks.json"
    backup_file(hooks_file)

    data: dict[str, Any] = {}
    if hooks_file.is_file():
        try:
            data = json.loads(hooks_file.read_text(encoding="utf-8"))
        except Exception:
            data = {}

    hooks = data.setdefault("hooks", {})
    pre_tool_list = hooks.setdefault("PreToolUse", [])

    pre_tool_list = [
        item for item in pre_tool_list
        if not any("agent_redline" in h.get("command", "") for h in item.get("hooks", []))
    ]

    pre_tool_list.append({
        "matcher": "Bash|apply_patch|Write",
        "hooks": [
            {
                "type": "command",
                "command": f"{HOOK_COMMAND_BASE} --agent codex",
            }
        ],
    })
    hooks["PreToolUse"] = pre_tool_list
    hooks_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return str(hooks_file)


def create_initial_guard_toml(project_dir: Path, preset: str = "core", mode: str = "balanced") -> Path:
    """Create a guard.toml in the project root if one does not already exist."""
    guard_path = project_dir / "guard.toml"
    if not guard_path.exists():
        content = f"""# Project configuration for agent-redline
mode = "{mode}"
presets = ["{preset}"]

allow_globs = []
deny_globs = []
allow_commands = []
deny_commands = []
"""
        guard_path.write_text(content, encoding="utf-8")
    return guard_path


def init_agent_hooks(
    project_dir: Path,
    agent_target: str = "all",
    preset: str = "core",
    mode: str = "balanced",
) -> list[str]:
    """Execute installation across requested agent targets."""
    installed: list[str] = []
    target_lower = agent_target.lower()

    if target_lower in ("all", "antigravity"):
        p = install_antigravity(project_dir)
        installed.append(f"Antigravity: {p}")

    if target_lower in ("all", "claude"):
        p = install_claude(project_dir)
        installed.append(f"Claude Code: {p}")

    if target_lower in ("all", "cursor"):
        p = install_cursor(project_dir)
        installed.append(f"Cursor (failClosed=True): {p}")

    if target_lower in ("all", "codex"):
        p = install_codex(project_dir)
        installed.append(f"OpenAI Codex: {p}")

    create_initial_guard_toml(project_dir, preset=preset, mode=mode)
    return installed


def uninstall_agent_hooks(project_dir: Path, agent_target: str = "all") -> list[str]:
    """Uninstall hooks and restore backups."""
    uninstalled: list[str] = []
    target_lower = agent_target.lower()

    targets = [
        ("antigravity", project_dir / ".agents" / "hooks.json"),
        ("claude", project_dir / ".claude" / "settings.json"),
        ("cursor", project_dir / ".cursor" / "hooks.json"),
        ("codex", project_dir / ".codex" / "hooks.json"),
    ]

    for name, path in targets:
        if target_lower in ("all", name) and path.exists():
            restored = restore_backup(path)
            if restored:
                uninstalled.append(f"{name.capitalize()}: Restored from {path}.bak")
            else:
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    if name == "antigravity":
                        data.pop("redline-safety-gate", None)
                    elif name in ("claude", "codex"):
                        hooks = data.get("hooks", {}).get("PreToolUse", [])
                        hooks = [h for h in hooks if not any("agent_redline" in sub.get("command", "") for sub in h.get("hooks", []))]
                        data.setdefault("hooks", {})["PreToolUse"] = hooks
                    elif name == "cursor":
                        hooks = data.get("hooks", {}).get("beforeShellExecution", [])
                        hooks = [h for h in hooks if "agent_redline" not in h.get("command", "")]
                        data.setdefault("hooks", {})["beforeShellExecution"] = hooks
                    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
                    uninstalled.append(f"{name.capitalize()}: Cleaned hooks from {path}")
                except Exception:
                    pass

    return uninstalled


def doctor_diagnostic(project_dir: Path) -> list[dict[str, Any]]:
    """Self-test and inspect all agent hooks."""
    results: list[dict[str, Any]] = []

    engine = Engine()
    probe_benign = engine.evaluate(ToolCall(kind=ToolKind.SHELL, command="git status"))
    probe_malicious = engine.evaluate(ToolCall(kind=ToolKind.SHELL, command="rm -rf /"))

    engine_healthy = (
        probe_benign.decision == Decision.ALLOW and probe_malicious.decision == Decision.DENY
    )

    targets = [
        ("antigravity", project_dir / ".agents" / "hooks.json", True),
        ("claude", project_dir / ".claude" / "settings.json", False),
        ("cursor", project_dir / ".cursor" / "hooks.json", False),
        ("codex", project_dir / ".codex" / "hooks.json", False),
    ]

    for name, path, post_tool in targets:
        installed = False
        fail_mode = "fail-closed"
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                content = json.dumps(data)
                if "agent_redline" in content:
                    installed = True

                if name == "cursor":
                    shell_hooks = data.get("hooks", {}).get("beforeShellExecution", [])
                    has_fail_closed = any(h.get("failClosed") is True for h in shell_hooks)
                    fail_mode = "fail-closed" if has_fail_closed else "fail-open"
            except Exception:
                pass

        results.append({
            "agent": name,
            "installed": installed,
            "path": str(path),
            "fail_mode": fail_mode if installed else "n/a",
            "engine_firing": engine_healthy,
            "post_tool_injection_scanner": "supported" if post_tool else "via SKILL.md",
        })

    return results
