"""Adapter registry for AI agent lifecycle hook protocols."""

from __future__ import annotations

from typing import Any

from agent_redline.adapters.antigravity import AntigravityAdapter
from agent_redline.adapters.base import BaseAdapter
from agent_redline.adapters.claude import ClaudeAdapter
from agent_redline.adapters.codex import CodexAdapter
from agent_redline.adapters.cursor import CursorAdapter

ADAPTERS: dict[str, BaseAdapter] = {
    "antigravity": AntigravityAdapter(),
    "claude": ClaudeAdapter(),
    "cursor": CursorAdapter(),
    "codex": CodexAdapter(),
}


def get_adapter(name: str) -> BaseAdapter:
    """Retrieve adapter by name."""
    clean_name = name.lower()
    if clean_name not in ADAPTERS:
        raise ValueError(
            f"Unsupported agent adapter '{name}'. Supported agents: {list(ADAPTERS.keys())}"
        )
    return ADAPTERS[clean_name]


def detect_adapter(payload: dict[str, Any]) -> BaseAdapter:
    """Auto-detect the appropriate agent adapter from the incoming payload schema."""
    if "toolCall" in payload:
        return ADAPTERS["antigravity"]
    if payload.get("hook_event_name") == "beforeShellExecution" or "workspace_roots" in payload:
        return ADAPTERS["cursor"]
    if "tool_name" in payload:
        # Check codex markers vs claude
        if "session_id" in payload and payload.get("tool_name") in ("apply_patch",):
            return ADAPTERS["codex"]
        return ADAPTERS["claude"]
    # Fallback to Antigravity / Claude
    return ADAPTERS["antigravity"]
