"""Claude Code lifecycle hook adapter (PreToolUse)."""

from __future__ import annotations

from typing import Any

from agent_redline.adapters.base import BaseAdapter
from agent_redline.models import Decision, ToolCall, ToolKind, Verdict


class ClaudeAdapter(BaseAdapter):
    """Adapter for Claude Code .claude/settings.json PreToolUse hooks."""

    agent_name = "claude"
    supports_post_tool_hook = False

    def normalize(self, raw_payload: dict[str, Any]) -> ToolCall:
        tool_name = str(raw_payload.get("tool_name", ""))
        tool_input = raw_payload.get("tool_input", {})
        if not isinstance(tool_input, dict):
            tool_input = {}

        kind = ToolKind.UNKNOWN
        command = ""
        paths: list[str] = []

        if tool_name == "Bash":
            kind = ToolKind.SHELL
            command = str(tool_input.get("command", ""))
        elif tool_name in ("FileRead", "View"):
            kind = ToolKind.READ
            p = str(tool_input.get("file_path", ""))
            if p:
                paths.append(p)
        elif tool_name in ("FileEdit", "Write"):
            kind = ToolKind.WRITE
            p = str(tool_input.get("file_path", ""))
            if p:
                paths.append(p)
        else:
            kind = ToolKind.MCP

        return ToolCall(
            kind=kind,
            command=command,
            paths=paths,
            tool_name=tool_name,
            raw_payload=raw_payload,
            agent=self.agent_name,
            cwd=str(raw_payload.get("cwd", "")),
        )

    def encode(self, verdict: Verdict) -> tuple[int, dict[str, Any] | None, str | None]:
        decision_str = "allow"
        if verdict.decision == Decision.DENY:
            decision_str = "deny"
        elif verdict.decision == Decision.ASK:
            decision_str = "ask"

        stdout_data: dict[str, Any] = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision_str,
            }
        }

        stderr_str = verdict.format_agent_feedback() if verdict.is_blocked else None
        return (0, stdout_data, stderr_str)
