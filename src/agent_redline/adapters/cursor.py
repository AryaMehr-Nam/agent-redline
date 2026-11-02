"""Cursor lifecycle hook adapter (beforeShellExecution)."""

from __future__ import annotations

from typing import Any

from agent_redline.adapters.base import BaseAdapter
from agent_redline.models import Decision, ToolCall, ToolKind, Verdict


class CursorAdapter(BaseAdapter):
    """Adapter for Cursor .cursor/hooks.json beforeShellExecution."""

    agent_name = "cursor"
    supports_post_tool_hook = False

    def normalize(self, raw_payload: dict[str, Any]) -> ToolCall:
        cmd = str(raw_payload.get("command", ""))
        cwd = str(raw_payload.get("currentWorkingDirectory", ""))

        return ToolCall(
            kind=ToolKind.SHELL,
            command=cmd,
            paths=[],
            tool_name="beforeShellExecution",
            raw_payload=raw_payload,
            agent=self.agent_name,
            cwd=cwd,
        )

    def encode(
        self, verdict: Verdict
    ) -> tuple[int, dict[str, Any] | None, str | None]:
        # Cursor expects { permission: "allow" | "deny", agentMessage?: string }
        if verdict.decision == Decision.ALLOW:
            return (0, {"permission": "allow"}, None)

        msg = verdict.format_agent_feedback()
        return (0, {"permission": "deny", "agentMessage": msg}, None)
