"""OpenAI Codex CLI hook adapter (PreToolUse)."""

from __future__ import annotations

from typing import Any

from agent_redline.adapters.base import BaseAdapter
from agent_redline.models import Decision, ToolCall, ToolKind, Verdict


class CodexAdapter(BaseAdapter):
    """Adapter for OpenAI Codex CLI PreToolUse hooks."""

    agent_name = "codex"
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
        elif tool_name in ("apply_patch", "Write"):
            kind = ToolKind.WRITE
            p = str(tool_input.get("path", ""))
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

    def encode(
        self, verdict: Verdict
    ) -> tuple[int, dict[str, Any] | None, str | None]:
        # Codex hard-blocks with exit code 2 and reason on stderr
        if verdict.decision == Decision.ALLOW:
            return (0, {"decision": "allow"}, None)

        err_msg = verdict.format_agent_feedback()
        return (2, None, err_msg)
