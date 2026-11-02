"""Antigravity lifecycle hook adapter (PreToolUse and PostToolUse)."""

from __future__ import annotations

from typing import Any

from agent_redline.adapters.base import BaseAdapter
from agent_redline.models import Decision, ToolCall, ToolKind, Verdict


class AntigravityAdapter(BaseAdapter):
    """Adapter for Google Antigravity .agents/hooks.json PreToolUse and PostToolUse."""

    agent_name = "antigravity"
    supports_post_tool_hook = True

    def normalize(self, raw_payload: dict[str, Any]) -> ToolCall:
        tool_call_dict = raw_payload.get("toolCall", {})
        tool_name = str(tool_call_dict.get("name", "")).lower()
        args = tool_call_dict.get("args", {})
        if not isinstance(args, dict):
            args = {}

        kind = ToolKind.UNKNOWN
        command = ""
        paths: list[str] = []

        if tool_name == "run_command":
            kind = ToolKind.SHELL
            command = str(args.get("CommandLine", ""))
        elif tool_name in ("read_file", "view_file"):
            kind = ToolKind.READ
            p = str(args.get("Path", ""))
            if p:
                paths.append(p)
        elif tool_name in ("write_file", "edit_file"):
            kind = ToolKind.WRITE
            p = str(args.get("Path", ""))
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
            cwd="",
        )

    def encode(
        self, verdict: Verdict
    ) -> tuple[int, dict[str, Any] | None, str | None]:
        decision_str = "allow"
        if verdict.decision == Decision.DENY:
            decision_str = "deny"
        elif verdict.decision == Decision.ASK:
            decision_str = "ask"

        stdout_data: dict[str, Any] = {
            "decision": decision_str,
            "reason": verdict.format_agent_feedback() if verdict.is_blocked else verdict.reason,
        }
        return (0, stdout_data, None)
