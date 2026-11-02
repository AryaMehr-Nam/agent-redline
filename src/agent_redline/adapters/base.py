"""Base class for agent hook protocol adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from agent_redline.models import ToolCall, Verdict


class BaseAdapter(ABC):
    """Abstract adapter translating between vendor hook payloads and agent-redline."""

    agent_name: str
    supports_post_tool_hook: bool = False

    @abstractmethod
    def normalize(self, raw_payload: dict[str, Any]) -> ToolCall:
        """Translate vendor-specific hook JSON into normalized ToolCall."""
        raise NotImplementedError

    @abstractmethod
    def encode(self, verdict: Verdict) -> tuple[int, dict[str, Any] | None, str | None]:
        """Encode Verdict into (exit_code, stdout_dict, stderr_str)."""
        raise NotImplementedError
