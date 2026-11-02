"""Core domain models for agent-redline."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ToolKind(str, Enum):
    """Categorized tool operation kinds."""

    SHELL = "shell"
    READ = "read"
    WRITE = "write"
    FETCH = "fetch"
    MCP = "mcp"
    UNKNOWN = "unknown"


class Decision(str, Enum):
    """Firewall verdict decision."""

    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


class RiskLevel(str, Enum):
    """Risk severity classification."""

    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Mode(str, Enum):
    """Operational mode of agent-redline."""

    AUDIT = "audit"  # Log actions, never block
    BALANCED = "balanced"  # Deny critical/destructive, ask on risky
    STRICT = "strict"  # Deny critical, high, and medium risks


@dataclass(slots=True)
class ToolCall:
    """Agent-agnostic normalized tool call representation."""

    kind: ToolKind
    command: str = ""
    paths: list[str] = field(default_factory=list)
    tool_name: str = ""
    raw_payload: dict[str, Any] = field(default_factory=dict)
    agent: str = "unknown"
    cwd: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert tool call to dictionary representation."""
        return {
            "kind": self.kind.value,
            "command": self.command,
            "paths": list(self.paths),
            "tool_name": self.tool_name,
            "agent": self.agent,
            "cwd": self.cwd,
        }


@dataclass(slots=True)
class Verdict:
    """Deterministic verdict produced by the firewall engine."""

    decision: Decision
    rule_id: str = "allow.default"
    reason: str = "Operation permitted by security policy."
    suggested_alternative: str | None = None
    risk_level: RiskLevel = RiskLevel.SAFE

    @property
    def is_blocked(self) -> bool:
        """Return True if decision is not allow."""
        return self.decision != Decision.ALLOW

    def to_dict(self) -> dict[str, Any]:
        """Convert verdict to dictionary."""
        return {
            "decision": self.decision.value,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "suggested_alternative": self.suggested_alternative,
            "risk_level": self.risk_level.value,
        }

    def format_agent_feedback(self) -> str:
        """Format an explanation specifically tailored for the AI agent."""
        if self.decision == Decision.ALLOW:
            return "Operation permitted."

        lines = [
            f"[REDLINE SECURITY BLOCK] Rule: {self.rule_id} ({self.risk_level.value.upper()})",
            f"Blocked: {self.reason}",
        ]
        if self.suggested_alternative:
            lines.append(f"Safe Alternative: {self.suggested_alternative}")
        return "\n".join(lines)


@dataclass(slots=True)
class RedlineConfig:
    """Configuration settings for agent-redline."""

    mode: Mode = Mode.BALANCED
    presets: list[str] = field(default_factory=lambda: ["core"])
    allow_globs: list[str] = field(default_factory=list)
    deny_globs: list[str] = field(default_factory=list)
    allow_commands: list[str] = field(default_factory=list)
    deny_commands: list[str] = field(default_factory=list)
    trusted_domains: list[str] = field(
        default_factory=lambda: [
            "github.com",
            "raw.githubusercontent.com",
            "pypi.org",
            "npmjs.com",
            "packagist.org",
        ]
    )
    fail_mode: Decision = Decision.ASK
    log_file: str = ".redline/audit.jsonl"
    enable_prompt_injection_warning: bool = True
