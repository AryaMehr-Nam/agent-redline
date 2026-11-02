"""Base class for all agent-redline security rules."""

from __future__ import annotations

from abc import ABC, abstractmethod

from agent_redline.models import Decision, RedlineConfig, RiskLevel, ToolCall, Verdict


class BaseRule(ABC):
    """Abstract base rule evaluated against incoming tool calls."""

    rule_id: str
    description: str
    risk_level: RiskLevel = RiskLevel.HIGH

    @abstractmethod
    def evaluate(self, tool_call: ToolCall, config: RedlineConfig) -> Verdict | None:
        """Evaluate the tool call.

        Returns a Verdict if the rule triggers, or None to pass.
        """
        raise NotImplementedError

    def build_verdict(
        self,
        decision: Decision,
        reason: str,
        suggested_alternative: str | None = None,
        risk_level: RiskLevel | None = None,
    ) -> Verdict:
        """Helper to construct a standardized Verdict."""
        return Verdict(
            decision=decision,
            rule_id=self.rule_id,
            reason=reason,
            suggested_alternative=suggested_alternative,
            risk_level=risk_level or self.risk_level,
        )
