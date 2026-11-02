"""Deterministic safety firewall evaluation engine."""

from __future__ import annotations

import fnmatch
import json
import logging
from pathlib import Path
from typing import Any

from agent_redline.config import load_config
from agent_redline.models import Decision, Mode, RedlineConfig, RiskLevel, ToolCall, Verdict
from agent_redline.rules.base import BaseRule
from agent_redline.rules.data import DestructiveDataRule
from agent_redline.rules.defense import PersistenceAndDefenseRule
from agent_redline.rules.exfiltration import ExfiltrationRule
from agent_redline.rules.filesystem import DestructiveFsRule
from agent_redline.rules.git import DestructiveGitRule
from agent_redline.rules.rce import RemoteCodeExecutionRule
from agent_redline.rules.secrets import SecretReadRule

logger = logging.getLogger("agent_redline.engine")


class Engine:
    """Core deterministic security firewall evaluation engine."""

    def __init__(self, config: RedlineConfig | None = None) -> None:
        self.config = config or load_config()
        self.rules: list[BaseRule] = [
            DestructiveFsRule(),
            DestructiveGitRule(),
            DestructiveDataRule(),
            SecretReadRule(),
            ExfiltrationRule(),
            RemoteCodeExecutionRule(),
            PersistenceAndDefenseRule(),
        ]

    def register_rule(self, rule: BaseRule) -> None:
        """Register an additional security rule."""
        self.rules.append(rule)

    def evaluate(self, tool_call: ToolCall) -> Verdict:
        """Evaluate a tool call against the security policy and active rules."""
        try:
            return self._evaluate_internal(tool_call)
        except Exception as exc:  # pragma: no cover
            logger.error("Internal engine evaluation exception: %s", exc)
            return Verdict(
                decision=self.config.fail_mode,
                rule_id="internal.error",
                reason=f"Evaluation failed safely with fail-mode ({self.config.fail_mode.value}): {exc}",
                risk_level=RiskLevel.HIGH,
            )

    def _evaluate_internal(self, tool_call: ToolCall) -> Verdict:
        cmd_str = tool_call.command.strip()

        # 1. User / Project explicit allowlists
        for allow_cmd in self.config.allow_commands:
            if cmd_str == allow_cmd or fnmatch.fnmatch(cmd_str, allow_cmd):
                return Verdict(
                    decision=Decision.ALLOW,
                    rule_id="allow.user_override",
                    reason=f"Matched explicit allowlist command: {allow_cmd}",
                )

        for path in tool_call.paths:
            for allow_glob in self.config.allow_globs:
                if fnmatch.fnmatch(path, allow_glob):
                    return Verdict(
                        decision=Decision.ALLOW,
                        rule_id="allow.user_override",
                        reason=f"Matched explicit allowlist glob: {allow_glob}",
                    )

        # 2. User / Project explicit denylists
        for deny_cmd in self.config.deny_commands:
            if cmd_str == deny_cmd or fnmatch.fnmatch(cmd_str, deny_cmd):
                return Verdict(
                    decision=Decision.DENY,
                    rule_id="deny.user_override",
                    reason=f"Matched explicit denylist command: {deny_cmd}",
                    risk_level=RiskLevel.HIGH,
                )

        for path in tool_call.paths:
            for deny_glob in self.config.deny_globs:
                if fnmatch.fnmatch(path, deny_glob):
                    return Verdict(
                        decision=Decision.DENY,
                        rule_id="deny.user_override",
                        reason=f"Matched explicit denylist glob: {deny_glob}",
                        risk_level=RiskLevel.HIGH,
                    )

        # 3. Rule evaluation chain
        for rule in self.rules:
            verdict = rule.evaluate(tool_call, self.config)
            if verdict and verdict.is_blocked:
                final_verdict = self._apply_operational_mode(verdict)
                self._record_audit_log(tool_call, final_verdict)
                return final_verdict

        # Default permit
        verdict = Verdict(decision=Decision.ALLOW)
        self._record_audit_log(tool_call, verdict)
        return verdict

    def _apply_operational_mode(self, verdict: Verdict) -> Verdict:
        """Adjust decision according to configured operational mode (audit, balanced, strict)."""
        if self.config.mode == Mode.AUDIT:
            return Verdict(
                decision=Decision.ALLOW,
                rule_id=verdict.rule_id,
                reason=f"[AUDIT] {verdict.reason} (Would block in balanced mode)",
                suggested_alternative=verdict.suggested_alternative,
                risk_level=verdict.risk_level,
            )

        if self.config.mode == Mode.STRICT:
            return Verdict(
                decision=Decision.DENY,
                rule_id=verdict.rule_id,
                reason=verdict.reason,
                suggested_alternative=verdict.suggested_alternative,
                risk_level=verdict.risk_level,
            )

        return verdict

    def _record_audit_log(self, tool_call: ToolCall, verdict: Verdict) -> None:
        """Append redacted event to JSONL audit log."""
        if not self.config.log_file:
            return

        try:
            log_path = Path(self.config.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            entry: dict[str, Any] = {
                "tool": tool_call.to_dict(),
                "verdict": verdict.to_dict(),
            }
            with log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass
