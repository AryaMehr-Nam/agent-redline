"""Persistence, security disabling, and self-defense rules."""

from __future__ import annotations

from agent_redline.models import Decision, RedlineConfig, RiskLevel, ToolCall, ToolKind, Verdict
from agent_redline.rules.base import BaseRule
from agent_redline.shellparse import ParsedCommand, normalize_path, parse_shell_command

PERSISTENCE_FILES = {
    ".bashrc",
    ".zshrc",
    ".profile",
    ".bash_profile",
    "authorized_keys",
}

CRON_INDICATORS = {"crontab", "/etc/cron.d", "/etc/crontab", "/var/spool/cron"}

GUARD_PROTECTED_FILES = {
    "guard.toml",
    ".redline.toml",
    "hooks.json",
    "settings.json",
}

GUARD_HOOK_PATHS = [
    ".claude/settings.json",
    ".agents/hooks.json",
    ".cursor/hooks.json",
    ".codex/hooks.json",
    "guard.toml",
    ".redline.toml",
]


class PersistenceAndDefenseRule(BaseRule):
    """Detects crontab edits, shell rc tampering, security disabling, and protects the guard itself."""

    rule_id = "system.defense"
    description = "Prevents establishing persistent backdoors, disabling security tools, or modifying redline config."
    risk_level = RiskLevel.CRITICAL

    def evaluate(self, tool_call: ToolCall, config: RedlineConfig) -> Verdict | None:
        # 1. Direct tool file write/edit targeting guard files or persistence files
        if tool_call.kind in (ToolKind.WRITE, ToolKind.READ):
            for path in tool_call.paths:
                norm = normalize_path(path).lower()

                # Self-defense: guard config/hooks protection
                for hook_path in GUARD_HOOK_PATHS:
                    if norm.endswith(hook_path) or hook_path in norm:
                        if tool_call.kind == ToolKind.WRITE:
                            return self.build_verdict(
                                decision=Decision.DENY,
                                reason=f"Self-defense: Modifying safety guard config or hook '{path}' via agent tool call is prohibited.",
                                suggested_alternative="Guard configuration changes must be performed by the developer directly.",
                                risk_level=RiskLevel.CRITICAL,
                            )

                # Persistence file modification
                if tool_call.kind == ToolKind.WRITE:
                    if any(norm.endswith(p) for p in PERSISTENCE_FILES):
                        return self.build_verdict(
                            decision=Decision.DENY,
                            reason=f"Modifying shell startup or persistence file '{path}' is prohibited.",
                            suggested_alternative="Set transient environment variables for the current session instead.",
                            risk_level=RiskLevel.HIGH,
                        )

        # 2. Shell commands inspection
        if tool_call.kind == ToolKind.SHELL and tool_call.command:
            commands = parse_shell_command(tool_call.command)
            return self._evaluate_commands(commands)

        return None

    def _evaluate_commands(self, commands: list[ParsedCommand]) -> Verdict | None:
        for cmd in commands:
            exe = cmd.executable
            raw = cmd.raw.lower()

            # Self-defense: prevent running uninstall via agent
            if exe in ("redline", "guard") and "uninstall" in cmd.args:
                return self.build_verdict(
                    decision=Decision.DENY,
                    reason="Self-defense: Uninstalling safety guard via agent tool call is prohibited.",
                    suggested_alternative="Uninstall must be executed directly by the human developer.",
                    risk_level=RiskLevel.CRITICAL,
                )

            # Check self-defense on shell writes to guard config/hooks
            if any(hp in raw for hp in GUARD_HOOK_PATHS) and any(
                w in exe for w in ("rm", "echo", "sed", "mv", "cp", "tee")
            ):
                return self.build_verdict(
                    decision=Decision.DENY,
                    reason="Self-defense: Modifying or deleting safety guard hooks via shell command is prohibited.",
                    suggested_alternative="Edit guard configuration manually as the project owner.",
                    risk_level=RiskLevel.CRITICAL,
                )

            # Crontab tampering
            if exe == "crontab":
                return self.build_verdict(
                    decision=Decision.DENY,
                    reason="Manipulating scheduled cron tasks via crontab is prohibited.",
                    suggested_alternative="Use project-level background workers or task schedulers.",
                    risk_level=RiskLevel.HIGH,
                )

            # Security tool disabling (ufw, iptables, setenforce)
            if exe in ("ufw", "iptables", "setenforce"):
                if "disable" in cmd.args or "0" in cmd.args or "-F" in cmd.args:
                    return self.build_verdict(
                        decision=Decision.DENY,
                        reason=f"Disabling system security firewall or SELinux control via '{exe}' is prohibited.",
                        suggested_alternative="Configure required network rules without disabling system firewalls.",
                        risk_level=RiskLevel.CRITICAL,
                    )

            # Modifying shell rc files via redirection (e.g. echo ... >> ~/.bashrc)
            if any(rc in raw for rc in PERSISTENCE_FILES) and (">" in raw or "tee" in exe):
                return self.build_verdict(
                    decision=Decision.DENY,
                    reason="Appending commands or modifying user shell rc files is prohibited.",
                    suggested_alternative="Export variables within the project environment or script.",
                    risk_level=RiskLevel.HIGH,
                )

        return None
