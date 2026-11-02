"""Destructive git operation protection rules."""

from __future__ import annotations

from agent_redline.models import (
    Decision,
    Mode,
    RedlineConfig,
    RiskLevel,
    ToolCall,
    ToolKind,
    Verdict,
)
from agent_redline.rules.base import BaseRule
from agent_redline.shellparse import ParsedCommand, parse_shell_command

PROTECTED_BRANCHES = {"main", "master", "prod", "production", "release"}


class DestructiveGitRule(BaseRule):
    """Detects force pushes to protected branches, git reset --hard, clean -fdx, branch deletion."""

    rule_id = "git.destructive"
    description = "Prevents irreversible git history rewrites, force pushes, and unrecoverable work loss."
    risk_level = RiskLevel.CRITICAL

    def evaluate(self, tool_call: ToolCall, config: RedlineConfig) -> Verdict | None:
        if tool_call.kind != ToolKind.SHELL or not tool_call.command:
            return None

        commands = parse_shell_command(tool_call.command)
        return self._evaluate_command_chain(commands, config)

    def _evaluate_command_chain(
        self, commands: list[ParsedCommand], config: RedlineConfig
    ) -> Verdict | None:
        for cmd in commands:
            v = self._check_parsed_command(cmd, config)
            if v:
                return v
            if cmd.nested_commands:
                nested_v = self._evaluate_command_chain(cmd.nested_commands, config)
                if nested_v:
                    return nested_v
        return None

    def _check_parsed_command(self, cmd: ParsedCommand, config: RedlineConfig) -> Verdict | None:
        if cmd.executable != "git":
            return None

        args = cmd.args
        if not args:
            return None

        subcommand = args[0].lower()

        # 1. git push
        if subcommand == "push":
            has_force = any(
                f in cmd.flags or f in ("--force", "-f", "--force-with-lease") for f in args
            ) or any(arg.startswith("+") for arg in args[1:])
            has_delete = any(arg in ("--delete", "-d") for arg in args)

            # Check if any branch in args references a protected branch
            protected_target: str | None = None
            feature_target: str | None = None

            for arg in args[1:]:
                # Check refspec deletion syntax: git push origin :main
                if arg.startswith(":"):
                    ref_branch = arg.lstrip(":").lower()
                    if ref_branch in PROTECTED_BRANCHES:
                        return self.build_verdict(
                            decision=Decision.DENY,
                            reason=f"Refspec deletion of protected branch '{arg}' is prohibited.",
                            suggested_alternative="Keep remote protected branch intact.",
                            risk_level=RiskLevel.CRITICAL,
                        )

                clean_arg = arg.lstrip("+").lower()
                branch_name = clean_arg.split(":")[-1]

                if branch_name in PROTECTED_BRANCHES:
                    protected_target = branch_name
                elif not arg.startswith("-") and arg not in ("origin", "upstream", "github"):
                    feature_target = branch_name

            if has_delete:
                if protected_target:
                    return self.build_verdict(
                        decision=Decision.DENY,
                        reason=f"Deleting protected branch '{protected_target}' on remote is prohibited.",
                        suggested_alternative="Branch deletion on protected branches should be managed via repository settings.",
                        risk_level=RiskLevel.CRITICAL,
                    )

            if has_force:
                if protected_target or config.mode == Mode.STRICT:
                    target_name = protected_target or feature_target or "current"
                    return self.build_verdict(
                        decision=Decision.DENY,
                        reason=f"Force-pushing to protected branch '{target_name}' is prohibited.",
                        suggested_alternative="Push normally without --force, or pull and merge latest remote commits.",
                        risk_level=RiskLevel.CRITICAL,
                    )
                # In balanced mode on feature branch or unspecified branch
                target_name = feature_target or "current branch"
                return self.build_verdict(
                    decision=Decision.ASK,
                    reason=f"Force-push requested to {target_name}.",
                    suggested_alternative="Confirm whether remote history overwrite is intended.",
                    risk_level=RiskLevel.HIGH,
                )

        # 2. git reset --hard
        if subcommand == "reset" and "--hard" in args:
            return self.build_verdict(
                decision=Decision.DENY if config.mode == Mode.STRICT else Decision.ASK,
                reason="git reset --hard permanently discards uncommitted changes and recent commits.",
                suggested_alternative="Run 'git stash' to save uncommitted work, or use 'git reset --soft HEAD~1'.",
                risk_level=RiskLevel.HIGH,
            )

        # 3. git clean -fdx
        if subcommand == "clean":
            flags_combined = "".join(f.lstrip("-") for f in args if f.startswith("-"))
            if "f" in flags_combined and "d" in flags_combined and "x" in flags_combined:
                return self.build_verdict(
                    decision=Decision.DENY,
                    reason="git clean -fdx permanently deletes all untracked files and ignored assets.",
                    suggested_alternative="Run 'git clean -ndx' first for a non-destructive preview.",
                    risk_level=RiskLevel.HIGH,
                )

        # 4. git branch -D main / master
        if subcommand == "branch":
            has_force_del = any(f in ("-D", "--delete", "-d") for f in args)
            if has_force_del:
                for arg in args[1:]:
                    if arg.lower() in PROTECTED_BRANCHES:
                        return self.build_verdict(
                            decision=Decision.DENY,
                            reason=f"Force-deleting protected local branch '{arg}' is prohibited.",
                            suggested_alternative="Checkout another branch without deleting the primary repository branch.",
                            risk_level=RiskLevel.CRITICAL,
                        )

        return None
