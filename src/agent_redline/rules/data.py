"""Destructive database and migration operation protection rules."""

from __future__ import annotations

import re

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

RAW_SQL_BINARIES = {"psql", "mysql", "sqlite3", "mariadb", "mongosh", "mongo"}

UNBOUNDED_DELETE_REGEX = re.compile(r"\bdelete\s+from\s+[a-zA-Z0-9_\.]+\s*(;|--|$)", re.IGNORECASE)
DROP_DATABASE_REGEX = re.compile(r"\bdrop\s+database\b", re.IGNORECASE)
DROP_TABLE_REGEX = re.compile(r"\bdrop\s+table\b", re.IGNORECASE)
TRUNCATE_REGEX = re.compile(r"\btruncate\s+(table\s+)?[a-zA-Z0-9_\.]+\b", re.IGNORECASE)


class DestructiveDataRule(BaseRule):
    """Detects raw DROP/TRUNCATE/DELETE without WHERE, prisma migrate reset, artisan migrate:fresh."""

    rule_id = "data.destructive"
    description = "Prevents irreversible database wipes, drops, and unbounded table deletes."
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
        exe = cmd.executable
        full_raw = cmd.raw

        # 1. Prisma migrate reset
        if exe in ("prisma", "npx") and "migrate" in cmd.args and "reset" in cmd.args:
            return self.build_verdict(
                decision=Decision.DENY if config.mode == Mode.STRICT else Decision.ASK,
                reason="prisma migrate reset will drop and recreate the entire database.",
                suggested_alternative="Use 'npx prisma migrate dev' or 'npx prisma db push' for safe schema updates.",
                risk_level=RiskLevel.HIGH,
            )

        # 2. Laravel artisan migrate:fresh or db:wipe
        if (exe in ("php", "artisan") or "./artisan" in full_raw) and any(
            action in full_raw
            for action in (
                "migrate:fresh",
                "db:wipe",
                "migrate:reset",
            )
        ):
            return self.build_verdict(
                decision=Decision.DENY if config.mode == Mode.STRICT else Decision.ASK,
                reason="artisan migrate:fresh and db:wipe drop all database tables permanently.",
                suggested_alternative="Run 'php artisan migrate' to apply pending migrations safely.",
                risk_level=RiskLevel.HIGH,
            )

        # 3. Direct SQL CLI queries (psql, mysql, sqlite3)
        if exe in RAW_SQL_BINARIES:
            sql_text = " ".join(cmd.args)
            if DROP_DATABASE_REGEX.search(sql_text):
                return self.build_verdict(
                    decision=Decision.DENY,
                    reason="Executing raw DROP DATABASE command is prohibited.",
                    suggested_alternative="Use schema migrations rather than dropping databases.",
                    risk_level=RiskLevel.CRITICAL,
                )

            if DROP_TABLE_REGEX.search(sql_text) or TRUNCATE_REGEX.search(sql_text):
                return self.build_verdict(
                    decision=Decision.DENY if config.mode == Mode.STRICT else Decision.ASK,
                    reason="Executing raw DROP TABLE or TRUNCATE is potentially destructive.",
                    suggested_alternative="Apply controlled versioned migrations.",
                    risk_level=RiskLevel.HIGH,
                )

            if UNBOUNDED_DELETE_REGEX.search(sql_text):
                return self.build_verdict(
                    decision=Decision.DENY,
                    reason="DELETE FROM executed without a WHERE clause will erase all records.",
                    suggested_alternative="Always supply an explicit WHERE clause or use a transaction with rollback.",
                    risk_level=RiskLevel.CRITICAL,
                )

        return None
