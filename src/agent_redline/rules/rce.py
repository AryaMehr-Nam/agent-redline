"""Remote Code Execution (RCE) pipeline protection rules."""

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
from agent_redline.rules.exfiltration import extract_domain_from_url, is_trusted_domain
from agent_redline.shellparse import ParsedCommand, parse_shell_command

CURL_PIPE_SHELL_REGEX = re.compile(
    r"(?:curl|wget)\s+[^|;]+\|\s*(?:sh|bash|zsh|python|python3|perl|ruby)",
    re.IGNORECASE,
)

EVAL_DOWNLOAD_REGEX = re.compile(
    r"\beval\s+[\"']?\$\((?:curl|wget)\s+",
    re.IGNORECASE,
)


class RemoteCodeExecutionRule(BaseRule):
    """Detects curl|sh pipes, eval of downloaded payloads, and untrusted package index installs."""

    rule_id = "exec.rce"
    description = (
        "Prevents executing arbitrary unverified code downloaded directly from the internet."
    )
    risk_level = RiskLevel.CRITICAL

    def evaluate(self, tool_call: ToolCall, config: RedlineConfig) -> Verdict | None:
        if tool_call.kind != ToolKind.SHELL or not tool_call.command:
            return None

        raw = tool_call.command.strip()

        # 1. Direct curl/wget piped to shell or interpreter
        if CURL_PIPE_SHELL_REGEX.search(raw):
            return self.build_verdict(
                decision=Decision.DENY,
                reason="Piping downloaded internet content directly into a shell interpreter (curl | sh) is prohibited.",
                suggested_alternative="Download the script first, inspect its contents, and run it explicitly.",
                risk_level=RiskLevel.CRITICAL,
            )

        # 2. eval $(curl ...)
        if EVAL_DOWNLOAD_REGEX.search(raw):
            return self.build_verdict(
                decision=Decision.DENY,
                reason="Direct eval of downloaded content is prohibited.",
                suggested_alternative="Inspect remote scripts before executing them.",
                risk_level=RiskLevel.CRITICAL,
            )

        commands = parse_shell_command(raw)
        return self._evaluate_commands(commands, config)

    def _evaluate_commands(
        self, commands: list[ParsedCommand], config: RedlineConfig
    ) -> Verdict | None:
        for cmd in commands:
            exe = cmd.executable
            args = cmd.args

            # 3. Pip install from direct URLs or untrusted custom indexes
            if exe in ("pip", "pip3") and "install" in args:
                for arg in args:
                    if arg.startswith(("http://", "https://", "git+http")):
                        dom = extract_domain_from_url(arg)
                        if not is_trusted_domain(dom, config.trusted_domains):
                            return self.build_verdict(
                                decision=Decision.DENY,
                                reason=f"pip install from direct untrusted URL '{arg}' is prohibited.",
                                suggested_alternative="Install verified packages from PyPI or trusted internal indexes.",
                                risk_level=RiskLevel.HIGH,
                            )
                    if arg in ("--index-url", "-i", "--extra-index-url"):
                        # next token might be URL
                        continue

            # 4. Strict mode npm install git URLs
            if (
                config.mode == Mode.STRICT
                and exe in ("npm", "yarn", "pnpm")
                and ("install" in args or "add" in args)
            ):
                for arg in args:
                    if arg.startswith(("git://", "git+https://", "github:")):
                        return self.build_verdict(
                            decision=Decision.DENY,
                            reason=f"Strict mode: Installing npm package from direct git URL '{arg}' is prohibited.",
                            suggested_alternative="Publish packages to a verified registry before installing in strict mode.",
                            risk_level=RiskLevel.MEDIUM,
                        )

        return None
