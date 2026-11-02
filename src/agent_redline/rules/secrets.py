"""Secret and credential read interception rules."""

from __future__ import annotations

import re
from pathlib import Path

from agent_redline.models import Decision, RedlineConfig, RiskLevel, ToolCall, ToolKind, Verdict
from agent_redline.rules.base import BaseRule
from agent_redline.shellparse import ParsedCommand, normalize_path, parse_shell_command

# Safe templates that do not contain actual production secrets
SAFE_TEMPLATE_SUFFIXES = {
    ".example",
    ".sample",
    ".template",
    ".dist",
    ".ci",
    ".schema",
    ".test",
    ".testing",
}

SECRET_PATTERNS = [
    re.compile(r"(^|/)\.env(\.[a-zA-Z0-9_\-]+)?$", re.IGNORECASE),
    re.compile(r"(^|/)\.aws/(credentials|config)$", re.IGNORECASE),
    re.compile(r"(^|/)\.ssh/(id_[a-zA-Z0-9_]+|authorized_keys|known_hosts)$", re.IGNORECASE),
    re.compile(r"(^|/)\.config/gcloud/.*credentials.*$", re.IGNORECASE),
    re.compile(r"(^|/)\.(azure|kube)/config$", re.IGNORECASE),
    re.compile(r"(^|/)\.(npmrc|pypirc|netrc|gem/credentials)$", re.IGNORECASE),
    re.compile(r"\.(pem|key|pfx|p12|pkcs12)$", re.IGNORECASE),
    re.compile(r"(^|/)\.(bash_history|zsh_history|ps_history|sh_history)$", re.IGNORECASE),
    re.compile(r"(^|/)ConsoleHost_history\.txt$", re.IGNORECASE),
    re.compile(r"(^|/)(Cookies|Login Data|key4\.db|logins\.json)$", re.IGNORECASE),
]

READ_BINARIES = {
    "cat",
    "less",
    "more",
    "head",
    "tail",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "ag",
    "ack",
    "cp",
    "mv",
    "tar",
    "zip",
    "7z",
    "base64",
    "xxd",
    "od",
    "hexdump",
    "awk",
    "sed",
    "cut",
    "sort",
    "strings",
    "type",
    "get-content",
    "gc",
}


def is_secret_file_path(path_str: str) -> bool:
    """Check if path points to a known sensitive secret or credential file."""
    norm = normalize_path(path_str).strip()
    if not norm:
        return False

    norm_lower = norm.lower()
    for safe_suffix in SAFE_TEMPLATE_SUFFIXES:
        if norm_lower.endswith(safe_suffix):
            return False

    for pat in SECRET_PATTERNS:
        if pat.search(norm):
            return True

    file_name = Path(norm).name.lower()
    if file_name in (".env", ".pypirc", ".npmrc", ".netrc", "id_rsa", "id_ed25519"):
        return True

    return False


class SecretReadRule(BaseRule):
    """Intercepts attempts to read or inspect credentials, .env files, and secret keys."""

    rule_id = "secrets.read"
    description = "Prevents reading or inspecting credentials, .env, SSH keys, cloud configs, and auth tokens."
    risk_level = RiskLevel.CRITICAL

    def evaluate(self, tool_call: ToolCall, config: RedlineConfig) -> Verdict | None:
        # 1. Inspect direct file read / view / grep / glob tools
        if tool_call.kind in (ToolKind.READ, ToolKind.WRITE, ToolKind.FETCH):
            for path in tool_call.paths:
                if is_secret_file_path(path):
                    return self.build_verdict(
                        decision=Decision.DENY,
                        reason=f"Access to sensitive credential/secret file '{path}' is prohibited.",
                        suggested_alternative="Reference .env.example or request sanitized configuration values from the user.",
                        risk_level=RiskLevel.CRITICAL,
                    )

        # 2. Inspect shell commands reading sensitive files
        if tool_call.kind == ToolKind.SHELL and tool_call.command:
            commands = parse_shell_command(tool_call.command)
            return self._evaluate_command_chain(commands)

        return None

    def _evaluate_command_chain(self, commands: list[ParsedCommand]) -> Verdict | None:
        for cmd in commands:
            v = self._check_parsed_command(cmd)
            if v:
                return v
            if cmd.nested_commands:
                nested_v = self._evaluate_command_chain(cmd.nested_commands)
                if nested_v:
                    return nested_v
        return None

    def _check_parsed_command(self, cmd: ParsedCommand) -> Verdict | None:
        exe = cmd.executable

        # Exemption: cp .env.example .env (source is safe template)
        if exe == "cp" and len(cmd.targets) >= 2:
            src = cmd.targets[0]
            if not is_secret_file_path(src):
                return None

        targets_to_check = list(cmd.targets)
        if exe in READ_BINARIES:
            targets_to_check.extend(cmd.args)

        for target in targets_to_check:
            if target.startswith("-"):
                continue

            if is_secret_file_path(target):
                return self.build_verdict(
                    decision=Decision.DENY,
                    reason=f"Command '{exe}' attempting to read sensitive secret target '{target}'.",
                    suggested_alternative="Inspect non-sensitive template files (e.g. .env.example) or use environment variables.",
                    risk_level=RiskLevel.CRITICAL,
                )

        return None
