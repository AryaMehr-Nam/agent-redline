"""Exfiltration sink and secret source correlation rules."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from agent_redline.models import Decision, RedlineConfig, RiskLevel, ToolCall, ToolKind, Verdict
from agent_redline.rules.base import BaseRule
from agent_redline.rules.secrets import is_secret_file_path
from agent_redline.shellparse import ParsedCommand, parse_shell_command

NETWORK_SINKS = {
    "curl",
    "wget",
    "nc",
    "netcat",
    "ncat",
    "socat",
    "telnet",
    "scp",
    "rsync",
    "ssh",
    "ftp",
    "tftp",
}

SECRET_ENV_VAR_REGEX = re.compile(
    r"\$(?:[A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|CREDENTIAL|AUTH)[A-Z0-9_]*)",
    re.IGNORECASE,
)

ENV_DUMP_COMMANDS = {"printenv", "env", "export"}


def extract_domain_from_url(url_or_target: str) -> str | None:
    """Extract host domain from a URL or network target."""
    if not url_or_target.startswith(("http://", "https://", "ftp://")):
        url_or_target = "https://" + url_or_target
    try:
        parsed = urlparse(url_or_target)
        return parsed.hostname
    except Exception:
        return None


def is_trusted_domain(domain: str | None, trusted_list: list[str]) -> bool:
    """Check if domain is in or subdomain of trusted domain list."""
    if not domain:
        return False
    domain = domain.lower()
    for trusted in trusted_list:
        trusted = trusted.lower()
        if domain == trusted or domain.endswith("." + trusted):
            return True
    return False


class ExfiltrationRule(BaseRule):
    """Detects pipelines combining secret sources with network exfiltration sinks."""

    rule_id = "network.exfiltration"
    description = "Prevents sending sensitive secrets, environment variables, or files to external network endpoints."
    risk_level = RiskLevel.CRITICAL

    def evaluate(self, tool_call: ToolCall, config: RedlineConfig) -> Verdict | None:
        if tool_call.kind != ToolKind.SHELL or not tool_call.command:
            return None

        commands = parse_shell_command(tool_call.command)
        return self._evaluate_pipeline(commands, tool_call.command, config)

    def _evaluate_pipeline(
        self, commands: list[ParsedCommand], raw_line: str, config: RedlineConfig
    ) -> Verdict | None:
        has_secret_source = False
        has_network_sink = False
        sink_target_domain: str | None = None

        # Check raw command line for sensitive environment variable references
        if SECRET_ENV_VAR_REGEX.search(raw_line):
            has_secret_source = True

        for cmd in commands:
            exe = cmd.executable

            # 1. Check if command is an env dumper (printenv, env)
            if exe in ENV_DUMP_COMMANDS and not cmd.args:
                has_secret_source = True

            # 2. Check if reading a secret file
            for arg in cmd.args:
                if is_secret_file_path(arg):
                    has_secret_source = True
                if arg.startswith("@") and is_secret_file_path(arg[1:]):
                    has_secret_source = True

            # 3. Check if command is a network sink
            if exe in NETWORK_SINKS:
                has_network_sink = True
                for arg in cmd.args:
                    if not arg.startswith("-"):
                        dom = extract_domain_from_url(arg)
                        if dom:
                            sink_target_domain = dom
                            break

            # 4. Check python/node inline network one-liners
            if exe in ("python", "python3", "node", "ruby", "perl"):
                arg_text = " ".join(cmd.args)
                if any(kw in arg_text for kw in ("requests.", "urllib", "http.client", "fetch(", "axios.")):
                    has_network_sink = True

            # 5. Check git remote add
            if exe == "git" and "remote" in cmd.args and "add" in cmd.args:
                for arg in cmd.args:
                    if "http" in arg or "@" in arg:
                        dom = extract_domain_from_url(arg)
                        if dom and not is_trusted_domain(dom, config.trusted_domains):
                            return self.build_verdict(
                                decision=Decision.DENY,
                                reason=f"Adding git remote pointing to untrusted domain '{dom}'.",
                                suggested_alternative="Add git remotes only for trusted hosts (e.g., github.com).",
                                risk_level=RiskLevel.HIGH,
                            )

        # Trigger exfiltration block if a secret source is chained or paired with a network sink
        if has_secret_source and has_network_sink:
            trusted = is_trusted_domain(sink_target_domain, config.trusted_domains)
            if not trusted:
                return self.build_verdict(
                    decision=Decision.DENY,
                    reason="Potential data exfiltration: secret source piped or sent to external network sink.",
                    suggested_alternative="Never upload secrets or credentials to external network endpoints.",
                    risk_level=RiskLevel.CRITICAL,
                )

        return None
