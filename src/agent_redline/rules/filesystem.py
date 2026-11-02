"""Destructive filesystem operation protection rules."""

from __future__ import annotations

import os
import re

from agent_redline.models import Decision, RedlineConfig, RiskLevel, ToolCall, ToolKind, Verdict
from agent_redline.rules.base import BaseRule
from agent_redline.shellparse import ParsedCommand, normalize_path, parse_shell_command

DANGEROUS_ROOT_TARGETS = {
    "/",
    "//",
    "/*",
    "/.",
    "/..",
    "c:/",
    "c:\\",
    "c:/*",
    "~",
    "~/",
    "$home",
    "$home/",
    "${home}",
    "${home}/",
    ".git",
    "./.git",
    ".git/",
    ".",
    "./",
    "*",
    "./*",
}

SYSTEM_DIRECTORIES = {
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/lib",
    "/lib64",
    "/proc",
    "/root",
    "/sbin",
    "/sys",
    "/usr",
    "/var",
    "c:/windows",
    "c:/program files",
}


def is_dangerous_fs_target(target: str) -> bool:
    """Check if target points to system root, home, project root or .git."""
    raw_lower = target.strip().strip("'\"").replace("\\", "/").lower()
    if raw_lower in DANGEROUS_ROOT_TARGETS:
        return True

    norm = normalize_path(target).lower().rstrip("/")
    if not norm:
        norm = "/"

    if norm in DANGEROUS_ROOT_TARGETS:
        return True

    # Check if target resolves to user's home directory
    home_dir = os.path.expanduser("~").replace("\\", "/").lower().rstrip("/")
    if norm == home_dir:
        return True

    # Check if target is system directory
    if norm in SYSTEM_DIRECTORIES:
        return True

    # Check .git path
    if norm == ".git" or norm.endswith("/.git") or norm.endswith("\\.git"):
        return True

    return False


class DestructiveFsRule(BaseRule):
    """Detects rm -rf, dd, mkfs, shred, chmod -R 777, and find -delete on broad paths."""

    rule_id = "fs.destructive"
    description = "Prevents catastrophic filesystem deletions and disk modifications."
    risk_level = RiskLevel.CRITICAL

    def evaluate(self, tool_call: ToolCall, config: RedlineConfig) -> Verdict | None:
        if tool_call.kind not in (ToolKind.SHELL, ToolKind.WRITE):
            return None

        # Check shell commands
        if tool_call.kind == ToolKind.SHELL and tool_call.command:
            commands = parse_shell_command(tool_call.command)
            return self._evaluate_command_chain(commands)

        # Check tool file deletion or broad directory write
        for path in tool_call.paths:
            if is_dangerous_fs_target(path):
                return self.build_verdict(
                    decision=Decision.DENY,
                    reason=f"Attempted destructive modification on critical path: {path}",
                    suggested_alternative="Specify a sub-path within your build or cache directory.",
                    risk_level=RiskLevel.CRITICAL,
                )

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

        # 1. rm / rmdir / Remove-Item / del
        if exe in ("rm", "rmdir", "remove-item", "del", "erase"):
            has_recursive = any(
                f in cmd.flags
                for f in (
                    "-r",
                    "-R",
                    "--recursive",
                    "-rf",
                    "-fr",
                    "/s",
                    "-recurse",
                )
            )
            # Check targets
            for target in cmd.targets:
                norm_target = normalize_path(target).lower()
                # Even without recursive, deleting root or .git is blocked
                if is_dangerous_fs_target(target) and (
                    has_recursive or norm_target.endswith(".git")
                ):
                    return self.build_verdict(
                        decision=Decision.DENY,
                        reason=f"Recursive deletion of protected path '{target}' is prohibited.",
                        suggested_alternative="Target a specific subdirectory (e.g., build/, dist/, node_modules/).",
                        risk_level=RiskLevel.CRITICAL,
                    )

        # 2. dd to raw block devices
        if exe == "dd":
            for arg in cmd.args:
                if arg.startswith("of="):
                    out_dev = arg.split("=", 1)[1].lower()
                    if re.match(
                        r"^/dev/(sd[a-z]|nvme[0-9]|hd[a-z]|vd[a-z]|loop[0-9]|null)", out_dev
                    ):
                        return self.build_verdict(
                            decision=Decision.DENY,
                            reason=f"Direct write to raw block device '{out_dev}' via dd is prohibited.",
                            suggested_alternative="Write output to a regular file instead of a block device.",
                            risk_level=RiskLevel.CRITICAL,
                        )

        # 3. mkfs
        if exe.startswith("mkfs"):
            return self.build_verdict(
                decision=Decision.DENY,
                reason="Formatting filesystem via mkfs is prohibited.",
                suggested_alternative="Verify block devices manually or use safe virtual loopback images.",
                risk_level=RiskLevel.CRITICAL,
            )

        # 4. shred
        if exe == "shred":
            for target in cmd.targets:
                if is_dangerous_fs_target(target) or target.startswith("/dev/"):
                    return self.build_verdict(
                        decision=Decision.DENY,
                        reason=f"Shredding protected target '{target}' is prohibited.",
                        suggested_alternative="Use standard file removal on non-system paths.",
                        risk_level=RiskLevel.CRITICAL,
                    )

        # 5. chmod -R 777 on broad paths
        if exe == "chmod":
            has_rec = any(f in cmd.flags for f in ("-R", "--recursive"))
            has_777 = any(arg in ("777", "a+rwx", "ugo+rwx") for arg in cmd.args)
            if has_rec and has_777:
                for target in cmd.targets:
                    if is_dangerous_fs_target(target):
                        return self.build_verdict(
                            decision=Decision.DENY,
                            reason=f"Broad chmod -R 777 on '{target}' is insecure.",
                            suggested_alternative="Apply least-privilege permissions (e.g., chmod 755 or 644) to specific files.",
                            risk_level=RiskLevel.HIGH,
                        )

        # 6. find -delete
        if exe == "find":
            has_delete = "-delete" in cmd.args
            if has_delete:
                for target in cmd.targets:
                    if is_dangerous_fs_target(target):
                        return self.build_verdict(
                            decision=Decision.DENY,
                            reason=f"find -delete on broad root path '{target}' is prohibited.",
                            suggested_alternative="List files first with find without -delete, then clean selectively.",
                            risk_level=RiskLevel.CRITICAL,
                        )

        return None
