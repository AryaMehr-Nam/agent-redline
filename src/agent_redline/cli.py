"""CLI interface for agent-redline."""

from __future__ import annotations

import argparse
import sys

from agent_redline import __version__
from agent_redline.config import load_config
from agent_redline.engine import Engine
from agent_redline.models import Decision, Mode, ToolCall, ToolKind


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser for redline / guard."""
    parser = argparse.ArgumentParser(
        prog="redline",
        description="Deterministic safety guardrail for AI coding agents",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # check
    check_p = subparsers.add_parser("check", help="Dry-run inspection of a command or path")
    check_p.add_argument("target", help="Shell command or file path to evaluate")
    check_p.add_argument(
        "--tool",
        default="shell",
        choices=["shell", "read", "write", "fetch", "mcp"],
        help="Tool type (default: shell)",
    )
    check_p.add_argument(
        "--mode",
        default="balanced",
        choices=["audit", "balanced", "strict"],
        help="Operational mode",
    )

    # hook
    hook_p = subparsers.add_parser("hook", help="Lifecycle hook entrypoint reading stdin")
    hook_p.add_argument(
        "--agent",
        default="auto",
        choices=["auto", "claude", "antigravity", "cursor", "codex"],
        help="Agent lifecycle protocol format",
    )

    # init
    init_p = subparsers.add_parser("init", help="Install agent-redline hooks")
    init_p.add_argument(
        "--agent",
        default="all",
        choices=["all", "claude", "antigravity", "cursor", "codex"],
        help="Agent to install hooks for",
    )
    init_p.add_argument("--preset", default="core", help="Security preset name")
    init_p.add_argument(
        "--mode",
        default="balanced",
        choices=["audit", "balanced", "strict"],
        help="Operational security mode",
    )

    # uninstall
    uninst_p = subparsers.add_parser("uninstall", help="Safely remove hooks and restore backup")
    uninst_p.add_argument(
        "--agent",
        default="all",
        choices=["all", "claude", "antigravity", "cursor", "codex"],
        help="Agent to uninstall hooks for",
    )

    # bench
    subparsers.add_parser("bench", help="Run precision and recall benchmark on labeled corpus")

    # log
    log_p = subparsers.add_parser("log", help="Inspect security audit log")
    log_p.add_argument("--tail", type=int, default=20, help="Number of recent entries to show")

    # explain
    explain_p = subparsers.add_parser("explain", help="Display details for a specific rule ID")
    explain_p.add_argument("rule_id", help="Rule identifier (e.g. fs.destructive)")

    # doctor
    doc_p = subparsers.add_parser("doctor", help="Verify hook installation and self-test agent hooks")
    doc_p.add_argument(
        "--agent",
        default="all",
        choices=["all", "claude", "antigravity", "cursor", "codex"],
        help="Agent to verify",
    )

    return parser


def run_check_command(args: argparse.Namespace) -> int:
    """Execute dry-run check."""
    config = load_config()
    if args.mode:
        config.mode = Mode(args.mode)

    kind_map = {
        "shell": ToolKind.SHELL,
        "read": ToolKind.READ,
        "write": ToolKind.WRITE,
        "fetch": ToolKind.FETCH,
        "mcp": ToolKind.MCP,
    }
    tool_kind = kind_map.get(args.tool, ToolKind.SHELL)

    if tool_kind == ToolKind.SHELL:
        tc = ToolCall(kind=tool_kind, command=args.target)
    else:
        tc = ToolCall(kind=tool_kind, paths=[args.target])

    engine = Engine(config=config)
    verdict = engine.evaluate(tc)

    # Print human-readable output
    status_symbol = {
        Decision.ALLOW: "[ALLOW]",
        Decision.ASK: "[ASK]  ",
        Decision.DENY: "[DENY] ",
    }.get(verdict.decision, "[UNKNOWN]")

    print(f"{status_symbol} Rule: {verdict.rule_id} ({verdict.risk_level.value.upper()})")
    print(f"Reason: {verdict.reason}")
    if verdict.suggested_alternative:
        print(f"Alternative: {verdict.suggested_alternative}")

    return 2 if verdict.decision == Decision.DENY else 0


def main(argv: list[str] | None = None) -> int:
    """CLI execution entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "check":
        return run_check_command(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
