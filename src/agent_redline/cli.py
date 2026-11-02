"""CLI interface for agent-redline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_redline import __version__
from agent_redline.adapters import detect_adapter, get_adapter
from agent_redline.bench import BenchmarkRunner
from agent_redline.config import load_config
from agent_redline.engine import Engine
from agent_redline.injection import InjectionScanner
from agent_redline.installer import (
    doctor_diagnostic,
    init_agent_hooks,
    uninstall_agent_hooks,
)
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

    # bench
    bench_p = subparsers.add_parser(
        "bench", help="Run precision and recall benchmark on labeled corpus"
    )
    bench_p.add_argument("--corpus", default="corpus", help="Path to corpus directory")

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

    # explain
    explain_p = subparsers.add_parser("explain", help="Display details for a specific rule ID")
    explain_p.add_argument("rule_id", help="Rule identifier (e.g. fs.destructive)")

    # doctor
    doc_p = subparsers.add_parser(
        "doctor", help="Verify hook installation and self-test agent hooks"
    )
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


def run_hook_command(args: argparse.Namespace) -> int:
    """Execute lifecycle hook by reading stdin JSON and delegating to adapter."""
    try:
        raw_text = sys.stdin.read()
        if not raw_text.strip():
            return 0
        payload = json.loads(raw_text)
    except Exception as exc:
        # Fallback to safe ask/deny on invalid JSON
        sys.stderr.write(f"[agent-redline] Error reading hook stdin: {exc}\n")
        return 2

    # Check if PostToolUse injection scan
    event_name = payload.get("hook_event_name") or payload.get("hookEventName")
    if event_name in ("PostToolUse", "postToolUse"):
        scanner = InjectionScanner()
        content = json.dumps(payload)
        scan_res = scanner.scan(content)
        if scan_res.is_suspicious:
            sys.stdout.write(scan_res.warning_banner + "\n")
        print("{}")
        return 0

    adapter = detect_adapter(payload) if args.agent == "auto" else get_adapter(args.agent)

    tool_call = adapter.normalize(payload)
    engine = Engine()
    verdict = engine.evaluate(tool_call)

    exit_code, stdout_data, stderr_str = adapter.encode(verdict)

    if stderr_str:
        sys.stderr.write(stderr_str + "\n")

    if stdout_data is not None:
        sys.stdout.write(json.dumps(stdout_data) + "\n")

    return exit_code


def run_bench_command(args: argparse.Namespace) -> int:
    """Execute benchmark against labeled corpus."""
    corpus_path = Path(args.corpus)
    runner = BenchmarkRunner(corpus_dir=corpus_path)
    result = runner.run()
    print(result.format_report())
    if result.recall < 0.95 or result.fpr > 0.05:
        return 1
    return 0


def run_init_command(args: argparse.Namespace) -> int:
    """Install redline hooks into requested agents."""
    project_dir = Path.cwd()
    installed = init_agent_hooks(
        project_dir=project_dir,
        agent_target=args.agent,
        preset=args.preset,
        mode=args.mode,
    )
    print("agent-redline hook installation complete:")
    for item in installed:
        print(f"  + {item}")
    print("\nSecurity firewall is active. Run 'redline doctor' to verify status.")
    return 0


def run_uninstall_command(args: argparse.Namespace) -> int:
    """Uninstall hooks and restore backups."""
    project_dir = Path.cwd()
    uninstalled = uninstall_agent_hooks(project_dir=project_dir, agent_target=args.agent)
    print("agent-redline uninstallation complete:")
    for item in uninstalled:
        print(f"  - {item}")
    return 0


def run_doctor_command(args: argparse.Namespace) -> int:
    """Run diagnostic self-test."""
    project_dir = Path.cwd()
    results = doctor_diagnostic(project_dir)

    print("\n=========================================================================")
    print("                   agent-redline Multi-Agent Diagnostics                 ")
    print("=========================================================================")
    print(
        f" {'Agent':<14} | {'Installed':<10} | {'Engine Firing':<14} | {'Fail Mode':<12} | {'Injection Scan':<14} "
    )
    print("-" * 73)
    for r in results:
        inst = "YES" if r["installed"] else "NO"
        firing = "HEALTHY" if r["engine_firing"] else "ERROR"
        print(
            f" {r['agent']:<14} | {inst:<10} | {firing:<14} | {r['fail_mode']:<12} | {r['post_tool_injection_scanner']:<14} "
        )
    print("=========================================================================\n")
    return 0


def run_explain_command(args: argparse.Namespace) -> int:
    """Display information about a specific rule ID."""
    rule_id = args.rule_id
    explanations = {
        "fs.destructive": "Prevents catastrophic filesystem modifications (rm -rf /, dd, mkfs, shred, chmod -R 777).",
        "git.destructive": "Blocks irreversible git history operations (push --force, clean -fdx, reset --hard).",
        "data.destructive": "Prevents raw DROP DATABASE, TRUNCATE, unbounded DELETE, and database wipe migrations.",
        "secrets.read": "Intercepts read attempts on credentials, .env, SSH keys, cloud configs, and tokens.",
        "network.exfiltration": "Stops pipelines combining secret sources with external network sinks.",
        "exec.rce": "Blocks piping untrusted remote scripts directly into shell interpreters (curl | sh).",
        "system.defense": "Protects against backdoor persistence and prevents agents from altering safety hooks.",
    }
    desc = explanations.get(rule_id, "Standard agent-redline security rule.")
    print(f"Rule ID: {rule_id}\nDescription: {desc}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI execution entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "check":
        return run_check_command(args)
    if args.command == "hook":
        return run_hook_command(args)
    if args.command == "bench":
        return run_bench_command(args)
    if args.command == "init":
        return run_init_command(args)
    if args.command == "uninstall":
        return run_uninstall_command(args)
    if args.command == "doctor":
        return run_doctor_command(args)
    if args.command == "explain":
        return run_explain_command(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
