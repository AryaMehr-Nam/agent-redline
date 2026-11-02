"""Robust shell command tokenizer, pipeline splitter, and AST parser.

Handles command separators (;, &&, ||, |, newlines), subshells ($(..), `..`),
command wrappers (sudo, env, exec, nohup), shell invocations (sh -c, bash -c),
base64 decoding pipelines, and path normalization without external dependencies.
"""

from __future__ import annotations

import base64
import os
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(slots=True)
class ParsedCommand:
    """Detailed structural representation of an atomic shell command."""

    raw: str
    executable: str
    args: list[str] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)
    targets: list[str] = field(default_factory=list)
    env_vars: dict[str, str] = field(default_factory=dict)
    is_sudo: bool = False
    nested_commands: list[ParsedCommand] = field(default_factory=list)
    piped_from: str | None = None


# Operators that separate distinct command segments
OPERATOR_SPLIT_REGEX = re.compile(r"(\&\&|\|\||;|\||\n)")

# Wrapper executables that wrap another underlying command
WRAPPERS = {"sudo", "doas", "env", "exec", "nohup", "time", "nice", "xargs"}

# Shell binaries that accept inline scripts via -c or -Command
SHELL_EXECUTABLES = {
    "sh",
    "bash",
    "zsh",
    "ksh",
    "dash",
    "ash",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
}

# Subshell extractors
DOLLAR_PAREN_REGEX = re.compile(r"\$\((.+?)\)")
BACKTICK_REGEX = re.compile(r"`(.+?)`")

# Base64 decoder pipeline regex
B64_PIPE_REGEX = re.compile(
    r"echo\s+['\"]?([A-Za-z0-9+/=]{4,})['\"]?\s*\|\s*base64\s+-(?:d|-decode)\s*\|\s*(?:sh|bash|zsh)",
    re.IGNORECASE,
)


def normalize_path(path_str: str, cwd: str | None = None) -> str:
    """Normalize a filesystem path resolving ~, $HOME, and relative segments."""
    cleaned = path_str.strip().strip("'\"")
    if not cleaned:
        return ""

    # Normalize backslashes first
    cleaned = cleaned.replace("\\", "/")

    home = os.path.expanduser("~").replace("\\", "/")
    cleaned = cleaned.replace("${HOME}", home).replace("$HOME", home)

    if cleaned.startswith("~"):
        cleaned = home + cleaned[1:]

    # Strip leading ./ if not root ./
    if cleaned.startswith("./") and cleaned != "./":
        cleaned = cleaned[2:]

    # Check root indicators
    if cleaned in {"/", "//", "/*", "/."}:
        return "/"

    return cleaned


def split_pipeline_segments(command_line: str) -> list[tuple[str, str | None]]:
    """Split a command line into segments, respecting quotes and capturing pipes."""
    segments: list[tuple[str, str | None]] = []
    current_token: list[str] = []
    in_single_quote = False
    in_double_quote = False
    escape = False
    i = 0
    last_pipe_source: str | None = None

    while i < len(command_line):
        char = command_line[i]

        if escape:
            current_token.append(char)
            escape = False
            i += 1
            continue

        if char == "\\":
            escape = True
            current_token.append(char)
            i += 1
            continue

        if char == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            current_token.append(char)
            i += 1
            continue

        if char == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            current_token.append(char)
            i += 1
            continue

        if not in_single_quote and not in_double_quote:
            two_char = command_line[i : i + 2]
            if two_char in ("&&", "||"):
                seg = "".join(current_token).strip()
                if seg:
                    segments.append((seg, last_pipe_source))
                    last_pipe_source = None
                current_token = []
                i += 2
                continue

            if char in (";", "\n"):
                seg = "".join(current_token).strip()
                if seg:
                    segments.append((seg, last_pipe_source))
                    last_pipe_source = None
                current_token = []
                i += 1
                continue

            if char == "|":
                seg = "".join(current_token).strip()
                if seg:
                    segments.append((seg, last_pipe_source))
                    last_pipe_source = seg
                current_token = []
                i += 1
                continue

        current_token.append(char)
        i += 1

    remaining = "".join(current_token).strip()
    if remaining:
        segments.append((remaining, last_pipe_source))

    return segments


def extract_base64_payload(text: str) -> str | None:
    """Detect and decode potential base64 payloads piped into sh/bash."""
    match = re.search(
        r"echo\s+['\"]?([A-Za-z0-9+/=]{4,})['\"]?\s*\|\s*base64\s+-(?:d|-decode)", text
    )
    if match:
        b64_str = match.group(1)
        try:
            decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
            return decoded
        except Exception:
            return None
    return None


def parse_atomic_command(raw_cmd: str, piped_from: str | None = None) -> ParsedCommand | None:
    """Parse a single command token stream (without top-level separators)."""
    trimmed = raw_cmd.strip()
    if not trimmed:
        return None

    try:
        tokens = shlex.split(trimmed, posix=False if os.name == "nt" else True)
    except ValueError:
        tokens = trimmed.split()

    if not tokens:
        return None

    env_vars: dict[str, str] = {}
    is_sudo = False
    idx = 0

    while idx < len(tokens):
        token = tokens[idx].strip("\"'")
        if "=" in token and not token.startswith("-"):
            k, v = token.split("=", 1)
            env_vars[k] = v
            idx += 1
            continue

        lower_token = token.lower()
        if lower_token in ("sudo", "doas"):
            is_sudo = True
            idx += 1
            continue

        if lower_token in ("env", "exec", "nohup", "time"):
            idx += 1
            continue

        break

    if idx >= len(tokens):
        return None

    raw_exe = tokens[idx].strip("\"'")
    exe_name = Path(raw_exe).name.lower()
    arg_tokens = [t.strip("\"'") for t in tokens[idx + 1 :]]

    flags: set[str] = set()
    targets: list[str] = []
    nested_commands: list[ParsedCommand] = []

    # Check for inline script execution
    if exe_name in SHELL_EXECUTABLES:
        for a_idx, arg in enumerate(arg_tokens):
            if arg in ("-c", "-Command", "/c") and a_idx + 1 < len(arg_tokens):
                script_body = arg_tokens[a_idx + 1]
                nested = parse_shell_command(script_body)
                nested_commands.extend(nested)
                break

    # Check for subshell syntax $(...) and `...`
    for match in DOLLAR_PAREN_REGEX.finditer(raw_cmd):
        sub_body = match.group(1)
        nested_commands.extend(parse_shell_command(sub_body))

    for match in BACKTICK_REGEX.finditer(raw_cmd):
        sub_body = match.group(1)
        nested_commands.extend(parse_shell_command(sub_body))

    for arg in arg_tokens:
        if arg.startswith("-"):
            flags.add(arg)
            if not arg.startswith("--") and len(arg) > 2:
                for ch in arg[1:]:
                    flags.add(f"-{ch}")
        else:
            targets.append(arg)

    if piped_from:
        decoded_b64 = extract_base64_payload(piped_from)
        if decoded_b64:
            nested_commands.extend(parse_shell_command(decoded_b64))

    return ParsedCommand(
        raw=trimmed,
        executable=exe_name,
        args=arg_tokens,
        flags=flags,
        targets=targets,
        env_vars=env_vars,
        is_sudo=is_sudo,
        nested_commands=nested_commands,
        piped_from=piped_from,
    )


def parse_shell_command(command_line: str) -> list[ParsedCommand]:
    """Parse a complete shell command string into a sequence of parsed commands."""
    # Check for global base64 pipe decoder pattern across the full pipeline
    extra_nested: list[ParsedCommand] = []
    b64_match = B64_PIPE_REGEX.search(command_line)
    if b64_match:
        b64_str = b64_match.group(1)
        try:
            decoded = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
            extra_nested.extend(parse_shell_command(decoded))
        except Exception:
            pass

    segments = split_pipeline_segments(command_line)
    parsed: list[ParsedCommand] = []

    for seg, piped_from in segments:
        cmd = parse_atomic_command(seg, piped_from=piped_from)
        if cmd:
            if extra_nested and cmd.executable in SHELL_EXECUTABLES:
                cmd.nested_commands.extend(extra_nested)
                extra_nested = []
            parsed.append(cmd)

    return parsed
