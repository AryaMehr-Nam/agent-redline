"""Configuration and preset loader for agent-redline."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from agent_redline.models import Decision, Mode, RedlineConfig

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


def get_presets_dir() -> Path:
    """Return the directory containing bundled TOML presets."""
    return Path(__file__).parent / "presets"


def load_toml_file(path: Path | str) -> dict[str, Any]:
    """Safely load and parse a TOML file."""
    p = Path(path)
    if not p.is_file():
        return {}
    with p.open("rb") as f:
        return tomllib.load(f)


def merge_config_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge override dictionary into base dictionary."""
    result = dict(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = merge_config_dicts(result[key], val)
        elif key in result and isinstance(result[key], list) and isinstance(val, list):
            # Unique merge preserving order
            merged_list = list(result[key])
            for item in val:
                if item not in merged_list:
                    merged_list.append(item)
            result[key] = merged_list
        else:
            result[key] = val
    return result


def parse_config_dict(data: dict[str, Any]) -> RedlineConfig:
    """Instantiate a RedlineConfig from parsed dictionary data."""
    mode_str = str(data.get("mode", "balanced")).lower()
    try:
        mode = Mode(mode_str)
    except ValueError:
        mode = Mode.BALANCED

    fail_mode_str = str(data.get("fail_mode", "ask")).lower()
    try:
        fail_mode = Decision(fail_mode_str)
    except ValueError:
        fail_mode = Decision.ASK

    presets = data.get("presets", ["core"])
    if isinstance(presets, str):
        presets = [presets]

    allow_globs = list(data.get("allow_globs", []))
    deny_globs = list(data.get("deny_globs", []))
    allow_commands = list(data.get("allow_commands", []))
    deny_commands = list(data.get("deny_commands", []))
    trusted_domains = list(
        data.get(
            "trusted_domains",
            [
                "github.com",
                "raw.githubusercontent.com",
                "pypi.org",
                "npmjs.com",
                "packagist.org",
            ],
        )
    )

    log_file = str(data.get("log_file", ".redline/audit.jsonl"))
    enable_pi_warn = bool(data.get("enable_prompt_injection_warning", True))

    return RedlineConfig(
        mode=mode,
        presets=presets,
        allow_globs=allow_globs,
        deny_globs=deny_globs,
        allow_commands=allow_commands,
        deny_commands=deny_commands,
        trusted_domains=trusted_domains,
        fail_mode=fail_mode,
        log_file=log_file,
        enable_prompt_injection_warning=enable_pi_warn,
    )


def load_config(
    project_dir: Path | str | None = None,
    explicit_config_path: Path | str | None = None,
) -> RedlineConfig:
    """Load configuration hierarchy: presets -> guard.toml overrides."""
    merged_data: dict[str, Any] = {}

    # Locate project directory
    cwd = Path(project_dir) if project_dir else Path.cwd()

    # Determine local config path
    config_file: Path | None = None
    if explicit_config_path:
        config_file = Path(explicit_config_path)
    else:
        for candidate in ["guard.toml", ".redline.toml", ".redline/guard.toml"]:
            cand_path = cwd / candidate
            if cand_path.is_file():
                config_file = cand_path
                break

    local_data = load_toml_file(config_file) if config_file else {}

    # Identify presets to load (default to core if none specified)
    presets = local_data.get("presets", ["core"])
    if isinstance(presets, str):
        presets = [presets]

    presets_dir = get_presets_dir()
    for preset_name in presets:
        preset_file = presets_dir / f"{preset_name}.toml"
        if preset_file.is_file():
            preset_data = load_toml_file(preset_file)
            merged_data = merge_config_dicts(merged_data, preset_data)

    # Finally overlay local config data
    if local_data:
        merged_data = merge_config_dicts(merged_data, local_data)

    # Check environment variable overrides
    env_mode = os.environ.get("REDLINE_MODE")
    if env_mode:
        merged_data["mode"] = env_mode

    return parse_config_dict(merged_data)
