"""Release verification tests for agent-redline v0.1.0."""

from pathlib import Path

from agent_redline import __version__
from agent_redline.config import get_presets_dir, load_toml_file


def test_package_version_and_metadata():
    assert __version__ == "0.1.0"


def test_skill_file_spec_compliance():
    skill_file = Path("skills/agent-safety/SKILL.md")
    assert skill_file.is_file(), "Canonical skills/agent-safety/SKILL.md must exist"

    content = skill_file.read_text(encoding="utf-8")
    assert content.startswith("---")
    assert "name: agent-safety" in content
    assert "description:" in content
    # Ensure open Agent Skills format without vendor-specific noise
    assert "rules of the road" in content.lower()


def test_readme_and_media_assets():
    readme = Path("README.md")
    assert readme.is_file()
    text = readme.read_text(encoding="utf-8")
    assert "demo.gif" in text
    assert Path("demo.gif").is_file()
    assert Path("demo.gif").stat().st_size > 1000

    assert "Recall (Catch Rate)" in text
    assert "Multi-Agent Compatibility Matrix" in text
    assert "Is this a sandbox?" in text


def test_presets_valid_toml():
    presets_dir = get_presets_dir()
    expected_presets = ["core", "laravel", "node", "python", "git"]
    for name in expected_presets:
        preset_file = presets_dir / f"{name}.toml"
        assert preset_file.is_file(), f"Preset {name}.toml must exist"
        data = load_toml_file(preset_file)
        assert data.get("name") == name
        assert "mode" in data
