"""Unit tests for agent-redline CLI entrypoint."""

import pytest

from agent_redline.cli import main


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "redline 0.1.0" in captured.out or "redline 0.1.0" in captured.err


def test_cli_help(capsys):
    ret = main([])
    assert ret == 0
    captured = capsys.readouterr()
    assert "usage:" in captured.out
    assert "redline" in captured.out
