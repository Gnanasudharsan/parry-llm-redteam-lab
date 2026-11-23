from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from parry import __version__
from parry.cli.app import EXIT_CONFIG, EXIT_REFUSED, app
from parry.mapping import OWASP_LLM_2025, validate_ids

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = str(ROOT / "parry.example.yaml")
runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_targets_list() -> None:
    result = runner.invoke(app, ["targets", "list", "-c", EXAMPLE])
    assert result.exit_code == 0
    assert "vuln-rag\thttp\tloopback" in result.stdout
    assert "vuln-mcp\tmcp_stdio\tin_process" in result.stdout


def test_check_refuses_without_flag() -> None:
    result = runner.invoke(app, ["targets", "check", "-c", EXAMPLE])
    assert result.exit_code == EXIT_REFUSED
    assert "refused" in result.stderr


def test_check_authorizes_named_target() -> None:
    result = runner.invoke(
        app, ["targets", "check", "-c", EXAMPLE, "--i-own-this-target", "vuln-rag"]
    )
    assert result.exit_code == 0
    assert "authorized: vuln-rag (loopback)" in result.stdout


def test_missing_config(tmp_path: Path) -> None:
    result = runner.invoke(app, ["targets", "list", "-c", str(tmp_path / "nope.yaml")])
    assert result.exit_code == EXIT_CONFIG


def test_owasp_table_complete() -> None:
    assert len(OWASP_LLM_2025) == 10
    assert validate_ids(["LLM01:2025"])[0].name == "Prompt Injection"
