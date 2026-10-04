from click.testing import CliRunner

from src.cli import cli


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "Threat Information Harvester" in result.output
    assert "run" in result.output
    assert "status" in result.output
    assert "test" in result.output


def test_cli_status(tmp_path, monkeypatch):
    monkeypatch.setenv("CACHE_DB_PATH", str(tmp_path / "test.db"))
    runner = CliRunner()
    result = runner.invoke(cli, ["status"])
    assert result.exit_code == 0
    assert "Gemini API Key" in result.output
    assert "Tor SOCKS5 Proxy" in result.output
