from click.testing import CliRunner

from worker.cli import cli


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


def test_cli_history_and_show(tmp_path, monkeypatch):
    db_path = str(tmp_path / "test.db")
    monkeypatch.setenv("CACHE_DB_PATH", db_path)

    from worker.models import EnrichedThreat, JapanRelevance, Severity, SourceType, ThreatItem
    from worker.storage.cache import ThreatCache

    cache = ThreatCache(db_path)
    item = ThreatItem.create(
        source_type=SourceType.VENDOR_RSS,
        source_name="JPCERT/CC",
        title="Critical Japan Alert",
        url="https://jpcert.or.jp/alert/1",
        summary="Detailed alert summary",
    )
    enriched = EnrichedThreat(
        item_id=item.id,
        item=item,
        severity=Severity.CRITICAL,
        japan_relevance=JapanRelevance.DIRECT,
        title_ja="緊急アラート",
        summary_ja="要約",
        impact_analysis_ja="影響大",
    )
    cache.mark_seen(item, enriched=enriched, notified=True)

    runner = CliRunner()
    # Test history
    res_hist = runner.invoke(cli, ["history"])
    assert res_hist.exit_code == 0
    assert "Critical Japan Alert" in res_hist.output

    # Test show
    res_show = runner.invoke(cli, ["show", item.id[:8]])
    assert res_show.exit_code == 0
    assert "Detailed alert summary" in res_show.output
