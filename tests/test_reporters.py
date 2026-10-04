from unittest.mock import MagicMock

from backend.models import EnrichedThreat, JapanRelevance, Severity, SourceType, ThreatItem
from backend.reporters.notion_reporter import NotionReporter


def test_notion_reporter_unconfigured():
    reporter = NotionReporter(api_key="", database_id="")
    assert not reporter.is_configured
    item = ThreatItem.create(
        source_type=SourceType.VENDOR_RSS,
        source_name="JPCERT",
        title="Test",
        url="https://example.com",
        summary="Test summary",
    )
    enriched = EnrichedThreat(
        item_id=item.id,
        item=item,
        severity=Severity.HIGH,
        japan_relevance=JapanRelevance.DIRECT,
        title_ja="テスト",
        summary_ja="要約",
        impact_analysis_ja="影響",
    )
    result = reporter.create_page(enriched)
    assert result is None


def test_notion_reporter_mock(monkeypatch):
    reporter = NotionReporter(api_key="secret_test", database_id="db_123")
    assert reporter.is_configured

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"id": "page_456", "url": "https://notion.so/page_456"}

    monkeypatch.setattr("requests.post", lambda url, headers, json, timeout: mock_resp)

    item = ThreatItem.create(
        source_type=SourceType.DARKWEB_ONION,
        source_name="LockBit",
        title="Victim: Corp",
        url="http://onion.test",
        summary="Summary test",
    )
    enriched = EnrichedThreat(
        item_id=item.id,
        item=item,
        severity=Severity.CRITICAL,
        japan_relevance=JapanRelevance.DIRECT,
        title_ja="国内大手へのランサムウェア",
        summary_ja="要約テスト",
        impact_analysis_ja="国内影響大",
        victim_orgs=["被害企業A"],
        threat_actors=["LockBit 3.0"],
        attack_type="Ransomware",
        recommended_actions_ja=["ネットワーク隔離"],
    )

    result = reporter.create_page(enriched)
    assert result is not None
    assert result["id"] == "page_456"
