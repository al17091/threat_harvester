from unittest.mock import MagicMock

from worker.analyzer.gemini_analyzer import GeminiThreatAnalyzer
from worker.models import JapanRelevance, Severity, SourceType, ThreatItem


def test_gemini_analyzer_mock(monkeypatch):
    analyzer = GeminiThreatAnalyzer(api_key="mock_key")

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = """{
        "severity": "Critical",
        "japan_relevance": "Direct",
        "title_ja": "国内大手製造業へのランサムウェア攻撃",
        "summary_ja": "LockBitにより国内工場の生産システムが暗号化されました。",
        "impact_analysis_ja": "サプライチェーン停止の恐れあり",
        "victim_orgs": ["テスト株式会社"],
        "threat_actors": ["LockBit 3.0"],
        "attack_type": "Ransomware",
        "recommended_actions_ja": ["端末の隔離", "Active Directoryパスワードリセット"]
    }"""
    mock_client.models.generate_content.return_value = mock_response
    analyzer.client = mock_client

    item = ThreatItem.create(
        source_type=SourceType.DARKWEB_ONION,
        source_name="LockBit DLS",
        title="Victim: Test Co Ltd",
        url="http://lockbit.onion/test",
        summary="LockBit published files from Test Co Ltd in Japan",
    )

    enriched = analyzer.analyze(item)
    assert enriched is not None
    assert enriched.severity == Severity.CRITICAL
    assert enriched.japan_relevance == JapanRelevance.DIRECT
    assert "国内大手製造業" in enriched.title_ja
    assert enriched.victim_orgs == ["テスト株式会社"]
    assert enriched.threat_actors == ["LockBit 3.0"]
