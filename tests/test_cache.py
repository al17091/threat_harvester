from src.models import EnrichedThreat, JapanRelevance, Severity, SourceType, ThreatItem
from src.storage.cache import ThreatCache


def test_cache_deduplication(tmp_path):
    db_file = str(tmp_path / "test_cache.db")
    cache = ThreatCache(db_path=db_file)

    item = ThreatItem.create(
        source_type=SourceType.VENDOR_RSS,
        source_name="IPA",
        title="Sample Advisory",
        url="https://ipa.go.jp/test",
        summary="Sample",
    )

    assert not cache.is_seen(item.id)

    enriched = EnrichedThreat(
        item_id=item.id,
        item=item,
        severity=Severity.HIGH,
        japan_relevance=JapanRelevance.DIRECT,
        title_ja="サンプルアドバイザリ",
        summary_ja="要約",
        impact_analysis_ja="影響大",
    )

    cache.mark_seen(item, enriched=enriched, notified=True)
    assert cache.is_seen(item.id)

    stats = cache.get_stats()
    assert stats["total_items"] == 1
    assert stats["notified_items"] == 1
    assert stats["japan_direct_items"] == 1
