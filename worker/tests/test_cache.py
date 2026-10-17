from worker.models import EnrichedThreat, JapanRelevance, Severity, SourceType, ThreatItem
from worker.storage.cache import ThreatCache


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
    assert stats["backend"] == "sqlite"


def test_cache_filters_and_item(tmp_path):
    db_file = str(tmp_path / "test_filter.db")
    cache = ThreatCache(db_path=db_file)

    item1 = ThreatItem.create(
        source_type=SourceType.VENDOR_RSS,
        source_name="IPA",
        title="Critical Vulnerability",
        url="https://example.com/1",
        summary="Urgent patch required",
    )
    enriched1 = EnrichedThreat(
        item_id=item1.id,
        item=item1,
        severity=Severity.CRITICAL,
        japan_relevance=JapanRelevance.DIRECT,
        title_ja="重大な脆弱性",
        summary_ja="緊急パッチ",
        impact_analysis_ja="高影響",
    )
    cache.mark_seen(item1, enriched=enriched1)

    item2 = ThreatItem.create(
        source_type=SourceType.DARKWEB_ONION,
        source_name="Ransomlook",
        title="Foreign leak",
        url="https://example.com/2",
        summary="Global leak without JP relevance",
    )
    enriched2 = EnrichedThreat(
        item_id=item2.id,
        item=item2,
        severity=Severity.LOW,
        japan_relevance=JapanRelevance.NONE,
        title_ja="海外リーク",
        summary_ja="国内影響なし",
        impact_analysis_ja="低影響",
    )
    cache.mark_seen(item2, enriched=enriched2)

    # Test filtering by japan_only
    jp_items = cache.get_history(japan_only=True)
    assert len(jp_items) == 1
    assert jp_items[0]["id"] == item1.id
    assert jp_items[0]["enriched_parsed"]["title_ja"] == "重大な脆弱性"

    # Test filtering by severity
    crit_items = cache.get_history(severity="Critical")
    assert len(crit_items) == 1
    assert crit_items[0]["id"] == item1.id

    # Test search query
    searched = cache.get_history(search="Ransomlook")
    assert len(searched) == 1
    assert searched[0]["id"] == item2.id

    # Test get_item
    single = cache.get_item(item1.id)
    assert single is not None
    assert single["title"] == "Critical Vulnerability"


def test_cache_postgres_url_resolution(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgres://user:pass@postgres-rw:5432/threatdb")
    cache = ThreatCache.__new__(ThreatCache)
    url = cache._resolve_database_url()
    assert url == "postgresql+psycopg://user:pass@postgres-rw:5432/threatdb"

    monkeypatch.delenv("DATABASE_URL")
    monkeypatch.setenv("DB_HOST", "cnpg-cluster-rw")
    monkeypatch.setenv("DB_USER", "harvester")
    monkeypatch.setenv("DB_PASSWORD", "secret")
    monkeypatch.setenv("DB_NAME", "harvester_db")
    url2 = cache._resolve_database_url()
    assert url2 == "postgresql+psycopg://harvester:secret@cnpg-cluster-rw:5432/harvester_db"
