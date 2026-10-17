from fastapi.testclient import TestClient

from backend.api import app
from backend.models import EnrichedThreat, JapanRelevance, Severity, SourceType, ThreatItem
from backend.storage.cache import ThreatCache

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "Threat Information Harvester API" in data["service"]


def test_api_status(tmp_path, monkeypatch):
    db_file = str(tmp_path / "status_test.db")
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.setenv("DB_HOST", "")
    monkeypatch.setenv("CACHE_DB_PATH", db_file)
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "database" in data
    assert "tor_proxy" in data
    assert "sources" in data


def test_api_incidents(tmp_path, monkeypatch):
    db_file = str(tmp_path / "web_test.db")
    monkeypatch.setenv("DATABASE_URL", "")
    monkeypatch.setenv("DB_HOST", "")
    monkeypatch.setenv("CACHE_DB_PATH", db_file)

    cache = ThreatCache(db_path=db_file)
    item = ThreatItem.create(
        source_type=SourceType.VENDOR_RSS,
        source_name="JPCERT/CC",
        title="Sample Web Alert",
        url="https://jpcert.or.jp/web/1",
        summary="Test web summary",
    )
    enriched = EnrichedThreat(
        item_id=item.id,
        item=item,
        severity=Severity.HIGH,
        japan_relevance=JapanRelevance.DIRECT,
        title_ja="ウェブアラートテスト",
        summary_ja="要約テスト",
        impact_analysis_ja="影響テスト",
        victim_orgs=["組織A"],
    )
    cache.mark_seen(item, enriched=enriched, notified=True)

    # Test list
    res = client.get("/api/incidents")
    assert res.status_code == 200
    data = res.json()
    assert data["count"] >= 1
    assert any(i["title"] == "Sample Web Alert" for i in data["items"])

    # Test get single
    res_single = client.get(f"/api/incidents/{item.id}")
    assert res_single.status_code == 200
    single = res_single.json()
    assert single["title"] == "Sample Web Alert"
    assert single["enriched_parsed"]["victim_orgs"] == ["組織A"]


def test_api_config_export_and_manage(tmp_path, monkeypatch):
    test_yaml = str(tmp_path / "web_config.yaml")
    monkeypatch.setenv("CONFIG_PATH", test_yaml)

    # Test GET /api/config
    res_cfg = client.get("/api/config")
    assert res_cfg.status_code == 200
    cfg = res_cfg.json()
    assert "sources" in cfg
    assert "database" in cfg

    # Test POST /api/config/sources (add)
    add_payload = {
        "source_type": "telegram",
        "action": "add",
        "data": {"channel": "unit_test_chan", "enabled": True},
    }
    res_add = client.post("/api/config/sources", json=add_payload)
    assert res_add.status_code == 200

    # Test toggle
    toggle_payload = {
        "source_type": "telegram",
        "action": "toggle",
        "identifier": "unit_test_chan",
        "enabled": False,
    }
    res_toggle = client.post("/api/config/sources", json=toggle_payload)
    assert res_toggle.status_code == 200

    # Test export
    res_export = client.get("/api/config/export")
    assert res_export.status_code == 200
    assert 'attachment; filename="config.yaml"' in res_export.headers.get("content-disposition", "")
    assert "unit_test_chan" in res_export.text

    # Test save
    res_save = client.post("/api/config/save")
    assert res_save.status_code == 200

    # Test delete
    del_payload = {
        "source_type": "telegram",
        "action": "delete",
        "identifier": "unit_test_chan",
    }
    res_del = client.post("/api/config/sources", json=del_payload)
    assert res_del.status_code == 200
