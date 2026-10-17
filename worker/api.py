import logging
import os
from datetime import datetime, timezone
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from worker.config import settings
from worker.harvesters.darkweb_onion import DarkwebOnionHarvester
from worker.models import EnrichedThreat, JapanRelevance, Severity, SourceType, ThreatItem
from worker.notifiers import NotificationManager
from worker.pipeline import HarvesterPipeline
from worker.reporters.notion_reporter import NotionReporter
from worker.storage.cache import ThreatCache

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Threat Information Harvester Dashboard",
    description="Cyber Threat Intelligence monitoring platform specialized for Japan-targeted threats.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global pipeline run state
pipeline_state = {
    "is_running": False,
    "last_run_at": None,
    "last_summary": None,
}


def get_cache() -> ThreatCache:
    """Return configured ThreatCache instance."""
    db_path = os.getenv("CACHE_DB_PATH", settings.cache_db_path)
    db_url = os.getenv("DATABASE_URL", settings.database_url)
    return ThreatCache(
        db_path=db_path,
        database_url=db_url,
    )


# --- API Models ---


class SourceActionRequest(BaseModel):
    source_type: str  # vendor_rss, telegram, darkweb_onion, x_monitor, web_search
    action: str  # add, toggle, delete
    data: dict[str, Any] = {}
    identifier: str = ""
    enabled: bool = True


# --- API Endpoints ---


@app.head("/")
@app.get("/")
async def root():
    """Return API status and metadata."""
    return {
        "service": "Threat Information Harvester API",
        "version": "1.0.0",
        "status": "healthy",
        "docs": "/docs",
    }


# --- Health & Status Endpoints ---


@app.get("/api/status")
async def get_system_status():
    """Retrieve system health, database metrics, proxy status, and source counts."""
    cache = get_cache()
    db_stats = cache.get_stats()

    # Tor proxy quick check
    tor_h = DarkwebOnionHarvester()
    tor_online = tor_h.test_connection()

    # Sources breakdown
    total_rss = len(settings.app_config.sources.vendor_rss)
    active_rss = len([f for f in settings.app_config.sources.vendor_rss if f.enabled])

    total_tg = len(settings.app_config.sources.telegram)
    active_tg = len([c for c in settings.app_config.sources.telegram if c.enabled])

    total_dw = len(settings.app_config.sources.darkweb_onion)
    active_dw = len([d for d in settings.app_config.sources.darkweb_onion if d.enabled])

    total_x = len(settings.app_config.sources.x_monitor)
    active_x = len([q for q in settings.app_config.sources.x_monitor if q.enabled])

    total_web = len(settings.app_config.sources.web_search)
    active_web = len([q for q in settings.app_config.sources.web_search if q.enabled])

    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": db_stats,
        "tor_proxy": {
            "online": tor_online,
            "url": settings.tor_proxy_url,
        },
        "ai": {
            "configured": bool(settings.gemini_api_key),
            "model": settings.gemini_model,
        },
        "sinks": {
            "discord": bool(settings.discord_webhook_url),
            "slack": bool(settings.slack_webhook_url),
            "generic_webhook": bool(settings.generic_webhook_url),
            "notion": bool(settings.notion_api_key and settings.notion_database_id),
        },
        "sources": {
            "vendor_rss": {"total": total_rss, "active": active_rss},
            "telegram": {"total": total_tg, "active": active_tg},
            "darkweb_onion": {"total": total_dw, "active": active_dw},
            "x_monitor": {"total": total_x, "active": active_x},
            "web_search": {"total": total_web, "active": active_web},
            "total_active": active_rss + active_tg + active_dw + active_x + active_web,
        },
        "pipeline": pipeline_state,
    }


# --- Incidents API ---


@app.get("/api/incidents")
async def list_incidents(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    japan_only: bool = Query(False),
    severity: str | None = Query(None),
    source_type: str | None = Query(None),
    search: str | None = Query(None),
):
    """Retrieve collected incidents with filtering options."""
    cache = get_cache()
    incidents = cache.get_history(
        limit=limit,
        offset=offset,
        japan_only=japan_only,
        severity=severity,
        source_type=source_type,
        search=search,
    )
    return {
        "count": len(incidents),
        "limit": limit,
        "offset": offset,
        "items": incidents,
    }


@app.get("/api/incidents/{item_id}")
async def get_incident(item_id: str):
    """Retrieve single incident details."""
    cache = get_cache()
    item = cache.get_item(item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Incident not found")
    return item


# --- Configuration Management & Export API ---


@app.get("/api/config")
async def get_config():
    """Retrieve safe configuration representation (masked sensitive secrets)."""
    return settings.to_safe_dict()


@app.get("/api/config/raw")
async def get_raw_config():
    """Retrieve unmasked configuration for full inspection."""
    return settings.app_config.model_dump()


@app.get("/api/config/export")
async def export_config(mask_secrets: bool = Query(False)):
    """Download current configuration as YAML file."""
    yaml_text = settings.export_yaml(mask_secrets=mask_secrets)
    return Response(
        content=yaml_text,
        media_type="application/x-yaml",
        headers={
            "Content-Disposition": 'attachment; filename="config.yaml"',
        },
    )


@app.post("/api/config/save")
async def save_config_file():
    """Save the active in-memory configuration back to config.yaml on disk."""
    try:
        settings.save()
        return {"status": "ok", "message": f"Saved configuration to {settings.config_path}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/config/sources")
async def manage_source(req: SourceActionRequest):
    """Add, toggle, or delete a threat collection source."""
    try:
        if req.action == "add":
            settings.add_source(req.source_type, req.data)
            return {"status": "ok", "message": f"Source added to {req.source_type}"}
        elif req.action == "toggle":
            identifier = req.identifier or req.data.get("url") or req.data.get("name") or req.data.get("channel") or req.data.get("query")
            if not identifier:
                raise HTTPException(status_code=400, detail="Missing identifier for toggle")
            success = settings.toggle_source(req.source_type, identifier, req.enabled)
            if not success:
                raise HTTPException(status_code=404, detail="Source not found")
            return {"status": "ok", "message": f"Source status updated to {req.enabled}"}
        elif req.action == "delete":
            identifier = req.identifier or req.data.get("url") or req.data.get("name") or req.data.get("channel") or req.data.get("query")
            if not identifier:
                raise HTTPException(status_code=400, detail="Missing identifier for delete")
            success = settings.delete_source(req.source_type, identifier)
            if not success:
                raise HTTPException(status_code=404, detail="Source not found")
            return {"status": "ok", "message": "Source deleted"}
        else:
            raise HTTPException(status_code=400, detail=f"Invalid action: {req.action}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# --- Pipeline Execution & Testing Endpoints ---


def _run_harvest_task():
    global pipeline_state
    pipeline_state["is_running"] = True
    try:
        pipeline = HarvesterPipeline()
        summary = pipeline.run_all(
            lookback_hours=settings.check_interval_hours,
            notify_direct_only=settings.app_config.pipeline.notify_direct_only,
        )
        pipeline_state["last_summary"] = summary
        pipeline_state["last_run_at"] = datetime.now(timezone.utc).isoformat()
    except Exception as e:
        logger.error(f"Harvest execution failed: {e}", exc_info=True)
        pipeline_state["last_summary"] = {"error": str(e)}
    finally:
        pipeline_state["is_running"] = False


@app.post("/api/pipeline/run")
async def trigger_harvest(background_tasks: BackgroundTasks):
    """Trigger threat harvesting across enabled sources in the background."""
    if pipeline_state["is_running"]:
        return {"status": "already_running", "message": "A harvest job is already in progress"}

    background_tasks.add_task(_run_harvest_task)
    return {"status": "started", "message": "Harvest pipeline started in background"}


@app.post("/api/test/notify")
async def trigger_test_notification():
    """Send a mock threat notification to all enabled Webhook sinks."""
    item = ThreatItem.create(
        source_type=SourceType.VENDOR_RSS,
        source_name="JPCERT/CC (GUI Test)",
        title="[TEST ALERT] 国内組織を標的としたサイバー攻撃インシデント検知テスト",
        url="https://www.jpcert.or.jp",
        summary="これはダッシュボードからのWebHook通知テストです。正常に配信されました。",
    )
    enriched = EnrichedThreat(
        item_id=item.id,
        item=item,
        severity=Severity.HIGH,
        japan_relevance=JapanRelevance.DIRECT,
        title_ja="【GUIテスト】国内重要組織を標的とした攻撃アラート",
        summary_ja="ダッシュボード管理画面からの通知疎通テストです。",
        impact_analysis_ja="通知システムの正常稼働を確認しました。",
        victim_orgs=["テスト対象企業"],
        threat_actors=["Simulated Adversary"],
        recommended_actions_ja=["本通知が受信できたことを確認してください。"],
    )

    notifier = NotificationManager()
    success = notifier.notify(enriched)
    return {"status": "sent", "dispatched": success}


@app.post("/api/test/notion")
async def trigger_test_notion():
    """Create a mock incident page in the configured Notion database."""
    item = ThreatItem.create(
        source_type=SourceType.VENDOR_RSS,
        source_name="JPCERT/CC (Notion Test)",
        title="[TEST NOTION] 脅威情報データベース連携テスト",
        url="https://www.jpcert.or.jp",
        summary="これはNotionデータベース連携の検証データです。",
    )
    enriched = EnrichedThreat(
        item_id=item.id,
        item=item,
        severity=Severity.CRITICAL,
        japan_relevance=JapanRelevance.DIRECT,
        title_ja="【Notion連携テスト】国内組織向け脅威レポート同期",
        summary_ja="ダッシュボードからのNotion API接続確認用レコードです。",
        impact_analysis_ja="データベースへの書き込み権限とプロパティ構成を確認中。",
        victim_orgs=["検証用企業"],
        threat_actors=["Test Actor"],
        recommended_actions_ja=["Notionデータベースに本ページが作成されたことを確認する。"],
    )

    reporter = NotionReporter()
    page_id = reporter.create_incident_page(enriched)
    if not page_id:
        raise HTTPException(status_code=500, detail="Failed to create Notion page. Check API key and database ID.")
    return {"status": "created", "page_id": page_id}
