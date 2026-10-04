import logging
import os
import sys
from datetime import datetime, timedelta, timezone

import click
from tabulate import tabulate

from src.config import settings
from src.harvesters.darkweb_onion import DarkwebOnionHarvester
from src.harvesters.telegram import TelegramHarvester
from src.harvesters.vendor_rss import VendorRSSHarvester
from src.harvesters.web_search import WebSearchHarvester
from src.harvesters.x_monitor import XMonitorHarvester
from src.models import EnrichedThreat, JapanRelevance, Severity, SourceType, ThreatItem
from src.notifiers import NotificationManager
from src.pipeline import HarvesterPipeline
from src.reporters.notion_reporter import NotionReporter
from src.storage.cache import ThreatCache

# Setup console logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)


@click.group()
def cli():
    """Threat Information Harvester - Japan CTI Operations CLI"""


@cli.command("run")
@click.option("--hours", default=1, help="Lookback interval in hours (default: 1)")
@click.option("--direct-only", is_flag=True, help="Only notify if direct Japan target is confirmed")
def run_command(hours: int, direct_only: bool):
    """Run full harvesting cycle across all configured sources."""
    click.echo(f"[*] Starting harvest pipeline (lookback: {hours}h, direct_only: {direct_only})...")
    pipeline = HarvesterPipeline()
    summary = pipeline.run_all(lookback_hours=hours, notify_direct_only=direct_only)

    click.echo("\n" + "=" * 50)
    click.echo("[*] Harvesting Summary:")
    click.echo(f"  - Total Collected: {summary['total_harvested']}")
    click.echo(f"  - New Items:       {summary['new_items']}")
    click.echo(f"  - Analyzed by AI:  {summary['analyzed']}")
    click.echo(f"  - Notifications:   {summary['notified']}")
    click.echo("Source Breakdown:")
    for src, count in summary["source_breakdown"].items():
        click.echo(f"  - {src:15}: {count} items")
    click.echo("=" * 50)


@cli.command("status")
def status_command():
    """Check system health, Tor proxy connectivity, API keys, and cache statistics."""
    click.echo("[*] Checking Threat Harvester System Status...\n")

    cache = ThreatCache(settings.cache_db_path)
    stats = cache.get_stats()

    # Probing harvesters
    vendor_h = VendorRSSHarvester()
    web_h = WebSearchHarvester()
    tor_h = DarkwebOnionHarvester()
    tg_h = TelegramHarvester()
    x_h = XMonitorHarvester()

    status_data = [
        ["Gemini API Key", "Configured" if bool(settings.gemini_api_key) else "MISSING", "Required for AI Analysis"],
        ["Gemini Model", settings.gemini_model, ""],
        [
            "Discord Webhook",
            "Configured" if bool(settings.discord_webhook_url) else "MISSING (Dry-run only)",
            "Alerts sink",
        ],
        ["Slack Webhook", "Configured" if bool(settings.slack_webhook_url) else "OFF", "Alerts sink"],
        ["Generic Webhook", "Configured" if bool(settings.generic_webhook_url) else "OFF", "Alerts sink"],
        [
            "Notion Reporter",
            "Configured" if bool(settings.notion_api_key and settings.notion_database_id) else "OFF",
            f"DB: {settings.notion_database_id[:8]}..." if settings.notion_database_id else "No DB",
        ],
        ["Tor SOCKS5 Proxy", "ONLINE" if tor_h.test_connection() else "OFFLINE", settings.tor_proxy_url],
        [
            "Gemini Web Search",
            "OK" if web_h.test_connection() else "NOT READY",
            f"{len(settings.web_search_queries)} queries",
        ],
        [
            "Vendor & CERT RSS",
            "OK" if vendor_h.test_connection() else "FAILED",
            f"{len(settings.vendor_feeds)} feeds configured",
        ],
        [
            "Telegram Harvester",
            "OK" if tg_h.test_connection() else "FAILED",
            f"{len(settings.telegram_channels)} channels",
        ],
        ["X (Twitter) Harvester", "OK" if x_h.test_connection() else "FAILED", "Grounded search ready"],
        ["Cache DB (SQLite)", f"{stats['total_items']} items", f"Path: {stats['db_path']}"],
    ]

    click.echo(tabulate(status_data, headers=["Component", "Status / Value", "Notes"], tablefmt="fancy_grid"))
    click.echo(
        f"\nCache Stats: Total Seen={stats['total_items']} | Notified={stats['notified_items']} | Japan Direct={stats['japan_direct_items']}"
    )


@cli.command("test")
@click.option(
    "--source",
    type=click.Choice(["vendor", "web", "tor", "telegram", "x", "all"], case_sensitive=False),
    required=True,
    help="Target source to test",
)
@click.option("--hours", default=24, help="Lookback interval in hours (default: 24)")
def test_source_command(source: str, hours: int):
    """Test a specific harvester source and print preview of items."""
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    click.echo(f"[*] Testing source '{source}' with lookback of {hours} hours...")

    harvester_map = {
        "vendor": VendorRSSHarvester(),
        "web": WebSearchHarvester(),
        "tor": DarkwebOnionHarvester(),
        "telegram": TelegramHarvester(),
        "x": XMonitorHarvester(),
    }

    targets = harvester_map.keys() if source == "all" else [source]

    for tgt in targets:
        h = harvester_map[tgt]
        click.echo(f"\n--- Running: {h.name} ---")
        items = h.harvest(since=since)
        click.echo(f"Harvested {len(items)} items from {h.name}")

        for i, item in enumerate(items[:5], 1):
            click.echo(f"\n[{i}] {item.title}")
            click.echo(f"    Source: {item.source_name} | Published: {item.published_at}")
            click.echo(f"    URL:    {item.url}")
            click.echo(f"    Summary: {item.summary[:140]}...")


@cli.command("search")
@click.argument("query")
def search_command(query: str):
    """Execute ad-hoc threat search using Gemini Search Grounding."""
    click.echo(f"[*] Querying Gemini Web Search for: '{query}'...")
    if not settings.gemini_api_key:
        click.echo("[!] Error: GEMINI_API_KEY is not configured.", err=True)
        sys.exit(1)

    harvester = WebSearchHarvester()
    # Temporarily override queries
    original_queries = settings.web_search_queries
    settings.web_search_queries = [query]
    try:
        items = harvester.harvest()
        click.echo(f"\nFound {len(items)} results:")
        for idx, item in enumerate(items, 1):
            click.echo(f"\n[{idx}] {item.title}")
            click.echo(f"    URL:     {item.url}")
            click.echo(f"    Victim:  {item.metadata.get('victim')}")
            click.echo(f"    Summary: {item.summary}")
    finally:
        settings.web_search_queries = original_queries


@cli.command("test-onion")
@click.argument("url")
def test_onion_command(url: str):
    """Test connecting to a specific .onion or HTTP URL via the Tor proxy."""
    click.echo(f"[*] Testing connection to '{url}' through Tor proxy ({settings.tor_proxy_url})...")
    harvester = DarkwebOnionHarvester()
    try:
        session = harvester._get_tor_session()
        resp = session.get(url, timeout=30)
        click.echo(f"[+] Response Status: {resp.status_code}")
        click.echo(f"[+] Content-Type: {resp.headers.get('content-type')}")
        click.echo(f"[+] Preview:\n{resp.text[:500]}...")
    except Exception as e:
        click.echo(f"[!] Error fetching {url} through Tor: {e}", err=True)


@cli.command("history")
@click.option("--limit", default=20, help="Number of items to show (default: 20)")
@click.option("--japan-only", is_flag=True, help="Only show items targeting Japan directly")
@click.option("--db", default=None, help="Custom SQLite cache database path")
def history_command(limit: int, japan_only: bool, db: str | None):
    """View collected threat items from the database cache."""
    db_path = db or os.getenv("CACHE_DB_PATH", settings.cache_db_path)
    cache = ThreatCache(db_path)
    rows = cache.get_history(limit=limit, japan_only=japan_only)

    if not rows:
        click.echo("No threat intelligence records found in cache.")
        return

    table_data = []
    for r in rows:
        item_id = r["id"][:8]
        src = f"{r['source_type']} ({r['source_name'][:12]})"
        title = r["title"][:50]
        sev = r.get("severity") or "-"
        jp = r.get("japan_relevance") or "-"
        notified = "Yes" if r.get("notified_at") else "No"
        table_data.append([item_id, src, sev, jp, notified, title])

    headers = ["ID", "Source", "Severity", "Japan Rel", "Notified", "Title"]
    click.echo(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
    click.echo(f"\nShowing {len(rows)} items (use 'harvester show <id>' for details)")


@cli.command("show")
@click.argument("item_id")
@click.option("--db", default=None, help="Custom SQLite cache database path")
def show_command(item_id: str, db: str | None):
    """Show detailed view of a specific threat record by ID."""
    db_path = db or os.getenv("CACHE_DB_PATH", settings.cache_db_path)
    cache = ThreatCache(db_path)
    # Search by prefix or exact ID
    with cache._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM threat_items WHERE id LIKE ?", (f"{item_id}%",))
        row = cursor.fetchone()

    if not row:
        click.echo(f"[!] Threat item not found matching ID '{item_id}'", err=True)
        return

    data = dict(row)
    click.echo("\n" + "=" * 60)
    click.echo(f"ID:              {data['id']}")
    click.echo(f"Source:          {data['source_type']} ({data['source_name']})")
    click.echo(f"Title:           {data['title']}")
    click.echo(f"URL:             {data.get('url') or 'N/A'}")
    click.echo(f"Severity:        {data.get('severity') or 'Unknown'}")
    click.echo(f"Japan Relevance: {data.get('japan_relevance') or 'Unknown'}")
    click.echo(f"Harvested At:    {data['harvested_at']}")
    click.echo(f"Notified:        {data.get('notified_at') or 'No'}")
    click.echo("-" * 60)
    click.echo("Summary / Content:")
    click.echo(data.get("summary", ""))
    click.echo("=" * 60 + "\n")


@cli.command("test-notify")
def test_notify_command():
    """Send a mock Critical Japan-targeted threat alert to all configured Webhooks."""
    click.echo("[*] Dispatching mock threat alert to configured Webhooks...")
    item = ThreatItem.create(
        source_type=SourceType.VENDOR_RSS,
        source_name="JPCERT/CC (Test)",
        title="[TEST ALERT] 国内重要インフラを標的としたゼロデイ脆弱性の悪用確認",
        url="https://www.jpcert.or.jp",
        summary="これは通知テスト用のモックデータです。国内組織への標的型サイバー攻撃に関する緊急警告。",
    )
    enriched = EnrichedThreat(
        item_id=item.id,
        item=item,
        severity=Severity.CRITICAL,
        japan_relevance=JapanRelevance.DIRECT,
        title_ja="[テスト] 国内重要インフラを標的としたゼロデイ悪用注意喚起",
        summary_ja="国内の重要通信網および製造拠点を標的とした未パッチのゼロデイ脆弱性の悪用が観測されました。直ちに該当サービスの停止またはアクセス制御を実施してください。",
        impact_analysis_ja="国内大手通信キャリアおよび重要製造ラインへの広範な影響が懸念されます。",
        victim_orgs=["国内重要インフラ事業者 (仮)", "テスト製造株式会社"],
        threat_actors=["Volt Typhoon (仮)"],
        attack_type="Zero-day",
        recommended_actions_ja=[
            "該当外部公開ポートの即時遮断",
            "EDRによる不審なPowerShell/WMI実行の監査",
            "最新パッチの緊急適用検証",
        ],
    )
    manager = NotificationManager()
    success = manager.dispatch(enriched)
    if success:
        click.echo("[+] Successfully dispatched test notification.")
    else:
        click.echo("[!] Failed to dispatch test notification. Check webhook URLs.", err=True)


@cli.command("test-notion")
def test_notion_command():
    """Publish a mock Critical threat intelligence page to the configured Notion Database."""
    click.echo("[*] Publishing mock threat intelligence page to Notion...")
    reporter = NotionReporter()
    if not reporter.is_configured:
        click.echo("[!] Error: NOTION_API_KEY and NOTION_DATABASE_ID must be set in environment.", err=True)
        sys.exit(1)

    item = ThreatItem.create(
        source_type=SourceType.DARKWEB_ONION,
        source_name="LockBit DLS (Test)",
        title="[TEST CTI] LockBit published data of Japan Org",
        url="https://example.com/test-lockbit",
        summary="テスト用ダークウェブリークサイト掲載インシデントデータ。",
    )
    enriched = EnrichedThreat(
        item_id=item.id,
        item=item,
        severity=Severity.HIGH,
        japan_relevance=JapanRelevance.DIRECT,
        title_ja="[テスト] ランサムウェアグループによる国内組織データ漏洩告知",
        summary_ja="LockBitリークサイト上に国内組織の内部文書および顧客情報とされるアーカイブが公開されました。",
        impact_analysis_ja="個人情報漏洩および取引先情報流出による事業継続リスク。",
        victim_orgs=["テスト情報システム株式会社"],
        threat_actors=["LockBit 3.0"],
        attack_type="Ransomware",
        recommended_actions_ja=[
            "漏洩データの同一性確認と影響範囲の特定",
            "個人情報保護委員会への速報対応",
            "二重恐喝への連絡遮断とフォレンジック調査の着手",
        ],
    )
    res = reporter.create_page(enriched)
    if res:
        click.echo(f"[+] Successfully created page in Notion! Page ID: {res.get('id')}")
        click.echo(f"[+] Notion Page URL: {res.get('url')}")
    else:
        click.echo("[!] Failed to create page in Notion. Check API key and database permissions.", err=True)


if __name__ == "__main__":
    cli()
