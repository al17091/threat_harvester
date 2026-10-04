import logging
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
from src.pipeline import HarvesterPipeline
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
        ["Discord Webhook", "Configured" if bool(settings.discord_webhook_url) else "MISSING (Dry-run only)", "Alerts sink"],
        ["Tor SOCKS5 Proxy", "ONLINE" if tor_h.test_connection() else "OFFLINE", settings.tor_proxy_url],
        ["Gemini Web Search", "OK" if web_h.test_connection() else "NOT READY", f"{len(settings.web_search_queries)} queries"],
        ["Vendor & CERT RSS", "OK" if vendor_h.test_connection() else "FAILED", f"{len(settings.vendor_feeds)} feeds configured"],
        ["Telegram Harvester", "OK" if tg_h.test_connection() else "FAILED", f"{len(settings.telegram_channels)} channels"],
        ["X (Twitter) Harvester", "OK" if x_h.test_connection() else "FAILED", "Grounded search ready"],
        ["Cache DB (SQLite)", f"{stats['total_items']} items", f"Path: {stats['db_path']}"],
    ]

    click.echo(tabulate(status_data, headers=["Component", "Status / Value", "Notes"], tablefmt="fancy_grid"))
    click.echo(f"\nCache Stats: Total Seen={stats['total_items']} | Notified={stats['notified_items']} | Japan Direct={stats['japan_direct_items']}")


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


if __name__ == "__main__":
    cli()
