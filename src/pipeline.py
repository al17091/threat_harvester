import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from src.analyzer.gemini_analyzer import GeminiThreatAnalyzer
from src.config import settings
from src.harvesters.darkweb_onion import DarkwebOnionHarvester
from src.harvesters.telegram import TelegramHarvester
from src.harvesters.vendor_rss import VendorRSSHarvester
from src.harvesters.web_search import WebSearchHarvester
from src.harvesters.x_monitor import XMonitorHarvester
from src.models import EnrichedThreat, JapanRelevance, Severity, SourceType, ThreatItem
from src.notifiers.discord import DiscordNotifier
from src.storage.cache import ThreatCache

logger = logging.getLogger(__name__)


class HarvesterPipeline:
    """Orchestrates threat harvesting, deduplication, Gemini enrichment, and notifications."""

    def __init__(
        self,
        cache: ThreatCache | None = None,
        analyzer: GeminiThreatAnalyzer | None = None,
        notifier: DiscordNotifier | None = None,
    ):
        self.cache = cache or ThreatCache(settings.cache_db_path)
        self.analyzer = analyzer or GeminiThreatAnalyzer()
        self.notifier = notifier or DiscordNotifier()

        # Registered harvesters
        self.harvesters = {
            SourceType.VENDOR_RSS: VendorRSSHarvester(),
            SourceType.WEB_SEARCH: WebSearchHarvester(),
            SourceType.DARKWEB_ONION: DarkwebOnionHarvester(),
            SourceType.TELEGRAM: TelegramHarvester(),
            SourceType.X_MONITOR: XMonitorHarvester(),
        }

    def run_all(
        self,
        lookback_hours: int | None = None,
        notify_direct_only: bool = False,
    ) -> dict[str, Any]:
        """Execute full harvesting cycle across all sources."""
        hours = lookback_hours or settings.check_interval_hours
        # Add 15 min buffer to prevent missing edge items
        since = datetime.now(timezone.utc) - timedelta(hours=hours, minutes=15)

        logger.info(f"=== Starting threat collection cycle (lookback: {hours}h, since: {since}) ===")

        all_items: list[ThreatItem] = []
        source_counts: dict[str, int] = {}

        for stype, harvester in self.harvesters.items():
            try:
                logger.info(f"Running harvester: {harvester.name}")
                items = harvester.harvest(since=since)
                source_counts[stype.value] = len(items)
                all_items.extend(items)
            except Exception as e:
                logger.error(f"Harvester '{harvester.name}' encountered unhandled error: {e}")
                source_counts[stype.value] = 0

        # Deduplication
        new_items: list[ThreatItem] = []
        for item in all_items:
            if not self.cache.is_seen(item.id):
                new_items.append(item)
            else:
                logger.debug(f"Skipping already seen item: {item.title}")

        logger.info(f"Collected total: {len(all_items)}, New unique items to analyze: {len(new_items)}")

        enriched_list: list[EnrichedThreat] = []
        notified_count = 0

        for item in new_items:
            try:
                enriched = self.analyzer.analyze(item)
                if not enriched:
                    continue

                enriched_list.append(enriched)

                # Determine notification criteria:
                # 1. Any direct Japan attack with Medium/High/Critical
                # 2. Any Critical incident (even indirect)
                # 3. High severity indirect incident if not notify_direct_only
                should_notify = False
                if enriched.japan_relevance == JapanRelevance.DIRECT and enriched.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM) or enriched.severity == Severity.CRITICAL or not notify_direct_only and enriched.severity == Severity.HIGH and enriched.japan_relevance == JapanRelevance.INDIRECT:
                    should_notify = True

                notified = False
                if should_notify:
                    logger.info(f"Alerting on threat: [{enriched.severity.value}] [{enriched.japan_relevance.value}] {enriched.title_ja}")
                    notified = self.notifier.notify(enriched)
                    if notified:
                        notified_count += 1

                # Record in persistent cache
                self.cache.mark_seen(item, enriched=enriched, notified=notified)

            except Exception as e:
                logger.error(f"Error processing item '{item.title}': {e}")

        summary = {
            "total_harvested": len(all_items),
            "new_items": len(new_items),
            "analyzed": len(enriched_list),
            "notified": notified_count,
            "source_breakdown": source_counts,
        }
        logger.info(f"=== Harvesting cycle complete: {summary} ===")
        return summary
