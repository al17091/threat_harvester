import logging
from datetime import datetime, timezone

import feedparser
import requests
from dateutil import parser

from worker.config import FeedConfig, settings
from worker.harvesters.base import BaseHarvester
from worker.models import SourceType, ThreatItem

logger = logging.getLogger(__name__)

# US Timezones mapping for global feeds
TZ_INFOS = {
    "EST": -18000,
    "EDT": -14400,
    "CST": -21600,
    "CDT": -18000,
    "MST": -25200,
    "MDT": -21600,
    "PST": -28800,
    "PDT": -25200,
    "JST": 32400,
}


class VendorRSSHarvester(BaseHarvester):
    """Harvests advisories and breaking news from Security Vendors and CERT RSS/Atom feeds."""

    def __init__(self, feeds: list[FeedConfig] | None = None):
        super().__init__(name="Vendor & CERT RSS", source_type=SourceType.VENDOR_RSS)
        self.feeds = feeds or settings.vendor_feeds

    def _parse_published_date(self, entry) -> datetime | None:
        date_str = None
        for attr in ("published", "updated", "created", "dc_date"):
            if hasattr(entry, attr):
                date_str = getattr(entry, attr)
                break
        if not date_str and hasattr(entry, "published_parsed") and entry.published_parsed:
            try:
                import time

                return datetime.fromtimestamp(time.mktime(entry.published_parsed), tz=timezone.utc)
            except Exception:
                pass

        if not date_str:
            return None

        try:
            dt = parser.parse(date_str, tzinfos=TZ_INFOS)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception as e:
            logger.debug(f"Failed to parse date '{date_str}': {e}")
            return None

    def harvest(self, since: datetime | None = None) -> list[ThreatItem]:
        items: list[ThreatItem] = []
        headers = {"User-Agent": "ThreatHarvesterBot/1.0 (+https://github.com/al17091/threat_harvester)"}

        for feed_cfg in self.feeds:
            try:
                logger.info(f"Checking RSS feed: {feed_cfg.name} ({feed_cfg.url})")
                # Using requests with timeout to prevent hang
                resp = requests.get(feed_cfg.url, headers=headers, timeout=settings.request_timeout)
                resp.raise_for_status()
                feed = feedparser.parse(resp.content)

                if feed.bozo and not feed.entries:
                    logger.warning(f"Feed error for {feed_cfg.name}: {feed.bozo_exception}")
                    continue

                for entry in feed.entries:
                    try:
                        title = getattr(entry, "title", "No Title")
                        link = getattr(entry, "link", None)
                        summary = getattr(entry, "summary", getattr(entry, "description", ""))

                        published_at = self._parse_published_date(entry)

                        if since and published_at and published_at < since:
                            # Skip entries older than threshold
                            continue

                        item = ThreatItem.create(
                            source_type=self.source_type,
                            source_name=feed_cfg.name,
                            title=title,
                            url=link,
                            summary=summary,
                            published_at=published_at,
                            metadata={"category": feed_cfg.category},
                        )
                        items.append(item)
                    except Exception as entry_err:
                        logger.warning(f"Error parsing feed entry from {feed_cfg.name}: {entry_err}")
            except Exception as feed_err:
                logger.error(f"Failed to fetch feed {feed_cfg.name} ({feed_cfg.url}): {feed_err}")

        logger.info(f"VendorRSSHarvester collected {len(items)} items")
        return items

    def test_connection(self) -> bool:
        """Check if at least one feed is reachable."""
        for feed in self.feeds[:2]:
            try:
                resp = requests.head(feed.url, timeout=5, allow_redirects=True)
                if resp.status_code < 400:
                    return True
            except Exception:
                continue
        return False
