import logging
from datetime import datetime, timezone

import feedparser
import requests
from dateutil import parser

from backend.config import settings
from backend.harvesters.base import BaseHarvester
from backend.models import SourceType, ThreatItem

logger = logging.getLogger(__name__)


class DarkwebOnionHarvester(BaseHarvester):
    """Harvests ransomware leak sites (DLS) and darkweb feeds via Tor SOCKS5 proxy."""

    def __init__(self, tor_proxy_url: str | None = None):
        super().__init__(name="Dark Web (.onion) & Ransomware DLS", source_type=SourceType.DARKWEB_ONION)
        self.tor_proxy_url = tor_proxy_url or settings.tor_proxy_url

    def _get_tor_session(self) -> requests.Session:
        """Create a requests session routed through Tor SOCKS5 proxy."""
        session = requests.Session()
        session.proxies = {
            "http": self.tor_proxy_url,
            "https": self.tor_proxy_url,
        }
        session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )
        return session

    def test_connection(self) -> bool:
        """Test connection to Tor proxy (e.g. check torproject check endpoint)."""
        try:
            session = self._get_tor_session()
            resp = session.get("https://check.torproject.org/api/ip", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                is_tor = data.get("IsTor", False)
                logger.info(f"Tor connectivity test: IsTor={is_tor}, IP={data.get('IP')}")
                return is_tor
        except Exception as e:
            logger.warning(f"Tor SOCKS5 proxy ({self.tor_proxy_url}) check failed: {e}")
        return False

    def harvest(self, since: datetime | None = None) -> list[ThreatItem]:
        items: list[ThreatItem] = []

        # 1. Harvest from Ransomware Feed / Aggregator (Ransomlook API / Ransomfeed RSS)
        for target in settings.onion_targets:
            target_name = target.get("name", "Unknown DLS Tracker")
            target_url = target.get("url", "")
            target_type = target.get("type", "api")

            try:
                logger.info(f"Checking Dark Web target: {target_name} ({target_url})")

                # If URL is .onion, route strictly through Tor session. Otherwise try direct first, fallback to Tor.
                is_onion = ".onion" in target_url
                session = self._get_tor_session() if is_onion else requests.Session()

                if target_type == "rss":
                    resp = session.get(target_url, timeout=settings.request_timeout)
                    resp.raise_for_status()
                    feed = feedparser.parse(resp.content)
                    for entry in feed.entries:
                        title = getattr(entry, "title", "Dark Web Notice")
                        link = getattr(entry, "link", None)
                        summary = getattr(entry, "summary", getattr(entry, "description", ""))

                        pub_date = None
                        if hasattr(entry, "published"):
                            try:
                                pub_date = parser.parse(entry.published).astimezone(timezone.utc)
                            except Exception:
                                pass

                        if since and pub_date and pub_date < since:
                            continue

                        item = ThreatItem.create(
                            source_type=self.source_type,
                            source_name=target_name,
                            title=title,
                            url=link,
                            summary=summary,
                            published_at=pub_date,
                            metadata={"is_onion": is_onion, "target_type": target_type},
                        )
                        items.append(item)

                elif target_type == "api":
                    resp = session.get(target_url, timeout=settings.request_timeout)
                    if resp.status_code == 200:
                        posts = resp.json()
                        if isinstance(posts, list):
                            for post in posts[:30]:  # inspect recent 30 posts
                                victim_name = post.get("victim", post.get("post_title", ""))
                                group_name = post.get("group_name", "Unknown Group")
                                description = post.get("description", post.get("country", ""))
                                country = post.get("country", "")

                                # Prioritize Japan or collect general ransomware victim postings
                                is_japan = (
                                    (country.upper() == "JP")
                                    or ("JAPAN" in victim_name.upper())
                                    or ("JAPAN" in description.upper())
                                )
                                title = f"[{group_name} DLS] Victim: {victim_name} ({country or 'Global'})"

                                item = ThreatItem.create(
                                    source_type=self.source_type,
                                    source_name=f"{target_name} ({group_name})",
                                    title=title,
                                    url=post.get("permalink") or post.get("website"),
                                    summary=f"Group: {group_name}\nVictim: {victim_name}\nCountry: {country}\nDetails: {description}",
                                    metadata={
                                        "victim": victim_name,
                                        "group": group_name,
                                        "country": country,
                                        "is_japan": is_japan,
                                    },
                                )
                                items.append(item)

            except Exception as e:
                logger.error(f"Error harvesting darkweb target {target_name}: {e}")

        logger.info(f"DarkwebOnionHarvester collected {len(items)} items")
        return items
