import logging
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup
from dateutil import parser

from worker.config import settings
from worker.harvesters.base import BaseHarvester
from worker.models import SourceType, ThreatItem

logger = logging.getLogger(__name__)


class TelegramHarvester(BaseHarvester):
    """Harvests threat disclosures and actor announcements from public Telegram channels via Web Preview."""

    def __init__(self, channels: list[str] | None = None):
        super().__init__(name="Telegram Channel Monitor", source_type=SourceType.TELEGRAM)
        self.channels = channels or settings.telegram_channels

    def harvest(self, since: datetime | None = None) -> list[ThreatItem]:
        items: list[ThreatItem] = []
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        for channel in self.channels:
            url = f"https://t.me/s/{channel}"
            try:
                logger.info(f"Checking Telegram channel: @{channel} ({url})")
                resp = requests.get(url, headers=headers, timeout=settings.request_timeout)
                if resp.status_code != 200:
                    logger.warning(f"Telegram channel @{channel} returned status {resp.status_code}")
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")
                messages = soup.find_all("div", class_="tgme_widget_message")

                for msg in messages:
                    try:
                        # Extract message text
                        text_div = msg.find("div", class_="tgme_widget_message_text")
                        if not text_div:
                            continue
                        text = text_div.get_text(separator="\n").strip()
                        if not text or len(text) < 20:
                            continue

                        # Extract timestamp
                        time_tag = msg.find("time")
                        pub_date = None
                        if time_tag and time_tag.get("datetime"):
                            try:
                                pub_date = parser.parse(time_tag["datetime"]).astimezone(timezone.utc)
                            except Exception:
                                pass

                        if since and pub_date and pub_date < since:
                            continue

                        # Extract message link
                        msg_link = None
                        link_tag = msg.find("a", class_="tgme_widget_message_date")
                        if link_tag and link_tag.get("href"):
                            msg_link = link_tag["href"]

                        # Title generation (first line or truncated text)
                        first_line = text.split("\n")[0].strip()
                        title = f"[@{channel}] {first_line[:80]}"

                        item = ThreatItem.create(
                            source_type=self.source_type,
                            source_name=f"Telegram:@{channel}",
                            title=title,
                            url=msg_link or url,
                            summary=text[:1000],
                            published_at=pub_date,
                            metadata={"channel": channel},
                        )
                        items.append(item)
                    except Exception as msg_err:
                        logger.debug(f"Error parsing Telegram message in @{channel}: {msg_err}")

            except Exception as e:
                logger.error(f"Error fetching Telegram channel @{channel}: {e}")

        logger.info(f"TelegramHarvester collected {len(items)} items")
        return items

    def test_connection(self) -> bool:
        try:
            sample = self.channels[0] if self.channels else "telegram"
            resp = requests.get(f"https://t.me/s/{sample}", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False
