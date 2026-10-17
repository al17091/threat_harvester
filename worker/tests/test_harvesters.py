from datetime import datetime, timezone
from unittest.mock import MagicMock

from worker.config import FeedConfig
from worker.harvesters.telegram import TelegramHarvester
from worker.harvesters.vendor_rss import VendorRSSHarvester
from worker.models import SourceType


def test_vendor_rss_harvester(monkeypatch):
    rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0">
      <channel>
        <title>Security Feed</title>
        <item>
          <title>Critical Zero-Day in VPN Gateway</title>
          <link>https://example.com/advisory/1</link>
          <description>Vulnerability details and mitigations</description>
          <pubDate>Wed, 15 Oct 2026 12:00:00 GMT</pubDate>
        </item>
      </channel>
    </rss>"""

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = rss_xml.encode("utf-8")
    monkeypatch.setattr("requests.get", lambda url, headers, timeout: mock_resp)

    feeds = [FeedConfig(name="TestCERT", url="https://example.com/rss", category="Alert")]
    harvester = VendorRSSHarvester(feeds=feeds)
    assert harvester.source_type == SourceType.VENDOR_RSS

    items = harvester.harvest()
    assert len(items) == 1
    assert items[0].title == "Critical Zero-Day in VPN Gateway"
    assert items[0].url == "https://example.com/advisory/1"
    assert items[0].source_type == SourceType.VENDOR_RSS


def test_telegram_harvester(monkeypatch):
    telegram_html = """
    <html>
      <body>
        <div class="tgme_widget_message">
          <div class="tgme_widget_message_text">
            Threat actor published sensitive stolen database dump of enterprise victim.
          </div>
          <time datetime="2026-10-15T12:00:00+00:00"></time>
        </div>
      </body>
    </html>
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = telegram_html
    monkeypatch.setattr("requests.get", lambda url, headers, timeout: mock_resp)

    harvester = TelegramHarvester(channels=["threat_channel"])
    assert harvester.source_type == SourceType.TELEGRAM

    items = harvester.harvest()
    assert len(items) == 1
    assert "Threat actor published" in items[0].title or "Threat actor published" in items[0].summary
    assert items[0].source_type == SourceType.TELEGRAM
