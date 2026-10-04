import os

from pydantic import BaseModel, Field


class FeedConfig(BaseModel):
    name: str
    url: str
    category: str = "general"


class Settings(BaseModel):
    # API & Keys
    gemini_api_key: str = Field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    gemini_model: str = Field(default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-2.5-flash"))
    discord_webhook_url: str = Field(default_factory=lambda: os.getenv("DISCORD_WEBHOOK_URL", ""))

    # Networking & Proxy
    tor_proxy_url: str = Field(default_factory=lambda: os.getenv("TOR_PROXY_URL", "socks5h://127.0.0.1:9050"))
    request_timeout: int = Field(default_factory=lambda: int(os.getenv("REQUEST_TIMEOUT", "25")))

    # Scheduling & Intervals
    check_interval_hours: int = Field(default_factory=lambda: int(os.getenv("CHECK_INTERVAL_HOURS", "1")))
    cache_db_path: str = Field(default_factory=lambda: os.getenv("CACHE_DB_PATH", "data/threat_cache.db"))

    # Vendor & CERT RSS Feeds
    vendor_feeds: list[FeedConfig] = Field(
        default_factory=lambda: [
            # Japanese CERT & Security Sources
            FeedConfig(name="JPCERT/CC 注意喚起", url="https://www.jpcert.or.jp/rss/jpcert.rdf", category="jp_cert"),
            FeedConfig(name="IPA 重要なセキュリティ情報", url="https://www.ipa.go.jp/security/rss/alert.rdf", category="jp_cert"),
            FeedConfig(name="ScanNetSecurity", url="https://scan.netsecurity.ne.jp/rss/index.rdf", category="jp_news"),
            FeedConfig(name="Security Next", url="https://www.security-next.com/feed", category="jp_news"),
            # Major Global Sources
            FeedConfig(name="BleepingComputer", url="https://www.bleepingcomputer.com/feed/", category="global_news"),
            FeedConfig(name="The Hacker News", url="https://thehackernews.com/rss.xml", category="global_news"),
            FeedConfig(name="CISA Alerts", url="https://www.cisa.gov/uscert/ncas/alerts.xml", category="global_cert"),
        ]
    )

    # Telegram Public Channels (Web Preview endpoints: https://t.me/s/<channel>)
    telegram_channels: list[str] = Field(
        default_factory=lambda: [
            # Notable OSINT and CTI public telegram channels
            "redabyss_cti",
            "malware_traffic",
            "ransomfeed",
            "cybersecurity_news_hub",
        ]
    )

    # Dark Web / Ransomware Leak Sites & Trackers
    # Note: Includes public mirror/aggregators and onion sites monitored via Tor
    onion_targets: list[dict[str, str]] = Field(
        default_factory=lambda: [
            # Open aggregator API and onion mirrors
            {"name": "Ransomlook Tracker", "url": "https://www.ransomlook.io/api/recent", "type": "api"},
            {"name": "RansomFeed Aggregator", "url": "https://ransomfeed.it/news.rss", "type": "rss"},
        ]
    )

    # X (Twitter) Security Handles / Search Queries for Grounded Search
    x_queries: list[str] = Field(
        default_factory=lambda: [
            "cyber attack Japan victim site:x.com OR site:twitter.com",
            "ランサムウェア 日本 標的 site:x.com OR site:twitter.com",
            "JPCERT CyberThreat site:x.com OR site:twitter.com",
        ]
    )

    # General Web Search queries for Gemini Grounding
    web_search_queries: list[str] = Field(
        default_factory=lambda: [
            "最新 サイバー攻撃 日本 企業 組織 被害 ランサムウェア",
            "Japan targeted cyber attack data breach ransomware recent",
            "セキュリティインシデント 漏洩 日本 国内 最近",
        ]
    )


settings = Settings()
