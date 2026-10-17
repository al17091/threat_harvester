import copy
import logging
import os
import re
from typing import Any

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Regular expression to match ${VAR} or ${VAR:-default}
ENV_VAR_PATTERN = re.compile(r"\$\{([A-Za-z0-9_]+)(?::-([^}]*))?\}")


def expand_env_vars(data: Any) -> Any:
    """Recursively expand environment variables in strings, dictionaries, and lists."""
    if isinstance(data, str):

        def replacer(match: re.Match) -> str:
            var_name = match.group(1)
            default_val = match.group(2) if match.group(2) is not None else ""
            return os.getenv(var_name, default_val)

        return ENV_VAR_PATTERN.sub(replacer, data)
    elif isinstance(data, dict):
        return {k: expand_env_vars(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [expand_env_vars(item) for item in data]
    return data


# --- Configuration Models ---


class ComplianceTiersConfig(BaseModel):
    commercial_ready: bool = True
    commercial_via_official_api: bool = True
    tos_restricted: bool = True
    darkweb_access: bool = True


class ComplianceConfig(BaseModel):
    mode: str = "all"
    tiers: ComplianceTiersConfig = Field(default_factory=ComplianceTiersConfig)


class FeedSourceConfig(BaseModel):
    name: str
    url: str
    category: str = "general"
    compliance_tier: str = "commercial_ready"
    enabled: bool = True


# Alias for backward compatibility
FeedConfig = FeedSourceConfig


class TelegramSourceConfig(BaseModel):
    channel: str
    compliance_tier: str = "tos_restricted"
    enabled: bool = True


class DarkwebSourceConfig(BaseModel):
    name: str
    url: str
    type: str = "api"  # "api", "rss", or "onion"
    compliance_tier: str = "commercial_via_official_api"
    enabled: bool = True


class QuerySourceConfig(BaseModel):
    name: str = ""
    directive: str = ""
    query: str = ""
    compliance_tier: str = "commercial_via_official_api"
    enabled: bool = True


class SourcesConfig(BaseModel):
    vendor_rss: list[FeedSourceConfig] = Field(default_factory=list)
    telegram: list[TelegramSourceConfig] = Field(default_factory=list)
    darkweb_onion: list[DarkwebSourceConfig] = Field(default_factory=list)
    x_monitor: list[QuerySourceConfig] = Field(default_factory=list)
    web_search: list[QuerySourceConfig] = Field(default_factory=list)


class DatabaseConfig(BaseModel):
    type: str = "sqlite"  # "postgres" (CNPG) or "sqlite"
    url: str = ""
    host: str = "postgres-cluster-rw"
    port: int = 5432
    name: str = "threat_harvester"
    user: str = "postgres"
    password: str = ""
    sslmode: str = "prefer"
    sqlite_path: str = "data/threat_cache.db"


class AiConfig(BaseModel):
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.5-flash-lite"


class SinkConfig(BaseModel):
    enabled: bool = True
    webhook_url: str = ""


class NotionSinkConfig(BaseModel):
    enabled: bool = True
    api_key: str = ""
    database_id: str = ""


class SinksConfig(BaseModel):
    discord: SinkConfig = Field(default_factory=SinkConfig)
    slack: SinkConfig = Field(default_factory=SinkConfig)
    generic_webhook: SinkConfig = Field(default_factory=SinkConfig)
    notion: NotionSinkConfig = Field(default_factory=NotionSinkConfig)


class NetworkConfig(BaseModel):
    tor_proxy_url: str = "socks5h://127.0.0.1:9050"
    request_timeout: int = 25


class PipelineConfig(BaseModel):
    check_interval_hours: int = 1
    notify_direct_only: bool = False


class AppConfig(BaseModel):
    version: str = "1.0"
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    ai: AiConfig = Field(default_factory=AiConfig)
    sinks: SinksConfig = Field(default_factory=SinksConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    sources: SourcesConfig = Field(default_factory=SourcesConfig)


def get_default_config() -> AppConfig:
    """Return default application configuration."""
    return AppConfig(
        sources=SourcesConfig(
            vendor_rss=[
                FeedSourceConfig(name="JPCERT/CC 注意喚起", url="https://www.jpcert.or.jp/rss/jpcert.rdf", category="jp_cert"),
                FeedSourceConfig(name="IPA 重要なセキュリティ情報", url="https://www.ipa.go.jp/security/rss/alert.rdf", category="jp_cert"),
                FeedSourceConfig(name="ScanNetSecurity", url="https://scan.netsecurity.ne.jp/rss/index.rdf", category="jp_news"),
                FeedSourceConfig(name="Security Next", url="https://www.security-next.com/feed", category="jp_news"),
                FeedSourceConfig(name="BleepingComputer", url="https://www.bleepingcomputer.com/feed/", category="global_news"),
                FeedSourceConfig(name="The Hacker News", url="https://thehackernews.com/rss.xml", category="global_news"),
                FeedSourceConfig(name="CISA Alerts", url="https://www.cisa.gov/uscert/ncas/alerts.xml", category="global_cert"),
            ],
            telegram=[
                TelegramSourceConfig(channel="redabyss_cti"),
                TelegramSourceConfig(channel="malware_traffic"),
                TelegramSourceConfig(channel="ransomfeed"),
                TelegramSourceConfig(channel="cybersecurity_news_hub"),
            ],
            darkweb_onion=[
                DarkwebSourceConfig(name="Ransomlook Tracker", url="https://www.ransomlook.io/api/recent", type="api"),
                DarkwebSourceConfig(name="RansomFeed Aggregator", url="https://ransomfeed.it/news.rss", type="rss"),
            ],
            x_monitor=[
                QuerySourceConfig(query="cyber attack Japan victim site:x.com OR site:twitter.com"),
                QuerySourceConfig(query="ランサムウェア 日本 標的 site:x.com OR site:twitter.com"),
                QuerySourceConfig(query="JPCERT CyberThreat site:x.com OR site:twitter.com"),
            ],
            web_search=[
                QuerySourceConfig(query="最新 サイバー攻撃 日本 企業 組織 被害 ランサムウェア"),
                QuerySourceConfig(query="Japan targeted cyber attack data breach ransomware recent"),
                QuerySourceConfig(query="セキュリティインシデント 漏洩 日本 国内 最近"),
            ],
        )
    )


class Settings:
    """Unified application settings backed by YAML config and environment variables."""

    def __init__(self, config_path: str | None = None):
        self.config_path = config_path or os.getenv("CONFIG_PATH", "config.yaml")
        self.app_config: AppConfig = get_default_config()
        self.reload(self.config_path)

    def reload(self, config_path: str | None = None) -> None:
        """Load configuration from file if exists, falling back to defaults and env vars."""
        path = config_path or self.config_path
        self.config_path = path

        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    raw_data = yaml.safe_load(f) or {}
                expanded = expand_env_vars(raw_data)
                self.app_config = AppConfig.model_validate(expanded)
                logger.info(f"Loaded configuration successfully from {path}")
            except Exception as e:
                logger.warning(f"Failed to parse {path}: {e}. Falling back to default configuration.")
                self.app_config = get_default_config()
        else:
            # Fall back to env-expanded default config
            logger.info(f"Configuration file {path} not found. Using defaults with environment variables.")
            default_dict = self.app_config.model_dump()
            expanded_default = expand_env_vars(default_dict)
            self.app_config = AppConfig.model_validate(expanded_default)

        # Ensure env vars override if explicitly set in environment
        self._apply_env_overrides()

    def _apply_env_overrides(self) -> None:
        """Apply top-level environment variable overrides for secrets."""
        if os.getenv("GEMINI_API_KEY"):
            self.app_config.ai.gemini_api_key = os.getenv("GEMINI_API_KEY", "")
        if os.getenv("GEMINI_MODEL"):
            self.app_config.ai.gemini_model = os.getenv("GEMINI_MODEL", "")
        if os.getenv("DATABASE_URL"):
            self.app_config.database.url = os.getenv("DATABASE_URL", "")
            self.app_config.database.type = "postgres" if "postgres" in os.getenv("DATABASE_URL", "") else "sqlite"
        if os.getenv("DISCORD_WEBHOOK_URL"):
            self.app_config.sinks.discord.webhook_url = os.getenv("DISCORD_WEBHOOK_URL", "")
        if os.getenv("SLACK_WEBHOOK_URL"):
            self.app_config.sinks.slack.webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
        if os.getenv("GENERIC_WEBHOOK_URL"):
            self.app_config.sinks.generic_webhook.webhook_url = os.getenv("GENERIC_WEBHOOK_URL", "")
        if os.getenv("NOTION_API_KEY"):
            self.app_config.sinks.notion.api_key = os.getenv("NOTION_API_KEY", "")
        if os.getenv("NOTION_DATABASE_ID"):
            self.app_config.sinks.notion.database_id = os.getenv("NOTION_DATABASE_ID", "")
        if os.getenv("TOR_PROXY_URL"):
            self.app_config.network.tor_proxy_url = os.getenv("TOR_PROXY_URL", "")
        if os.getenv("CACHE_DB_PATH"):
            self.app_config.database.sqlite_path = os.getenv("CACHE_DB_PATH", "")

    # --- Property Accessors for Backward Compatibility ---

    @property
    def gemini_api_key(self) -> str:
        return self.app_config.ai.gemini_api_key

    @property
    def gemini_model(self) -> str:
        return self.app_config.ai.gemini_model

    @property
    def discord_webhook_url(self) -> str:
        return self.app_config.sinks.discord.webhook_url

    @property
    def slack_webhook_url(self) -> str:
        return self.app_config.sinks.slack.webhook_url

    @property
    def generic_webhook_url(self) -> str:
        return self.app_config.sinks.generic_webhook.webhook_url

    @property
    def notion_api_key(self) -> str:
        return self.app_config.sinks.notion.api_key

    @property
    def notion_database_id(self) -> str:
        return self.app_config.sinks.notion.database_id

    @property
    def tor_proxy_url(self) -> str:
        return self.app_config.network.tor_proxy_url

    @property
    def request_timeout(self) -> int:
        return self.app_config.network.request_timeout

    @property
    def check_interval_hours(self) -> int:
        return self.app_config.pipeline.check_interval_hours

    @property
    def cache_db_path(self) -> str:
        return self.app_config.database.sqlite_path

    @property
    def database_url(self) -> str:
        return self.app_config.database.url

    @property
    def vendor_feeds(self) -> list[FeedSourceConfig]:
        return [f for f in self.app_config.sources.vendor_rss if f.enabled]

    @property
    def telegram_channels(self) -> list[str]:
        return [c.channel for c in self.app_config.sources.telegram if c.enabled]

    @property
    def onion_targets(self) -> list[dict[str, str]]:
        return [
            {"name": t.name, "url": t.url, "type": t.type}
            for t in self.app_config.sources.darkweb_onion
            if t.enabled
        ]

    @property
    def x_queries(self) -> list[str]:
        return [q.query for q in self.app_config.sources.x_monitor if q.enabled]

    @property
    def web_search_queries(self) -> list[str]:
        return [q.query for q in self.app_config.sources.web_search if q.enabled]

    # --- Source Mutation Methods for GUI ---

    def add_source(self, source_type: str, item_data: dict[str, Any]) -> None:
        """Add a new source to the active configuration."""
        if source_type == "vendor_rss":
            self.app_config.sources.vendor_rss.append(FeedSourceConfig.model_validate(item_data))
        elif source_type == "telegram":
            self.app_config.sources.telegram.append(TelegramSourceConfig.model_validate(item_data))
        elif source_type == "darkweb_onion":
            self.app_config.sources.darkweb_onion.append(DarkwebSourceConfig.model_validate(item_data))
        elif source_type == "x_monitor":
            self.app_config.sources.x_monitor.append(QuerySourceConfig.model_validate(item_data))
        elif source_type == "web_search":
            self.app_config.sources.web_search.append(QuerySourceConfig.model_validate(item_data))
        else:
            raise ValueError(f"Unknown source type: {source_type}")

    def toggle_source(self, source_type: str, identifier: str, enabled: bool) -> bool:
        """Toggle enabled status of a specific source."""
        if source_type == "vendor_rss":
            for feed in self.app_config.sources.vendor_rss:
                if feed.url == identifier or feed.name == identifier:
                    feed.enabled = enabled
                    return True
        elif source_type == "telegram":
            for ch in self.app_config.sources.telegram:
                if ch.channel == identifier:
                    ch.enabled = enabled
                    return True
        elif source_type == "darkweb_onion":
            for dw in self.app_config.sources.darkweb_onion:
                if dw.url == identifier or dw.name == identifier:
                    dw.enabled = enabled
                    return True
        elif source_type == "x_monitor":
            for xq in self.app_config.sources.x_monitor:
                if xq.query == identifier or xq.directive == identifier or (xq.name and xq.name == identifier):
                    xq.enabled = enabled
                    return True
        elif source_type == "web_search":
            for wq in self.app_config.sources.web_search:
                if wq.query == identifier or wq.directive == identifier or (wq.name and wq.name == identifier):
                    wq.enabled = enabled
                    return True
        return False

    def delete_source(self, source_type: str, identifier: str) -> bool:
        """Delete a source from configuration."""
        if source_type == "vendor_rss":
            orig = len(self.app_config.sources.vendor_rss)
            self.app_config.sources.vendor_rss = [
                f for f in self.app_config.sources.vendor_rss if f.url != identifier and f.name != identifier
            ]
            return len(self.app_config.sources.vendor_rss) < orig
        elif source_type == "telegram":
            orig = len(self.app_config.sources.telegram)
            self.app_config.sources.telegram = [
                c for c in self.app_config.sources.telegram if c.channel != identifier
            ]
            return len(self.app_config.sources.telegram) < orig
        elif source_type == "darkweb_onion":
            orig = len(self.app_config.sources.darkweb_onion)
            self.app_config.sources.darkweb_onion = [
                d for d in self.app_config.sources.darkweb_onion if d.url != identifier and d.name != identifier
            ]
            return len(self.app_config.sources.darkweb_onion) < orig
        elif source_type == "x_monitor":
            orig = len(self.app_config.sources.x_monitor)
            self.app_config.sources.x_monitor = [
                q for q in self.app_config.sources.x_monitor
                if q.query != identifier and q.directive != identifier and q.name != identifier
            ]
            return len(self.app_config.sources.x_monitor) < orig
        elif source_type == "web_search":
            orig = len(self.app_config.sources.web_search)
            self.app_config.sources.web_search = [
                q for q in self.app_config.sources.web_search
                if q.query != identifier and q.directive != identifier and q.name != identifier
            ]
            return len(self.app_config.sources.web_search) < orig
        return False

    def export_yaml(self, mask_secrets: bool = False) -> str:
        """Export active configuration as clean YAML string."""
        data = self.app_config.model_dump()
        if mask_secrets:
            # Mask sensitive tokens/passwords
            if data.get("ai", {}).get("gemini_api_key"):
                data["ai"]["gemini_api_key"] = "********"
            if data.get("database", {}).get("password"):
                data["database"]["password"] = "********"
            sinks = data.get("sinks", {})
            for sink_name in ["discord", "slack", "generic_webhook"]:
                if sinks.get(sink_name, {}).get("webhook_url"):
                    sinks[sink_name]["webhook_url"] = "https://...[masked]"
            if sinks.get("notion", {}).get("api_key"):
                sinks["notion"]["api_key"] = "********"

        header = "# Threat Information Harvester Configuration\n# Exported from Web GUI\n\n"
        return header + yaml.dump(data, allow_unicode=True, sort_keys=False)

    def save(self, path: str | None = None) -> None:
        """Persist current configuration to disk."""
        target_path = path or self.config_path
        yaml_content = self.export_yaml(mask_secrets=False)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(yaml_content)
        logger.info(f"Saved configuration to {target_path}")

    def to_safe_dict(self) -> dict[str, Any]:
        """Return dict representation with masked secrets for Web UI."""
        data = copy.deepcopy(self.app_config.model_dump())
        if data.get("ai", {}).get("gemini_api_key"):
            key = data["ai"]["gemini_api_key"]
            data["ai"]["gemini_api_key"] = key[:4] + "..." + key[-4:] if len(key) > 8 else "***"
        if data.get("database", {}).get("password"):
            data["database"]["password"] = "******"
        return data


# Global singleton instance
settings = Settings()
