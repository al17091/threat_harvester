import logging

import requests

from backend.config import settings
from backend.models import EnrichedThreat, JapanRelevance, Severity

logger = logging.getLogger(__name__)


class DiscordNotifier:
    """Dispatches enriched threat intelligence to Discord channels."""

    def __init__(self, webhook_url: str | None = None):
        self.webhook_url = webhook_url or settings.discord_webhook_url

    def notify(self, threat: EnrichedThreat) -> bool:
        if not self.webhook_url:
            logger.info(f"[Dry-Run / No Webhook] Alert would be sent: [{threat.severity.value}] {threat.title_ja}")
            return True

        # Color mapping: Red for Critical/Direct, Orange for High, Blue for Medium
        if threat.japan_relevance == JapanRelevance.DIRECT or threat.severity == Severity.CRITICAL:
            color = 0xFF0033  # Red / Alert
        elif threat.severity == Severity.HIGH:
            color = 0xFFA500  # Orange
        elif threat.severity == Severity.MEDIUM:
            color = 0x3399FF  # Blue
        else:
            color = 0x808080  # Grey

        # Headline badge
        badges = []
        if threat.japan_relevance == JapanRelevance.DIRECT:
            badges.append("🇯🇵 [日本標的 / 関連]")
        elif threat.japan_relevance == JapanRelevance.INDIRECT:
            badges.append("🌐 [日本波及 / 警戒]")

        badges.append(f"[{threat.severity.value}]")
        prefix = " ".join(badges)

        # Discord content mention
        content = ""
        if threat.japan_relevance == JapanRelevance.DIRECT and threat.severity in (Severity.CRITICAL, Severity.HIGH):
            content = "🚨 @here **日本国内を標的とした重大インシデントを検知しました**"
        elif threat.severity == Severity.CRITICAL:
            content = "🚨 @here **Critical Threat Incident Alert**"

        fields = [
            {"name": "情報源", "value": f"{threat.item.source_type.value} ({threat.item.source_name})", "inline": True},
            {"name": "日本への関連性", "value": threat.japan_relevance.value, "inline": True},
            {"name": "攻撃分類", "value": threat.attack_type or "未特定", "inline": True},
        ]

        if threat.victim_orgs:
            fields.append({"name": "被害組織", "value": ", ".join(threat.victim_orgs), "inline": True})

        if threat.threat_actors:
            fields.append({"name": "脅威グループ", "value": ", ".join(threat.threat_actors), "inline": True})

        if threat.impact_analysis_ja:
            fields.append({"name": "日本への影響分析", "value": threat.impact_analysis_ja[:1000], "inline": False})

        if threat.recommended_actions_ja:
            actions = "\n".join([f"• {a}" for a in threat.recommended_actions_ja[:5]])
            fields.append({"name": "推奨対策", "value": actions[:1000], "inline": False})

        if threat.item.url:
            fields.append({"name": "参照元リンク", "value": f"[詳細を見る]({threat.item.url})", "inline": False})

        payload = {
            "username": "Threat Harvester (Japan CTI)",
            "content": content,
            "embeds": [
                {
                    "title": f"{prefix} {threat.title_ja[:200]}",
                    "description": threat.summary_ja[:2000],
                    "url": threat.item.url,
                    "color": color,
                    "fields": fields,
                    "footer": {"text": f"Harvester ID: {threat.item_id[:8]} | Powered by Gemini & Tor CTI"},
                    "timestamp": threat.analyzed_at.isoformat(),
                }
            ],
        }

        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            if resp.status_code in (200, 204):
                logger.info(f"Sent Discord notification for threat: {threat.title_ja}")
                return True
            else:
                logger.error(f"Failed to post to Discord (status {resp.status_code}): {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Error posting notification to Discord: {e}")
            return False
