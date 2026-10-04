import logging

import requests

from src.config import settings
from src.models import EnrichedThreat, JapanRelevance, Severity

logger = logging.getLogger(__name__)


class SlackNotifier:
    """Dispatches enriched threat intelligence to Slack incoming webhooks."""

    def __init__(self, webhook_url: str | None = None):
        self.webhook_url = webhook_url or settings.slack_webhook_url

    def notify(self, threat: EnrichedThreat) -> bool:
        if not self.webhook_url:
            return True

        header_prefix = ""
        if threat.japan_relevance == JapanRelevance.DIRECT:
            header_prefix = "🇯🇵 [日本標的] "
        elif threat.japan_relevance == JapanRelevance.INDIRECT:
            header_prefix = "🌐 [国内波及] "

        mention = ""
        if threat.japan_relevance == JapanRelevance.DIRECT and threat.severity in (Severity.CRITICAL, Severity.HIGH):
            mention = "<!channel> "
        elif threat.severity == Severity.CRITICAL:
            mention = "<!here> "

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{header_prefix}[{threat.severity.value}] {threat.title_ja[:80]}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{mention}*概要:*\n{threat.summary_ja}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*日本関連性:*\n{threat.japan_relevance.value}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*情報源:*\n{threat.item.source_type.value} ({threat.item.source_name})",
                    },
                    {"type": "mrkdwn", "text": f"*被害組織:*\n{', '.join(threat.victim_orgs) or '未特定'}"},
                    {"type": "mrkdwn", "text": f"*攻撃グループ:*\n{', '.join(threat.threat_actors) or '未特定'}"},
                ],
            },
        ]

        if threat.impact_analysis_ja:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*国内影響分析:*\n{threat.impact_analysis_ja}",
                    },
                }
            )

        if threat.item.url:
            blocks.append(
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "詳細ソースを見る", "emoji": True},
                            "url": threat.item.url,
                        }
                    ],
                }
            )

        payload = {"blocks": blocks}

        try:
            resp = requests.post(self.webhook_url, json=payload, timeout=10)
            if resp.status_code == 200:
                logger.info(f"Sent Slack notification for threat: {threat.title_ja}")
                return True
            else:
                logger.error(f"Failed to post Slack webhook (status {resp.status_code}): {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Error posting to Slack: {e}")
            return False
