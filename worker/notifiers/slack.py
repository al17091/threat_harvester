import logging

import requests

from worker.config import settings
from worker.models import EnrichedThreat, JapanRelevance, Severity

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

        meta_fields = [
            {"type": "mrkdwn", "text": f"*日本関連性:*\n{threat.japan_relevance.value}"},
            {
                "type": "mrkdwn",
                "text": f"*情報源:*\n{threat.item.source_type.value} ({threat.item.source_name})",
            },
        ]
        clean_victims = [
            v.strip()
            for v in threat.victim_orgs
            if v and v.strip().lower() not in {"unknown", "none", "n/a", "unspecified", "未特定", "不明", "特定なし", "指定なし"}
        ]
        if clean_victims:
            meta_fields.append({"type": "mrkdwn", "text": f"*被害組織:*\n{', '.join(clean_victims)}"})
        clean_actors = [
            a.strip()
            for a in threat.threat_actors
            if a and a.strip().lower() not in {"unknown", "none", "n/a", "unspecified", "未特定", "不明", "特定なし"}
        ]
        if clean_actors:
            meta_fields.append({"type": "mrkdwn", "text": f"*攻撃グループ:*\n{', '.join(clean_actors)}"})

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
                    "text": f"{mention}*事象ファクト要約:*\n{threat.summary_ja}",
                },
            },
            {
                "type": "section",
                "fields": meta_fields,
            },
        ]

        if threat.impact_analysis_ja:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*確認された被害・影響範囲:*\n{threat.impact_analysis_ja}",
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
