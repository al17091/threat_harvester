import logging
from typing import Any

import requests

from src.config import settings
from src.models import EnrichedThreat

logger = logging.getLogger(__name__)


class GenericWebhookNotifier:
    """Dispatches standardized JSON payloads to any HTTP/HTTPS webhook endpoint."""

    def __init__(self, webhook_url: str | None = None):
        self.webhook_url = webhook_url or settings.generic_webhook_url

    def notify(self, threat: EnrichedThreat) -> bool:
        if not self.webhook_url:
            return True

        payload: dict[str, Any] = {
            "event": "threat_intelligence_alert",
            "threat_id": threat.item_id,
            "severity": threat.severity.value,
            "japan_relevance": threat.japan_relevance.value,
            "title_ja": threat.title_ja,
            "summary_ja": threat.summary_ja,
            "impact_analysis_ja": threat.impact_analysis_ja,
            "victim_orgs": threat.victim_orgs,
            "threat_actors": threat.threat_actors,
            "attack_type": threat.attack_type,
            "recommended_actions": threat.recommended_actions_ja,
            "source_type": threat.item.source_type.value,
            "source_name": threat.item.source_name,
            "url": threat.item.url,
            "published_at": threat.item.published_at.isoformat() if threat.item.published_at else None,
            "analyzed_at": threat.analyzed_at.isoformat(),
        }

        headers = {
            "Content-Type": "application/json",
            "User-Agent": "ThreatInformationHarvester/0.2.0",
        }

        try:
            resp = requests.post(self.webhook_url, json=payload, headers=headers, timeout=10)
            if resp.status_code in (200, 201, 202, 204):
                logger.info(f"Sent Generic Webhook notification for threat: {threat.title_ja}")
                return True
            else:
                logger.error(f"Generic Webhook failed with status {resp.status_code}: {resp.text}")
                return False
        except Exception as e:
            logger.error(f"Error posting to generic webhook: {e}")
            return False
