import logging
from typing import Any

import requests

from worker.config import settings
from worker.models import EnrichedThreat

logger = logging.getLogger(__name__)


class NotionReporter:
    """Publishes enriched threat intelligence items to a Notion Database."""

    def __init__(self, api_key: str | None = None, database_id: str | None = None):
        self.api_key = api_key if api_key is not None else settings.notion_api_key
        self.database_id = database_id if database_id is not None else settings.notion_database_id

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.database_id)

    def _get_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Notion-Version": "2022-06-28",
            "Content-Type": "application/json",
        }

    def create_page(self, threat: EnrichedThreat) -> dict[str, Any] | None:
        """Create a new threat intelligence page inside the target Notion database."""
        if not self.is_configured:
            logger.info(f"[Notion Dry-Run] Notion is not configured. Would publish: {threat.title_ja}")
            return None

        # Build properties
        properties: dict[str, Any] = {
            "Name": {"title": [{"type": "text", "text": {"content": threat.title_ja[:100]}}]},
            "Severity": {"select": {"name": threat.severity.value}},
            "Japan Relevance": {"select": {"name": threat.japan_relevance.value}},
        }

        if threat.attack_type:
            properties["Attack Type"] = {"select": {"name": threat.attack_type[:100]}}

        clean_victims = [
            v.strip()
            for v in threat.victim_orgs
            if v and v.strip().lower() not in {"unknown", "none", "n/a", "unspecified", "未特定", "不明", "特定なし", "指定なし"}
        ]
        if clean_victims:
            properties["Victims"] = {
                "multi_select": [{"name": v[:100].replace(",", "")} for v in clean_victims[:5]]
            }

        clean_actors = [
            a.strip()
            for a in threat.threat_actors
            if a and a.strip().lower() not in {"unknown", "none", "n/a", "unspecified", "未特定", "不明", "特定なし"}
        ]
        if clean_actors:
            properties["Threat Actors"] = {
                "multi_select": [{"name": a[:100].replace(",", "")} for a in clean_actors[:5]]
            }

        if threat.item.source_name:
            properties["Source"] = {
                "rich_text": [
                    {
                        "type": "text",
                        "text": {"content": f"{threat.item.source_type.value} ({threat.item.source_name[:50]})"},
                    }
                ]
            }

        if threat.item.url:
            properties["URL"] = {"url": threat.item.url}

        if threat.item.published_at:
            properties["Published Date"] = {"date": {"start": threat.item.published_at.strftime("%Y-%m-%d")}}

        # Build page body blocks
        children: list[dict[str, Any]] = [
            {
                "object": "block",
                "type": "heading_2",
                "heading_2": {"rich_text": [{"type": "text", "text": {"content": "📋 事象ファクト要約 (Factual Summary)"}}]},
            },
            {
                "object": "block",
                "type": "paragraph",
                "paragraph": {"rich_text": [{"type": "text", "text": {"content": threat.summary_ja}}]},
            },
        ]

        if threat.impact_analysis_ja:
            children.extend(
                [
                    {
                        "object": "block",
                        "type": "heading_2",
                        "heading_2": {
                            "rich_text": [
                                {"type": "text", "text": {"content": "📊 確認された被害・影響範囲 (Confirmed Impact & Scope)"}}
                            ]
                        },
                    },
                    {
                        "object": "block",
                        "type": "paragraph",
                        "paragraph": {"rich_text": [{"type": "text", "text": {"content": threat.impact_analysis_ja}}]},
                    },
                ]
            )

        if threat.item.url:
            children.append(
                {
                    "object": "block",
                    "type": "bookmark",
                    "bookmark": {"url": threat.item.url},
                }
            )

        payload = {
            "parent": {"database_id": self.database_id},
            "properties": properties,
            "children": children,
        }

        try:
            url = "https://api.notion.com/v1/pages"
            resp = requests.post(url, headers=self._get_headers(), json=payload, timeout=settings.request_timeout)
            if resp.status_code in (200, 201):
                data = resp.json()
                logger.info(f"Successfully published threat to Notion: {threat.title_ja} (Page ID: {data.get('id')})")
                return data
            else:
                logger.error(f"Notion API error (status {resp.status_code}): {resp.text}")
                return None
        except Exception as e:
            logger.error(f"Failed to post threat to Notion: {e}")
            return None
