import json
import logging
from datetime import datetime, timezone

from google import genai
from google.genai import types

from worker.config import settings
from worker.harvesters.base import BaseHarvester
from worker.models import SourceType, ThreatItem

logger = logging.getLogger(__name__)


class WebSearchHarvester(BaseHarvester):
    """Harvests Japan-targeted cyber threat news using Gemini Google Search Grounding."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        super().__init__(name="Gemini Web Search Grounding", source_type=SourceType.WEB_SEARCH)
        self.api_key = api_key or settings.gemini_api_key
        self.model = model or settings.gemini_model
        self.client = genai.Client(api_key=self.api_key) if self.api_key else None

    def harvest(self, since: datetime | None = None) -> list[ThreatItem]:
        if not self.client:
            logger.warning("Gemini API key is not configured. Skipping WebSearchHarvester.")
            return []

        items: list[ThreatItem] = []
        queries = settings.web_search_queries

        for query in queries:
            try:
                logger.info(f"Running Gemini Grounded Search for query: {query}")
                prompt = f"""
                You are a cyber threat intelligence researcher monitoring threats against Japan.
                Search for recent cyber attacks, ransomware incidents, data breaches, and zero-day advisories targeting Japanese companies, government, or infrastructure.

                Query context: {query}

                Extract any distinct recent incidents found (up to 5 incidents per query).
                For each incident, output a JSON array of objects with the following schema:
                [
                  {{
                    "title": "Incident title in English or Japanese",
                    "url": "Source URL if available or reputable domain",
                    "summary": "Concise summary of the incident and impact on Japanese entities",
                    "published_date": "YYYY-MM-DD or estimated ISO date",
                    "victim_name": "Targeted Japanese organization if known"
                  }}
                ]
                Only return valid JSON array without Markdown code block formatting.
                """

                # Call Gemini with Google Search tool enabled
                response = self.client.models.generate_content(
                    model=self.model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        tools=[types.Tool(google_search=types.GoogleSearch())],
                        response_mime_type="application/json",
                    ),
                )

                if not response.text:
                    continue

                try:
                    results = json.loads(response.text)
                    if isinstance(results, list):
                        for res in results:
                            title = res.get("title", "").strip()
                            if not title:
                                continue
                            url = res.get("url")
                            summary = res.get("summary", "")
                            victim = res.get("victim_name", "")

                            pub_date = None
                            if res.get("published_date"):
                                try:
                                    from dateutil import parser

                                    pub_date = parser.parse(res["published_date"]).replace(tzinfo=timezone.utc)
                                except Exception:
                                    pass

                            item = ThreatItem.create(
                                source_type=self.source_type,
                                source_name=f"WebSearch:{query[:20]}",
                                title=title,
                                url=url,
                                summary=summary,
                                published_at=pub_date,
                                metadata={"victim": victim, "query": query},
                            )
                            items.append(item)
                except json.JSONDecodeError as json_err:
                    logger.warning(
                        f"Failed to parse Gemini Web Search JSON output: {json_err} (raw: {response.text[:200]})"
                    )

            except Exception as e:
                logger.error(f"Error executing Gemini Grounded Search for '{query}': {e}")

        logger.info(f"WebSearchHarvester collected {len(items)} items")
        return items

    def test_connection(self) -> bool:
        if not self.client:
            return False
        try:
            # Simple minimal probe
            resp = self.client.models.generate_content(
                model=self.model,
                contents="Ping. Reply with 'pong'.",
            )
            return bool(resp.text)
        except Exception as e:
            logger.warning(f"Gemini connection probe failed: {e}")
            return False
