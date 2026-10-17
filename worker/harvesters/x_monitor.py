import json
import logging
from datetime import datetime, timezone

from google import genai
from google.genai import types

from worker.config import settings
from worker.harvesters.base import BaseHarvester
from worker.models import SourceType, ThreatItem

logger = logging.getLogger(__name__)


class XMonitorHarvester(BaseHarvester):
    """Harvests threat intelligence reported on X (Twitter) using low-cost Gemini Grounded Search."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        super().__init__(name="X (Twitter) Monitor", source_type=SourceType.X_MONITOR)
        self.api_key = api_key or settings.gemini_api_key
        self.model = model or settings.gemini_model
        self.client = genai.Client(api_key=self.api_key) if self.api_key else None

    def harvest(self, since: datetime | None = None) -> list[ThreatItem]:
        if not self.client:
            logger.warning("Gemini API key is not configured. Skipping XMonitorHarvester.")
            return []

        items: list[ThreatItem] = []
        queries = settings.x_queries

        for query in queries:
            try:
                logger.info(f"Monitoring X/Twitter via Gemini Grounded Search for query: {query}")
                prompt = f"""
                You are a threat intelligence analyst tracking alerts and reports on X (Twitter).
                Search X/Twitter posts (tweets) from cybersecurity researchers, threat intelligence feeds (e.g. vxunderground, ransomware trackers, JPCERT accounts), and incident response groups.

                Search query target: {query}

                Focus specifically on incidents affecting Japanese companies, organizations, public entities, or global incidents with significant impact on Japan.

                Output a JSON array of objects with the following schema:
                [
                  {{
                    "author_handle": "Twitter handle e.g. @vxunderground or source account",
                    "tweet_summary": "Summary of the tweet alert and technical findings",
                    "tweet_url": "URL to the tweet or referenced threat report if available",
                    "victim_or_threat": "Victim organization or malware/actor name mentioned",
                    "date_posted": "Estimated date e.g. YYYY-MM-DD"
                  }}
                ]
                Only return valid JSON array without Markdown code block formatting.
                """

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
                            handle = res.get("author_handle", "@X_User")
                            summary = res.get("tweet_summary", "")
                            if not summary:
                                continue
                            tweet_url = res.get("tweet_url")
                            victim = res.get("victim_or_threat", "")

                            pub_date = None
                            if res.get("date_posted"):
                                try:
                                    from dateutil import parser

                                    pub_date = parser.parse(res["date_posted"]).replace(tzinfo=timezone.utc)
                                except Exception:
                                    pass

                            title = f"[{handle}] {summary[:70]}..."
                            item = ThreatItem.create(
                                source_type=self.source_type,
                                source_name=f"X:{handle}",
                                title=title,
                                url=tweet_url,
                                summary=summary,
                                published_at=pub_date,
                                metadata={"author": handle, "victim_or_threat": victim, "query": query},
                            )
                            items.append(item)
                except json.JSONDecodeError as json_err:
                    logger.warning(f"Failed to parse X monitor JSON response: {json_err} (raw: {response.text[:200]})")

            except Exception as e:
                logger.error(f"Error executing X Monitor Grounded Search for '{query}': {e}")

        logger.info(f"XMonitorHarvester collected {len(items)} items")
        return items

    def test_connection(self) -> bool:
        return bool(self.client)
