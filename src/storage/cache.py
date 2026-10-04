import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from src.models import EnrichedThreat, ThreatItem


class ThreatCache:
    """SQLite-backed cache for deduplication and incident history."""

    def __init__(self, db_path: str = "data/threat_cache.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_items (
                    id TEXT PRIMARY KEY,
                    source_type TEXT NOT NULL,
                    source_name TEXT NOT NULL,
                    title TEXT NOT NULL,
                    url TEXT,
                    summary TEXT,
                    published_at TEXT,
                    harvested_at TEXT NOT NULL,
                    severity TEXT,
                    japan_relevance TEXT,
                    notified_at TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_harvested_at ON threat_items(harvested_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_source_type ON threat_items(source_type)")
            conn.commit()

    def is_seen(self, item_id: str) -> bool:
        """Check if an item has already been collected/processed."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM threat_items WHERE id = ?", (item_id,))
            return cursor.fetchone() is not None

    def mark_seen(
        self,
        item: ThreatItem,
        enriched: EnrichedThreat | None = None,
        notified: bool = False
    ) -> None:
        """Record an item as seen/processed."""
        now_str = datetime.now(timezone.utc).isoformat()
        published_str = item.published_at.isoformat() if item.published_at else None
        severity_val = enriched.severity.value if enriched else None
        japan_rel_val = enriched.japan_relevance.value if enriched else None
        notified_val = now_str if notified else None

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO threat_items (
                    id, source_type, source_name, title, url, summary,
                    published_at, harvested_at, severity, japan_relevance, notified_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.id,
                    item.source_type.value,
                    item.source_name,
                    item.title,
                    item.url,
                    item.summary,
                    published_str,
                    now_str,
                    severity_val,
                    japan_rel_val,
                    notified_val,
                ),
            )
            conn.commit()

    def get_stats(self) -> dict[str, Any]:
        """Return cache statistics for status check."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM threat_items")
            total_items = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM threat_items WHERE notified_at IS NOT NULL")
            notified_items = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM threat_items WHERE japan_relevance = 'Direct'")
            japan_direct_items = cursor.fetchone()[0]

            return {
                "total_items": total_items,
                "notified_items": notified_items,
                "japan_direct_items": japan_direct_items,
                "db_path": self.db_path,
            }

    def get_history(
        self,
        limit: int = 20,
        japan_only: bool = False,
    ) -> list[dict[str, Any]]:
        """Retrieve recent threat items from the database."""
        query = "SELECT * FROM threat_items WHERE 1=1"
        params: list[Any] = []

        if japan_only:
            query += " AND japan_relevance = 'Direct'"

        query += " ORDER BY harvested_at DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            return [dict(row) for row in cursor.fetchall()]

    def get_item(self, item_id: str) -> dict[str, Any] | None:
        """Retrieve single threat item by ID."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM threat_items WHERE id = ?", (item_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def cleanup_old(self, retention_days: int = 60) -> int:
        """Remove records older than retention_days."""
        threshold = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM threat_items WHERE harvested_at < ?", (threshold,))
            deleted = cursor.rowcount
            conn.commit()
            return deleted

