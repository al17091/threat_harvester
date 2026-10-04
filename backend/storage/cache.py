import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from backend.models import EnrichedThreat, ThreatItem

logger = logging.getLogger(__name__)


class ThreatCache:
    """SQLAlchemy-backed store supporting PostgreSQL (k3s CNPG) and SQLite."""

    def __init__(self, db_path: str | None = None, database_url: str | None = None):
        self.database_url = self._resolve_database_url(db_path=db_path, database_url=database_url)
        self.is_sqlite = self.database_url.startswith("sqlite")
        self.db_path = db_path

        connect_args: dict[str, Any] = {}
        if self.is_sqlite:
            connect_args["check_same_thread"] = False
            # Ensure local directory exists
            file_match = re.search(r"sqlite:///(.+)", self.database_url)
            if file_match and file_match.group(1) != ":memory:":
                os.makedirs(os.path.dirname(os.path.abspath(file_match.group(1))), exist_ok=True)

        self.engine = sa.create_engine(
            self.database_url,
            connect_args=connect_args,
            pool_pre_ping=True,
        )
        self.metadata = sa.MetaData()
        self.threat_items = sa.Table(
            "threat_items",
            self.metadata,
            sa.Column("id", sa.String(64), primary_key=True),
            sa.Column("source_type", sa.String(32), nullable=False),
            sa.Column("source_name", sa.String(128), nullable=False),
            sa.Column("title", sa.Text, nullable=False),
            sa.Column("url", sa.Text, nullable=True),
            sa.Column("summary", sa.Text, nullable=True),
            sa.Column("raw_content", sa.Text, nullable=True),
            sa.Column("published_at", sa.Text, nullable=True),
            sa.Column("harvested_at", sa.Text, nullable=False),
            sa.Column("severity", sa.String(32), nullable=True),
            sa.Column("japan_relevance", sa.String(32), nullable=True),
            sa.Column("notified_at", sa.Text, nullable=True),
            sa.Column("enriched_data", sa.Text, nullable=True),
            sa.Index("idx_harvested_at", "harvested_at"),
            sa.Index("idx_source_type", "source_type"),
        )
        self._init_db()

    def _resolve_database_url(self, db_path: str | None = None, database_url: str | None = None) -> str:
        """Resolve database URL with PostgreSQL priority and SQLite fallback."""
        if database_url:
            return self._normalize_url(database_url)

        env_url = os.getenv("DATABASE_URL")
        if env_url:
            return self._normalize_url(env_url)

        host = os.getenv("DB_HOST")
        if host:
            user = os.getenv("DB_USER", "postgres")
            password = os.getenv("DB_PASSWORD", "")
            port = os.getenv("DB_PORT", "5432")
            name = os.getenv("DB_NAME", "information_harvester")
            sslmode = os.getenv("DB_SSLMODE", "")
            auth = f"{user}:{password}@" if password else f"{user}@"
            url = f"postgresql+psycopg://{auth}{host}:{port}/{name}"
            if sslmode:
                url += f"?sslmode={sslmode}"
            return url

        # Fallback to SQLite
        target_path = db_path or os.getenv("CACHE_DB_PATH", "data/threat_cache.db")
        if target_path == ":memory:":
            return "sqlite:///:memory:"
        return f"sqlite:///{os.path.abspath(target_path)}"

    def _normalize_url(self, url: str) -> str:
        """Ensure driver compatibility (e.g. postgresql+psycopg)."""
        if url.startswith("postgres://"):
            return "postgresql+psycopg://" + url[len("postgres://") :]
        if url.startswith("postgresql://") and not url.startswith("postgresql+"):
            return "postgresql+psycopg://" + url[len("postgresql://") :]
        return url

    def _init_db(self) -> None:
        """Create tables and indexes if they do not exist, and migrate columns."""
        try:
            self.metadata.create_all(self.engine)
            # Ensure enriched_data column exists on existing DB files
            with self.engine.begin() as conn:
                try:
                    conn.execute(sa.text("ALTER TABLE threat_items ADD COLUMN enriched_data TEXT"))
                except Exception:
                    pass
                try:
                    conn.execute(sa.text("ALTER TABLE threat_items ADD COLUMN raw_content TEXT"))
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"Failed to initialize database schema: {e}", exc_info=True)
            raise

    def is_seen(self, item_id: str) -> bool:
        """Check if an item has already been collected/processed."""
        query = sa.select(self.threat_items.c.id).where(self.threat_items.c.id == item_id).limit(1)
        with self.engine.connect() as conn:
            result = conn.execute(query).scalar_one_or_none()
            return result is not None

    def mark_seen(
        self,
        item: ThreatItem,
        enriched: EnrichedThreat | None = None,
        notified: bool = False,
    ) -> None:
        """Record or update a threat item."""
        now_str = datetime.now(timezone.utc).isoformat()
        published_str = item.published_at.isoformat() if item.published_at else None
        severity_val = enriched.severity.value if enriched else None
        japan_rel_val = enriched.japan_relevance.value if enriched else None
        notified_val = now_str if notified else None
        enriched_json = json.dumps(enriched.model_dump(), default=str, ensure_ascii=False) if enriched else None

        values = {
            "id": item.id,
            "source_type": item.source_type.value,
            "source_name": item.source_name,
            "title": item.title,
            "url": item.url,
            "summary": item.summary,
            "published_at": published_str,
            "harvested_at": now_str,
            "severity": severity_val,
            "japan_relevance": japan_rel_val,
            "notified_at": notified_val,
            "enriched_data": enriched_json,
        }

        with self.engine.begin() as conn:
            if self.is_sqlite:
                stmt = sqlite_insert(self.threat_items).values(**values)
                stmt = stmt.on_conflict_do_update(
                    index_elements=["id"],
                    set_={
                        "title": stmt.excluded.title,
                        "summary": stmt.excluded.summary,
                        "harvested_at": stmt.excluded.harvested_at,
                        "severity": stmt.excluded.severity,
                        "japan_relevance": stmt.excluded.japan_relevance,
                        "notified_at": stmt.excluded.notified_at,
                        "enriched_data": stmt.excluded.enriched_data,
                    },
                )
            else:
                stmt = pg_insert(self.threat_items).values(**values)
                stmt = stmt.on_conflict_do_update(
                    index_elements=["id"],
                    set_={
                        "title": stmt.excluded.title,
                        "summary": stmt.excluded.summary,
                        "harvested_at": stmt.excluded.harvested_at,
                        "severity": stmt.excluded.severity,
                        "japan_relevance": stmt.excluded.japan_relevance,
                        "notified_at": stmt.excluded.notified_at,
                        "enriched_data": stmt.excluded.enriched_data,
                    },
                )
            conn.execute(stmt)

    def get_stats(self) -> dict[str, Any]:
        """Return database statistics for status check."""
        with self.engine.connect() as conn:
            total_items = conn.execute(
                sa.select(sa.func.count()).select_from(self.threat_items)
            ).scalar_one()

            notified_items = conn.execute(
                sa.select(sa.func.count())
                .select_from(self.threat_items)
                .where(self.threat_items.c.notified_at.is_not(None))
            ).scalar_one()

            japan_direct_items = conn.execute(
                sa.select(sa.func.count())
                .select_from(self.threat_items)
                .where(self.threat_items.c.japan_relevance == "Direct")
            ).scalar_one()

            return {
                "total_items": total_items,
                "notified_items": notified_items,
                "japan_direct_items": japan_direct_items,
                "backend": "sqlite" if self.is_sqlite else "postgresql",
                "database_url": self._mask_url(self.database_url),
                "db_path": self.db_path or self.database_url,
            }

    def _mask_url(self, url: str) -> str:
        """Mask credentials in database URL."""
        return re.sub(r":([^:@]+)@", ":****@", url)

    def get_history(
        self,
        limit: int = 50,
        japan_only: bool = False,
        severity: str | None = None,
        source_type: str | None = None,
        search: str | None = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Retrieve recent threat items with optional filtering."""
        query = sa.select(self.threat_items)

        if japan_only:
            query = query.where(self.threat_items.c.japan_relevance == "Direct")
        if severity:
            query = query.where(self.threat_items.c.severity == severity)
        if source_type:
            query = query.where(self.threat_items.c.source_type == source_type)
        if search:
            search_pattern = f"%{search}%"
            query = query.where(
                sa.or_(
                    self.threat_items.c.title.ilike(search_pattern),
                    self.threat_items.c.summary.ilike(search_pattern),
                    self.threat_items.c.source_name.ilike(search_pattern),
                    self.threat_items.c.enriched_data.ilike(search_pattern),
                )
            )

        query = query.order_by(self.threat_items.c.harvested_at.desc()).limit(limit).offset(offset)

        with self.engine.connect() as conn:
            rows = conn.execute(query).mappings().fetchall()
            items = []
            for row in rows:
                item_dict = dict(row)
                if item_dict.get("enriched_data"):
                    try:
                        item_dict["enriched_parsed"] = json.loads(item_dict["enriched_data"])
                    except Exception:
                        item_dict["enriched_parsed"] = None
                items.append(item_dict)
            return items

    def _get_connection(self):
        """Backward compatibility helper for raw connection context."""
        return self.engine.connect()

    def get_item(self, item_id: str) -> dict[str, Any] | None:
        """Retrieve single threat item by ID or prefix."""
        query = sa.select(self.threat_items).where(self.threat_items.c.id == item_id)
        with self.engine.connect() as conn:
            row = conn.execute(query).mappings().first()
            if not row and len(item_id) >= 4:
                prefix_query = sa.select(self.threat_items).where(
                    self.threat_items.c.id.startswith(item_id)
                ).limit(1)
                row = conn.execute(prefix_query).mappings().first()

            if not row:
                return None
            item_dict = dict(row)
            if item_dict.get("enriched_data"):
                try:
                    item_dict["enriched_parsed"] = json.loads(item_dict["enriched_data"])
                except Exception:
                    item_dict["enriched_parsed"] = None
            return item_dict

    def cleanup_old(self, retention_days: int = 60) -> int:
        """Remove records older than retention_days."""
        threshold = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        stmt = sa.delete(self.threat_items).where(self.threat_items.c.harvested_at < threshold)
        with self.engine.begin() as conn:
            result = conn.execute(stmt)
            return result.rowcount
