import logging
from abc import ABC, abstractmethod
from datetime import datetime

from backend.models import SourceType, ThreatItem

logger = logging.getLogger(__name__)


class BaseHarvester(ABC):
    """Abstract base class for threat information collectors."""

    def __init__(self, name: str, source_type: SourceType):
        self.name = name
        self.source_type = source_type

    @abstractmethod
    def harvest(self, since: datetime | None = None) -> list[ThreatItem]:
        """Harvest threat items published or detected since the specified time."""

    @abstractmethod
    def test_connection(self) -> bool:
        """Verify reachability and configuration for this source."""
