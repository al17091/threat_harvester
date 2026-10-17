import logging

from worker.models import EnrichedThreat
from worker.notifiers.discord import DiscordNotifier
from worker.notifiers.generic_webhook import GenericWebhookNotifier
from worker.notifiers.slack import SlackNotifier

logger = logging.getLogger(__name__)


class NotificationManager:
    """Dispatches threat alerts across all enabled notification channels."""

    def __init__(
        self,
        discord: DiscordNotifier | None = None,
        slack: SlackNotifier | None = None,
        generic: GenericWebhookNotifier | None = None,
    ):
        self.discord = discord or DiscordNotifier()
        self.slack = slack or SlackNotifier()
        self.generic = generic or GenericWebhookNotifier()

    def dispatch(self, threat: EnrichedThreat) -> bool:
        """Send notification to all configured sinks."""
        success_any = False

        if self.discord.webhook_url:
            if self.discord.notify(threat):
                success_any = True

        if self.slack.webhook_url:
            if self.slack.notify(threat):
                success_any = True

        if self.generic.webhook_url:
            if self.generic.notify(threat):
                success_any = True

        # If no sinks configured, return True (dry run)
        if not (self.discord.webhook_url or self.slack.webhook_url or self.generic.webhook_url):
            logger.info(f"[Dry-Run] All notifiers unconfigured. Alert would be: {threat.title_ja}")
            return True

        return success_any


__all__ = [
    "DiscordNotifier",
    "SlackNotifier",
    "GenericWebhookNotifier",
    "NotificationManager",
]
