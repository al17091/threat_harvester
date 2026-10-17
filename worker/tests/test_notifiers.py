from unittest.mock import MagicMock

from worker.models import EnrichedThreat, JapanRelevance, Severity, SourceType, ThreatItem
from worker.notifiers import NotificationManager
from worker.notifiers.generic_webhook import GenericWebhookNotifier
from worker.notifiers.slack import SlackNotifier


def _make_threat():
    item = ThreatItem.create(
        source_type=SourceType.VENDOR_RSS,
        source_name="JPCERT",
        title="Test Incident",
        url="https://example.com/test",
        summary="A test incident",
    )
    return EnrichedThreat(
        item_id=item.id,
        item=item,
        severity=Severity.HIGH,
        japan_relevance=JapanRelevance.DIRECT,
        title_ja="テストインシデント",
        summary_ja="要約",
        impact_analysis_ja="影響",
        victim_orgs=["組織A"],
        threat_actors=["ActorX"],
    )


def test_slack_notifier(monkeypatch):
    notifier = SlackNotifier(webhook_url="https://hooks.slack.com/services/XXX")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    monkeypatch.setattr("requests.post", lambda url, json, timeout: mock_resp)

    threat = _make_threat()
    assert notifier.notify(threat) is True


def test_generic_webhook(monkeypatch):
    notifier = GenericWebhookNotifier(webhook_url="https://webhook.site/test")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    monkeypatch.setattr("requests.post", lambda url, json, headers, timeout: mock_resp)

    threat = _make_threat()
    assert notifier.notify(threat) is True


def test_notification_manager(monkeypatch):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    monkeypatch.setattr("requests.post", lambda *args, **kwargs: mock_resp)

    discord = MagicMock()
    discord.webhook_url = "https://discord.com/api/webhooks/xxx"
    discord.notify.return_value = True

    slack = MagicMock()
    slack.webhook_url = "https://hooks.slack.com/xxx"
    slack.notify.return_value = True

    manager = NotificationManager(discord=discord, slack=slack)
    threat = _make_threat()
    assert manager.dispatch(threat) is True
    discord.notify.assert_called_once_with(threat)
    slack.notify.assert_called_once_with(threat)
