from worker.models import SourceType, ThreatItem


def test_threat_item_create():
    item = ThreatItem.create(
        source_type=SourceType.VENDOR_RSS,
        source_name="JPCERT/CC",
        title="Test Alert",
        url="https://example.com/alert/1",
        summary="A test security alert",
        metadata={"category": "jp_cert"},
    )
    assert item.id is not None
    assert len(item.id) == 64  # SHA256 hex
    assert item.source_type == SourceType.VENDOR_RSS
    assert item.title == "Test Alert"
    assert item.metadata["category"] == "jp_cert"


def test_threat_item_deterministic_id():
    item1 = ThreatItem.create(
        source_type=SourceType.TELEGRAM,
        source_name="TestChan",
        title="Same title",
        url="https://t.me/test/1",
        summary="Summary",
    )
    item2 = ThreatItem.create(
        source_type=SourceType.TELEGRAM,
        source_name="TestChan",
        title="Same title",
        url="https://t.me/test/1",
        summary="Summary different",
    )
    # The hash should match because source, name, url, title are the same
    assert item1.id == item2.id
