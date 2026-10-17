import os

from worker.config import Settings, expand_env_vars


def test_expand_env_vars(monkeypatch):
    monkeypatch.setenv("TEST_VAR", "my_secret_token")
    raw = {
        "token": "${TEST_VAR}",
        "host": "${UNSET_HOST:-db.local}",
        "nested": ["${TEST_VAR}", "literal"],
    }
    expanded = expand_env_vars(raw)
    assert expanded["token"] == "my_secret_token"
    assert expanded["host"] == "db.local"
    assert expanded["nested"] == ["my_secret_token", "literal"]


def test_config_source_mutations(tmp_path):
    test_yaml = tmp_path / "test_config.yaml"
    settings = Settings(config_path=str(test_yaml))

    # Add RSS source
    settings.add_source(
        "vendor_rss",
        {"name": "Custom Feed", "url": "https://example.com/rss", "category": "custom"},
    )
    assert any(f.name == "Custom Feed" for f in settings.app_config.sources.vendor_rss)
    assert any(f.name == "Custom Feed" for f in settings.vendor_feeds)

    # Toggle RSS source
    toggled = settings.toggle_source("vendor_rss", "Custom Feed", False)
    assert toggled is True
    assert not any(f.name == "Custom Feed" for f in settings.vendor_feeds)

    # Add Telegram source
    settings.add_source("telegram", {"channel": "test_threat_channel", "enabled": True})
    assert "test_threat_channel" in settings.telegram_channels

    # Toggle Telegram source
    settings.toggle_source("telegram", "test_threat_channel", False)
    assert "test_threat_channel" not in settings.telegram_channels

    # Delete Telegram source
    deleted = settings.delete_source("telegram", "test_threat_channel")
    assert deleted is True
    assert not any(c.channel == "test_threat_channel" for c in settings.app_config.sources.telegram)


def test_config_export_and_save(tmp_path):
    test_yaml = tmp_path / "exported.yaml"
    settings = Settings(config_path=str(test_yaml))
    settings.app_config.ai.gemini_api_key = "super_secret_ai_key"

    # Export masked
    masked_yaml = settings.export_yaml(mask_secrets=True)
    assert "super_secret_ai_key" not in masked_yaml
    assert "********" in masked_yaml

    # Export raw / unmasked
    raw_yaml = settings.export_yaml(mask_secrets=False)
    assert "super_secret_ai_key" in raw_yaml

    # Save to disk
    settings.save(str(test_yaml))
    assert os.path.exists(test_yaml)

    # Reload from disk
    new_settings = Settings(config_path=str(test_yaml))
    assert new_settings.app_config.ai.gemini_api_key == "super_secret_ai_key"
