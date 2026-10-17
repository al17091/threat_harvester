package config

import (
	"os"
	"strings"
	"testing"
)

func TestEnvInterpolation(t *testing.T) {
	os.Setenv("TEST_VAR", "my_secret")
	defer os.Unsetenv("TEST_VAR")

	expanded := expandEnvVars("url: ${TEST_VAR}")
	if expanded != "url: my_secret" {
		t.Fatalf("expected 'url: my_secret', got '%s'", expanded)
	}

	expandedDefault := expandEnvVars("url: ${NON_EXISTENT_VAR:-fallback_value}")
	if expandedDefault != "url: fallback_value" {
		t.Fatalf("expected 'url: fallback_value', got '%s'", expandedDefault)
	}
}

func TestSourceMutationAndExport(t *testing.T) {
	mgr := GetSettings()

	// Add source
	err := mgr.AddSource("vendor_rss", map[string]interface{}{
		"name":     "Test Feed",
		"url":      "https://example.com/rss",
		"category": "test",
	})
	if err != nil {
		t.Fatalf("AddSource failed: %v", err)
	}

	// Toggle source
	toggled := mgr.ToggleSource("vendor_rss", "https://example.com/rss", false)
	if !toggled {
		t.Fatal("expected toggle to succeed")
	}

	// Update source
	err = mgr.UpdateSource("vendor_rss", "https://example.com/rss", map[string]interface{}{
		"name":     "Updated Feed Name",
		"category": "threat_intel",
	})
	if err != nil {
		t.Fatalf("UpdateSource failed: %v", err)
	}

	// Export YAML
	yamlStr := mgr.ExportYAML(true)
	if !strings.Contains(yamlStr, "Updated Feed Name") {
		t.Fatal("expected exported YAML to contain updated feed name")
	}

	// Delete source
	deleted := mgr.DeleteSource("vendor_rss", "https://example.com/rss")
	if !deleted {
		t.Fatal("expected delete to succeed")
	}
}

func TestComplianceControl(t *testing.T) {
	mgr := GetSettings()

	// Test preset modes
	_ = mgr.SetComplianceMode(ComplianceModeCommercialOnly)
	cfg := mgr.GetConfig()
	if !cfg.Compliance.Tiers.CommercialReady || cfg.Compliance.Tiers.CommercialViaOfficialAPI ||
		cfg.Compliance.Tiers.ToSRestricted || cfg.Compliance.Tiers.DarkwebAccess {
		t.Fatalf("unexpected tiers for commercial_only: %+v", cfg.Compliance.Tiers)
	}

	// Commercial item enabled
	if !mgr.IsSourceActive("vendor_rss", true, TierCommercialReady) {
		t.Fatal("expected commercial_ready item to be active in commercial_only mode")
	}
	// Telegram / ToS restricted item disabled
	if mgr.IsSourceActive("telegram", true, TierToSRestricted) {
		t.Fatal("expected tos_restricted item to be inactive in commercial_only mode")
	}
	// Darkweb item disabled
	if mgr.IsSourceActive("darkweb_onion", true, TierDarkwebAccess) {
		t.Fatal("expected darkweb_access item to be inactive in commercial_only mode")
	}

	// Test Official API Ready mode
	_ = mgr.SetComplianceMode(ComplianceModeOfficialAPIReady)
	if !mgr.IsSourceActive("x_monitor", true, TierCommercialViaOfficialAPI) {
		t.Fatal("expected commercial_via_official_api item to be active in official_api_ready mode")
	}
	if mgr.IsSourceActive("darkweb_onion", true, TierDarkwebAccess) {
		t.Fatal("expected darkweb_access item to be inactive in official_api_ready mode")
	}

	// Test Individual Tier Toggle
	_ = mgr.ToggleComplianceTier(TierDarkwebAccess, true)
	if !mgr.IsSourceActive("darkweb_onion", true, TierDarkwebAccess) {
		t.Fatal("expected darkweb_access item to be active after toggling on")
	}

	// Test Individual Source Item Toggle overrides tier
	if mgr.IsSourceActive("darkweb_onion", false, TierDarkwebAccess) {
		t.Fatal("expected item to be inactive if its individual enabled flag is false")
	}

	// Summary check
	summary := mgr.GetComplianceSummary()
	if summary["mode"] == "" {
		t.Fatal("expected summary to include mode")
	}

	// Reset to All
	_ = mgr.SetComplianceMode(ComplianceModeAll)
}

func TestDarkwebAndRansomwareTrackerConfig(t *testing.T) {
	mgr := GetSettings()

	// Non-onion darkweb must fail
	err := mgr.AddSource("darkweb_onion", map[string]interface{}{
		"name": "Invalid Clearnet Darkweb",
		"url":  "https://clearnet.example.com/feed.xml",
	})
	if err == nil {
		t.Fatal("expected error when adding non-onion darkweb source")
	}

	// Valid onion darkweb must succeed
	onionURL := "http://exampledarkwebhidden5xyz.onion/posts.rss"
	err = mgr.AddSource("darkweb_onion", map[string]interface{}{
		"name": "Valid Onion Site",
		"url":  onionURL,
	})
	if err != nil {
		t.Fatalf("expected adding onion darkweb source to succeed, got: %v", err)
	}
	defer mgr.DeleteSource("darkweb_onion", onionURL)

	// Ransomware tracker clearnet must succeed
	rwURL := "https://api.ransomtracker.test/recent"
	err = mgr.AddSource("ransomware_tracker", map[string]interface{}{
		"name": "Ransomware Test Tracker",
		"url":  rwURL,
		"type": "api",
	})
	if err != nil {
		t.Fatalf("expected adding ransomware_tracker to succeed, got: %v", err)
	}

	// Verify toggle and delete for ransomware_tracker
	if !mgr.ToggleSource("ransomware_tracker", rwURL, false) {
		t.Fatal("expected ToggleSource on ransomware_tracker to succeed")
	}
	if !mgr.DeleteSource("ransomware_tracker", rwURL) {
		t.Fatal("expected DeleteSource on ransomware_tracker to succeed")
	}
}

func TestToSafeMapAndMasking(t *testing.T) {
	mgr := GetSettings()
	origCfg := mgr.GetConfig()
	defer mgr.SetConfig(origCfg)

	cfg := origCfg
	cfg.AI.GeminiAPIKey = "AIzaSySecretLongKey12345"
	cfg.Database.Password = "SuperSecretDBPassword"
	cfg.Sinks.Discord.WebhookURL = "https://discord.com/api/webhooks/123/token-secret"
	cfg.Sinks.Slack.WebhookURL = "https://hooks.slack.com/services/T00/B00/secret-token"
	cfg.Sinks.GenericWebhook.WebhookURL = "https://example.com/webhook/secret"
	cfg.Sinks.Notion.APIKey = "secret_notion_api_key_long"
	mgr.SetConfig(cfg)

	safeMap := mgr.ToSafeMap()
	if safeMap == nil {
		t.Fatal("expected non-nil safe map")
	}

	aiMap, ok := safeMap["ai"].(map[string]interface{})
	if !ok {
		t.Fatal("expected ai section in safe map")
	}
	if geminiKey, ok := aiMap["gemini_api_key"].(string); !ok || !strings.Contains(geminiKey, "...") {
		t.Errorf("expected masked gemini_api_key, got %v", geminiKey)
	}

	dbMap, ok := safeMap["database"].(map[string]interface{})
	if !ok {
		t.Fatal("expected database section in safe map")
	}
	if dbPass, ok := dbMap["password"].(string); !ok || dbPass != "******" {
		t.Errorf("expected masked database password, got %v", dbPass)
	}

	// Also verify ExportYAML masking
	maskedYAML := mgr.ExportYAML(true)
	if !strings.Contains(maskedYAML, "https://...[masked]") {
		t.Errorf("expected masked webhook url in ExportYAML")
	}
}

func TestGetDefaultTierForSource(t *testing.T) {
	if tier := GetDefaultTierForSource("darkweb_onion", ""); tier != TierDarkwebAccess {
		t.Errorf("expected TierDarkwebAccess, got %s", tier)
	}
	if tier := GetDefaultTierForSource("telegram", ""); tier != TierToSRestricted {
		t.Errorf("expected TierToSRestricted, got %s", tier)
	}
	if tier := GetDefaultTierForSource("x_monitor", ""); tier != TierCommercialViaOfficialAPI {
		t.Errorf("expected TierCommercialViaOfficialAPI, got %s", tier)
	}
	if tier := GetDefaultTierForSource("ransomware_tracker", "api"); tier != TierCommercialViaOfficialAPI {
		t.Errorf("expected TierCommercialViaOfficialAPI, got %s", tier)
	}
	if tier := GetDefaultTierForSource("ransomware_tracker", "scrape"); tier != TierCommercialReady {
		t.Errorf("expected TierCommercialReady, got %s", tier)
	}
	if tier := GetDefaultTierForSource("vendor_rss", ""); tier != TierCommercialReady {
		t.Errorf("expected TierCommercialReady, got %s", tier)
	}
	if tier := GetDefaultTierForSource("unknown", ""); tier != TierCommercialReady {
		t.Errorf("expected TierCommercialReady for unknown source, got %s", tier)
	}
}

func TestSaveAndReloadConfig(t *testing.T) {
	mgr := GetSettings()
	tmpFile, err := os.CreateTemp("", "test_config_*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	if err := mgr.Save(tmpFile.Name()); err != nil {
		t.Fatalf("failed to save config: %v", err)
	}

	if err := mgr.Reload(tmpFile.Name()); err != nil {
		t.Fatalf("failed to reload config from saved file: %v", err)
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	mgr := GetSettings()
	origCfg := mgr.GetConfig()
	defer mgr.SetConfig(origCfg)

	os.Setenv("DB_PORT", "5433")
	os.Setenv("LITELLM_ENDPOINT", "http://custom-litellm.local/v1")
	os.Setenv("GEMINI_API_KEY", "env-gemini-key")
	os.Setenv("DISCORD_WEBHOOK_URL", "https://discord.com/api/webhooks/env")
	os.Setenv("SLACK_WEBHOOK_URL", "https://slack.com/env")
	os.Setenv("NOTION_API_KEY", "env-notion-key")
	os.Setenv("NOTION_DATABASE_ID", "env-notion-db")
	os.Setenv("COMPLIANCE_MODE", "strict")

	defer func() {
		os.Unsetenv("DB_PORT")
		os.Unsetenv("LITELLM_ENDPOINT")
		os.Unsetenv("GEMINI_API_KEY")
		os.Unsetenv("DISCORD_WEBHOOK_URL")
		os.Unsetenv("SLACK_WEBHOOK_URL")
		os.Unsetenv("NOTION_API_KEY")
		os.Unsetenv("NOTION_DATABASE_ID")
		os.Unsetenv("COMPLIANCE_MODE")
	}()

	mgr.applyEnvOverrides()
	cfg := mgr.GetConfig()

	if cfg.Database.Port != 5433 {
		t.Errorf("expected database port 5433, got %d", cfg.Database.Port)
	}
	if cfg.AI.Endpoint != "http://custom-litellm.local/v1" {
		t.Errorf("expected custom endpoint, got %s", cfg.AI.Endpoint)
	}
	if cfg.AI.GeminiAPIKey != "env-gemini-key" {
		t.Errorf("expected env-gemini-key, got %s", cfg.AI.GeminiAPIKey)
	}
	if cfg.Sinks.Discord.WebhookURL != "https://discord.com/api/webhooks/env" {
		t.Errorf("expected env discord webhook, got %s", cfg.Sinks.Discord.WebhookURL)
	}
	if cfg.Compliance.Mode != "strict" {
		t.Errorf("expected compliance mode strict, got %s", cfg.Compliance.Mode)
	}
}

func TestSourceMutationsAllTypes(t *testing.T) {
	mgr := GetSettings()

	// 1. web_search
	wsErr := mgr.AddSource("web_search", map[string]interface{}{
		"name":      "Test Web Search",
		"query":     "cyber attack japan",
		"directive": "daily",
	})
	if wsErr != nil {
		t.Fatalf("AddSource web_search failed: %v", wsErr)
	}
	if !mgr.ToggleSource("web_search", "cyber attack japan", false) {
		t.Errorf("ToggleSource web_search failed")
	}
	if err := mgr.UpdateSource("web_search", "cyber attack japan", map[string]interface{}{"directive": "weekly"}); err != nil {
		t.Errorf("UpdateSource web_search failed: %v", err)
	}
	if !mgr.DeleteSource("web_search", "cyber attack japan") {
		t.Errorf("DeleteSource web_search failed")
	}

	// 2. telegram
	tgErr := mgr.AddSource("telegram", map[string]interface{}{
		"channel": "tg_cyber_intel",
		"name":    "Test TG",
	})
	if tgErr != nil {
		t.Fatalf("AddSource telegram failed: %v", tgErr)
	}
	if !mgr.ToggleSource("telegram", "tg_cyber_intel", false) {
		t.Errorf("ToggleSource telegram failed")
	}
	if err := mgr.UpdateSource("telegram", "tg_cyber_intel", map[string]interface{}{"name": "Updated TG"}); err != nil {
		t.Errorf("UpdateSource telegram failed: %v", err)
	}
	if !mgr.DeleteSource("telegram", "tg_cyber_intel") {
		t.Errorf("DeleteSource telegram failed")
	}

	// 3. x_monitor
	xmErr := mgr.AddSource("x_monitor", map[string]interface{}{
		"name":  "X Monitor Test",
		"query": "malware analysis",
	})
	if xmErr != nil {
		t.Fatalf("AddSource x_monitor failed: %v", xmErr)
	}
	if !mgr.ToggleSource("x_monitor", "malware analysis", false) {
		t.Errorf("ToggleSource x_monitor failed")
	}
	if err := mgr.UpdateSource("x_monitor", "malware analysis", map[string]interface{}{"name": "Updated X"}); err != nil {
		t.Errorf("UpdateSource x_monitor failed: %v", err)
	}
	if !mgr.DeleteSource("x_monitor", "malware analysis") {
		t.Errorf("DeleteSource x_monitor failed")
	}
}

func TestComplianceTiersAndSummary(t *testing.T) {
	mgr := GetSettings()

	// UpdateCompliance
	tiers := ComplianceTiersConfig{
		CommercialReady:          true,
		CommercialViaOfficialAPI: true,
		ToSRestricted:            false,
		DarkwebAccess:            false,
	}
	if err := mgr.UpdateCompliance("custom", tiers); err != nil {
		t.Fatalf("UpdateCompliance failed: %v", err)
	}
	summary := mgr.GetComplianceSummary()
	if summary["mode"] != "custom" {
		t.Errorf("expected custom mode, got %v", summary["mode"])
	}

	// ToggleComplianceTier
	if err := mgr.ToggleComplianceTier(TierToSRestricted, true); err != nil {
		t.Fatalf("ToggleComplianceTier failed: %v", err)
	}
	if err := mgr.ToggleComplianceTier("invalid_tier", true); err == nil {
		t.Errorf("expected error toggling invalid tier")
	}
}

func TestConfigErrorHandlingAndInvalidInputs(t *testing.T) {
	mgr := GetSettings()

	// SetComplianceMode applies mode and returns nil
	if err := mgr.SetComplianceMode("strict"); err != nil {
		t.Errorf("expected nil for SetComplianceMode, got: %v", err)
	}

	// Reload handles missing file gracefully without crashing
	if err := mgr.Reload("this_file_does_not_exist_at_all.yaml"); err != nil {
		t.Errorf("expected Reload to gracefully handle missing file, got: %v", err)
	}

	// AddSource unknown sourceType
	if err := mgr.AddSource("unknown_type", map[string]interface{}{"name": "foo"}); err == nil {
		t.Errorf("expected error adding unknown source type")
	}

	// UpdateSource unknown sourceType
	if err := mgr.UpdateSource("unknown_type", "ident", map[string]interface{}{"name": "foo"}); err == nil {
		t.Errorf("expected error updating unknown source type")
	}

	// DeleteSource unknown sourceType
	if mgr.DeleteSource("unknown_type", "ident") {
		t.Errorf("expected false deleting unknown source type")
	}

	// ToggleSource unknown sourceType
	if mgr.ToggleSource("unknown_type", "ident", true) {
		t.Errorf("expected false toggling unknown source type")
	}
}


