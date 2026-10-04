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

