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
