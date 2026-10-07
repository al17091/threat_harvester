package harvesters

import (
	"strings"
	"testing"

	"github.com/dapt/information_harvester/backend/internal/config"
	"github.com/dapt/information_harvester/backend/internal/models"
)

func TestIsCTIRelevant(t *testing.T) {
	cases := []struct {
		input    string
		expected bool
	}{
		{"LockBit ransomware gang published stolen data of company", true},
		{"New database dump containing 500k credentials on darknet forum", true},
		{"0day exploit available for enterprise VPN", true},
		{"Japan manufacturing corporation victim of extortion group", true},
		{"Online pharmacy selling cheap sunglasses and vitamins", false},
		{"Personal blog about gardening and cats", false},
	}

	for _, c := range cases {
		got := isCTIRelevant(c.input)
		if got != c.expected {
			t.Errorf("isCTIRelevant(%q) = %v, expected %v", c.input, got, c.expected)
		}
	}
}

func TestDarkwebSearchConfigValidation(t *testing.T) {
	mgr := config.GetSettings()
	err := mgr.AddSource("darkweb_onion", map[string]interface{}{
		"name":      "Tor Search: Japan Ransomware",
		"type":      "search",
		"query":     "japan ransomware leak",
		"directive": "",
	})
	if err != nil {
		t.Fatalf("expected adding search source to succeed, got %v", err)
	}
	defer mgr.DeleteSource("darkweb_onion", "Tor Search: Japan Ransomware")

	cfg := mgr.GetConfig()
	found := false
	for _, dw := range cfg.Sources.DarkwebOnion {
		if dw.Type == "search" && dw.Query == "japan ransomware leak" {
			found = true
			if !strings.Contains(dw.URL, ".onion") {
				t.Errorf("expected default .onion URL to be populated, got %s", dw.URL)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected search source to be registered in DarkwebOnion")
	}
}

func TestDarkwebSourceType(t *testing.T) {
	dw := NewDarkwebOnionHarvester()
	if dw.SourceType() != models.SourceTypeDarkwebOnion {
		t.Errorf("expected %s, got %s", models.SourceTypeDarkwebOnion, dw.SourceType())
	}
	if dw.Name() == "" {
		t.Error("expected non-empty name")
	}
}
