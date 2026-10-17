package harvesters

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/al17091/threat_harvester/backend/internal/config"
	"github.com/al17091/threat_harvester/backend/internal/models"
)

func TestHarvestCISAKEV(t *testing.T) {
	mockJSON := `{
		"title": "CISA Catalog of Known Exploited Vulnerabilities",
		"count": 2,
		"vulnerabilities": [
			{
				"cveID": "CVE-2024-1234",
				"vendorProject": "ExampleVendor",
				"product": "ExampleProduct",
				"vulnerabilityName": "Remote Code Execution",
				"dateAdded": "2024-01-15",
				"shortDescription": "A critical RCE flaw.",
				"knownRansomwareCampaignUse": "Known",
				"notes": "https://example.com/cve-2024-1234"
			},
			{
				"cveID": "CVE-2024-5678",
				"vendorProject": "AnotherVendor",
				"product": "AnotherProduct",
				"vulnerabilityName": "Auth Bypass",
				"dateAdded": "2024-02-01",
				"shortDescription": "Authentication bypass vulnerability.",
				"knownRansomwareCampaignUse": "Unknown",
				"notes": ""
			}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockJSON))
	}))
	defer server.Close()

	harvester := NewVendorRSSHarvester()
	feedCfg := config.FeedSourceConfig{
		Name:     "CISA KEV Test",
		URL:      server.URL + "/known_exploited_vulnerabilities.json",
		Category: "global_cert",
		Enabled:  true,
	}

	items, err := harvester.harvestCISAKEV(context.Background(), feedCfg, nil)
	if err != nil {
		t.Fatalf("harvestCISAKEV failed: %v", err)
	}

	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}

	if items[0].SourceType != models.SourceTypeVendorRSS {
		t.Errorf("expected source type VendorRSS, got %s", items[0].SourceType)
	}

	// Verify CVE and metadata
	if cve, ok := items[0].Metadata["cve"].(string); !ok || cve != "CVE-2024-5678" {
		t.Errorf("expected CVE-2024-5678 for most recent item, got %v", items[0].Metadata["cve"])
	}
}

func TestHarvestGitHubAdvisories(t *testing.T) {
	mockJSON := `[
		{
			"ghsa_id": "GHSA-xxxx-yyyy-zzzz",
			"cve_id": "CVE-2024-9999",
			"summary": "Critical Prototype Pollution",
			"description": "Prototype pollution leading to RCE.",
			"severity": "critical",
			"published_at": "2024-03-01T12:00:00Z",
			"html_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz"
		}
	]`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockJSON))
	}))
	defer server.Close()

	harvester := NewVendorRSSHarvester()
	feedCfg := config.FeedSourceConfig{
		Name:     "GitHub Advisories Test",
		URL:      server.URL + "/api.github.com/advisories",
		Category: "global_research",
		Enabled:  true,
	}

	items, err := harvester.harvestGitHubAdvisories(context.Background(), feedCfg, nil)
	if err != nil {
		t.Fatalf("harvestGitHubAdvisories failed: %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}

	if items[0].URL != "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("unexpected URL: %s", items[0].URL)
	}

	if ghsa, ok := items[0].Metadata["ghsa_id"].(string); !ok || ghsa != "GHSA-xxxx-yyyy-zzzz" {
		t.Errorf("expected GHSA ID in metadata, got %v", items[0].Metadata["ghsa_id"])
	}
}
