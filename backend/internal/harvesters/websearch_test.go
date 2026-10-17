package harvesters

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/al17091/threat_harvester/backend/internal/config"
	"github.com/al17091/threat_harvester/backend/internal/models"
)

func TestWebSearchSearXNG(t *testing.T) {
	mockSearxng := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if q == "" {
			t.Errorf("Expected query parameter 'q', got none")
		}

		resp := searxngResponse{
			Query: q,
			Results: []searxngResult{
				{
					Title:         "Japan Critical Breach Advisory",
					URL:           "https://example.com/japan-breach-news",
					Content:       "Japanese enterprise suffered ransomware attack and data leak.",
					Engine:        "google",
					Engines:       []string{"google", "bing"},
					PublishedDate: "2026-10-15T12:00:00Z",
				},
				{
					Title:         "Darknet Onion Leak Should Be Excluded from Clearnet Web Search",
					URL:           "http://evilvaultleak7777777777.onion/victim-corp",
					Content:       "Ransomware leak post on onion site.",
					Engine:        "ahmia",
					PublishedDate: "2026-10-15T10:00:00Z",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockSearxng.Close()

	qCfg := config.QuerySourceConfig{
		Name:           "Test SearXNG Clearnet Web",
		Query:          "japan cyber attack",
		Type:           "searxng",
		URL:            mockSearxng.URL,
		ComplianceTier: config.TierCommercialViaOfficialAPI,
		Enabled:        true,
	}

	jobs := []searchJob{
		{query: "japan cyber attack", directive: "", displayName: "Test SearXNG Clearnet Web"},
	}

	harvester := NewWebSearchHarvester()
	items, err := harvester.harvestSearXNGWeb(context.Background(), qCfg, jobs, nil)
	if err != nil {
		t.Fatalf("harvestSearXNGWeb returned error: %v", err)
	}

	if len(items) != 1 {
		t.Fatalf("Expected exactly 1 clearnet item (onion filtered out), got %d", len(items))
	}

	item := items[0]
	if item.SourceType != models.SourceTypeWebSearch {
		t.Errorf("Expected SourceTypeWebSearch, got %v", item.SourceType)
	}
	if item.URL != "https://example.com/japan-breach-news" {
		t.Errorf("Unexpected URL: %s", item.URL)
	}
	if item.Metadata["fetch_status"] != "pending" {
		t.Errorf("Expected fetch_status pending, got %v", item.Metadata["fetch_status"])
	}
	if item.Metadata["is_onion"] != false {
		t.Errorf("Expected is_onion to be false for web search, got %v", item.Metadata["is_onion"])
	}
}

