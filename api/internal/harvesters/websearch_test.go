package harvesters

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/models"
)

func TestWebSearchSearXNG(t *testing.T) {
	var mockSearxng *httptest.Server
	mockSearxng = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/japan-breach-news" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write([]byte(`<!DOCTYPE html><html><body><article class="article-body"><h1>Japan Critical Breach Advisory</h1><p>Japanese enterprise suffered ransomware attack and extensive data leak affecting 500,000 customers across Tokyo branches. Threat actors gained initial access through vulnerable VPN endpoints.</p></article></body></html>`))
			return
		}

		q := r.URL.Query().Get("q")
		if q == "" {
			t.Errorf("Expected query parameter 'q', got none")
		}

		resp := searxngResponse{
			Query: q,
			Results: []searxngResult{
				{
					Title:         "Japan Critical Breach Advisory",
					URL:           mockSearxng.URL + "/japan-breach-news",
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
	if item.URL != mockSearxng.URL+"/japan-breach-news" {
		t.Errorf("Unexpected URL: %s", item.URL)
	}
	// Verify actual web access (実アクセス) succeeded and extracted full article text
	if item.Metadata["fetch_status"] != "completed" {
		t.Errorf("Expected fetch_status completed, got %v (error: %v)", item.Metadata["fetch_status"], item.Metadata["fetch_error"])
	}
	if !strings.Contains(item.RawContent, "extensive data leak affecting 500,000 customers") {
		t.Errorf("Expected RawContent to contain full article text, got: %s", item.RawContent)
	}
	// Verify internal query string leak is eliminated
	if strings.Contains(item.RawContent, "[SearXNG Query:") {
		t.Errorf("RawContent leaked [SearXNG Query:]: %s", item.RawContent)
	}
	if item.Metadata["is_onion"] != false {
		t.Errorf("Expected is_onion to be false for web search, got %v", item.Metadata["is_onion"])
	}
}

