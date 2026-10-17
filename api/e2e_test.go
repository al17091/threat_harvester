package main_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/al17091/threat_harvester/api/internal/analyzer"
	"github.com/al17091/threat_harvester/api/internal/api"
	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/models"
	"github.com/al17091/threat_harvester/api/internal/pipeline"
	"github.com/al17091/threat_harvester/api/internal/storage"
)

type mockE2EAnalyzer struct{}

func (m *mockE2EAnalyzer) Analyze(ctx context.Context, item models.ThreatItem) (*models.EnrichedThreat, error) {
	return &models.EnrichedThreat{
		ItemID:           item.ID,
		Title:            item.Title,
		TitleJa:          "【緊急】" + item.Title,
		Summary:          item.Summary,
		SummaryJa:        "要約: " + item.Summary,
		ImpactAnalysis:   "Significant business disruption",
		ImpactAnalysisJa: "甚大な業務影響のおそれ",
		Severity:         models.SeverityCritical,
		JapanRelevance:   models.JapanRelevanceDirect,
		AttackType:       "Ransomware",
		ThreatActors:     []string{"LockBit"},
		VictimOrgs:       []string{"Cyber Defense Inc"},
		CVEs:             []string{"CVE-2024-9999"},
		AffectedProducts: []string{"Firewall OS"},
	}, nil
}

func (m *mockE2EAnalyzer) AnalyzeBatch(ctx context.Context, items []models.ThreatItem) ([]*models.EnrichedThreat, error) {
	results := make([]*models.EnrichedThreat, len(items))
	for i, it := range items {
		res, _ := m.Analyze(ctx, it)
		results[i] = res
	}
	return results, nil
}

func (m *mockE2EAnalyzer) GenerateSearchQueries(ctx context.Context, directive, targetDesc string, count int) ([]string, error) {
	return []string{directive}, nil
}

func (m *mockE2EAnalyzer) TranslateIncident(ctx context.Context, input analyzer.IncidentTranslationInput) (*analyzer.IncidentTranslationOutput, error) {
	return &analyzer.IncidentTranslationOutput{
		ID:             input.ID,
		Title:          "Translated " + input.Title,
		Summary:        "Translated " + input.Summary,
		ImpactAnalysis: "Translated " + input.ImpactAnalysis,
	}, nil
}

func (m *mockE2EAnalyzer) TranslateIncidentFields(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	return "Translated " + title, "Translated " + summary, "Translated " + impact, actions, nil
}

func (m *mockE2EAnalyzer) TranslateFieldsToJapanese(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	return title, summary, impact, actions, nil
}

func (m *mockE2EAnalyzer) LocalizeThreatToJapanese(ctx context.Context, enriched *models.EnrichedThreat) error {
	return nil
}

func (m *mockE2EAnalyzer) TranslateBatch(ctx context.Context, items []analyzer.BatchTranslateItem) ([]analyzer.BatchTranslateResult, error) {
	var results []analyzer.BatchTranslateResult
	for _, it := range items {
		results = append(results, analyzer.BatchTranslateResult{
			ID:             it.ID,
			Title:          "Translated " + it.Title,
			Summary:        "Translated " + it.Summary,
			ImpactAnalysis: "Translated " + it.ImpactAnalysis,
		})
	}
	return results, nil
}

func TestE2EPipelineAndAPI(t *testing.T) {
	// 1. Setup mock RSS Server
	rssXML := `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Security Alerts Feed</title>
    <link>https://example.com</link>
    <description>Latest Security Advisories</description>
    <item>
      <title>LockBit claims attack on Cyber Defense Inc exploiting CVE-2024-9999</title>
      <link>https://example.com/alerts/lockbit-incident</link>
      <description>LockBit ransomware group published data allegedly stolen from Cyber Defense Inc.</description>
      <pubDate>Mon, 17 Oct 2026 12:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/rss+xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(rssXML))
	}))
	defer ts.Close()

	// 2. Configure mock feed in Settings
	origCfg := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origCfg)

	cfg := origCfg
	cfg.Sources.VendorRSS = []config.FeedSourceConfig{
		{
			Name:           "Mock E2E Feed",
			URL:            ts.URL,
			Category:       "jp_cert",
			ComplianceTier: config.TierCommercialReady,
			Enabled:        true,
		},
	}
	cfg.Sources.DarkwebOnion = nil
	cfg.Sources.Telegram = nil
	cfg.Sources.RansomwareTracker = nil
	cfg.Sources.XMonitor = nil
	cfg.Sources.WebSearch = nil
	config.GetSettings().SetConfig(cfg)

	// 3. Initialize in-memory storage
	ctx := context.Background()
	store, err := storage.NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	// 4. Run pipeline
	pipe := pipeline.NewPipeline(store)
	pipe.SetAnalyzer(&mockE2EAnalyzer{})

	summary, err := pipe.RunAll(ctx, 24, false)
	if err != nil {
		t.Fatalf("pipeline RunAll failed: %v", err)
	}
	if summary.TotalHarvested == 0 {
		t.Fatalf("expected at least 1 harvested threat item, got 0")
	}

	// 5. Initialize API Server and verify endpoints
	srv := api.NewServer(store)
	srv.StartScheduler(ctx) // triggers initial background workers with pre-configured store

	// (a) GET /api/incidents
	req := httptest.NewRequest(http.MethodGet, "/api/incidents", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/incidents returned status %d (body: %s)", w.Code, w.Body.String())
	}

	var incResp struct {
		Items []map[string]interface{} `json:"items"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &incResp); err != nil {
		t.Fatalf("failed to parse incidents response: %v", err)
	}
	if incResp.Total < 1 || len(incResp.Items) < 1 {
		t.Fatalf("expected at least 1 incident, got %d (list len: %d)", incResp.Total, len(incResp.Items))
	}

	firstInc := incResp.Items[0]
	incidentID, ok := firstInc["id"].(string)
	if !ok || incidentID == "" {
		t.Fatalf("incident missing id: %+v", firstInc)
	}

	// (b) GET /api/incidents/{id}
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/incidents/%s?lang=ja", incidentID), nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/incidents/%s returned status %d", incidentID, w.Code)
	}

	// (c) GET /rss
	req = httptest.NewRequest(http.MethodGet, "/rss", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /rss returned status %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("LockBit")) {
		t.Errorf("expected RSS feed to contain LockBit")
	}

	// (d) GET /api/stats/entities
	req = httptest.NewRequest(http.MethodGet, "/api/stats/entities", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/stats/entities returned status %d", w.Code)
	}

	// (e) POST /api/incidents/{id}/update
	updateBody, _ := json.Marshal(map[string]interface{}{
		"threat_actors":   []string{"LockBit 3.0"},
		"severity":        "Critical",
		"japan_relevance": "Direct",
		"attack_type":     "Double Extortion Ransomware",
		"victim_org":      "Cyber Defense Inc",
	})
	req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/incidents/%s/update", incidentID), bytes.NewReader(updateBody))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/incidents/%s/update returned status %d (body: %s)", incidentID, w.Code, w.Body.String())
	}

	// (f) POST /api/pipeline/translate-incidents
	req = httptest.NewRequest(http.MethodPost, "/api/pipeline/translate-incidents", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/pipeline/translate-incidents returned status %d", w.Code)
	}
}
