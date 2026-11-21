package scraper

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/api/internal/analyzer"
	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/models"
	"github.com/al17091/threat_harvester/api/internal/storage"
)

type mockAnalyzer struct {
	analyzer.ThreatAnalyzer
}

func (m *mockAnalyzer) Analyze(ctx context.Context, item models.ThreatItem) (*models.EnrichedThreat, error) {
	return &models.EnrichedThreat{
		ItemID:         item.ID,
		Item:           item,
		Title:          "Enriched: " + item.Title,
		TitleJa:        "エンリッチ: " + item.Title,
		Summary:        "Enriched summary for " + item.Title,
		SummaryJa:      "エンリッチ要約: " + item.Title,
		Severity:       models.SeverityHigh,
		JapanRelevance: models.JapanRelevanceDirect,
		VictimOrgs:     []string{"Target Organization"},
		ThreatActors:   []string{"APT-Mock"},
	}, nil
}

func (m *mockAnalyzer) AnalyzeBatch(ctx context.Context, items []models.ThreatItem) ([]*models.EnrichedThreat, error) {
	var list []*models.EnrichedThreat
	for _, it := range items {
		en, _ := m.Analyze(ctx, it)
		list = append(list, en)
	}
	return list, nil
}

func (m *mockAnalyzer) Name() string { return "mock" }

func TestReEnrich(t *testing.T) {
	ctx := context.Background()
	store, err := storage.NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	defer store.Close()

	// Mock HTTP server serving HTML article
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><body><h1>セキュリティ速報</h1><p>標的型ランサムウェア攻撃により機密情報が流出しました。</p><table><tr><th>CVE</th><th>CVSS</th></tr><tr><td>CVE-2026-9999</td><td>9.8</td></tr></table></body></html>`))
	}))
	defer srv.Close()

	now := time.Now().UTC()
	item := models.ThreatItem{
		ID:          "test-reenrich-1",
		SourceType:  models.SourceTypeVendorRSS,
		SourceName:  "Test Feed",
		Title:       "Test Ransomware Notice",
		URL:         srv.URL + "/alert/1",
		HarvestedAt: now,
		FetchStatus: "pending",
	}

	if err := store.MarkSeen(ctx, item, nil, false); err != nil {
		t.Fatalf("MarkSeen failed: %v", err)
	}

	cfg := config.ScraperConfig{
		Enabled:                true,
		ClearnetEnabled:        true,
		ClearnetConcurrency:    2,
		ClearnetTimeoutSeconds: 5,
		AutoReAnalyze:          true,
	}
	netCfg := config.NetworkConfig{}

	mgr := NewScraperManager(store, &mockAnalyzer{}, cfg, netCfg)

	summary, err := mgr.ReEnrich(ctx, 7, 10, true)
	if err != nil {
		t.Fatalf("ReEnrich failed: %v", err)
	}

	if summary.Processed != 1 {
		t.Errorf("Expected 1 processed, got %d", summary.Processed)
	}
	if summary.ScrapedSuccess != 1 {
		t.Errorf("Expected 1 scraped success, got %d", summary.ScrapedSuccess)
	}
	if summary.IncidentsUpdated != 1 {
		t.Errorf("Expected 1 incident updated, got %d", summary.IncidentsUpdated)
	}

	// Verify item in store was updated with raw_content
	gotItem, err := store.GetItem(ctx, "test-reenrich-1")
	if err != nil || gotItem == nil {
		t.Fatalf("GetItem failed: %v", err)
	}
	if gotItem["fetch_status"] != "completed" {
		t.Errorf("Expected fetch_status=completed, got %v", gotItem["fetch_status"])
	}
}
