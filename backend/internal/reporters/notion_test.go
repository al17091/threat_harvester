package reporters

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/backend/internal/config"
	"github.com/al17091/threat_harvester/backend/internal/models"
)

func TestNotionReporter(t *testing.T) {
	ctx := context.Background()
	reporter := NewNotionReporter()

	origConfig := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origConfig)

	// 1. IsConfigured test
	cfg := origConfig
	cfg.Sinks.Notion.Enabled = false
	cfg.Sinks.Notion.APIKey = ""
	cfg.Sinks.Notion.DatabaseID = ""
	config.GetSettings().SetConfig(cfg)

	if reporter.IsConfigured() {
		t.Errorf("Expected IsConfigured to be false")
	}

	// 2. Dry-Run / unconfigured error
	threat := &models.EnrichedThreat{
		TitleJa: "テスト脅威",
	}
	_, err := reporter.CreateIncidentPage(ctx, threat)
	if err == nil {
		t.Errorf("Expected error when notion is unconfigured")
	}

	// 3. Successful creation with rich properties and children
	var receivedPayload map[string]interface{}
	var authHeader string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedPayload)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"page-notion-12345"}`))
	}))
	defer ts.Close()

	reporter.baseURL = ts.URL
	cfg.Sinks.Notion.Enabled = true
	cfg.Sinks.Notion.APIKey = "secret_notion_key_123"
	cfg.Sinks.Notion.DatabaseID = "database-id-xyz"
	config.GetSettings().SetConfig(cfg)

	if !reporter.IsConfigured() {
		t.Errorf("Expected IsConfigured to be true")
	}

	pubDate := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	fullThreat := &models.EnrichedThreat{
		ItemID: "threat-notion-1",
		Item: models.ThreatItem{
			ID:          "threat-notion-1",
			SourceName:  "JPCERT/CC",
			SourceType:  models.SourceTypeVendorRSS,
			URL:         "https://example.com/notion/advisory",
			PublishedAt: &pubDate,
		},
		Title:                "Notion Test Threat EN",
		TitleJa:              "Notion テスト脅威 JA",
		SummaryJa:            "テスト脅威の概要です。",
		Severity:             models.SeverityCritical,
		JapanRelevance:       models.JapanRelevanceDirect,
		AttackType:           "Ransomware",
		VictimOrgs:           []string{"Company A", "Company B", "Company C", "Company D", "Company E", "Company F"},
		ThreatActors:         []string{"Actor A", "Actor B", "Actor C", "Actor D", "Actor E", "Actor F"},
		ImpactAnalysisJa:     "国内組織への広範囲な影響が想定されます。",
		RecommendedActionsJa: []string{"パッチ適用", "EIR手順の確認", "ログ調査", "アクセス制限", "バックアップ確認", "追加対策"},
	}

	pageID, err := reporter.CreateIncidentPage(ctx, fullThreat)
	if err != nil {
		t.Fatalf("CreateIncidentPage failed: %v", err)
	}
	if pageID != "page-notion-12345" {
		t.Errorf("Expected page id page-notion-12345, got %s", pageID)
	}
	if authHeader != "Bearer secret_notion_key_123" {
		t.Errorf("Expected Bearer secret_notion_key_123, got %s", authHeader)
	}
	if receivedPayload == nil {
		t.Fatalf("Received payload should not be nil")
	}

	// 4. Notion API Error (400)
	tsErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"object":"error","message":"Invalid request"}`))
	}))
	defer tsErr.Close()

	reporter.baseURL = tsErr.URL
	_, err = reporter.CreateIncidentPage(ctx, fullThreat)
	if err == nil {
		t.Errorf("Expected error on Notion 400 response")
	}

	// 5. Network error
	reporter.baseURL = "http://127.0.0.1:9"
	_, err = reporter.CreateIncidentPage(ctx, fullThreat)
	if err == nil {
		t.Errorf("Expected error on network failure")
	}
}
