package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/api/internal/analyzer"
	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/models"
	"github.com/al17091/threat_harvester/api/internal/storage"
)

type mockAPIAnalyzer struct{}

func (m *mockAPIAnalyzer) Analyze(ctx context.Context, item models.ThreatItem) (*models.EnrichedThreat, error) {
	return &models.EnrichedThreat{ItemID: item.ID, Title: item.Title, Severity: models.SeverityHigh}, nil
}
func (m *mockAPIAnalyzer) AnalyzeBatch(ctx context.Context, items []models.ThreatItem) ([]*models.EnrichedThreat, error) {
	var res []*models.EnrichedThreat
	for _, it := range items {
		res = append(res, &models.EnrichedThreat{ItemID: it.ID, Title: it.Title, Severity: models.SeverityHigh})
	}
	return res, nil
}
func (m *mockAPIAnalyzer) GenerateSearchQueries(ctx context.Context, directive, targetDesc string, count int) ([]string, error) {
	return []string{directive}, nil
}
func (m *mockAPIAnalyzer) TranslateIncident(ctx context.Context, input analyzer.IncidentTranslationInput) (*analyzer.IncidentTranslationOutput, error) {
	return &analyzer.IncidentTranslationOutput{
		ID: input.ID,
		Title: "Translated " + input.Title,
		Summary: "Translated summary",
	}, nil
}
func (m *mockAPIAnalyzer) TranslateIncidentFields(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	return "Translated " + title, "Translated summary", "Translated impact", actions, nil
}
func (m *mockAPIAnalyzer) TranslateFieldsToJapanese(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	return title, summary, impact, actions, nil
}
func (m *mockAPIAnalyzer) LocalizeThreatToJapanese(ctx context.Context, enriched *models.EnrichedThreat) error {
	return nil
}
func (m *mockAPIAnalyzer) TranslateBatch(ctx context.Context, items []analyzer.BatchTranslateItem) ([]analyzer.BatchTranslateResult, error) {
	var res []analyzer.BatchTranslateResult
	for _, it := range items {
		res = append(res, analyzer.BatchTranslateResult{
			ID: it.ID,
			Title: "Translated " + it.Title,
			Summary: "Translated " + it.Summary,
		})
	}
	return res, nil
}


func TestAPIRoutes(t *testing.T) {
	defer os.Remove("config.yaml")
	store, err := storage.NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	mgr := config.GetSettings()
	if mgr != nil && mgr.ConfigPath != "" {
		origConfig, _ := os.ReadFile(mgr.ConfigPath)
		defer func() {
			if len(origConfig) > 0 {
				_ = os.WriteFile(mgr.ConfigPath, origConfig, 0644)
			}
		}()
	}

	srv := NewServer(store)

	// 1. GET /
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 2. GET /api/status
	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 3. GET /api/incidents
	req = httptest.NewRequest(http.MethodGet, "/api/incidents", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 4. GET /api/config
	req = httptest.NewRequest(http.MethodGet, "/api/config", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 5. POST /api/config/sources (add)
	addPayload := map[string]interface{}{
		"source_type": "vendor_rss",
		"action":      "add",
		"data": map[string]interface{}{
			"name": "Unit Test Source",
			"url":  "https://example.com/test_feed.rss",
		},
	}
	b, _ := json.Marshal(addPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/sources", bytes.NewReader(b))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 5b. POST /api/config/sources (update)
	updatePayload := map[string]interface{}{
		"source_type": "vendor_rss",
		"action":      "update",
		"identifier":  "https://example.com/test_feed.rss",
		"data": map[string]interface{}{
			"name":     "Updated Unit Test Source",
			"category": "updated_cat",
		},
	}
	bUpdate, _ := json.Marshal(updatePayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/sources", bytes.NewReader(bUpdate))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 6. POST /api/test/notify
	req = httptest.NewRequest(http.MethodPost, "/api/test/notify", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 7. POST /api/config/compliance (update mode)
	compPayload := map[string]interface{}{
		"mode": "commercial_only",
	}
	bComp, _ := json.Marshal(compPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/compliance", bytes.NewReader(bComp))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 8. POST /api/config/sources (toggle compliance tier)
	tierTogglePayload := map[string]interface{}{
		"action":     "toggle_compliance_tier",
		"identifier": "darkweb_access",
		"enabled":    false,
	}
	bTier, _ := json.Marshal(tierTogglePayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/sources", bytes.NewReader(bTier))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 9. GET /api/feed.xml and GET /rss
	req = httptest.NewRequest(http.MethodGet, "/api/feed.xml", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "application/rss+xml") {
		t.Fatalf("expected RSS content-type, got %s", w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Body.String(), "<rss version=\"2.0\"") {
		t.Fatalf("expected RSS 2.0 root element, got %s", w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/rss", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on /rss, got %d", w.Code)
	}

	// 9b. GET /api/rss?lang=ja and /api/rss?lang=en
	reqJa := httptest.NewRequest(http.MethodGet, "/api/rss?lang=ja", nil)
	wJa := httptest.NewRecorder()
	srv.ServeHTTP(wJa, reqJa)
	if wJa.Code != http.StatusOK || !strings.Contains(wJa.Body.String(), "<language>ja</language>") {
		t.Fatalf("expected Japanese RSS feed with <language>ja</language>, got code %d body %s", wJa.Code, wJa.Body.String())
	}

	reqEn := httptest.NewRequest(http.MethodGet, "/api/rss?lang=en", nil)
	wEn := httptest.NewRecorder()
	srv.ServeHTTP(wEn, reqEn)
	if wEn.Code != http.StatusOK || !strings.Contains(wEn.Body.String(), "<language>en</language>") {
		t.Fatalf("expected English RSS feed with <language>en</language>, got code %d body %s", wEn.Code, wEn.Body.String())
	}
}

func TestAPIIncidentEndpoints(t *testing.T) {
	defer os.Remove("config.yaml")
	store, _ := storage.NewStore("", ":memory:")
	defer store.Close()

	srv := NewServer(store)
	ctx := context.Background()

	// Seed an incident
	now := time.Now().UTC()
	item := models.ThreatItem{
		ID:          "api-item-1",
		Title:       "Test Advisory API",
		URL:         "https://example.com/api-test",
		Summary:     "Test Summary",
		PublishedAt: &now,
		HarvestedAt: now,
	}
	enriched := &models.EnrichedThreat{
		ItemID:         "api-item-1",
		Item:           item,
		Title:          "Test Advisory API EN",
		TitleJa:        "テストアドバイザリ API JA",
		Severity:       models.SeverityCritical,
		JapanRelevance: models.JapanRelevanceDirect,
		VictimOrgs:     []string{"MegaCorp"},
		ThreatActors:   []string{"APT99"},
	}
	inc, err := store.FindOrCreateIncident(ctx, item, enriched, 30)
	if err != nil || inc == nil {
		t.Fatalf("failed to seed incident: %v", err)
	}

	// 1. GET /api/incidents with query params
	req := httptest.NewRequest(http.MethodGet, "/api/incidents?severity=Critical&japan_only=true&limit=10&offset=0&order_by=first_seen_at", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/incidents, got %d", w.Code)
	}

	// 2. GET /api/incidents/{id}
	req = httptest.NewRequest(http.MethodGet, "/api/incidents/"+inc.ID, nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/incidents/{id}, got %d", w.Code)
	}

	// 2b. GET /api/incidents/{id} 404
	req = httptest.NewRequest(http.MethodGet, "/api/incidents/incident--non-existent-999", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for missing incident, got %d", w.Code)
	}

	// 3. POST /api/incidents/{id}/update
	updateBody, _ := json.Marshal(map[string]interface{}{
		"threat_actors":   []string{"Lazarus"},
		"severity":        "High",
		"japan_relevance": "Direct",
		"attack_type":     "Ransomware",
		"victim_org":      "New Corp",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/incidents/"+inc.ID+"/update", bytes.NewReader(updateBody))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on update incident labels, got %d", w.Code)
	}

	// 4. GET /api/stats/entities
	req = httptest.NewRequest(http.MethodGet, "/api/stats/entities?limit=10&japan_only=false", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/stats/entities, got %d", w.Code)
	}
}

func TestAPIConfigEndpoints(t *testing.T) {
	defer os.Remove("config.yaml")
	store, _ := storage.NewStore("", ":memory:")
	defer store.Close()

	srv := NewServer(store)

	// 1. GET /api/config/raw
	req := httptest.NewRequest(http.MethodGet, "/api/config/raw", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/config/raw, got %d", w.Code)
	}

	// 2. GET /api/config/export
	req = httptest.NewRequest(http.MethodGet, "/api/config/export?mask=true", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/config/export, got %d", w.Code)
	}

	// 3. POST /api/config/save
	savePayload, _ := json.Marshal(map[string]string{
		"config_yaml": config.GetSettings().ExportYAML(false),
	})
	req = httptest.NewRequest(http.MethodPost, "/api/config/save", bytes.NewReader(savePayload))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/config/save, got %d: %s", w.Code, w.Body.String())
	}

	// 4. POST /api/config/compliance
	compPayload, _ := json.Marshal(map[string]interface{}{
		"mode": "commercial_only",
		"tiers": map[string]bool{
			"commercial_ready": true,
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/config/compliance", bytes.NewReader(compPayload))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/config/compliance, got %d", w.Code)
	}

	// 5. POST /api/config/sources (toggle & delete)
	togglePayload, _ := json.Marshal(map[string]interface{}{
		"action":      "toggle",
		"source_type": "vendor_rss",
		"identifier":  "https://example.com/test_feed.rss",
		"enabled":     true,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/config/sources", bytes.NewReader(togglePayload))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on toggle source, got %d", w.Code)
	}

	deletePayload, _ := json.Marshal(map[string]interface{}{
		"action":      "delete",
		"source_type": "vendor_rss",
		"identifier":  "https://example.com/test_feed.rss",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/config/sources", bytes.NewReader(deletePayload))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on delete source, got %d", w.Code)
	}

	// Invalid action
	badPayload, _ := json.Marshal(map[string]interface{}{
		"action": "unknown_action",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/config/sources", bytes.NewReader(badPayload))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad action, got %d", w.Code)
	}
}

func TestAPIPipelineAndUtilities(t *testing.T) {
	defer os.Remove("config.yaml")
	store, _ := storage.NewStore("", ":memory:")
	defer store.Close()

	srv := NewServer(store)
	srv.pipeline.SetAnalyzer(&mockAPIAnalyzer{})

	// 1. HEAD /
	req := httptest.NewRequest(http.MethodHead, "/", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on HEAD /, got %d", w.Code)
	}

	// 2. Pipeline logs & clear
	req = httptest.NewRequest(http.MethodGet, "/api/pipeline/logs", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/pipeline/logs, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/pipeline/logs/clear", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/pipeline/logs/clear, got %d", w.Code)
	}

	// 3. POST /api/test/notion (unconfigured dry-run)
	req = httptest.NewRequest(http.MethodPost, "/api/test/notion", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError {
		t.Errorf("expected 200 or 500 on /api/test/notion, got %d", w.Code)
	}

	// 4. POST /api/ai/generate-queries
	qPayload, _ := json.Marshal(map[string]interface{}{
		"directive":   "ransomware leak japan",
		"target_type": "darkweb_onion",
		"count":       2,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/ai/generate-queries", bytes.NewReader(qPayload))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/ai/generate-queries, got %d: %s", w.Code, w.Body.String())
	}

	// 5. Backfill endpoints
	req = httptest.NewRequest(http.MethodPost, "/api/pipeline/backfill-incidents", bytes.NewReader([]byte(`{"sliding_window_days": 10}`)))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on backfill-incidents, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/pipeline/backfill-articles", bytes.NewReader([]byte(`{"limit": 5}`)))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202 on backfill-articles, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/pipeline/translate-incidents", bytes.NewReader([]byte(`{"limit": 5}`)))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on translate-incidents, got %d", w.Code)
	}

	// 6. POST /api/pipeline/run
	req = httptest.NewRequest(http.MethodPost, "/api/pipeline/run", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/pipeline/run, got %d", w.Code)
	}
	// Run again when running -> returns already_running
	srv.isPipeRunning = true
	req = httptest.NewRequest(http.MethodPost, "/api/pipeline/run", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	srv.isPipeRunning = false
	if !strings.Contains(w.Body.String(), "already_running") {
		t.Errorf("expected already_running status")
	}

	// 7. GET /api/pipeline/stream (SSE) with cancelled context
	streamCtx, cancelStream := context.WithCancel(context.Background())
	cancelStream() // Cancel immediately
	req = httptest.NewRequest(http.MethodGet, "/api/pipeline/stream", nil).WithContext(streamCtx)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if !strings.Contains(w.Header().Get("Content-Type"), "text/event-stream") {
		t.Errorf("expected text/event-stream, got %s", w.Header().Get("Content-Type"))
	}
}

func TestAPIIncidentFormatsAndLang(t *testing.T) {
	defer os.Remove("config.yaml")
	store, _ := storage.NewStore("", ":memory:")
	defer store.Close()

	srv := NewServer(store)
	ctx := context.Background()

	now := time.Now().UTC()
	item := models.ThreatItem{
		ID:          "fmt-item-1",
		Title:       "Format Test Threat",
		URL:         "https://example.com/fmt",
		Summary:     "Format summary",
		PublishedAt: &now,
		HarvestedAt: now,
	}
	enriched := &models.EnrichedThreat{
		ItemID:         "fmt-item-1",
		Item:           item,
		Title:          "Format Test Threat EN",
		TitleJa:        "フォーマットテスト脅威 JA",
		Summary:        "Summary EN",
		SummaryJa:      "要約 JA",
		Severity:       models.SeverityHigh,
		JapanRelevance: models.JapanRelevanceDirect,
		VictimOrgs:     []string{"Victim Org"},
		ThreatActors:   []string{"Actor 1"},
	}
	inc, _ := store.FindOrCreateIncident(ctx, item, enriched, 30)

	// 1. GET /api/incidents with lang=en and lang=ja
	req := httptest.NewRequest(http.MethodGet, "/api/incidents?lang=en", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/incidents?lang=en, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/incidents?lang=ja", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/incidents?lang=ja, got %d", w.Code)
	}

	// 2. GET /api/incidents/{id}
	req = httptest.NewRequest(http.MethodGet, "/api/incidents/"+inc.ID, nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on get incident, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), inc.ID) {
		t.Errorf("expected response to contain incident ID %s, got %s", inc.ID, w.Body.String())
	}

	// 3. GET /api/incidents/{id} with lang=ja
	req = httptest.NewRequest(http.MethodGet, "/api/incidents/"+inc.ID+"?lang=ja", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on lang=ja incident, got %d", w.Code)
	}

	// 4. GET /api/incidents/{id} with lang=en
	req = httptest.NewRequest(http.MethodGet, "/api/incidents/"+inc.ID+"?lang=en", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on lang=en incident, got %d", w.Code)
	}
}

func TestAPIRSSFeedAndAdvancedRoutes(t *testing.T) {
	defer os.Remove("config.yaml")
	store, err := storage.NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	srv := NewServer(store)
	srv.pipeline.SetAnalyzer(&mockAPIAnalyzer{})
	ctx := context.Background()

	// Insert test incident
	item := models.ThreatItem{
		ID:         "rss-threat-item-1",
		Title:      "Critical Zero-Day Exploit",
		Summary:    "Japanese text 要約 CVE-2024-5555",
		RawContent: "Full details about exploit",
		URL:        "https://example.com/exploit",
		SourceType: models.SourceTypeVendorRSS,
		SourceName: "ThreatFeed",
	}
	enriched := &models.EnrichedThreat{
		ItemID:           item.ID,
		Title:            "Critical Zero-Day Exploit",
		TitleJa:          "ゼロデイ脆弱性の悪用",
		Summary:          "English summary for exploit",
		SummaryJa:        "悪用に関する日本語要約",
		ImpactAnalysis:   "High potential impact",
		ImpactAnalysisJa: "高い潜在的影響",
		Severity:         models.SeverityCritical,
		JapanRelevance:   models.JapanRelevanceDirect,
		VictimOrgs:       []string{"VictimCorp"},
		ThreatActors:     []string{"APT29"},
		CVEs:             []string{"CVE-2024-5555"},
		AttackType:       "Zero-day",
	}
	inc, err := store.FindOrCreateIncident(ctx, item, enriched, 30)
	if err != nil {
		t.Fatalf("failed to insert incident: %v", err)
	}

	// 1. GET /rss
	req := httptest.NewRequest(http.MethodGet, "/rss", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /rss, got %d", w.Code)
	}
	rssBody := w.Body.String()
	if !strings.Contains(rssBody, "<rss") || !strings.Contains(rssBody, "Critical Zero-Day Exploit") {
		t.Errorf("expected valid RSS XML containing incident title, got: %s", rssBody)
	}

	// 2. GET /rss with filters
	req = httptest.NewRequest(http.MethodGet, "/rss?severity=Critical&japan_only=true&limit=10&search=Zero-Day", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /rss with filters, got %d", w.Code)
	}

	// 3. GET /api/incidents with various filters
	req = httptest.NewRequest(http.MethodGet, "/api/incidents?severity=Critical&actor=APT29&cve=CVE-2024-5555&japan_only=true&search=Exploit&page=1&page_size=10", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on filtered /api/incidents, got %d", w.Code)
	}

	// 4. GET /api/incidents/nonexistent
	req = httptest.NewRequest(http.MethodGet, "/api/incidents/incident--non-existent", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 on missing incident, got %d", w.Code)
	}

	// 5. POST /api/pipeline/translate-incidents
	req = httptest.NewRequest(http.MethodPost, "/api/pipeline/translate-incidents", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/pipeline/translate-incidents, got %d", w.Code)
	}

	// Direct call to RunIncidentBatchTranslation
	_ = srv.RunIncidentBatchTranslation(ctx, 10)

	// 6. POST /api/ai/generate-queries
	genPayload := map[string]interface{}{
		"directive":   "monitor cyber threats",
		"target_desc": "Japan critical infrastructure",
		"count":       2,
	}
	body, _ := json.Marshal(genPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/ai/generate-queries", bytes.NewReader(body))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/ai/generate-queries, got %d", w.Code)
	}

	// 7. Source management through /api/config/sources
	// Add
	addPayload := map[string]interface{}{
		"action":      "add",
		"source_type": "vendor_rss",
		"data": map[string]interface{}{
			"name":        "Test RSS Feed",
			"url":         "https://example.com/test-feed.xml",
			"category":    "Threat Intel",
			"enabled":     true,
			"source_type": "vendor_rss",
		},
	}
	body, _ = json.Marshal(addPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/sources", bytes.NewReader(body))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on add source, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Toggle
	togglePayload := map[string]interface{}{
		"action":      "toggle",
		"source_type": "vendor_rss",
		"identifier":  "https://example.com/test-feed.xml",
		"enabled":     false,
	}
	body, _ = json.Marshal(togglePayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/sources", bytes.NewReader(body))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on toggle source, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Update
	updatePayload := map[string]interface{}{
		"action":      "update",
		"source_type": "vendor_rss",
		"identifier":  "https://example.com/test-feed.xml",
		"data": map[string]interface{}{
			"name":        "Renamed RSS Feed",
			"url":         "https://example.com/test-feed.xml",
			"category":    "Updated Category",
			"enabled":     true,
			"source_type": "vendor_rss",
		},
	}
	body, _ = json.Marshal(updatePayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/sources", bytes.NewReader(body))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on update source, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Delete
	delPayload := map[string]interface{}{
		"action":      "delete",
		"source_type": "vendor_rss",
		"identifier":  "https://example.com/test-feed.xml",
	}
	body, _ = json.Marshal(delPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/sources", bytes.NewReader(body))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on delete source, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Invalid action
	invPayload := map[string]interface{}{
		"action": "unknown_action",
	}
	body, _ = json.Marshal(invPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/sources", bytes.NewReader(body))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 on invalid action, got %d", w.Code)
	}

	// 8. POST /api/pipeline/run
	req = httptest.NewRequest(http.MethodPost, "/api/pipeline/run", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on /api/pipeline/run, got %d", w.Code)
	}

	_ = inc
}

func TestAPIServerExtended(t *testing.T) {
	store, err := storage.NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	srv := NewServer(store)
	srv.pipeline.SetAnalyzer(&mockAPIAnalyzer{})

	// Seed test incident
	item := models.ThreatItem{
		ID:         "threat-ext-1",
		Title:      "テストインシデント",
		Summary:    "テストの要約内容",
		RawContent: "LockBit targeted ターゲット企業",
		SourceType: models.SourceTypeVendorRSS,
		SourceName: "TestFeed",
		URL:        "https://example.com/test-ext-1",
	}
	enriched := &models.EnrichedThreat{
		ItemID:           "threat-ext-1",
		Title:            "テストインシデント",
		TitleJa:          "テストインシデント",
		Summary:          "テストの要約内容",
		SummaryJa:        "テストの要約内容",
		ImpactAnalysis:   "影響大",
		ImpactAnalysisJa: "影響大",
		Severity:         models.SeverityHigh,
		JapanRelevance:   models.JapanRelevanceDirect,
		AttackType:       "Ransomware",
		ThreatActors:     []string{"LockBit"},
		VictimOrgs:       []string{"ターゲット企業"},
	}
	inc, err := store.FindOrCreateIncident(context.Background(), item, enriched, 30)
	if err != nil {
		t.Fatalf("failed to create incident: %v", err)
	}

	// 1. GET /api/incidents/{id}
	// Normal
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/incidents/%s", inc.ID), nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for existing incident, got %d", w.Code)
	}

	// With lang=ja
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/incidents/%s?lang=ja", inc.ID), nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for incident with lang=ja, got %d", w.Code)
	}

	// With lang=en
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/incidents/%s?lang=en", inc.ID), nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for incident with lang=en, got %d", w.Code)
	}

	// Non-existent incident
	req = httptest.NewRequest(http.MethodGet, "/api/incidents/nonexistent-999", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for non-existent incident, got %d", w.Code)
	}

	// 2. POST /api/incidents/{id}/update
	labelPayload := map[string]interface{}{
		"threat_actors":   []string{"LockBit", "BlackCat"},
		"severity":        "Critical",
		"japan_relevance": "Direct",
		"attack_type":     "Data Exfiltration",
		"victim_org":      "Updated Org",
	}
	body, _ := json.Marshal(labelPayload)
	req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/incidents/%s/update", inc.ID), bytes.NewReader(body))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on update labels, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Invalid body for update labels
	req = httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/incidents/%s/update", inc.ID), bytes.NewReader([]byte("NOT_JSON")))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 on invalid JSON for update labels, got %d", w.Code)
	}

	// 3. POST /api/pipeline/translate-incidents & RunIncidentBatchTranslation
	req = httptest.NewRequest(http.MethodPost, "/api/pipeline/translate-incidents", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on translate incidents endpoint, got %d", w.Code)
	}
	translated := srv.RunIncidentBatchTranslation(context.Background(), 10)
	if translated == 0 {
		t.Logf("RunIncidentBatchTranslation translated %d items", translated)
	}

	// 4. POST /api/pipeline/backfill-articles and /api/pipeline/backfill-incidents
	req = httptest.NewRequest(http.MethodPost, "/api/pipeline/backfill-articles", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusAccepted {
		t.Errorf("expected 202 on backfill articles, got %d", w.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/pipeline/backfill-incidents", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on backfill incidents, got %d", w.Code)
	}

	// 5. POST /api/ai/generate-queries
	qPayload := map[string]interface{}{
		"directive":   "ransomware attacks",
		"source_type": "vendor_rss",
		"count":       2,
	}
	body, _ = json.Marshal(qPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/ai/generate-queries", bytes.NewReader(body))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on generate queries, got %d (body: %s)", w.Code, w.Body.String())
	}

	// 6. Source management extra actions & compliance
	tierPayload := map[string]interface{}{
		"action":     "toggle_tier",
		"identifier": config.TierDarkwebAccess,
		"enabled":    false,
	}
	body, _ = json.Marshal(tierPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/sources", bytes.NewReader(body))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on toggle tier, got %d (body: %s)", w.Code, w.Body.String())
	}

	// Update compliance
	compPayload := map[string]interface{}{
		"mode": "strict",
	}
	body, _ = json.Marshal(compPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/compliance", bytes.NewReader(body))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 on update compliance, got %d (body: %s)", w.Code, w.Body.String())
	}

	// 7. StartScheduler test with canceled context
	schedCtx, schedCancel := context.WithCancel(context.Background())
	schedCancel()
	srv.StartScheduler(schedCtx)
}

