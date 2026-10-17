package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/models"
	"github.com/al17091/threat_harvester/api/internal/storage"
)

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

