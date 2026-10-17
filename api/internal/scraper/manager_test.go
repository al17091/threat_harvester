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

func TestScraperManagerClearnet(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`
			<!DOCTYPE html>
			<html>
			<body>
				<article class="article-body">
					<h1>Breaking Threat Intelligence</h1>
					<p>Ransomware gang has officially released the full stolen dataset containing intellectual property and customer databases.</p>
				</article>
			</body>
			</html>
		`))
	}))
	defer ts.Close()

	store, err := storage.NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	// Seed a threat item with pending fetch status
	now := time.Now().UTC()
	item := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"Test Vendor",
		"Critical Security Advisory",
		ts.URL,
		"Snippet text",
		"",
		&now,
		map[string]interface{}{"fetch_status": "pending"},
	)
	item.FetchStatus = "pending"

	if err := store.MarkSeen(context.Background(), item, nil, false); err != nil {
		t.Fatalf("MarkSeen failed: %v", err)
	}

	cfg := config.ScraperConfig{
		Enabled:                true,
		ClearnetEnabled:        true,
		TorEnabled:             false,
		ClearnetConcurrency:    2,
		ClearnetTimeoutSeconds: 5,
		WorkerIntervalSeconds:  1,
		BatchSize:              10,
		MaxAttempts:            2,
		AutoReAnalyze:          false,
	}
	netCfg := config.NetworkConfig{}

	mgr := NewScraperManager(store, nil, cfg, netCfg)

	// Run single pass
	mgr.processClearnetQueue(context.Background())

	// Verify item was updated to completed and raw_content was populated
	items, err := store.GetHistory(context.Background(), storage.HistoryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(items))
	}

	raw := items[0]["raw_content"].(string)
	if len(raw) == 0 {
		t.Errorf("expected raw_content to be non-empty")
	}
	if items[0]["fetch_status"] != "completed" {
		t.Errorf("expected fetch_status=completed, got %v", items[0]["fetch_status"])
	}
}

type mockScraperAnalyzer struct {
	analyzed bool
}

func (m *mockScraperAnalyzer) Analyze(ctx context.Context, item models.ThreatItem) (*models.EnrichedThreat, error) {
	m.analyzed = true
	return &models.EnrichedThreat{
		ItemID:   item.ID,
		Item:     item,
		Severity: models.SeverityCritical,
		TitleJa:  "Re-analyzed Title",
	}, nil
}
func (m *mockScraperAnalyzer) AnalyzeBatch(ctx context.Context, items []models.ThreatItem) ([]*models.EnrichedThreat, error) {
	return nil, nil
}
func (m *mockScraperAnalyzer) GenerateSearchQueries(ctx context.Context, directive string, targetType string, count int) ([]string, error) {
	return nil, nil
}
func (m *mockScraperAnalyzer) TranslateIncidentFields(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	return title, summary, impact, actions, nil
}
func (m *mockScraperAnalyzer) TranslateFieldsToJapanese(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	return title, summary, impact, actions, nil
}
func (m *mockScraperAnalyzer) LocalizeThreatToJapanese(ctx context.Context, enriched *models.EnrichedThreat) error {
	return nil
}
func (m *mockScraperAnalyzer) TranslateIncident(ctx context.Context, input analyzer.IncidentTranslationInput) (*analyzer.IncidentTranslationOutput, error) {
	return nil, nil
}
func (m *mockScraperAnalyzer) TranslateBatch(ctx context.Context, items []analyzer.BatchTranslateItem) ([]analyzer.BatchTranslateResult, error) {
	return nil, nil
}

func TestScraperManagerLifecycleAndDefaults(t *testing.T) {
	store, _ := storage.NewStore("", ":memory:")
	defer store.Close()

	// Zero / negative configs should fallback to defaults
	cfg := config.ScraperConfig{
		Enabled: false,
	}
	mgr := NewScraperManager(store, nil, cfg, config.NetworkConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start when disabled
	mgr.Start(ctx)
	// Multi start
	mgr.Start(ctx)
	mgr.Stop()
	mgr.Stop() // idempotent

	// Start when enabled with short interval
	cfg.Enabled = true
	cfg.WorkerIntervalSeconds = 1
	mgr2 := NewScraperManager(store, nil, cfg, config.NetworkConfig{})
	mgr2.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	mgr2.Stop()
}

func TestScraperManagerClearnetFailuresAndEmpty(t *testing.T) {
	store, _ := storage.NewStore("", ":memory:")
	defer store.Close()

	now := time.Now().UTC()
	// Item 1: Failing URL (port 9 connection refused)
	itemFail := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"Test Vendor",
		"Failing Threat",
		"http://127.0.0.1:9/fail",
		"Snippet",
		"",
		&now,
		nil,
	)
	itemFail.FetchStatus = "pending"
	_ = store.MarkSeen(context.Background(), itemFail, nil, false)

	// Item 2: Empty HTML
	tsEmpty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<html><body></body></html>`))
	}))
	defer tsEmpty.Close()

	itemEmpty := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"Test Vendor",
		"Empty Content Threat",
		tsEmpty.URL,
		"Snippet",
		"",
		&now,
		nil,
	)
	itemEmpty.FetchStatus = "pending"
	_ = store.MarkSeen(context.Background(), itemEmpty, nil, false)

	cfg := config.ScraperConfig{
		Enabled:                true,
		ClearnetEnabled:        true,
		ClearnetConcurrency:    2,
		ClearnetTimeoutSeconds: 1,
		BatchSize:              10,
		MaxAttempts:            2,
	}
	mgr := NewScraperManager(store, nil, cfg, config.NetworkConfig{})
	mgr.processClearnetQueue(context.Background())

	// Verify statuses
	items, _ := store.GetHistory(context.Background(), storage.HistoryFilter{Limit: 10})
	for _, it := range items {
		title := it["title"].(string)
		status := it["fetch_status"].(string)
		if title == "Failing Threat" && status != "failed" {
			t.Errorf("expected status=failed for failing threat, got %s", status)
		}
		if title == "Empty Content Threat" && status != "failed" {
			t.Errorf("expected status=failed for empty threat, got %s", status)
		}
	}
}

func TestScraperManagerTorQueueAndAutoReAnalyze(t *testing.T) {
	store, _ := storage.NewStore("", ":memory:")
	defer store.Close()

	now := time.Now().UTC()
	// Onion item
	onionItem := models.NewThreatItem(
		models.SourceTypeDarkwebOnion,
		"Tor Source",
		"Onion Leak",
		"http://sampledarkweb9999.onion/leak",
		"Darkweb snippet",
		"",
		&now,
		nil,
	)
	onionItem.FetchStatus = "pending"
	_ = store.MarkSeen(context.Background(), onionItem, nil, false)

	mockAI := &mockScraperAnalyzer{}
	cfg := config.ScraperConfig{
		Enabled:           true,
		TorEnabled:        true,
		TorConcurrency:    1,
		TorTimeoutSeconds: 1,
		BatchSize:         10,
		MaxAttempts:       2,
		AutoReAnalyze:     true,
	}
	netCfg := config.NetworkConfig{
		TorProxyURL: "socks5://127.0.0.1:9050",
	}

	mgr := NewScraperManager(store, mockAI, cfg, netCfg)
	// Tor fetch fails (no tor proxy running)
	mgr.processTorQueue(context.Background())

	// Verify onion status failed
	items, _ := store.GetHistory(context.Background(), storage.HistoryFilter{Limit: 10})
	if len(items) == 0 || items[0]["fetch_status"] != "failed" {
		t.Errorf("expected onion item to fail, got %+v", items)
	}

	// Test postProcessEnrichment directly
	mgr.postProcessEnrichment(context.Background(), onionItem, "Deep scraped full article content.")
	if !mockAI.analyzed {
		t.Errorf("expected mockAI to have analyzed article in postProcessEnrichment")
	}
}

