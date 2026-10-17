package scraper

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/backend/internal/config"
	"github.com/al17091/threat_harvester/backend/internal/models"
	"github.com/al17091/threat_harvester/backend/internal/storage"
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

