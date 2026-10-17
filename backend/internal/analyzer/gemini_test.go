package analyzer

import (
	"context"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/backend/internal/models"
)

func TestQueryCache(t *testing.T) {
	an := NewGeminiThreatAnalyzer()
	an.cacheTTL = 5 * time.Minute

	// Manually inject cache entry
	cacheKey := "web_search:test directive:3"
	an.queryCache[cacheKey] = queryCacheEntry{
		queries:  []string{"q1", "q2", "q3"},
		cachedAt: time.Now().UTC(),
	}

	ctx := context.Background()
	queries, err := an.GenerateSearchQueries(ctx, "test directive", "web_search", 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(queries) != 3 || queries[0] != "q1" {
		t.Fatalf("expected cached queries [q1, q2, q3], got %v", queries)
	}

	// Test cache clear
	an.ClearQueryCache()
	if len(an.queryCache) != 0 {
		t.Fatalf("expected empty cache after ClearQueryCache, got %d", len(an.queryCache))
	}
}

func TestAnalyzeBatchBasic(t *testing.T) {
	an := NewGeminiThreatAnalyzer()
	ctx := context.Background()

	// Empty items
	results, err := an.AnalyzeBatch(ctx, nil)
	if err != nil || len(results) != 0 {
		t.Fatalf("expected empty results for nil items, got %v, %v", results, err)
	}

	// Multiple items with mock/no api key
	item1 := models.ThreatItem{
		ID:         "test-1",
		Title:      "Test Threat 1",
		Summary:    "Summary 1",
		SourceType: models.SourceTypeVendorRSS,
		SourceName: "Vendor",
	}
	item2 := models.ThreatItem{
		ID:         "test-2",
		Title:      "Test Threat 2",
		Summary:    "Summary 2",
		SourceType: models.SourceTypeTelegram,
		SourceName: "Telegram",
	}

	results, err = an.AnalyzeBatch(ctx, []models.ThreatItem{item1, item2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 enriched items, got %d", len(results))
	}
	if results[0].ItemID != "test-1" || results[1].ItemID != "test-2" {
		t.Fatalf("unexpected item IDs in batch results: %+v", results)
	}
}
