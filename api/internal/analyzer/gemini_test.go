package analyzer

import (
	"context"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/api/internal/models"
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

func TestGeminiFallbacksAndHelpers(t *testing.T) {
	an := NewGeminiThreatAnalyzer()
	ctx := context.Background()

	item := models.ThreatItem{
		ID:         "test-gemini-single",
		Title:      "Critical Vulnerability in Apache",
		Summary:    "Apache HTTP Server vulnerability",
		SourceType: models.SourceTypeVendorRSS,
		SourceName: "JPCERT",
	}

	// 1. Analyze single fallback
	enriched, err := an.Analyze(ctx, item)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if enriched.ItemID != "test-gemini-single" {
		t.Errorf("expected item id test-gemini-single, got %s", enriched.ItemID)
	}

	// 2. TranslateIncident fallback
	incOut, err := an.TranslateIncident(ctx, IncidentTranslationInput{
		ID:      "inc-gemini-1",
		Title:   "日本語タイトル",
		Summary: "日本語要約",
	})
	if incOut == nil || incOut.Title != "日本語タイトル" {
		t.Errorf("expected fallback title, got %+v", incOut)
	}
	_ = err // Expected error when unconfigured

	// 3. TranslateIncidentFields fallback
	t1, s1, i1, a1, err := an.TranslateIncidentFields(ctx, "Title", "Summary", "Impact", []string{"Act1"})
	if err == nil || t1 != "Title" || len(a1) != 1 {
		t.Errorf("TranslateIncidentFields fallback failed: t1=%s, err=%v", t1, err)
	}
	_ = s1
	_ = i1

	// 4. TranslateFieldsToJapanese fallback
	tj1, sj1, ij1, aj1, err := an.TranslateFieldsToJapanese(ctx, "Title", "Summary", "Impact", []string{"Act1"})
	if err == nil || tj1 != "Title" || len(aj1) != 1 {
		t.Errorf("TranslateFieldsToJapanese fallback failed: tj1=%s, err=%v", tj1, err)
	}
	_ = sj1
	_ = ij1

	// 5. LocalizeThreatToJapanese fallback
	if err := an.LocalizeThreatToJapanese(ctx, enriched); err == nil {
		t.Errorf("expected error when unconfigured in LocalizeThreatToJapanese")
	}

	// 6. TranslateBatch fallback
	batchRes, err := an.TranslateBatch(ctx, []BatchTranslateItem{
		{ID: "b1", Title: "Title 1", Summary: "Summary 1"},
	})
	if err == nil {
		t.Errorf("expected error when unconfigured in TranslateBatch")
	}
	_ = batchRes

	// 7. cleanJSONFences
	fenced := "```json\n{\"test\": true}\n```"
	if cleaned := cleanJSONFences(fenced); cleaned != "{\"test\": true}" {
		t.Errorf("expected cleaned JSON, got: %s", cleaned)
	}

	// 8. fallbackSequential
	seqItems, err := an.fallbackSequential(ctx, []models.ThreatItem{item})
	if err != nil || len(seqItems) != 1 {
		t.Errorf("fallbackSequential failed: %v", err)
	}
}

func TestBuildEnrichedThreat(t *testing.T) {
	item := models.ThreatItem{
		ID:         "threat-100",
		Title:      "Original Title CVE-2024-9999",
		Summary:    "Original Summary text",
		RawContent: "Raw threat intelligence mentioning Lazarus and Fortinet FortiGate",
		URL:        "https://example.com/advisory",
		SourceType: models.SourceTypeVendorRSS,
		SourceName: "Vendor Feed",
	}

	out := analysisOutput{
		Severity:             "High",
		JapanRelevance:      "Direct",
		Title:                "Enriched English Title",
		TitleJa:              "濃縮された日本語タイトル",
		Summary:              "Enriched English Summary",
		SummaryJa:            "濃縮された日本語要約",
		ImpactAnalysis:       "High potential damage",
		ImpactAnalysisJa:     "潜在的な甚大影響",
		VictimOrgs:           []string{"Example Corp"},
		ThreatActors:         []string{"Lazarus"},
		ThreatActorReasons:   map[string]string{"Lazarus": "Named explicitly in bulletin"},
		AttackType:           "Vulnerability",
		CVEs:                 []string{"CVE-2024-9999"},
		AffectedProducts:     []string{"FortiGate"},
		RecommendedActions:   []string{"Apply emergency firmware patch"},
		RecommendedActionsJa: []string{"緊急ファームウェアパッチを適用"},
	}

	enriched := buildEnrichedThreat(item, out)
	if enriched.Severity != models.SeverityHigh {
		t.Errorf("Expected SeverityHigh, got %s", enriched.Severity)
	}
	if enriched.JapanRelevance != models.JapanRelevanceDirect {
		t.Errorf("Expected JapanRelevanceDirect, got %s", enriched.JapanRelevance)
	}
	if enriched.Title != "Enriched English Title" {
		t.Errorf("Expected Enriched English Title, got %s", enriched.Title)
	}
	if len(enriched.CVEs) == 0 || enriched.CVEs[0] != "CVE-2024-9999" {
		t.Errorf("Expected CVE-2024-9999, got %v", enriched.CVEs)
	}
	if len(enriched.ThreatActors) == 0 || enriched.ThreatActors[0] != "Lazarus" {
		t.Errorf("Expected Lazarus threat actor, got %v", enriched.ThreatActors)
	}
}

