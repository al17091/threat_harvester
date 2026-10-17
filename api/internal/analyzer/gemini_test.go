package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/api/internal/config"
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

type mockTransport struct {
	roundTrip func(req *http.Request) (*http.Response, error)
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.roundTrip(req)
}

func mockGeminiResponse(rawText string, statusCode int) *http.Response {
	respObj := geminiResponse{
		Candidates: []geminiCandidate{
			{
				Content: struct {
					Parts []geminiPart `json:"parts"`
				}{
					Parts: []geminiPart{
						{Text: rawText},
					},
				},
			},
		},
	}
	body, _ := json.Marshal(respObj)
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Header:     make(http.Header),
	}
}

func TestGeminiAnalyzeMock(t *testing.T) {
	origCfg := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origCfg)

	cfg := origCfg
	cfg.AI.GeminiAPIKey = "test-gemini-key"
	config.GetSettings().SetConfig(cfg)

	an := NewGeminiThreatAnalyzer()
	ctx := context.Background()

	item := models.ThreatItem{
		ID:         "gemini-item-1",
		Title:      "Ransomware attack on Healthcare Org",
		Summary:    "LockBit ransomware compromised network",
		RawContent: "LockBit group claimed responsibility for targeting ABC Hospital",
		SourceType: models.SourceTypeDarkwebOnion,
		SourceName: "Ransomware Monitor",
	}

	analysisJSON := `{
		"severity": "Critical",
		"japan_relevance": "Direct",
		"title": "Hospital Compromised by LockBit",
		"title_ja": "LockBitにより病院が侵害",
		"summary": "LockBit attacked hospital network",
		"summary_ja": "LockBitが病院ネットワークを攻撃",
		"impact_analysis": "Severe operations disruption",
		"victim_orgs": ["ABC Hospital"],
		"threat_actors": ["LockBit"],
		"attack_type": "Ransomware"
	}`

	// 1. Success case
	an.client.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return mockGeminiResponse(analysisJSON, http.StatusOK), nil
		},
	}

	enriched, err := an.Analyze(ctx, item)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if enriched.Severity != models.SeverityCritical {
		t.Errorf("expected Critical severity, got %s", enriched.Severity)
	}
	if enriched.JapanRelevance != models.JapanRelevanceDirect {
		t.Errorf("expected Direct relevance, got %s", enriched.JapanRelevance)
	}

	// 2. HTTP error case
	an.client.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Body:       io.NopCloser(bytes.NewReader([]byte("Quota exceeded"))),
				Header:     make(http.Header),
			}, nil
		},
	}
	if _, err := an.Analyze(ctx, item); err == nil {
		t.Errorf("expected error on HTTP 429")
	}

	// 3. Invalid JSON case
	an.client.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return mockGeminiResponse("NOT_JSON", http.StatusOK), nil
		},
	}
	if _, err := an.Analyze(ctx, item); err == nil {
		t.Errorf("expected error on invalid JSON response")
	}

	// 4. Empty candidates case
	an.client.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			body, _ := json.Marshal(geminiResponse{Candidates: nil})
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		},
	}
	if _, err := an.Analyze(ctx, item); err == nil {
		t.Errorf("expected error on empty candidates")
	}
}

func TestGeminiAnalyzeBatchMock(t *testing.T) {
	origCfg := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origCfg)

	cfg := origCfg
	cfg.AI.GeminiAPIKey = "test-gemini-key"
	config.GetSettings().SetConfig(cfg)

	an := NewGeminiThreatAnalyzer()
	ctx := context.Background()

	items := []models.ThreatItem{
		{ID: "batch-1", Title: "Threat 1", RawContent: "APT29 phishing"},
		{ID: "batch-2", Title: "Threat 2", RawContent: "Volt Typhoon activity"},
	}

	batchJSON := `[
		{
			"index": 0,
			"severity": "High",
			"japan_relevance": "Potential",
			"title": "Threat 1 Enriched",
			"threat_actors": ["APT29"]
		},
		{
			"index": 1,
			"severity": "Medium",
			"japan_relevance": "Direct",
			"title": "Threat 2 Enriched",
			"threat_actors": ["Volt Typhoon"]
		}
	]`

	// Success case
	an.client.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return mockGeminiResponse(batchJSON, http.StatusOK), nil
		},
	}

	results, err := an.AnalyzeBatch(ctx, items)
	if err != nil {
		t.Fatalf("AnalyzeBatch failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Severity != models.SeverityHigh || results[1].Severity != models.SeverityMedium {
		t.Errorf("unexpected severities in batch results: %+v", results)
	}

	// Fallback to sequential on batch failure
	an.client.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(bytes.NewReader([]byte("server error"))),
				Header:     make(http.Header),
			}, nil
		},
	}
	fallbackResults, err := an.AnalyzeBatch(ctx, items)
	if err != nil {
		t.Fatalf("expected fallback sequential to handle error, got: %v", err)
	}
	if len(fallbackResults) != 2 {
		t.Errorf("expected 2 fallback results, got %d", len(fallbackResults))
	}
}

func TestGeminiGenerateSearchQueriesMock(t *testing.T) {
	origCfg := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origCfg)

	cfg := origCfg
	cfg.AI.GeminiAPIKey = "test-gemini-key"
	config.GetSettings().SetConfig(cfg)

	an := NewGeminiThreatAnalyzer()
	ctx := context.Background()

	an.client.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return mockGeminiResponse(`["cve 2024", "critical zero-day"]`, http.StatusOK), nil
		},
	}

	queries, err := an.GenerateSearchQueries(ctx, "find vulnerabilities", "web_search", 2)
	if err != nil {
		t.Fatalf("GenerateSearchQueries failed: %v", err)
	}
	if len(queries) != 2 || queries[0] != "cve 2024" {
		t.Errorf("unexpected queries: %v", queries)
	}

	// Should hit cache now
	an.client.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			t.Fatalf("should not make network call on cached query")
			return nil, nil
		},
	}
	cachedQueries, err := an.GenerateSearchQueries(ctx, "find vulnerabilities", "web_search", 2)
	if err != nil || len(cachedQueries) != 2 {
		t.Errorf("cache fetch failed: %v, %v", cachedQueries, err)
	}
}

func TestGeminiTranslationsMock(t *testing.T) {
	origCfg := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origCfg)

	cfg := origCfg
	cfg.AI.GeminiAPIKey = "test-gemini-key"
	config.GetSettings().SetConfig(cfg)

	an := NewGeminiThreatAnalyzer()
	ctx := context.Background()

	// 1. TranslateIncidentFields
	an.client.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return mockGeminiResponse(`{
				"title": "翻訳タイトル",
				"summary": "翻訳要約",
				"impact_analysis": "翻訳影響",
				"title_ja": "翻訳タイトル",
				"summary_ja": "翻訳要約",
				"impact_analysis_ja": "翻訳影響",
				"recommended_actions": ["アクション1"],
				"recommended_actions_ja": ["アクション1"]
			}`, http.StatusOK), nil
		},
	}

	tJa, sJa, iJa, aJa, err := an.TranslateIncidentFields(ctx, "Title", "Summary", "Impact", []string{"Action 1"})
	if err != nil {
		t.Fatalf("TranslateIncidentFields failed: %v", err)
	}
	if tJa != "翻訳タイトル" || len(aJa) != 1 || sJa != "翻訳要約" || iJa != "翻訳影響" {
		t.Errorf("unexpected translation: %s, %s, %s, %v", tJa, sJa, iJa, aJa)
	}

	// 2. TranslateFieldsToJapanese
	tJa2, _, _, _, err := an.TranslateFieldsToJapanese(ctx, "Title", "Summary", "Impact", []string{"Action 1"})
	if err != nil || tJa2 != "翻訳タイトル" {
		t.Errorf("TranslateFieldsToJapanese failed: %v", err)
	}

	// 3. TranslateIncident
	inc, err := an.TranslateIncident(ctx, IncidentTranslationInput{
		ID:                 "inc-test",
		Title:              "Title",
		Summary:            "Summary",
		ImpactAnalysis:     "Impact",
		RecommendedActions: []string{"Action 1"},
	})
	if err != nil || inc.Title != "翻訳タイトル" {
		t.Errorf("TranslateIncident failed: %v", err)
	}

	// 4. LocalizeThreatToJapanese
	enriched := &models.EnrichedThreat{
		Title:              "English Title",
		Summary:            "English Summary",
		ImpactAnalysis:     "English Impact",
		RecommendedActions: []string{"Action 1"},
	}
	if err := an.LocalizeThreatToJapanese(ctx, enriched); err != nil {
		t.Fatalf("LocalizeThreatToJapanese failed: %v", err)
	}
	if enriched.TitleJa != "翻訳タイトル" {
		t.Errorf("expected localized title, got %s", enriched.TitleJa)
	}

	// 5. TranslateBatch
	an.client.Transport = &mockTransport{
		roundTrip: func(req *http.Request) (*http.Response, error) {
			return mockGeminiResponse(`[
				{
					"id": "inc-b1",
					"title": "タイトル1",
					"summary": "要約1",
					"impact": "影響1",
					"recommended_actions": ["対策1"]
				}
			]`, http.StatusOK), nil
		},
	}

	bResults, err := an.TranslateBatch(ctx, []BatchTranslateItem{
		{ID: "inc-b1", Title: "Title 1", Summary: "Summary 1"},
	})
	if err != nil || len(bResults) != 1 {
		t.Fatalf("TranslateBatch failed: %v, results: %v", err, bResults)
	}
	if bResults[0].Title != "タイトル1" {
		t.Errorf("unexpected batch translation title: %s", bResults[0].Title)
	}
}

