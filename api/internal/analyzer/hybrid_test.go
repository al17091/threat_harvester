package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/models"
)

type mockSubAnalyzer struct {
	ThreatAnalyzer
	enriched *models.EnrichedThreat
	queries  []string
	err      error
}

func (m *mockSubAnalyzer) Analyze(ctx context.Context, item models.ThreatItem) (*models.EnrichedThreat, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.enriched, nil
}

func (m *mockSubAnalyzer) AnalyzeBatch(ctx context.Context, items []models.ThreatItem) ([]*models.EnrichedThreat, error) {
	if m.err != nil {
		return nil, m.err
	}
	return []*models.EnrichedThreat{m.enriched}, nil
}

func (m *mockSubAnalyzer) GenerateSearchQueries(ctx context.Context, directive, targetType string, count int) ([]string, error) {
	return m.queries, nil
}

func (m *mockSubAnalyzer) TranslateIncident(ctx context.Context, input IncidentTranslationInput) (*IncidentTranslationOutput, error) {
	return &IncidentTranslationOutput{Title: input.Title, Summary: input.Summary}, nil
}

func (m *mockSubAnalyzer) TranslateIncidentFields(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	return title, summary, impact, actions, nil
}

func (m *mockSubAnalyzer) TranslateFieldsToJapanese(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	return title, summary, impact, actions, nil
}

func (m *mockSubAnalyzer) LocalizeThreatToJapanese(ctx context.Context, enriched *models.EnrichedThreat) error {
	return nil
}

func (m *mockSubAnalyzer) TranslateBatch(ctx context.Context, items []BatchTranslateItem) ([]BatchTranslateResult, error) {
	return nil, nil
}

func TestHybridAnalyzerEscalationAndDelegation(t *testing.T) {
	ctx := context.Background()

	// Setup mock OpenAI/LiteLLM server
	tsPrimary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"choices": []map[string]interface{}{
				{
					"message": map[string]interface{}{
						"content": `{
							"severity": "Critical",
							"japan_relevance": "Direct",
							"title": "Primary AI Incident Title",
							"title_ja": "一次AI検知タイトル",
							"summary": "Primary summary",
							"summary_ja": "一次要約",
							"victim_orgs": ["Test Victim"],
							"threat_actors": ["APT-Primary"],
							"recommended_actions": ["Isolate host"]
						}`,
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tsPrimary.Close()

	cfg := config.AiConfig{
		PrimaryProvider: "litellm",
		Endpoint:        tsPrimary.URL,
		Model:           "qwen2.5-3b-instruct",
		APIKey:          "dummy-key",
		TimeoutSeconds:  5,
		Escalation: config.EscalationConfig{
			Enabled:              true,
			GeminiAPIKey:         "dummy-gemini-key",
			GeminiModel:          "gemini-1.5-flash",
			MaxLocalContentRunes: 100, // Small threshold for testing escalation
			TriggerSeverities:    []string{"Critical"},
			TriggerJapanDirect:   true,
		},
	}

	hybrid := NewHybridThreatAnalyzer(cfg)
	if hybrid == nil {
		t.Fatalf("Failed to initialize NewHybridThreatAnalyzer")
	}

	// Mock escalation analyzer
	mockEsc := &mockSubAnalyzer{
		enriched: &models.EnrichedThreat{
			Severity:       models.SeverityCritical,
			JapanRelevance: models.JapanRelevanceDirect,
			TitleJa:        "エスカレーション解析タイトル",
		},
		queries: []string{"escalated query 1"},
	}
	hybrid.escalation = mockEsc

	// 1. Test shouldEscalateByLength
	shortContent := "Short article content below threshold."
	longContent := strings.Repeat("Long article content exceeding the threshold. ", 10)
	if hybrid.shouldEscalateByLength(shortContent) {
		t.Errorf("expected short content to not escalate by length")
	}
	if !hybrid.shouldEscalateByLength(longContent) {
		t.Errorf("expected long content to escalate by length")
	}

	// 2. Test shouldEscalateByThreat
	critJpThreat := &models.EnrichedThreat{
		Severity:       models.SeverityCritical,
		JapanRelevance: models.JapanRelevanceDirect,
	}
	highJpThreat := &models.EnrichedThreat{
		Severity:       models.SeverityHigh,
		JapanRelevance: models.JapanRelevanceDirect,
	}
	lowThreat := &models.EnrichedThreat{
		Severity:       models.SeverityLow,
		JapanRelevance: models.JapanRelevanceNone,
	}
	if !hybrid.shouldEscalateByThreat(critJpThreat) {
		t.Errorf("expected critical threat to escalate")
	}
	if !hybrid.shouldEscalateByThreat(highJpThreat) {
		t.Errorf("expected high japan direct threat to escalate")
	}
	if hybrid.shouldEscalateByThreat(lowThreat) {
		t.Errorf("expected low threat to not escalate")
	}

	// 3. Test Analyze (Escalation triggered by length)
	longItem := models.ThreatItem{
		ID:         "long-1",
		Title:      "Long Threat",
		RawContent: longContent,
	}
	enriched, err := hybrid.Analyze(ctx, longItem)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if enriched == nil || enriched.TitleJa != "エスカレーション解析タイトル" {
		t.Errorf("Expected escalated enriched threat, got: %+v", enriched)
	}

	// 4. Test AnalyzeBatch
	shortItem := models.ThreatItem{
		ID:         "short-1",
		Title:      "Short Threat",
		RawContent: shortContent,
	}
	batch := []models.ThreatItem{shortItem}
	results, err := hybrid.AnalyzeBatch(ctx, batch)
	if err != nil {
		t.Fatalf("AnalyzeBatch failed: %v", err)
	}
	if len(results) != 1 || results[0] == nil {
		t.Fatalf("Expected 1 result from AnalyzeBatch")
	}

	// 5. Test GenerateSearchQueries, TranslateIncident, TranslateIncidentFields, TranslateFieldsToJapanese, LocalizeThreatToJapanese
	queries, err := hybrid.GenerateSearchQueries(ctx, "directive", "web_search", 2)
	if err != nil {
		t.Fatalf("GenerateSearchQueries failed: %v", err)
	}
	if len(queries) == 0 {
		t.Errorf("Expected search queries generated")
	}

	transOut, err := hybrid.TranslateIncident(ctx, IncidentTranslationInput{
		ID:      "inc-1",
		Title:   "タイトル",
		Summary: "要約",
	})
	if err != nil {
		t.Fatalf("TranslateIncident failed: %v", err)
	}
	_ = transOut

	_, _, _, _, err = hybrid.TranslateIncidentFields(ctx, "タイトル", "要約", "影響", []string{"対策"})
	if err != nil {
		t.Fatalf("TranslateIncidentFields failed: %v", err)
	}

	_, _, _, _, err = hybrid.TranslateFieldsToJapanese(ctx, "Title", "Summary", "Impact", []string{"Action"})
	if err != nil {
		t.Fatalf("TranslateFieldsToJapanese failed: %v", err)
	}

	err = hybrid.LocalizeThreatToJapanese(ctx, enriched)
	if err != nil {
		t.Fatalf("LocalizeThreatToJapanese failed: %v", err)
	}

	batchTrans, err := hybrid.TranslateBatch(ctx, []BatchTranslateItem{{ID: "1", Title: "タイトル"}})
	if err != nil {
		t.Fatalf("TranslateBatch failed: %v", err)
	}
	_ = batchTrans

	// 6. Test NewDefaultThreatAnalyzer constructor
	defaultAI := NewDefaultThreatAnalyzer()
	if defaultAI == nil {
		t.Errorf("Expected non-nil default threat analyzer")
	}
}
