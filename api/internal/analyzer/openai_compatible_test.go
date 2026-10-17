package analyzer

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/al17091/threat_harvester/api/internal/models"
)

func mockChatResp(content string) chatCompletionResponse {
	var resp chatCompletionResponse
	resp.Choices = append(resp.Choices, struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	}{
		Message: struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{
			Role:    "assistant",
			Content: content,
		},
	})
	return resp
}

func TestOpenAICompatibleAnalyzer_LifecycleAndMethods(t *testing.T) {
	// Setup mock server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatCompletionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		userMsg := ""
		systemMsg := ""
		for _, m := range req.Messages {
			if m.Role == "user" {
				userMsg = m.Content
			}
			if m.Role == "system" {
				systemMsg = m.Content
			}
		}

		if userMsg == "ping" {
			_ = json.NewEncoder(w).Encode(mockChatResp("pong"))
			return
		}

		if strings.Contains(userMsg, "User Monitoring Directive") {
			// GenerateSearchQueries response
			queries := []string{"query1", "query2"}
			bytes, _ := json.Marshal(queries)
			_ = json.NewEncoder(w).Encode(mockChatResp(string(bytes)))
			return
		}

		if strings.Contains(systemMsg, "editor and translator") {
			// Translation response
			transResp := map[string]interface{}{
				"title":               "Translated Title",
				"summary":             "Translated Summary",
				"impact_analysis":     "Translated Impact",
				"victim_org_en":       "Victim Org Corp",
				"affected_product_en": "Affected Product Pro",
				"recommended_actions": []string{"Apply patch", "Monitor traffic"},
			}
			bytes, _ := json.Marshal(transResp)
			_ = json.NewEncoder(w).Encode(mockChatResp(string(bytes)))
			return
		}

		// Analysis response
		analysisResp := map[string]interface{}{
			"severity":             "High",
			"japan_relevance":      "Direct",
			"title":                "Analyzed Incident",
			"summary":              "Analyzed Summary",
			"impact_analysis":      "Analyzed Impact",
			"victim_orgs":          []string{"Target Org"},
			"threat_actors":        []string{"Lazarus"},
			"threat_actor_reasons": map[string]string{"Lazarus": "Explicit attribution in report"},
			"attack_type":          "Ransomware",
			"affected_products":    []string{"VPN Gateway"},
			"cves":                 []string{"CVE-2024-1234"},
			"indicators_of_compromise": []string{"192.168.1.1"},
			"recommended_actions":  []string{"Isolate host"},
		}
		bytes, _ := json.Marshal(analysisResp)
		_ = json.NewEncoder(w).Encode(mockChatResp(string(bytes)))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	analyzer := NewOpenAICompatibleAnalyzer(server.URL, "test-model", "test-key", 0.1, true, 5)
	ctx := context.Background()

	// 1. TestConnection
	if ok := analyzer.TestConnection(ctx); !ok {
		t.Errorf("TestConnection expected true, got false")
	}

	// 2. Analyze
	item := models.ThreatItem{
		ID:         "test-item-1",
		Title:      "Suspicious Activity Detected",
		RawContent: "A severe ransomware incident affected Target Org via VPN Gateway.",
		Metadata:   map[string]interface{}{"source": "threat_intel"},
	}
	enriched, err := analyzer.Analyze(ctx, item)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if enriched.Severity != "High" {
		t.Errorf("Expected severity High, got %s", enriched.Severity)
	}
	if enriched.JapanRelevance != "Direct" {
		t.Errorf("Expected relevance Direct, got %s", enriched.JapanRelevance)
	}
	if len(enriched.ThreatActors) == 0 || enriched.ThreatActors[0] != "Lazarus" {
		t.Errorf("Expected Lazarus threat actor, got %v", enriched.ThreatActors)
	}

	// 3. AnalyzeBatch
	batchEnriched, err := analyzer.AnalyzeBatch(ctx, []models.ThreatItem{item})
	if err != nil {
		t.Fatalf("AnalyzeBatch failed: %v", err)
	}
	if len(batchEnriched) != 1 || batchEnriched[0].Severity != "High" {
		t.Errorf("AnalyzeBatch result unexpected: %+v", batchEnriched)
	}

	// 4. GenerateSearchQueries
	queries, err := analyzer.GenerateSearchQueries(ctx, "directive", "target", 2)
	if err != nil {
		t.Fatalf("GenerateSearchQueries failed: %v", err)
	}
	if len(queries) != 2 || queries[0] != "query1" {
		t.Errorf("GenerateSearchQueries returned unexpected queries: %v", queries)
	}

	// 5. TranslateIncident
	transOut, err := analyzer.TranslateIncident(ctx, IncidentTranslationInput{
		ID:                 "inc-1",
		Title:              "日本語タイトル",
		Summary:            "概要",
		ImpactAnalysis:     "影響",
		VictimOrg:          "被害組織",
		AffectedProduct:    "製品",
		RecommendedActions: []string{"対策"},
	})
	if err != nil {
		t.Fatalf("TranslateIncident failed: %v", err)
	}
	if transOut.Title != "Translated Title" {
		t.Errorf("Expected Translated Title, got %s", transOut.Title)
	}

	// 6. TranslateIncidentFields
	tTitle, tSum, tImp, tAct, err := analyzer.TranslateIncidentFields(ctx, "日本語タイトル", "概要", "影響", []string{"対策"})
	if err != nil {
		t.Fatalf("TranslateIncidentFields failed: %v", err)
	}
	if tTitle != "Translated Title" || tSum != "Translated Summary" || tImp != "Translated Impact" || len(tAct) != 2 {
		t.Errorf("TranslateIncidentFields result mismatch: %s, %v", tTitle, tAct)
	}

	// 7. TranslateBatch
	batchResults, err := analyzer.TranslateBatch(ctx, []BatchTranslateItem{
		{
			ID:                 "inc-1",
			Title:              "日本語タイトル",
			Summary:            "概要",
			ImpactAnalysis:     "影響",
			VictimOrg:          "被害組織",
			AffectedProduct:    "製品",
			RecommendedActions: []string{"対策"},
		},
	})
	if err != nil {
		t.Fatalf("TranslateBatch failed: %v", err)
	}
	if len(batchResults) != 1 || batchResults[0].Title != "Translated Title" {
		t.Errorf("TranslateBatch unexpected result: %+v", batchResults)
	}

	// 8. TranslateFieldsToJapanese & LocalizeThreatToJapanese fallbacks
	_, _, _, _, err = analyzer.TranslateFieldsToJapanese(ctx, "Title", "Summary", "Impact", nil)
	if err == nil {
		t.Errorf("Expected error from TranslateFieldsToJapanese on primary local model, got nil")
	}
	if err := analyzer.LocalizeThreatToJapanese(ctx, enriched); err != nil {
		t.Errorf("Expected LocalizeThreatToJapanese to return nil, got %v", err)
	}
}

func TestOpenAICompatibleAnalyzer_ErrorHandling(t *testing.T) {
	// Server that returns 500 error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	analyzer := NewOpenAICompatibleAnalyzer(server.URL, "", "", 0, false, 0)
	ctx := context.Background()

	if ok := analyzer.TestConnection(ctx); ok {
		t.Errorf("TestConnection expected false on 500 status")
	}

	item := models.ThreatItem{ID: "err-item", Summary: "testing failure"}
	_, err := analyzer.Analyze(ctx, item)
	if err == nil {
		t.Errorf("Expected error from Analyze when server returns 500, got nil")
	}

	queries, _ := analyzer.GenerateSearchQueries(ctx, "fallback query", "target", 1)
	if len(queries) != 1 || queries[0] != "fallback query" {
		t.Errorf("Expected fallback query on error, got %v", queries)
	}

	transOut, err := analyzer.TranslateIncident(ctx, IncidentTranslationInput{
		ID:    "inc-err",
		Title: "Fallback Title",
	})
	if err == nil {
		t.Errorf("Expected error from TranslateIncident on 500 status")
	}
	if transOut.Title != "Fallback Title" {
		t.Errorf("Expected original title fallback, got %s", transOut.Title)
	}
}
