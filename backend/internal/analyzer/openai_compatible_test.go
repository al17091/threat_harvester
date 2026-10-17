package analyzer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dapt/information_harvester/backend/internal/models"
)

func TestOpenAICompatibleAnalyzerMock(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "expected POST", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "chatcmpl-test",
			"choices": [
				{
					"index": 0,
					"message": {
						"role": "assistant",
						"content": "{\n  \"severity\": \"High\",\n  \"japan_relevance\": \"Direct\",\n  \"title\": \"Major Japanese Logistics Firm Hit by Ransomware\",\n  \"summary\": \"Confidential corporate documents leaked on darknet DLS. Operations disrupted.\",\n  \"impact_analysis\": \"Direct impact on domestic supply chain and logistics infrastructure.\",\n  \"victim_orgs\": [\"Tokyo Logistics Co.\"],\n  \"threat_actors\": [\"BlackCat\"],\n  \"attack_type\": \"Ransomware\",\n  \"cves\": [\"CVE-2026-1234\"],\n  \"affected_products\": [\"Citrix Gateway\"],\n  \"recommended_actions\": [\"Isolate affected servers and reset credentials\"]\n}"
					},
					"finish_reason": "stop"
				}
			]
		}`))
	}))
	defer ts.Close()

	analyzer := NewOpenAICompatibleAnalyzer(ts.URL, "qwen2.5-3b-instruct", "", 0.1, true, 5)

	pubDate := time.Now().UTC()
	item := models.NewThreatItem(
		models.SourceTypeDarkwebOnion,
		"Test Harvester",
		"Ransomware Leak Post",
		"http://leak.onion/123",
		"Summary text",
		"Detailed raw leak content mentioning Citrix Gateway and CVE-2026-1234",
		&pubDate,
		nil,
	)

	enriched, err := analyzer.Analyze(context.Background(), item)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if enriched.Severity != models.SeverityHigh {
		t.Errorf("expected Severity High, got %s", enriched.Severity)
	}
	if enriched.JapanRelevance != models.JapanRelevanceDirect {
		t.Errorf("expected JapanRelevance Direct, got %s", enriched.JapanRelevance)
	}
	if enriched.Title != "Major Japanese Logistics Firm Hit by Ransomware" {
		t.Errorf("expected English title, got %s", enriched.Title)
	}
	if enriched.Summary != "Confidential corporate documents leaked on darknet DLS. Operations disrupted." {
		t.Errorf("expected English summary, got %s", enriched.Summary)
	}
	if len(enriched.VictimOrgs) != 1 || enriched.VictimOrgs[0] != "Tokyo Logistics Co." {
		t.Errorf("expected victim org Tokyo Logistics Co., got %v", enriched.VictimOrgs)
	}
	if len(enriched.CVEs) == 0 || enriched.CVEs[0] != "CVE-2026-1234" {
		t.Errorf("expected CVE-2026-1234, got %v", enriched.CVEs)
	}
}

func TestOpenAICompatibleAnalyzerLiveLiteLLM(t *testing.T) {
	// Live test against https://litellm.lab.internal/v1/chat/completions
	analyzer := NewOpenAICompatibleAnalyzer("https://litellm.lab.internal/v1/chat/completions", "qwen2.5-3b-instruct", "", 0.1, true, 15)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	queries, err := analyzer.GenerateSearchQueries(ctx, "japan ransomware leak", "darkweb_search", 2)
	if err != nil {
		t.Logf("Live LiteLLM test skipped/warning (could not reach): %v", err)
		return
	}
	if len(queries) == 0 {
		t.Errorf("expected non-empty queries")
	}
	t.Logf("Generated queries from Live LiteLLM (Qwen2.5-3B): %v", queries)
}

