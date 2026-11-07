package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/al17091/threat_harvester/api/internal/models"
)

// AgentClientAnalyzer delegates threat analysis to the autonomous TypeScript CTI Agent service.
type AgentClientAnalyzer struct {
	endpoint string
	client   *http.Client
}

// NewAgentClientAnalyzer initializes a client to the autonomous agent service.
func NewAgentClientAnalyzer(endpoint string, timeoutSec int) *AgentClientAnalyzer {
	if endpoint == "" {
		endpoint = "http://threat-harvester-agent:8002"
	}
	if timeoutSec <= 0 {
		timeoutSec = 180
	}
	return &AgentClientAnalyzer{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: time.Duration(timeoutSec) * time.Second,
		},
	}
}

func (a *AgentClientAnalyzer) Analyze(ctx context.Context, item models.ThreatItem) (*models.EnrichedThreat, error) {
	url := fmt.Sprintf("%s/analyze", a.endpoint)
	bodyBytes, err := json.Marshal(item)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ThreatItem: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create agent request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent service request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("agent returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var enriched models.EnrichedThreat
	if err := json.NewDecoder(resp.Body).Decode(&enriched); err != nil {
		return nil, fmt.Errorf("failed to decode agent response: %w", err)
	}

	enriched.ItemID = item.ID
	enriched.Item = item
	if enriched.AnalyzedAt.IsZero() {
		enriched.AnalyzedAt = time.Now().UTC()
	}

	return &enriched, nil
}

func (a *AgentClientAnalyzer) AnalyzeBatch(ctx context.Context, items []models.ThreatItem) ([]*models.EnrichedThreat, error) {
	if len(items) == 0 {
		return nil, nil
	}
	url := fmt.Sprintf("%s/analyze/batch", a.endpoint)
	payload := map[string]interface{}{"items": items}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch items: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create batch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("agent batch request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("agent batch returned HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var batchResp struct {
		Results []*models.EnrichedThreat `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&batchResp); err != nil {
		return nil, fmt.Errorf("failed to decode batch response: %w", err)
	}

	for i, r := range batchResp.Results {
		if r != nil && i < len(items) {
			r.ItemID = items[i].ID
			r.Item = items[i]
			if r.AnalyzedAt.IsZero() {
				r.AnalyzedAt = time.Now().UTC()
			}
		}
	}

	return batchResp.Results, nil
}

func (a *AgentClientAnalyzer) GenerateSearchQueries(ctx context.Context, directive string, targetType string, count int) ([]string, error) {
	return nil, nil
}

func (a *AgentClientAnalyzer) TranslateIncident(ctx context.Context, input IncidentTranslationInput) (*IncidentTranslationOutput, error) {
	return &IncidentTranslationOutput{
		Title:          input.Title,
		Summary:        input.Summary,
		ImpactAnalysis: input.ImpactAnalysis,
	}, nil
}

func (a *AgentClientAnalyzer) TranslateIncidentFields(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	return title, summary, impact, actions, nil
}

func (a *AgentClientAnalyzer) TranslateBatch(ctx context.Context, items []BatchTranslateItem) ([]BatchTranslateResult, error) {
	results := make([]BatchTranslateResult, len(items))
	for i, it := range items {
		results[i] = BatchTranslateResult{
			ID:             it.ID,
			Title:          it.Title,
			Summary:        it.Summary,
			ImpactAnalysis: it.ImpactAnalysis,
		}
	}
	return results, nil
}

func (a *AgentClientAnalyzer) TranslateBatchToJapanese(ctx context.Context, items []BatchTranslateItem) ([]BatchTranslateResult, error) {
	results := make([]BatchTranslateResult, len(items))
	for i, it := range items {
		results[i] = BatchTranslateResult{
			ID:             it.ID,
			Title:          it.Title,
			Summary:        it.Summary,
			ImpactAnalysis: it.ImpactAnalysis,
		}
	}
	return results, nil
}

func (a *AgentClientAnalyzer) TranslateFieldsToJapanese(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	return title, summary, impact, actions, nil
}

func (a *AgentClientAnalyzer) LocalizeThreatToJapanese(ctx context.Context, enriched *models.EnrichedThreat) error {
	log.Printf("[AgentClient] LocalizeThreatToJapanese no-op (agent handles localization natively)")
	return nil
}

