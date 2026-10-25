package analyzer

import (
	"context"
	"log"
	"strings"

	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/models"
)

type HybridThreatAnalyzer struct {
	primary           ThreatAnalyzer
	escalation        ThreatAnalyzer
	escalationEnabled bool
	maxLocalRunes     int
	triggerSeverities map[string]bool
	triggerJapanDir   bool
	cfg               config.AiConfig
}

func NewHybridThreatAnalyzer(cfg config.AiConfig) *HybridThreatAnalyzer {
	primary := NewOpenAICompatibleAnalyzer(
		cfg.Endpoint,
		cfg.Model,
		cfg.APIKey,
		cfg.Temperature,
		cfg.InsecureSkipVerify,
		cfg.TimeoutSeconds,
	)

	var escalation ThreatAnalyzer
	escEnabled := cfg.Escalation.Enabled

	// If escalation is enabled and Gemini API key is provided
	geminiKey := cfg.Escalation.GeminiAPIKey
	if geminiKey == "" {
		geminiKey = cfg.GeminiAPIKey
	}
	if geminiKey != "" {
		escalation = NewGeminiThreatAnalyzer()
		escEnabled = true
	} else if escEnabled && geminiKey == "" {
		log.Printf("[HybridAnalyzer] Escalation is enabled but Gemini API key is missing. Running in primary-only mode.")
		escEnabled = false
	}

	maxRunes := cfg.Escalation.MaxLocalContentRunes
	if maxRunes <= 0 {
		maxRunes = 6000
	}

	triggerMap := make(map[string]bool)
	severities := cfg.Hybrid.RefineSeverities
	if len(severities) == 0 {
		severities = cfg.Escalation.TriggerSeverities
	}
	for _, s := range severities {
		triggerMap[strings.ToUpper(strings.TrimSpace(s))] = true
	}
	if len(triggerMap) == 0 {
		triggerMap["CRITICAL"] = true
		triggerMap["HIGH"] = true
	}

	return &HybridThreatAnalyzer{
		primary:           primary,
		escalation:        escalation,
		escalationEnabled: escEnabled,
		maxLocalRunes:     maxRunes,
		triggerSeverities: triggerMap,
		triggerJapanDir:   cfg.Escalation.TriggerJapanDirect,
		cfg:               cfg,
	}
}

func (h *HybridThreatAnalyzer) shouldEscalateByLength(content string) bool {
	if !h.escalationEnabled || h.escalation == nil {
		return false
	}
	return len([]rune(content)) > h.maxLocalRunes
}

func (h *HybridThreatAnalyzer) shouldEscalateByThreat(enriched *models.EnrichedThreat) bool {
	if !h.escalationEnabled || h.escalation == nil || enriched == nil {
		return false
	}
	if h.cfg.Hybrid.Refiner == "none" {
		return false
	}
	if h.cfg.Hybrid.RefineJapanOnly {
		if enriched.JapanRelevance == models.JapanRelevanceNone {
			return false
		}
	}
	sevUpper := strings.ToUpper(string(enriched.Severity))
	if h.triggerSeverities[sevUpper] {
		return true
	}
	if h.triggerJapanDir && enriched.Severity == models.SeverityHigh && enriched.JapanRelevance == models.JapanRelevanceDirect {
		return true
	}
	return false
}

func (h *HybridThreatAnalyzer) Analyze(ctx context.Context, item models.ThreatItem) (*models.EnrichedThreat, error) {
	content := strings.TrimSpace(item.RawContent)
	if content == "" {
		content = strings.TrimSpace(item.Summary)
	}

	// 1. Context overflow: direct escalation to Gemini for long articles
	if h.shouldEscalateByLength(content) {
		log.Printf("[HybridAnalyzer] Article content length (%d runes) exceeds %d runes threshold. Escalating directly to Gemini for item %s", len([]rune(content)), h.maxLocalRunes, item.Title)
		enriched, err := h.escalation.Analyze(ctx, item)
		if err == nil {
			return enriched, nil
		}
		log.Printf("[HybridAnalyzer] Gemini escalation failed: %v. Falling back to primary.", err)
	}

	// 2. Initial threat extraction
	var enriched *models.EnrichedThreat
	var err error
	if h.cfg.Hybrid.Extractor == "gemini" && h.escalation != nil {
		enriched, err = h.escalation.Analyze(ctx, item)
	} else {
		enriched, err = h.primary.Analyze(ctx, item)
		if err != nil && h.escalation != nil {
			log.Printf("[HybridAnalyzer] Primary analysis failed: %v. Falling back to Gemini.", err)
			enriched, err = h.escalation.Analyze(ctx, item)
		}
	}
	if err != nil {
		return nil, err
	}

	// 3. High severity / Japan threat escalation for in-depth CTI refinement
	if h.shouldEscalateByThreat(enriched) {
		log.Printf("[HybridAnalyzer] Threat item %s triggered escalation (Severity: %s, Japan: %s). Escalating to Gemini for deep analysis.", item.Title, enriched.Severity, enriched.JapanRelevance)
		deepEnriched, err := h.escalation.Analyze(ctx, item)
		if err == nil {
			return deepEnriched, nil
		}
		log.Printf("[HybridAnalyzer] Gemini deep analysis failed: %v. Retaining initial analysis.", err)
	}

	// 4. Localize English primary analysis into professional Japanese using Gemini
	if h.escalation != nil && enriched != nil {
		if err := h.escalation.LocalizeThreatToJapanese(ctx, enriched); err != nil {
			log.Printf("[HybridAnalyzer] Gemini Japanese localization failed: %v. Retaining primary text.", err)
		}
	}

	return enriched, nil
}

func (h *HybridThreatAnalyzer) AnalyzeBatch(ctx context.Context, items []models.ThreatItem) ([]*models.EnrichedThreat, error) {
	if len(items) == 0 {
		return nil, nil
	}

	// 1. Ingest & initial batch extraction
	var results []*models.EnrichedThreat
	var err error
	if h.cfg.Hybrid.Extractor == "gemini" && h.escalation != nil {
		results, err = h.escalation.AnalyzeBatch(ctx, items)
	} else {
		results, err = h.primary.AnalyzeBatch(ctx, items)
		if err != nil && h.escalation != nil {
			log.Printf("[HybridAnalyzer] Primary batch analysis failed: %v. Falling back to Gemini.", err)
			results, err = h.escalation.AnalyzeBatch(ctx, items)
		}
	}
	if err != nil {
		return nil, err
	}

	if !h.escalationEnabled || h.escalation == nil {
		return results, nil
	}

	// 2. Process escalation and Japanese localization
	for i, res := range results {
		if res == nil {
			continue
		}
		if h.shouldEscalateByThreat(res) {
			log.Printf("[HybridAnalyzer] Batch item %d (%s) triggered escalation. Refining with Gemini.", i, res.Item.Title)
			refined, err := h.escalation.Analyze(ctx, items[i])
			if err == nil {
				results[i] = refined
				continue
			}
		}

		// Localize primary analysis into professional Japanese using Gemini
		if err := h.escalation.LocalizeThreatToJapanese(ctx, res); err != nil {
			log.Printf("[HybridAnalyzer] Batch item %d Japanese localization failed: %v", i, err)
		}
	}

	return results, nil
}

func (h *HybridThreatAnalyzer) GenerateSearchQueries(ctx context.Context, directive string, targetType string, count int) ([]string, error) {
	if h.cfg.Hybrid.QueryGenerator == "gemini" && h.escalation != nil {
		return h.escalation.GenerateSearchQueries(ctx, directive, targetType, count)
	}
	queries, err := h.primary.GenerateSearchQueries(ctx, directive, targetType, count)
	if err != nil && h.escalation != nil {
		return h.escalation.GenerateSearchQueries(ctx, directive, targetType, count)
	}
	return queries, err
}

func (h *HybridThreatAnalyzer) TranslateIncident(ctx context.Context, input IncidentTranslationInput) (*IncidentTranslationOutput, error) {
	// If Gemini is the configured translator, prefer Gemini for high translation quality
	if (h.cfg.Hybrid.Translator == "gemini" || h.cfg.Hybrid.Translator == "") && h.escalation != nil {
		out, err := h.escalation.TranslateIncident(ctx, input)
		if err == nil {
			return out, nil
		}
		log.Printf("[HybridAnalyzer] Gemini incident translation failed: %v. Falling back to primary.", err)
	}
	out, err := h.primary.TranslateIncident(ctx, input)
	if err != nil && h.escalation != nil {
		return h.escalation.TranslateIncident(ctx, input)
	}
	return out, err
}

func (h *HybridThreatAnalyzer) TranslateIncidentFields(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	if (h.cfg.Hybrid.Translator == "gemini" || h.cfg.Hybrid.Translator == "") && h.escalation != nil {
		tTitle, tSummary, tImpact, tActions, err := h.escalation.TranslateIncidentFields(ctx, title, summary, impact, actions)
		if err == nil {
			return tTitle, tSummary, tImpact, tActions, nil
		}
	}
	tTitle, tSummary, tImpact, tActions, err := h.primary.TranslateIncidentFields(ctx, title, summary, impact, actions)
	if err != nil && h.escalation != nil {
		return h.escalation.TranslateIncidentFields(ctx, title, summary, impact, actions)
	}
	return tTitle, tSummary, tImpact, tActions, err
}

func (h *HybridThreatAnalyzer) TranslateBatch(ctx context.Context, items []BatchTranslateItem) ([]BatchTranslateResult, error) {
	if (h.cfg.Hybrid.Translator == "gemini" || h.cfg.Hybrid.Translator == "") && h.escalation != nil {
		results, err := h.escalation.TranslateBatch(ctx, items)
		if err == nil {
			return results, nil
		}
	}
	return h.primary.TranslateBatch(ctx, items)
}

func (h *HybridThreatAnalyzer) TranslateFieldsToJapanese(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	if h.escalation != nil {
		return h.escalation.TranslateFieldsToJapanese(ctx, title, summary, impact, actions)
	}
	return h.primary.TranslateFieldsToJapanese(ctx, title, summary, impact, actions)
}

func (h *HybridThreatAnalyzer) LocalizeThreatToJapanese(ctx context.Context, enriched *models.EnrichedThreat) error {
	if h.escalation != nil {
		return h.escalation.LocalizeThreatToJapanese(ctx, enriched)
	}
	return h.primary.LocalizeThreatToJapanese(ctx, enriched)
}

// NewDefaultThreatAnalyzer returns the configured analyzer (Hybrid, OpenAI-compatible, or Gemini)
func NewDefaultThreatAnalyzer() ThreatAnalyzer {
	cfg := config.GetSettings().GetConfig()
	if cfg.AI.PrimaryProvider == "gemini" && cfg.AI.GeminiAPIKey != "" {
		return NewGeminiThreatAnalyzer()
	}
	if cfg.AI.PrimaryProvider == "openai_compatible" {
		return NewOpenAICompatibleAnalyzer(
			cfg.AI.Endpoint,
			cfg.AI.Model,
			cfg.AI.APIKey,
			cfg.AI.Temperature,
			cfg.AI.InsecureSkipVerify,
			cfg.AI.TimeoutSeconds,
		)
	}
	return NewHybridThreatAnalyzer(cfg.AI)
}

