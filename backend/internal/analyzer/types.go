package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/al17091/threat_harvester/backend/internal/models"
)

// BatchTranslateItem defines input structure for incident translation.
type BatchTranslateItem struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Summary            string   `json:"summary"`
	ImpactAnalysis     string   `json:"impact_analysis"`
	VictimOrg          string   `json:"victim_org,omitempty"`
	AffectedProduct    string   `json:"affected_product,omitempty"`
	RecommendedActions []string `json:"recommended_actions,omitempty"`
}

// BatchTranslateResult defines translated output structure.
type BatchTranslateResult struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Summary            string   `json:"summary"`
	ImpactAnalysis     string   `json:"impact_analysis"`
	VictimOrgEn        string   `json:"victim_org_en,omitempty"`
	AffectedProductEn  string   `json:"affected_product_en,omitempty"`
	RecommendedActions []string `json:"recommended_actions"`
}

// IncidentTranslationInput defines input for translating an entire incident.
type IncidentTranslationInput struct {
	ID                 string   `json:"id,omitempty"`
	Title              string   `json:"title"`
	Summary            string   `json:"summary"`
	ImpactAnalysis     string   `json:"impact_analysis"`
	VictimOrg          string   `json:"victim_org,omitempty"`
	AffectedProduct    string   `json:"affected_product,omitempty"`
	RecommendedActions []string `json:"recommended_actions,omitempty"`
}

// IncidentTranslationOutput defines translated English incident fields.
type IncidentTranslationOutput struct {
	ID                 string   `json:"id,omitempty"`
	Title              string   `json:"title"`
	Summary            string   `json:"summary"`
	ImpactAnalysis     string   `json:"impact_analysis"`
	VictimOrgEn        string   `json:"victim_org_en,omitempty"`
	AffectedProductEn  string   `json:"affected_product_en,omitempty"`
	RecommendedActions []string `json:"recommended_actions,omitempty"`
}

// ThreatAnalyzer defines common capabilities for AI threat intelligence analysis.
type ThreatAnalyzer interface {
	Analyze(ctx context.Context, item models.ThreatItem) (*models.EnrichedThreat, error)
	AnalyzeBatch(ctx context.Context, items []models.ThreatItem) ([]*models.EnrichedThreat, error)
	GenerateSearchQueries(ctx context.Context, directive string, targetType string, count int) ([]string, error)
	TranslateIncidentFields(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error)
	TranslateFieldsToJapanese(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error)
	LocalizeThreatToJapanese(ctx context.Context, enriched *models.EnrichedThreat) error
	TranslateIncident(ctx context.Context, input IncidentTranslationInput) (*IncidentTranslationOutput, error)
	TranslateBatch(ctx context.Context, items []BatchTranslateItem) ([]BatchTranslateResult, error)
}

// AnalysisOutput represents the structured JSON output from LLM analysis.
type AnalysisOutput struct {
	Index                int      `json:"index,omitempty"`
	Severity             string   `json:"severity"`
	JapanRelevance       string   `json:"japan_relevance"`
	Title                string   `json:"title,omitempty"`
	TitleEn              string   `json:"title_en,omitempty"`
	TitleJa              string   `json:"title_ja,omitempty"`
	Summary              string   `json:"summary,omitempty"`
	SummaryEn            string   `json:"summary_en,omitempty"`
	SummaryJa            string   `json:"summary_ja,omitempty"`
	ImpactAnalysis       string   `json:"impact_analysis,omitempty"`
	ImpactAnalysisEn     string   `json:"impact_analysis_en,omitempty"`
	ImpactAnalysisJa     string   `json:"impact_analysis_ja,omitempty"`
	VictimOrgs           []string          `json:"victim_orgs"`
	ThreatActors         []string          `json:"threat_actors"`
	ThreatActorReasons   map[string]string `json:"threat_actor_reasons,omitempty"`
	AttackType           string            `json:"attack_type"`
	CVEs                 []string          `json:"cves,omitempty"`
	AffectedProducts     []string          `json:"affected_products,omitempty"`
	RecommendedActions   []string          `json:"recommended_actions,omitempty"`
	RecommendedActionsEn []string          `json:"recommended_actions_en,omitempty"`
	RecommendedActionsJa []string          `json:"recommended_actions_ja,omitempty"`
}

// ResolveThreatActorReasons normalizes LLM-provided reasons and falls back to extracting context snippets from the ThreatItem.
func ResolveThreatActorReasons(item models.ThreatItem, cleanActors []string, rawReasons map[string]string) map[string]string {
	if len(cleanActors) == 0 {
		return nil
	}
	reasons := make(map[string]string, len(cleanActors))
	srcLabel := strings.TrimSpace(item.SourceName)
	if srcLabel == "" {
		srcLabel = string(item.SourceType)
	}

	for _, actor := range cleanActors {
		var matchedReason string
		for k, v := range rawReasons {
			if strings.EqualFold(strings.TrimSpace(k), actor) && strings.TrimSpace(v) != "" {
				matchedReason = strings.TrimSpace(v)
				break
			}
		}
		if matchedReason != "" {
			if srcLabel != "" && !strings.Contains(strings.ToLower(matchedReason), strings.ToLower(srcLabel)) {
				matchedReason = fmt.Sprintf("[%s] %s", srcLabel, matchedReason)
			}
			reasons[actor] = matchedReason
			continue
		}

		// Automatic snippet extraction from item fields
		if snip := models.ExtractActorSnippet(item.Title, actor, 140); snip != "" {
			reasons[actor] = fmt.Sprintf("[%s] Mentioned in report title: \"%s\"", srcLabel, snip)
			continue
		}
		if snip := models.ExtractActorSnippet(item.RawContent, actor, 160); snip != "" {
			reasons[actor] = fmt.Sprintf("[%s] Mentioned in report body: \"%s\"", srcLabel, snip)
			continue
		}
		if snip := models.ExtractActorSnippet(item.Summary, actor, 160); snip != "" {
			reasons[actor] = fmt.Sprintf("[%s] Mentioned in report summary: \"%s\"", srcLabel, snip)
			continue
		}
		if item.Metadata != nil {
			metaBytes, _ := json.Marshal(item.Metadata)
			if snip := models.ExtractActorSnippet(string(metaBytes), actor, 140); snip != "" {
				reasons[actor] = fmt.Sprintf("[%s] Attributed in feed metadata: %s", srcLabel, snip)
				continue
			}
		}
		reasons[actor] = fmt.Sprintf("[%s] Identified by AI analysis from report context", srcLabel)
	}
	return reasons
}

// CleanJSONFences removes markdown code fences around JSON outputs.
func CleanJSONFences(raw string) string {
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	return strings.TrimSpace(raw)
}

// ParseActionsFlexible parses recommended actions from either a string slice or a single string with newlines.
func ParseActionsFlexible(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		var res []string
		for _, a := range arr {
			a = strings.TrimSpace(a)
			if a != "" {
				res = append(res, a)
			}
		}
		return res
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil
		}
		lines := strings.Split(s, "\n")
		var clean []string
		for _, l := range lines {
			l = strings.TrimSpace(l)
			l = strings.TrimLeft(l, "-*0123456789. ")
			l = strings.TrimSpace(l)
			if l != "" {
				clean = append(clean, l)
			}
		}
		if len(clean) > 0 {
			return clean
		}
		return []string{s}
	}
	return nil
}

// BuildEnrichedThreatFromOutput builds models.EnrichedThreat from raw AnalysisOutput.
func BuildEnrichedThreatFromOutput(item models.ThreatItem, out AnalysisOutput) *models.EnrichedThreat {
	severity := models.Severity(out.Severity)
	switch severity {
	case models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo:
	default:
		severity = models.SeverityUnknown
	}

	attackType := out.AttackType
	if severity == models.SeverityUnknown {
		if models.IsServiceReleaseOrNonThreat(item, nil) {
			severity = models.SeverityInfo
			if attackType == "" {
				attackType = "Service Release"
			}
		}
	}

	japanRel := models.JapanRelevance(out.JapanRelevance)
	switch japanRel {
	case models.JapanRelevanceDirect, models.JapanRelevanceIndirect, models.JapanRelevanceNone:
	default:
		japanRel = models.JapanRelevanceUnknown
	}

	// Resolve title (prefer English, fallback to Ja or item title)
	title := out.Title
	if title == "" {
		title = out.TitleEn
	}
	if title == "" {
		title = out.TitleJa
	}
	if title == "" {
		title = item.Title
	}

	// Resolve summary
	summary := out.Summary
	if summary == "" {
		summary = out.SummaryEn
	}
	if summary == "" {
		summary = out.SummaryJa
	}
	if summary == "" {
		summary = item.Summary
	}

	// Resolve impact analysis
	impact := out.ImpactAnalysis
	if impact == "" {
		impact = out.ImpactAnalysisEn
	}
	if impact == "" {
		impact = out.ImpactAnalysisJa
	}

	// Resolve recommended actions
	actions := out.RecommendedActions
	if len(actions) == 0 {
		actions = out.RecommendedActionsEn
	}
	if len(actions) == 0 {
		actions = out.RecommendedActionsJa
	}

	// Extract & merge CVEs
	cves := models.ExtractCVEs(item.Title, item.Summary, item.RawContent, item.URL)
	if len(out.CVEs) > 0 {
		cves = append(cves, models.ExtractCVEs(out.CVEs...)...)
	}
	seenCVE := make(map[string]bool)
	var uniqueCVEs []string
	for _, c := range cves {
		if !seenCVE[c] {
			seenCVE[c] = true
			uniqueCVEs = append(uniqueCVEs, c)
		}
	}

	// Extract & merge Affected products
	var affectedProducts []string
	for _, p := range out.AffectedProducts {
		norm := models.NormalizeProduct(p)
		if norm != "" {
			affectedProducts = append(affectedProducts, strings.TrimSpace(p))
		}
	}
	if len(affectedProducts) == 0 {
		rawProd, _ := models.ExtractAffectedProduct(item, nil)
		if rawProd != "" {
			affectedProducts = append(affectedProducts, rawProd)
		}
	}

	titleJa := strings.TrimSpace(out.TitleJa)
	if titleJa == "" {
		titleJa = title
	}
	summaryJa := strings.TrimSpace(out.SummaryJa)
	if summaryJa == "" {
		summaryJa = summary
	}
	impactJa := strings.TrimSpace(out.ImpactAnalysisJa)
	if impactJa == "" {
		impactJa = impact
	}
	actionsJa := out.RecommendedActionsJa
	if len(actionsJa) == 0 {
		actionsJa = actions
	}

	metaBytes, _ := json.Marshal(item.Metadata)
	groundedActors := models.FilterGroundedThreatActors(
		out.ThreatActors,
		item.Title,
		item.Summary,
		item.RawContent,
		item.URL,
		string(metaBytes),
	)
	actorReasons := ResolveThreatActorReasons(item, groundedActors, out.ThreatActorReasons)

	return &models.EnrichedThreat{
		ItemID:               item.ID,
		Item:                 item,
		Severity:             severity,
		JapanRelevance:       japanRel,
		Title:                title,
		TitleJa:              titleJa,
		Summary:              summary,
		SummaryJa:            summaryJa,
		ImpactAnalysis:       impact,
		ImpactAnalysisJa:     impactJa,
		VictimOrgs:           out.VictimOrgs,
		ThreatActors:         groundedActors,
		ThreatActorReasons:   actorReasons,
		AttackType:           attackType,
		CVEs:                 uniqueCVEs,
		AffectedProducts:     affectedProducts,
		RecommendedActions:   actions,
		RecommendedActionsJa: actionsJa,
		AnalyzedAt:           time.Now().UTC(),
	}
}

