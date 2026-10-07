package models

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// SourceDetail captures individual report metadata attached to a clustered Incident.
type SourceDetail struct {
	Type        SourceType `json:"source_type"`
	Name        string     `json:"source_name"`
	Title       string     `json:"title"`
	URL         string     `json:"url"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	HarvestedAt time.Time  `json:"harvested_at"`
}

// Incident represents a STIX 2.1 compliant clustered cyber threat incident (incident--<UUIDv4>).
type Incident struct {
	ID                  string         `json:"id"`
	VictimOrg           string         `json:"victim_org"`
	NormalizedVictimOrg string         `json:"normalized_victim_org"`
	Title               string         `json:"title"`
	SummaryJa           string         `json:"summary_ja"`
	ImpactAnalysisJa    string         `json:"impact_analysis_ja"`
	Severity            Severity       `json:"severity"`
	JapanRelevance      JapanRelevance `json:"japan_relevance"`
	AttackType          string         `json:"attack_type,omitempty"`
	PrimaryURL          string         `json:"primary_url"`
	SourceURLs          []string       `json:"source_urls"`
	SourcesDetail       []SourceDetail `json:"sources_detail"`
	FirstSeenAt         time.Time      `json:"first_seen_at"`
	LastSeenAt          time.Time      `json:"last_seen_at"`
	ReportCount         int            `json:"report_count"`
	ThreatActors        []string       `json:"threat_actors"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
}

// NewSTIXIncidentID generates a STIX 2.1 compliant identifier: incident--<UUIDv4>.
func NewSTIXIncidentID() string {
	return fmt.Sprintf("incident--%s", uuid.NewString())
}

var genericVictimWords = map[string]bool{
	"japan": true, "japanese": true, "日本": true, "日本企業": true, "日本組織": true,
	"国内企業": true, "国内組織": true, "政府機関": true, "各企業": true, "複数企業": true,
	"multiple": true, "unknown": true, "n/a": true, "none": true, "various": true,
	"victim": true, "target": true, "organization": true, "company": true,
	"企業": true, "病院": true, "大学": true, "自治体": true, "学校": true,
}

// IsGenericVictimOrg checks if a victim organization name is too generic to cluster on safely.
func IsGenericVictimOrg(name string) bool {
	cleaned := strings.ToLower(strings.TrimSpace(name))
	if cleaned == "" || len([]rune(cleaned)) < 2 {
		return true
	}
	return genericVictimWords[cleaned]
}

// NormalizeVictimOrg normalizes an organization name for clustering.
// Strips common corporate affixes (株式会社, Co., Ltd., etc.), whitespace, and punctuation.
func NormalizeVictimOrg(org string) string {
	trimmed := strings.TrimSpace(org)
	if IsGenericVictimOrg(trimmed) {
		return ""
	}

	lower := strings.ToLower(trimmed)

	// Remove common Japanese corporate affixes
	jpAffixes := []string{
		"株式会社", "有限会社", "合同会社", "一般社団法人", "公益財団法人",
		"独立行政法人", "学校法人", "医療法人",
	}
	for _, affix := range jpAffixes {
		lower = strings.ReplaceAll(lower, affix, "")
	}

	// Remove English corporate affixes (longest phrases first)
	enAffixes := []string{
		"corporation", "co., ltd.", "co.,ltd.", "co. ltd.", "co. ltd",
		"holdings", "holding", "group", "corp.", "corp", "inc.", "inc",
		"ltd.", "ltd", "llc", "plc",
	}
	for _, affix := range enAffixes {
		lower = strings.ReplaceAll(lower, affix, "")
	}

	// Remove symbols and extra spaces
	var b strings.Builder
	for _, r := range lower {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	res := strings.TrimSpace(b.String())
	if len([]rune(res)) < 2 || genericVictimWords[res] {
		return ""
	}
	return res
}

// ExtractVictimOrgs returns all unique victim orgs and their normalized forms.
func ExtractVictimOrgs(item ThreatItem, enriched *EnrichedThreat) ([]string, []string) {
	var raws, norms []string
	seen := make(map[string]bool)

	add := func(v string) {
		t := strings.TrimSpace(v)
		if t == "" || seen[t] {
			return
		}
		seen[t] = true
		n := NormalizeVictimOrg(t)
		if n != "" {
			raws = append(raws, t)
			norms = append(norms, n)
		}
	}

	if enriched != nil {
		for _, org := range enriched.VictimOrgs {
			add(org)
		}
	}

	if item.Metadata != nil {
		if v, ok := item.Metadata["victim"].(string); ok && v != "" {
			add(v)
		}
	}

	// Darkweb titles often contain "Victim: <name> ("
	if strings.Contains(item.Title, "Victim:") {
		parts := strings.Split(item.Title, "Victim:")
		if len(parts) > 1 {
			raw := parts[1]
			if idx := strings.Index(raw, "("); idx != -1 {
				raw = raw[:idx]
			}
			add(raw)
		}
	}

	return raws, norms
}

// ExtractVictimOrg extracts the best available primary victim org and its normalized form.
func ExtractVictimOrg(item ThreatItem, enriched *EnrichedThreat) (string, string) {
	raws, norms := ExtractVictimOrgs(item, enriched)
	if len(raws) > 0 {
		return raws[0], norms[0]
	}
	return "", ""
}

// SeverityScore returns a numeric score for comparison (higher = more severe).
func SeverityScore(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// HigherSeverity returns the higher of two severities.
func HigherSeverity(a, b Severity) Severity {
	if SeverityScore(b) > SeverityScore(a) {
		return b
	}
	return a
}

// RelevanceScore returns a numeric score for comparison (higher = more relevant).
func RelevanceScore(r JapanRelevance) int {
	switch r {
	case JapanRelevanceDirect:
		return 3
	case JapanRelevanceIndirect:
		return 2
	case JapanRelevanceNone:
		return 1
	default:
		return 0
	}
}

// HigherRelevance returns the higher of two relevance levels.
func HigherRelevance(a, b JapanRelevance) JapanRelevance {
	if RelevanceScore(b) > RelevanceScore(a) {
		return b
	}
	return a
}
