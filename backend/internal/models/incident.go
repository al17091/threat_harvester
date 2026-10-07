package models

import (
	"fmt"
	"regexp"
	"sort"
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
	CVEs                []string       `json:"cves,omitempty"`
	AffectedProduct     string         `json:"affected_product,omitempty"`
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
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// IsServiceReleaseOrNonThreat detects service releases, PR announcements, marketing, or general non-threat content.
func IsServiceReleaseOrNonThreat(item ThreatItem, enriched *EnrichedThreat) bool {
	if enriched != nil {
		if enriched.Severity == SeverityInfo {
			return true
		}
		if strings.EqualFold(enriched.AttackType, "Service Release") ||
			strings.EqualFold(enriched.AttackType, "PR") ||
			strings.EqualFold(enriched.AttackType, "Marketing") ||
			strings.EqualFold(enriched.AttackType, "Product Release") ||
			strings.EqualFold(enriched.AttackType, "None") {
			return true
		}
	}

	combined := item.Title + " " + item.Summary
	if enriched != nil {
		combined += " " + enriched.TitleJa + " " + enriched.SummaryJa + " " + enriched.ImpactAnalysisJa
	}
	lower := strings.ToLower(combined)

	// Explicit non-threat markers that override threat indicators (e.g. social chit-chat / no-threat notices)
	explicitNonThreat := []string{
		"セキュリティ脅威なし", "脅威なし", "雑談投稿", "雑談", "個人的な投稿", "減量に関する投稿",
		"サイバー攻撃による侵害ではなく", "攻撃による侵害ではなく", "サイバー攻撃による被害ではなく",
		"公式なデータ収集方針", "自発的な共有", "オプトイン",
	}
	for _, ent := range explicitNonThreat {
		if strings.Contains(lower, ent) {
			return true
		}
	}

	// If it contains verified CVEs or threat actors, it's a threat
	cves := ExtractCVEs(item.Title, item.Summary, item.RawContent, item.URL)
	if len(cves) > 0 {
		return false
	}
	if enriched != nil && len(enriched.CVEs) > 0 {
		return false
	}
	if enriched != nil && len(enriched.ThreatActors) > 0 {
		return false
	}

	// Explicit threat indicators in the raw report - if any exist, do not classify as non-threat
	rawLower := strings.ToLower(item.Title + " " + item.Summary)
	threatIndicators := []string{
		"ゼロデイ", "0-day", "zero-day", "ランサムウェア", "ransomware", "不正アクセス",
		"情報漏洩", "データ漏洩", "情報流出", "マルウェア", "malware", "侵入検知",
		"脆弱性", "vulnerability", "cve-", "dls掲載", "身代金", "攻撃グループ",
		"暗号化された", "サイバー攻撃", "標的型攻撃", "フィッシング", "phishing",
		"認証回避", "任意コード実行", "rce", "バックドア", "backdoor",
	}
	for _, ti := range threatIndicators {
		if strings.Contains(rawLower, ti) {
			return false
		}
	}

	// Service release / PR / marketing / column / chit-chat keywords
	releaseKeywords := []string{
		"提供開始", "新機能", "機能提供", "機能追加", "サービス開始", "サービスリリース",
		"バージョンアップ", "製品リリース", "新サービス", "業務提携", "協業を開始",
		"パートナーシップ", "出展", "セミナー開催", "イベント開催", "スポンサー",
		"新仕様", "仕様を導入", "機能を展開", "広告を表示", "ビジュアル広告",
		"アクセスランキング", "ランキング記事", "セッション紹介", "経団連に入会", "政策提言",
		"asks claude users", "share voice data", "bets security teams",
		"startup looks to", "press release", "プレスリリース",
	}
	for _, rk := range releaseKeywords {
		if strings.Contains(lower, rk) {
			return true
		}
	}

	return false
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

var cveRegex = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)

// ExtractCVEs parses any text inputs and extracts all standardized, unique CVE IDs (e.g. CVE-2026-88771).
func ExtractCVEs(texts ...string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, text := range texts {
		if text == "" {
			continue
		}
		matches := cveRegex.FindAllString(text, -1)
		for _, m := range matches {
			norm := strings.ToUpper(strings.TrimSpace(m))
			if norm != "" && !seen[norm] {
				seen[norm] = true
				result = append(result, norm)
			}
		}
	}
	sort.Strings(result)
	return result
}

// NormalizeProduct normalizes software and product names for vulnerability clustering.
func NormalizeProduct(prod string) string {
	trimmed := strings.TrimSpace(prod)
	if trimmed == "" {
		return ""
	}

	// Remove common Japanese/English enclosing quotes and brackets
	replacer := strings.NewReplacer(
		"「", "", "」", "",
		"『", "", "』", "",
		"【", "", "】", "",
		"（", " ", "）", " ",
		"(", " ", ")", " ",
		"\"", "", "'", "",
	)
	cleaned := replacer.Replace(trimmed)
	lower := strings.ToLower(cleaned)

	// Canonical product aliases
	switch {
	case strings.Contains(lower, "netscaler"):
		return "netscaler"
	case strings.Contains(lower, "fortimail"):
		return "fortimail"
	case strings.Contains(lower, "fortios") || strings.Contains(lower, "fortigate") || strings.Contains(lower, "forticloud"):
		return "fortios"
	case strings.Contains(lower, "fortinet") && !strings.Contains(lower, "fortimail"):
		return "fortinet"
	case strings.Contains(lower, "wordpress"):
		return "wordpress"
	case strings.Contains(lower, "movable type") || strings.Contains(lower, "movabletype"):
		return "movable type"
	case strings.Contains(lower, "routeros") || strings.Contains(lower, "mikrotik"):
		return "mikrotik routeros"
	case strings.Contains(lower, "ivanti"):
		return "ivanti"
	case strings.Contains(lower, "langflow"):
		return "langflow"
	case strings.Contains(lower, "tomcat"):
		return "apache tomcat"
	case strings.Contains(lower, "pan-os") || strings.Contains(lower, "panos") || strings.Contains(lower, "palo alto") || strings.Contains(lower, "globalprotect"):
		return "pan-os"
	case strings.Contains(lower, "exchange"):
		return "microsoft exchange"
	case strings.Contains(lower, "sharepoint"):
		return "microsoft sharepoint"
	case strings.Contains(lower, "esxi") || strings.Contains(lower, "vcenter") || strings.Contains(lower, "vmware"):
		return "vmware"
	case strings.Contains(lower, "confluence"):
		return "atlassian confluence"
	case strings.Contains(lower, "jira"):
		return "atlassian jira"
	case strings.Contains(lower, "gitlab"):
		return "gitlab"
	case strings.Contains(lower, "github"):
		return "github"
	}

	// Strip noise words
	noiseWords := []string{
		"vulnerability", "advisories", "advisory", "zero-day", "0-day",
		"脆弱性", "に関する注意喚起", "不具合", "アップデート", "セキュリティ",
		"security", "update", "patch", "exploit", "悪用",
	}
	for _, nw := range noiseWords {
		lower = strings.ReplaceAll(lower, nw, " ")
	}

	var b strings.Builder
	for _, r := range lower {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == ' ' {
			b.WriteRune(r)
		}
	}
	res := strings.Join(strings.Fields(b.String()), " ")
	if len([]rune(res)) < 3 {
		return ""
	}
	return res
}

// ExtractAffectedProduct identifies the affected product name and its normalized clustering key.
func ExtractAffectedProduct(item ThreatItem, enriched *EnrichedThreat) (string, string) {
	// 1. From enriched metadata
	if enriched != nil {
		for _, p := range enriched.AffectedProducts {
			norm := NormalizeProduct(p)
			if norm != "" {
				return strings.TrimSpace(p), norm
			}
		}
	}

	// 2. From item metadata
	if item.Metadata != nil {
		if p, ok := item.Metadata["affected_product"].(string); ok && p != "" {
			norm := NormalizeProduct(p)
			if norm != "" {
				return strings.TrimSpace(p), norm
			}
		}
		if p, ok := item.Metadata["product"].(string); ok && p != "" {
			norm := NormalizeProduct(p)
			if norm != "" {
				return strings.TrimSpace(p), norm
			}
		}
	}

	// 3. Known product heuristic matching in Title and Summary
	combined := item.Title + " " + item.Summary
	lower := strings.ToLower(combined)

	type knownProduct struct {
		keyword string
		raw     string
		norm    string
	}
	known := []knownProduct{
		{"netscaler", "NetScaler ADC/Gateway", "netscaler"},
		{"fortimail", "Fortinet FortiMail", "fortimail"},
		{"fortios", "Fortinet FortiOS", "fortios"},
		{"fortigate", "Fortinet FortiOS", "fortios"},
		{"wordpress", "WordPress", "wordpress"},
		{"movable type", "Movable Type", "movable type"},
		{"movabletype", "Movable Type", "movable type"},
		{"routeros", "MikroTik RouterOS", "mikrotik routeros"},
		{"mikrotik", "MikroTik RouterOS", "mikrotik routeros"},
		{"ivanti", "Ivanti Connect Secure", "ivanti"},
		{"langflow", "Langflow", "langflow"},
		{"tomcat", "Apache Tomcat", "apache tomcat"},
		{"pan-os", "Palo Alto PAN-OS", "pan-os"},
		{"globalprotect", "Palo Alto GlobalProtect", "pan-os"},
		{"sharepoint", "Microsoft SharePoint", "microsoft sharepoint"},
		{"exchange server", "Microsoft Exchange Server", "microsoft exchange"},
		{"esxi", "VMware ESXi", "vmware"},
		{"vcenter", "VMware vCenter", "vmware"},
		{"confluence", "Atlassian Confluence", "atlassian confluence"},
		{"jira", "Atlassian Jira", "atlassian jira"},
		{"gitlab", "GitLab", "gitlab"},
	}

	for _, kp := range known {
		if strings.Contains(lower, kp.keyword) {
			return kp.raw, kp.norm
		}
	}

	return "", ""
}

