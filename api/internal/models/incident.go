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
	ID                   string         `json:"id"`
	VictimOrg            string         `json:"victim_org"`
	VictimOrgEn          string         `json:"victim_org_en,omitempty"`
	VictimOrgJa          string         `json:"victim_org_ja,omitempty"`
	NormalizedVictimOrg  string         `json:"normalized_victim_org"`
	CVEs                 []string       `json:"cves,omitempty"`
	AffectedProduct      string         `json:"affected_product,omitempty"`
	AffectedProductEn    string         `json:"affected_product_en,omitempty"`
	AffectedProductJa    string         `json:"affected_product_ja,omitempty"`
	Title                string         `json:"title"`
	TitleJa              string         `json:"title_ja,omitempty"`
	Summary              string         `json:"summary,omitempty"`
	SummaryJa            string         `json:"summary_ja,omitempty"`
	ImpactAnalysis       string         `json:"impact_analysis,omitempty"`
	ImpactAnalysisJa     string         `json:"impact_analysis_ja,omitempty"`
	RecommendedActions   []string       `json:"recommended_actions,omitempty"`
	RecommendedActionsJa []string       `json:"recommended_actions_ja,omitempty"`
	Severity             Severity       `json:"severity"`
	JapanRelevance      JapanRelevance `json:"japan_relevance"`
	AttackType          string         `json:"attack_type,omitempty"`
	RawContent          string         `json:"raw_content,omitempty"`
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

var invalidActorSubstrings = []string{
	"not specified", "not explicitly", "not identified", "not provided", "not named", "not known",
	"likely cybercrime", "likely a cybercrime", "targeting japanese", "targeting corporate",
	"unknown threat actor", "unknown/third-party", "unknown chinese", "unknown (",
	"threat actor", "cybercrime group", "initial access broker",
	"aiを使用した", "aiエージェント", "ai-driven", "rogue openai", "openai agents",
	"state-sponsored", "state sponsored", "国家支援型", "国家背景", "サイバーエスピオナージ",
	"中国系", "中国国家", "北朝鮮国家", "北朝鮮系", "campaign", "vx-underground",
	"related actor", "関連の攻撃者", "に関連する", "operator", "運用グループ",
	"未確認", "未特定", "不特定", "未詳", "特定なし",
	"未知", "未提及", "未确认", "未确定", "威胁行为者", "犯罪集团",
	"不正アクセスの攻撃者", "悪意のある第三者",
	"it労働者", "it workers", "associated groups", "linked actors", "関連グループ",
	"傘下サイバー部隊", "配下グループ", "関連懸念", "国家安全部", "通用技術研究院",
	"darknet army", "darknetarmy",
}

var invalidActorExact = map[string]bool{
	"[]": true, "[ ]": true, "null": true, "nil": true, "undefined": true, "{}": true,
	"[none]": true, "[unknown]": true, "[\"\"]": true,
	"unknown": true, "unspecified": true, "unidentified": true, "unnamed": true,
	"none": true, "n/a": true, "hackers": true, "hacker": true,
	"cybercriminals": true, "cybercriminal": true,
	"attackers": true, "attacker": true, "adversary": true, "adversaries": true,
	"automated attack tools": true, "unauthorized access perpetrators": true,
	"third-party external server provider": true, "microsoft (for publishing updates)": true,
	"openai（エージェントの不正動作）": true, "chaotic eclipse (researcher)": true,
	"nightmare eclipse (研究者)": true, "chaotic eclipse": true, "nightmare eclipse": true,
	"black kite": true, "darknet army": true, "darknetarmy": true,
	"ghostwire": true,
	"world leaks": true, "leakeddata": true, "contagious interview": true,
	"未特定": true, "未確認": true, "不明": true,
	"外部攻撃者": true, "攻撃者": true, "サイバー犯罪者": true, "サイバー攻撃者": true, "ハッカー": true,
	"侵入者": true, "第三者": true, "悪意のある第三者": true,
	"不特定のサイバー攻撃者群": true, "不特定のサイバー犯罪者群": true,
	"未提及具体威胁行为者或犯罪集团": true, "未知威胁行为者": true, "未特定脅威アクター": true,
	"複数の未特定脅威アクター": true, "none identified": true, "none specified": true, "not available": true,
	"黑客": true, "犯罪集团": true,
	"dprk threat actors": true, "chinese apt": true, "china-nexus threat actor": true,
	"north korean state-sponsored actors": true,
	"北朝鮮it労働者": true, "dprk it workers": true, "dprk it workers (北朝鮮it労働者)": true,
	"北朝鮮it労働者 (north korean it workers)": true,
}

// IsValidThreatActor determines if a threat actor name is a legitimate specific entity rather than a generic or unknown disclaimer.
func IsValidThreatActor(actor string) bool {
	s := strings.Trim(strings.TrimSpace(actor), "[]\"' ")
	if s == "" || len([]rune(s)) < 2 || len(s) > 40 {
		return false
	}
	low := strings.ToLower(s)
	if invalidActorExact[low] || strings.HasPrefix(low, "not ") || strings.HasPrefix(low, "unknown") {
		return false
	}
	for _, sub := range invalidActorSubstrings {
		if strings.Contains(low, sub) {
			return false
		}
	}
	return true
}

// CleanThreatActors filters out generic, speculative, or 'unknown' threat actor strings.
func CleanThreatActors(actors []string) []string {
	var valid []string
	seen := make(map[string]bool)
	for _, a := range actors {
		trimmed := strings.Trim(strings.TrimSpace(a), "[]\"' ")
		if !IsValidThreatActor(trimmed) {
			continue
		}
		low := strings.ToLower(trimmed)
		if !seen[low] {
			seen[low] = true
			valid = append(valid, trimmed)
		}
	}
	return valid
}

// IsActorGrounded checks whether an actor name is explicitly mentioned in any of the provided source texts.
func IsActorGrounded(actor string, texts ...string) bool {
	cleaned := strings.Trim(strings.TrimSpace(actor), "[]\"' ")
	if cleaned == "" || len([]rune(cleaned)) < 2 {
		return false
	}
	lowActor := strings.ToLower(cleaned)

	for _, text := range texts {
		t := strings.TrimSpace(text)
		if t == "" {
			continue
		}
		if strings.Contains(strings.ToLower(t), lowActor) {
			return true
		}
	}
	return false
}

// FilterGroundedThreatActors filters out any threat actors that are not explicitly grounded in the source texts.
// If an actor is not explicitly named in the source, it is omitted.
func FilterGroundedThreatActors(actors []string, texts ...string) []string {
	cleaned := CleanThreatActors(actors)
	if len(cleaned) == 0 {
		return nil
	}
	var grounded []string
	for _, a := range cleaned {
		if IsActorGrounded(a, texts...) {
			grounded = append(grounded, a)
		}
	}
	return grounded
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
			strings.EqualFold(enriched.AttackType, "Product Release") {
			return true
		}
		// If AI analyzed and determined this is an active threat (Critical/High/Medium/Low),
		// trust the AI's contextual judgment over keyword heuristics.
		if enriched.Severity == SeverityCritical || enriched.Severity == SeverityHigh ||
			enriched.Severity == SeverityMedium || enriched.Severity == SeverityLow {
			return false
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
	rawLower := strings.ToLower(item.Title + " " + item.Summary + " " + item.RawContent)
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

// ActorStat represents aggregated intelligence for an observed threat actor.
type ActorStat struct {
	Name       string `json:"name"`
	Count      int    `json:"count"`
	JapanCount int    `json:"japan_count"`
	LastSeenAt string `json:"last_seen_at"`
}

// VictimStat represents aggregated intelligence for an observed victim or targeted organization.
type VictimStat struct {
	Name       string `json:"name"`
	NameJa     string `json:"name_ja,omitempty"`
	NameEn     string `json:"name_en,omitempty"`
	Count      int    `json:"count"`
	JapanCount int    `json:"japan_count"`
	LastSeenAt string `json:"last_seen_at"`
}

// EntityStats represents the aggregated summary of all observed threat actors and victims.
type EntityStats struct {
	TotalUniqueActors  int          `json:"total_unique_actors"`
	TotalUniqueVictims int          `json:"total_unique_victims"`
	TopActors          []ActorStat  `json:"top_actors"`
	TopVictims         []VictimStat `json:"top_victims"`
}

// ExtractActorSnippet finds a concise snippet around an actor name inside text.
func ExtractActorSnippet(text, actor string, maxRunes int) string {
	text = strings.TrimSpace(text)
	actor = strings.TrimSpace(actor)
	if text == "" || actor == "" {
		return ""
	}
	if maxRunes <= 0 {
		maxRunes = 160
	}

	lowerText := strings.ToLower(text)
	lowerActor := strings.ToLower(actor)
	idx := strings.Index(lowerText, lowerActor)
	if idx < 0 {
		return ""
	}

	runes := []rune(text)
	// Find rune index corresponding to byte index safely
	prefixRunes := []rune(text[:idx])
	actorRunes := []rune(actor)
	startRune := len(prefixRunes) - 55
	if startRune < 0 {
		startRune = 0
	}
	endRune := len(prefixRunes) + len(actorRunes) + 85
	if endRune > len(runes) {
		endRune = len(runes)
	}

	snippet := strings.TrimSpace(string(runes[startRune:endRune]))
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	snippet = strings.Join(strings.Fields(snippet), " ")
	if startRune > 0 {
		snippet = "..." + snippet
	}
	if endRune < len(runes) {
		snippet = snippet + "..."
	}
	return snippet
}


