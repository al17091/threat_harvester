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
	"multiple organizations": true, "japanese enterprises": true, "not specified": true,
	"various organizations": true, "various companies": true, "domestic companies": true,
	"japanese companies": true, "domestic organizations": true, "japanese entities": true,
	"各社": true, "複数社": true, "不特定": true, "未特定": true,
}

var genericVictimSubstrings = []string{
	"multiple organization", "multiple enterprise", "multiple compan", "multiple domestic",
	"global trend report", "trend report", "annual report", "survey report", "cybersecurity survey",
	"not specified", "unspecified", "not identified", "unknown organization", "unknown victim",
	"various organization", "various compan", "japanese enterprise", "japanese organization",
	"japanese compan", "japanese entit", "domestic enterprise", "domestic compan",
	"domestic organization", "domestic entit", "private companies", "government/municipalities",
	"critical infrastructure", "国内の企業", "国内の組織", "不特定の", "複数の企業",
	"複数の組織", "各企業", "複数企業", "各組織", "複数組織", "サプライチェーン", "調査レポート",
}

// IsGenericVictimOrg checks if a victim organization name is too generic to cluster on safely.
func IsGenericVictimOrg(name string) bool {
	cleaned := strings.ToLower(strings.TrimSpace(name))
	if cleaned == "" || len([]rune(cleaned)) < 2 {
		return true
	}
	if genericVictimWords[cleaned] {
		return true
	}
	for _, sub := range genericVictimSubstrings {
		if strings.Contains(cleaned, sub) {
			return true
		}
	}
	return false
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
		"インターネットグループ", "インターネット",
		"株式会社", "有限会社", "合同会社", "一般社団法人", "公益財団法人",
		"独立行政法人", "学校法人", "医療法人",
		"ホールディングス", "グループ", "集團", "集团",
	}
	for _, affix := range jpAffixes {
		lower = strings.ReplaceAll(lower, affix, "")
	}

	// Remove English corporate affixes (longest phrases first)
	enAffixes := []string{
		"corporation", "co., ltd.", "co.,ltd.", "co. ltd.", "co. ltd",
		"internet group", "internet",
		"holdings", "holding", "group", "corp.", "corp", "inc.", "inc",
		"ltd.", "ltd", "llc", "plc",
	}
	for _, affix := range enAffixes {
		lower = strings.ReplaceAll(lower, affix, "")
	}

	// Canonical brand / service mapping to parent organizations
	if strings.Contains(lower, "お名前.com") || strings.Contains(lower, "お名前com") || strings.Contains(lower, "onamae") {
		return "gmo"
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

// HasRansomOrExtortionIntel checks whether the provided texts contain active threat intelligence
// regarding ransom demands, ransom payments, financial extortion, or dark web leak site publications.
// Such reports MUST be retained as threat intelligence even if they originate from corporate announcements.
func HasRansomOrExtortionIntel(texts ...string) bool {
	combined := strings.ToLower(strings.Join(texts, " "))
	if strings.TrimSpace(combined) == "" {
		return false
	}

	// 1. Explicit ransom and extortion keywords
	ransomTerms := []string{
		"身代金", "二重脅迫", "多重脅迫", "金銭要求", "金銭の要求",
		"暗号資産で要求", "ビットコインで要求", "btcで要求", "仮想通貨で要求",
		"攻撃者に支払", "攻撃者への支払", "犯人に支払", "犯人への支払", "ハッカーに支払", "ハッカーへの支払",
		"身代金の支払", "身代金支払", "身代金支払い",
		"ransom payment", "paid the ransom", "paid ransom", "demanded ransom", "demanding ransom",
		"demanding payment", "extortion demand", "extortion payment", "double extortion",
		"leak site", "data leak site", "リークサイト", "ダークウェブ", "dark web",
		"懸賞金", "bug bounty", "bounty",
	}
	for _, term := range ransomTerms {
		if strings.Contains(combined, term) {
			return true
		}
	}

	// 2. Ransom / extortion context combined with payment, demand, or cryptocurrency
	isRansomContext := strings.Contains(combined, "ランサム") ||
		strings.Contains(combined, "ransom") ||
		strings.Contains(combined, "脅迫") ||
		strings.Contains(combined, "恐喝") ||
		strings.Contains(combined, "extortion")

	if isRansomContext {
		demandOrPayment := []string{
			"支払", "要求", "ビットコイン", "bitcoin", "btc", "暗号資産", "仮想通貨",
			"cryptocurrency", "億", "万ドル", "usd", "pay", "demand", "million",
		}
		for _, dop := range demandOrPayment {
			if strings.Contains(combined, dop) {
				return true
			}
		}
	}

	return false
}

// IsCorporatePRNotice determines if an item is a purely corporate public relations (PR),
// post-incident customer communication, apology, service recovery update, user sympathy payment,
// or administrative petition that should not be handled as a cyber threat incident in the application.
//
// Exception: If the item contains active threat intelligence regarding ransom payments, ransom demands,
// or extortion (e.g., whether a ransom was paid or demanded), it returns false so it is retained.
func IsCorporatePRNotice(texts ...string) bool {
	combined := strings.ToLower(strings.Join(texts, " "))
	if strings.TrimSpace(combined) == "" {
		return false
	}

	// Exception: If the report contains ransom or extortion intel, DO NOT drop.
	if HasRansomOrExtortionIntel(texts...) {
		return false
	}

	corporatePRMarkers := []string{
		// Apology & generic corporate notices
		"お詫びとお知らせ", "お詫びとご報告", "お詫びとお願い", "深くお詫び", "に関するお詫び", "不正アクセスに関するお詫び",
		"notice of apology", "apology and notice", "apology regarding",
		// Progress, intermediate, and third-party investigation reports
		"経過報告", "進捗報告", "調査結果のご報告", "調査結果について", "調査結果中間報告", "中間報告",
		"調査委員会", "特別調査委員会", "第三者委員会", "第三者調査機関", "外部専門機関による調査",
		"progress report", "interim report", "investigation committee", "third-party investigation",
		// Outage, maintenance, and service restoration notices
		"サーバー停止", "サーバー再開", "サービス停止", "サービス再開", "サービス一時停止", "サービスの一時停止",
		"復旧状況", "復旧進捗", "復旧報告", "復旧作業", "復旧のお知らせ", "復旧完了", "復旧のご報告",
		"メンテナンスのお知らせ", "緊急メンテナンス", "メンテナンス作業", "障害報告", "システム障害のお詫び",
		"service restoration", "restoration progress", "service outage update", "maintenance notice", "service resumed",
		// Customer sympathy / compensation payouts (distinguished from ransom payment)
		"見舞金", "お見舞金", "代替サービス提供", "代替サービスのご案内", "補償対応", "迷惑料", "クオカード", "ギフト券を進呈",
		"sympathy money", "gift payment", "user compensation", "alternative service provision",
		// Preventative measures, FAQs, and administrative follow-ups
		"再発防止策", "再発防止に向けた", "今後の対応", "対応状況", "よくあるご質問", "よくある質問",
		"preventive measures", "reoccurrence prevention", "frequently asked questions",
		// Petitions / requests to authorities
		"能動的サイバー防御の適用要請", "能動的サイバー防御を要請", "適用を要請", "警察への被害届", "警察に被害届",
		"active cyber defense", "active cyberdefense", "cyberdefense operations", "petition to government",
	}

	for _, marker := range corporatePRMarkers {
		if strings.Contains(combined, marker) {
			return true
		}
	}

	return false
}

// IsServiceReleaseOrNonThreat detects service releases, PR announcements, marketing, or general non-threat content.
func IsServiceReleaseOrNonThreat(item ThreatItem, enriched *EnrichedThreat) bool {
	if IsCorporatePRNotice(item.Title, item.Summary, item.RawContent) {
		return true
	}
	if enriched != nil {
		if IsCorporatePRNotice(enriched.Title, enriched.TitleJa, enriched.Summary, enriched.SummaryJa, enriched.ImpactAnalysisJa) {
			return true
		}
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

// IsJPCERTOrIPASource checks if the item originates directly from official Japanese CERT/public security advisories (JPCERT/CC, JVN, IPA, NISC).
func IsJPCERTOrIPASource(item ThreatItem) bool {
	uLower := strings.ToLower(strings.TrimSpace(item.URL))
	officialDomains := []string{
		"jpcert.or.jp", "jvn.jp", "ipa.go.jp", "nisc.go.jp", "cyber.go.jp",
	}
	for _, dom := range officialDomains {
		if strings.Contains(uLower, dom) {
			return true
		}
	}

	sLower := strings.ToLower(strings.TrimSpace(item.SourceName))
	if strings.Contains(sLower, "jpcert") || strings.Contains(sLower, "jvn") || strings.Contains(sLower, "情報処理推進機構") {
		return true
	}
	if sLower == "ipa" || strings.HasPrefix(sLower, "ipa ") || strings.Contains(sLower, " ipa") || strings.Contains(sLower, "ipa/") {
		return true
	}
	return false
}

// HasSpecificVictimOrg returns true if at least one non-generic victim organization is named.
func HasSpecificVictimOrg(orgs []string) bool {
	for _, org := range orgs {
		cleaned := strings.TrimSpace(org)
		if cleaned != "" && !IsGenericVictimOrg(cleaned) {
			return true
		}
	}
	return false
}

// IsGeneralAdvisoryOrRoundup detects general security advisories, JPCERT/IPA alerts, weekly reports,
// vendor FAQ bulletins, or trend/roundup articles that do NOT report a specific breached victim organization.
// Such advisories are capped at Medium severity.
func IsGeneralAdvisoryOrRoundup(item ThreatItem, enriched *EnrichedThreat) bool {
	// If a specific non-generic victim organization is named, it is a concrete victim report, not a generic advisory
	if enriched != nil && HasSpecificVictimOrg(enriched.VictimOrgs) {
		return false
	}

	if IsJPCERTOrIPASource(item) {
		return true
	}

	uLower := strings.ToLower(strings.TrimSpace(item.URL))
	advisoryURLPatterns := []string{
		"/tag/", "/search/label/", "/topic/", "/support/faq/", "/wr/",
		"/known-exploited-vulnerabilities",
	}
	for _, pat := range advisoryURLPatterns {
		if strings.Contains(uLower, pat) {
			return true
		}
	}

	titles := item.Title
	if enriched != nil {
		titles += " " + enriched.Title + " " + enriched.TitleJa
	}
	tLower := strings.ToLower(titles)

	advisoryTitleMarkers := []string{
		"注意喚起", "週報", "weekly report", "security advisory", "security advisories",
		"security bulletin", "patch tuesday", "セキュリティアップデート", "アップデート公開",
		"脆弱性対策情報", "月例セキュリティ", "動向調査", "脅威動向", "まとめ", "白書",
		"を取り巻く現状", "振り返り", "調査レポート", "アクセスランキング",
		"cisa adds", "kev catalog", "cisa kev",
	}
	for _, m := range advisoryTitleMarkers {
		if strings.Contains(tLower, m) {
			return true
		}
	}

	return false
}

// IsPureVulnerabilityAdvisory determines if an item is merely a security patch announcement,
// routine vendor advisory, or general vulnerability disclosure without active exploitation,
// weaponized PoC, or verified breach incident.
func IsPureVulnerabilityAdvisory(item ThreatItem, enriched *EnrichedThreat) bool {
	// If it's a confirmed incident type with a specific victim or active zero-day, check carefully
	if enriched != nil {
		switch strings.ToLower(enriched.AttackType) {
		case "ransomware", "data breach", "zero-day", "ddos", "phishing":
			return false
		case "supply chain":
			if HasSpecificVictimOrg(enriched.VictimOrgs) {
				return false
			}
		}
	}

	// Only inspect factual source content and titles (exclude speculative ImpactAnalysis text)
	combined := item.Title + " " + item.Summary + " " + item.RawContent
	if enriched != nil {
		combined += " " + enriched.Title + " " + enriched.Summary + " " + enriched.TitleJa + " " + enriched.SummaryJa
	}
	lower := strings.ToLower(combined)

	// Threat evidence: if any active exploit, weaponized PoC, or real-world compromise indicator is present, do NOT treat as pure advisory
	threatEvidence := []string{
		"in the wild", "in-the-wild", "actively exploited", "exploited in the wild", "active exploitation",
		"under active exploit", "zero-day", "0-day", "ゼロデイ", "悪用が確認", "悪用確認",
		"weaponized", "proof of concept", "poc available", "exploit code released", "poc demonstrates",
		"pocコード", "実証コード", "悪用コード",
		"compromised", "breached", "data breach", "data leak", "stolen data", "ransomware",
		"情報漏洩", "データ漏洩", "情報流出", "不正アクセスにより", "身代金", "ランサムウェア",
		"被害が発生", "被害を受けた", "侵害された",
	}
	for _, te := range threatEvidence {
		if strings.Contains(lower, te) {
			return false
		}
	}

	// Advisory & patch announcement markers
	advisoryMarkers := []string{
		"security advisory", "security advisories", "security update", "security updates",
		"monthly security", "monthly update", "patch tuesday",
		"patches flaw", "patches vulnerability", "patches vulnerabilities",
		"fixes flaw", "fixes vulnerability", "fixes vulnerabilities",
		"addresses flaw", "addresses vulnerability", "addresses vulnerabilities",
		"releases patch", "releases update", "released security update",
		"vulnerabilities released", "vulnerability released",
		"vulnerability in", "flaw in", "bug in",
		"receives patent", "patent for",
		"セキュリティ更新プログラム", "セキュリティアップデート", "脆弱性の公表",
		"脆弱性を修正", "修正プログラム", "アップデートを公開", "アップデートの提供",
		"注意喚起", "脆弱性情報", "修正パッチ", "バグ修正",
	}
	for _, am := range advisoryMarkers {
		if strings.Contains(lower, am) {
			return true
		}
	}

	// If attack_type is explicitly Vulnerability and no threat evidence was found, it's an advisory
	if enriched != nil && strings.EqualFold(enriched.AttackType, "Vulnerability") {
		return true
	}

	return false
}

// RefineJapanRelevance enforces strict guardrails on JapanRelevanceDirect.
// A threat is ONLY Direct if:
// 1. It originates directly from official JPCERT/CC, JVN, IPA, or NISC sources, OR
// 2. A specific (non-generic) Japanese victim organization is explicitly identified, OR
// 3. The source/incident title explicitly describes an attack or breach against domestic Japanese organizations.
// General global enterprise product vulnerabilities (Fortinet, Cisco, PAN-OS, etc.) without specific Japanese victims
// are downgraded to Indirect.
func RefineJapanRelevance(item ThreatItem, enriched *EnrichedThreat) JapanRelevance {
	if enriched == nil {
		return JapanRelevanceNone
	}
	if IsJPCERTOrIPASource(item) && enriched.JapanRelevance == JapanRelevanceDirect {
		return JapanRelevanceDirect
	}
	if enriched.JapanRelevance != JapanRelevanceDirect {
		return enriched.JapanRelevance
	}

	// Check if any specific Japanese victim organization is present
	hasJapaneseVictim := false
	for _, org := range enriched.VictimOrgs {
		cleaned := strings.TrimSpace(org)
		if cleaned == "" || IsGenericVictimOrg(cleaned) {
			continue
		}
		// If org contains Japanese characters or ends with .jp, it's domestic
		for _, r := range cleaned {
			if unicode.In(r, unicode.Hiragana, unicode.Katakana, unicode.Han) {
				hasJapaneseVictim = true
				break
			}
		}
		if hasJapaneseVictim {
			break
		}
		lowerOrg := strings.ToLower(cleaned)
		if strings.HasSuffix(lowerOrg, ".jp") || strings.Contains(lowerOrg, "japan") || strings.Contains(lowerOrg, "japanese") {
			hasJapaneseVictim = true
			break
		}
	}
	if hasJapaneseVictim {
		return JapanRelevanceDirect
	}

	// Check ONLY raw source title/summary and incident titles (exclude LLM-generated ImpactAnalysis/SummaryJa
	// where generic phrases like "日本国内にも影響" on global CVEs previously caused false Direct classification).
	combined := item.Title + " " + item.Summary + " " + enriched.Title + " " + enriched.TitleJa
	lower := strings.ToLower(combined)

	domesticIndicators := []string{
		"国内組織", "国内企業", "日本企業", "日本組織", "国内自治体", "国内大学", "国内病院",
		"国内大手", "国内メーカー", "日本の組織", "日本の企業", "日本の主要", "日本通信",
		"日本国内で", "国内で被害", "国内で情報", "targeting japanese", "targeting japan",
		"against japanese", "japan firms", "japanese firm", "japanese telecom",
		"japanese manufacturer", "japanese bank", "japanese hospital", "japanese university",
		"japanese entities", "japanese organizations", "japanese companies",
		"警察庁", "デジタル庁", "内閣官房", "内閣サイバー", "個人情報保護委員会",
	}
	for _, di := range domesticIndicators {
		if strings.Contains(lower, di) {
			return JapanRelevanceDirect
		}
	}

	// If victim is Unknown or foreign vendor, downgrade to Indirect
	return JapanRelevanceIndirect
}

// RefineSeverity enforces deterministic severity caps aligned with Japan CTI priorities:
// 1. Non-threat / service release items -> Info.
// 2. Non-Direct items (Indirect / None / Unknown) -> NEVER Critical (capped at High).
// 3. General advisories, JPCERT/IPA alerts, weekly roundups, and FAQ/tag pages without a specific victim breach -> capped at Medium.
// 4. DoS-only vulnerabilities without RCE/breach -> capped at Medium.
// 5. Routine patch announcements without active exploitation or PoC -> capped at Low.
func RefineSeverity(item ThreatItem, enriched *EnrichedThreat) Severity {
	if enriched == nil {
		return SeverityUnknown
	}
	if IsServiceReleaseOrNonThreat(item, enriched) {
		return SeverityInfo
	}

	sev := enriched.Severity

	// Core invariant: non-Direct items must never be Critical
	if enriched.JapanRelevance != JapanRelevanceDirect && sev == SeverityCritical {
		sev = SeverityHigh
	}

	// General advisories / JPCERT-IPA alerts / roundups without a specific breached victim are capped at Medium
	if IsGeneralAdvisoryOrRoundup(item, enriched) {
		if sev == SeverityCritical || sev == SeverityHigh {
			sev = SeverityMedium
		}
	}

	// DoS-only vulnerability advisories without specific breached victims are capped at Medium
	if !HasSpecificVictimOrg(enriched.VictimOrgs) && (sev == SeverityCritical || sev == SeverityHigh) {
		tLower := strings.ToLower(item.Title + " " + enriched.Title + " " + enriched.TitleJa)
		isDoS := strings.Contains(tLower, "dos脆弱性") || strings.Contains(tLower, "dos vulnerability") ||
			strings.Contains(tLower, "denial of service") || strings.Contains(tLower, "denial-of-service") ||
			strings.Contains(tLower, "サービス拒否") || strings.Contains(tLower, "crash ssl vpn")
		hasRCE := strings.Contains(tLower, "rce") || strings.Contains(tLower, "remote code") ||
			strings.Contains(tLower, "コード実行") || strings.Contains(tLower, "認証回避") ||
			strings.Contains(tLower, "authentication bypass")
		if isDoS && !hasRCE {
			sev = SeverityMedium
		}
	}

	// Pure routine vulnerability patch disclosures without active exploit/PoC/breach -> Low
	if IsPureVulnerabilityAdvisory(item, enriched) {
		if sev == SeverityCritical || sev == SeverityHigh {
			sev = SeverityLow
		}
	}

	return sev
}

var hallucinatedPlaceholderCVEs = map[string]bool{
	"CVE-2026-9999": true,
	"CVE-2025-9999": true,
	"CVE-2024-9999": true,
	"CVE-2026-0000": true,
	"CVE-2024-0000": true,
}

// SanitizeHallucinatedCVEs strips known LLM prompt-placeholder CVEs unless they literally appear in the raw source item.
func SanitizeHallucinatedCVEs(item ThreatItem, cves []string) []string {
	if len(cves) == 0 {
		return nil
	}
	rawUpper := strings.ToUpper(item.Title + " " + item.Summary + " " + item.RawContent + " " + item.URL)
	seen := make(map[string]bool)
	var clean []string
	for _, c := range cves {
		norm := strings.ToUpper(strings.TrimSpace(c))
		if norm == "" || seen[norm] {
			continue
		}
		if hallucinatedPlaceholderCVEs[norm] && !strings.Contains(rawUpper, norm) {
			continue
		}
		seen[norm] = true
		clean = append(clean, norm)
	}
	return clean
}

// NormalizeEnrichedThreat deterministically enforces CVE sanitization, removes preachy recommended actions,
// and applies JapanRelevance and Severity guardrails without any LLM calls.
func NormalizeEnrichedThreat(item ThreatItem, enriched *EnrichedThreat) {
	if enriched == nil {
		return
	}
	enriched.CVEs = SanitizeHallucinatedCVEs(item, enriched.CVEs)
	enriched.RecommendedActions = nil
	enriched.RecommendedActionsJa = nil
	enriched.JapanRelevance = RefineJapanRelevance(item, enriched)
	enriched.Severity = RefineSeverity(item, enriched)
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
	case strings.Contains(lower, "お名前") || strings.Contains(lower, "onamae") || strings.Contains(lower, "デスクトップクラウド") || strings.Contains(lower, "桌面云"):
		return "onamae desktop cloud"
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
		{"onamae", "GMO お名前.com デスクトップクラウド", "onamae desktop cloud"},
		{"お名前", "GMO お名前.com デスクトップクラウド", "onamae desktop cloud"},
		{"デスクトップクラウド", "GMO お名前.com デスクトップクラウド", "onamae desktop cloud"},
		{"桌面云", "GMO お名前.com デスクトップクラウド", "onamae desktop cloud"},
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

// IsJapaneseText checks whether a string contains Japanese text.
// It requires Japanese Hiragana (0x3040-0x309F) or Katakana (0x30A0-0x30FF)
// to avoid falsely classifying pure Chinese (Hanzi) text as Japanese.
func IsJapaneseText(s string) bool {
	for _, r := range s {
		if (r >= 0x3040 && r <= 0x309F) || (r >= 0x30A0 && r <= 0x30FF) {
			return true
		}
	}
	return false
}

// HasChineseCTITerms checks if a string contains known Simplified Chinese cybersecurity terms or phrasings.
func HasChineseCTITerms(s string) bool {
	if s == "" {
		return false
	}
	chineseMarkers := []string{
		"关于", "不正当", "泄露", "个人数据", "数据泄露", "服务器遭受",
		"未经授权", "不法访问", "被盗", "两阶段", "兩階段", "针对",
		"更新版本", "修复旧版本", "解决了", "会员管理", "官方应用",
		"受影响", "未提及", "未确认", "攻击活动", "恶意软件", "漏洞",
		"钓鱼", "黑客", "木马", "后门", "云计算", "邮件杂志", "零日漏洞",
		"非法入侵", "遭勒索", "赎金", "公布调查", "宣布", "遭受",
		"非法访问", "非法", "导致", "巨头", "电商", "个人身份", "子公司",
		"窃取取", "超过", "东证", "主板", "网络访问", "已漏洩", "客户",
	}
	for _, m := range chineseMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// IsChineseOrCorruptedJapanese returns true if the string contains Chinese CTI terms,
// or contains Kanji/Hanzi but lacks any Hiragana or Katakana.
func IsChineseOrCorruptedJapanese(s string) bool {
	if s == "" {
		return false
	}
	if HasChineseCTITerms(s) {
		return true
	}
	hasHanzi := false
	hasKana := false
	for _, r := range s {
		if r >= 0x4E00 && r <= 0x9FAF {
			hasHanzi = true
		}
		if (r >= 0x3040 && r <= 0x309F) || (r >= 0x30A0 && r <= 0x30FF) {
			hasKana = true
		}
	}
	return hasHanzi && !hasKana
}



