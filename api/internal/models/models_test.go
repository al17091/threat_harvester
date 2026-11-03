package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewThreatItem(t *testing.T) {
	now := time.Now().UTC()
	item := NewThreatItem(
		SourceTypeVendorRSS,
		"JPCERT",
		"Test Advisory",
		"https://example.com/advisory",
		"Summary text",
		"Raw content",
		&now,
		map[string]interface{}{"tag": "security"},
	)

	if item.ID == "" {
		t.Fatal("expected non-empty ID")
	}

	// Determinism check: same attributes produce same SHA256 ID
	item2 := NewThreatItem(
		SourceTypeVendorRSS,
		"JPCERT",
		"Test Advisory",
		"https://example.com/advisory",
		"Different summary shouldn't affect ID",
		"",
		nil,
		nil,
	)

	if item.ID != item2.ID {
		t.Fatalf("expected identical IDs, got %s and %s", item.ID, item2.ID)
	}

	// Cross-source and tracking-param URL deduplication check
	item3 := NewThreatItem(
		SourceTypeWebSearch,
		"Gemini Search",
		"Different Title Reported by AI",
		"https://example.com/advisory?utm_source=twitter&ref=soc#overview",
		"Another summary",
		"",
		nil,
		nil,
	)

	if item.ID != item3.ID {
		t.Fatalf("expected identical IDs across sources and tracking params, got %s and %s", item.ID, item3.ID)
	}

	// Generic URL falls back to title deduplication
	genericItem1 := NewThreatItem(
		SourceTypeXMonitor,
		"X Monitor",
		"[X/Twitter] Breach alert at Company A",
		"https://x.com",
		"Summary 1",
		"",
		nil,
		nil,
	)
	genericItem2 := NewThreatItem(
		SourceTypeTelegram,
		"Telegram",
		"Breach alert at Company A",
		"https://t.me",
		"Summary 2",
		"",
		nil,
		nil,
	)
	if genericItem1.ID != genericItem2.ID {
		t.Fatalf("expected identical title-based IDs for generic URLs, got %s and %s", genericItem1.ID, genericItem2.ID)
	}
}

func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"https://example.com/path/", "https://example.com/path"},
		{"https://www.example.com/path?utm_source=rss&ref=feed", "https://example.com/path"},
		{"http://EXAMPLE.COM/advisory#heading", "http://example.com/advisory"},
		{"  https://scan.netsecurity.ne.jp/article/2026/01/01/12345.html  ", "https://scan.netsecurity.ne.jp/article/2026/01/01/12345.html"},
	}

	for _, c := range cases {
		out := NormalizeURL(c.input)
		if out != c.expected {
			t.Errorf("NormalizeURL(%q) = %q, expected %q", c.input, out, c.expected)
		}
	}
}

func TestNewSTIXIncidentID(t *testing.T) {
	id := NewSTIXIncidentID()
	if !strings.HasPrefix(id, "incident--") {
		t.Fatalf("expected STIX prefix 'incident--', got %s", id)
	}
	if len(id) != len("incident--")+36 {
		t.Fatalf("expected length of incident--<uuid>, got %s", id)
	}
}

func TestNormalizeVictimOrg(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"パーク24株式会社", "パーク24"},
		{"株式会社パーク24", "パーク24"},
		{"Park24 Co., Ltd.", "park24"},
		{"Keio Corporation", "keio"},
		{"日本企業", ""}, // Generic
		{"Unknown", ""}, // Generic
		{"病院", ""},   // Generic
		{"N/A", ""},    // Generic
	}

	for _, c := range cases {
		out := NormalizeVictimOrg(c.input)
		if out != c.expected {
			t.Errorf("NormalizeVictimOrg(%q) = %q, expected %q", c.input, out, c.expected)
		}
	}
}

func TestComputeContentHash(t *testing.T) {
	item1 := NewThreatItem(
		SourceTypeWebSearch,
		"WebSearch",
		"Times Car Data Breach",
		"https://example.com/news/123",
		"Summary",
		"",
		nil,
		nil,
	)
	item2 := NewThreatItem(
		SourceTypeWebSearch,
		"WebSearch2",
		"Times Car Data Breach (Updated)",
		"https://example.com/news/123?utm_source=feed",
		"Different summary",
		"",
		nil,
		nil,
	)
	if item1.ContentHash == "" || item2.ContentHash == "" {
		t.Fatal("expected non-empty ContentHash")
	}
	if item1.ContentHash != item2.ContentHash {
		t.Fatalf("expected identical ContentHash for same normalized URL, got %s vs %s", item1.ContentHash, item2.ContentHash)
	}
}

func TestSeverityAndRelevanceRanking(t *testing.T) {
	if HigherSeverity(SeverityLow, SeverityCritical) != SeverityCritical {
		t.Error("expected Critical to be higher than Low")
	}
	if HigherSeverity(SeverityHigh, SeverityMedium) != SeverityHigh {
		t.Error("expected High to be higher than Medium")
	}
	if HigherRelevance(JapanRelevanceNone, JapanRelevanceDirect) != JapanRelevanceDirect {
		t.Error("expected Direct to be higher than None")
	}
	if HigherRelevance(JapanRelevanceDirect, JapanRelevanceIndirect) != JapanRelevanceDirect {
		t.Error("expected Direct to be higher than Indirect")
	}
}

func TestExtractCVEs(t *testing.T) {
	texts := []string{
		"Active Exploitation of NetScaler ADC (CVE-2026-88771, CVE-2026-88772)",
		"See details at https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2026-88771",
		"Duplicate mentions: cve-2026-88771 and CVE-2026-88772",
		"Another alert: CVE-2024-23113 in FortiOS",
	}

	cves := ExtractCVEs(texts...)
	expected := []string{"CVE-2024-23113", "CVE-2026-88771", "CVE-2026-88772"}

	if len(cves) != len(expected) {
		t.Fatalf("expected %d CVEs, got %d: %v", len(expected), len(cves), cves)
	}
	for i, exp := range expected {
		if cves[i] != exp {
			t.Errorf("expected cve[%d] to be %s, got %s", i, exp, cves[i])
		}
	}
}

func TestNormalizeProduct(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"Citrix NetScaler ADC", "netscaler"},
		{"NetScaler Gateway 13.1", "netscaler"},
		{"フォーティネット「FortiMail」", "fortimail"},
		{"Fortinet FortiOS SSO", "fortios"},
		{"WordPress Core 6.7", "wordpress"},
		{"Movable Type 7", "movable type"},
		{"MikroTik RouterOS", "mikrotik routeros"},
		{"Ivanti Connect Secure", "ivanti"},
		{"Langflow", "langflow"},
		{"Apache Tomcat", "apache tomcat"},
		{"Palo Alto Networks PAN-OS", "pan-os"},
	}

	for _, c := range cases {
		out := NormalizeProduct(c.input)
		if out != c.expected {
			t.Errorf("NormalizeProduct(%q) = %q, expected %q", c.input, out, c.expected)
		}
	}
}

func TestExtractAffectedProduct(t *testing.T) {
	item1 := ThreatItem{
		Title:   "IPAおよびJPCERT/CCがNetScaler ADC/Gatewayの悪用中脆弱性（CVE-2026-88771等）に注意喚起",
		Summary: "Citrix NetScalerにおける認証回避脆弱性",
	}
	raw, norm := ExtractAffectedProduct(item1, nil)
	if norm != "netscaler" {
		t.Fatalf("expected norm to be netscaler, got %s (raw: %s)", norm, raw)
	}

	item2 := ThreatItem{
		Title:   "FortiMailの深刻なゼロデイ脆弱性（CVE-2026-104286）の悪用",
		Summary: "Fortinet FortiMailアプライアンスに対する攻撃",
	}
	raw2, norm2 := ExtractAffectedProduct(item2, nil)
	if norm2 != "fortimail" {
		t.Fatalf("expected norm to be fortimail, got %s (raw: %s)", norm2, raw2)
	}
}

func TestIsServiceReleaseOrNonThreat(t *testing.T) {
	// Service release / PR announcements
	itemPR := ThreatItem{
		Title:   "HENNGE、新機能「HENNGE Mesh Network」の提供開始を発表",
		Summary: "SaaSセキュリティ新機能の提供を開始",
	}
	if !IsServiceReleaseOrNonThreat(itemPR, nil) {
		t.Errorf("expected HENNGE service release to be identified as non-threat")
	}

	itemClaude := ThreatItem{
		Title:   "Anthropic asks Claude users to share voice data for AI model training",
		Summary: "Anthropic is expanding its data collection options",
	}
	if !IsServiceReleaseOrNonThreat(itemClaude, nil) {
		t.Errorf("expected Anthropic voice data prompt to be identified as non-threat")
	}

	// Legitimate threat with CVE
	itemVuln := ThreatItem{
		Title:   "Fortinet FortiMailにおける新機能の提供開始に伴う深刻なゼロデイ脆弱性（CVE-2026-104286）",
		Summary: "認証回避および任意コード実行の恐れ",
	}
	if IsServiceReleaseOrNonThreat(itemVuln, nil) {
		t.Errorf("expected item with CVE to NOT be identified as non-threat")
	}

	// Threat with ransomware indicator
	itemRansom := ThreatItem{
		Title:   "大手製造業A社、ランサムウェア被害により基幹システム停止を発表",
		Summary: "身代金要求およびデータ暗号化が確認された",
	}
	if IsServiceReleaseOrNonThreat(itemRansom, nil) {
		t.Errorf("expected ransomware item to NOT be identified as non-threat")
	}

	// Severity Info enriched threat
	itemInfo := ThreatItem{
		Title: "Tech conference 2026 announced",
	}
	enrichedInfo := &EnrichedThreat{
		Severity: SeverityInfo,
	}
	if !IsServiceReleaseOrNonThreat(itemInfo, enrichedInfo) {
		t.Errorf("expected item with SeverityInfo to be identified as non-threat")
	}
}

func TestIsPureVulnerabilityAdvisory(t *testing.T) {
	// Routine monthly security advisory without active exploitation
	routineAdvisory := ThreatItem{
		Title:   "Adobe Releases Security Advisories Addressing Multiple Vulnerabilities Across 11 Products",
		Summary: "Adobe has published its monthly security updates fixing several flaws.",
	}
	enrichedAdvisory := &EnrichedThreat{
		AttackType: "Vulnerability",
		Severity:   SeverityHigh,
	}
	if !IsPureVulnerabilityAdvisory(routineAdvisory, enrichedAdvisory) {
		t.Errorf("expected routine Adobe advisory to be identified as pure advisory")
	}

	// Splunk routine security update
	splunkUpdate := ThreatItem{
		Title:   "Critical Security Updates for Splunk Enterprise: CVE-2026-76299, CVE-2026-76302",
		Summary: "Splunk releases patches for multiple vulnerabilities.",
	}
	if !IsPureVulnerabilityAdvisory(splunkUpdate, nil) {
		t.Errorf("expected Splunk patch release to be identified as pure advisory")
	}

	// In-the-wild exploitation: MUST NOT be treated as pure advisory
	inTheWild := ThreatItem{
		Title:   "Cisco FMC flaws exploited by ransomware gang, state-sponsored hackers",
		Summary: "Actively exploited zero-day vulnerability observed in cyber attacks.",
	}
	enrichedInTheWild := &EnrichedThreat{
		AttackType: "Vulnerability",
		Severity:   SeverityCritical,
	}
	if IsPureVulnerabilityAdvisory(inTheWild, enrichedInTheWild) {
		t.Errorf("expected in-the-wild exploit to NOT be identified as pure advisory")
	}

	// EC-CUBE exploited in the wild
	ecCube := ThreatItem{
		Title:   "Vulnerability in AmazonPay Plugin for EC-CUBE 4 Exploited in the Wild",
		Summary: "JPCERT warns of active attacks exploiting plugin flaw.",
	}
	enrichedECCube := &EnrichedThreat{
		AttackType: "Zero-day",
		Severity:   SeverityCritical,
	}
	if IsPureVulnerabilityAdvisory(ecCube, enrichedECCube) {
		t.Errorf("expected EC-CUBE active attack to NOT be identified as pure advisory")
	}

	// Ransomware breach: MUST NOT be treated as advisory
	ransomware := ThreatItem{
		Title:   "Japan Digital Agency Data Breach Affects Multiple Ministries",
		Summary: "Unauthorized access via VPN leads to personal information leakage.",
	}
	enrichedRansom := &EnrichedThreat{
		AttackType: "Data Breach",
		Severity:   SeverityHigh,
	}
	if IsPureVulnerabilityAdvisory(ransomware, enrichedRansom) {
		t.Errorf("expected data breach to NOT be identified as pure advisory")
	}
}

func TestRefineJapanRelevance(t *testing.T) {
	// Unknown victim on global vulnerability: must downgrade to Indirect
	globalVuln := ThreatItem{
		Title:   "Critical Security Updates for Splunk Enterprise",
		Summary: "Patches released for enterprise customers.",
	}
	enrichedGlobal := &EnrichedThreat{
		VictimOrgs:     []string{"Unknown"},
		JapanRelevance: JapanRelevanceDirect,
	}
	refined := RefineJapanRelevance(globalVuln, enrichedGlobal)
	if refined != JapanRelevanceIndirect {
		t.Errorf("expected global vuln with Unknown victim to be downgraded to Indirect, got %s", refined)
	}

	// Domestic Japanese organization victim: must remain Direct
	domesticThreat := ThreatItem{
		Title:   "不正アクセスによる情報漏洩の可能性に関するお知らせ",
		Summary: "社内サーバへの侵害が確認された",
	}
	enrichedDomestic := &EnrichedThreat{
		VictimOrgs:     []string{"株式会社エグザンプル (example.co.jp)"},
		JapanRelevance: JapanRelevanceDirect,
	}
	if RefineJapanRelevance(domesticThreat, enrichedDomestic) != JapanRelevanceDirect {
		t.Errorf("expected domestic victim org to remain Direct")
	}

	// Unknown victim, but title explicitly targets Japan: must remain Direct
	targetingJapan := ThreatItem{
		Title:   "国内組織を標的としたランサムウェア攻撃キャンペーンが観測される",
		Summary: "国内企業および自治体への不審メールが急増",
	}
	enrichedTargeting := &EnrichedThreat{
		VictimOrgs:     []string{"Unknown"},
		JapanRelevance: JapanRelevanceDirect,
	}
	if RefineJapanRelevance(targetingJapan, enrichedTargeting) != JapanRelevanceDirect {
		t.Errorf("expected explicit domestic target to remain Direct")
	}
}

func TestThreatActorsCleaningAndValidation(t *testing.T) {
	actors := []string{
		"APT28",
		"Lazarus Group",
		"Unknown",
		"Not specified",
		"attackers",
		"  LockBit 3.0  ",
		"APT28", // Duplicate
		"a",     // Too short
		strings.Repeat("long", 15), // Too long
	}

	cleaned := CleanThreatActors(actors)
	expected := []string{"APT28", "Lazarus Group", "LockBit 3.0"}
	if len(cleaned) != len(expected) {
		t.Fatalf("expected %d cleaned actors, got %d: %v", len(expected), len(cleaned), cleaned)
	}
	for i, a := range cleaned {
		if a != expected[i] {
			t.Errorf("expected actor %s, got %s", expected[i], a)
		}
	}
}

func TestExtractVictimOrgs(t *testing.T) {
	item := ThreatItem{
		Title: "Ransomware Attack Victim: Tokyo Gas Co., Ltd. (Japan)",
		Metadata: map[string]interface{}{
			"victim": "Tokyo Gas Co., Ltd.",
		},
	}
	enriched := &EnrichedThreat{
		VictimOrgs: []string{"株式会社東京ガス", "Some Generic Org"},
	}

	raws, norms := ExtractVictimOrgs(item, enriched)
	if len(raws) == 0 || len(norms) == 0 {
		t.Fatalf("expected extracted victim orgs, got empty")
	}

	primaryRaw, primaryNorm := ExtractVictimOrg(item, enriched)
	if primaryRaw == "" || primaryNorm == "" {
		t.Fatalf("expected non-empty primary victim org")
	}

	// Empty test
	emptyRaw, emptyNorm := ExtractVictimOrg(ThreatItem{}, nil)
	if emptyRaw != "" || emptyNorm != "" {
		t.Errorf("expected empty victim org for empty item, got raw=%s norm=%s", emptyRaw, emptyNorm)
	}
}

func TestExtractActorSnippet(t *testing.T) {
	text := "Recent intelligence reports suggest that LockBit 3.0 has targeted multiple critical infrastructure operators in Japan during Q3."
	snippet := ExtractActorSnippet(text, "LockBit 3.0", 50)
	if !strings.Contains(snippet, "LockBit 3.0") {
		t.Errorf("expected snippet to contain actor name, got: %s", snippet)
	}

	// Non-existent actor
	if s := ExtractActorSnippet(text, "NonExistentGroup", 50); s != "" {
		t.Errorf("expected empty snippet for non-existent actor, got: %s", s)
	}

	// Empty text or actor
	if s := ExtractActorSnippet("", "Actor", 50); s != "" {
		t.Errorf("expected empty snippet for empty text, got: %s", s)
	}
}

func TestTruncateRunes(t *testing.T) {
	multibyte := "日本語の長いテキストデータです。これは切り捨てテストです。"
	truncated := TruncateRunes(multibyte, 5)
	if truncated != "日本語の長" {
		t.Errorf("expected '日本語の長', got '%s'", truncated)
	}
	// Under limit
	if s := TruncateRunes("短い", 10); s != "短い" {
		t.Errorf("expected '短い', got '%s'", s)
	}
}

func TestRelevanceAndSeverityScoresExtended(t *testing.T) {
	if s := SeverityScore(Severity("UnknownSeverity")); s != 0 {
		t.Errorf("expected 0 for unknown severity, got %d", s)
	}
	if r := RelevanceScore(JapanRelevance("UnknownRelevance")); r != 0 {
		t.Errorf("expected 0 for unknown relevance, got %d", r)
	}
}

func TestNormalizeProductExtended(t *testing.T) {
	products := []string{
		"Apache HTTP Server",
		"Microsoft Exchange Server",
		"Fortinet FortiOS",
		"Cisco IOS XE",
		"VMware ESXi",
		"Palo Alto Networks PAN-OS",
		"GitLab Enterprise Edition",
		"WordPress Core",
		"Ivanti Connect Secure",
		"OpenSSL Cryptographic Library",
	}
	for _, p := range products {
		norm := NormalizeProduct(p)
		if norm == "" {
			t.Errorf("expected normalized product for %s", p)
		}
	}

	// ExtractAffectedProduct test
	item := ThreatItem{
		Title:   "Critical RCE vulnerability in Fortinet FortiOS (CVE-2024-1234)",
		Summary: "Advisory for FortiOS devices",
	}
	raw, norm := ExtractAffectedProduct(item, nil)
	if raw == "" || norm == "" {
		t.Errorf("expected extracted affected product for FortiOS")
	}
}

func TestThreatActorValidationAndGrounding(t *testing.T) {
	// Test IsValidThreatActor
	invalidCases := []string{
		"[]", "[ ]", "null", "nil", "none", "unknown", "unspecified",
		"Hackers", "Cybercriminals", "未知威胁行为者", "中国国家支援型アクター",
		"  ", "a",
	}
	for _, tc := range invalidCases {
		if IsValidThreatActor(tc) {
			t.Errorf("expected %q to be invalid threat actor", tc)
		}
	}

	validCases := []string{"LockBit", "Lazarus", "APT10", "Qilin", "BlackCat", "Volt Typhoon", "银狐", "海莲花"}
	for _, tc := range validCases {
		if !IsValidThreatActor(tc) {
			t.Errorf("expected %q to be valid threat actor string format", tc)
		}
	}

	// Test CleanThreatActors strips brackets, deduplicates, and filters invalid
	rawList := []string{"[]", "LockBit", "  LockBit  ", "unknown", "海莲花", "none"}
	cleaned := CleanThreatActors(rawList)
	if len(cleaned) != 2 || cleaned[0] != "LockBit" || cleaned[1] != "海莲花" {
		t.Fatalf("unexpected CleanThreatActors result: %v", cleaned)
	}

	// Test FilterGroundedThreatActors:
	// When report text only mentions Qilin, hallucinated actors (银狐, 海莲花, 暗雪) must be dropped!
	sourceTitle := "Japanese Healthcare Institution Targeted in Qilin Ransomware Attack"
	sourceBody := "A cyberattack encrypting electronic medical records was attributed to the Qilin ransomware group."

	extractedActors := []string{"Qilin", "银狐", "海莲花", "暗雪", "LockBit"}
	grounded := FilterGroundedThreatActors(extractedActors, sourceTitle, sourceBody)

	if len(grounded) != 1 || grounded[0] != "Qilin" {
		t.Fatalf("expected only ['Qilin'] to survive grounding filter, got: %v", grounded)
	}

	// When report text has no named actor, all hallucinated actors must be dropped
	genericTitle := "Rising Ransomware Attacks Against Japanese Enterprises in the First Half of 2022"
	genericBody := "National Police Agency reported a 60% increase in ransomware cases with no specific group named."
	hallucinated := FilterGroundedThreatActors([]string{"LockBit", "银狐", "海莲花", "暗雪"}, genericTitle, genericBody)
	if len(hallucinated) != 0 {
		t.Fatalf("expected empty actors when source has no mentions, got: %v", hallucinated)
	}
}

func TestIsJapaneseText(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool
	}{
		{"石油資源開発が利用するラクスライトクラウドのASPサービス「blastmail」に不正アクセス", true}, // Natural Japanese with Hiragana & Katakana
		{"脆弱性情報に関する注意喚起", true},                                                // Japanese with Hiragana
		{"マルウェア感染インシデント", true},                                                // Japanese with Katakana
		{"JAPEX邮件杂志服务遭受不正当访问，可能导致个人数据泄露", false},                         // Pure Chinese (Hanzi)
		{"关于某些黑客组织利用某某漏洞的分析报告", false},                                         // Pure Chinese
		{"Healthcare Sector Cyberattack Report: Ransomware and Data Breaches", false}, // English
		{"LockBit Ransomware Advisory 2026", false},                                   // English
		{"", false},                                                                   // Empty
	}

	for _, tc := range testCases {
		res := IsJapaneseText(tc.input)
		if res != tc.expected {
			t.Errorf("IsJapaneseText(%q) = %v; want %v", tc.input, res, tc.expected)
		}
	}
}

func TestHasChineseCTITermsAndCorruption(t *testing.T) {
	chineseInputs := []string{
		"大和証券株式会社关于SC社不正当访问事件的公告",
		"「焼肉きんぐ」公式アプリ会員情報泄露事件：1078万8963件の个人数据被盗",
		"佐川急便荷物問合サービス个人数据泄露调查结果公布",
		"MrMax公司数据泄露事件：1735,154名会员信息被盗取",
		"CAPCOM ID服务泄露11774247个电子邮件地址及其他信息",
		"GMOインターネット服务遭勒索攻击，要求支付80亿日元赎金",
	}

	for _, s := range chineseInputs {
		if !HasChineseCTITerms(s) {
			t.Errorf("expected HasChineseCTITerms(%q) = true, got false", s)
		}
		if !IsChineseOrCorruptedJapanese(s) {
			t.Errorf("expected IsChineseOrCorruptedJapanese(%q) = true, got false", s)
		}
	}

	pureJapaneseInputs := []string{
		"大和証券株式会社、SC社への不正アクセスに関する報告書を公表",
		"「焼肉きんぐ」公式アプリ会員情報漏洩事件：個人情報が流出",
		"佐川急便荷物問い合わせサービスにおける個人情報漏洩の調査結果を発表",
		"株式会社ミスターマックス・ホールディングスにおける不正アクセス被害について",
	}

	for _, s := range pureJapaneseInputs {
		if HasChineseCTITerms(s) {
			t.Errorf("expected HasChineseCTITerms(%q) = false, got true", s)
		}
		if IsChineseOrCorruptedJapanese(s) {
			t.Errorf("expected IsChineseOrCorruptedJapanese(%q) = false, got true", s)
		}
	}
}

func TestIsCorporatePRNoticeAndRansomExceptions(t *testing.T) {
	// 1. Pure corporate PR notices that MUST be dropped
	prCases := []struct {
		title   string
		summary string
	}{
		{
			title:   "GMOインターネット、「お名前.com デスクトップクラウド」への攻撃で全利用者に5,000円のお見舞金を発表",
			summary: "代替サービスの提供と見舞金支払いを実施する",
		},
		{
			title:   "「お名前.com デスクトップクラウド」に不正アクセス、見舞金として一律 5,000円を支払い",
			summary: "契約者に対する補償対応についての案内",
		},
		{
			title:   "お名前.com デスクトップクラウド不正アクセス事件：見舞金支払いと代替サービス提供",
			summary: "ユーザーへの代替サービス提供と今後の対応",
		},
		{
			title:   "お名前.com デスクトップクラウドのサーバー停止・復旧作業完了のご報告",
			summary: "緊急メンテナンスおよびサーバー停止から復旧完了した",
		},
		{
			title:   "当社サーバーへの不正アクセスに関するお詫びとお知らせ（第2報）",
			summary: "調査委員会の設置と外部専門機関による調査の経過報告",
		},
		{
			title:   "GMO Internet has made an urgent request for the Japanese government to implement active cyberdefense operations",
			summary: "Company petitioned the government for active cyber defense application",
		},
		{
			title:   "不正アクセスに関するよくあるご質問（FAQ）および再発防止策について",
			summary: "お客様からの問い合わせ対応状況と再発防止策の策定",
		},
	}

	for _, tc := range prCases {
		if !IsCorporatePRNotice(tc.title, tc.summary) {
			t.Errorf("expected corporate PR notice to be dropped: %q", tc.title)
		}
	}

	// 2. Threat articles containing ransom payment / extortion / leak intel that MUST BE RETAINED
	ransomCases := []struct {
		title   string
		summary string
	}{
		{
			title:   "GMOに身代金要求 - ランサム攻撃や情報公開を行うと脅迫",
			summary: "攻撃グループが身代金を要求し、支払わない場合はデータを公開すると脅迫",
		},
		{
			title:   "GMO Internet Services Exposed to Ransomware Attack, Demanding Payment of 8 Billion Japanese Yen in Ransom",
			summary: "Attackers demanded payment of 8 billion yen in cryptocurrency",
		},
		{
			title:   "東証プライム経営者向けまとめ GMO FX自動取引サービス二重脅迫→能動的サイバー防御要請経緯 及び ランサムウェア実務家向け脅威インテリジェンス",
			summary: "二重脅迫の手口とランサムウェア実務家向けOSINT分析",
		},
		{
			title:   "Astemo、ランサムウェア攻撃によるシステム障害から全面復旧（身代金の支払いは拒否）",
			summary: "攻撃者への身代金支払いを拒否し、バックアップから復旧したと公表",
		},
		{
			title:   "暗号資産で要求された身代金支払いの事実関係について",
			summary: "ハッカーへの支払いは行わなかったと説明",
		},
		{
			title:   "LockBit、ダークウェブのリークサイトに被害組織の機密データを公開",
			summary: "身代金支払いに応じなかったためDLSに掲載",
		},
	}

	for _, tc := range ransomCases {
		if IsCorporatePRNotice(tc.title, tc.summary) {
			t.Errorf("expected ransom/extortion intelligence to be KEPT (not corporate PR): %q", tc.title)
		}
	}

	// 3. Technical analysis / third-party reports that must NOT be dropped
	techCases := []struct {
		title   string
		summary string
	}{
		{
			title:   "お名前.com デスクトップクラウドへの不正アクセス事案のまとめ",
			summary: "piyologによるインシデント技術分析とタイムライン",
		},
		{
			title:   "PHP Windows版同梱圧縮ライブラリ「Brotli」の脆弱性修正（CVE-2026-111497）",
			summary: "バッファオーバーフローの脆弱性を修正",
		},
		{
			title:   "GMOクリック証券警戒：自動売買ツールによる不正取引の可能性",
			summary: "金融口座への不正アクセスと不正送金被害の可能性について調査",
		},
	}

	for _, tc := range techCases {
		if IsCorporatePRNotice(tc.title, tc.summary) {
			t.Errorf("expected technical report to be KEPT: %q", tc.title)
		}
	}
}

func TestNormalizeVictimOrgAndProductEnhanced(t *testing.T) {
	victimCases := []struct {
		input    string
		expected string
	}{
		{"GMOインターネット株式会社", "gmo"},
		{"GMOインターネットグループ", "gmo"},
		{"GMOインターネット", "gmo"},
		{"GMO Internet Group, Inc.", "gmo"},
		{"GMO Internet (Onamae.com Desktop Cloud)", "gmo"},
		{"お名前.com デスクトップクラウド", "gmo"},
		{"お名前.com", "gmo"},
		{"株式会社日立Astemo", "日立astemo"},
		{"トヨタ自動車株式会社", "トヨタ自動車"},
	}

	for _, tc := range victimCases {
		res := NormalizeVictimOrg(tc.input)
		if res != tc.expected {
			t.Errorf("NormalizeVictimOrg(%q) = %q; want %q", tc.input, res, tc.expected)
		}
	}

	productCases := []struct {
		input    string
		expected string
	}{
		{"お名前.com デスクトップクラウド", "onamae desktop cloud"},
		{"お名前.com デスクトップ クラウド", "onamae desktop cloud"},
		{"Onamae.com Desktop Cloud", "onamae desktop cloud"},
		{"お名前.com桌面云服务", "onamae desktop cloud"},
		{"GMO「デスクトップクラウド」", "onamae desktop cloud"},
	}

	for _, tc := range productCases {
		res := NormalizeProduct(tc.input)
		if res != tc.expected {
			t.Errorf("NormalizeProduct(%q) = %q; want %q", tc.input, res, tc.expected)
		}
	}
}

func TestNormalizeEnrichedThreatAndSeverityCaps(t *testing.T) {
	// 1. Non-Direct item (Indirect) with Critical MUST be capped at High, actions stripped, placeholder CVE stripped
	itemGlobal := ThreatItem{
		Title:      "Critical Zero-day Actively Exploited in FortiWeb Appliance",
		Summary:    "Global exploitation of CVE-2026-44551 observed in the wild.",
		RawContent: "Attackers are actively exploiting CVE-2026-44551 in FortiWeb.",
		URL:        "https://security-next.com/180001",
		SourceType: SourceTypeVendorRSS,
		SourceName: "Security NEXT",
	}
	enrichedGlobal := &EnrichedThreat{
		Severity:             SeverityCritical,
		JapanRelevance:       JapanRelevanceDirect, // Falsely marked Direct due to Japanese SummaryJa
		Title:                "FortiWeb Zero-day Exploitation",
		TitleJa:              "FortiWebにおけるゼロデイ脆弱性の悪用",
		SummaryJa:            "日本国内の組織にも影響が及ぶ可能性がある。",
		AttackType:           "Zero-day",
		CVEs:                 []string{"CVE-2026-44551", "CVE-2026-9999"}, // CVE-2026-9999 is ungrounded
		RecommendedActions:   []string{"Implement MFA"},
		RecommendedActionsJa: []string{"多要素認証を導入してください"},
	}
	NormalizeEnrichedThreat(itemGlobal, enrichedGlobal)
	if enrichedGlobal.JapanRelevance != JapanRelevanceIndirect {
		t.Errorf("expected foreign product zero-day without JP victim to downgrade to Indirect, got %s", enrichedGlobal.JapanRelevance)
	}
	if enrichedGlobal.Severity != SeverityHigh {
		t.Errorf("expected non-Direct Critical to cap at High, got %s", enrichedGlobal.Severity)
	}
	if len(enrichedGlobal.CVEs) != 1 || enrichedGlobal.CVEs[0] != "CVE-2026-44551" {
		t.Errorf("expected hallucinated CVE-2026-9999 to be stripped, got %v", enrichedGlobal.CVEs)
	}
	if len(enrichedGlobal.RecommendedActions) != 0 || len(enrichedGlobal.RecommendedActionsJa) != 0 {
		t.Errorf("expected recommended actions to be cleared")
	}

	// 2. Official JPCERT/IPA general advisory stays Japan Direct, but severity caps at Medium
	itemJPCERT := ThreatItem{
		Title:      "Apache Tomcat の脆弱性に関する注意喚起",
		Summary:    "JPCERT/CCは悪用が確認された脆弱性について注意喚起を公開しました。",
		RawContent: "悪用が確認されています。",
		URL:        "https://www.jpcert.or.jp/at/2026/at260010.html",
		SourceType: SourceTypeVendorRSS,
		SourceName: "JPCERT/CC",
	}
	enrichedJPCERT := &EnrichedThreat{
		Severity:       SeverityCritical,
		JapanRelevance: JapanRelevanceDirect,
		TitleJa:        "JPCERT/CCによるApache Tomcatの脆弱性に関する注意喚起",
		AttackType:     "Zero-day",
	}
	NormalizeEnrichedThreat(itemJPCERT, enrichedJPCERT)
	if enrichedJPCERT.JapanRelevance != JapanRelevanceDirect {
		t.Errorf("expected official JPCERT source to remain Direct, got %s", enrichedJPCERT.JapanRelevance)
	}
	if enrichedJPCERT.Severity != SeverityMedium {
		t.Errorf("expected JPCERT general advisory without specific victim breach to cap at Medium, got %s", enrichedJPCERT.Severity)
	}

	// 3. Confirmed domestic Japanese breach remains Direct + Critical
	itemDomestic := ThreatItem{
		Title:      "株式会社物語コーポレーション「焼肉きんぐ」アプリで会員情報漏洩",
		Summary:    "不正アクセスにより会員情報が流出した事実を公表。",
		RawContent: "約100万件の会員データが漏洩。",
		URL:        "https://example.jp/breach-1",
		SourceType: SourceTypeWebSearch,
		SourceName: "Domestic News",
	}
	enrichedDomestic := &EnrichedThreat{
		Severity:       SeverityCritical,
		JapanRelevance: JapanRelevanceDirect,
		TitleJa:        "物語コーポレーション「焼肉きんぐ」アプリ会員情報漏洩",
		VictimOrgs:     []string{"株式会社物語コーポレーション"},
		AttackType:     "Data Breach",
	}
	NormalizeEnrichedThreat(itemDomestic, enrichedDomestic)
	if enrichedDomestic.JapanRelevance != JapanRelevanceDirect {
		t.Errorf("expected domestic breach to remain Direct, got %s", enrichedDomestic.JapanRelevance)
	}
	if enrichedDomestic.Severity != SeverityCritical {
		t.Errorf("expected severe domestic breach to remain Critical, got %s", enrichedDomestic.Severity)
	}
}

func TestUnmarshalPythonEnrichedThreatJSON(t *testing.T) {
	pythonJSON := `{"item_id": "451e2e80", "item": {"id": "451e2e80", "source_type": "vendor_rss", "source_name": "Security Next", "title": "ファンケルとアテニア、eコマースサイトの会員情報が流出", "url": "https://www.security-next.com/191600", "summary": "会員の個人情報が流出した。", "raw_content": null, "published_at": "2026-10-19 06:56:04+00:00", "harvested_at": "2026-10-19 08:02:54.149142+00:00", "metadata": {"category": "jp_news"}}, "severity": "High", "japan_relevance": "Direct", "title_ja": "ファンケルおよびアテニアのeコマースサイトで会員情報流出が発生", "summary_ja": "顧客の個人情報が流出したインシデント。", "victim_orgs": ["株式会社ファンケル"], "threat_actors": [], "attack_type": "Data Breach", "recommended_actions_ja": ["パスワード変更の要請"], "analyzed_at": "2026-10-19 08:10:04.281141+00:00"}`

	var parsed EnrichedThreat
	if err := json.Unmarshal([]byte(pythonJSON), &parsed); err != nil {
		t.Fatalf("expected Python space-separated timestamp JSON to unmarshal cleanly, got error: %v", err)
	}
	if parsed.Severity != SeverityHigh || parsed.JapanRelevance != JapanRelevanceDirect {
		t.Errorf("unexpected severity/relevance: %s / %s", parsed.Severity, parsed.JapanRelevance)
	}
	if parsed.Item.PublishedAt == nil || parsed.Item.PublishedAt.Year() != 2026 {
		t.Errorf("expected PublishedAt to parse 2026, got %v", parsed.Item.PublishedAt)
	}
	if parsed.AnalyzedAt.Year() != 2026 {
		t.Errorf("expected AnalyzedAt to parse 2026, got %v", parsed.AnalyzedAt)
	}

	NormalizeEnrichedThreat(parsed.Item, &parsed)
	out, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("failed to marshal normalized threat: %v", err)
	}
	if strings.Contains(string(out), "recommended_actions") {
		t.Errorf("expected recommended_actions_ja to be stripped after NormalizeEnrichedThreat, got %s", string(out))
	}
}

func TestCleanVictimOrgs(t *testing.T) {
	input := []string{
		"Unknown",
		"不明",
		"未具体提及",
		"未指定",
		"特定なし",
		"Multiple Japanese Corporations",
		"Various corporate entities",
		"Not explicitly named",
		"Fortinet customers",
		"Microsoft Windows users",
		"日本国内のPAN-OS導入企業",
		"株式会社ファンケル",
		"GMOインターネットグループ",
	}
	cleaned := CleanVictimOrgs(input)
	if len(cleaned) != 2 || cleaned[0] != "株式会社ファンケル" || cleaned[1] != "GMOインターネットグループ" {
		t.Fatalf("expected only specific named victim orgs, got %v", cleaned)
	}
}

func TestInformationalSeverityNormalization(t *testing.T) {
	if got := NormalizeDisplaySeverity(""); got != SeverityInformational {
		t.Errorf("expected empty severity -> Informational, got %s", got)
	}
	if got := NormalizeDisplaySeverity(SeverityUnknown); got != SeverityInformational {
		t.Errorf("expected Unknown severity -> Informational, got %s", got)
	}
	if got := NormalizeDisplaySeverity(SeverityInfo); got != SeverityInformational {
		t.Errorf("expected Info severity -> Informational for display, got %s", got)
	}
	if got := RefineSeverity(ThreatItem{Title: "MirrorFace Threat Actor Profile"}, nil); got != SeverityInformational {
		t.Errorf("expected nil enriched -> Informational, got %s", got)
	}
	// Ensure PR / Service Release still returns internal SeverityInfo so it gets dropped from incidents
	prItem := ThreatItem{Title: "新サービス提供開始のお知らせ"}
	prEnriched := &EnrichedThreat{Severity: SeverityInfo}
	if got := RefineSeverity(prItem, prEnriched); got != SeverityInfo {
		t.Errorf("expected service release to retain SeverityInfo for dismissal, got %s", got)
	}
}

func TestCyberattackGroupsExtractedAndReclassifiedAsActors(t *testing.T) {
	// 1. Japanese quoted APT group in title with empty LLM threat_actors
	itemUAT := ThreatItem{
		Title:   "【セキュリティ】APTグループ「UAT-11473」がCisco SD-WAN制御基盤を侵害",
		Summary: "Cisco Talosは高度なサイバー攻撃グループUAT-11473の活動を公表した。",
	}
	actorsUAT := ExtractThreatActors(itemUAT, nil)
	if len(actorsUAT) != 1 || actorsUAT[0] != "UAT-11473" {
		t.Fatalf("expected [UAT-11473], got %v", actorsUAT)
	}

	// 2. Ransomware group misclassified into VictimOrgs & AffectedProducts, plus vendor in ThreatActors
	itemRoundup := ThreatItem{
		Title:      "Monthly Ransomware Monitor: Multiple Japanese Organizations Targeted",
		Summary:    "Qilin and RansomEXX targeted domestic companies while DeadLock ransomware expanded.",
		SourceName: "Ransomlook Tracker (deadlock)",
	}
	enrichedMisclassified := &EnrichedThreat{
		Severity:         SeverityCritical,
		JapanRelevance:   JapanRelevanceDirect,
		VictimOrgs:       []string{"Qilin", "RansomEXX", "Ca***ka - Ransomware.live"},
		ThreatActors:     []string{"GeoVision", "Nightmare-Eclipse"},
		AffectedProducts: []string{"DeadLock ransomware", "Not specified"},
	}
	NormalizeEnrichedThreat(itemRoundup, enrichedMisclassified)

	if len(enrichedMisclassified.VictimOrgs) != 0 {
		t.Errorf("expected misclassified ransomware groups and masked victims stripped from VictimOrgs, got %v", enrichedMisclassified.VictimOrgs)
	}
	if len(enrichedMisclassified.AffectedProducts) != 0 {
		t.Errorf("expected ransomware family and 'Not specified' stripped from AffectedProducts, got %v", enrichedMisclassified.AffectedProducts)
	}
	actorSet := make(map[string]bool)
	for _, a := range enrichedMisclassified.ThreatActors {
		actorSet[a] = true
	}
	for _, want := range []string{"Qilin", "RansomEXX", "DeadLock"} {
		if !actorSet[want] {
			t.Errorf("expected %s in ThreatActors, got %v", want, enrichedMisclassified.ThreatActors)
		}
	}
	if actorSet["GeoVision"] || actorSet["Nightmare-Eclipse"] {
		t.Errorf("expected vendor/researcher excluded from ThreatActors, got %v", enrichedMisclassified.ThreatActors)
	}
	if enrichedMisclassified.Severity != SeverityMedium {
		t.Errorf("expected monthly roundup without concrete victim capped at Medium, got %s", enrichedMisclassified.Severity)
	}

	// 3. Parenthetical alias ("BlackTech（Earth Hundun）") and MirrorFace advisory
	itemBT := ThreatItem{
		Title:   "中国を背景とするサイバー攻撃グループ「BlackTech」によるサイバー攻撃に関する注意喚起",
		Summary: "BlackTech（Earth Hundun）の活動に関する共同注意喚起の概要",
	}
	actorsBT := ExtractThreatActors(itemBT, nil)
	btSet := make(map[string]bool)
	for _, a := range actorsBT {
		btSet[a] = true
	}
	if !btSet["BlackTech"] || !btSet["Earth Hundun"] {
		t.Errorf("expected BlackTech and Earth Hundun extracted as actors, got %v", actorsBT)
	}

	// 4. Legitimate security product ("Cisco Secure Firewall Adaptive Security Appliance", "Malwarebytes") preserved
	cleanProds := CleanAffectedProducts([]string{"Cisco Secure Firewall Adaptive Security Appliance", "Malwarebytes", "BlackTech supply chain products"})
	if len(cleanProds) != 2 {
		t.Errorf("expected 2 legitimate products preserved, got %v", cleanProds)
	}
}








