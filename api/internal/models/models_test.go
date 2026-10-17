package models

import (
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


