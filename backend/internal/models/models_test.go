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


