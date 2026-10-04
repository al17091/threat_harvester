package models

import (
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
