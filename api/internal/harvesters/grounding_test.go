package harvesters

import (
	"testing"
)

func TestIsGenericDomain(t *testing.T) {
	tests := []struct {
		url      string
		expected bool
	}{
		{"https://www.google.com/search?q=test", true},
		{"https://google.co.jp/", true},
		{"https://twitter.com/home", true},
		{"https://x.com/", true},
		{"https://t.me/", true},
		{"https://duckduckgo.com", true},
		{"https://news.yahoo.co.jp/articles/12345", false},
		{"https://example.com/advisory/cve-2024-1111", false},
		{"invalid-url", true},
	}

	for _, tt := range tests {
		got := isGenericDomain(tt.url)
		if got != tt.expected {
			t.Errorf("isGenericDomain(%q) = %v, want %v", tt.url, got, tt.expected)
		}
	}
}

func TestMatchGroundingChunkURL(t *testing.T) {
	chunks := []geminiGroundingChunk{
		{
			Web: struct {
				URI   string `json:"uri"`
				Title string `json:"title"`
			}{
				URI:   "https://www.google.com/search",
				Title: "Google Search",
			},
		},
		{
			Web: struct {
				URI   string `json:"uri"`
				Title string `json:"title"`
			}{
				URI:   "https://security-today.example/articles/acme-corp-breach",
				Title: "Acme Corp Hit By Ransomware",
			},
		},
		{
			Web: struct {
				URI   string `json:"uri"`
				Title string `json:"title"`
			}{
				URI:   "https://cert.example/advisory/critical-vulnerability",
				Title: "Critical Security Advisory Update",
			},
		},
	}

	// 1. Match by victim org
	uri := matchGroundingChunkURL("Ransomware Notice", "Acme Corp", chunks)
	if uri != "https://security-today.example/articles/acme-corp-breach" {
		t.Errorf("expected match by victim org, got: %s", uri)
	}

	// 2. Match by title significant words
	uri = matchGroundingChunkURL("Security Advisory Update", "", chunks)
	if uri != "https://cert.example/advisory/critical-vulnerability" {
		t.Errorf("expected match by title words, got: %s", uri)
	}

	// 3. Fallback to first non-generic chunk
	uri = matchGroundingChunkURL("Unrelated Incident", "Unknown Org", chunks)
	if uri != "https://security-today.example/articles/acme-corp-breach" {
		t.Errorf("expected fallback to first non-generic chunk, got: %s", uri)
	}

	// 4. Empty chunks
	if matchGroundingChunkURL("Title", "Victim", nil) != "" {
		t.Errorf("expected empty string for nil chunks")
	}
}
