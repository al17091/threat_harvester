package harvesters

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/models"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestTelegramHarvester(t *testing.T) {
	ctx := context.Background()
	h := NewTelegramHarvester()

	if h.Name() == "" || h.SourceType() != models.SourceTypeTelegram {
		t.Errorf("unexpected name or source type")
	}

	// Mock Telegram channel HTML
	telegramHTML := `
		<!DOCTYPE html>
		<html>
		<body>
			<div class="tgme_widget_message" data-post="security_channel/100">
				<div class="tgme_widget_message_text">
					Critical zero-day exploit detected targeting enterprise VPN gateways across Japan.
					https://example.com/advisory/vpn-zero-day
				</div>
				<time datetime="` + time.Now().UTC().Format(time.RFC3339) + `"></time>
			</div>
		</body>
		</html>
	`

	h.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(telegramHTML)),
			Header:     make(http.Header),
		}, nil
	})

	origCfg := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origCfg)

	cfg := origCfg
	cfg.Sources.Telegram = []config.TelegramSourceConfig{
		{
			Channel:        "@security_channel",
			Enabled:        true,
			ComplianceTier: config.TierToSRestricted,
		},
	}
	cfg.Compliance.Tiers.ToSRestricted = true
	config.GetSettings().SetConfig(cfg)

	// TestConnection
	if !h.TestConnection(ctx) {
		t.Errorf("expected TestConnection to succeed")
	}

	// Harvest
	items, err := h.Harvest(ctx, nil)
	if err != nil {
		t.Fatalf("Harvest failed: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("expected harvested items from telegram")
	}
	if items[0].SourceType != models.SourceTypeTelegram {
		t.Errorf("expected SourceTypeTelegram, got %s", items[0].SourceType)
	}
}

func TestRansomwareTrackerHarvester(t *testing.T) {
	ctx := context.Background()
	h := NewRansomwareTrackerHarvester()

	if h.Name() == "" || h.SourceType() != models.SourceTypeRansomwareTracker {
		t.Errorf("unexpected name or source type")
	}

	ransomwareJSON := `[
		{
			"victim": "Tokyo Financial Holdings",
			"group_name": "LockBit3",
			"discovered": "` + time.Now().UTC().Format("2006-01-02 15:04:05.000000") + `",
			"website": "http://lockbitvictim.test",
			"country": "JP"
		}
	]`

	h.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(ransomwareJSON)),
			Header:     make(http.Header),
		}, nil
	})

	origCfg := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origCfg)

	cfg := origCfg
	cfg.Sources.RansomwareTracker = []config.RansomwareSourceConfig{
		{
			Name:           "Test Ransomware Feed",
			URL:            "https://ransomware.test/api/posts",
			Type:           "api",
			Enabled:        true,
			ComplianceTier: config.TierCommercialViaOfficialAPI,
		},
	}
	cfg.Compliance.Tiers.CommercialViaOfficialAPI = true
	config.GetSettings().SetConfig(cfg)

	// TestConnection
	if !h.TestConnection(ctx) {
		t.Errorf("expected TestConnection to succeed")
	}

	// Harvest
	items, err := h.Harvest(ctx, nil)
	if err != nil {
		t.Fatalf("Harvest failed: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("expected harvested ransomware items")
	}
	if items[0].SourceType != models.SourceTypeRansomwareTracker {
		t.Errorf("expected SourceTypeRansomwareTracker, got %s", items[0].SourceType)
	}

	// Harvest RSS target
	rssFeed := `<?xml version="1.0" encoding="utf-8"?>
	<rss version="2.0">
	<channel>
		<title>RansomFeed Aggregator</title>
		<item>
			<title>[LockBit] Target Organization Data Published</title>
			<link>https://ransomfeed.test/post/1</link>
			<description>Victim: Target Organization</description>
			<pubDate>` + time.Now().UTC().Format(time.RFC1123) + `</pubDate>
		</item>
	</channel>
	</rss>`

	h.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(rssFeed)),
			Header:     make(http.Header),
		}, nil
	})

	cfg.Sources.RansomwareTracker = []config.RansomwareSourceConfig{
		{
			Name:           "Test Ransomware RSS",
			URL:            "https://ransomfeed.test/news.rss",
			Type:           "rss",
			Enabled:        true,
			ComplianceTier: config.TierCommercialViaOfficialAPI,
		},
	}
	config.GetSettings().SetConfig(cfg)

	rssItems, err := h.Harvest(ctx, nil)
	if err != nil || len(rssItems) != 1 {
		t.Fatalf("expected 1 RSS item, got %d, err: %v", len(rssItems), err)
	}
	if rssItems[0].SourceType != models.SourceTypeRansomwareTracker {
		t.Errorf("expected SourceTypeRansomwareTracker, got %s", rssItems[0].SourceType)
	}
}

func TestVendorRSSHarvester(t *testing.T) {
	ctx := context.Background()
	h := NewVendorRSSHarvester()

	if h.Name() == "" || h.SourceType() != models.SourceTypeVendorRSS {
		t.Errorf("unexpected name or source type")
	}

	rssXML := `<?xml version="1.0" encoding="UTF-8"?>
		<rss version="2.0">
			<channel>
				<title>CERT Alert Feed</title>
				<link>https://cert.test</link>
				<item>
					<title>Severe Vulnerability in Routing Software</title>
					<link>https://cert.test/advisory/101</link>
					<description>A vulnerability allows remote code execution.</description>
					<pubDate>` + time.Now().UTC().Format(time.RFC1123) + `</pubDate>
				</item>
			</channel>
		</rss>`

	h.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(rssXML)),
			Header:     make(http.Header),
		}, nil
	})

	origCfg := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origCfg)

	cfg := origCfg
	cfg.Sources.VendorRSS = []config.FeedSourceConfig{
		{
			Name:           "CERT Alert Feed",
			URL:            "https://cert.test/rss.xml",
			Enabled:        true,
			ComplianceTier: config.TierCommercialReady,
		},
	}
	cfg.Compliance.Tiers.CommercialReady = true
	config.GetSettings().SetConfig(cfg)

	// TestConnection
	if !h.TestConnection(ctx) {
		t.Errorf("expected TestConnection to succeed")
	}

	// Harvest
	items, err := h.Harvest(ctx, nil)
	if err != nil {
		t.Fatalf("Harvest failed: %v", err)
	}
	if len(items) == 0 {
		t.Fatalf("expected harvested RSS items")
	}
}

func TestXMonitorHarvester(t *testing.T) {
	ctx := context.Background()
	h := NewXMonitorHarvester()

	if h.Name() == "" || h.SourceType() != models.SourceTypeXMonitor {
		t.Errorf("unexpected name or source type")
	}

	searxngJSON := `{
		"results": [
			{
				"title": "Critical incident reported on X / Twitter",
				"url": "https://x.com/researcher/status/1234567890",
				"content": "Malware campaign observed targeting energy sector."
			}
		]
	}`

	h.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(searxngJSON)),
			Header:     make(http.Header),
		}, nil
	})

	origCfg := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origCfg)

	cfg := origCfg
	// 1. Without Gemini API key: TestConnection is false, Harvest returns nil
	cfg.AI.GeminiAPIKey = ""
	config.GetSettings().SetConfig(cfg)
	if h.TestConnection(ctx) {
		t.Errorf("expected TestConnection to fail without Gemini API key")
	}
	itemsNoKey, err := h.Harvest(ctx, nil)
	if err != nil || itemsNoKey != nil {
		t.Errorf("expected nil items without API key")
	}

	// 2. With Gemini API key: TestConnection is true
	cfg.AI.GeminiAPIKey = "dummy-gemini-key"
	cfg.Sources.XMonitor = []config.QuerySourceConfig{
		{
			Name:           "X Researcher Feed",
			Query:          "malware energy",
			Enabled:        true,
			ComplianceTier: config.TierCommercialViaOfficialAPI,
		},
	}
	cfg.Compliance.Tiers.CommercialViaOfficialAPI = true
	config.GetSettings().SetConfig(cfg)

	if !h.TestConnection(ctx) {
		t.Errorf("expected TestConnection to succeed with API key")
	}

	geminiJSON := `{
		"candidates": [
			{
				"content": {
					"parts": [
						{
							"text": "[{\"title\": \"Critical breach alert on X\", \"url\": \"https://x.com/researcher/status/12345\", \"summary\": \"Data breach disclosed\", \"published_date\": \"2026-10-15\"}]"
						}
					]
				},
				"groundingMetadata": {
					"groundingChunks": [
						{
							"web": {
								"uri": "https://x.com/researcher/status/12345",
								"title": "Critical breach alert on X"
							}
						}
					]
				}
			}
		]
	}`

	h.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(geminiJSON)),
			Header:     make(http.Header),
		}, nil
	})

	items, err := h.Harvest(ctx, nil)
	if err != nil {
		t.Fatalf("h.Harvest failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 grounded X item, got %d", len(items))
	}
	if items[0].Title != "Critical breach alert on X" {
		t.Errorf("expected title 'Critical breach alert on X', got: %s", items[0].Title)
	}
}

func TestGroundingHelpers(t *testing.T) {
	// isGenericDomain
	if !isGenericDomain("https://www.google.com/search?q=test") {
		t.Errorf("expected google.com to be generic domain")
	}
	if !isGenericDomain("https://x.com/home") {
		t.Errorf("expected x.com to be generic domain")
	}
	if isGenericDomain("https://threat-intel-vendor.example.jp/reports/123") {
		t.Errorf("expected threat intel vendor to not be generic domain")
	}

	// matchGroundingChunkURL
	chunks := []geminiGroundingChunk{
		{
			Web: struct {
				URI   string `json:"uri"`
				Title string `json:"title"`
			}{
				URI:   "https://example.com/advisory/2026",
				Title: "Advisory for ACME Corp",
			},
		},
	}
	target := matchGroundingChunkURL("Ransomware breach", "ACME Corp", chunks)
	if target != "https://example.com/advisory/2026" {
		t.Errorf("expected matched grounding URL, got: %s", target)
	}
}

func TestWebSearchHarvester(t *testing.T) {
	ctx := context.Background()
	h := NewWebSearchHarvester()

	if h.Name() == "" || h.SourceType() != models.SourceTypeWebSearch {
		t.Errorf("unexpected name or source type")
	}

	searxngJSON := `{
		"results": [
			{
				"title": "Critical infrastructure cyber threat detected",
				"url": "https://cybersecurity.example.com/alert/123",
				"content": "Malware campaign observed targeting energy sector across APAC.",
				"publishedDate": "2026-10-15T10:00:00Z"
			}
		]
	}`

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(searxngJSON))
	}))
	defer mockServer.Close()

	origCfg := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origCfg)

	cfg := origCfg
	cfg.AI.GeminiAPIKey = "mock-gemini-key"
	cfg.Sources.WebSearch = []config.QuerySourceConfig{
		{
			Name:            "SearXNG Threat Query",
			Type:            "searxng",
			URL:             mockServer.URL,
			Query:           "ransomware energy APAC",
			Enabled:         true,
			ComplianceTier:  config.TierCommercialViaOfficialAPI,
			IntervalMinutes: 0,
		},
	}
	cfg.Compliance.Tiers.CommercialViaOfficialAPI = true
	config.GetSettings().SetConfig(cfg)

	// TestConnection with API key
	if !h.TestConnection(ctx) {
		t.Errorf("expected TestConnection to be true with Gemini key")
	}

	// Harvest
	items, err := h.Harvest(ctx, nil)
	if err != nil {
		t.Fatalf("Harvest failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 item from SearXNG web search, got %d", len(items))
	}
	if items[0].Title != "Critical infrastructure cyber threat detected" {
		t.Errorf("unexpected item title: %s", items[0].Title)
	}
}

func TestDarkwebHarvester_BasicAndSearch(t *testing.T) {
	ctx := context.Background()
	h := NewDarkwebOnionHarvester()

	if h.Name() == "" || h.SourceType() != models.SourceTypeDarkwebOnion {
		t.Errorf("unexpected name or source type")
	}

	searxngJSON := `{
		"results": [
			{
				"title": "Darkweb Leak Forum Post",
				"url": "http://examp1eonionaddress777.onion/leak/123",
				"content": "Confidential data dump from enterprise network."
			}
		]
	}`

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(searxngJSON))
	}))
	defer mockServer.Close()

	origCfg := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origCfg)

	cfg := origCfg
	cfg.Sources.DarkwebOnion = []config.DarkwebSourceConfig{
		{
			Name:           "Darkweb SearXNG Search",
			Type:           "searxng",
			URL:            mockServer.URL,
			Query:          "database breach",
			Enabled:        true,
			ComplianceTier: config.TierDarkwebAccess,
		},
	}
	cfg.Compliance.Tiers.DarkwebAccess = true
	config.GetSettings().SetConfig(cfg)

	items, err := h.Harvest(ctx, nil)
	if err != nil {
		t.Fatalf("Harvest failed: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 darkweb item, got %d", len(items))
	}
	if !strings.Contains(items[0].URL, ".onion") {
		t.Errorf("expected .onion URL, got %s", items[0].URL)
	}
}

func TestHarvesterTestConnections(t *testing.T) {
	ctx := context.Background()

	// 1. WebSearchHarvester TestConnection with Gemini API key
	origCfg := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origCfg)

	cfg := origCfg
	cfg.AI.GeminiAPIKey = "test-key"
	config.GetSettings().SetConfig(cfg)

	wsh := NewWebSearchHarvester()
	if !wsh.TestConnection(ctx) {
		t.Errorf("expected WebSearchHarvester.TestConnection to return true when API key is set")
	}

	// 2. DarkwebOnionHarvester TestConnection with canceled context
	dwh := NewDarkwebOnionHarvester()
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if dwh.TestConnection(canceledCtx) {
		t.Errorf("expected DarkwebOnionHarvester.TestConnection to return false for canceled context")
	}
}


