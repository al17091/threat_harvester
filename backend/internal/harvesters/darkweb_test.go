package harvesters

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dapt/information_harvester/backend/internal/config"
	"github.com/dapt/information_harvester/backend/internal/models"
)

func TestIsCTIRelevant(t *testing.T) {
	cases := []struct {
		input    string
		expected bool
	}{
		{"LockBit ransomware gang published stolen data of company", true},
		{"New database dump containing 500k credentials on darknet forum", true},
		{"0day exploit available for enterprise VPN", true},
		{"Japan manufacturing corporation victim of extortion group", true},
		{"Online pharmacy selling cheap sunglasses and vitamins", false},
		{"Personal blog about gardening and cats", false},
	}

	for _, c := range cases {
		got := isCTIRelevant(c.input)
		if got != c.expected {
			t.Errorf("isCTIRelevant(%q) = %v, expected %v", c.input, got, c.expected)
		}
	}
}

func TestDoAhmiaSearchParser(t *testing.T) {
	// Mock Ahmia web server returning dynamic honeypot token and search results
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`
				<!DOCTYPE html><html><body>
				<form action="/search/" method="get">
					<input type="hidden" name="c0ffee1234" value="9876543210abcdef">
					<input type="text" name="q">
				</form>
				</body></html>
			`))
			return
		}

		if strings.HasPrefix(r.URL.Path, "/search/") {
			q := r.URL.Query().Get("q")
			tok := r.URL.Query().Get("c0ffee1234")
			if q != "japan ransomware" || tok != "9876543210abcdef" {
				http.Error(w, "missing or invalid query/token", http.StatusBadRequest)
				return
			}

			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`
				<!DOCTYPE html><html><body>
				<ol>
					<li class="result">
						<h4><a href="/search/redirect?search_term=japan+ransomware&redirect_url=http%3A%2F%2Flockbitcorp1234.onion%2Ftarget">LockBit 3.0: Japan Corp Data Leak</a></h4>
						<p>Stolen confidential accounting files and customer database published.</p>
						<span class="lastSeen">2026-10-07</span>
					</li>
					<li class="result">
						<h4><a href="/search/redirect?search_term=japan+ransomware&redirect_url=https%3A%2F%2Fclearnet-market.com%2Fitem">Clearnet Market</a></h4>
						<p>Buy discounted software and sunglasses</p>
					</li>
				</ol>
				</body></html>
			`))
			return
		}

		http.NotFound(w, r)
	}))
	defer ts.Close()

	dw := NewDarkwebOnionHarvester()
	ctx := context.Background()
	results, err := dw.doAhmiaSearch(ctx, ts.Client(), ts.URL, "japan ransomware")
	if err != nil {
		t.Fatalf("expected doAhmiaSearch to succeed, got: %v", err)
	}

	// Clearnet URL must be skipped, strictly retaining only .onion result
	if len(results) != 1 {
		t.Fatalf("expected exactly 1 result (onion only), got: %d", len(results))
	}

	res := results[0]
	if res.URL != "http://lockbitcorp1234.onion/target" {
		t.Errorf("unexpected target URL: %s", res.URL)
	}
	if res.Title != "LockBit 3.0: Japan Corp Data Leak" {
		t.Errorf("unexpected Title: %s", res.Title)
	}
	if !strings.Contains(res.Snippet, "Stolen confidential accounting") {
		t.Errorf("unexpected Snippet: %s", res.Snippet)
	}
	if res.PublishedAt == nil {
		t.Error("expected PublishedAt to be parsed")
	} else if res.PublishedAt.Format("2006-01-02") != "2026-10-07" {
		t.Errorf("unexpected PublishedAt: %s", res.PublishedAt.Format("2006-01-02"))
	}
}

func TestHarvestHTMLScraper(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`
			<!DOCTYPE html><html><head><title>BlackCat DLS Portal</title></head><body>
			<div class="card">
				<h2>Victim: Tokyo Energy Systems</h2>
				<p>750GB of corporate intranet documents and SCADA logs exfiltrated.</p>
				<a href="http://blackcathidden987.onion/proof/1">Download Proof</a>
			</div>
			</body></html>
		`))
	}))
	defer ts.Close()

	dw := NewDarkwebOnionHarvester()
	ctx := context.Background()
	target := config.DarkwebSourceConfig{
		Name:    "BlackCat DLS",
		URL:     ts.URL,
		Type:    "html",
		Enabled: true,
	}

	items, err := dw.harvestHTML(ctx, ts.Client(), target, nil)
	if err != nil {
		t.Fatalf("expected harvestHTML to succeed, got: %v", err)
	}

	if len(items) == 0 {
		t.Fatal("expected at least 1 threat item extracted from HTML")
	}

	item := items[0]
	if item.SourceType != models.SourceTypeDarkwebOnion {
		t.Errorf("expected SourceTypeDarkwebOnion, got: %s", item.SourceType)
	}
	if !strings.Contains(item.Title, "Tokyo Energy Systems") && !strings.Contains(item.Title, "BlackCat DLS") {
		t.Errorf("unexpected Title: %s", item.Title)
	}
	if !strings.Contains(item.Summary, "750GB") {
		t.Errorf("unexpected Summary: %s", item.Summary)
	}
}

func TestDarkwebSearchConfigValidation(t *testing.T) {
	mgr := config.GetSettings()
	err := mgr.AddSource("darkweb_onion", map[string]interface{}{
		"name":      "Tor Search: Japan Ransomware",
		"type":      "search",
		"query":     "japan ransomware leak",
		"directive": "",
	})
	if err != nil {
		t.Fatalf("expected adding search source to succeed, got %v", err)
	}
	defer mgr.DeleteSource("darkweb_onion", "Tor Search: Japan Ransomware")

	cfg := mgr.GetConfig()
	found := false
	for _, dw := range cfg.Sources.DarkwebOnion {
		if dw.Type == "search" && dw.Query == "japan ransomware leak" {
			found = true
			if !strings.Contains(dw.URL, ".onion") {
				t.Errorf("expected default .onion URL to be populated, got %s", dw.URL)
			}
			break
		}
	}
	if !found {
		t.Fatal("expected search source to be registered in DarkwebOnion")
	}
}

func TestDarkwebSourceType(t *testing.T) {
	dw := NewDarkwebOnionHarvester()
	if dw.SourceType() != models.SourceTypeDarkwebOnion {
		t.Errorf("expected %s, got %s", models.SourceTypeDarkwebOnion, dw.SourceType())
	}
	if dw.Name() == "" {
		t.Error("expected non-empty name")
	}
}

