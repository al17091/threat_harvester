package storage

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/api/internal/models"
)

func TestStorageOperations(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	item := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"CERT-JP",
		"Zero-Day advisory in popular framework",
		"https://cert.org/123",
		"Critical flaw actively exploited",
		"",
		&now,
		nil,
	)

	// IsSeen should be false initially
	seen, err := store.IsSeen(ctx, item.ID)
	if err != nil {
		t.Fatalf("IsSeen failed: %v", err)
	}
	if seen {
		t.Fatal("expected item to not be seen")
	}

	enriched := &models.EnrichedThreat{
		ItemID:               item.ID,
		Item:                 item,
		Severity:             models.SeverityCritical,
		JapanRelevance:       models.JapanRelevanceDirect,
		TitleJa:              "フレームワークのゼロデイ脆弱性悪用",
		SummaryJa:            "日本国内の複数組織で悪用観測",
		ImpactAnalysisJa:     "国内インフラへの影響大",
		VictimOrgs:           []string{"Example Corp"},
		ThreatActors:         []string{"APT99"},
		RecommendedActionsJa: []string{"パッチ適用"},
		AnalyzedAt:           now,
	}

	// MarkSeen
	if err := store.MarkSeen(ctx, item, enriched, true); err != nil {
		t.Fatalf("MarkSeen failed: %v", err)
	}

	// IsSeen should be true now
	seen, err = store.IsSeen(ctx, item.ID)
	if err != nil || !seen {
		t.Fatal("expected item to be seen after MarkSeen")
	}

	// Stats
	stats, err := store.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if stats["total_items"] != 1 || stats["notified_items"] != 1 || stats["japan_direct_items"] != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}

	// History
	history, err := store.GetHistory(ctx, HistoryFilter{Limit: 10, JapanOnly: true})
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected 1 history item, got %d", len(history))
	}

	total, err := store.GetHistoryTotal(ctx, HistoryFilter{JapanOnly: true})
	if err != nil {
		t.Fatalf("GetHistoryTotal failed: %v", err)
	}
	if total != 1 {
		t.Fatalf("expected total 1, got %d", total)
	}

	// Insert older published item to test ordering
	olderTime := now.Add(-24 * time.Hour)
	olderItem := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"CERT-JP",
		"Older advisory",
		"https://cert.org/older",
		"Older description",
		"",
		&olderTime,
		nil,
	)
	_ = store.MarkSeen(ctx, olderItem, enriched, false)

	historyOrdered, err := store.GetHistory(ctx, HistoryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("GetHistory with ordering failed: %v", err)
	}
	if len(historyOrdered) < 2 {
		t.Fatalf("expected at least 2 items, got %d", len(historyOrdered))
	}
	if historyOrdered[0]["id"] != item.ID {
		t.Fatalf("expected newer published item to be first, got %v", historyOrdered[0]["id"])
	}

	// GetItem
	retrieved, err := store.GetItem(ctx, item.ID)
	if err != nil || retrieved == nil {
		t.Fatalf("GetItem failed: %v", err)
	}
	if retrieved["title"] != item.Title {
		t.Fatalf("expected title %s, got %v", item.Title, retrieved["title"])
	}
	if retrieved["raw_content"] != item.RawContent {
		t.Fatalf("expected raw_content %q, got %v", item.RawContent, retrieved["raw_content"])
	}

	// Test IsSeenItem by URL match
	duplicateURLItem := models.NewThreatItem(
		models.SourceTypeWebSearch,
		"WebSearch",
		"Completely Different Title Mentioning Flaw",
		"https://cert.org/123", // same URL as item
		"New summary",
		"",
		&now,
		nil,
	)
	seenItem, err := store.IsSeenItem(ctx, duplicateURLItem)
	if err != nil {
		t.Fatalf("IsSeenItem failed: %v", err)
	}
	if !seenItem {
		t.Fatal("expected IsSeenItem to be true due to matching URL")
	}

	// Test IsRecentlyNotified: Example Corp was notified above
	recentlyNotified, err := store.IsRecentlyNotified(ctx, []string{"Example Corp"}, "New attack report", nil, 48)
	if err != nil {
		t.Fatalf("IsRecentlyNotified failed: %v", err)
	}
	if !recentlyNotified {
		t.Fatal("expected recentlyNotified to be true for Example Corp")
	}

	// Test CVE matching in IsRecentlyNotified
	cveNotified, err := store.IsRecentlyNotified(ctx, nil, "Advisory without org", []string{"CVE-2026-99999"}, 48)
	if err != nil {
		t.Fatalf("IsRecentlyNotified with CVE failed: %v", err)
	}
	if cveNotified {
		// No item was notified with CVE-2026-99999 yet
	}

	// Unrelated org should not trigger cooldown
	unrelatedNotified, err := store.IsRecentlyNotified(ctx, []string{"Unrelated Org"}, "Different incident", nil, 48)
	if err != nil {
		t.Fatalf("IsRecentlyNotified failed: %v", err)
	}
	if unrelatedNotified {
		t.Fatal("expected unrelatedNotified to be false")
	}

	// Test IsIncidentRecentlyNotified
	itemWithInc := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"CERT-JP",
		"Notified Incident Item",
		"https://cert.org/inc-item",
		"Incident description",
		"",
		&now,
		nil,
	)
	itemWithInc.IncidentID = "inc-test-123"
	_ = store.MarkSeen(ctx, itemWithInc, enriched, true)

	incNotified, err := store.IsIncidentRecentlyNotified(ctx, "inc-test-123", 48)
	if err != nil {
		t.Fatalf("IsIncidentRecentlyNotified failed: %v", err)
	}
	if !incNotified {
		t.Fatal("expected IsIncidentRecentlyNotified to be true for inc-test-123")
	}

	incUnnotified, err := store.IsIncidentRecentlyNotified(ctx, "inc-unknown-999", 48)
	if err != nil {
		t.Fatalf("IsIncidentRecentlyNotified failed: %v", err)
	}
	if incUnnotified {
		t.Fatal("expected IsIncidentRecentlyNotified to be false for unknown incident")
	}
}

func TestRemediateSearXNG(t *testing.T) {
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	sqlStore, ok := store.(*SQLStore)
	if !ok {
		t.Fatal("expected SQLStore")
	}

	// Insert threat item with SearXNG branding and query leak
	_, err = sqlStore.db.Exec(`
		INSERT INTO threat_items (id, source_type, source_name, title, url, raw_content, harvested_at)
		VALUES ('item-searxng-1', 'web_search', 'SearXNG Web: 国内ランサムウェア速報', 'Title', 'https://scan.netsecurity.ne.jp/article/2026/01.html', ?, '2026-11-08T00:00:00Z')
	`, "Article body\n\n[SearXNG Query: test query]\n[Engine: google]")
	if err != nil {
		t.Fatalf("failed to insert test item: %v", err)
	}

	// Run remediation
	sqlStore.remediateSearXNGSourcesAndSnippets()

	// Verify
	var srcName, rawContent string
	err = sqlStore.db.QueryRow("SELECT source_name, raw_content FROM threat_items WHERE id = 'item-searxng-1'").Scan(&srcName, &rawContent)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if srcName != "ScanNetSecurity" {
		t.Errorf("expected source_name 'ScanNetSecurity', got '%s'", srcName)
	}
	if rawContent != "Article body" {
		t.Errorf("expected raw_content 'Article body', got '%s'", rawContent)
	}

	// Insert incident with SearXNG in sources_detail
	_, err = sqlStore.db.Exec(`
		INSERT INTO incidents (id, title, victim_org, affected_product, attack_type, severity, japan_relevance, first_seen_at, last_seen_at, created_at, updated_at, sources_detail, raw_content)
		VALUES ('inc-searxng-1', 'Incident Title', 'Victim', 'Product', 'Ransomware', 'High', 'Direct', '2026-11-08T00:00:00Z', '2026-11-08T00:00:00Z', '2026-11-08T00:00:00Z', '2026-11-08T00:00:00Z', '[{"source_type":"web_search","source_name":"SearXNG Web: 国内速報","url":"https://scan.netsecurity.ne.jp/article/1"}]', ?)
	`, "Incident body\n\n[SearXNG Query: test query]\n[Engine: google]")
	if err != nil {
		t.Fatalf("failed to insert test incident: %v", err)
	}

	// Run remediation again
	sqlStore.remediateSearXNGSourcesAndSnippets()

	var incDetail, incRaw string
	err = sqlStore.db.QueryRow("SELECT sources_detail, raw_content FROM incidents WHERE id = 'inc-searxng-1'").Scan(&incDetail, &incRaw)
	if err != nil {
		t.Fatalf("query incident failed: %v", err)
	}
	if incRaw != "Incident body" {
		t.Errorf("expected inc raw_content 'Incident body', got '%s'", incRaw)
	}
	if !strings.Contains(incDetail, "ScanNetSecurity") || strings.Contains(incDetail, "SearXNG") {
		t.Errorf("expected clean sources_detail containing ScanNetSecurity without SearXNG, got: %s", incDetail)
	}
}
