package storage

import (
	"context"
	"testing"
	"time"

	"github.com/dapt/information_harvester/backend/internal/models"
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
	recentlyNotified, err := store.IsRecentlyNotified(ctx, []string{"Example Corp"}, "New attack report", 48)
	if err != nil {
		t.Fatalf("IsRecentlyNotified failed: %v", err)
	}
	if !recentlyNotified {
		t.Fatal("expected recentlyNotified to be true for Example Corp")
	}

	// Unrelated org should not trigger cooldown
	unrelatedNotified, err := store.IsRecentlyNotified(ctx, []string{"Unrelated Org"}, "Different incident", 48)
	if err != nil {
		t.Fatalf("IsRecentlyNotified failed: %v", err)
	}
	if unrelatedNotified {
		t.Fatal("expected unrelatedNotified to be false")
	}
}
