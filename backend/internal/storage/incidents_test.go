package storage

import (
	"context"
	"testing"
	"time"

	"github.com/dapt/information_harvester/backend/internal/models"
)

func TestIncidentClusteringSlidingWindow(t *testing.T) {
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	baseTime := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	pub1 := baseTime
	pub2 := baseTime.Add(15 * 24 * time.Hour) // Day 15 (within 30 days of pub1)
	pub3 := baseTime.Add(40 * 24 * time.Hour) // Day 40 (within 30 days of pub2 Day 15 -> sliding window extended!)
	pub4 := baseTime.Add(80 * 24 * time.Hour) // Day 80 (40 days after pub3 -> outside 30-day window!)

	// Report 1: Initial breach report for "パーク24株式会社"
	item1 := models.NewThreatItem(
		models.SourceTypeWebSearch,
		"WebSearch",
		"パーク24 不正アクセス報告",
		"https://example.com/report1",
		"Summary 1",
		"",
		&pub1,
		map[string]interface{}{"victim": "パーク24株式会社"},
	)
	enriched1 := &models.EnrichedThreat{
		Severity:       models.SeverityHigh,
		JapanRelevance: models.JapanRelevanceDirect,
		VictimOrgs:     []string{"パーク24株式会社"},
		TitleJa:        "パーク24 不正アクセス報告 (日本語)",
	}

	inc1, err := store.FindOrCreateIncident(ctx, item1, enriched1, 30)
	if err != nil {
		t.Fatalf("failed to cluster item 1: %v", err)
	}
	if inc1.ReportCount != 1 {
		t.Errorf("expected report count 1, got %d", inc1.ReportCount)
	}
	if len(inc1.SourceURLs) != 1 || inc1.SourceURLs[0] != "https://example.com/report1" {
		t.Errorf("expected source URL preserved, got %v", inc1.SourceURLs)
	}

	// Report 2: Day 15 report from Ransomware group DLS targeting same org
	item2 := models.NewThreatItem(
		models.SourceTypeDarkwebOnion,
		"DarkWeb",
		"[Group DLS] Victim: Park24 (JP)",
		"https://ransomlook.io/group/test",
		"Summary 2",
		"",
		&pub2,
		map[string]interface{}{"victim": "株式会社パーク24"},
	)
	enriched2 := &models.EnrichedThreat{
		Severity:       models.SeverityCritical,
		JapanRelevance: models.JapanRelevanceDirect,
		VictimOrgs:     []string{"株式会社パーク24"},
	}

	inc2, err := store.FindOrCreateIncident(ctx, item2, enriched2, 30)
	if err != nil {
		t.Fatalf("failed to cluster item 2: %v", err)
	}
	if inc2.ID != inc1.ID {
		t.Fatalf("expected item 2 to cluster into inc 1, got different IDs: %s vs %s", inc2.ID, inc1.ID)
	}
	if inc2.ReportCount != 2 {
		t.Errorf("expected report count 2, got %d", inc2.ReportCount)
	}
	if inc2.Severity != models.SeverityCritical {
		t.Errorf("expected severity elevated to Critical, got %s", inc2.Severity)
	}
	if len(inc2.SourceURLs) != 2 {
		t.Errorf("expected 2 distinct source URLs preserved, got %v", inc2.SourceURLs)
	}
	if !inc2.LastSeenAt.Equal(pub2) {
		t.Errorf("expected last_seen_at extended to pub2, got %v", inc2.LastSeenAt)
	}

	// Report 3: Day 40 report (within 30 days of pub2 Day 15 -> sliding window!)
	item3 := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"Vendor RSS",
		"JPCERT Update on Park24 Incident",
		"https://jpcert.or.jp/at/2026/park24.html",
		"Summary 3",
		"",
		&pub3,
		nil,
	)
	enriched3 := &models.EnrichedThreat{
		Severity:       models.SeverityMedium,
		JapanRelevance: models.JapanRelevanceDirect,
		VictimOrgs:     []string{"パーク24"},
	}

	inc3, err := store.FindOrCreateIncident(ctx, item3, enriched3, 30)
	if err != nil {
		t.Fatalf("failed to cluster item 3: %v", err)
	}
	if inc3.ID != inc1.ID {
		t.Fatalf("expected sliding window to extend inc 1, got new ID: %s", inc3.ID)
	}
	if inc3.ReportCount != 3 {
		t.Errorf("expected report count 3, got %d", inc3.ReportCount)
	}
	if len(inc3.SourceURLs) != 3 {
		t.Errorf("expected 3 source URLs, got %v", inc3.SourceURLs)
	}

	// Report 4: Day 80 report (40 days after Day 40 -> 30-day window expired)
	item4 := models.NewThreatItem(
		models.SourceTypeWebSearch,
		"WebSearch",
		"Fresh Attack on Park24 After Long Hiatus",
		"https://example.com/report4",
		"Summary 4",
		"",
		&pub4,
		nil,
	)
	enriched4 := &models.EnrichedThreat{
		Severity:       models.SeverityHigh,
		JapanRelevance: models.JapanRelevanceDirect,
		VictimOrgs:     []string{"パーク24"},
	}

	inc4, err := store.FindOrCreateIncident(ctx, item4, enriched4, 30)
	if err != nil {
		t.Fatalf("failed to cluster item 4: %v", err)
	}
	if inc4.ID == inc1.ID {
		t.Fatalf("expected new incident after window expired, but got same ID: %s", inc4.ID)
	}
	if inc4.ReportCount != 1 {
		t.Errorf("expected new incident report count 1, got %d", inc4.ReportCount)
	}
}

func TestGenericVictimOrgIsolation(t *testing.T) {
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	item1 := models.NewThreatItem(models.SourceTypeWebSearch, "Source1", "日本企業へのランサムウェア攻撃", "https://ex.com/1", "Sum1", "", &now, nil)
	enriched1 := &models.EnrichedThreat{VictimOrgs: []string{"日本企業"}}

	item2 := models.NewThreatItem(models.SourceTypeWebSearch, "Source2", "国内企業を狙うフィッシング", "https://ex.com/2", "Sum2", "", &now, nil)
	enriched2 := &models.EnrichedThreat{VictimOrgs: []string{"国内企業"}}

	inc1, err := store.FindOrCreateIncident(ctx, item1, enriched1, 30)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	inc2, err := store.FindOrCreateIncident(ctx, item2, enriched2, 30)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if inc1.ID == inc2.ID {
		t.Fatalf("generic victim names must NOT be clustered together! got identical ID %s", inc1.ID)
	}
}
