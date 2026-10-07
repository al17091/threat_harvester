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

func TestVulnerabilityCVEClustering(t *testing.T) {
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	pub1 := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	pub2 := pub1.Add(5 * 24 * time.Hour)

	// Report 1: NetScaler advisory mentioning two CVEs
	item1 := models.NewThreatItem(
		models.SourceTypeXMonitor,
		"X Monitor",
		"Active Exploitation of NetScaler ADC and Gateway Vulnerabilities (CVE-2026-88771, CVE-2026-88772)",
		"https://x.com/sec/status/123",
		"Alert regarding active attacks on NetScaler ADC and Gateway",
		"",
		&pub1,
		nil,
	)
	enriched1 := &models.EnrichedThreat{
		Severity:       models.SeverityCritical,
		JapanRelevance: models.JapanRelevanceIndirect,
		AttackType:     "Vulnerability",
		VictimOrgs:     []string{"Unknown"},
	}

	inc1, err := store.FindOrCreateIncident(ctx, item1, enriched1, 30)
	if err != nil {
		t.Fatalf("failed to cluster item 1: %v", err)
	}
	if inc1.ReportCount != 1 {
		t.Errorf("expected report count 1, got %d", inc1.ReportCount)
	}
	if len(inc1.CVEs) != 2 {
		t.Fatalf("expected 2 CVEs extracted, got %v", inc1.CVEs)
	}

	// Report 2: JPCERT advisory mentioning CVE-2026-88771 with generic victim
	item2 := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"JPCERT",
		"IPAおよびJPCERT/CCがNetScaler ADC/Gatewayの悪用中脆弱性（CVE-2026-88771等）に注意喚起",
		"https://jpcert.or.jp/at/2026/netscaler.html",
		"NetScalerに関する注意喚起情報",
		"",
		&pub2,
		nil,
	)
	enriched2 := &models.EnrichedThreat{
		Severity:       models.SeverityHigh,
		JapanRelevance: models.JapanRelevanceDirect,
		AttackType:     "Vulnerability",
		VictimOrgs:     []string{"国内組織全般"},
	}

	inc2, err := store.FindOrCreateIncident(ctx, item2, enriched2, 30)
	if err != nil {
		t.Fatalf("failed to cluster item 2: %v", err)
	}

	// Must cluster into the SAME incident due to matching CVE-2026-88771
	if inc2.ID != inc1.ID {
		t.Fatalf("expected item 2 to cluster into inc 1 by matching CVE, got distinct IDs: %s vs %s", inc2.ID, inc1.ID)
	}
	if inc2.ReportCount != 2 {
		t.Errorf("expected report count 2, got %d", inc2.ReportCount)
	}
	if len(inc2.SourceURLs) != 2 {
		t.Errorf("expected 2 source URLs preserved, got %v", inc2.SourceURLs)
	}
	if inc2.AffectedProduct == "" {
		t.Errorf("expected AffectedProduct to be set, got empty")
	}
}

func TestVulnerabilityProductClustering(t *testing.T) {
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	pub1 := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	pub2 := pub1.Add(3 * 24 * time.Hour)

	// Report 1: Zero-day alert for FortiMail without CVE
	item1 := models.NewThreatItem(
		models.SourceTypeWebSearch,
		"WebSearch",
		"Fortinet FortiMailの深刻なゼロデイ脆弱性の悪用が確認される",
		"https://example.com/fortimail-0day",
		"FortiMailアプライアンスに対する攻撃",
		"",
		&pub1,
		nil,
	)
	enriched1 := &models.EnrichedThreat{
		Severity:       models.SeverityCritical,
		JapanRelevance: models.JapanRelevanceDirect,
		AttackType:     "Zero-day",
		VictimOrgs:     []string{"Unknown"},
	}

	inc1, err := store.FindOrCreateIncident(ctx, item1, enriched1, 30)
	if err != nil {
		t.Fatalf("failed to cluster item 1: %v", err)
	}

	// Report 2: JPCERT alert on same product without CVE
	item2 := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"VendorRSS",
		"JPCERTがFortiMailアプライアンスのゼロデイ攻撃に緊急警戒情報",
		"https://jpcert.or.jp/fortimail",
		"FortiMail脆弱性への対応策",
		"",
		&pub2,
		nil,
	)
	enriched2 := &models.EnrichedThreat{
		Severity:       models.SeverityHigh,
		JapanRelevance: models.JapanRelevanceDirect,
		AttackType:     "Zero-day",
		VictimOrgs:     []string{"国内FortiMail利用組織"},
	}

	inc2, err := store.FindOrCreateIncident(ctx, item2, enriched2, 30)
	if err != nil {
		t.Fatalf("failed to cluster item 2: %v", err)
	}

	// Must cluster into the same incident based on same product ("fortimail")
	if inc2.ID != inc1.ID {
		t.Fatalf("expected items about same product to cluster together, got %s vs %s", inc2.ID, inc1.ID)
	}
	if inc2.ReportCount != 2 {
		t.Errorf("expected report count 2, got %d", inc2.ReportCount)
	}
}

func TestServiceReleaseAndInfoIncidentExclusion(t *testing.T) {
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	pub := time.Now()

	// 1. Service release announcement
	itemRelease := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"SecurityVendor",
		"HENNGE、新機能「HENNGE Mesh Network」の提供開始を発表",
		"https://example.com/hennge-mesh",
		"セキュリティ新機能の提供を開始",
		"",
		&pub,
		nil,
	)
	enrichedRelease := &models.EnrichedThreat{
		Severity:       models.SeverityLow,
		JapanRelevance: models.JapanRelevanceDirect,
		AttackType:     "Service Release",
		VictimOrgs:     []string{"HENNGE"},
	}

	inc1, err := store.FindOrCreateIncident(ctx, itemRelease, enrichedRelease, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inc1 != nil {
		t.Fatalf("expected nil incident for service release, got %v", inc1)
	}

	// 2. Info severity item
	itemInfo := models.NewThreatItem(
		models.SourceTypeWebSearch,
		"NewsFeed",
		"AI技術に関する国際カンファレンスが東京で開催決定",
		"https://example.com/ai-conf",
		"国内セキュリティカンファレンスの開催告知",
		"",
		&pub,
		nil,
	)
	enrichedInfo := &models.EnrichedThreat{
		Severity:       models.SeverityInfo,
		JapanRelevance: models.JapanRelevanceDirect,
		AttackType:     "None",
	}

	inc2, err := store.FindOrCreateIncident(ctx, itemInfo, enrichedInfo, 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inc2 != nil {
		t.Fatalf("expected nil incident for SeverityInfo, got %v", inc2)
	}

	// Verify incidents table remains empty
	var count int
	sqlStore := store.(*SQLStore)
	_ = sqlStore.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM incidents").Scan(&count)
	if count != 0 {
		t.Fatalf("expected 0 incidents in database, got %d", count)
	}
}



