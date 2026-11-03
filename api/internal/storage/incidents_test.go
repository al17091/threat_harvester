package storage

import (
	"context"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/api/internal/models"
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

func TestIncidentClusteringByURLAndLinkedURL(t *testing.T) {
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	pub := time.Now().UTC()

	// 1. Telegram post linking to an external advisory
	itemTelegram := models.NewThreatItem(
		models.SourceTypeTelegram,
		"Telegram:@intel_news",
		"[@intel_news] 重大な認証バイパスのゼロデイ発見",
		"https://t.me/s/intel_news/123",
		"テレグラム速報",
		"テレグラム本文\n\n--- [Linked Content: https://advisories.vendor.com/sec-2026-01] ---\n詳細な脆弱性解説",
		&pub,
		map[string]interface{}{
			"channel":     "intel_news",
			"linked_urls": []string{"https://advisories.vendor.com/sec-2026-01"},
		},
	)
	enrichedTG := &models.EnrichedThreat{
		Severity:       models.SeverityCritical,
		JapanRelevance: models.JapanRelevanceDirect,
		AttackType:     "Zero-day",
		TitleJa:        "ベンダー製品における重大な認証バイパス脆弱性",
	}

	inc1, err := store.FindOrCreateIncident(ctx, itemTelegram, enrichedTG, 14)
	if err != nil {
		t.Fatalf("failed to create incident from Telegram: %v", err)
	}
	if inc1.ReportCount != 1 {
		t.Fatalf("expected ReportCount 1, got %d", inc1.ReportCount)
	}
	// Check source URLs contain both Telegram and linked URL
	foundLinked := false
	for _, u := range inc1.SourceURLs {
		if u == "https://advisories.vendor.com/sec-2026-01" {
			foundLinked = true
			break
		}
	}
	if !foundLinked {
		t.Fatalf("expected linked URL to be in inc1.SourceURLs, got %v", inc1.SourceURLs)
	}
	if len(inc1.SourcesDetail) < 2 {
		t.Fatalf("expected at least 2 sources_detail entries (telegram + linked), got %d", len(inc1.SourcesDetail))
	}

	// 2. An X (Twitter) post referencing the same advisory URL
	itemX := models.NewThreatItem(
		models.SourceTypeXMonitor,
		"XMonitor:zeroday_alert",
		"Researcher confirms exploitation of vendor bug",
		"https://x.com/researcher/status/987654321",
		"X post summary",
		"Tweet text\n\n--- [Linked Content: https://advisories.vendor.com/sec-2026-01] ---\n詳細",
		&pub,
		map[string]interface{}{
			"linked_urls": []string{"https://advisories.vendor.com/sec-2026-01"},
		},
	)
	enrichedX := &models.EnrichedThreat{
		Severity:       models.SeverityCritical,
		JapanRelevance: models.JapanRelevanceDirect,
		AttackType:     "Zero-day",
		TitleJa:        "ベンダー製品における重大な認証バイパス脆弱性",
	}

	inc2, err := store.FindOrCreateIncident(ctx, itemX, enrichedX, 14)
	if err != nil {
		t.Fatalf("failed to cluster X post: %v", err)
	}

	// Must cluster into the EXACT same incident bundle (same ID, report count 2)
	if inc2.ID != inc1.ID {
		t.Fatalf("expected same incident ID, got %s vs %s", inc2.ID, inc1.ID)
	}
	if inc2.ReportCount != 2 {
		t.Fatalf("expected ReportCount 2, got %d", inc2.ReportCount)
	}
}

func TestTargetOrgAndAffectedProductClustering(t *testing.T) {
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	pub := time.Now().UTC()

	// 1. Report 1: GMO Internet Desktop Cloud Ransomware / 8 Billion Yen Extortion
	item1 := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"SecurityNext",
		"GMOに身代金要求 - ランサム攻撃や情報公開を行うと脅迫",
		"https://example.com/gmo-ransom-1",
		"GMOインターネット株式会社の「お名前.com デスクトップクラウド」に不正アクセス、身代金として80億円を要求",
		"",
		&pub,
		map[string]interface{}{
			"victim":  "GMOインターネット株式会社",
			"product": "お名前.com デスクトップクラウド",
		},
	)
	enriched1 := &models.EnrichedThreat{
		Severity:         models.SeverityCritical,
		JapanRelevance:   models.JapanRelevanceDirect,
		AttackType:       "Ransomware",
		VictimOrgs:       []string{"GMOインターネット株式会社"},
		AffectedProducts: []string{"お名前.com デスクトップクラウド"},
		TitleJa:          "GMOインターネット：お名前.com デスクトップクラウドに対するランサムウェア身代金要求",
	}

	inc1, err := store.FindOrCreateIncident(ctx, item1, enriched1, 30)
	if err != nil {
		t.Fatalf("failed to create initial incident: %v", err)
	}
	if inc1 == nil {
		t.Fatalf("expected incident to be created, got nil")
	}

	// 2. Report 2: English news reporting the same service compromise under different org alias
	item2 := models.NewThreatItem(
		models.SourceTypeWebSearch,
		"WebSearch",
		"GMO Internet Services Affected by Security Incident Involving Desktop Cloud",
		"https://example.com/gmo-ransom-2",
		"Attackers breached Onamae.com Desktop Cloud demanding ransom",
		"",
		&pub,
		map[string]interface{}{
			"victim":  "GMO Internet Group, Inc.",
			"product": "Onamae.com Desktop Cloud",
		},
	)
	enriched2 := &models.EnrichedThreat{
		Severity:         models.SeverityCritical,
		JapanRelevance:   models.JapanRelevanceDirect,
		AttackType:       "Data Breach",
		VictimOrgs:       []string{"GMO Internet Group, Inc."},
		AffectedProducts: []string{"Onamae.com Desktop Cloud"},
		TitleJa:          "GMOインターネットグループ デスクトップクラウド侵害事案",
	}

	inc2, err := store.FindOrCreateIncident(ctx, item2, enriched2, 30)
	if err != nil {
		t.Fatalf("failed to cluster second report: %v", err)
	}
	if inc2 == nil {
		t.Fatalf("expected inc2 to be non-nil")
	}
	if inc2.ID != inc1.ID {
		t.Fatalf("expected items with same target org and product to cluster together! Got %s vs %s", inc2.ID, inc1.ID)
	}
	if inc2.ReportCount != 2 {
		t.Errorf("expected ReportCount 2, got %d", inc2.ReportCount)
	}

	// 3. Report 3: GMO reporting on a DIFFERENT service ("infoQ")
	itemInfoQ := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"SecurityNext",
		"GMOリサーチ&AI運営のアンケートサイト「infoQ」への不正アクセス、個人情報流出を確認",
		"https://example.com/gmo-infoq",
		"infoQサイトへの不正アクセスにより会員情報が流出",
		"",
		&pub,
		map[string]interface{}{
			"victim":  "GMOインターネットグループ",
			"product": "infoQ",
		},
	)
	enrichedInfoQ := &models.EnrichedThreat{
		Severity:         models.SeverityHigh,
		JapanRelevance:   models.JapanRelevanceDirect,
		AttackType:       "Data Breach",
		VictimOrgs:       []string{"GMOインターネットグループ"},
		AffectedProducts: []string{"infoQ"},
		TitleJa:          "GMOリサーチ&AI「infoQ」個人情報流出事案",
	}

	incInfoQ, err := store.FindOrCreateIncident(ctx, itemInfoQ, enrichedInfoQ, 30)
	if err != nil {
		t.Fatalf("failed to process infoQ report: %v", err)
	}
	if incInfoQ.ID == inc1.ID {
		t.Fatalf("expected different product 'infoQ' to NOT merge into 'お名前.com デスクトップクラウド' incident! Both had ID: %s", incInfoQ.ID)
	}

	// 4. Report 4: Corporate PR notice (sympathy money payout) -> MUST RETURN nil, nil
	itemPR := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"SecurityNext",
		"「お名前.com デスクトップクラウド」に不正アクセス、見舞金として一律 5,000円を支払い",
		"https://example.com/gmo-pr",
		"代替サービスの提供とお見舞金の支払いについて発表",
		"",
		&pub,
		map[string]interface{}{
			"victim":  "GMOインターネット株式会社",
			"product": "お名前.com デスクトップクラウド",
		},
	)
	enrichedPR := &models.EnrichedThreat{
		Severity:         models.SeverityInfo,
		JapanRelevance:   models.JapanRelevanceDirect,
		AttackType:       "Corporate Notice",
		VictimOrgs:       []string{"GMOインターネット株式会社"},
		AffectedProducts: []string{"お名前.com デスクトップクラウド"},
	}

	incPR, err := store.FindOrCreateIncident(ctx, itemPR, enrichedPR, 30)
	if err != nil {
		t.Fatalf("unexpected error on corporate PR: %v", err)
	}
	if incPR != nil {
		t.Fatalf("expected corporate PR notice to be excluded from incident creation, got incident: %s", incPR.ID)
	}
}

func TestSeverityPrecedenceAndDisjointCVEIsolation(t *testing.T) {
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	pub1 := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	pub2 := pub1.Add(1 * time.Hour)
	pub3 := pub1.Add(2 * time.Hour)

	// Report 1: Critical RCE Zero-Day on PAN-OS (CVE-2026-0322)
	item1 := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"The Hacker News",
		"PAN-OS RCE Flaw Exploited in the Wild (CVE-2026-0322)",
		"https://thehackernews.com/cve-2026-0322",
		"Active exploitation of PAN-OS RCE",
		"CVE-2026-0322 active exploitation details",
		&pub1,
		nil,
	)
	enriched1 := &models.EnrichedThreat{
		Title:            "Palo Alto Networks Patches Actively Exploited PAN-OS RCE Vulnerability (CVE-2026-0322)",
		TitleJa:          "Palo Alto Networks PAN-OSにおける悪用確認済みのRCEゼロデイ脆弱性（CVE-2026-0322）",
		Summary:          "Palo Alto Networks has released patches for an actively exploited RCE zero-day.",
		SummaryJa:        "Palo Alto Networksは、悪用が確認されたPAN-OSのRCEゼロデイ脆弱性に対する修正パッチを公開しました。",
		ImpactAnalysisJa: "管理インターフェイスが露出している場合、完全な侵害を受ける危険性があります。",
		Severity:         models.SeverityCritical,
		JapanRelevance:   models.JapanRelevanceDirect,
		AttackType:       "Zero-day",
		CVEs:             []string{"CVE-2026-0322"},
		AffectedProducts: []string{"Palo Alto Networks PAN-OS"},
	}

	inc1, err := store.FindOrCreateIncident(ctx, item1, enriched1, 30)
	if err != nil {
		t.Fatalf("failed to create incident 1: %v", err)
	}
	if inc1.Severity != models.SeverityCritical {
		t.Fatalf("expected Critical severity, got %s", inc1.Severity)
	}

	// Report 2: Same CVE-2026-0322, but High severity vendor notice with different (lower-priority) summary
	item2 := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"Vendor Advisory",
		"Palo Alto Networks Advisory on CVE-2026-0322",
		"https://securityadvisories.paloaltonetworks.com/cve-2026-0322",
		"Vendor advisory for PAN-OS CVE-2026-0322",
		"Vendor advisory details",
		&pub2,
		nil,
	)
	enriched2 := &models.EnrichedThreat{
		Title:            "Vendor Advisory: PAN-OS CVE-2026-0322",
		TitleJa:          "Palo Alto NetworksによるCVE-2026-0322アドバイザリ",
		Summary:          "Minor vendor advisory summary",
		SummaryJa:        "ベンダーによるパッチ適用の案内",
		ImpactAnalysisJa: "パッチ適用により影響は限定的になります。",
		Severity:         models.SeverityHigh, // Lower than Critical!
		JapanRelevance:   models.JapanRelevanceIndirect,
		AttackType:       "Vulnerability",
		CVEs:             []string{"CVE-2026-0322"},
		AffectedProducts: []string{"Palo Alto Networks PAN-OS"},
	}

	inc2, err := store.FindOrCreateIncident(ctx, item2, enriched2, 30)
	if err != nil {
		t.Fatalf("failed to cluster report 2: %v", err)
	}
	if inc2.ID != inc1.ID {
		t.Fatalf("expected report 2 to cluster into inc1 due to shared CVE, got %s", inc2.ID)
	}
	// Verify that the Critical title and summary were PRESERVED and not overwritten by the lower-severity report!
	if inc2.Severity != models.SeverityCritical {
		t.Errorf("expected Severity to remain Critical, got %s", inc2.Severity)
	}
	if inc2.TitleJa != enriched1.TitleJa {
		t.Errorf("expected TitleJa to be preserved from Critical report: %q, got: %q", enriched1.TitleJa, inc2.TitleJa)
	}
	if inc2.SummaryJa != enriched1.SummaryJa {
		t.Errorf("expected SummaryJa to be preserved from Critical report: %q, got: %q", enriched1.SummaryJa, inc2.SummaryJa)
	}

	// Report 3: Disjoint CVE on PAN-OS (CVE-2026-9999, DoS advisory, High severity)
	item3 := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"Vendor Advisory",
		"Palo Alto Networks PAN-OS DoS Advisory (CVE-2026-9999)",
		"https://securityadvisories.paloaltonetworks.com/cve-2026-9999",
		"Denial of service advisory for PAN-OS",
		"CVE-2026-9999 DoS details",
		&pub3,
		nil,
	)
	enriched3 := &models.EnrichedThreat{
		Title:            "Palo Alto Networks PAN-OS Denial of Service Vulnerability Advisory",
		TitleJa:          "Palo Alto Networks PAN-OSのサービス拒否（DoS）脆弱性に関するアドバイザリ",
		Summary:          "DoS vulnerability in PAN-OS",
		SummaryJa:        "PAN-OSにおけるサービス拒否脆弱性",
		ImpactAnalysisJa: "ファイアウォールがメンテナンスモードになる恐れがあります。",
		Severity:         models.SeverityHigh,
		JapanRelevance:   models.JapanRelevanceIndirect,
		AttackType:       "Vulnerability",
		CVEs:             []string{"CVE-2026-9999"}, // Disjoint from CVE-2026-0322!
		AffectedProducts: []string{"Palo Alto Networks PAN-OS"},
	}

	inc3, err := store.FindOrCreateIncident(ctx, item3, enriched3, 30)
	if err != nil {
		t.Fatalf("failed to cluster report 3: %v", err)
	}
	// Must NOT cluster with inc1 because CVEs are disjoint and attack types/severities differ!
	if inc3.ID == inc1.ID {
		t.Fatalf("expected report 3 with disjoint CVE to create separate incident, but clustered into inc1: %s", inc3.ID)
	}
	if inc3.Severity != models.SeverityHigh {
		t.Errorf("expected report 3 to have Severity High, got %s", inc3.Severity)
	}
	if inc3.TitleJa != enriched3.TitleJa {
		t.Errorf("expected report 3 to have its own TitleJa, got: %q", inc3.TitleJa)
	}
}

func TestBlackholeClusteringPrevention(t *testing.T) {
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	pub := time.Now().UTC()

	// 1. Initial FortiOS critical vulnerability incident
	itemForti := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"Fortinet Security Advisory",
		"FortiOS SSL-VPN Authentication Bypass RCE",
		"https://fortiguard.com/psirt/FG-IR-26-001",
		"FortiOS VPN vulnerability exploited in the wild",
		"Raw body with links to https://securityaffairs.com and https://cisa.gov/known-exploited-vulnerabilities-catalog",
		&pub,
		map[string]interface{}{
			"linked_urls": []string{
				"https://securityaffairs.com/",
				"https://cisa.gov/known-exploited-vulnerabilities-catalog",
			},
		},
	)
	enrichedForti := &models.EnrichedThreat{
		Title:            "FortiOS SSL-VPN Remote Code Execution",
		TitleJa:          "FortiOS SSL-VPNにおけるリモートコード実行の脆弱性（CVE-2026-12345）",
		Severity:         models.SeverityCritical,
		JapanRelevance:   models.JapanRelevanceIndirect,
		AttackType:       "Zero-day",
		CVEs:             []string{"CVE-2026-12345"},
		AffectedProducts: []string{"FortiOS"},
	}

	incForti, err := store.FindOrCreateIncident(ctx, itemForti, enrichedForti, 30)
	if err != nil {
		t.Fatalf("failed to create FortiOS incident: %v", err)
	}

	// 2. Trend Micro report linking to domain root https://securityaffairs.com
	// Must NOT cluster with FortiOS via Track 0 domain root or substring matching!
	itemTrend := models.NewThreatItem(
		models.SourceTypeWebSearch,
		"Trend Micro Research",
		"AI-driven Cyber Attack Infrastructure Discovered",
		"https://trendmicro.com/en_us/research/26/ai-infrastructure.html",
		"Global cybercrime infrastructure report",
		"Body linking to https://securityaffairs.com",
		&pub,
		map[string]interface{}{
			"linked_urls": []string{"https://securityaffairs.com/"},
		},
	)
	enrichedTrend := &models.EnrichedThreat{
		Title:          "AI-driven Cyber Attack Infrastructure Discovered",
		TitleJa:        "AI駆動型サイバー攻撃インフラの発見",
		Severity:       models.SeverityHigh,
		JapanRelevance: models.JapanRelevanceNone,
		AttackType:     "Cybercrime",
	}

	incTrend, err := store.FindOrCreateIncident(ctx, itemTrend, enrichedTrend, 30)
	if err != nil {
		t.Fatalf("failed to cluster Trend Micro report: %v", err)
	}
	if incTrend.ID == incForti.ID {
		t.Fatalf("blackhole bug reproduced: Trend Micro report falsely merged into FortiOS incident via domain root!")
	}

	// 3. Apple iOS zero-day with distinct CVE and product. Must NOT merge into FortiOS!
	itemApple := models.NewThreatItem(
		models.SourceTypeWebSearch,
		"Apple Security",
		"Apple iOS 18.7 Zero-day Exploit",
		"https://support.apple.com/en-us/HT214000",
		"Apple releases emergency patch for iOS",
		"Apple iOS kernel vulnerability CVE-2026-86950",
		&pub,
		nil,
	)
	enrichedApple := &models.EnrichedThreat{
		Title:            "Apple iOS Kernel Zero-day",
		TitleJa:          "Apple iOSにおける悪用確認済みのゼロデイ脆弱性（CVE-2026-86950）",
		Severity:         models.SeverityCritical,
		JapanRelevance:   models.JapanRelevanceIndirect,
		AttackType:       "Zero-day",
		CVEs:             []string{"CVE-2026-86950"},
		AffectedProducts: []string{"Apple iOS"},
	}

	incApple, err := store.FindOrCreateIncident(ctx, itemApple, enrichedApple, 30)
	if err != nil {
		t.Fatalf("failed to cluster Apple report: %v", err)
	}
	if incApple.ID == incForti.ID {
		t.Fatalf("blackhole bug reproduced: Apple iOS report merged into FortiOS incident!")
	}

	// 4. Generic victim org reports (e.g. Multiple Organizations / Japanese enterprises)
	// Must NOT merge into each other under generic victim clustering!
	itemGeneric1 := models.NewThreatItem(
		models.SourceTypeWebSearch,
		"Report 1",
		"Cyber Threat Landscape Survey",
		"https://example.com/survey-2026",
		"Annual survey",
		"Summary",
		&pub,
		nil,
	)
	enrichedGeneric1 := &models.EnrichedThreat{
		Title:          "Cyber Threat Landscape Survey",
		TitleJa:        "2026年サイバー脅威動向調査",
		Severity:       models.SeverityMedium,
		JapanRelevance: models.JapanRelevanceIndirect,
		VictimOrgs:     []string{"Multiple Organizations (Global Trend Report)"},
	}
	incGen1, err := store.FindOrCreateIncident(ctx, itemGeneric1, enrichedGeneric1, 30)
	if err != nil {
		t.Fatalf("failed to cluster generic report 1: %v", err)
	}

	itemGeneric2 := models.NewThreatItem(
		models.SourceTypeWebSearch,
		"Report 2",
		"IDC Frontier Ransomware Incident",
		"https://example.com/idc-incident",
		"IDC Frontier breach",
		"Summary",
		&pub,
		nil,
	)
	enrichedGeneric2 := &models.EnrichedThreat{
		Title:          "IDC Frontier Ransomware Incident",
		TitleJa:        "IDCフロンティアにおけるランサムウェア被害",
		Severity:       models.SeverityHigh,
		JapanRelevance: models.JapanRelevanceDirect,
		VictimOrgs:     []string{"Multiple Organizations (Global Trend Report)"}, // noisy extraction
	}
	incGen2, err := store.FindOrCreateIncident(ctx, itemGeneric2, enrichedGeneric2, 30)
	if err != nil {
		t.Fatalf("failed to cluster generic report 2: %v", err)
	}
	if incGen1.ID == incGen2.ID {
		t.Fatalf("generic victim org falsely clustered unrelated reports together!")
	}
}

func TestBackfillIncidentsRetroactiveNormalization(t *testing.T) {
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	pub := time.Now().UTC()

	// Insert a legacy over-inflated threat_item (Indirect + Critical + RecommendedActions + CVE-2026-9999)
	item := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"BleepingComputer",
		"Foreign Cloud Vendor Suffers Zero-day Attack",
		"https://bleepingcomputer.com/news/security/foreign-cloud-attack",
		"Active zero-day exploit against foreign cloud software",
		"Active exploitation observed in the wild",
		&pub,
		nil,
	)
	legacyEnriched := &models.EnrichedThreat{
		ItemID:               item.ID,
		Item:                 item,
		Severity:             models.SeverityCritical,
		JapanRelevance:       models.JapanRelevanceIndirect,
		Title:                "Foreign Cloud Zero-day Attack",
		TitleJa:              "海外クラウド製品に対するゼロデイ攻撃",
		AttackType:           "Zero-day",
		CVEs:                 []string{"CVE-2026-9999", "CVE-2026-77777"},
		RecommendedActions:   []string{"Enable MFA"},
		RecommendedActionsJa: []string{"MFAを有効化してください"},
		AnalyzedAt:           pub,
	}
	if err := store.MarkSeen(ctx, item, legacyEnriched, false); err != nil {
		t.Fatalf("MarkSeen failed: %v", err)
	}

	incCount, err := store.BackfillIncidents(ctx, 30)
	if err != nil {
		t.Fatalf("BackfillIncidents failed: %v", err)
	}
	if incCount != 1 {
		t.Fatalf("expected 1 incident after backfill, got %d", incCount)
	}

	incs, err := store.GetIncidents(ctx, HistoryFilter{Limit: 10})
	if err != nil || len(incs) != 1 {
		t.Fatalf("expected 1 incident from GetIncidents, got %d (err=%v)", len(incs), err)
	}
	if incs[0]["severity"] != "High" {
		t.Errorf("expected retroactive backfill to cap Indirect Critical to High, got %v", incs[0]["severity"])
	}
	cves, _ := incs[0]["cves"].([]string)
	if len(cves) != 1 || cves[0] != "CVE-2026-77777" {
		t.Errorf("expected CVE-2026-9999 to be stripped during backfill, got %v", cves)
	}
}






