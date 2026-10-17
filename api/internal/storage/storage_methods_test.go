package storage

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/api/internal/models"
)

func TestIncidentOperations(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory store: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	item1 := models.ThreatItem{
		ID:          "item-test-1",
		SourceType:  models.SourceTypeVendorRSS,
		SourceName:  "JPCERT",
		Title:       "標的型攻撃インシデントに関する注意喚起",
		URL:         "https://example.com/sec/incident-1",
		Summary:     "国内組織に対する標的型攻撃が確認されました。",
		PublishedAt: &now,
		HarvestedAt: now,
	}
	enriched1 := &models.EnrichedThreat{
		ItemID:               "item-test-1",
		Item:                 item1,
		Title:                "Targeted Attack Alert EN",
		TitleJa:              "標的型攻撃インシデントに関する注意喚起",
		Summary:              "Targeted attacks observed against domestic organizations.",
		SummaryJa:            "国内組織に対する標的型攻撃が確認されました。",
		Severity:             models.SeverityCritical,
		JapanRelevance:       models.JapanRelevanceDirect,
		AttackType:           "Ransomware",
		VictimOrgs:           []string{"Example Manufacturing Corp"},
		ThreatActors:         []string{"APT99"},
		RecommendedActions:   []string{"Block C2 IPs"},
		RecommendedActionsJa: []string{"C2 IPの遮断"},
	}

	// 1. Create Incident
	inc, err := store.FindOrCreateIncident(ctx, item1, enriched1, 30)
	if err != nil {
		t.Fatalf("FindOrCreateIncident failed: %v", err)
	}
	if inc == nil || inc.ID == "" {
		t.Fatalf("Expected valid incident created")
	}
	item1.IncidentID = inc.ID
	if err := store.MarkSeen(ctx, item1, enriched1, true); err != nil {
		t.Fatalf("MarkSeen failed: %v", err)
	}

	// 2. GetIncidents & GetIncidentsTotal
	filter := HistoryFilter{
		Limit:     10,
		Offset:    0,
		JapanOnly: true,
		Severity:  "Critical",
		OrderBy:   "first_seen_at",
	}
	incidents, err := store.GetIncidents(ctx, filter)
	if err != nil {
		t.Fatalf("GetIncidents failed: %v", err)
	}
	if len(incidents) != 1 {
		t.Fatalf("Expected 1 incident, got %d", len(incidents))
	}
	total, err := store.GetIncidentsTotal(ctx, filter)
	if err != nil || total != 1 {
		t.Errorf("Expected total 1, got %d, err: %v", total, err)
	}

	// 3. GetIncident single
	singleInc, err := store.GetIncident(ctx, inc.ID)
	if err != nil {
		t.Fatalf("GetIncident failed: %v", err)
	}
	if singleInc == nil {
		t.Fatalf("Expected incident %s, got nil", inc.ID)
	}
	if singleInc["id"] != inc.ID {
		t.Errorf("Expected incident id %s, got %v", inc.ID, singleInc["id"])
	}
	// Verify non-existent returns nil, nil
	missingInc, err := store.GetIncident(ctx, "incident--non-existent-999")
	if err != nil || missingInc != nil {
		t.Errorf("Expected nil, nil for missing incident, got %v, %v", missingInc, err)
	}

	// 4. UpdateIncidentLabels
	err = store.UpdateIncidentLabels(ctx, inc.ID, []string{"Lazarus"}, "High", "Indirect", "DDoS", "New Victim")
	if err != nil {
		t.Fatalf("UpdateIncidentLabels failed: %v", err)
	}
	updatedInc, _ := store.GetIncident(ctx, inc.ID)
	if updatedInc["severity"] != "High" {
		t.Errorf("Expected updated severity High, got %v", updatedInc["severity"])
	}
	if updatedInc["victim_org"] != "New Victim" {
		t.Errorf("Expected updated victim_org New Victim, got %v", updatedInc["victim_org"])
	}

	// 5. UpdateIncidentTranslations
	err = store.UpdateIncidentTranslations(ctx, inc.ID, "New English Title", "New English Summary", "New Impact", "Victim EN", "Product EN", []string{"Patch"})
	if err != nil {
		t.Fatalf("UpdateIncidentTranslations failed: %v", err)
	}
	transInc, _ := store.GetIncident(ctx, inc.ID)
	if transInc["title"] != "New English Title" {
		t.Errorf("Expected updated title 'New English Title', got %v", transInc["title"])
	}

	// 6. GetIncidentsNeedingTranslation
	needing, err := store.GetIncidentsNeedingTranslation(ctx, 10)
	if err != nil {
		t.Fatalf("GetIncidentsNeedingTranslation failed: %v", err)
	}
	_ = needing // verify query execution without error

	// 7. GetEntityStats
	stats, err := store.GetEntityStats(ctx, 10, false)
	if err != nil {
		t.Fatalf("GetEntityStats failed: %v", err)
	}
	if stats == nil {
		t.Fatalf("Expected non-nil entity stats")
	}
	// japanOnly=true
	statsJp, err := store.GetEntityStats(ctx, 10, true)
	if err != nil {
		t.Fatalf("GetEntityStats(japanOnly=true) failed: %v", err)
	}
	if statsJp == nil {
		t.Fatalf("Expected non-nil stats for japanOnly")
	}
}

func TestStorageItemsAndHistory(t *testing.T) {
	ctx := context.Background()
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory store: %v", err)
	}
	defer store.Close()

	now := time.Now().UTC()
	item := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"Test Feed",
		"Test Vulnerability in OpenSSL",
		"https://example.com/vuln/1",
		"Summary of OpenSSL vulnerability",
		"Raw content here",
		&now,
		map[string]interface{}{"cve": "CVE-2026-9999"},
	)
	item.FetchStatus = "pending"
	enriched := &models.EnrichedThreat{
		ItemID:         item.ID,
		Item:           item,
		Severity:       models.SeverityHigh,
		JapanRelevance: models.JapanRelevanceDirect,
		TitleJa:        "OpenSSLの脆弱性",
	}

	if err := store.MarkSeen(ctx, item, enriched, false); err != nil {
		t.Fatalf("MarkSeen failed: %v", err)
	}

	// 1. GetLatestHarvestTime
	latest, err := store.GetLatestHarvestTime(ctx)
	if err != nil {
		t.Fatalf("GetLatestHarvestTime failed: %v", err)
	}
	if latest == nil {
		t.Fatalf("Expected non-nil latest harvest time")
	}

	// 2. GetItem
	gotItem, err := store.GetItem(ctx, item.ID)
	if err != nil || gotItem == nil {
		t.Fatalf("GetItem failed or returned nil: %v", err)
	}
	if gotItem["title"] != item.Title {
		t.Errorf("Expected title %s, got %v", item.Title, gotItem["title"])
	}

	// 3. GetPendingFetchItems & UpdateFetchStatus
	pendingItems, err := store.GetPendingFetchItems(ctx, 10, 2, false)
	if err != nil {
		t.Fatalf("GetPendingFetchItems failed: %v", err)
	}
	if len(pendingItems) != 1 {
		t.Errorf("Expected 1 pending fetch item, got %d", len(pendingItems))
	}

	err = store.UpdateFetchStatus(ctx, item.ID, "completed", 1, "", "Updated Scraped Content")
	if err != nil {
		t.Fatalf("UpdateFetchStatus failed: %v", err)
	}

	// 4. GetHistory with filters
	hFilter := HistoryFilter{
		Limit:      10,
		Offset:     0,
		Search:     "OpenSSL",
		Severity:   "High",
		SourceType: "vendor_rss",
		JapanOnly:  true,
	}
	history, err := store.GetHistory(ctx, hFilter)
	if err != nil {
		t.Fatalf("GetHistory failed: %v", err)
	}
	if len(history) != 1 {
		t.Errorf("Expected 1 history item, got %d", len(history))
	}
	totalHist, err := store.GetHistoryTotal(ctx, hFilter)
	if err != nil || totalHist != 1 {
		t.Errorf("Expected history total 1, got %d", totalHist)
	}

	// 5. normalizePostgresURL helper
	sqlStore := store.(*SQLStore)
	normURL := normalizePostgresURL("postgresql+psycopg://user:pass@localhost:5432/threat_db?sslmode=disable")
	if normURL == "" {
		t.Errorf("Expected normalized postgres url")
	}
	normURL2 := normalizePostgresURL("postgresql://user:pass@localhost:5432/threat_db")
	if normURL2 == "" {
		t.Errorf("Expected normalized postgres url")
	}
	masked := sqlStore.maskURL("postgres://user:supersecret@localhost:5432/db")
	if masked == "postgres://user:supersecret@localhost:5432/db" {
		t.Errorf("Expected masked url")
	}
}

func TestBackfillOperations(t *testing.T) {
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open store: %v", err)
	}
	defer store.Close()
	ctx := context.Background()

	// 1. BackfillArticleContents
	item1 := models.ThreatItem{
		ID:         "bf-item-1",
		Title:      "Advisory Without Full Content",
		URL:        "https://example.com/advisory-1",
		Summary:    "Short summary",
		RawContent: "", // empty triggers backfill
		SourceType: models.SourceTypeVendorRSS,
		SourceName: "Vendor Feed",
	}
	item2 := models.ThreatItem{
		ID:         "bf-item-2",
		Title:      "Another Advisory",
		URL:        "https://example.com/advisory-2",
		Summary:    "Short summary 2",
		RawContent: "Brief", // length < 150 triggers backfill for vendor_rss
		SourceType: models.SourceTypeVendorRSS,
		SourceName: "Vendor Feed",
	}
	enriched := &models.EnrichedThreat{
		Severity:       models.SeverityHigh,
		JapanRelevance: models.JapanRelevanceDirect,
		Title:          "Advisory Without Full Content",
		Summary:        "Enriched summary",
	}

	_ = store.MarkSeen(ctx, item1, enriched, false)
	_ = store.MarkSeen(ctx, item2, enriched, false)
	_, _ = store.FindOrCreateIncident(ctx, item1, enriched, 30)
	_, _ = store.FindOrCreateIncident(ctx, item2, enriched, 30)

	sqlStore := store.(*SQLStore)

	// Fetcher error case (nil fetcher)
	if _, err := sqlStore.BackfillArticleContents(ctx, nil); err == nil {
		t.Errorf("Expected error for nil fetcher")
	}

	// Successful fetcher
	mockFetcher := func(ctx context.Context, u string) (string, error) {
		return "This is the full scraped content from the website providing comprehensive threat details.", nil
	}
	count, err := sqlStore.BackfillArticleContents(ctx, mockFetcher)
	if err != nil {
		t.Fatalf("BackfillArticleContents failed: %v", err)
	}
	if count < 1 {
		t.Errorf("Expected at least 1 backfilled article, got %d", count)
	}

	// 2. BackfillIncidents
	clusteredCount, err := sqlStore.BackfillIncidents(ctx, 30)
	if err != nil {
		t.Fatalf("BackfillIncidents failed: %v", err)
	}
	if clusteredCount < 1 {
		t.Errorf("Expected at least 1 incident created during backfill, got %d", clusteredCount)
	}
}

func TestBuildIncidentActorReasons(t *testing.T) {
	// 1. Empty cleanActors
	rEn, rJa := buildIncidentActorReasons(&models.Incident{}, nil)
	if len(rEn) != 0 || len(rJa) != 0 {
		t.Errorf("expected empty maps, got %v, %v", rEn, rJa)
	}

	inc := &models.Incident{
		Title:      "Incident title mentioning Lazarus Group",
		TitleJa:    "日本語タイトル APT29 を含む",
		RawContent: "Full article body reporting that Volt Typhoon was detected",
		Summary:    "Summary text mentioning FIN7 financial threat",
		SourcesDetail: []models.SourceDetail{
			{Name: "CISA Alert", Title: "Advisory on BlackCat ransomware operations"},
		},
	}

	actors := []string{"BlackCat", "Lazarus Group", "APT29", "Volt Typhoon", "FIN7", "UnknownActor"}
	reasonsEn, reasonsJa := buildIncidentActorReasons(inc, actors)

	if len(reasonsEn) != 6 {
		t.Fatalf("expected 6 reasons, got %d", len(reasonsEn))
	}
	if reasonsEn["BlackCat"] == "" || reasonsJa["BlackCat"] == "" {
		t.Errorf("expected reason for BlackCat from SourceDetail")
	}
	if reasonsEn["Lazarus Group"] == "" || reasonsJa["Lazarus Group"] == "" {
		t.Errorf("expected reason for Lazarus from Title")
	}
	if reasonsEn["APT29"] == "" || reasonsJa["APT29"] == "" {
		t.Errorf("expected reason for APT29 from TitleJa")
	}
	if reasonsEn["Volt Typhoon"] == "" || reasonsJa["Volt Typhoon"] == "" {
		t.Errorf("expected reason for Volt Typhoon from RawContent")
	}
	if reasonsEn["FIN7"] == "" || reasonsJa["FIN7"] == "" {
		t.Errorf("expected reason for FIN7 from Summary")
	}
	if reasonsEn["UnknownActor"] == "" || reasonsJa["UnknownActor"] == "" {
		t.Errorf("expected fallback reason for UnknownActor")
	}
}

func TestCleanUngroundedIncidentThreatActors(t *testing.T) {
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	sqlStore := store.(*SQLStore)
	ctx := context.Background()

	// Insert an incident with an ungrounded threat actor directly into DB
	_, err = sqlStore.db.ExecContext(ctx, `
		INSERT INTO incidents (
			id, title, raw_content, summary_ja, sources_detail, threat_actors, severity, japan_relevance, attack_type, victim_org, first_seen_at, last_seen_at, created_at, updated_at
		) VALUES (
			'inc-ungrounded-1', 'Routine system maintenance', 'No threats mentioned in content', 'Summary text', '[]', '["FakeHallucinatedActor"]', 'Low', 'Indirect', 'Unknown', 'Test Victim', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("failed to insert test incident: %v", err)
	}

	// Also insert an incident with valid JSON array of grounded actor
	_, err = sqlStore.db.ExecContext(ctx, `
		INSERT INTO incidents (
			id, title, raw_content, summary_ja, sources_detail, threat_actors, severity, japan_relevance, attack_type, victim_org, first_seen_at, last_seen_at, created_at, updated_at
		) VALUES (
			'inc-grounded-1', 'Incident mentioning Lazarus', 'Content about Lazarus group', 'Summary', '[]', '["Lazarus"]', 'High', 'Direct', 'Ransomware', 'Test Victim', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("failed to insert test incident: %v", err)
	}

	// Run sanitization
	sqlStore.cleanUngroundedIncidentThreatActors()

	// Verify ungrounded actor was removed
	var ungroundedActors string
	err = sqlStore.db.QueryRowContext(ctx, "SELECT threat_actors FROM incidents WHERE id = 'inc-ungrounded-1'").Scan(&ungroundedActors)
	if err != nil {
		t.Fatalf("failed to query cleaned incident: %v", err)
	}
	if ungroundedActors != "[]" {
		t.Errorf("expected empty actors '[]', got: %s", ungroundedActors)
	}

	// Verify grounded actor was preserved
	var groundedActors string
	err = sqlStore.db.QueryRowContext(ctx, "SELECT threat_actors FROM incidents WHERE id = 'inc-grounded-1'").Scan(&groundedActors)
	if err != nil {
		t.Fatalf("failed to query grounded incident: %v", err)
	}
	if !strings.Contains(groundedActors, "Lazarus") {
		t.Errorf("expected Lazarus preserved, got: %s", groundedActors)
	}
}

func TestIncidentsFilterConditions(t *testing.T) {
	store, err := NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	sqlStore := store.(*SQLStore)

	// Test comprehensive HistoryFilter conditions
	filter := HistoryFilter{
		Severity:   string(models.SeverityCritical),
		JapanOnly:  true,
		Search:     "Healthcare",
		SourceType: string(models.SourceTypeVendorRSS),
		Limit:      10,
		Offset:     0,
	}

	incidents, err := sqlStore.GetIncidents(ctx, filter)
	if err != nil {
		t.Fatalf("GetIncidents failed: %v", err)
	}
	if len(incidents) != 0 {
		t.Errorf("expected 0 incidents on empty DB, got %d", len(incidents))
	}

	total, err := sqlStore.GetIncidentsTotal(ctx, filter)
	if err != nil {
		t.Fatalf("GetIncidentsTotal failed: %v", err)
	}
	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}
}

