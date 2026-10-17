package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/backend/internal/analyzer"
	"github.com/al17091/threat_harvester/backend/internal/config"
	"github.com/al17091/threat_harvester/backend/internal/harvesters"
	"github.com/al17091/threat_harvester/backend/internal/models"
	"github.com/al17091/threat_harvester/backend/internal/storage"
)

// mockHarvester implements harvesters.Harvester for pipeline testing.
type mockHarvester struct {
	name       string
	sourceType models.SourceType
	items      []models.ThreatItem
	err        error
}

func (m *mockHarvester) Name() string {
	return m.name
}

func (m *mockHarvester) SourceType() models.SourceType {
	return m.sourceType
}

func (m *mockHarvester) Harvest(ctx context.Context, since *time.Time) ([]models.ThreatItem, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.items, nil
}

func (m *mockHarvester) TestConnection(ctx context.Context) bool {
	return m.err == nil
}

// mockAnalyzer implements analyzer.ThreatAnalyzer for pipeline testing.
type mockAnalyzer struct {
	analyzer.ThreatAnalyzer
	enriched []*models.EnrichedThreat
	err      error
}

func (m *mockAnalyzer) Analyze(ctx context.Context, item models.ThreatItem) (*models.EnrichedThreat, error) {
	if m.err != nil {
		return nil, m.err
	}
	if len(m.enriched) > 0 {
		return m.enriched[0], nil
	}
	return nil, nil
}

func (m *mockAnalyzer) AnalyzeBatch(ctx context.Context, items []models.ThreatItem) ([]*models.EnrichedThreat, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.enriched, nil
}

func (m *mockAnalyzer) GenerateSearchQueries(ctx context.Context, directive string, targetType string, count int) ([]string, error) {
	return []string{"query1", "query2"}, nil
}

func (m *mockAnalyzer) TranslateIncidentFields(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	return title, summary, impact, actions, nil
}

func (m *mockAnalyzer) TranslateFieldsToJapanese(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	return title, summary, impact, actions, nil
}

func (m *mockAnalyzer) LocalizeThreatToJapanese(ctx context.Context, enriched *models.EnrichedThreat) error {
	return nil
}

func (m *mockAnalyzer) TranslateIncident(ctx context.Context, input analyzer.IncidentTranslationInput) (*analyzer.IncidentTranslationOutput, error) {
	return &analyzer.IncidentTranslationOutput{Title: input.Title, Summary: input.Summary}, nil
}

func (m *mockAnalyzer) TranslateBatch(ctx context.Context, items []analyzer.BatchTranslateItem) ([]analyzer.BatchTranslateResult, error) {
	return nil, nil
}

func TestPipeline(t *testing.T) {
	ctx := context.Background()

	store, err := storage.NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory store: %v", err)
	}
	defer store.Close()

	p := NewPipeline(store)
	if p == nil || p.Analyzer() == nil {
		t.Fatalf("Expected pipeline and analyzer to be initialized")
	}

	// Disable external notification sinks
	cfg := config.GetSettings().GetConfig()
	cfg.Sinks.Discord.Enabled = false
	cfg.Sinks.Discord.WebhookURL = ""
	cfg.Sinks.Slack.Enabled = false
	cfg.Sinks.Slack.WebhookURL = ""
	cfg.Sinks.GenericWebhook.Enabled = false
	cfg.Sinks.GenericWebhook.WebhookURL = ""
	cfg.Sinks.Notion.Enabled = false
	cfg.Sinks.Notion.APIKey = ""
	config.GetSettings().SetConfig(cfg)

	now := time.Now().UTC()
	oldDate := now.Add(-10 * 24 * time.Hour) // > 7 days old

	items1 := []models.ThreatItem{
		{
			ID:          "item-1",
			SourceType:  models.SourceTypeVendorRSS,
			SourceName:  "JPCERT",
			Title:       "Critical Japan Breach",
			URL:         "https://example.com/item-1",
			Summary:     "Critical targeted attack against Japanese corp",
			PublishedAt: &now,
			HarvestedAt: now,
		},
		{
			ID:          "item-1-dup", // Duplicate URL
			SourceType:  models.SourceTypeVendorRSS,
			SourceName:  "JPCERT",
			Title:       "Critical Japan Breach Duplicate URL",
			URL:         "https://example.com/item-1",
			Summary:     "Duplicate URL item",
			PublishedAt: &now,
			HarvestedAt: now,
		},
		{
			ID:          "item-old", // Old item, > 7 days
			SourceType:  models.SourceTypeVendorRSS,
			SourceName:  "JPCERT",
			Title:       "Older Critical Threat",
			URL:         "https://example.com/item-old",
			Summary:     "Old breach",
			PublishedAt: &oldDate,
			HarvestedAt: now,
		},
	}

	items2 := []models.ThreatItem{
		{
			ID:          "item-global",
			SourceType:  models.SourceTypeDarkwebOnion,
			SourceName:  "Tor Search",
			Title:       "Global Critical Threat",
			URL:         "https://example.com/item-global",
			Summary:     "Global ransomware campaign",
			PublishedAt: &now,
			HarvestedAt: now,
		},
	}

	p.harvesterList = []harvesters.Harvester{
		&mockHarvester{name: "Mock RSS", sourceType: models.SourceTypeVendorRSS, items: items1},
		&mockHarvester{name: "Mock Tor", sourceType: models.SourceTypeDarkwebOnion, items: items2},
		&mockHarvester{name: "Failing Harvester", sourceType: models.SourceTypeTelegram, err: errors.New("timeout connecting")},
	}

	enrichedList := []*models.EnrichedThreat{
		{
			ItemID:         "item-1",
			Item:           items1[0],
			Title:          "Critical Japan Breach",
			TitleJa:        "国内企業を標的とした重大侵害",
			SummaryJa:      "重大侵害が検知されました",
			Severity:       models.SeverityCritical,
			JapanRelevance: models.JapanRelevanceDirect,
			VictimOrgs:     []string{"Japan MegaCorp"},
			ThreatActors:   []string{"APT100"},
		},
		{
			ItemID:         "item-old",
			Item:           items1[2],
			Title:          "Older Critical Threat",
			TitleJa:        "過去の重大脅威",
			SummaryJa:      "過去のインシデント",
			Severity:       models.SeverityCritical,
			JapanRelevance: models.JapanRelevanceDirect,
			VictimOrgs:     []string{"Historic Victim"},
		},
		{
			ItemID:         "item-global",
			Item:           items2[0],
			Title:          "Global Critical Threat",
			TitleJa:        "世界的な重大脅威",
			SummaryJa:      "グローバルな攻撃",
			Severity:       models.SeverityCritical,
			JapanRelevance: models.JapanRelevanceIndirect,
			VictimOrgs:     []string{"Global Victim"},
		},
	}

	p.analyzer = &mockAnalyzer{enriched: enrichedList}

	// First cycle: RunAll
	summary, err := p.RunAll(ctx, 24, false)
	if err != nil {
		t.Fatalf("RunAll failed: %v", err)
	}

	if summary.TotalHarvested != 4 {
		t.Errorf("Expected 4 total harvested, got %d", summary.TotalHarvested)
	}
	// unique batch: item-1, item-old, item-global = 3 items (item-1-dup eliminated)
	if summary.NewItems != 3 {
		t.Errorf("Expected 3 new unique items, got %d", summary.NewItems)
	}
	if summary.Analyzed != 3 {
		t.Errorf("Expected 3 analyzed, got %d", summary.Analyzed)
	}
	// Notified count:
	// item-1 (Direct, Critical) -> notified
	// item-old (Direct, Critical, but > 7 days old) -> suppressed
	// item-global (Indirect, Critical, notifyDirectOnly=false) -> notified
	if summary.Notified != 2 {
		t.Errorf("Expected 2 notified, got %d", summary.Notified)
	}

	// Second cycle: RunAll should deduplicate existing items in store
	summary2, err := p.RunAll(ctx, 0, true) // lookbackHours <= 0 defaults to cfg
	if err != nil {
		t.Fatalf("Second RunAll failed: %v", err)
	}
	if summary2.NewItems != 0 {
		t.Errorf("Expected 0 new items on repeat run, got %d", summary2.NewItems)
	}
}
