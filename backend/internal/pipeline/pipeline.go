package pipeline

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/dapt/information_harvester/backend/internal/analyzer"
	"github.com/dapt/information_harvester/backend/internal/config"
	"github.com/dapt/information_harvester/backend/internal/harvesters"
	"github.com/dapt/information_harvester/backend/internal/models"
	"github.com/dapt/information_harvester/backend/internal/notifiers"
	"github.com/dapt/information_harvester/backend/internal/reporters"
	"github.com/dapt/information_harvester/backend/internal/storage"
)

type PipelineSummary struct {
	TotalHarvested   int            `json:"total_harvested"`
	NewItems         int            `json:"new_items"`
	Analyzed         int            `json:"analyzed"`
	Notified         int            `json:"notified"`
	NotionReported   int            `json:"notion_reported"`
	NotionConfigured bool           `json:"notion_configured"`
	SourceBreakdown  map[string]int `json:"source_breakdown"`
}

type Pipeline struct {
	store          storage.Store
	analyzer       *analyzer.GeminiThreatAnalyzer
	notifier       *notifiers.NotificationManager
	notionReporter *reporters.NotionReporter
	harvesterList  []harvesters.Harvester
}

func NewPipeline(store storage.Store) *Pipeline {
	return &Pipeline{
		store:          store,
		analyzer:       analyzer.NewGeminiThreatAnalyzer(),
		notifier:       notifiers.NewNotificationManager(),
		notionReporter: reporters.NewNotionReporter(),
		harvesterList: []harvesters.Harvester{
			harvesters.NewVendorRSSHarvester(),
			harvesters.NewDarkwebOnionHarvester(),
			harvesters.NewTelegramHarvester(),
			harvesters.NewWebSearchHarvester(),
			harvesters.NewXMonitorHarvester(),
		},
	}
}

func (p *Pipeline) RunAll(ctx context.Context, lookbackHours int, notifyDirectOnly bool) (PipelineSummary, error) {
	cfg := config.GetSettings().GetConfig()
	if lookbackHours <= 0 {
		lookbackHours = cfg.Pipeline.CheckIntervalHours
		if lookbackHours < 48 {
			lookbackHours = 48
		}
	}

	since := time.Now().UTC().Add(-time.Duration(lookbackHours)*time.Hour - 15*time.Minute)
	log.Printf("=== Starting threat collection cycle (lookback: %dh, since: %s) ===", lookbackHours, since.Format(time.RFC3339))

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allItems []models.ThreatItem
	sourceCounts := make(map[string]int)

	for _, h := range p.harvesterList {
		wg.Add(1)
		go func(h harvesters.Harvester) {
			defer wg.Done()
			log.Printf("[Pipeline] Starting harvester: %s", h.Name())

			hCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
			defer cancel()

			items, err := h.Harvest(hCtx, &since)
			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				log.Printf("[Pipeline] Harvester %s encountered error: %v", h.Name(), err)
				sourceCounts[string(h.SourceType())] = 0
				return
			}

			sourceCounts[string(h.SourceType())] = len(items)
			allItems = append(allItems, items...)
			log.Printf("[Pipeline] Harvester %s finished: %d items", h.Name(), len(items))
		}(h)
	}

	wg.Wait()

	// In-memory deduplication across all sources in this cycle
	seenIDs := make(map[string]bool)
	seenURLs := make(map[string]bool)
	var uniqueBatch []models.ThreatItem
	for _, item := range allItems {
		if seenIDs[item.ID] {
			continue
		}
		if item.URL != "" && seenURLs[item.URL] {
			continue
		}
		seenIDs[item.ID] = true
		if item.URL != "" {
			seenURLs[item.URL] = true
		}
		uniqueBatch = append(uniqueBatch, item)
	}

	// Persistent store deduplication
	var newItems []models.ThreatItem
	for _, item := range uniqueBatch {
		seen, err := p.store.IsSeenItem(ctx, item)
		if err != nil || !seen {
			newItems = append(newItems, item)
		} else {
			log.Printf("[Pipeline] Skipping seen item: %s (%s)", item.Title, item.URL)
		}
	}

	log.Printf("[Pipeline] Collected total: %d (unique batch: %d), New unique items to analyze: %d", len(allItems), len(uniqueBatch), len(newItems))

	analyzedCount := 0
	notifiedCount := 0
	notionReportedCount := 0

	for _, item := range newItems {
		enriched, err := p.analyzer.Analyze(ctx, item)
		if err != nil || enriched == nil {
			log.Printf("[Pipeline] Error analyzing '%s': %v", item.Title, err)
			continue
		}
		analyzedCount++

		shouldNotify := false
		// High-value alerting criteria:
		// 1. Direct relevance to Japan with Critical or High severity
		// 2. If notifyDirectOnly is false: Indirect relevance with Critical severity (global severe supply chain impact)
		if enriched.JapanRelevance == models.JapanRelevanceDirect &&
			(enriched.Severity == models.SeverityCritical || enriched.Severity == models.SeverityHigh) {
			shouldNotify = true
		} else if !notifyDirectOnly && enriched.JapanRelevance == models.JapanRelevanceIndirect &&
			enriched.Severity == models.SeverityCritical {
			shouldNotify = true
		}

		// Suppress notifications for older historical incidents (> 7 days old)
		if shouldNotify && item.PublishedAt != nil && time.Since(*item.PublishedAt) > 7*24*time.Hour {
			log.Printf("[Pipeline] Suppressing notification for older incident (published %s): %s",
				item.PublishedAt.Format("2006-01-02"), enriched.TitleJa)
			shouldNotify = false
		}

		// Suppress duplicate alerts for same victim organization or CVE within 48 hours
		if shouldNotify {
			isRecent, err := p.store.IsRecentlyNotified(ctx, enriched.VictimOrgs, enriched.TitleJa, 48)
			if err == nil && isRecent {
				log.Printf("[Pipeline] Suppressing alert due to 48h cooldown for victim/CVE: %s", enriched.TitleJa)
				shouldNotify = false
			}
		}

		notified := false
		if shouldNotify {
			log.Printf("[Pipeline] Alerting on threat: [%s] [%s] %s", enriched.Severity, enriched.JapanRelevance, enriched.TitleJa)
			notified = p.notifier.Dispatch(ctx, enriched)
			if notified {
				notifiedCount++
			}

			if p.notionReporter.IsConfigured() {
				if _, err := p.notionReporter.CreateIncidentPage(ctx, enriched); err == nil {
					notionReportedCount++
				}
			}
		}

		if err := p.store.MarkSeen(ctx, item, enriched, notified); err != nil {
			log.Printf("[Pipeline] Failed to mark seen in store: %v", err)
		}
	}

	summary := PipelineSummary{
		TotalHarvested:   len(allItems),
		NewItems:         len(newItems),
		Analyzed:         analyzedCount,
		Notified:         notifiedCount,
		NotionReported:   notionReportedCount,
		NotionConfigured: p.notionReporter.IsConfigured(),
		SourceBreakdown:  sourceCounts,
	}

	log.Printf("=== Harvesting cycle complete: %+v ===", summary)
	return summary, nil
}
