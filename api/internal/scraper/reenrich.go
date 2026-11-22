package scraper

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/al17091/threat_harvester/api/internal/harvesters"
	"github.com/al17091/threat_harvester/api/internal/models"
)

// ReEnrichSummary holds telemetry about the bulk re-enrichment operation.
type ReEnrichSummary struct {
	WindowDays       int `json:"window_days"`
	TotalCandidates  int `json:"total_candidates"`
	Processed        int `json:"processed"`
	ScrapedSuccess   int `json:"scraped_success"`
	ScrapedFailed    int `json:"scraped_failed"`
	ContentEnriched  int `json:"content_enriched"`
	IncidentsUpdated int `json:"incidents_updated"`
}

// ReEnrich iterates over past threat items in the specified window, re-scrapes their
// full articles with modern browser headers / encoding handling, and re-analyzes them
// with the configured AI model to refresh threat incidents.
func (m *ScraperManager) ReEnrich(ctx context.Context, windowDays int, limit int, forceAll bool) (*ReEnrichSummary, error) {
	if windowDays <= 0 {
		windowDays = 7
	}

	items, err := m.store.GetItemsForReEnrich(ctx, windowDays, limit, forceAll)
	if err != nil {
		return nil, fmt.Errorf("failed to query items for re-enrichment: %w", err)
	}

	summary := &ReEnrichSummary{
		WindowDays:      windowDays,
		TotalCandidates: len(items),
	}

	if len(items) == 0 {
		log.Printf("[ReEnrich] No candidate threat items found in past %d days.", windowDays)
		return summary, nil
	}

	concurrency := m.cfg.ClearnetConcurrency
	if concurrency <= 0 {
		concurrency = 5
	}
	timeoutSec := m.cfg.ClearnetTimeoutSeconds
	if timeoutSec <= 0 {
		timeoutSec = 15
	}

	log.Printf("[ReEnrich] Starting re-enrichment of %d items (past %d days, concurrency: %d, timeout: %ds, force: %t)...",
		len(items), windowDays, concurrency, timeoutSec, forceAll)

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	var (
		processedCount        int64
		scrapedSuccessCount   int64
		scrapedFailedCount    int64
		contentEnrichedCount  int64
		incidentsUpdatedCount int64
	)

	for idx, it := range items {
		select {
		case <-ctx.Done():
			log.Println("[ReEnrich] Context cancelled, aborting remaining items.")
			break
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(itemNum int, item models.ThreatItem) {
			defer wg.Done()
			defer func() { <-sem }()

			atomic.AddInt64(&processedCount, 1)

			fetchCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
			defer cancel()

			content, pubDate, fetchErr := harvesters.FetchArticleDetailsWithTimeout(fetchCtx, item.URL, timeoutSec)
			if fetchErr != nil {
				atomic.AddInt64(&scrapedFailedCount, 1)
				_ = m.store.UpdateFetchStatus(ctx, item.ID, "failed", item.FetchAttempts+1, fetchErr.Error(), "")
				log.Printf("[ReEnrich] [%d/%d] Fetch failed for %s (%s): %v", itemNum+1, len(items), item.Title, item.URL, fetchErr)
				return
			}

			trimmed := strings.TrimSpace(content)
			if trimmed == "" {
				atomic.AddInt64(&scrapedFailedCount, 1)
				_ = m.store.UpdateFetchStatus(ctx, item.ID, "completed", item.FetchAttempts+1, "empty content extracted", "")
				return
			}

			if pubDate != nil && (item.PublishedAt == nil || item.PublishedAt.IsZero()) {
				item.PublishedAt = pubDate
				_ = m.store.UpdateItemPublishedAt(ctx, item.ID, *pubDate)
			}

			atomic.AddInt64(&scrapedSuccessCount, 1)
			prevRunes := len([]rune(item.RawContent))
			newRunes := len([]rune(trimmed))

			if newRunes > prevRunes {
				atomic.AddInt64(&contentEnrichedCount, 1)
			}

			if err := m.store.UpdateFetchStatus(ctx, item.ID, "completed", item.FetchAttempts+1, "", trimmed); err != nil {
				log.Printf("[ReEnrich] Failed to update completed fetch status for %s: %v", item.ID, err)
			}

			log.Printf("[ReEnrich] [%d/%d] Successfully scraped article for %s (%d runes, prev: %d runes)",
				itemNum+1, len(items), item.Title, newRunes, prevRunes)

			// Drop / skip AI re-analysis if article is old (>30 days) or historical retrospective
			if item.PublishedAt != nil && time.Since(*item.PublishedAt) > 30*24*time.Hour {
				log.Printf("[ReEnrich] [%d/%d] Skipping AI re-analysis for old article (%s): %s",
					itemNum+1, len(items), item.PublishedAt.Format("2006-01-02"), item.Title)
				return
			}
			if models.IsHistoricalOrRetrospectiveNotice(item.Title, item.Summary, trimmed) {
				log.Printf("[ReEnrich] [%d/%d] Skipping AI re-analysis for historical retrospective: %s",
					itemNum+1, len(items), item.Title)
				return
			}

			// Re-analyze with AI if enabled
			if m.cfg.AutoReAnalyze && m.analyzer != nil {
				reCtx, reCancel := context.WithTimeout(ctx, 600*time.Second)
				defer reCancel()

				item.RawContent = trimmed
				enriched, aErr := m.analyzer.Analyze(reCtx, item)
				if aErr != nil {
					log.Printf("[ReEnrich] [%d/%d] AI re-analysis failed for %s: %v", itemNum+1, len(items), item.Title, aErr)
				} else if enriched != nil {
					models.NormalizeEnrichedThreat(item, enriched)
					if inc, incErr := m.store.FindOrCreateIncident(ctx, item, enriched, 30); incErr != nil {
						log.Printf("[ReEnrich] [%d/%d] FindOrCreateIncident failed for %s: %v", itemNum+1, len(items), item.Title, incErr)
					} else {
						atomic.AddInt64(&incidentsUpdatedCount, 1)
						incIDStr := ""
						if inc != nil {
							incIDStr = inc.ID
						}
						log.Printf("[ReEnrich] [%d/%d] Re-analyzed incident %s for %s (Severity: %s, Japan: %s)",
							itemNum+1, len(items), incIDStr, item.Title, enriched.Severity, enriched.JapanRelevance)
					}
				}
			}
		}(idx, it)
	}

	wg.Wait()

	summary.Processed = int(processedCount)
	summary.ScrapedSuccess = int(scrapedSuccessCount)
	summary.ScrapedFailed = int(scrapedFailedCount)
	summary.ContentEnriched = int(contentEnrichedCount)
	summary.IncidentsUpdated = int(incidentsUpdatedCount)

	log.Printf("[ReEnrich] Completed: Processed=%d, Success=%d, Failed=%d, Enriched=%d, IncidentsUpdated=%d",
		summary.Processed, summary.ScrapedSuccess, summary.ScrapedFailed, summary.ContentEnriched, summary.IncidentsUpdated)

	return summary, nil
}
