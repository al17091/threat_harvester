package scraper

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/al17091/threat_harvester/api/internal/analyzer"
	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/harvesters"
	"github.com/al17091/threat_harvester/api/internal/models"
	"github.com/al17091/threat_harvester/api/internal/storage"
)

type ScraperManager struct {
	store    storage.Store
	analyzer analyzer.ThreatAnalyzer
	cfg      config.ScraperConfig
	netCfg   config.NetworkConfig
	stopChan chan struct{}
	mu       sync.Mutex
	running  bool
}

func NewScraperManager(store storage.Store, analyzer analyzer.ThreatAnalyzer, cfg config.ScraperConfig, netCfg config.NetworkConfig) *ScraperManager {
	if cfg.ClearnetConcurrency <= 0 {
		cfg.ClearnetConcurrency = 5
	}
	if cfg.TorConcurrency <= 0 {
		cfg.TorConcurrency = 2
	}
	if cfg.ClearnetTimeoutSeconds <= 0 {
		cfg.ClearnetTimeoutSeconds = 15
	}
	if cfg.TorTimeoutSeconds <= 0 {
		cfg.TorTimeoutSeconds = 45
	}
	if cfg.WorkerIntervalSeconds <= 0 {
		cfg.WorkerIntervalSeconds = 10
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 20
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 2
	}

	return &ScraperManager{
		store:    store,
		analyzer: analyzer,
		cfg:      cfg,
		netCfg:   netCfg,
		stopChan: make(chan struct{}),
	}
}

func (m *ScraperManager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.mu.Unlock()

	if !m.cfg.Enabled {
		log.Println("[ScraperManager] Scraper is disabled in configuration.")
		return
	}

	log.Printf("[ScraperManager] Starting Async Content Scraper (Clearnet Concurrency: %d, Tor Concurrency: %d, Interval: %ds)",
		m.cfg.ClearnetConcurrency, m.cfg.TorConcurrency, m.cfg.WorkerIntervalSeconds)

	go m.runLoop(ctx)
}

func (m *ScraperManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.running {
		return
	}
	m.running = false
	close(m.stopChan)
	log.Println("[ScraperManager] ScraperManager stopped.")
}

func (m *ScraperManager) runLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(m.cfg.WorkerIntervalSeconds) * time.Second)
	defer ticker.Stop()

	// Initial immediate poll
	m.processPendingQueues(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.processPendingQueues(ctx)
		}
	}
}

func (m *ScraperManager) processPendingQueues(ctx context.Context) {
	var wg sync.WaitGroup

	if m.cfg.ClearnetEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.processClearnetQueue(ctx)
		}()
	}

	if m.cfg.TorEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.processTorQueue(ctx)
		}()
	}

	wg.Wait()
}

func (m *ScraperManager) processClearnetQueue(ctx context.Context) {
	items, err := m.store.GetPendingFetchItems(ctx, m.cfg.BatchSize, m.cfg.MaxAttempts, false)
	if err != nil || len(items) == 0 {
		return
	}

	log.Printf("[ScraperManager] Processing %d pending Clearnet items...", len(items))

	sem := make(chan struct{}, m.cfg.ClearnetConcurrency)
	var wg sync.WaitGroup

	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}

		go func(item models.ThreatItem) {
			defer wg.Done()
			defer func() { <-sem }()

			fetchCtx, cancel := context.WithTimeout(ctx, time.Duration(m.cfg.ClearnetTimeoutSeconds)*time.Second)
			defer cancel()

			content, fetchErr := harvesters.FetchArticleContentWithTimeout(fetchCtx, item.URL, m.cfg.ClearnetTimeoutSeconds)
			if fetchErr != nil {
				log.Printf("[ScraperManager] Clearnet fetch failed for %s (%s): %v", item.Title, item.URL, fetchErr)
				_ = m.store.UpdateFetchStatus(ctx, item.ID, "failed", item.FetchAttempts+1, fetchErr.Error(), "")
				return
			}

			if strings.TrimSpace(content) == "" {
				_ = m.store.UpdateFetchStatus(ctx, item.ID, "completed", item.FetchAttempts+1, "empty content extracted", "")
				return
			}

			// Save scraped raw content
			_ = m.store.UpdateFetchStatus(ctx, item.ID, "completed", item.FetchAttempts+1, "", content)
			log.Printf("[ScraperManager] Successfully scraped Clearnet article for %s (%d runes)", item.Title, len([]rune(content)))

			m.postProcessEnrichment(ctx, item, content)
		}(it)
	}

	wg.Wait()
}

func (m *ScraperManager) processTorQueue(ctx context.Context) {
	items, err := m.store.GetPendingFetchItems(ctx, m.cfg.BatchSize, m.cfg.MaxAttempts, true)
	if err != nil || len(items) == 0 {
		return
	}

	log.Printf("[ScraperManager] Processing %d pending Tor/.onion items...", len(items))

	sem := make(chan struct{}, m.cfg.TorConcurrency)
	var wg sync.WaitGroup

	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}

		go func(item models.ThreatItem) {
			defer wg.Done()
			defer func() { <-sem }()

			fetchCtx, cancel := context.WithTimeout(ctx, time.Duration(m.cfg.TorTimeoutSeconds)*time.Second)
			defer cancel()

			content, fetchErr := harvesters.FetchOnionArticleContent(fetchCtx, item.URL, m.netCfg.TorProxyURL, m.cfg.TorTimeoutSeconds)
			if fetchErr != nil {
				log.Printf("[ScraperManager] Tor fetch failed for %s (%s): %v", item.Title, item.URL, fetchErr)
				_ = m.store.UpdateFetchStatus(ctx, item.ID, "failed", item.FetchAttempts+1, fetchErr.Error(), "")
				return
			}

			if strings.TrimSpace(content) == "" {
				_ = m.store.UpdateFetchStatus(ctx, item.ID, "completed", item.FetchAttempts+1, "empty content extracted", "")
				return
			}

			// Save scraped raw content
			_ = m.store.UpdateFetchStatus(ctx, item.ID, "completed", item.FetchAttempts+1, "", content)
			log.Printf("[ScraperManager] Successfully scraped Tor .onion article for %s (%d runes)", item.Title, len([]rune(content)))

			m.postProcessEnrichment(ctx, item, content)
		}(it)
	}

	wg.Wait()
}

func (m *ScraperManager) postProcessEnrichment(ctx context.Context, item models.ThreatItem, content string) {
	item.RawContent = content

	// Optional AI re-analysis on deep fetched article
	if m.cfg.AutoReAnalyze && m.analyzer != nil {
		reCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()

		enriched, err := m.analyzer.Analyze(reCtx, item)
		if err == nil && enriched != nil {
			log.Printf("[ScraperManager] Auto re-analyzed item %s with full content. Severity: %s", item.Title, enriched.Severity)
			// Re-cluster or update parent incident with enriched intelligence
			_, _ = m.store.FindOrCreateIncident(ctx, item, enriched, 30)
		}
	}
}
