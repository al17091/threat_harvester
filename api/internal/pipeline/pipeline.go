package pipeline

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/al17091/threat_harvester/api/internal/analyzer"
	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/harvesters"
	"github.com/al17091/threat_harvester/api/internal/models"
	"github.com/al17091/threat_harvester/api/internal/notifiers"
	"github.com/al17091/threat_harvester/api/internal/reporters"
	"github.com/al17091/threat_harvester/api/internal/storage"
)

type StageName string

const (
	StageIdle        StageName = "idle"
	StageHarvesting  StageName = "harvesting"
	StageFiltering   StageName = "filtering"
	StageAnalyzing   StageName = "analyzing"
	StageClustering  StageName = "clustering"
	StageAlerting    StageName = "alerting"
	StageTranslating StageName = "translating"
	StageCompleted   StageName = "completed"
)

type StageProgress struct {
	CurrentStage StageName `json:"current_stage"`
	StageTitle   string    `json:"stage_title"`
	StageTitleJa string    `json:"stage_title_ja"`
	CurrentItem  int       `json:"current_item"`
	TotalItems   int       `json:"total_items"`
	Message      string    `json:"message"`
	StartedAt    string    `json:"started_at,omitempty"`
}

type StageCallback func(progress StageProgress)

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
	analyzer       analyzer.ThreatAnalyzer
	notifier       *notifiers.NotificationManager
	notionReporter *reporters.NotionReporter
	harvesterList  []harvesters.Harvester
	stageMu        sync.RWMutex
	currentStage   StageProgress
	stageCallback  StageCallback
}

func stageTitles(stage StageName) (string, string) {
	switch stage {
	case StageHarvesting:
		return "Threat Ingestion & Harvesting", "脅威情報収集"
	case StageFiltering:
		return "Deduplication & Pre-Filter", "重複排除・事前フィルタ"
	case StageAnalyzing:
		return "AI Threat Analysis & Triage", "AI脅威分析・トリアージ"
	case StageClustering:
		return "STIX 2.1 Incident Clustering", "インシデント統合・クラスタリング"
	case StageAlerting:
		return "Alerts & Knowledge Base Sync", "アラート通知・ナレッジ連携"
	case StageTranslating:
		return "Bilingual Sync & Translation", "日英翻訳・多言語同期"
	case StageCompleted:
		return "Harvest Cycle Completed", "収集サイクル完了"
	default:
		return "Idle", "待機中"
	}
}

func (p *Pipeline) SetStageCallback(cb StageCallback) {
	p.stageMu.Lock()
	defer p.stageMu.Unlock()
	p.stageCallback = cb
}

func (p *Pipeline) GetStageProgress() StageProgress {
	p.stageMu.RLock()
	defer p.stageMu.RUnlock()
	if p.currentStage.CurrentStage == "" {
		return StageProgress{
			CurrentStage: StageIdle,
			StageTitle:   "Idle",
			StageTitleJa: "待機中",
			Message:      "パイプライン待機中",
		}
	}
	return p.currentStage
}

func (p *Pipeline) updateStage(stage StageName, current, total int, msg string) {
	titleEn, titleJa := stageTitles(stage)
	p.stageMu.Lock()
	p.currentStage = StageProgress{
		CurrentStage: stage,
		StageTitle:   titleEn,
		StageTitleJa: titleJa,
		CurrentItem:  current,
		TotalItems:   total,
		Message:      msg,
		StartedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	cb := p.stageCallback
	prog := p.currentStage
	p.stageMu.Unlock()

	if cb != nil {
		cb(prog)
	}
}

func NewPipeline(store storage.Store) *Pipeline {
	return &Pipeline{
		store:          store,
		analyzer:       analyzer.NewDefaultThreatAnalyzer(),
		notifier:       notifiers.NewNotificationManager(),
		notionReporter: reporters.NewNotionReporter(),
		harvesterList: []harvesters.Harvester{
			harvesters.NewVendorRSSHarvester(),
			harvesters.NewDarkwebOnionHarvester(),
			harvesters.NewRansomwareTrackerHarvester(),
			harvesters.NewTelegramHarvester(),
			harvesters.NewWebSearchHarvester(),
			harvesters.NewXMonitorHarvester(),
		},
	}
}

func (p *Pipeline) Analyzer() analyzer.ThreatAnalyzer {
	return p.analyzer
}

func (p *Pipeline) SetAnalyzer(a analyzer.ThreatAnalyzer) {
	p.analyzer = a
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
	p.updateStage(StageHarvesting, 0, len(p.harvesterList), "情報ソース (RSS, Tor, Telegram, Web Search, X) から脅威データを収集中...")

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allItems []models.ThreatItem
	sourceCounts := make(map[string]int)

	for _, h := range p.harvesterList {
		wg.Add(1)
		go func(h harvesters.Harvester) {
			defer wg.Done()
			log.Printf("[Pipeline] Starting harvester: %s", h.Name())

			// Allow up to 8 minutes to accommodate high-latency operations (Tor onion routing and live Gemini Grounding)
			hCtx, cancel := context.WithTimeout(ctx, 8*time.Minute)
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

	p.updateStage(StageFiltering, 0, len(allItems), "収集データの重複排除・事前フィルタリングを実行中...")
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

	// Persistent store deduplication & corporate PR notice filtering
	var newItems []models.ThreatItem
	for _, item := range uniqueBatch {
		if models.IsCorporatePRNotice(item.Title, item.Summary, item.RawContent) {
			log.Printf("[Pipeline] Discarding corporate PR notice: %s (%s)", item.Title, item.URL)
			_ = p.store.MarkSeen(ctx, item, &models.EnrichedThreat{
				Severity:       models.SeverityInfo,
				JapanRelevance: models.JapanRelevanceNone,
				TitleJa:        item.Title,
				SummaryJa:      item.Summary,
			}, false)
			continue
		}
		seen, err := p.store.IsSeenItem(ctx, item)
		if err != nil || !seen {
			newItems = append(newItems, item)
		} else {
			log.Printf("[Pipeline] Skipping seen item: %s (%s)", item.Title, item.URL)
		}
	}

	log.Printf("[Pipeline] Collected total: %d (unique batch: %d), New unique items to analyze: %d", len(allItems), len(uniqueBatch), len(newItems))
	p.updateStage(StageAnalyzing, 0, len(newItems), fmt.Sprintf("新着 %d 件の脅威データを汎用LLMで分析開始...", len(newItems)))

	analyzedCount := 0
	notifiedCount := 0
	notionReportedCount := 0
	circuitBreakerTriggered := false

	batchSize := 5
	for i := 0; i < len(newItems); i += batchSize {
		end := i + batchSize
		if end > len(newItems) {
			end = len(newItems)
		}
		chunk := newItems[i:end]
		log.Printf("[Pipeline] [%d-%d/%d] Analyzing threat batch (%d items)...",
			i+1, end, len(newItems), len(chunk))
		p.updateStage(StageAnalyzing, i+1, len(newItems), fmt.Sprintf("汎用LLMによる脅威分析 (%d-%d/%d)...", i+1, end, len(newItems)))

		enrichedBatch, err := p.analyzer.AnalyzeBatch(ctx, chunk)
		if err != nil {
			log.Printf("[Pipeline] Error during batch analysis: %v", err)
		}

		for itemIdx, item := range chunk {
			var enriched *models.EnrichedThreat
			if itemIdx < len(enrichedBatch) && enrichedBatch[itemIdx] != nil {
				enriched = enrichedBatch[itemIdx]
			}
			if enriched == nil {
				log.Printf("[Pipeline] Missing enrichment for item: %s. Generating baseline enrichment.", item.Title)
				enriched = analyzer.CreateBaselineEnrichedThreat(item)
			}

			if models.IsCorporatePRNotice(item.Title, item.Summary, item.RawContent, enriched.Title, enriched.TitleJa, enriched.SummaryJa, enriched.ImpactAnalysisJa) {
				log.Printf("[Pipeline] Discarding analyzed corporate PR notice: %s", item.Title)
				enriched.Severity = models.SeverityInfo
				_ = p.store.MarkSeen(ctx, item, enriched, false)
				continue
			}

			prevSev := enriched.Severity
			models.NormalizeEnrichedThreat(item, enriched)
			if prevSev != enriched.Severity {
				log.Printf("[Pipeline] Normalized severity from %s to %s (Japan=%s): %s", prevSev, enriched.Severity, enriched.JapanRelevance, item.Title)
			}

			analyzedCount++
			log.Printf("[Pipeline] [%d/%d] Analysis result: Severity=%s | Japan=%s | Actor=%v",
				i+itemIdx+1, len(newItems), enriched.Severity, enriched.JapanRelevance, enriched.ThreatActors)

			// Cluster into STIX 2.1 parent incident (30-day dynamic sliding window) BEFORE notification evaluation.
			// This attaches the item to its canonical parent incident, enabling parent-level duplicate suppression.
			incident, err := p.store.FindOrCreateIncident(ctx, item, enriched, 30)
			if err != nil {
				log.Printf("[Pipeline] Error clustering incident for item %s: %v", item.Title, err)
			} else if incident != nil {
				item.IncidentID = incident.ID
				log.Printf("[Pipeline] Clustered item into parent incident: %s (Total reports: %d, Victim: %s)",
					incident.ID, incident.ReportCount, incident.VictimOrg)
			} else {
				item.IncidentID = ""
			}

			cfg := config.GetSettings().GetConfig()
			notifyLang := cfg.Pipeline.NotifyLanguage
			circuitBreakerMax := cfg.Pipeline.CircuitBreakerMaxAlerts
			if circuitBreakerMax <= 0 {
				circuitBreakerMax = 5
			}

			shouldNotify := false
			// High-value alerting criteria based on notification scope:
			if enriched.Severity != models.SeverityInfo {
				if notifyLang == "ja" {
					// Japanese side only: Direct (Critical/High), or Indirect (Critical) if not notifyDirectOnly
					if enriched.JapanRelevance == models.JapanRelevanceDirect &&
						(enriched.Severity == models.SeverityCritical || enriched.Severity == models.SeverityHigh) {
						shouldNotify = true
					} else if !notifyDirectOnly && enriched.JapanRelevance == models.JapanRelevanceIndirect &&
						enriched.Severity == models.SeverityCritical {
						shouldNotify = true
					}
				} else {
					// Default / English side: Global / English alerts
					if enriched.Severity == models.SeverityCritical || enriched.Severity == models.SeverityHigh {
						if notifyDirectOnly {
							shouldNotify = (enriched.JapanRelevance == models.JapanRelevanceDirect)
						} else {
							shouldNotify = true
						}
					}
				}
			}

			// Suppress notifications for older historical incidents (> 7 days old)
			if shouldNotify {
				if item.PublishedAt != nil && time.Since(*item.PublishedAt) > 7*24*time.Hour {
					log.Printf("[Pipeline] Suppressing notification for older incident (published %s): %s",
						item.PublishedAt.Format("2006-01-02"), enriched.TitleJa)
					shouldNotify = false
				} else if item.PublishedAt == nil && !item.HarvestedAt.IsZero() && time.Since(item.HarvestedAt) > 7*24*time.Hour {
					log.Printf("[Pipeline] Suppressing notification for older incident (harvested %s): %s",
						item.HarvestedAt.Format("2006-01-02"), enriched.TitleJa)
					shouldNotify = false
				}
			}

			// Suppress duplicate alerts if parent incident was already notified within 48h (unless severity elevated to Critical)
			if shouldNotify && incident != nil && incident.ReportCount > 1 {
				isIncNotified, err := p.store.IsIncidentRecentlyNotified(ctx, incident.ID, 48)
				if err == nil && isIncNotified {
					if enriched.Severity != models.SeverityCritical {
						log.Printf("[Pipeline] Suppressing alert: parent incident %s already notified within 48h: %s", incident.ID, enriched.TitleJa)
						shouldNotify = false
					}
				}
			}

			// Suppress duplicate alerts for same victim organization or CVE within 48 hours
			if shouldNotify {
				isRecent, err := p.store.IsRecentlyNotified(ctx, enriched.VictimOrgs, enriched.TitleJa, enriched.CVEs, 48)
				if err == nil && isRecent {
					log.Printf("[Pipeline] Suppressing alert due to 48h cooldown for victim/CVE: %s", enriched.TitleJa)
					shouldNotify = false
				}
			}

			notified := false
			if shouldNotify {
				if notifiedCount >= circuitBreakerMax {
					if !circuitBreakerTriggered {
						circuitBreakerTriggered = true
						log.Printf("[Pipeline Circuit Breaker] Notification threshold reached (%d). Suppressing further individual alerts and dispatching summary alert.", circuitBreakerMax)
						if !cfg.Pipeline.NotifyDryRun {
							p.notifier.DispatchSummary(ctx, notifiedCount+1, circuitBreakerMax)
						}
					} else {
						log.Printf("[Pipeline Circuit Breaker] Suppressed individual alert (over threshold %d): [%s] %s", circuitBreakerMax, enriched.Severity, enriched.TitleJa)
					}
				} else {
					displayTitle := enriched.Title
					if notifyLang == "ja" || displayTitle == "" {
						displayTitle = enriched.TitleJa
					}
					log.Printf("[Pipeline] Alerting on threat (lang=%s): [%s] [%s] %s", notifyLang, enriched.Severity, enriched.JapanRelevance, displayTitle)
					if cfg.Pipeline.NotifyDryRun {
						log.Printf("[Pipeline Dry-Run (Config)] Alert would be sent: [%s] %s", enriched.Severity, displayTitle)
						notified = true
						notifiedCount++
					} else {
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
				}
			}

			if err := p.store.MarkSeen(ctx, item, enriched, notified); err != nil {
				log.Printf("[Pipeline] Failed to mark seen in store: %v", err)
			}
		}
	}

	// Translate any Japanese incidents into English (runs every pipeline cycle to ensure zero untranslated backlog)
	if p.analyzer != nil {
		needingTrans, err := p.store.GetIncidentsNeedingTranslation(ctx, 50)
		if err == nil && len(needingTrans) > 0 {
			log.Printf("[Pipeline] Translating %d incidents into English...", len(needingTrans))
			p.updateStage(StageTranslating, 0, len(needingTrans), fmt.Sprintf("日本語特化モデルによる英語翻訳処理中 (%d件)...", len(needingTrans)))
			var transItems []analyzer.BatchTranslateItem
			for _, inc := range needingTrans {
				sum := inc.Summary
				if sum == "" {
					sum = inc.SummaryJa
				}
				imp := inc.ImpactAnalysis
				if imp == "" {
					imp = inc.ImpactAnalysisJa
				}
				title := inc.Title
				if title == "" {
					title = inc.TitleJa
				}
				transItems = append(transItems, analyzer.BatchTranslateItem{
					ID:              inc.ID,
					Title:           title,
					Summary:         sum,
					ImpactAnalysis:  imp,
					VictimOrg:       inc.VictimOrg,
					AffectedProduct: inc.AffectedProduct,
				})
			}
			results, err := p.analyzer.TranslateBatch(ctx, transItems)
			if err == nil {
				for _, res := range results {
					if res.Title != "" || res.Summary != "" || res.ImpactAnalysis != "" || res.VictimOrgEn != "" {
						_ = p.store.UpdateIncidentTranslations(ctx, res.ID, res.Title, res.Summary, res.ImpactAnalysis, res.VictimOrgEn, res.AffectedProductEn, res.RecommendedActions)
					}
				}
				log.Printf("[Pipeline] Successfully translated %d incidents into English", len(results))
				p.updateStage(StageTranslating, len(results), len(needingTrans), fmt.Sprintf("英語翻訳完了 (%d/%d件)", len(results), len(needingTrans)))
			}
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
	p.updateStage(StageCompleted, len(newItems), len(newItems), fmt.Sprintf("パイプライン収集・分析サイクル完了 (新着: %d, 分析: %d, 通知: %d)", len(newItems), analyzedCount, notifiedCount))
	go func() {
		time.Sleep(4 * time.Second)
		p.updateStage(StageIdle, 0, 0, "パイプライン待機中")
	}()
	return summary, nil
}
