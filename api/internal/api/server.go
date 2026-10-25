package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/al17091/threat_harvester/api/internal/analyzer"
	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/harvesters"
	"github.com/al17091/threat_harvester/api/internal/logger"
	"github.com/al17091/threat_harvester/api/internal/models"
	"github.com/al17091/threat_harvester/api/internal/notifiers"
	"github.com/al17091/threat_harvester/api/internal/pipeline"
	"github.com/al17091/threat_harvester/api/internal/reporters"
	"github.com/al17091/threat_harvester/api/internal/scraper"
	"github.com/al17091/threat_harvester/api/internal/storage"
)

type Server struct {
	store      storage.Store
	pipeline   *pipeline.Pipeline
	scraperMgr *scraper.ScraperManager
	router     *chi.Mux

	pipeMu           sync.Mutex
	isPipeRunning    bool
	lastPipeRunAt    *string
	nextPipeRunAt    *string
	schedulerEnabled bool
	lastPipeSummary  interface{}

	torMu        sync.Mutex
	lastTorCheck time.Time
	lastTorState bool

	llmMu        sync.Mutex
	lastLLMCheck time.Time
	lastLLMState bool
}

func NewServer(store storage.Store) *Server {
	logger.InitGlobalLogger()
	cfg := config.GetSettings().GetConfig()
	pipe := pipeline.NewPipeline(store)
	s := &Server{
		store:      store,
		pipeline:   pipe,
		scraperMgr: scraper.NewScraperManager(store, pipe.Analyzer(), cfg.Scraper, cfg.Network),
		router:     chi.NewRouter(),
	}
	s.setupRoutes()
	s.triggerAsyncHealthChecks(cfg)
	return s
}

func (s *Server) setupRoutes() {
	r := s.router

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/", s.handleRoot)
	r.Head("/", s.handleRoot)
	r.Get("/rss", s.handleRSSFeed)
	r.Get("/rss/{lang}", s.handleRSSFeed)
	r.Get("/feed.xml", s.handleRSSFeed)
	r.Get("/feed.xml/{lang}", s.handleRSSFeed)

	r.Route("/api", func(r chi.Router) {
		r.Get("/rss", s.handleRSSFeed)
		r.Get("/rss/{lang}", s.handleRSSFeed)
		r.Get("/feed.xml", s.handleRSSFeed)
		r.Get("/feed.xml/{lang}", s.handleRSSFeed)
		r.Get("/status", s.handleStatus)
		r.Get("/stats/entities", s.handleGetEntityStats)
		r.Get("/incidents", s.handleListIncidents)
		r.Get("/incidents/{id}", s.handleGetIncident)
		r.Post("/incidents/{id}/update", s.handleUpdateIncidentLabels)

		r.Get("/config", s.handleGetConfig)
		r.Get("/config/raw", s.handleGetRawConfig)
		r.Get("/config/export", s.handleExportConfig)
		r.Post("/config/save", s.handleSaveConfig)
		r.Post("/config/sources", s.handleManageSources)
		r.Post("/config/compliance", s.handleUpdateCompliance)

		r.Post("/pipeline/run", s.handleTriggerPipeline)
		r.Post("/pipeline/backfill-incidents", s.handleBackfillIncidents)
		r.Post("/pipeline/backfill-articles", s.handleBackfillArticles)
		r.Post("/pipeline/translate-incidents", s.handleTranslateIncidents)
		r.Get("/pipeline/stream", s.handlePipelineStream)
		r.Get("/pipeline/logs", s.handleGetPipelineLogs)
		r.Post("/pipeline/logs/clear", s.handleClearPipelineLogs)
		r.Post("/test/notify", s.handleTestNotify)
		r.Post("/test/notion", s.handleTestNotion)
		r.Post("/ai/generate-queries", s.handleGenerateQueries)
	})
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func errorResponse(w http.ResponseWriter, status int, msg string) {
	jsonResponse(w, status, map[string]string{"detail": msg})
}

func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]string{
		"service": "Threat Information Harvester API",
		"version": "1.0.0",
		"status":  "healthy",
		"docs":    "/docs",
	})
}

func (s *Server) triggerAsyncHealthChecks(cfg config.AppConfig) {
	s.torMu.Lock()
	if time.Since(s.lastTorCheck) > 60*time.Second {
		s.lastTorCheck = time.Now()
		go func() {
			probeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			torH := harvesters.NewDarkwebOnionHarvester()
			state := torH.TestConnection(probeCtx)
			s.torMu.Lock()
			s.lastTorState = state
			s.torMu.Unlock()
		}()
	}
	s.torMu.Unlock()

	s.llmMu.Lock()
	if time.Since(s.lastLLMCheck) > 60*time.Second {
		s.lastLLMCheck = time.Now()
		go func() {
			probeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			llmAnalyzer := analyzer.NewOpenAICompatibleAnalyzer(
				cfg.AI.Endpoint,
				cfg.AI.Model,
				cfg.AI.APIKey,
				cfg.AI.Temperature,
				cfg.AI.InsecureSkipVerify,
				5,
			)
			state := llmAnalyzer.TestConnection(probeCtx)
			s.llmMu.Lock()
			s.lastLLMState = state
			s.llmMu.Unlock()
		}()
	}
	s.llmMu.Unlock()
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := config.GetSettings().GetConfig()

	dbStats, err := s.store.GetStats(ctx)
	if err != nil {
		dbStats = map[string]interface{}{"error": err.Error()}
	}

	s.triggerAsyncHealthChecks(cfg)

	s.torMu.Lock()
	torOnline := s.lastTorState
	s.torMu.Unlock()

	s.llmMu.Lock()
	llmOnline := s.lastLLMState
	s.llmMu.Unlock()

	mgr := config.GetSettings()

	totalRSS := len(cfg.Sources.VendorRSS)
	activeRSS := 0
	for _, f := range cfg.Sources.VendorRSS {
		if mgr.IsSourceActive("vendor_rss", f.Enabled, f.ComplianceTier) {
			activeRSS++
		}
	}

	totalTG := len(cfg.Sources.Telegram)
	activeTG := 0
	for _, c := range cfg.Sources.Telegram {
		if mgr.IsSourceActive("telegram", c.Enabled, c.ComplianceTier) {
			activeTG++
		}
	}

	totalDW := len(cfg.Sources.DarkwebOnion)
	activeDW := 0
	for _, d := range cfg.Sources.DarkwebOnion {
		tier := d.ComplianceTier
		if tier == "" {
			tier = config.GetDefaultTierForSource("darkweb_onion", d.Type)
		}
		if mgr.IsSourceActive("darkweb_onion", d.Enabled, tier) {
			activeDW++
		}
	}

	totalRansom := len(cfg.Sources.RansomwareTracker)
	activeRansom := 0
	for _, r := range cfg.Sources.RansomwareTracker {
		tier := r.ComplianceTier
		if tier == "" {
			tier = config.GetDefaultTierForSource("ransomware_tracker", r.Type)
		}
		if mgr.IsSourceActive("ransomware_tracker", r.Enabled, tier) {
			activeRansom++
		}
	}

	totalX := len(cfg.Sources.XMonitor)
	activeX := 0
	for _, q := range cfg.Sources.XMonitor {
		if mgr.IsSourceActive("x_monitor", q.Enabled, q.ComplianceTier) {
			activeX++
		}
	}

	totalWeb := len(cfg.Sources.WebSearch)
	activeWeb := 0
	for _, q := range cfg.Sources.WebSearch {
		if mgr.IsSourceActive("web_search", q.Enabled, q.ComplianceTier) {
			activeWeb++
		}
	}

	s.pipeMu.Lock()
	pipeState := map[string]interface{}{
		"is_running":        s.isPipeRunning,
		"last_run_at":       s.lastPipeRunAt,
		"next_run_at":       s.nextPipeRunAt,
		"scheduler_enabled": s.schedulerEnabled,
		"interval_hours":    cfg.Pipeline.CheckIntervalHours,
		"last_summary":      s.lastPipeSummary,
	}
	s.pipeMu.Unlock()

	res := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"database":  dbStats,
		"compliance": mgr.GetComplianceSummary(),
		"tor_proxy": map[string]interface{}{
			"online": torOnline,
			"url":    cfg.Network.TorProxyURL,
		},
		"ai": map[string]interface{}{
			"configured":       cfg.AI.GeminiAPIKey != "",
			"model":            cfg.AI.GeminiModel,
			"primary_provider": cfg.AI.PrimaryProvider,
			"local_llm": map[string]interface{}{
				"online":   llmOnline,
				"model":    cfg.AI.Model,
				"endpoint": cfg.AI.Endpoint,
			},
		},
		"sinks": map[string]interface{}{
			"discord":         cfg.Sinks.Discord.Enabled && cfg.Sinks.Discord.WebhookURL != "",
			"slack":           cfg.Sinks.Slack.Enabled && cfg.Sinks.Slack.WebhookURL != "",
			"generic_webhook": cfg.Sinks.GenericWebhook.Enabled && cfg.Sinks.GenericWebhook.WebhookURL != "",
			"notion":          cfg.Sinks.Notion.Enabled && cfg.Sinks.Notion.APIKey != "" && cfg.Sinks.Notion.DatabaseID != "",
		},
		"sources": map[string]interface{}{
			"vendor_rss":         map[string]int{"total": totalRSS, "active": activeRSS},
			"telegram":           map[string]int{"total": totalTG, "active": activeTG},
			"darkweb_onion":      map[string]int{"total": totalDW, "active": activeDW},
			"ransomware_tracker": map[string]int{"total": totalRansom, "active": activeRansom},
			"x_monitor":          map[string]int{"total": totalX, "active": activeX},
			"web_search":         map[string]int{"total": totalWeb, "active": activeWeb},
			"total_active":       activeRSS + activeTG + activeDW + activeRansom + activeX + activeWeb,
		},
		"pipeline": pipeState,
	}

	jsonResponse(w, http.StatusOK, res)
}

func (s *Server) handleGetEntityStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	limit := 100
	if l := q.Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	japanOnly := q.Get("japan_only") == "true" || q.Get("japan_only") == "1"

	stats, err := s.store.GetEntityStats(ctx, limit, japanOnly)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, stats)
}

func (s *Server) handleListIncidents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	offset, _ := strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}

	japanOnly := q.Get("japan_only") == "true"
	severity := q.Get("severity")
	sourceType := q.Get("source_type")
	search := q.Get("search")
	sortBy := q.Get("sort_by")

	filter := storage.HistoryFilter{
		Limit:      limit,
		Offset:     offset,
		JapanOnly:  japanOnly,
		Severity:   severity,
		SourceType: sourceType,
		Search:     search,
		OrderBy:    sortBy,
	}

	viewMode := q.Get("view")
	var items []map[string]interface{}
	var total int
	var err error

	if viewMode == "raw" {
		items, err = s.store.GetHistory(ctx, filter)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}
		total, err = s.store.GetHistoryTotal(ctx, filter)
		if err != nil {
			total = len(items)
		}
	} else {
		items, err = s.store.GetIncidents(ctx, filter)
		if err != nil {
			errorResponse(w, http.StatusInternalServerError, err.Error())
			return
		}
		total, err = s.store.GetIncidentsTotal(ctx, filter)
		if err != nil {
			total = len(items)
		}
		// Graceful fallback to raw history if incidents have not yet been clustered
		if total == 0 && search == "" && severity == "" {
			rawItems, rawErr := s.store.GetHistory(ctx, filter)
			if rawErr == nil && len(rawItems) > 0 {
				items = rawItems
				total, _ = s.store.GetHistoryTotal(ctx, filter)
			}
		}
	}

	if items == nil {
		items = []map[string]interface{}{}
	}

	lang := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("lang")))
	for _, inc := range items {
		formatIncidentForLang(inc, lang)
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"count":  len(items),
		"total":  total,
		"limit":  limit,
		"offset": offset,
		"items":  items,
	})
}

func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	lang := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("lang")))
	// Try clustered incident first
	inc, err := s.store.GetIncident(r.Context(), id)
	if err == nil && inc != nil {
		// If incident contains Japanese text, translate to English on the fly and cache in DB
		title, _ := inc["title"].(string)
		summary, _ := inc["summary"].(string)
		impact, _ := inc["impact_analysis"].(string)
		victimOrg, _ := inc["victim_org"].(string)
		affProduct, _ := inc["affected_product"].(string)
		var actions []string
		if ep, ok := inc["enriched_parsed"].(map[string]interface{}); ok {
			if ra, ok := ep["recommended_actions"].([]string); ok {
				actions = ra
			} else if rai, ok := ep["recommended_actions"].([]interface{}); ok {
				for _, a := range rai {
					if as, ok := a.(string); ok && as != "" {
						actions = append(actions, as)
					}
				}
			}
			if len(actions) == 0 {
				if raja, ok := ep["recommended_actions_ja"].([]string); ok {
					actions = raja
				} else if raja, ok := ep["recommended_actions_ja"].([]interface{}); ok {
					for _, a := range raja {
						if as, ok := a.(string); ok && as != "" {
							actions = append(actions, as)
						}
					}
				}
			}
		}

		if isJapaneseText(title) || isJapaneseText(summary) || isJapaneseText(impact) || isJapaneseText(victimOrg) || hasJapaneseItem(actions) {
			if s.pipeline != nil && s.pipeline.Analyzer() != nil {
				transOut, transErr := s.pipeline.Analyzer().TranslateIncident(r.Context(), analyzer.IncidentTranslationInput{
					ID:                 id,
					Title:              title,
					Summary:            summary,
					ImpactAnalysis:     impact,
					VictimOrg:          victimOrg,
					AffectedProduct:    affProduct,
					RecommendedActions: actions,
				})
				if transErr == nil && transOut != nil {
					inc["title"] = transOut.Title
					if isJapaneseText(title) && (inc["title_ja"] == nil || inc["title_ja"] == "") {
						inc["title_ja"] = title
					}
					inc["summary"] = transOut.Summary
					inc["summary_ja"] = transOut.Summary
					inc["impact_analysis"] = transOut.ImpactAnalysis
					inc["impact_analysis_ja"] = transOut.ImpactAnalysis
					if transOut.VictimOrgEn != "" {
						inc["victim_org_en"] = transOut.VictimOrgEn
					}
					if isJapaneseText(victimOrg) && (inc["victim_org_ja"] == nil || inc["victim_org_ja"] == "") {
						inc["victim_org_ja"] = victimOrg
					}
					if transOut.AffectedProductEn != "" {
						inc["affected_product_en"] = transOut.AffectedProductEn
					}
					if isJapaneseText(affProduct) && (inc["affected_product_ja"] == nil || inc["affected_product_ja"] == "") {
						inc["affected_product_ja"] = affProduct
					}
					if ep, ok := inc["enriched_parsed"].(map[string]interface{}); ok {
						ep["title"] = transOut.Title
						ep["summary"] = transOut.Summary
						ep["impact_analysis"] = transOut.ImpactAnalysis
						if transOut.VictimOrgEn != "" {
							ep["victim_org_en"] = transOut.VictimOrgEn
						}
						if isJapaneseText(victimOrg) && ep["victim_org_ja"] == nil {
							ep["victim_org_ja"] = victimOrg
						}
						if transOut.AffectedProductEn != "" {
							ep["affected_product_en"] = transOut.AffectedProductEn
						}
						if len(transOut.RecommendedActions) > 0 {
							ep["recommended_actions"] = transOut.RecommendedActions
						}
					}
					_ = s.store.UpdateIncidentTranslations(r.Context(), id, transOut.Title, transOut.Summary, transOut.ImpactAnalysis, transOut.VictimOrgEn, transOut.AffectedProductEn, transOut.RecommendedActions)
				}
			}
		}

		formatIncidentForLang(inc, lang)
		jsonResponse(w, http.StatusOK, inc)
		return
	}

	// Fallback to raw threat item
	item, err := s.store.GetItem(r.Context(), id)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
	if item == nil {
		errorResponse(w, http.StatusNotFound, "Incident not found")
		return
	}
	jsonResponse(w, http.StatusOK, item)
}

func (s *Server) handleUpdateIncidentLabels(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		errorResponse(w, http.StatusBadRequest, "Incident ID required")
		return
	}

	var req struct {
		ThreatActors   []string `json:"threat_actors"`
		Severity       string   `json:"severity"`
		JapanRelevance string   `json:"japan_relevance"`
		AttackType     string   `json:"attack_type"`
		VictimOrg      string   `json:"victim_org"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if err := s.store.UpdateIncidentLabels(r.Context(), id, req.ThreatActors, req.Severity, req.JapanRelevance, req.AttackType, req.VictimOrg); err != nil {
		errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	inc, err := s.store.GetIncident(r.Context(), id)
	if err != nil || inc == nil {
		jsonResponse(w, http.StatusOK, map[string]interface{}{"status": "updated", "id": id})
		return
	}
	jsonResponse(w, http.StatusOK, inc)
}

func (s *Server) handleTranslateIncidents(w http.ResponseWriter, r *http.Request) {
	go func() {
		ctx := context.Background()
		s.RunIncidentBatchTranslation(ctx, 200)
	}()
	jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "started",
		"message": "Background incident translation started",
	})
}

// RunIncidentBatchTranslation translates Japanese incidents in batches using Gemini/Qwen and persists results.
func (s *Server) RunIncidentBatchTranslation(ctx context.Context, maxItems int) int {
	if maxItems <= 0 {
		maxItems = 200
	}
	incidents, err := s.store.GetIncidentsNeedingTranslation(ctx, maxItems)
	if err != nil || len(incidents) == 0 {
		return 0
	}

	log.Printf("[Translator] Found %d incidents needing English translation. Starting batch translation...", len(incidents))
	translatedCount := 0
	batchSize := 15
	for i := 0; i < len(incidents); i += batchSize {
		end := i + batchSize
		if end > len(incidents) {
			end = len(incidents)
		}
		chunk := incidents[i:end]

		var items []analyzer.BatchTranslateItem
		for _, inc := range chunk {
			sum := inc.SummaryJa
			if sum == "" {
				sum = inc.Summary
			}
			imp := inc.ImpactAnalysisJa
			if imp == "" {
				imp = inc.ImpactAnalysis
			}
			items = append(items, analyzer.BatchTranslateItem{
				ID:              inc.ID,
				Title:           inc.Title,
				Summary:         sum,
				ImpactAnalysis:  imp,
				VictimOrg:       inc.VictimOrg,
				AffectedProduct: inc.AffectedProduct,
			})
		}

		results, err := s.pipeline.Analyzer().TranslateBatch(ctx, items)
		if err != nil {
			log.Printf("[Translator] Batch translation failed: %v", err)
			continue
		}

		for _, res := range results {
			if res.Title != "" || res.Summary != "" || res.ImpactAnalysis != "" || res.VictimOrgEn != "" {
				_ = s.store.UpdateIncidentTranslations(ctx, res.ID, res.Title, res.Summary, res.ImpactAnalysis, res.VictimOrgEn, res.AffectedProductEn, res.RecommendedActions)
				translatedCount++
			}
		}
	}
	log.Printf("[Translator] Successfully translated and updated %d incidents in English", translatedCount)
	return translatedCount
}

func formatIncidentForLang(inc map[string]interface{}, lang string) {
	if lang == "ja" {
		// JA VIEW:
		if tJa, ok := inc["title_ja"].(string); ok && tJa != "" {
			inc["title"] = tJa
		}
		if sJa, ok := inc["summary_ja"].(string); ok && sJa != "" {
			inc["summary"] = sJa
		}
		if iJa, ok := inc["impact_analysis_ja"].(string); ok && iJa != "" {
			inc["impact_analysis"] = iJa
		}
		if vJa, ok := inc["victim_org_ja"].(string); ok && vJa != "" {
			inc["victim_org"] = vJa
		}
		if pJa, ok := inc["affected_product_ja"].(string); ok && pJa != "" {
			inc["affected_product"] = pJa
		}
		if ep, ok := inc["enriched_parsed"].(map[string]interface{}); ok {
			if raja, ok := ep["recommended_actions_ja"].([]string); ok && len(raja) > 0 {
				ep["recommended_actions"] = raja
			} else if rajai, ok := ep["recommended_actions_ja"].([]interface{}); ok && len(rajai) > 0 {
				ep["recommended_actions"] = rajai
			}
			if tJa, ok := inc["title_ja"].(string); ok && tJa != "" {
				ep["title"] = tJa
			}
			if sJa, ok := inc["summary_ja"].(string); ok && sJa != "" {
				ep["summary"] = sJa
			}
			if iJa, ok := inc["impact_analysis_ja"].(string); ok && iJa != "" {
				ep["impact_analysis"] = iJa
			}
			if vJa, ok := inc["victim_org_ja"].(string); ok && vJa != "" {
				ep["victim_orgs"] = []string{vJa}
			}
			if pJa, ok := inc["affected_product_ja"].(string); ok && pJa != "" {
				ep["affected_products"] = []string{pJa}
			}
		}
	} else {
		// EN VIEW (default):
		if vEn, ok := inc["victim_org_en"].(string); ok && vEn != "" {
			inc["victim_org"] = vEn
			if ep, ok := inc["enriched_parsed"].(map[string]interface{}); ok {
				ep["victim_orgs"] = []string{vEn}
			}
		}
		if pEn, ok := inc["affected_product_en"].(string); ok && pEn != "" {
			inc["affected_product"] = pEn
			if ep, ok := inc["enriched_parsed"].(map[string]interface{}); ok {
				ep["affected_products"] = []string{pEn}
			}
		}
	}
}

func isJapaneseText(s string) bool {
	for _, r := range s {
		if (r >= 0x3040 && r <= 0x309F) || (r >= 0x30A0 && r <= 0x30FF) || (r >= 0x4E00 && r <= 0x9FAF) {
			return true
		}
	}
	return false
}

func hasJapaneseItem(items []string) bool {
	for _, it := range items {
		if isJapaneseText(it) {
			return true
		}
	}
	return false
}

func (s *Server) handleBackfillIncidents(w http.ResponseWriter, r *http.Request) {
	windowDays := 30
	if wStr := r.URL.Query().Get("window_days"); wStr != "" {
		if wd, err := strconv.Atoi(wStr); err == nil && wd > 0 {
			windowDays = wd
		}
	}
	count, err := s.store.BackfillIncidents(r.Context(), windowDays)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("backfill failed: %v", err))
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":      "success",
		"window_days": windowDays,
		"incidents":   count,
	})
}

func (s *Server) handleBackfillArticles(w http.ResponseWriter, r *http.Request) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		count, err := s.store.BackfillArticleContents(ctx, harvesters.FetchArticleContent)
		if err != nil {
			log.Printf("[Backfill] Manual article backfill error: %v", err)
		} else {
			log.Printf("[Backfill] Manual article backfill completed: %d enriched", count)
		}
	}()
	jsonResponse(w, http.StatusAccepted, map[string]string{
		"status":  "accepted",
		"message": "Article content backfill started in background",
	})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, config.GetSettings().ToSafeMap())
}

func (s *Server) handleGetRawConfig(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, config.GetSettings().GetConfig())
}

func (s *Server) handleExportConfig(w http.ResponseWriter, r *http.Request) {
	mask := r.URL.Query().Get("mask_secrets") == "true"
	yamlText := config.GetSettings().ExportYAML(mask)

	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", `attachment; filename="config.yaml"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(yamlText))
}

func (s *Server) handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	if err := config.GetSettings().Save(""); err != nil {
		errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": fmt.Sprintf("Saved configuration to %s", config.GetSettings().ConfigPath),
	})
}

type sourceActionReq struct {
	SourceType string                 `json:"source_type"`
	Action     string                 `json:"action"`
	Data       map[string]interface{} `json:"data"`
	Identifier string                 `json:"identifier"`
	Enabled    bool                   `json:"enabled"`
}

func (s *Server) handleManageSources(w http.ResponseWriter, r *http.Request) {
	var req sourceActionReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	mgr := config.GetSettings()
	switch req.Action {
	case "add":
		if err := mgr.AddSource(req.SourceType, req.Data); err != nil {
			errorResponse(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = mgr.Save("")
		jsonResponse(w, http.StatusOK, map[string]string{"status": "ok", "message": "Source added"})
	case "toggle":
		id := req.Identifier
		if id == "" && req.Data != nil {
			if u, _ := req.Data["url"].(string); u != "" {
				id = u
			} else if n, _ := req.Data["name"].(string); n != "" {
				id = n
			} else if c, _ := req.Data["channel"].(string); c != "" {
				id = c
			} else if q, _ := req.Data["query"].(string); q != "" {
				id = q
			}
		}
		if id == "" {
			errorResponse(w, http.StatusBadRequest, "Missing identifier for toggle")
			return
		}
		if !mgr.ToggleSource(req.SourceType, id, req.Enabled) {
			errorResponse(w, http.StatusNotFound, "Source not found")
			return
		}
		_ = mgr.Save("")
		jsonResponse(w, http.StatusOK, map[string]string{"status": "ok", "message": "Source status updated"})
	case "delete":
		id := req.Identifier
		if id == "" && req.Data != nil {
			if u, _ := req.Data["url"].(string); u != "" {
				id = u
			} else if n, _ := req.Data["name"].(string); n != "" {
				id = n
			} else if c, _ := req.Data["channel"].(string); c != "" {
				id = c
			} else if q, _ := req.Data["query"].(string); q != "" {
				id = q
			}
		}
		if id == "" {
			errorResponse(w, http.StatusBadRequest, "Missing identifier for delete")
			return
		}
		if !mgr.DeleteSource(req.SourceType, id) {
			errorResponse(w, http.StatusNotFound, "Source not found")
			return
		}
		_ = mgr.Save("")
		jsonResponse(w, http.StatusOK, map[string]string{"status": "ok", "message": "Source deleted"})
	case "edit", "update":
		id := req.Identifier
		if id == "" && req.Data != nil {
			if old, _ := req.Data["old_identifier"].(string); old != "" {
				id = old
			} else if u, _ := req.Data["url"].(string); u != "" {
				id = u
			} else if n, _ := req.Data["name"].(string); n != "" {
				id = n
			} else if c, _ := req.Data["channel"].(string); c != "" {
				id = c
			} else if q, _ := req.Data["query"].(string); q != "" {
				id = q
			}
		}
		if id == "" {
			errorResponse(w, http.StatusBadRequest, "Missing identifier for update")
			return
		}
		if err := mgr.UpdateSource(req.SourceType, id, req.Data); err != nil {
			errorResponse(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = mgr.Save("")
		jsonResponse(w, http.StatusOK, map[string]string{"status": "ok", "message": "Source updated"})
	case "toggle_tier", "toggle_compliance_tier":
		tier := req.Identifier
		if tier == "" && req.Data != nil {
			tier, _ = req.Data["tier"].(string)
		}
		if tier == "" {
			errorResponse(w, http.StatusBadRequest, "Missing tier identifier")
			return
		}
		if err := mgr.ToggleComplianceTier(tier, req.Enabled); err != nil {
			errorResponse(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = mgr.Save("")
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"status":     "ok",
			"message":    fmt.Sprintf("Compliance tier '%s' status updated", tier),
			"compliance": mgr.GetComplianceSummary(),
		})
	case "set_compliance_mode":
		mode := req.Identifier
		if mode == "" && req.Data != nil {
			mode, _ = req.Data["mode"].(string)
		}
		if mode == "" {
			errorResponse(w, http.StatusBadRequest, "Missing compliance mode")
			return
		}
		if err := mgr.SetComplianceMode(mode); err != nil {
			errorResponse(w, http.StatusBadRequest, err.Error())
			return
		}
		_ = mgr.Save("")
		jsonResponse(w, http.StatusOK, map[string]interface{}{
			"status":     "ok",
			"message":    fmt.Sprintf("Compliance mode set to '%s'", mode),
			"compliance": mgr.GetComplianceSummary(),
		})
	default:
		errorResponse(w, http.StatusBadRequest, fmt.Sprintf("Invalid action: %s", req.Action))
	}
}

type updateComplianceReq struct {
	Mode  string                       `json:"mode"`
	Tiers *config.ComplianceTiersConfig `json:"tiers,omitempty"`
}

func (s *Server) handleUpdateCompliance(w http.ResponseWriter, r *http.Request) {
	var req updateComplianceReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	mgr := config.GetSettings()
	if req.Tiers != nil {
		_ = mgr.UpdateCompliance(req.Mode, *req.Tiers)
	} else if req.Mode != "" {
		_ = mgr.SetComplianceMode(req.Mode)
	} else {
		errorResponse(w, http.StatusBadRequest, "Either mode or tiers must be provided")
		return
	}

	_ = mgr.Save("")
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":     "ok",
		"message":    "Compliance configuration updated",
		"compliance": mgr.GetComplianceSummary(),
	})
}

// RunHarvestJob executes the full pipeline cycle safely under a mutex lock.
func (s *Server) RunHarvestJob(triggerSource string) (bool, error) {
	s.pipeMu.Lock()
	if s.isPipeRunning {
		s.pipeMu.Unlock()
		return false, fmt.Errorf("a harvest job is already in progress")
	}
	s.isPipeRunning = true
	s.pipeMu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		log.Printf("[%s] Starting threat intelligence harvest cycle...", triggerSource)
		cfg := config.GetSettings().GetConfig()
		lookback := cfg.Pipeline.CheckIntervalHours
		directOnly := cfg.Pipeline.NotifyDirectOnly

		// Automatic Lookback Expansion:
		// If triggered manually from WebUI, or if the system was stopped / last harvest was long ago,
		// dynamically expand lookbackHours so uncollected RSS/Telegram/Tracker feeds are not skipped.
		latestHarvest, _ := s.store.GetLatestHarvestTime(ctx)
		if latestHarvest != nil {
			elapsedHours := int(time.Since(*latestHarvest).Hours()) + 1
			if triggerSource == "Manual-WebUI" {
				// Manual trigger: ensure at least 72 hours, or the full elapsed downtime up to 7 days (168h)
				if elapsedHours < 72 {
					elapsedHours = 72
				}
				if elapsedHours > 168 {
					elapsedHours = 168
				}
				if elapsedHours > lookback {
					lookback = elapsedHours
					log.Printf("[Manual-WebUI] Expanded lookback to %d hours (last harvest: %s)", lookback, latestHarvest.Format(time.RFC3339))
				}
			} else {
				// Scheduled run: if downtime occurred, automatically expand lookback to cover unharvested gap
				if elapsedHours > lookback {
					if elapsedHours > 168 {
						elapsedHours = 168 // cap at 7 days
					}
					log.Printf("[%s] Expanded lookback to %d hours to cover downtime (last harvest: %s)", triggerSource, elapsedHours, latestHarvest.Format(time.RFC3339))
					lookback = elapsedHours
				}
			}
		} else {
			// Initial run when DB is empty: look back 72 hours by default
			if lookback < 72 {
				lookback = 72
				log.Printf("[%s] Initial harvest detected: expanded lookback to %d hours", triggerSource, lookback)
			}
		}

		summary, err := s.pipeline.RunAll(ctx, lookback, directOnly)

		s.pipeMu.Lock()
		defer s.pipeMu.Unlock()
		s.isPipeRunning = false
		now := time.Now().UTC().Format(time.RFC3339)
		s.lastPipeRunAt = &now
		if err != nil {
			log.Printf("[%s] Harvest job completed with error: %v", triggerSource, err)
			s.lastPipeSummary = map[string]string{"error": err.Error()}
		} else {
			log.Printf("[%s] Harvest job completed successfully", triggerSource)
			s.lastPipeSummary = summary
		}
	}()

	return true, nil
}

// StartScheduler launches an in-process background ticker that runs harvest cycles periodically.
func (s *Server) StartScheduler(ctx context.Context) {
	cfg := config.GetSettings().GetConfig()
	if !cfg.Pipeline.SchedulerEnabled || cfg.Pipeline.CheckIntervalHours <= 0 {
		log.Println("[Scheduler] Background threat harvester scheduler and scraper are disabled by configuration")
		s.pipeMu.Lock()
		s.schedulerEnabled = false
		s.nextPipeRunAt = nil
		s.pipeMu.Unlock()
		return
	}

	if s.scraperMgr != nil {
		s.scraperMgr.Start(ctx)
	}

	intervalHours := cfg.Pipeline.CheckIntervalHours
	duration := time.Duration(intervalHours) * time.Hour

	s.pipeMu.Lock()
	s.schedulerEnabled = true
	nextRun := time.Now().UTC().Add(duration).Format(time.RFC3339)
	s.nextPipeRunAt = &nextRun
	s.pipeMu.Unlock()

	go func() {
		ticker := time.NewTicker(duration)
		defer ticker.Stop()

		log.Printf("[Scheduler] Background threat harvester active (Interval: %d hour(s)). Next cycle scheduled at %s", intervalHours, nextRun)

		for {
			select {
			case <-ctx.Done():
				log.Println("[Scheduler] Background scheduler stopped")
				return
			case <-ticker.C:
				log.Printf("[Scheduler] Ticker fired: initiating scheduled harvest cycle")
				_, _ = s.RunHarvestJob("Scheduler")

				s.pipeMu.Lock()
				next := time.Now().UTC().Add(duration).Format(time.RFC3339)
				s.nextPipeRunAt = &next
				s.pipeMu.Unlock()
			}
		}
	}()

	// Asynchronously enrich existing items that lack full article body
	go func() {
		time.Sleep(2 * time.Second)
		bCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		count, err := s.store.BackfillArticleContents(bCtx, harvesters.FetchArticleContent)
		if err != nil {
			log.Printf("[Backfill] Article content backfill encountered error: %v", err)
		} else if count > 0 {
			log.Printf("[Backfill] Successfully enriched %d articles with full original content", count)
		}
	}()
}

func (s *Server) handleTriggerPipeline(w http.ResponseWriter, r *http.Request) {
	started, err := s.RunHarvestJob("Manual-WebUI")
	if !started {
		jsonResponse(w, http.StatusOK, map[string]string{
			"status":  "already_running",
			"message": err.Error(),
		})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "started",
		"message": "Harvest pipeline started in background",
	})
}

func (s *Server) handlePipelineStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Subscribe to live log stream
	ch, unsub := logger.DefaultHub.Subscribe()
	defer unsub()

	// Flush initial recent logs
	recent := logger.DefaultHub.GetEntries(100)
	for _, entry := range recent {
		data, _ := json.Marshal(entry)
		fmt.Fprintf(w, "event: log\ndata: %s\n\n", data)
	}

	s.pipeMu.Lock()
	statusData, _ := json.Marshal(map[string]interface{}{
		"is_running":  s.isPipeRunning,
		"last_run_at": s.lastPipeRunAt,
	})
	s.pipeMu.Unlock()
	fmt.Fprintf(w, "event: status\ndata: %s\n\n", statusData)
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case entry, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(entry)
			fmt.Fprintf(w, "event: log\ndata: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) handleGetPipelineLogs(w http.ResponseWriter, r *http.Request) {
	limit := 150
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}

	entries := logger.DefaultHub.GetEntries(limit)

	s.pipeMu.Lock()
	isRunning := s.isPipeRunning
	lastRunAt := s.lastPipeRunAt
	s.pipeMu.Unlock()

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"logs":        entries,
		"is_running":  isRunning,
		"last_run_at": lastRunAt,
	})
}

func (s *Server) handleClearPipelineLogs(w http.ResponseWriter, r *http.Request) {
	logger.DefaultHub.Clear()
	jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"message": "Logs cleared",
	})
}

func (s *Server) handleTestNotify(w http.ResponseWriter, r *http.Request) {
	item := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"JPCERT/CC (GUI Test)",
		"[TEST ALERT] 国内組織を標的としたサイバー攻撃インシデント検知テスト",
		"https://www.jpcert.or.jp",
		"これはダッシュボードからのWebHook通知テストです。正常に配信されました。",
		"",
		nil,
		nil,
	)

	enriched := &models.EnrichedThreat{
		ItemID:               item.ID,
		Item:                 item,
		Severity:             models.SeverityHigh,
		JapanRelevance:       models.JapanRelevanceDirect,
		TitleJa:              "【GUIテスト】国内重要組織を標的とした攻撃アラート",
		SummaryJa:            "ダッシュボード管理画面からの通知疎通テストです。",
		ImpactAnalysisJa:     "通知システムの正常稼働を確認しました。",
		VictimOrgs:           []string{"テスト対象企業"},
		ThreatActors:         []string{"Simulated Adversary"},
		RecommendedActionsJa: []string{"本通知が受信できたことを確認してください。"},
		AnalyzedAt:           time.Now().UTC(),
	}

	mgr := notifiers.NewNotificationManager()
	dispatched := mgr.Dispatch(r.Context(), enriched)
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":     "sent",
		"dispatched": dispatched,
	})
}

func (s *Server) handleTestNotion(w http.ResponseWriter, r *http.Request) {
	item := models.NewThreatItem(
		models.SourceTypeVendorRSS,
		"JPCERT/CC (Notion Test)",
		"[TEST NOTION] 脅威情報データベース連携テスト",
		"https://www.jpcert.or.jp",
		"これはNotionデータベース連携の検証データです。",
		"",
		nil,
		nil,
	)

	enriched := &models.EnrichedThreat{
		ItemID:               item.ID,
		Item:                 item,
		Severity:             models.SeverityCritical,
		JapanRelevance:       models.JapanRelevanceDirect,
		TitleJa:              "【Notion連携テスト】国内組織向け脅威レポート同期",
		SummaryJa:            "ダッシュボードからのNotion API接続確認用レコードです。",
		ImpactAnalysisJa:     "データベースへの書き込み権限とプロパティ構成を確認中。",
		VictimOrgs:           []string{"検証用企業"},
		ThreatActors:         []string{"Test Actor"},
		RecommendedActionsJa: []string{"Notionデータベースに本ページが作成されたことを確認する。"},
		AnalyzedAt:           time.Now().UTC(),
	}

	rep := reporters.NewNotionReporter()
	pageID, err := rep.CreateIncidentPage(r.Context(), enriched)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create Notion page: %v", err))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "created",
		"page_id": pageID,
	})
}

func (s *Server) handleGenerateQueries(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Directive  string `json:"directive"`
		TargetType string `json:"target_type"`
		Count      int    `json:"count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.Directive) == "" {
		errorResponse(w, http.StatusBadRequest, "Directive is required")
		return
	}
	if req.Count <= 0 {
		req.Count = 3
	}

	var az analyzer.ThreatAnalyzer
	if s.pipeline != nil && s.pipeline.Analyzer() != nil {
		az = s.pipeline.Analyzer()
	} else {
		az = analyzer.NewDefaultThreatAnalyzer()
	}
	queries, err := az.GenerateSearchQueries(r.Context(), req.Directive, req.TargetType, req.Count)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to generate queries: %v", err))
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"directive":   req.Directive,
		"target_type": req.TargetType,
		"queries":     queries,
	})
}
