package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"

	"github.com/dapt/information_harvester/backend/internal/config"
	"github.com/dapt/information_harvester/backend/internal/harvesters"
	"github.com/dapt/information_harvester/backend/internal/models"
	"github.com/dapt/information_harvester/backend/internal/notifiers"
	"github.com/dapt/information_harvester/backend/internal/pipeline"
	"github.com/dapt/information_harvester/backend/internal/reporters"
	"github.com/dapt/information_harvester/backend/internal/storage"
)

type Server struct {
	store    storage.Store
	pipeline *pipeline.Pipeline
	router   *chi.Mux

	pipeMu          sync.Mutex
	isPipeRunning   bool
	lastPipeRunAt   *string
	lastPipeSummary interface{}

	torMu        sync.Mutex
	lastTorCheck time.Time
	lastTorState bool
}

func NewServer(store storage.Store) *Server {
	s := &Server{
		store:    store,
		pipeline: pipeline.NewPipeline(store),
		router:   chi.NewRouter(),
	}
	s.setupRoutes()
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

	r.Route("/api", func(r chi.Router) {
		r.Get("/status", s.handleStatus)
		r.Get("/incidents", s.handleListIncidents)
		r.Get("/incidents/{id}", s.handleGetIncident)

		r.Get("/config", s.handleGetConfig)
		r.Get("/config/raw", s.handleGetRawConfig)
		r.Get("/config/export", s.handleExportConfig)
		r.Post("/config/save", s.handleSaveConfig)
		r.Post("/config/sources", s.handleManageSources)

		r.Post("/pipeline/run", s.handleTriggerPipeline)
		r.Post("/test/notify", s.handleTestNotify)
		r.Post("/test/notion", s.handleTestNotion)
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

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := config.GetSettings().GetConfig()

	dbStats, err := s.store.GetStats(ctx)
	if err != nil {
		dbStats = map[string]interface{}{"error": err.Error()}
	}

	s.torMu.Lock()
	if time.Since(s.lastTorCheck) > 60*time.Second {
		torH := harvesters.NewDarkwebOnionHarvester()
		s.lastTorState = torH.TestConnection(ctx)
		s.lastTorCheck = time.Now()
	}
	torOnline := s.lastTorState
	s.torMu.Unlock()

	totalRSS := len(cfg.Sources.VendorRSS)
	activeRSS := 0
	for _, f := range cfg.Sources.VendorRSS {
		if f.Enabled {
			activeRSS++
		}
	}

	totalTG := len(cfg.Sources.Telegram)
	activeTG := 0
	for _, c := range cfg.Sources.Telegram {
		if c.Enabled {
			activeTG++
		}
	}

	totalDW := len(cfg.Sources.DarkwebOnion)
	activeDW := 0
	for _, d := range cfg.Sources.DarkwebOnion {
		if d.Enabled {
			activeDW++
		}
	}

	totalX := len(cfg.Sources.XMonitor)
	activeX := 0
	for _, q := range cfg.Sources.XMonitor {
		if q.Enabled {
			activeX++
		}
	}

	totalWeb := len(cfg.Sources.WebSearch)
	activeWeb := 0
	for _, q := range cfg.Sources.WebSearch {
		if q.Enabled {
			activeWeb++
		}
	}

	s.pipeMu.Lock()
	pipeState := map[string]interface{}{
		"is_running":   s.isPipeRunning,
		"last_run_at":  s.lastPipeRunAt,
		"last_summary": s.lastPipeSummary,
	}
	s.pipeMu.Unlock()

	res := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"database":  dbStats,
		"tor_proxy": map[string]interface{}{
			"online": torOnline,
			"url":    cfg.Network.TorProxyURL,
		},
		"ai": map[string]interface{}{
			"configured": cfg.AI.GeminiAPIKey != "",
			"model":      cfg.AI.GeminiModel,
		},
		"sinks": map[string]interface{}{
			"discord":         cfg.Sinks.Discord.Enabled && cfg.Sinks.Discord.WebhookURL != "",
			"slack":           cfg.Sinks.Slack.Enabled && cfg.Sinks.Slack.WebhookURL != "",
			"generic_webhook": cfg.Sinks.GenericWebhook.Enabled && cfg.Sinks.GenericWebhook.WebhookURL != "",
			"notion":          cfg.Sinks.Notion.Enabled && cfg.Sinks.Notion.APIKey != "" && cfg.Sinks.Notion.DatabaseID != "",
		},
		"sources": map[string]interface{}{
			"vendor_rss":    map[string]int{"total": totalRSS, "active": activeRSS},
			"telegram":      map[string]int{"total": totalTG, "active": activeTG},
			"darkweb_onion": map[string]int{"total": totalDW, "active": activeDW},
			"x_monitor":     map[string]int{"total": totalX, "active": activeX},
			"web_search":    map[string]int{"total": totalWeb, "active": activeWeb},
			"total_active":  activeRSS + activeTG + activeDW + activeX + activeWeb,
		},
		"pipeline": pipeState,
	}

	jsonResponse(w, http.StatusOK, res)
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

	items, err := s.store.GetHistory(ctx, storage.HistoryFilter{
		Limit:      limit,
		Offset:     offset,
		JapanOnly:  japanOnly,
		Severity:   severity,
		SourceType: sourceType,
		Search:     search,
		OrderBy:    sortBy,
	})
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	if items == nil {
		items = []map[string]interface{}{}
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"count":  len(items),
		"limit":  limit,
		"offset": offset,
		"items":  items,
	})
}

func (s *Server) handleGetIncident(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
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
	default:
		errorResponse(w, http.StatusBadRequest, fmt.Sprintf("Invalid action: %s", req.Action))
	}
}

func (s *Server) handleTriggerPipeline(w http.ResponseWriter, r *http.Request) {
	s.pipeMu.Lock()
	if s.isPipeRunning {
		s.pipeMu.Unlock()
		jsonResponse(w, http.StatusOK, map[string]string{
			"status":  "already_running",
			"message": "A harvest job is already in progress",
		})
		return
	}
	s.isPipeRunning = true
	s.pipeMu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		summary, err := s.pipeline.RunAll(ctx, 0, false)

		s.pipeMu.Lock()
		defer s.pipeMu.Unlock()
		s.isPipeRunning = false
		now := time.Now().UTC().Format(time.RFC3339)
		s.lastPipeRunAt = &now
		if err != nil {
			s.lastPipeSummary = map[string]string{"error": err.Error()}
		} else {
			s.lastPipeSummary = summary
		}
	}()

	jsonResponse(w, http.StatusOK, map[string]string{
		"status":  "started",
		"message": "Harvest pipeline started in background",
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
