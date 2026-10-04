package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dapt/information_harvester/backend/internal/api"
	"github.com/dapt/information_harvester/backend/internal/config"
	"github.com/dapt/information_harvester/backend/internal/logger"
	"github.com/dapt/information_harvester/backend/internal/pipeline"
	"github.com/dapt/information_harvester/backend/internal/storage"
)

func main() {
	logger.InitGlobalLogger()
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	// Initialize configuration
	cfgMgr := config.GetSettings()
	cfg := cfgMgr.GetConfig()

	// Initialize storage
	dbURL := cfg.Database.URL
	sqlitePath := cfg.Database.SQLitePath
	store, err := storage.NewStore(dbURL, sqlitePath)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer store.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch command {
	case "web", "serve":
		runWeb(ctx, store)
	case "run", "harvest":
		runHarvest(ctx, store)
	case "cron":
		runCron(ctx, store)
	case "status":
		runStatus(ctx, store)
	case "history":
		runHistory(ctx, store)
	case "show":
		runShow(ctx, store)
	case "test-notify":
		runTestNotify(ctx)
	case "test-notion":
		runTestNotion(ctx)
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`Threat Information Harvester - High-Performance CTI Engine

Usage:
  harvester <command> [arguments]

Commands:
  web, serve     Start the REST API server and dashboard backend (default: :8000)
  run, harvest   Execute a single threat harvesting and enrichment cycle
  cron           Run the harvesting pipeline in an infinite loop with interval
  status         Check database statistics and component connectivity
  history        List recent collected threat incidents
  show <id>      Display full details of a specific incident
  test-notify    Dispatch a test alert to configured Webhook channels
  test-notion    Create a test incident page in the Notion database
`)
}

func runWeb(ctx context.Context, store storage.Store) {
	fs := flag.NewFlagSet("web", flag.ExitOnError)
	port := fs.Int("port", 8000, "Port to listen on")
	host := fs.String("host", "0.0.0.0", "Host address to bind to")
	_ = fs.Parse(os.Args[2:])

	if envPort := os.Getenv("PORT"); envPort != "" {
		var p int
		if _, err := fmt.Sscanf(envPort, "%d", &p); err == nil && p > 0 {
			*port = p
		}
	}

	srv := api.NewServer(store)
	srv.StartScheduler(ctx)

	addr := fmt.Sprintf("%s:%d", *host, *port)
	httpServer := &http.Server{
		Addr:    addr,
		Handler: srv,
	}

	go func() {
		log.Printf("Threat Information Harvester API running on http://%s", addr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down server gracefully...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
	log.Println("Server stopped")
}

func runHarvest(ctx context.Context, store storage.Store) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	lookback := fs.Int("lookback", 0, "Hours to look back (default: config setting)")
	directOnly := fs.Bool("direct-only", false, "Notify Japan-direct incidents only")
	_ = fs.Parse(os.Args[2:])

	pipe := pipeline.NewPipeline(store)
	summary, err := pipe.RunAll(ctx, *lookback, *directOnly)
	if err != nil {
		log.Fatalf("Harvest failed: %v", err)
	}

	fmt.Printf("\n=== Harvesting Completed ===\n")
	fmt.Printf("Total Collected : %d\n", summary.TotalHarvested)
	fmt.Printf("New Incidents   : %d\n", summary.NewItems)
	fmt.Printf("Analyzed Items  : %d\n", summary.Analyzed)
	fmt.Printf("Alerts Dispatched: %d\n", summary.Notified)
	if summary.NotionConfigured {
		fmt.Printf("Notion Synced   : %d\n", summary.NotionReported)
	}
}

func runCron(ctx context.Context, store storage.Store) {
	cfg := config.GetSettings().GetConfig()
	intervalHours := cfg.Pipeline.CheckIntervalHours
	if intervalHours <= 0 {
		intervalHours = 1
	}

	pipe := pipeline.NewPipeline(store)
	ticker := time.NewTicker(time.Duration(intervalHours) * time.Hour)
	defer ticker.Stop()

	log.Printf("Starting cron harvester loop (Interval: %d hour(s)). Initial run now...", intervalHours)
	_, _ = pipe.RunAll(ctx, intervalHours, cfg.Pipeline.NotifyDirectOnly)

	for {
		select {
		case <-ctx.Done():
			log.Println("Cron loop stopped")
			return
		case <-ticker.C:
			log.Printf("Triggering scheduled harvest cycle...")
			_, _ = pipe.RunAll(ctx, intervalHours, cfg.Pipeline.NotifyDirectOnly)
		}
	}
}

func runStatus(ctx context.Context, store storage.Store) {
	stats, err := store.GetStats(ctx)
	if err != nil {
		log.Fatalf("Failed to fetch stats: %v", err)
	}
	b, _ := json.MarshalIndent(stats, "", "  ")
	fmt.Println(string(b))
}

func runHistory(ctx context.Context, store storage.Store) {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	limit := fs.Int("limit", 20, "Number of items to show")
	japanOnly := fs.Bool("japan-only", false, "Show Japan-direct incidents only")
	severity := fs.String("severity", "", "Filter by severity (Critical, High, Medium, Low)")
	_ = fs.Parse(os.Args[2:])

	items, err := store.GetHistory(ctx, storage.HistoryFilter{
		Limit:     *limit,
		JapanOnly: *japanOnly,
		Severity:  *severity,
	})
	if err != nil {
		log.Fatalf("Failed to query history: %v", err)
	}

	fmt.Printf("%-8s | %-10s | %-8s | %-20s | %s\n", "ID", "SEVERITY", "JP-REL", "SOURCE", "TITLE")
	fmt.Println("---------------------------------------------------------------------------------------------------------")
	for _, it := range items {
		id, _ := it["id"].(string)
		if len(id) > 8 {
			id = id[:8]
		}
		sev, _ := it["severity"].(string)
		jrel, _ := it["japan_relevance"].(string)
		src, _ := it["source_name"].(string)
		if len(src) > 20 {
			src = src[:20]
		}
		title, _ := it["title"].(string)
		if len(title) > 50 {
			title = title[:50] + "..."
		}
		fmt.Printf("%-8s | %-10s | %-8s | %-20s | %s\n", id, sev, jrel, src, title)
	}
}

func runShow(ctx context.Context, store storage.Store) {
	if len(os.Args) < 3 {
		log.Fatal("Usage: harvester show <id>")
	}
	id := os.Args[2]
	item, err := store.GetItem(ctx, id)
	if err != nil {
		log.Fatalf("Error retrieving item: %v", err)
	}
	if item == nil {
		log.Fatalf("Incident not found for ID: %s", id)
	}
	b, _ := json.MarshalIndent(item, "", "  ")
	fmt.Println(string(b))
}

func runTestNotify(ctx context.Context) {
	srv := api.NewServer(nil)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/api/test/notify", nil)
	rr := &stubResponseWriter{header: make(http.Header)}
	srv.ServeHTTP(rr, req)
	fmt.Println(string(rr.body))
}

func runTestNotion(ctx context.Context) {
	srv := api.NewServer(nil)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/api/test/notion", nil)
	rr := &stubResponseWriter{header: make(http.Header)}
	srv.ServeHTTP(rr, req)
	fmt.Println(string(rr.body))
}

type stubResponseWriter struct {
	header http.Header
	code   int
	body   []byte
}

func (w *stubResponseWriter) Header() http.Header        { return w.header }
func (w *stubResponseWriter) Write(b []byte) (int, error) { w.body = append(w.body, b...); return len(b), nil }
func (w *stubResponseWriter) WriteHeader(code int)        { w.code = code }
