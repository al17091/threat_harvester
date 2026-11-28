package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/storage"
)

func TestResponsesDoNotExposeCredentials(t *testing.T) {
	mgr := config.GetSettings()
	orig := mgr.GetConfig()
	defer mgr.SetConfig(orig)

	cfg := orig
	cfg.Database.URL = "postgres://app:leak-db-url@db:5432/app"
	cfg.Database.Password = "leak-db-password"
	cfg.AI.Endpoint = "http://u:leak-endpoint@127.0.0.1:1/v1/chat/completions"
	cfg.AI.APIKey = "leak-ai-key"
	cfg.Sinks.Discord.WebhookURL = "https://discord.com/api/webhooks/1/leak-discord"
	cfg.Sinks.Notion.APIKey = "leak-notion-key"
	cfg.Network.TorProxyURL = "socks5h://u:leak-tor@127.0.0.1:1"
	mgr.SetConfig(cfg)

	// A file path containing "?password=" stands in for a credential-bearing database URL.
	dbPath := t.TempDir() + "/cache.db?password=leak-store"
	store, err := storage.NewStore("", dbPath)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()
	defer os.Remove(dbPath)
	srv := NewServer(store)

	get := func(path string) string {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: status %d", path, w.Code)
		}
		return w.Body.String()
	}

	for _, path := range []string{"/api/status", "/api/config", "/api/config/raw", "/api/config/export", "/api/config/export?mask_secrets=true", "/api/config/export?mask=true"} {
		if body := get(path); strings.Contains(body, "leak-") {
			t.Errorf("GET %s exposes a credential: %s", path, body)
		}
	}
	if strings.Contains(get("/api/status"), "db_path") {
		t.Error("status must not report db_path")
	}
	if !strings.Contains(get("/api/config/export?mask_secrets=false"), "leak-notion-key") {
		t.Error("explicit unmasked export must keep credentials")
	}
}
