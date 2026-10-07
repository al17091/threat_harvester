package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/dapt/information_harvester/backend/internal/config"
	"github.com/dapt/information_harvester/backend/internal/storage"
)

func TestAPIRoutes(t *testing.T) {
	defer os.Remove("config.yaml")
	store, err := storage.NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory store: %v", err)
	}
	defer store.Close()

	mgr := config.GetSettings()
	if mgr != nil && mgr.ConfigPath != "" {
		origConfig, _ := os.ReadFile(mgr.ConfigPath)
		defer func() {
			if len(origConfig) > 0 {
				_ = os.WriteFile(mgr.ConfigPath, origConfig, 0644)
			}
		}()
	}

	srv := NewServer(store)

	// 1. GET /
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 2. GET /api/status
	req = httptest.NewRequest(http.MethodGet, "/api/status", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 3. GET /api/incidents
	req = httptest.NewRequest(http.MethodGet, "/api/incidents", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 4. GET /api/config
	req = httptest.NewRequest(http.MethodGet, "/api/config", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 5. POST /api/config/sources (add)
	addPayload := map[string]interface{}{
		"source_type": "vendor_rss",
		"action":      "add",
		"data": map[string]interface{}{
			"name": "Unit Test Source",
			"url":  "https://example.com/test_feed.rss",
		},
	}
	b, _ := json.Marshal(addPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/sources", bytes.NewReader(b))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 5b. POST /api/config/sources (update)
	updatePayload := map[string]interface{}{
		"source_type": "vendor_rss",
		"action":      "update",
		"identifier":  "https://example.com/test_feed.rss",
		"data": map[string]interface{}{
			"name":     "Updated Unit Test Source",
			"category": "updated_cat",
		},
	}
	bUpdate, _ := json.Marshal(updatePayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/sources", bytes.NewReader(bUpdate))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 6. POST /api/test/notify
	req = httptest.NewRequest(http.MethodPost, "/api/test/notify", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// 7. POST /api/config/compliance (update mode)
	compPayload := map[string]interface{}{
		"mode": "commercial_only",
	}
	bComp, _ := json.Marshal(compPayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/compliance", bytes.NewReader(bComp))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 8. POST /api/config/sources (toggle compliance tier)
	tierTogglePayload := map[string]interface{}{
		"action":     "toggle_compliance_tier",
		"identifier": "darkweb_access",
		"enabled":    false,
	}
	bTier, _ := json.Marshal(tierTogglePayload)
	req = httptest.NewRequest(http.MethodPost, "/api/config/sources", bytes.NewReader(bTier))
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// 9. GET /api/feed.xml and GET /rss
	req = httptest.NewRequest(http.MethodGet, "/api/feed.xml", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "application/rss+xml") {
		t.Fatalf("expected RSS content-type, got %s", w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Body.String(), "<rss version=\"2.0\"") {
		t.Fatalf("expected RSS 2.0 root element, got %s", w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/rss", nil)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on /rss, got %d", w.Code)
	}
}
