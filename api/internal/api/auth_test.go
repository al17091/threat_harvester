package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/storage"
)

const testToken = "test-token-0123456789abcdef0123456789"

func newAuthServer(t *testing.T, token, disabled, origins string) *Server {
	t.Helper()
	t.Setenv("INTERNAL_API_TOKEN", token)
	t.Setenv("INTERNAL_API_AUTH_DISABLED", disabled)
	t.Setenv("CORS_ALLOWED_ORIGINS", origins)
	store, err := storage.NewStore("", ":memory:")
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return NewServer(store)
}

func serve(srv *Server, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// publicRoutes is the complete list of routes reachable without a token.
var publicRoutes = map[string]bool{
	"GET /": true, "HEAD /": true, "GET /healthz": true,
	"GET /rss": true, "GET /rss/{lang}": true, "GET /feed.xml": true, "GET /feed.xml/{lang}": true,
	"GET /api/rss": true, "GET /api/rss/{lang}": true, "GET /api/feed.xml": true, "GET /api/feed.xml/{lang}": true,
	"GET /api/status": true, "GET /api/stats/entities": true,
	"GET /api/incidents": true, "GET /api/incidents/{id}": true,
}

// Walking the router means a newly added route fails this test unless it is protected or listed.
func TestEveryRouteIsPublicByListOrRequiresToken(t *testing.T) {
	srv := newAuthServer(t, testToken, "", "")
	protected := 0
	err := chi.Walk(srv.router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if publicRoutes[method+" "+route] {
			return nil
		}
		protected++
		path := strings.NewReplacer("{id}", "abc", "{lang}", "ja").Replace(route)
		for name, headers := range map[string]map[string]string{
			"no header":     nil,
			"wrong token":   {"Authorization": "Bearer " + testToken + "x"},
			"empty token":   {"Authorization": "Bearer "},
			"basic scheme":  {"Authorization": "Basic " + testToken},
			"doubled space": {"Authorization": "Bearer  " + testToken},
			"token only":    {"Authorization": testToken},
		} {
			w := serve(srv, method, path, headers)
			if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Errorf("%s %s (%s): expected 401, got %d", method, route, name, w.Code)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk routes: %v", err)
	}
	if protected != 19 {
		t.Errorf("expected 19 protected routes, got %d", protected)
	}
}

func TestValidTokenReachesProtectedRoutes(t *testing.T) {
	srv := newAuthServer(t, testToken+"\n", "", "")
	for _, scheme := range []string{"Bearer", "bearer"} {
		w := serve(srv, http.MethodGet, "/api/config", map[string]string{"Authorization": scheme + " " + testToken})
		if w.Code != http.StatusOK {
			t.Errorf("%s: expected 200, got %d", scheme, w.Code)
		}
	}
}

func TestPublicRoutesNeedNoToken(t *testing.T) {
	for _, token := range []string{testToken, ""} {
		srv := newAuthServer(t, token, "", "")
		for _, path := range []string{"/healthz", "/api/status", "/api/stats/entities", "/api/incidents", "/api/rss", "/rss"} {
			if w := serve(srv, http.MethodGet, path, nil); w.Code != http.StatusOK {
				t.Errorf("GET %s (token set: %t): expected 200, got %d", path, token != "", w.Code)
			}
		}
	}
}

func TestProtectedRoutesFailClosedWithoutToken(t *testing.T) {
	for name, token := range map[string]string{"unset": "", "too short": "short-token"} {
		srv := newAuthServer(t, token, "", "")
		for _, headers := range []map[string]string{nil, {"Authorization": "Bearer " + token}} {
			if w := serve(srv, http.MethodGet, "/api/config", headers); w.Code != http.StatusServiceUnavailable {
				t.Errorf("%s: expected 503, got %d", name, w.Code)
			}
		}
	}
}

func TestAuthOptOutAppliesOnlyWithoutToken(t *testing.T) {
	if w := serve(newAuthServer(t, "", "true", ""), http.MethodGet, "/api/config", nil); w.Code != http.StatusOK {
		t.Errorf("opt-out: expected 200, got %d", w.Code)
	}
	if w := serve(newAuthServer(t, testToken, "true", ""), http.MethodGet, "/api/config", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("token must win over opt-out: expected 401, got %d", w.Code)
	}
}

func TestPathVariantsDoNotBypassAuth(t *testing.T) {
	srv := newAuthServer(t, testToken, "", "")
	for _, req := range [][2]string{
		{"GET", "/api/config/"}, {"GET", "/api/%63onfig"}, {"GET", "/api/config%2Fraw"},
		{"GET", "/api/status/../config"}, {"GET", "//api/config"}, {"GET", "/API/config"},
		{"HEAD", "/api/config"}, {"OPTIONS", "/api/config"}, {"GET", "/api/incidents/abc/../../config"},
	} {
		if w := serve(srv, req[0], req[1], nil); w.Code == http.StatusOK || w.Code == http.StatusNoContent {
			t.Errorf("%s %s: unexpected status %d: %s", req[0], req[1], w.Code, w.Body.String())
		}
	}
}

func TestEnvValidation(t *testing.T) {
	for name, env := range map[string][2]string{
		"short token":      {"short", ""},
		"wildcard":         {"", "*"},
		"partial wildcard": {"", "https://ok.example, https://*.example"},
	} {
		t.Setenv("INTERNAL_API_TOKEN", env[0])
		t.Setenv("CORS_ALLOWED_ORIGINS", env[1])
		if ValidateSecurityEnv() == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	t.Setenv("INTERNAL_API_TOKEN", testToken)
	t.Setenv("CORS_ALLOWED_ORIGINS", " https://a.example , ,https://b.example")
	if err := ValidateSecurityEnv(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCORSIsOffByDefaultAndAllowlisted(t *testing.T) {
	const allowed, other = "https://allowed.example", "https://other.example"
	cases := []struct {
		origins, origin, want string
	}{
		{"", allowed, ""},
		{" , ", allowed, ""},
		{"*", allowed, ""},
		{allowed, allowed, allowed},
		{allowed, other, ""},
	}
	for _, c := range cases {
		srv := newAuthServer(t, testToken, "", c.origins)
		for _, method := range []string{http.MethodGet, http.MethodOptions} {
			w := serve(srv, method, "/api/status", map[string]string{"Origin": c.origin, "Access-Control-Request-Method": "GET"})
			if got := w.Header().Get("Access-Control-Allow-Origin"); got != c.want {
				t.Errorf("origins=%q %s from %s: ACAO %q, want %q", c.origins, method, c.origin, got, c.want)
			}
			if w.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Errorf("credentials must never be allowed")
			}
		}
	}
}

func TestStatusOmitsInternalHosts(t *testing.T) {
	mgr := config.GetSettings()
	orig := mgr.GetConfig()
	defer mgr.SetConfig(orig)
	cfg := orig
	cfg.AI.Endpoint = "http://internal-llm.invalid:4000/v1/chat/completions"
	cfg.Network.TorProxyURL = "socks5h://internal-tor.invalid:9050"
	mgr.SetConfig(cfg)

	w := serve(newAuthServer(t, testToken, "", ""), http.MethodGet, "/api/status", nil)
	body := w.Body.String()
	for _, forbidden := range []string{"internal-llm", "internal-tor", "database_url", "db_path", "endpoint", `"url"`} {
		if strings.Contains(body, forbidden) {
			t.Errorf("status exposes %q: %s", forbidden, body)
		}
	}
	for _, required := range []string{`"backend":"sqlite"`, `"total_items"`, `"online"`, `"model"`} {
		if !strings.Contains(body, required) {
			t.Errorf("status lost %q: %s", required, body)
		}
	}
}
