package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// minTokenLength rejects tokens short enough to be guessed.
const minTokenLength = 32

// AuthConfig describes how protected API routes are authenticated.
type AuthConfig struct {
	tokenDigest []byte // SHA-256 of INTERNAL_API_TOKEN; nil when unset
	disabled    bool   // explicit development opt-out, ignored when a token is set
}

// AuthConfigFromEnv reads INTERNAL_API_TOKEN and INTERNAL_API_AUTH_DISABLED. On error the
// returned configuration rejects every protected request.
func AuthConfigFromEnv() (AuthConfig, error) {
	// Secret files and manifests often leave a trailing newline.
	token := strings.TrimSpace(os.Getenv("INTERNAL_API_TOKEN"))
	if token == "" {
		disabled := strings.EqualFold(strings.TrimSpace(os.Getenv("INTERNAL_API_AUTH_DISABLED")), "true")
		return AuthConfig{disabled: disabled}, nil
	}
	if len(token) < minTokenLength {
		return AuthConfig{}, fmt.Errorf("INTERNAL_API_TOKEN must be at least %d characters", minTokenLength)
	}
	digest := sha256.Sum256([]byte(token))
	return AuthConfig{tokenDigest: digest[:]}, nil
}

// CORSOriginsFromEnv parses the comma-separated CORS_ALLOWED_ORIGINS allowlist. Wildcards are
// rejected; an empty result means that no CORS headers are served at all.
func CORSOriginsFromEnv() ([]string, error) {
	var origins []string
	for _, entry := range strings.Split(os.Getenv("CORS_ALLOWED_ORIGINS"), ",") {
		origin := strings.TrimSpace(entry)
		if origin == "" {
			continue
		}
		if strings.Contains(origin, "*") {
			return nil, errors.New("CORS_ALLOWED_ORIGINS must list explicit origins; wildcards are not allowed")
		}
		origins = append(origins, origin)
	}
	return origins, nil
}

// ValidateSecurityEnv reports configuration mistakes that should stop the server at startup.
func ValidateSecurityEnv() error {
	_, authErr := AuthConfigFromEnv()
	_, corsErr := CORSOriginsFromEnv()
	return errors.Join(authErr, corsErr)
}

func (c AuthConfig) logStatus() {
	switch {
	case c.tokenDigest != nil:
		log.Println("[Auth] Protected API routes require INTERNAL_API_TOKEN")
	case c.disabled:
		log.Println("[Auth] WARNING: INTERNAL_API_AUTH_DISABLED=true, protected API routes are open. Use for local development only")
	default:
		log.Println("[Auth] ERROR: INTERNAL_API_TOKEN is not configured, protected API routes are unavailable")
	}
}

// requireInternalToken guards a route group with service-to-service bearer authentication.
func (s *Server) requireInternalToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.auth.tokenDigest == nil {
			if s.auth.disabled {
				next.ServeHTTP(w, r)
				return
			}
			errorResponse(w, http.StatusServiceUnavailable, "INTERNAL_API_TOKEN is not configured")
			return
		}

		scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		digest := sha256.Sum256([]byte(token))
		// Digests have a fixed length, so the comparison time does not depend on the input.
		if !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare(digest[:], s.auth.tokenDigest) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			errorResponse(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}
