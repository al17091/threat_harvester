package api

import (
	"os"
	"testing"
)

// Handler tests exercise behavior behind the auth layer; auth_test.go overrides these variables.
func TestMain(m *testing.M) {
	os.Setenv("INTERNAL_API_AUTH_DISABLED", "true")
	os.Unsetenv("INTERNAL_API_TOKEN")
	os.Unsetenv("CORS_ALLOWED_ORIGINS")
	os.Exit(m.Run())
}
