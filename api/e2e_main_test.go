package main_test

import (
	"os"
	"testing"
)

// The end-to-end flow includes protected routes; authentication is covered in internal/api.
func TestMain(m *testing.M) {
	os.Setenv("INTERNAL_API_AUTH_DISABLED", "true")
	os.Unsetenv("INTERNAL_API_TOKEN")
	os.Exit(m.Run())
}
