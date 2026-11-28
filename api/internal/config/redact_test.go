package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactURL(t *testing.T) {
	cases := map[string]string{
		"":                                     "",
		"postgres://user:s3cret@db:5432/app":   "postgres://db:5432/app",
		"postgres://user:s3:cr@et@db:5432/app": "postgres://db:5432/app",
		"postgresql://db/app?user=u&password=s3cret":     "postgresql://db/app",
		"socks5h://user:s3cret@tor:9050":                 "socks5h://tor:9050",
		"ws://browserless:3000?token=s3cret":             "ws://browserless:3000",
		"https://llm.example/v1/chat/completions#s3cret": "https://llm.example/v1/chat/completions",
		"postgres://user:12/s3cret@db:5432/app":          "[redacted]",
		"postgres://user:12#s3cret@db:5432/app":          "[redacted]",
		"postgres://user:s3 cret%zz@db/app":              "[redacted]",
		"host=db user=app password=s3cret dbname=app":    "[redacted]",
		"user:s3cret@proxy:8080":                         "[redacted]",
		"data/threat_cache.db":                           "data/threat_cache.db",
		"sqlite:///data/threat_cache.db":                 "sqlite:///data/threat_cache.db",
		"socks5h://host.docker.internal:9050":            "socks5h://host.docker.internal:9050",
	}
	for in, want := range cases {
		if got := RedactURL(in); got != want {
			t.Errorf("RedactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func secretConfig() AppConfig {
	cfg := DefaultConfig()
	cfg.Database.URL = "postgres://app:leak-db-url@db:5432/app"
	cfg.Database.Password = "leak-db-password"
	cfg.AI.Endpoint = "https://u:leak-endpoint@llm.example/v1"
	cfg.AI.APIKey = "leak-ai-key"
	cfg.AI.GeminiAPIKey = "leak-gemini-key"
	cfg.AI.Escalation.GeminiAPIKey = "leak-escalation-key"
	cfg.Sinks.Discord.WebhookURL = "https://discord.com/api/webhooks/1/leak-discord"
	cfg.Sinks.Slack.WebhookURL = "https://hooks.slack.com/services/leak-slack"
	cfg.Sinks.GenericWebhook.WebhookURL = "https://example.com/leak-generic"
	cfg.Sinks.Notion.APIKey = "leak-notion-key"
	cfg.Network.TorProxyURL = "socks5h://u:leak-tor@tor:9050"
	cfg.Network.HTTPProxy = "http://u:leak-proxy@proxy:3128"
	cfg.Scraper.BrowserlessURL = "ws://browserless:3000?token=leak-browserless"
	return cfg
}

func TestNoCredentialSurvivesRedaction(t *testing.T) {
	mgr := GetSettings()
	orig := mgr.GetConfig()
	defer mgr.SetConfig(orig)
	mgr.SetConfig(secretConfig())

	safeJSON, err := json.Marshal(mgr.ToSafeMap())
	if err != nil {
		t.Fatalf("marshal safe map: %v", err)
	}
	for name, out := range map[string]string{
		"ToSafeMap":        string(safeJSON),
		"ExportYAML(true)": mgr.ExportYAML(true),
	} {
		if strings.Contains(out, "leak-") {
			t.Errorf("%s leaks a credential:\n%s", name, out)
		}
	}

	// Redaction works on a copy: the live configuration and unmasked export keep real values.
	if got := mgr.GetConfig().Sinks.Notion.APIKey; got != "leak-notion-key" {
		t.Errorf("live configuration was modified: %q", got)
	}
	if !strings.Contains(mgr.ExportYAML(false), "leak-db-url") {
		t.Error("unmasked export must keep credentials")
	}
}

func TestRedactedKeepsEmptyValuesEmpty(t *testing.T) {
	var cfg AppConfig
	red := cfg.Redacted()
	if red.Database.Password != "" || red.Sinks.Discord.WebhookURL != "" || red.AI.APIKey != "" {
		t.Errorf("unset secrets must stay empty so clients can tell they are not configured: %+v", red)
	}
}
