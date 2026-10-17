package notifiers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/backend/internal/config"
	"github.com/al17091/threat_harvester/backend/internal/models"
)

func sampleThreat(severity models.Severity, relevance models.JapanRelevance) *models.EnrichedThreat {
	return &models.EnrichedThreat{
		ItemID: "threat-1234",
		Item: models.ThreatItem{
			ID:          "threat-1234",
			URL:         "https://example.com/advisory/101",
			Title:       "Sample Threat Alert",
			Summary:     "A test threat detected.",
			HarvestedAt: time.Now(),
		},
		Title:              "Sample Threat Alert",
		TitleJa:            "サンプル脅威アラート",
		Summary:            "A test threat detected.",
		SummaryJa:          "検知されたテスト脅威です。",
		Severity:           severity,
		JapanRelevance:     relevance,
		VictimOrgs:         []string{"Target Corp Japan"},
		ThreatActors:       []string{"APT99"},
		ImpactAnalysis:     "Critical impact on production systems.",
		RecommendedActions: []string{"Isolate affected network immediately."},
		AnalyzedAt:         time.Now(),
	}
}

func TestGenericNotifier(t *testing.T) {
	ctx := context.Background()
	notifier := NewGenericNotifier()

	origConfig := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origConfig)

	// 1. Disabled case
	cfg := origConfig
	cfg.Sinks.GenericWebhook.Enabled = false
	cfg.Sinks.GenericWebhook.WebhookURL = ""
	config.GetSettings().SetConfig(cfg)

	threat := sampleThreat(models.SeverityHigh, models.JapanRelevanceDirect)
	if ok := notifier.Notify(ctx, threat); !ok {
		t.Errorf("Expected true when generic webhook is disabled")
	}

	// 2. Successful POST
	var receivedBody []byte
	var receivedHeaders http.Header
	tsSuccess := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer tsSuccess.Close()

	cfg.Sinks.GenericWebhook.Enabled = true
	cfg.Sinks.GenericWebhook.WebhookURL = tsSuccess.URL
	config.GetSettings().SetConfig(cfg)

	if ok := notifier.Notify(ctx, threat); !ok {
		t.Errorf("Expected true when generic webhook succeeds")
	}
	if receivedHeaders.Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", receivedHeaders.Get("Content-Type"))
	}
	var receivedThreat models.EnrichedThreat
	if err := json.Unmarshal(receivedBody, &receivedThreat); err != nil {
		t.Fatalf("Failed to unmarshal received generic payload: %v", err)
	}
	if receivedThreat.TitleJa != threat.TitleJa {
		t.Errorf("Expected title %s, got %s", threat.TitleJa, receivedThreat.TitleJa)
	}

	// 3. HTTP Server Error response (500)
	tsErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer tsErr.Close()

	cfg.Sinks.GenericWebhook.WebhookURL = tsErr.URL
	config.GetSettings().SetConfig(cfg)

	if ok := notifier.Notify(ctx, threat); ok {
		t.Errorf("Expected false when generic webhook returns 500")
	}

	// 4. Client error / connection refused
	cfg.Sinks.GenericWebhook.WebhookURL = "http://127.0.0.1:9"
	config.GetSettings().SetConfig(cfg)
	if ok := notifier.Notify(ctx, threat); ok {
		t.Errorf("Expected false when generic webhook connection fails")
	}
}

func TestDiscordNotifier(t *testing.T) {
	ctx := context.Background()
	notifier := NewDiscordNotifier()

	origConfig := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origConfig)

	// 1. Dry run / Disabled
	cfg := origConfig
	cfg.Sinks.Discord.Enabled = false
	cfg.Sinks.Discord.WebhookURL = ""
	config.GetSettings().SetConfig(cfg)

	threat := sampleThreat(models.SeverityCritical, models.JapanRelevanceDirect)
	if ok := notifier.Notify(ctx, threat); !ok {
		t.Errorf("Expected true for dry-run discord notify")
	}

	// 2. Enabled and various severity & relevance branches
	var lastPayload map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &lastPayload)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()

	cfg.Sinks.Discord.Enabled = true
	cfg.Sinks.Discord.WebhookURL = ts.URL
	config.GetSettings().SetConfig(cfg)

	testCases := []struct {
		severity  models.Severity
		relevance models.JapanRelevance
		title     string
		summary   string
	}{
		{models.SeverityCritical, models.JapanRelevanceDirect, "Critical Japan Threat", "Summary EN"},
		{models.SeverityHigh, models.JapanRelevanceIndirect, "", ""}, // test fallback to TitleJa / SummaryJa
		{models.SeverityMedium, models.JapanRelevanceNone, "Med Threat", "Summary"},
		{models.SeverityLow, models.JapanRelevanceNone, "Low Threat", "Summary"},
	}

	for _, tc := range testCases {
		th := sampleThreat(tc.severity, tc.relevance)
		th.Title = tc.title
		th.Summary = tc.summary
		if tc.title == "" {
			th.ImpactAnalysis = ""
			th.RecommendedActions = nil
		}
		if ok := notifier.Notify(ctx, th); !ok {
			t.Errorf("Failed to notify discord for case %v / %v", tc.severity, tc.relevance)
		}
		if len(lastPayload) == 0 {
			t.Errorf("No payload received for discord notify")
		}
	}

	// 3. HTTP Error from Discord server
	tsErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer tsErr.Close()

	cfg.Sinks.Discord.WebhookURL = tsErr.URL
	config.GetSettings().SetConfig(cfg)
	if ok := notifier.Notify(ctx, threat); ok {
		t.Errorf("Expected false when discord server returns 400")
	}

	// 4. Invalid URL / network failure
	cfg.Sinks.Discord.WebhookURL = "http://127.0.0.1:9"
	config.GetSettings().SetConfig(cfg)
	if ok := notifier.Notify(ctx, threat); ok {
		t.Errorf("Expected false when discord network error occurs")
	}
}

func TestSlackNotifier(t *testing.T) {
	ctx := context.Background()
	notifier := NewSlackNotifier()

	origConfig := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origConfig)

	// 1. Disabled case
	cfg := origConfig
	cfg.Sinks.Slack.Enabled = false
	cfg.Sinks.Slack.WebhookURL = ""
	config.GetSettings().SetConfig(cfg)

	threat := sampleThreat(models.SeverityCritical, models.JapanRelevanceDirect)
	if ok := notifier.Notify(ctx, threat); !ok {
		t.Errorf("Expected true when slack is disabled")
	}

	// 2. Successful POST with varied configurations
	var lastPayload map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &lastPayload)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	cfg.Sinks.Slack.Enabled = true
	cfg.Sinks.Slack.WebhookURL = ts.URL
	config.GetSettings().SetConfig(cfg)

	testCases := []struct {
		severity  models.Severity
		relevance models.JapanRelevance
		victims   []string
		actors    []string
		title     string
	}{
		{models.SeverityCritical, models.JapanRelevanceDirect, []string{"Company A"}, []string{"Actor X"}, "Title EN"},
		{models.SeverityCritical, models.JapanRelevanceIndirect, nil, nil, ""}, // fallback to title ja, empty victims/actors
		{models.SeverityHigh, models.JapanRelevanceDirect, []string{"Company B"}, []string{"Actor Y"}, "High Threat"},
		{models.SeverityMedium, models.JapanRelevanceNone, []string{"Company C"}, []string{"Actor Z"}, "Medium Threat"},
	}

	for _, tc := range testCases {
		th := sampleThreat(tc.severity, tc.relevance)
		th.VictimOrgs = tc.victims
		th.ThreatActors = tc.actors
		th.Title = tc.title
		if tc.title == "" {
			th.ImpactAnalysis = ""
			th.RecommendedActions = nil
		}
		if ok := notifier.Notify(ctx, th); !ok {
			t.Errorf("Failed to notify slack for case %v / %v", tc.severity, tc.relevance)
		}
	}

	// 3. HTTP Error
	tsErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer tsErr.Close()

	cfg.Sinks.Slack.WebhookURL = tsErr.URL
	config.GetSettings().SetConfig(cfg)
	if ok := notifier.Notify(ctx, threat); ok {
		t.Errorf("Expected false when slack returns 403")
	}

	// 4. Network failure
	cfg.Sinks.Slack.WebhookURL = "http://127.0.0.1:9"
	config.GetSettings().SetConfig(cfg)
	if ok := notifier.Notify(ctx, threat); ok {
		t.Errorf("Expected false on slack network error")
	}
}

func TestNotificationManager(t *testing.T) {
	ctx := context.Background()
	mgr := NewNotificationManager()

	origConfig := config.GetSettings().GetConfig()
	defer config.GetSettings().SetConfig(origConfig)

	// Configure all sinks disabled
	cfg := origConfig
	cfg.Sinks.Discord.Enabled = false
	cfg.Sinks.Discord.WebhookURL = ""
	cfg.Sinks.Slack.Enabled = false
	cfg.Sinks.Slack.WebhookURL = ""
	cfg.Sinks.GenericWebhook.Enabled = false
	cfg.Sinks.GenericWebhook.WebhookURL = ""
	config.GetSettings().SetConfig(cfg)

	threat := sampleThreat(models.SeverityHigh, models.JapanRelevanceDirect)
	// Even if all disabled, dry run or no-op returns true for discord/slack/generic
	if ok := mgr.Dispatch(ctx, threat); !ok {
		t.Errorf("Expected true when dispatching with disabled sinks")
	}
}
