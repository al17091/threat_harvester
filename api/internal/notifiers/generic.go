package notifiers

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/models"
)

type GenericNotifier struct {
	client *http.Client
}

func NewGenericNotifier() *GenericNotifier {
	return &GenericNotifier{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *GenericNotifier) Notify(ctx context.Context, threat *models.EnrichedThreat) bool {
	cfg := config.GetSettings().GetConfig()
	webhookURL := cfg.Sinks.GenericWebhook.WebhookURL
	if !cfg.Sinks.GenericWebhook.Enabled || webhookURL == "" {
		return true
	}
	if cfg.Pipeline.NotifyDryRun {
		log.Printf("[GenericWebhook Dry-Run (Config)] Alert would be sent: [%s] %s", threat.Severity, threat.TitleJa)
		return true
	}

	body, err := json.Marshal(threat)
	if err != nil {
		return false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ThreatHarvester-Webhook/1.0")

	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("[GenericWebhook] Failed to post webhook: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Printf("[GenericWebhook] Successfully sent payload for: %s", threat.TitleJa)
		return true
	}
	log.Printf("[GenericWebhook] Webhook returned status: %d", resp.StatusCode)
	return false
}

type NotificationManager struct {
	discord *DiscordNotifier
	slack   *SlackNotifier
	generic *GenericNotifier
}

func NewNotificationManager() *NotificationManager {
	return &NotificationManager{
		discord: NewDiscordNotifier(),
		slack:   NewSlackNotifier(),
		generic: NewGenericNotifier(),
	}
}

func (m *NotificationManager) Dispatch(ctx context.Context, threat *models.EnrichedThreat) bool {
	dOk := m.discord.Notify(ctx, threat)
	sOk := m.slack.Notify(ctx, threat)
	gOk := m.generic.Notify(ctx, threat)
	return dOk || sOk || gOk
}

func (m *NotificationManager) DispatchSummary(ctx context.Context, totalAlerts int, maxAlerts int) bool {
	dOk := m.discord.NotifySummary(ctx, totalAlerts, maxAlerts)
	sOk := m.slack.NotifySummary(ctx, totalAlerts, maxAlerts)
	return dOk || sOk
}
