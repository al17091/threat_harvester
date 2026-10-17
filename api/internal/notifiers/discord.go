package notifiers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/models"
)

type DiscordNotifier struct {
	client *http.Client
}

func NewDiscordNotifier() *DiscordNotifier {
	return &DiscordNotifier{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *DiscordNotifier) Notify(ctx context.Context, threat *models.EnrichedThreat) bool {
	cfg := config.GetSettings().GetConfig()
	webhookURL := cfg.Sinks.Discord.WebhookURL
	if !cfg.Sinks.Discord.Enabled || webhookURL == "" {
		log.Printf("[Discord Dry-Run] Alert would be sent: [%s] %s", threat.Severity, threat.TitleJa)
		return true
	}

	var color int
	if threat.JapanRelevance == models.JapanRelevanceDirect || threat.Severity == models.SeverityCritical {
		color = 0xFF0033
	} else if threat.Severity == models.SeverityHigh {
		color = 0xFFA500
	} else if threat.Severity == models.SeverityMedium {
		color = 0x3399FF
	} else {
		color = 0x808080
	}

	badges := ""
	if threat.JapanRelevance == models.JapanRelevanceDirect {
		badges += "🇯🇵 [Targeting Japan] "
	} else if threat.JapanRelevance == models.JapanRelevanceIndirect {
		badges += "🌐 [Global / Indirect] "
	}
	badges += fmt.Sprintf("[%s]", threat.Severity)

	content := ""
	if threat.JapanRelevance == models.JapanRelevanceDirect && (threat.Severity == models.SeverityCritical || threat.Severity == models.SeverityHigh) {
		content = "🚨 @here **Critical Threat Incident Alert - Targeted Attack Detected**"
	} else if threat.Severity == models.SeverityCritical {
		content = "🚨 @here **Critical Threat Incident Alert**"
	}

	titleText := threat.Title
	if titleText == "" {
		titleText = threat.TitleJa
	}
	summaryText := threat.Summary
	if summaryText == "" {
		summaryText = threat.SummaryJa
	}
	impactText := threat.ImpactAnalysis
	if impactText == "" {
		impactText = threat.ImpactAnalysisJa
	}
	actions := threat.RecommendedActions
	if len(actions) == 0 {
		actions = threat.RecommendedActionsJa
	}

	fields := []map[string]interface{}{
		{"name": "Source", "value": fmt.Sprintf("%s (%s)", threat.Item.SourceType, threat.Item.SourceName), "inline": true},
		{"name": "Japan Relevance", "value": string(threat.JapanRelevance), "inline": true},
		{"name": "Attack Type", "value": orDefault(threat.AttackType, "Unspecified"), "inline": true},
	}

	if len(threat.VictimOrgs) > 0 {
		fields = append(fields, map[string]interface{}{"name": "Victim Organization", "value": strings.Join(threat.VictimOrgs, ", "), "inline": true})
	}
	if len(threat.ThreatActors) > 0 {
		fields = append(fields, map[string]interface{}{"name": "Threat Actor", "value": strings.Join(threat.ThreatActors, ", "), "inline": true})
	}
	if impactText != "" {
		fields = append(fields, map[string]interface{}{"name": "Impact Analysis", "value": truncate(impactText, 1000), "inline": false})
	}
	if len(actions) > 0 {
		var acts []string
		for _, a := range actions {
			acts = append(acts, "• "+a)
		}
		fields = append(fields, map[string]interface{}{"name": "Recommended Actions", "value": truncate(strings.Join(acts, "\n"), 1000), "inline": false})
	}
	if threat.Item.URL != "" {
		fields = append(fields, map[string]interface{}{"name": "Reference Link", "value": fmt.Sprintf("[View Source](%s)", threat.Item.URL), "inline": false})
	}

	shortID := threat.ItemID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}

	payload := map[string]interface{}{
		"username": "Threat Harvester CTI",
		"content":  content,
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("%s %s", badges, truncate(titleText, 200)),
				"description": truncate(summaryText, 2000),
				"url":         threat.Item.URL,
				"color":       color,
				"fields":      fields,
				"footer": map[string]string{
					"text": fmt.Sprintf("Harvester ID: %s | Threat Harvester Bot", shortID),
				},
				"timestamp": threat.AnalyzedAt.Format(time.RFC3339),
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("[Discord] Failed to post webhook: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		log.Printf("[Discord] Successfully sent alert for: %s", threat.TitleJa)
		return true
	}
	log.Printf("[Discord] Webhook returned status: %d", resp.StatusCode)
	return false
}

func orDefault(val, def string) string {
	if val == "" {
		return def
	}
	return val
}

func truncate(s string, max int) string {
	return models.TruncateRunes(s, max)
}
