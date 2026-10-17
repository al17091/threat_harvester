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

type SlackNotifier struct {
	client *http.Client
}

func NewSlackNotifier() *SlackNotifier {
	return &SlackNotifier{
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (n *SlackNotifier) Notify(ctx context.Context, threat *models.EnrichedThreat) bool {
	cfg := config.GetSettings().GetConfig()
	webhookURL := cfg.Sinks.Slack.WebhookURL
	if !cfg.Sinks.Slack.Enabled || webhookURL == "" {
		return true
	}

	headerPrefix := ""
	if threat.JapanRelevance == models.JapanRelevanceDirect {
		headerPrefix = "🇯🇵 [Targeting Japan] "
	} else if threat.JapanRelevance == models.JapanRelevanceIndirect {
		headerPrefix = "🌐 [Global / Indirect] "
	}

	mention := ""
	if threat.JapanRelevance == models.JapanRelevanceDirect && (threat.Severity == models.SeverityCritical || threat.Severity == models.SeverityHigh) {
		mention = "<!channel> "
	} else if threat.Severity == models.SeverityCritical {
		mention = "<!here> "
	}

	victims := "Unspecified"
	if len(threat.VictimOrgs) > 0 {
		victims = strings.Join(threat.VictimOrgs, ", ")
	}
	actors := "Unspecified"
	if len(threat.ThreatActors) > 0 {
		actors = strings.Join(threat.ThreatActors, ", ")
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

	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]interface{}{
				"type":  "plain_text",
				"text":  fmt.Sprintf("%s[%s] %s", headerPrefix, threat.Severity, truncate(titleText, 80)),
				"emoji": true,
			},
		},
		{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("%s*Summary:*\n%s", mention, summaryText),
			},
		},
		{
			"type": "section",
			"fields": []map[string]interface{}{
				{"type": "mrkdwn", "text": fmt.Sprintf("*Japan Relevance:*\n%s", threat.JapanRelevance)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Source:*\n%s (%s)", threat.Item.SourceType, threat.Item.SourceName)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Victims:*\n%s", victims)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Threat Actors:*\n%s", actors)},
			},
		},
	}

	if impactText != "" {
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Impact Analysis:*\n%s", impactText),
			},
		})
	}

	if threat.Item.URL != "" {
		blocks = append(blocks, map[string]interface{}{
			"type": "actions",
			"elements": []map[string]interface{}{
				{
					"type": "button",
					"text": map[string]interface{}{
						"type":  "plain_text",
						"text":  "View Source Link",
						"emoji": true,
					},
					"url": threat.Item.URL,
				},
			},
		})
	}

	payload := map[string]interface{}{"blocks": blocks}
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
		log.Printf("[Slack] Failed to post webhook: %v", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		log.Printf("[Slack] Successfully sent alert for: %s", threat.TitleJa)
		return true
	}
	log.Printf("[Slack] Webhook returned status: %d", resp.StatusCode)
	return false
}
