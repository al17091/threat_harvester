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

	"github.com/dapt/information_harvester/backend/internal/config"
	"github.com/dapt/information_harvester/backend/internal/models"
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
		headerPrefix = "🇯🇵 [日本標的] "
	} else if threat.JapanRelevance == models.JapanRelevanceIndirect {
		headerPrefix = "🌐 [国内波及] "
	}

	mention := ""
	if threat.JapanRelevance == models.JapanRelevanceDirect && (threat.Severity == models.SeverityCritical || threat.Severity == models.SeverityHigh) {
		mention = "<!channel> "
	} else if threat.Severity == models.SeverityCritical {
		mention = "<!here> "
	}

	victims := "未特定"
	if len(threat.VictimOrgs) > 0 {
		victims = strings.Join(threat.VictimOrgs, ", ")
	}
	actors := "未特定"
	if len(threat.ThreatActors) > 0 {
		actors = strings.Join(threat.ThreatActors, ", ")
	}

	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]interface{}{
				"type":  "plain_text",
				"text":  fmt.Sprintf("%s[%s] %s", headerPrefix, threat.Severity, truncate(threat.TitleJa, 80)),
				"emoji": true,
			},
		},
		{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("%s*概要:*\n%s", mention, threat.SummaryJa),
			},
		},
		{
			"type": "section",
			"fields": []map[string]interface{}{
				{"type": "mrkdwn", "text": fmt.Sprintf("*日本関連性:*\n%s", threat.JapanRelevance)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*情報源:*\n%s (%s)", threat.Item.SourceType, threat.Item.SourceName)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*被害組織:*\n%s", victims)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*攻撃グループ:*\n%s", actors)},
			},
		},
	}

	if threat.ImpactAnalysisJa != "" {
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*国内影響分析:*\n%s", threat.ImpactAnalysisJa),
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
						"text":  "詳細ソースを見る",
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
