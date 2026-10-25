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

	isJa := cfg.Pipeline.NotifyLanguage == "ja"

	titleText := threat.Title
	if isJa {
		titleText = threat.TitleJa
		if titleText == "" {
			titleText = threat.Title
		}
	} else if titleText == "" {
		titleText = threat.TitleJa
	}

	if cfg.Pipeline.NotifyDryRun {
		log.Printf("[Slack Dry-Run (Config)] Alert would be sent (lang=%s): [%s] %s", cfg.Pipeline.NotifyLanguage, threat.Severity, titleText)
		return true
	}

	summaryText := threat.Summary
	if isJa {
		summaryText = threat.SummaryJa
		if summaryText == "" {
			summaryText = threat.Summary
		}
	} else if summaryText == "" {
		summaryText = threat.SummaryJa
	}

	impactText := threat.ImpactAnalysis
	if isJa {
		impactText = threat.ImpactAnalysisJa
		if impactText == "" {
			impactText = threat.ImpactAnalysis
		}
	} else if impactText == "" {
		impactText = threat.ImpactAnalysisJa
	}

	headerPrefix := ""
	if isJa {
		if threat.JapanRelevance == models.JapanRelevanceDirect {
			headerPrefix = "🇯🇵 [日本直接標的] "
		} else if threat.JapanRelevance == models.JapanRelevanceIndirect {
			headerPrefix = "🌐 [世界規模/間接影響] "
		}
	} else {
		if threat.JapanRelevance == models.JapanRelevanceDirect {
			headerPrefix = "🇯🇵 [Targeting Japan] "
		} else if threat.JapanRelevance == models.JapanRelevanceIndirect {
			headerPrefix = "🌐 [Global / Indirect] "
		}
	}

	mention := ""
	if threat.JapanRelevance == models.JapanRelevanceDirect && (threat.Severity == models.SeverityCritical || threat.Severity == models.SeverityHigh) {
		mention = "<!channel> "
	} else if threat.Severity == models.SeverityCritical {
		mention = "<!here> "
	}

	victims := "Unspecified"
	if isJa {
		victims = "指定なし"
	}
	if len(threat.VictimOrgs) > 0 {
		victims = strings.Join(threat.VictimOrgs, ", ")
	}
	actors := "Unspecified"
	if isJa {
		actors = "特定なし"
	}
	if len(threat.ThreatActors) > 0 {
		actors = strings.Join(threat.ThreatActors, ", ")
	}

	var sumLabel, relLabel, srcLabel, vicLabel, actLabel, impLabel, btnLabel string
	if isJa {
		sumLabel = "概要 / 要約:"
		relLabel = "日本関連性:"
		srcLabel = "情報ソース:"
		vicLabel = "被害組織:"
		actLabel = "脅威アクター / 攻撃グループ:"
		impLabel = "日本への影響分析:"
		btnLabel = "元記事を開く"
	} else {
		sumLabel = "Summary:"
		relLabel = "Japan Relevance:"
		srcLabel = "Source:"
		vicLabel = "Victims:"
		actLabel = "Threat Actors:"
		impLabel = "Impact Analysis:"
		btnLabel = "View Source Link"
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
				"text": fmt.Sprintf("%s*%s*\n%s", mention, sumLabel, summaryText),
			},
		},
		{
			"type": "section",
			"fields": []map[string]interface{}{
				{"type": "mrkdwn", "text": fmt.Sprintf("*%s*\n%s", relLabel, threat.JapanRelevance)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*%s*\n%s (%s)", srcLabel, threat.Item.SourceType, threat.Item.SourceName)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*%s*\n%s", vicLabel, victims)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*%s*\n%s", actLabel, actors)},
			},
		},
	}

	if impactText != "" {
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*%s*\n%s", impLabel, impactText),
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
						"text":  btnLabel,
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

func (n *SlackNotifier) NotifySummary(ctx context.Context, totalAlerts int, maxAlerts int) bool {
	cfg := config.GetSettings().GetConfig()
	webhookURL := cfg.Sinks.Slack.WebhookURL
	if !cfg.Sinks.Slack.Enabled || webhookURL == "" {
		return true
	}
	if cfg.Pipeline.NotifyDryRun {
		log.Printf("[Slack Dry-Run (Config)] Circuit breaker summary alert would be sent: %d alerts (max: %d)", totalAlerts, maxAlerts)
		return true
	}

	isJa := cfg.Pipeline.NotifyLanguage == "ja"
	var title, desc string
	if isJa {
		title = fmt.Sprintf("⚠️ 【大量検知】サーキットブレーカー発動 (%d件超過)", maxAlerts)
		desc = fmt.Sprintf("本収集サイクルにおいて通知上限（%d件）を超える脅威インシデントを検知しました。\n通知スパム防止のため、これ以降の個別アラートを集約しました。\n最新のインシデント一覧や詳細な調査結果はダッシュボードをご確認ください。", maxAlerts)
	} else {
		title = fmt.Sprintf("⚠️ [High Volume Alert] Circuit Breaker Triggered (Exceeded %d alerts)", maxAlerts)
		desc = fmt.Sprintf("The threat harvester detected incidents exceeding the alert threshold (%d items) in the current harvesting cycle.\nTo prevent notification flooding, individual notifications have been temporarily grouped.\nPlease inspect the dashboard for full correlation and threat intelligence details.", maxAlerts)
	}

	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]interface{}{
				"type":  "plain_text",
				"text":  title,
				"emoji": true,
			},
		},
		{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": desc,
			},
		},
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
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
