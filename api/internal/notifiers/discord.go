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
		log.Printf("[Discord Dry-Run (Config)] Alert would be sent (lang=%s): [%s] %s", cfg.Pipeline.NotifyLanguage, threat.Severity, titleText)
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

	actions := threat.RecommendedActions
	if isJa {
		actions = threat.RecommendedActionsJa
		if len(actions) == 0 {
			actions = threat.RecommendedActions
		}
	} else if len(actions) == 0 {
		actions = threat.RecommendedActionsJa
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
	if isJa {
		if threat.JapanRelevance == models.JapanRelevanceDirect {
			badges += "🇯🇵 [日本直接標的] "
		} else if threat.JapanRelevance == models.JapanRelevanceIndirect {
			badges += "🌐 [世界規模/間接影響] "
		}
	} else {
		if threat.JapanRelevance == models.JapanRelevanceDirect {
			badges += "🇯🇵 [Targeting Japan] "
		} else if threat.JapanRelevance == models.JapanRelevanceIndirect {
			badges += "🌐 [Global / Indirect] "
		}
	}
	badges += fmt.Sprintf("[%s]", threat.Severity)

	content := ""
	if isJa {
		if threat.JapanRelevance == models.JapanRelevanceDirect && (threat.Severity == models.SeverityCritical || threat.Severity == models.SeverityHigh) {
			content = "🚨 @here **【緊急脅威アラート】日本組織を標的とする攻撃を検知しました**"
		} else if threat.Severity == models.SeverityCritical {
			content = "🚨 @here **【重大脅威アラート】重要インシデントを検知しました**"
		}
	} else {
		if threat.JapanRelevance == models.JapanRelevanceDirect && (threat.Severity == models.SeverityCritical || threat.Severity == models.SeverityHigh) {
			content = "🚨 @here **Critical Threat Incident Alert - Targeted Attack Detected**"
		} else if threat.Severity == models.SeverityCritical {
			content = "🚨 @here **Critical Threat Incident Alert**"
		}
	}

	var srcLabel, relLabel, typeLabel, victimLabel, actorLabel, impactLabel, actionLabel, refLabel string
	if isJa {
		srcLabel = "情報ソース"
		relLabel = "日本関連性"
		typeLabel = "攻撃種別"
		victimLabel = "被害組織"
		actorLabel = "脅威アクター / 攻撃者"
		impactLabel = "日本組織への影響分析"
		actionLabel = "推奨アクション"
		refLabel = "参照リンク"
	} else {
		srcLabel = "Source"
		relLabel = "Japan Relevance"
		typeLabel = "Attack Type"
		victimLabel = "Victim Organization"
		actorLabel = "Threat Actor"
		impactLabel = "Impact Analysis"
		actionLabel = "Recommended Actions"
		refLabel = "Reference Link"
	}

	fields := []map[string]interface{}{
		{"name": srcLabel, "value": fmt.Sprintf("%s (%s)", threat.Item.SourceType, threat.Item.SourceName), "inline": true},
		{"name": relLabel, "value": string(threat.JapanRelevance), "inline": true},
		{"name": typeLabel, "value": orDefault(threat.AttackType, "Unspecified"), "inline": true},
	}

	if len(threat.VictimOrgs) > 0 {
		fields = append(fields, map[string]interface{}{"name": victimLabel, "value": strings.Join(threat.VictimOrgs, ", "), "inline": true})
	}
	if len(threat.ThreatActors) > 0 {
		fields = append(fields, map[string]interface{}{"name": actorLabel, "value": strings.Join(threat.ThreatActors, ", "), "inline": true})
	}
	if impactText != "" {
		fields = append(fields, map[string]interface{}{"name": impactLabel, "value": truncate(impactText, 1000), "inline": false})
	}
	if len(actions) > 0 {
		var acts []string
		for _, a := range actions {
			acts = append(acts, "• "+a)
		}
		fields = append(fields, map[string]interface{}{"name": actionLabel, "value": truncate(strings.Join(acts, "\n"), 1000), "inline": false})
	}
	if threat.Item.URL != "" {
		linkText := "View Source"
		if isJa {
			linkText = "元記事を開く"
		}
		fields = append(fields, map[string]interface{}{"name": refLabel, "value": fmt.Sprintf("[%s](%s)", linkText, threat.Item.URL), "inline": false})
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

func (n *DiscordNotifier) NotifySummary(ctx context.Context, totalAlerts int, maxAlerts int) bool {
	cfg := config.GetSettings().GetConfig()
	webhookURL := cfg.Sinks.Discord.WebhookURL
	if !cfg.Sinks.Discord.Enabled || webhookURL == "" {
		return true
	}
	if cfg.Pipeline.NotifyDryRun {
		log.Printf("[Discord Dry-Run (Config)] Circuit breaker summary alert would be sent: %d alerts (max: %d)", totalAlerts, maxAlerts)
		return true
	}

	isJa := cfg.Pipeline.NotifyLanguage == "ja"
	var title, desc string
	if isJa {
		title = fmt.Sprintf("⚠️ 【大量検知】サーキットブレーカー発動 (%d件超過)", maxAlerts)
		desc = fmt.Sprintf("本収集サイクルにおいて通知上限（%d件）を超える脅威インシデントを検知しました。\n通知の連投・スパムを防止するため、これ以降の個別アラートを集約しました。\n最新のインシデント一覧や詳細な調査結果はダッシュボードをご確認ください。", maxAlerts)
	} else {
		title = fmt.Sprintf("⚠️ [High Volume Alert] Circuit Breaker Triggered (Exceeded %d alerts)", maxAlerts)
		desc = fmt.Sprintf("The threat harvester detected incidents exceeding the alert threshold (%d items) in the current harvesting cycle.\nTo prevent notification flooding, individual notifications have been temporarily grouped.\nPlease inspect the dashboard for full correlation and threat intelligence details.", maxAlerts)
	}

	payload := map[string]interface{}{
		"username": "Threat Harvester CTI",
		"content":  "⚠️ **Circuit Breaker Rate Limiter Activated**",
		"embeds": []map[string]interface{}{
			{
				"title":       title,
				"description": desc,
				"color":       0xFF9900,
				"footer": map[string]string{
					"text": "Threat Harvester Safety Circuit Breaker",
				},
				"timestamp": time.Now().UTC().Format(time.RFC3339),
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
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent
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
