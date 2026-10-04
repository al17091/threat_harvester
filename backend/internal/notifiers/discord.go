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
		badges += "🇯🇵 [日本標的 / 関連] "
	} else if threat.JapanRelevance == models.JapanRelevanceIndirect {
		badges += "🌐 [日本波及 / 警戒] "
	}
	badges += fmt.Sprintf("[%s]", threat.Severity)

	content := ""
	if threat.JapanRelevance == models.JapanRelevanceDirect && (threat.Severity == models.SeverityCritical || threat.Severity == models.SeverityHigh) {
		content = "🚨 @here **日本国内を標的とした重大インシデントを検知しました**"
	} else if threat.Severity == models.SeverityCritical {
		content = "🚨 @here **Critical Threat Incident Alert**"
	}

	fields := []map[string]interface{}{
		{"name": "情報源", "value": fmt.Sprintf("%s (%s)", threat.Item.SourceType, threat.Item.SourceName), "inline": true},
		{"name": "日本への関連性", "value": string(threat.JapanRelevance), "inline": true},
		{"name": "攻撃分類", "value": orDefault(threat.AttackType, "未特定"), "inline": true},
	}

	if len(threat.VictimOrgs) > 0 {
		fields = append(fields, map[string]interface{}{"name": "被害組織", "value": strings.Join(threat.VictimOrgs, ", "), "inline": true})
	}
	if len(threat.ThreatActors) > 0 {
		fields = append(fields, map[string]interface{}{"name": "脅威グループ", "value": strings.Join(threat.ThreatActors, ", "), "inline": true})
	}
	if threat.ImpactAnalysisJa != "" {
		fields = append(fields, map[string]interface{}{"name": "日本への影響分析", "value": truncate(threat.ImpactAnalysisJa, 1000), "inline": false})
	}
	if len(threat.RecommendedActionsJa) > 0 {
		var acts []string
		for _, a := range threat.RecommendedActionsJa {
			acts = append(acts, "• "+a)
		}
		fields = append(fields, map[string]interface{}{"name": "推奨対策", "value": truncate(strings.Join(acts, "\n"), 1000), "inline": false})
	}
	if threat.Item.URL != "" {
		fields = append(fields, map[string]interface{}{"name": "参照元リンク", "value": fmt.Sprintf("[詳細を見る](%s)", threat.Item.URL), "inline": false})
	}

	shortID := threat.ItemID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}

	payload := map[string]interface{}{
		"username": "Threat Harvester (Japan CTI)",
		"content":  content,
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("%s %s", badges, truncate(threat.TitleJa, 200)),
				"description": truncate(threat.SummaryJa, 2000),
				"url":         threat.Item.URL,
				"color":       color,
				"fields":      fields,
				"footer": map[string]string{
					"text": fmt.Sprintf("Harvester ID: %s | Powered by Gemini & Tor CTI", shortID),
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
