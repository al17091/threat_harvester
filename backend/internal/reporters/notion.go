package reporters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dapt/information_harvester/backend/internal/config"
	"github.com/dapt/information_harvester/backend/internal/models"
)

type NotionReporter struct {
	client *http.Client
}

func NewNotionReporter() *NotionReporter {
	return &NotionReporter{
		client: &http.Client{Timeout: 25 * time.Second},
	}
}

func (r *NotionReporter) IsConfigured() bool {
	cfg := config.GetSettings().GetConfig()
	return cfg.Sinks.Notion.Enabled && cfg.Sinks.Notion.APIKey != "" && cfg.Sinks.Notion.DatabaseID != ""
}

func (r *NotionReporter) CreateIncidentPage(ctx context.Context, threat *models.EnrichedThreat) (string, error) {
	cfg := config.GetSettings().GetConfig()
	apiKey := cfg.Sinks.Notion.APIKey
	databaseID := cfg.Sinks.Notion.DatabaseID

	if apiKey == "" || databaseID == "" {
		log.Printf("[Notion Dry-Run] Notion is not configured. Would publish: %s", threat.TitleJa)
		return "", fmt.Errorf("notion credentials not configured")
	}

	properties := map[string]interface{}{
		"Name": map[string]interface{}{
			"title": []map[string]interface{}{
				{"type": "text", "text": map[string]string{"content": truncate(threat.TitleJa, 100)}},
			},
		},
		"Severity": map[string]interface{}{
			"select": map[string]string{"name": string(threat.Severity)},
		},
		"Japan Relevance": map[string]interface{}{
			"select": map[string]string{"name": string(threat.JapanRelevance)},
		},
	}

	if threat.AttackType != "" {
		properties["Attack Type"] = map[string]interface{}{
			"select": map[string]string{"name": truncate(threat.AttackType, 100)},
		}
	}

	if len(threat.VictimOrgs) > 0 {
		var victims []map[string]string
		for i, v := range threat.VictimOrgs {
			if i >= 5 {
				break
			}
			victims = append(victims, map[string]string{"name": truncate(strings.ReplaceAll(v, ",", ""), 100)})
		}
		properties["Victims"] = map[string]interface{}{"multi_select": victims}
	}

	if len(threat.ThreatActors) > 0 {
		var actors []map[string]string
		for i, a := range threat.ThreatActors {
			if i >= 5 {
				break
			}
			actors = append(actors, map[string]string{"name": truncate(strings.ReplaceAll(a, ",", ""), 100)})
		}
		properties["Threat Actors"] = map[string]interface{}{"multi_select": actors}
	}

	if threat.Item.SourceName != "" {
		srcText := fmt.Sprintf("%s (%s)", threat.Item.SourceType, truncate(threat.Item.SourceName, 50))
		properties["Source"] = map[string]interface{}{
			"rich_text": []map[string]interface{}{
				{"type": "text", "text": map[string]string{"content": srcText}},
			},
		}
	}

	if threat.Item.URL != "" {
		properties["URL"] = map[string]string{"url": threat.Item.URL}
	}

	if threat.Item.PublishedAt != nil {
		properties["Published Date"] = map[string]interface{}{
			"date": map[string]string{"start": threat.Item.PublishedAt.Format("2006-01-02")},
		}
	}

	children := []map[string]interface{}{
		{
			"object": "block",
			"type":   "heading_2",
			"heading_2": map[string]interface{}{
				"rich_text": []map[string]interface{}{
					{"type": "text", "text": map[string]string{"content": "📋 概要 (Executive Summary)"}},
				},
			},
		},
		{
			"object": "block",
			"type":   "paragraph",
			"paragraph": map[string]interface{}{
				"rich_text": []map[string]interface{}{
					{"type": "text", "text": map[string]string{"content": threat.SummaryJa}},
				},
			},
		},
	}

	if threat.ImpactAnalysisJa != "" {
		children = append(children,
			map[string]interface{}{
				"object": "block",
				"type":   "heading_2",
				"heading_2": map[string]interface{}{
					"rich_text": []map[string]interface{}{
						{"type": "text", "text": map[string]string{"content": "🎯 日本国内への影響分析 (Impact to Japan)"}},
					},
				},
			},
			map[string]interface{}{
				"object": "block",
				"type":   "paragraph",
				"paragraph": map[string]interface{}{
					"rich_text": []map[string]interface{}{
						{"type": "text", "text": map[string]string{"content": threat.ImpactAnalysisJa}},
					},
				},
			},
		)
	}

	if len(threat.RecommendedActionsJa) > 0 {
		children = append(children, map[string]interface{}{
			"object": "block",
			"type":   "heading_2",
			"heading_2": map[string]interface{}{
				"rich_text": []map[string]interface{}{
					{"type": "text", "text": map[string]string{"content": "🛡️ 推奨対策 (Recommended Actions)"}},
				},
			},
		})
		for i, act := range threat.RecommendedActionsJa {
			if i >= 5 {
				break
			}
			children = append(children, map[string]interface{}{
				"object": "block",
				"type":   "bulleted_list_item",
				"bulleted_list_item": map[string]interface{}{
					"rich_text": []map[string]interface{}{
						{"type": "text", "text": map[string]string{"content": act}},
					},
				},
			})
		}
	}

	if threat.Item.URL != "" {
		children = append(children, map[string]interface{}{
			"object": "block",
			"type":   "bookmark",
			"bookmark": map[string]string{
				"url": threat.Item.URL,
			},
		})
	}

	payload := map[string]interface{}{
		"parent":     map[string]string{"database_id": databaseID},
		"properties": properties,
		"children":   children,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.notion.com/v1/pages", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiKey))
	req.Header.Set("Notion-Version", "2022-06-28")
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("notion request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("notion api error (%d): %s", resp.StatusCode, string(respBody))
	}

	var resData struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&resData)
	log.Printf("[Notion] Successfully created incident page %s for: %s", resData.ID, threat.TitleJa)
	return resData.ID, nil
}

func truncate(s string, max int) string {
	return models.TruncateRunes(s, max)
}
