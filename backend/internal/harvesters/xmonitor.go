package harvesters

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

type XMonitorHarvester struct {
	client *http.Client
}

func NewXMonitorHarvester() *XMonitorHarvester {
	return &XMonitorHarvester{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

func (h *XMonitorHarvester) Name() string {
	return "X (Twitter) Grounded Monitor"
}

func (h *XMonitorHarvester) SourceType() models.SourceType {
	return models.SourceTypeXMonitor
}

func (h *XMonitorHarvester) Harvest(ctx context.Context, since *time.Time) ([]models.ThreatItem, error) {
	cfg := config.GetSettings().GetConfig()
	apiKey := cfg.AI.GeminiAPIKey
	model := cfg.AI.GeminiModel
	if model == "" {
		model = "gemini-2.5-flash"
	}

	if apiKey == "" {
		log.Println("[XMonitor] Gemini API key not configured. Skipping XMonitorHarvester.")
		return nil, nil
	}

	var items []models.ThreatItem

	for _, qCfg := range cfg.Sources.XMonitor {
		if !qCfg.Enabled {
			continue
		}

		query := qCfg.Query
		log.Printf("[XMonitor] Running Gemini Grounded Search for X: %s", query)

		currentDate := time.Now().UTC().Format("2006-01-02")
		prompt := fmt.Sprintf(`
Today's date is %s. You are a cybersecurity intelligence analyst monitoring security researcher posts and breaking threat alerts on X (Twitter).
Search for recent tweets, threads, and reports regarding cyber attacks, zero-days, or data leaks related to: %s

CRITICAL INSTRUCTION ON TIMESTAMPS:
- Prioritize newly reported active incidents from the current year (2026) or within the last few weeks.
- Do NOT output old historical archive incidents from previous years (such as 2023 or 2024) unless there is a fresh disclosure published today (%s).
- Ensure "published_date" reflects the actual date of the tweet/disclosure in ISO-8601 (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ).

Extract distinct recent incidents found (up to 5 posts/incidents per query).
For each incident, output a JSON array of objects with the following schema:
[
  {
    "title": "Concise headline of the threat disclosure from X",
    "url": "Tweet URL or source URL",
    "summary": "Key details of the disclosure and significance to Japanese defenders",
    "published_date": "YYYY-MM-DD or estimated ISO date",
    "victim_name": "Targeted organization if mentioned"
  }
]
Only return valid JSON array without Markdown code block formatting.
`, currentDate, query, currentDate)

		reqPayload := map[string]interface{}{
			"contents": []map[string]interface{}{
				{
					"parts": []map[string]interface{}{
						{"text": prompt},
					},
				},
			},
			"tools": []map[string]interface{}{
				{"googleSearch": map[string]interface{}{}},
			},
		}

		payloadBytes, err := json.Marshal(reqPayload)
		if err != nil {
			continue
		}

		apiURL := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, apiKey)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(payloadBytes))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := h.client.Do(req)
		if err != nil {
			log.Printf("[XMonitor] Request error for %s: %v", query, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			log.Printf("[XMonitor] Gemini API status %d: %s", resp.StatusCode, string(body))
			continue
		}

		var geminiResp struct {
			Candidates []struct {
				Content struct {
					Parts []struct {
						Text string `json:"text"`
					} `json:"parts"`
				} `json:"content"`
			} `json:"candidates"`
		}

		err = json.NewDecoder(resp.Body).Decode(&geminiResp)
		resp.Body.Close()
		if err != nil || len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
			continue
		}

		rawText := geminiResp.Candidates[0].Content.Parts[0].Text
		rawText = strings.TrimPrefix(rawText, "```json")
		rawText = strings.TrimPrefix(rawText, "```")
		rawText = strings.TrimSuffix(rawText, "```")
		rawText = strings.TrimSpace(rawText)

		var searchResults []groundedItem
		if err := json.Unmarshal([]byte(rawText), &searchResults); err != nil {
			log.Printf("[XMonitor] JSON parse error: %v (raw: %s)", err, rawText)
			continue
		}

		for _, res := range searchResults {
			if res.Title == "" {
				continue
			}

			var pubDate *time.Time
			if res.PublishedDate != "" {
				if t, err := time.Parse("2006-01-02", res.PublishedDate); err == nil {
					utc := t.UTC()
					pubDate = &utc
				}
			}

			sourceName := models.TruncateRunes(fmt.Sprintf("XMonitor:%s", query), 30)

			item := models.NewThreatItem(
				models.SourceTypeXMonitor,
				sourceName,
				res.Title,
				res.URL,
				res.Summary,
				"",
				pubDate,
				map[string]interface{}{
					"victim": res.VictimName,
					"query":  query,
				},
			)
			items = append(items, item)
		}
	}

	log.Printf("[XMonitor] XMonitorHarvester collected %d items", len(items))
	return items, nil
}

func (h *XMonitorHarvester) TestConnection(ctx context.Context) bool {
	cfg := config.GetSettings().GetConfig()
	return cfg.AI.GeminiAPIKey != ""
}
