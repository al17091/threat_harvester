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

	"github.com/dapt/information_harvester/backend/internal/analyzer"
	"github.com/dapt/information_harvester/backend/internal/config"
	"github.com/dapt/information_harvester/backend/internal/models"
)

type WebSearchHarvester struct {
	client   *http.Client
	analyzer *analyzer.GeminiThreatAnalyzer
}

func NewWebSearchHarvester() *WebSearchHarvester {
	return &WebSearchHarvester{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		analyzer: analyzer.NewGeminiThreatAnalyzer(),
	}
}

func (h *WebSearchHarvester) Name() string {
	return "Gemini Web Search Grounding"
}

func (h *WebSearchHarvester) SourceType() models.SourceType {
	return models.SourceTypeWebSearch
}

type groundedItem struct {
	Title         string `json:"title"`
	URL           string `json:"url"`
	Summary       string `json:"summary"`
	PublishedDate string `json:"published_date"`
	VictimName    string `json:"victim_name"`
}

type searchJob struct {
	query       string
	directive   string
	displayName string
}

func (h *WebSearchHarvester) Harvest(ctx context.Context, since *time.Time) ([]models.ThreatItem, error) {
	cfg := config.GetSettings().GetConfig()
	apiKey := cfg.AI.GeminiAPIKey
	model := cfg.AI.GeminiModel
	if model == "" {
		model = "gemini-2.5-flash"
	}

	if apiKey == "" {
		log.Println("[WebSearch] Gemini API key not configured. Skipping WebSearchHarvester.")
		return nil, nil
	}

	var items []models.ThreatItem

	for _, qCfg := range cfg.Sources.WebSearch {
		if !qCfg.Enabled {
			continue
		}

		var jobs []searchJob
		directive := strings.TrimSpace(qCfg.Directive)
		displayName := strings.TrimSpace(qCfg.Name)

		if directive != "" {
			label := displayName
			if label == "" {
				label = models.TruncateRunes(directive, 30)
			}
			log.Printf("[WebSearch] Directive detected for '%s'. Generating AI search queries...", label)
			aiQueries, err := h.analyzer.GenerateSearchQueries(ctx, directive, "web_search", 3)
			if err != nil || len(aiQueries) == 0 {
				log.Printf("[WebSearch] AI query fallback for directive '%s': %v", label, err)
				jobs = append(jobs, searchJob{query: directive, directive: directive, displayName: label})
			} else {
				log.Printf("[WebSearch] Directive '%s' expanded into %d AI queries: %v", label, len(aiQueries), aiQueries)
				for _, q := range aiQueries {
					jobs = append(jobs, searchJob{query: q, directive: directive, displayName: label})
				}
			}
		} else if strings.TrimSpace(qCfg.Query) != "" {
			label := displayName
			if label == "" {
				label = qCfg.Query
			}
			jobs = append(jobs, searchJob{query: strings.TrimSpace(qCfg.Query), directive: "", displayName: label})
		} else {
			continue
		}

		for _, job := range jobs {
			query := job.query
			log.Printf("[WebSearch] Executing Grounded Search for query: %s", query)

		currentDate := time.Now().UTC().Format("2006-01-02")
		prompt := fmt.Sprintf(`
Today's date is %s. You are a cyber threat intelligence researcher monitoring recent and active cyber threats against Japan.
Search for breaking and recent cyber attacks, ransomware incidents, data breaches, and zero-day advisories targeting Japanese companies, government, or infrastructure.

CRITICAL INSTRUCTION ON TIMESTAMPS:
- Prioritize newly reported active incidents from the current year (2026) or within the last few weeks.
- Do NOT output old historical archive incidents from previous years (such as 2023 or 2024) unless there is a fresh disclosure published today (%s).
- Ensure "published_date" reflects the actual date of the report in ISO-8601 (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ).

Query context: %s

Extract distinct recent incidents found (up to 5 incidents per query).
For each incident, output a JSON array of objects with the following schema:
[
  {
    "title": "Incident title in English or Japanese",
    "url": "Source URL if available or reputable domain",
    "summary": "Concise summary of the incident and impact on Japanese entities",
    "published_date": "YYYY-MM-DD or estimated ISO date",
    "victim_name": "Targeted Japanese organization if known"
  }
]
Only return valid JSON array without Markdown code block formatting.
`, currentDate, currentDate, query)

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
			log.Printf("[WebSearch] Request error for %s: %v", query, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			log.Printf("[WebSearch] Gemini API status %d: %s", resp.StatusCode, string(body))
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
			log.Printf("[WebSearch] JSON parse error: %v (raw: %s)", err, rawText)
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

			sourceLabel := job.displayName
			if sourceLabel == "" {
				sourceLabel = query
			}
			sourceName := models.TruncateRunes(fmt.Sprintf("WebSearch:%s", sourceLabel), 30)

			meta := map[string]interface{}{
				"victim": res.VictimName,
				"query":  query,
			}
			if job.directive != "" {
				meta["directive"] = job.directive
			}

			item := models.NewThreatItem(
				models.SourceTypeWebSearch,
				sourceName,
				res.Title,
				res.URL,
				res.Summary,
				"",
				pubDate,
				meta,
			)
			items = append(items, item)
		}
		}
	}

	log.Printf("[WebSearch] WebSearchHarvester collected %d items", len(items))
	return items, nil
}

func (h *WebSearchHarvester) TestConnection(ctx context.Context) bool {
	cfg := config.GetSettings().GetConfig()
	return cfg.AI.GeminiAPIKey != ""
}
