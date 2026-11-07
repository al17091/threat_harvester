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

	"github.com/al17091/threat_harvester/api/internal/analyzer"
	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/models"
)

type XMonitorHarvester struct {
	client   *http.Client
	analyzer analyzer.ThreatAnalyzer
}

func NewXMonitorHarvester() *XMonitorHarvester {
	return &XMonitorHarvester{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		analyzer: analyzer.NewDefaultThreatAnalyzer(),
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
		model = "gemini-3.5-flash-lite"
	}

	var items []models.ThreatItem

	for _, qCfg := range cfg.Sources.XMonitor {
		tier := qCfg.ComplianceTier
		if tier == "" {
			tier = config.TierCommercialViaOfficialAPI
		}
		if !qCfg.Enabled || !cfg.Compliance.IsTierEnabled(tier) {
			continue
		}

		provider := strings.ToLower(strings.TrimSpace(qCfg.Type))
		if provider == "" {
			if strings.Contains(qCfg.URL, "searxng") {
				provider = "searxng"
			} else {
				provider = "gemini"
			}
		}

		var jobs []searchJob
		directive := strings.TrimSpace(qCfg.Directive)
		displayName := strings.TrimSpace(qCfg.Name)

		if directive != "" {
			label := displayName
			if label == "" {
				label = models.TruncateRunes(directive, 30)
			}
			log.Printf("[XMonitor] Directive detected for '%s'. Generating AI search queries...", label)
			aiQueries, err := h.analyzer.GenerateSearchQueries(ctx, directive, "x_monitor", 3)
			if err != nil || len(aiQueries) == 0 {
				log.Printf("[XMonitor] AI query fallback for directive '%s': %v", label, err)
				jobs = append(jobs, searchJob{query: directive, directive: directive, displayName: label})
			} else {
				log.Printf("[XMonitor] Directive '%s' expanded into %d AI queries: %v", label, len(aiQueries), aiQueries)
				for _, q := range aiQueries {
					jobs = append(jobs, searchJob{query: q, directive: directive, displayName: label})
				}
			}
			if strings.TrimSpace(qCfg.Query) != "" {
				jobs = append(jobs, searchJob{query: strings.TrimSpace(qCfg.Query), directive: directive, displayName: label})
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

		if provider == "searxng" {
			searxItems, err := h.harvestSearXNGX(ctx, qCfg, jobs, since)
			if err != nil {
				log.Printf("[XMonitor] SearXNG X search error for %s: %v", qCfg.Name, err)
			} else {
				items = append(items, searxItems...)
			}
			continue
		}

		// Provider is Gemini
		if apiKey == "" {
			log.Printf("[XMonitor] Gemini API key not configured. Skipping Gemini search for '%s'.", qCfg.Name)
			continue
		}

		for _, job := range jobs {
			query := job.query
			log.Printf("[XMonitor] Executing Grounded Search for X query: %s", query)

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
    "url": "Direct Tweet URL or source article URL found in the search results (e.g. https://...). Must be a full URL, do not leave empty.",
    "linked_urls": ["Any external URLs, blog links, or advisories mentioned or linked in the tweet/thread (e.g. https://...)"],
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
				GroundingMetadata struct {
					GroundingChunks []struct {
						Web struct {
							URI   string `json:"uri"`
							Title string `json:"title"`
						} `json:"web"`
					} `json:"groundingChunks"`
					WebSearchQueries []string `json:"webSearchQueries"`
				} `json:"groundingMetadata"`
			} `json:"candidates"`
		}

		err = json.NewDecoder(resp.Body).Decode(&geminiResp)
		resp.Body.Close()
		if err != nil || len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
			continue
		}

		candidate := geminiResp.Candidates[0]
		rawText := candidate.Content.Parts[0].Text
		rawText = strings.TrimPrefix(rawText, "```json")
		rawText = strings.TrimPrefix(rawText, "```")
		rawText = strings.TrimSuffix(rawText, "```")
		rawText = strings.TrimSpace(rawText)

		var searchResults []groundedItem
		if err := json.Unmarshal([]byte(rawText), &searchResults); err != nil {
			log.Printf("[XMonitor] JSON parse error: %v (raw: %s)", err, rawText)
			continue
		}

		var chunks []geminiGroundingChunk
		for _, c := range candidate.GroundingMetadata.GroundingChunks {
			chunks = append(chunks, geminiGroundingChunk{
				Web: struct {
					URI   string `json:"uri"`
					Title string `json:"title"`
				}{
					URI:   c.Web.URI,
					Title: c.Web.Title,
				},
			})
		}

		for _, res := range searchResults {
			if res.Title == "" {
				continue
			}

			finalURL := strings.TrimSpace(res.URL)
			if finalURL == "" || !strings.HasPrefix(finalURL, "http") || isGenericDomain(finalURL) {
				if chunkURL := matchGroundingChunkURL(res.Title, res.VictimName, chunks); chunkURL != "" {
					finalURL = chunkURL
				}
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
			sourceName := models.TruncateRunes(fmt.Sprintf("XMonitor:%s", sourceLabel), 30)

			meta := map[string]interface{}{
				"victim": res.VictimName,
				"query":  query,
			}
			if job.directive != "" {
				meta["directive"] = job.directive
			}

			// Collect target links from AI disclosure, finalURL, and summary
			var targetURLs []string
			for _, lu := range res.LinkedURLs {
				if IsCrawleableURL(lu) {
					targetURLs = append(targetURLs, lu)
				}
			}
			if finalURL != "" && IsCrawleableURL(finalURL) {
				targetURLs = append(targetURLs, finalURL)
			}
			targetURLs = append(targetURLs, ExtractURLsFromText(res.Summary)...)

			rawContent := fmt.Sprintf("[%s]\nTitle: %s\nSummary: %s", sourceName, res.Title, res.Summary)
			if len(targetURLs) > 0 {
				enrichedScraped, visitedURLs := FollowAndScrapeLinkedArticles(ctx, targetURLs, 2)
				if enrichedScraped != "" {
					rawContent += "\n\n" + enrichedScraped
				}
				if len(visitedURLs) > 0 {
					meta["linked_urls"] = visitedURLs
					log.Printf("[XMonitor] %s: recursively followed %d links (%d chars)", sourceName, len(visitedURLs), len([]rune(enrichedScraped)))
				}
			}

			item := models.NewThreatItem(
				models.SourceTypeXMonitor,
				sourceName,
				res.Title,
				finalURL,
				res.Summary,
				rawContent,
				pubDate,
				meta,
			)
			items = append(items, item)
		}
		}
	}

	log.Printf("[XMonitor] XMonitorHarvester collected %d items", len(items))
	return items, nil
}

// harvestSearXNGX executes clearnet meta-search via SearXNG for X (Twitter) queries without consuming Gemini API tokens
func (h *XMonitorHarvester) harvestSearXNGX(ctx context.Context, qCfg config.QuerySourceConfig, jobs []searchJob, since *time.Time) ([]models.ThreatItem, error) {
	primaryURL, fallbackURL := ResolveSearXNGBaseURL(qCfg.URL)
	timeoutSec := qCfg.TimeoutSeconds
	if timeoutSec <= 0 {
		timeoutSec = 30
	}

	client := &http.Client{
		Transport: defaultSearxngTransport,
		Timeout:   time.Duration(timeoutSec) * time.Second,
	}

	categories := qCfg.Categories
	if categories == "" {
		categories = "general,news"
	}
	timeRange := strings.TrimSpace(qCfg.TimeRange)
	if timeRange == "" {
		timeRange = "day"
	}

	var items []models.ThreatItem
	seenURLs := make(map[string]bool)

	for _, job := range jobs {
		query := job.query
		// Ensure site filter is present for X monitoring if query doesn't already have it
		if !strings.Contains(query, "site:x.com") && !strings.Contains(query, "site:twitter.com") {
			query = fmt.Sprintf("(%s) (site:x.com OR site:twitter.com)", query)
		}

		log.Printf("[XMonitor] Executing SearXNG X search query: '%s' (Source: %s, Engines: %s, Categories: %s, TimeRange: %s)", query, qCfg.Name, qCfg.Engines, categories, timeRange)
		results, err := QuerySearXNGAPIWithFallback(ctx, client, primaryURL, fallbackURL, query, qCfg.Engines, categories, timeRange)
		if (err != nil || len(results) == 0) && timeRange == "day" {
			log.Printf("[XMonitor] 0 results or error with time_range=day for '%s', retrying with time_range=week", query)
			weekResults, weekErr := QuerySearXNGAPIWithFallback(ctx, client, primaryURL, fallbackURL, query, qCfg.Engines, categories, "week")
			if weekErr == nil && len(weekResults) > 0 {
				results = weekResults
				err = nil
			}
		}
		if err != nil {
			log.Printf("[XMonitor] SearXNG X query '%s' failed: %v", query, err)
			continue
		}

		for _, res := range results {
			if strings.TrimSpace(res.URL) == "" {
				continue
			}
			if seenURLs[res.URL] {
				continue
			}
			seenURLs[res.URL] = true

			if isHistoricalArticle(res.Title, res.Content) {
				continue
			}

			var pubDate *time.Time
			if res.PublishedDate != "" {
				layouts := []string{
					time.RFC3339,
					"2006-01-02T15:04:05Z07:00",
					"2006-01-02 15:04:05",
					"2006-01-02",
				}
				for _, layout := range layouts {
					if t, err := time.Parse(layout, strings.TrimSpace(res.PublishedDate)); err == nil {
						utc := t.UTC()
						pubDate = &utc
						break
					}
				}
			}

			if since != nil && pubDate != nil && pubDate.Before(*since) {
				continue
			}

			if !isCTIRelevant(res.Title + " " + res.Content) {
				continue
			}

			sourceLabel := job.displayName
			if sourceLabel == "" {
				sourceLabel = "国内セキュリティ速報"
			}
			sourceName := models.TruncateRunes(fmt.Sprintf("X:%s", sourceLabel), 30)

			rawContent := fmt.Sprintf("[%s]\nTitle: %s\nSummary: %s\nURL: %s", sourceName, res.Title, res.Content, res.URL)
			meta := map[string]interface{}{
				"is_onion":      false,
				"fetch_status":  "pending",
				"engine":        res.Engine,
				"searxng_query": query,
				"source_engine": res.Engine,
			}
			if len(res.Engines) > 0 {
				meta["engines"] = res.Engines
			}

			item := models.NewThreatItem(
				models.SourceTypeXMonitor,
				sourceName,
				res.Title,
				res.URL,
				res.Content,
				rawContent,
				pubDate,
				meta,
			)
			items = append(items, item)
		}
	}
	return items, nil
}

func (h *XMonitorHarvester) TestConnection(ctx context.Context) bool {
	cfg := config.GetSettings().GetConfig()
	return cfg.AI.GeminiAPIKey != ""
}
