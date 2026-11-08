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
	"sync"
	"time"

	"github.com/al17091/threat_harvester/api/internal/analyzer"
	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/models"
)

type WebSearchHarvester struct {
	client     *http.Client
	analyzer   analyzer.ThreatAnalyzer
	lastRunMu  sync.Mutex
	lastRunMap map[string]time.Time
}

func NewWebSearchHarvester() *WebSearchHarvester {
	return &WebSearchHarvester{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		analyzer:   analyzer.NewDefaultThreatAnalyzer(),
		lastRunMap: make(map[string]time.Time),
	}
}

func (h *WebSearchHarvester) Name() string {
	return "Gemini Web Search Grounding"
}

func (h *WebSearchHarvester) SourceType() models.SourceType {
	return models.SourceTypeWebSearch
}

type groundedItem struct {
	Title         string   `json:"title"`
	URL           string   `json:"url"`
	LinkedURLs    []string `json:"linked_urls,omitempty"`
	Summary       string   `json:"summary"`
	PublishedDate string   `json:"published_date"`
	VictimName    string   `json:"victim_name"`
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
		model = "gemini-3.5-flash-lite"
	}

	var items []models.ThreatItem

	for _, qCfg := range cfg.Sources.WebSearch {
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
			} else if apiKey != "" {
				provider = "gemini"
			} else {
				provider = "searxng"
			}
		}

		// Interval handling
		intervalMin := qCfg.IntervalMinutes
		if intervalMin <= 0 {
			if provider == "gemini" {
				intervalMin = 240 // 4 hours default for Gemini Grounding
			} else {
				intervalMin = 0 // SearXNG can run every cycle by default
			}
		}

		if intervalMin > 0 {
			targetKey := qCfg.Name + ":" + qCfg.Directive + ":" + qCfg.Query
			h.lastRunMu.Lock()
			lastRun, ok := h.lastRunMap[targetKey]
			if ok && time.Since(lastRun) < time.Duration(intervalMin)*time.Minute {
				h.lastRunMu.Unlock()
				log.Printf("[WebSearch] Skipping '%s': interval %dm not yet elapsed (last ran %s ago)", qCfg.Name, intervalMin, time.Since(lastRun).Round(time.Minute))
				continue
			}
			h.lastRunMap[targetKey] = time.Now().UTC()
			h.lastRunMu.Unlock()
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
			searxItems, err := h.harvestSearXNGWeb(ctx, qCfg, jobs, since)
			if err != nil {
				log.Printf("[WebSearch] SearXNG web search error for %s: %v", qCfg.Name, err)
			} else {
				items = append(items, searxItems...)
			}
			continue
		}

		// Provider is Gemini
		if apiKey == "" {
			log.Printf("[WebSearch] Gemini API key not configured. Skipping Gemini search for '%s'.", qCfg.Name)
			continue
		}

		geminiItems, err := h.harvestGeminiGrounded(ctx, qCfg, jobs, model, apiKey, since)
		if err != nil {
			log.Printf("[WebSearch] Gemini search error for %s: %v", qCfg.Name, err)
		} else {
			items = append(items, geminiItems...)
		}
	}

	log.Printf("[WebSearch] WebSearchHarvester collected %d items", len(items))
	return items, nil
}

// harvestSearXNGWeb executes clearnet meta-search via SearXNG format=json API (zero cost, no darkweb)
func (h *WebSearchHarvester) harvestSearXNGWeb(ctx context.Context, qCfg config.QuerySourceConfig, jobs []searchJob, since *time.Time) ([]models.ThreatItem, error) {
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
		log.Printf("[WebSearch] Executing SearXNG web search query: '%s' (Source: %s, Engines: %s, Categories: %s, TimeRange: %s)", job.query, qCfg.Name, qCfg.Engines, categories, timeRange)
		results, err := QuerySearXNGAPIWithFallback(ctx, client, primaryURL, fallbackURL, job.query, qCfg.Engines, categories, timeRange)
		if (err != nil || len(results) == 0) && timeRange == "day" {
			log.Printf("[WebSearch] 0 results or error with time_range=day for '%s', retrying with time_range=week", job.query)
			weekResults, weekErr := QuerySearXNGAPIWithFallback(ctx, client, primaryURL, fallbackURL, job.query, qCfg.Engines, categories, "week")
			if weekErr == nil && len(weekResults) > 0 {
				results = weekResults
				err = nil
			}
		}
		if err != nil {
			log.Printf("[WebSearch] SearXNG query '%s' failed: %v", job.query, err)
			continue
		}

		var validResults []searxngResult
		var validPubDates []*time.Time

		for _, res := range results {
			if strings.TrimSpace(res.URL) == "" {
				continue
			}
			// Exclude .onion (this is clearnet web_search without darkweb)
			if strings.Contains(res.URL, ".onion") {
				continue
			}
			if seenURLs[res.URL] {
				continue
			}
			seenURLs[res.URL] = true

			// Filter out obvious historical/archived articles (e.g. from 2024 or earlier without modern context)
			if isHistoricalArticle(res.Title, res.Content) {
				continue
			}

			// Parse publication date if present
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

			// Validate CTI relevance
			if !isCTIRelevant(res.Title + " " + res.Content) {
				continue
			}

			validResults = append(validResults, res)
			validPubDates = append(validPubDates, pubDate)
		}

		// Perform actual web access (実アクセス) concurrently across valid search results
		type fetchedDoc struct {
			content string
			status  string
			errMsg  string
		}
		docs := make([]fetchedDoc, len(validResults))
		var wg sync.WaitGroup
		sem := make(chan struct{}, 4)

		for i, vr := range validResults {
			wg.Add(1)
			go func(idx int, targetURL string, fallbackSnippet string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				fetchCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
				defer cancel()

				content, err := FetchArticleContentWithTimeout(fetchCtx, targetURL, 10)
				if err == nil && len([]rune(strings.TrimSpace(content))) >= 80 {
					docs[idx] = fetchedDoc{
						content: content,
						status:  "completed",
					}
					log.Printf("[WebSearch] Actually fetched article for '%s' (%d runes)", targetURL, len([]rune(content)))
				} else {
					errStr := "empty article content"
					if err != nil {
						errStr = err.Error()
					}
					docs[idx] = fetchedDoc{
						content: fallbackSnippet,
						status:  "failed",
						errMsg:  errStr,
					}
					log.Printf("[WebSearch] Direct fetch failed for '%s' (%s), using snippet fallback", targetURL, errStr)
				}
			}(i, vr.URL, vr.Content)
		}
		wg.Wait()

		for i, res := range validResults {
			doc := docs[i]
			pubDate := validPubDates[i]

			// Determine true information source from the publisher URL, never SearXNG
			sourceName := models.ExtractSourceFromURL(res.URL)
			if sourceName == "" || sourceName == "Web Source" {
				sourceName = qCfg.Name
			}

			summary := res.Content
			if doc.status == "completed" && strings.TrimSpace(summary) == "" {
				summary = models.TruncateRunes(doc.content, 300)
			}

			meta := map[string]interface{}{
				"is_onion":      false,
				"fetch_status":  doc.status,
				"engine":        res.Engine,
				"source_engine": res.Engine,
			}
			if doc.errMsg != "" {
				meta["fetch_error"] = doc.errMsg
			}
			if doc.status == "completed" {
				meta["fetched_at"] = time.Now().UTC().Format(time.RFC3339)
				meta["content_source"] = "direct_fetch"
			} else {
				meta["content_source"] = "snippet_fallback"
			}
			if len(res.Engines) > 0 {
				meta["engines"] = res.Engines
			}

			item := models.NewThreatItem(
				models.SourceTypeWebSearch,
				sourceName,
				res.Title,
				res.URL,
				summary,
				doc.content,
				pubDate,
				meta,
			)
			items = append(items, item)
		}
	}

	log.Printf("[WebSearch] SearXNG harvested %d clearnet web items for %s", len(items), qCfg.Name)
	return items, nil
}

// harvestGeminiGrounded executes search grounding via Gemini API
func (h *WebSearchHarvester) harvestGeminiGrounded(ctx context.Context, qCfg config.QuerySourceConfig, jobs []searchJob, model, apiKey string, since *time.Time) ([]models.ThreatItem, error) {
	var items []models.ThreatItem

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
    "url": "Direct source article URL or official announcement link found in the search results (e.g. https://...). Must be a full URL, do not leave empty.",
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
			log.Printf("[WebSearch] JSON parse error: %v (raw: %s)", err, rawText)
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
				finalURL,
				res.Summary,
				"",
				pubDate,
				meta,
			)
			items = append(items, item)
		}
	}

	return items, nil
}

func (h *WebSearchHarvester) TestConnection(ctx context.Context) bool {
	cfg := config.GetSettings().GetConfig()
	if cfg.AI.GeminiAPIKey != "" {
		return true
	}
	// Check if SearXNG is configured/reachable
	testCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(testCtx, http.MethodGet, "https://searxng.lab.internal/search?q=test&format=json", nil)
	if err != nil {
		return false
	}
	client := &http.Client{Transport: defaultSearxngTransport, Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err == nil && resp.StatusCode == http.StatusOK {
		resp.Body.Close()
		return true
	}
	return false
}

func isHistoricalArticle(title, content string) bool {
	combined := strings.ToLower(title + " " + content)
	currentYear := time.Now().UTC().Year()
	currYearStr := fmt.Sprintf("%d", currentYear)
	prevYearStr := fmt.Sprintf("%d", currentYear-1)

	// If it contains references to current or previous year, consider it active
	if strings.Contains(combined, currYearStr) || strings.Contains(combined, prevYearStr) {
		return false
	}

	// Check for explicit historical years in title or content
	historicalYears := []string{"2024", "2023", "2022", "2021", "2020", "2019", "2018"}
	for _, yr := range historicalYears {
		if strings.Contains(combined, yr+"年") || strings.Contains(combined, yr+"/") || strings.Contains(combined, yr+"-") || strings.Contains(combined, "in "+yr) || strings.Contains(combined, yr+" ") {
			return true
		}
	}
	return false
}
