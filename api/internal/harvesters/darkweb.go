package harvesters

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"
	"golang.org/x/net/proxy"

	"github.com/al17091/threat_harvester/api/internal/analyzer"
	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/models"
)

var (
	ahmiaTokenRegex  = regexp.MustCompile(`<input type="hidden" name="([a-f0-9]+)" value="([a-f0-9]+)">`)
	ahmiaResultRegex = regexp.MustCompile(`(?s)<li class="result">(.*?)</li>`)
	ahmiaLinkRegex   = regexp.MustCompile(`(?s)href="/search/redirect\?[^"]*redirect_url=([^"&]+)`)
	ahmiaTitleRegex  = regexp.MustCompile(`(?s)<h4>\s*<a[^>]*>(.*?)</a>\s*</h4>`)
	ahmiaDescRegex   = regexp.MustCompile(`(?s)<p>(.*?)</p>`)
	ahmiaDateRegex   = regexp.MustCompile(`(?s)<span class="lastSeen"[^>]*>(.*?)</span>`)
	htmlTagStrip     = regexp.MustCompile(`<[^>]+>`)
)

type ahmiaResult struct {
	URL         string
	Title       string
	Snippet     string
	PublishedAt *time.Time
}

type DarkwebOnionHarvester struct {
	parser   *gofeed.Parser
	analyzer analyzer.ThreatAnalyzer
}

func NewDarkwebOnionHarvester() *DarkwebOnionHarvester {
	return &DarkwebOnionHarvester{
		parser:   gofeed.NewParser(),
		analyzer: analyzer.NewDefaultThreatAnalyzer(),
	}
}

func (h *DarkwebOnionHarvester) Name() string {
	return "Dark Web (.onion) & Ransomware DLS"
}

func (h *DarkwebOnionHarvester) SourceType() models.SourceType {
	return models.SourceTypeDarkwebOnion
}

func (h *DarkwebOnionHarvester) getTorClient(proxyURLStr string) *http.Client {
	timeout := 35 * time.Second
	if proxyURLStr == "" {
		proxyURLStr = "socks5h://127.0.0.1:9050"
	}

	u, err := url.Parse(proxyURLStr)
	host := proxyURLStr
	if err == nil && u.Host != "" {
		host = u.Host
	} else {
		host = strings.TrimPrefix(proxyURLStr, "socks5h://")
		host = strings.TrimPrefix(host, "socks5://")
	}

	dialer, err := proxy.SOCKS5("tcp", host, nil, proxy.Direct)
	if err != nil {
		return &http.Client{Timeout: timeout}
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		DisableKeepAlives: true,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

func (h *DarkwebOnionHarvester) TestConnection(ctx context.Context) bool {
	cfg := config.GetSettings().GetConfig()
	client := h.getTorClient(cfg.Network.TorProxyURL)
	testCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(testCtx, http.MethodGet, "https://check.torproject.org/api/ip", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var data struct {
			IsTor bool   `json:"IsTor"`
			IP    string `json:"IP"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
			return data.IsTor
		}
	}
	return false
}

func (h *DarkwebOnionHarvester) Harvest(ctx context.Context, since *time.Time) ([]models.ThreatItem, error) {
	cfg := config.GetSettings().GetConfig()
	torClient := h.getTorClient(cfg.Network.TorProxyURL)

	var items []models.ThreatItem

	for _, target := range cfg.Sources.DarkwebOnion {
		tier := target.ComplianceTier
		if tier == "" {
			tier = config.TierDarkwebAccess
		}
		if !target.Enabled || !cfg.Compliance.IsTierEnabled(tier) {
			continue
		}

		// 0. SearXNG unified meta-search exploration
		if target.Type == "searxng" {
			searxItems, err := h.harvestSearXNG(ctx, target, since)
			if err != nil {
				log.Printf("[DarkWeb] SearXNG exploration error for %s: %v", target.Name, err)
			} else {
				items = append(items, searxItems...)
			}
			continue
		}

		// 1. Active Tor search exploration (Ahmia .onion search)
		if target.Type == "search" || target.Query != "" || target.Directive != "" {
			searchItems, err := h.harvestSearch(ctx, torClient, target, since)
			if err != nil {
				log.Printf("[DarkWeb] Search exploration error for %s: %v", target.Name, err)
			} else {
				items = append(items, searchItems...)
			}
			continue
		}

		// Direct .onion site validation
		if !strings.Contains(target.URL, ".onion") {
			log.Printf("[DarkWeb] Skipping non-onion target %s (%s): darkweb_onion strictly requires .onion domain", target.Name, target.URL)
			continue
		}

		log.Printf("[DarkWeb] Checking onion target: %s (%s)", target.Name, target.URL)
		client := torClient

		if target.Type == "rss" || target.Type == "onion" || target.Type == "" {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0")

			resp, err := client.Do(req)
			if err != nil {
				log.Printf("[DarkWeb] Failed to fetch onion %s: %v", target.Name, err)
				continue
			}

			feed, err := h.parser.Parse(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				// If RSS parsing fails, fallback to HTML scraper
				log.Printf("[DarkWeb] RSS parsing failed for %s (%v). Attempting HTML scraper fallback.", target.Name, err)
				htmlItems, htmlErr := h.harvestHTML(ctx, torClient, target, since)
				if htmlErr == nil && len(htmlItems) > 0 {
					items = append(items, htmlItems...)
				}
				continue
			}

			for _, entry := range feed.Items {
				var pubDate *time.Time
				if entry.PublishedParsed != nil {
					t := entry.PublishedParsed.UTC()
					pubDate = &t
				}

				if since != nil && pubDate != nil && pubDate.Before(*since) {
					continue
				}

				summary := entry.Description
				if summary == "" {
					summary = entry.Content
				}

				link := entry.Link
				if link == "" {
					link = target.URL
				}

				item := models.NewThreatItem(
					models.SourceTypeDarkwebOnion,
					target.Name,
					entry.Title,
					link,
					summary,
					entry.Content,
					pubDate,
					map[string]interface{}{"is_onion": true, "type": "rss"},
				)
				items = append(items, item)
			}

		} else if target.Type == "html" {
			htmlItems, err := h.harvestHTML(ctx, torClient, target, since)
			if err != nil {
				log.Printf("[DarkWeb] HTML scraper error for %s: %v", target.Name, err)
			} else {
				items = append(items, htmlItems...)
			}

		} else if target.Type == "api" {
			// JSON API on .onion
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0")

			resp, err := client.Do(req)
			if err != nil {
				log.Printf("[DarkWeb] Failed to fetch API %s: %v", target.Name, err)
				continue
			}

			if resp.StatusCode == http.StatusOK {
				var posts []map[string]interface{}
				if err := json.NewDecoder(resp.Body).Decode(&posts); err == nil {
					_ = resp.Body.Close()
					for i, post := range posts {
						if i >= 30 {
							break
						}
						victimName, _ := post["victim"].(string)
						if victimName == "" {
							victimName, _ = post["post_title"].(string)
						}
						groupName, _ := post["group_name"].(string)
						if groupName == "" {
							groupName = "Unknown Group"
						}
						description, _ := post["description"].(string)
						country, _ := post["country"].(string)
						permalink, _ := post["permalink"].(string)
						if permalink == "" {
							permalink, _ = post["website"].(string)
						}
						if permalink == "" {
							if groupName != "" && groupName != "Unknown Group" {
								permalink = fmt.Sprintf("https://www.ransomlook.io/group/%s", url.PathEscape(groupName))
							} else if target.URL != "" {
								permalink = target.URL
							} else {
								permalink = "https://www.ransomlook.io/recent"
							}
						}

						var pubDate *time.Time
						if discStr, ok := post["discovered"].(string); ok && discStr != "" {
							layouts := []string{
								"2006-01-02 15:04:05.999999",
								"2006-01-02 15:04:05",
								"2006-01-02T15:04:05Z07:00",
								"2006-01-02",
							}
							for _, layout := range layouts {
								if t, err := time.Parse(layout, strings.TrimSpace(discStr)); err == nil {
									utc := t.UTC()
									pubDate = &utc
									break
								}
							}
						}

						if since != nil && pubDate != nil && pubDate.Before(*since) {
							continue
						}

						upperVictim := strings.ToUpper(victimName)
						upperCountry := strings.ToUpper(country)
						upperDesc := strings.ToUpper(description)
						isJapan := upperCountry == "JP" || strings.Contains(upperVictim, "JAPAN") || strings.Contains(upperDesc, "JAPAN")

						title := fmt.Sprintf("[%s DLS] Victim: %s (%s)", groupName, victimName, country)
						summary := fmt.Sprintf("Group: %s\nVictim: %s\nCountry: %s\nDetails: %s", groupName, victimName, country, description)

						item := models.NewThreatItem(
							models.SourceTypeDarkwebOnion,
							fmt.Sprintf("%s (%s)", target.Name, groupName),
							title,
							permalink,
							summary,
							description,
							pubDate,
							map[string]interface{}{
								"victim":   victimName,
								"group":    groupName,
								"country":  country,
								"is_japan": isJapan,
							},
						)
						items = append(items, item)
					}
				} else {
					_ = resp.Body.Close()
				}
			} else {
				_ = resp.Body.Close()
			}
		}
	}

	log.Printf("[DarkWeb] DarkwebOnionHarvester collected %d items", len(items))
	return items, nil
}

// harvestSearch executes keyword or directive-driven darkweb exploration over Tor.
func (h *DarkwebOnionHarvester) harvestSearch(ctx context.Context, torClient *http.Client, target config.DarkwebSourceConfig, since *time.Time) ([]models.ThreatItem, error) {
	var queries []string
	if strings.TrimSpace(target.Directive) != "" {
		directive := strings.TrimSpace(target.Directive)
		aiQueries, err := h.analyzer.GenerateSearchQueries(ctx, directive, "darkweb_search", 3)
		if err == nil && len(aiQueries) > 0 {
			queries = aiQueries
		} else {
			queries = []string{directive}
		}
	} else if strings.TrimSpace(target.Query) != "" {
		queries = []string{strings.TrimSpace(target.Query)}
	} else {
		return nil, nil
	}

	var items []models.ThreatItem
	seenURLs := make(map[string]bool)

	for _, q := range queries {
		log.Printf("[DarkWeb] Executing Tor Search Exploration for query: '%s' (Target: %s)", q, target.Name)
		results, err := h.queryAhmia(ctx, torClient, q)
		if err != nil {
			log.Printf("[DarkWeb] Ahmia search query '%s': %v", q, err)
			continue
		}

		for _, res := range results {
			if !strings.Contains(res.URL, ".onion") {
				continue
			}
			if seenURLs[res.URL] {
				continue
			}
			seenURLs[res.URL] = true

			if since != nil && res.PublishedAt != nil && res.PublishedAt.Before(*since) {
				continue
			}

			// Verify threat relevance
			if !isCTIRelevant(res.Title + " " + res.Snippet) {
				continue
			}

			rawContent := fmt.Sprintf("%s\n\n[DarkWeb Search Query: %s]\n[Hidden Service: %s]", res.Snippet, q, res.URL)
			item := models.NewThreatItem(
				models.SourceTypeDarkwebOnion,
				fmt.Sprintf("Tor Search: %s", target.Name),
				res.Title,
				res.URL,
				res.Snippet,
				rawContent,
				res.PublishedAt,
				map[string]interface{}{
					"is_onion": true,
					"query":    q,
					"engine":   "ahmia",
				},
			)
			items = append(items, item)
			if len(items) >= 25 {
				break
			}
		}
	}

	return items, nil
}

// queryAhmia executes a search on Ahmia over Tor, trying the native onion endpoint first.
func (h *DarkwebOnionHarvester) queryAhmia(ctx context.Context, torClient *http.Client, query string) ([]ahmiaResult, error) {
	ahmiaBases := []string{
		"http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion",
		"https://ahmia.fi",
	}

	for _, base := range ahmiaBases {
		results, err := h.doAhmiaSearch(ctx, torClient, base, query)
		if err == nil && len(results) > 0 {
			return results, nil
		}
	}
	return nil, fmt.Errorf("no search results returned from Ahmia endpoints")
}

func (h *DarkwebOnionHarvester) doAhmiaSearch(ctx context.Context, torClient *http.Client, base string, query string) ([]ahmiaResult, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()

	// 1. Fetch homepage to get dynamic honeypot token
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, base+"/", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0")

	resp, err := torClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}

	tokenMatch := ahmiaTokenRegex.FindStringSubmatch(string(body))
	var searchURL string
	if len(tokenMatch) >= 3 {
		searchURL = fmt.Sprintf("%s/search/?q=%s&%s=%s", base, url.QueryEscape(query), tokenMatch[1], tokenMatch[2])
	} else {
		searchURL = fmt.Sprintf("%s/search/?q=%s", base, url.QueryEscape(query))
	}

	// 2. Query search endpoint
	sreq, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, searchURL, nil)
	if err != nil {
		return nil, err
	}
	sreq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0")

	sresp, err := torClient.Do(sreq)
	if err != nil {
		return nil, err
	}
	sbody, err := io.ReadAll(sresp.Body)
	_ = sresp.Body.Close()
	if err != nil {
		return nil, err
	}

	if sresp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("search endpoint returned status %d", sresp.StatusCode)
	}

	// 3. Parse search results
	blocks := ahmiaResultRegex.FindAllStringSubmatch(string(sbody), -1)
	var results []ahmiaResult

	for _, blk := range blocks {
		content := blk[1]
		linkMatch := ahmiaLinkRegex.FindStringSubmatch(content)
		if len(linkMatch) < 2 {
			continue
		}
		rawTargetURL, err := url.QueryUnescape(linkMatch[1])
		if err != nil || !strings.Contains(rawTargetURL, ".onion") {
			continue
		}

		title := ""
		titleMatch := ahmiaTitleRegex.FindStringSubmatch(content)
		if len(titleMatch) >= 2 {
			title = html.UnescapeString(strings.TrimSpace(htmlTagStrip.ReplaceAllString(titleMatch[1], "")))
		}
		if title == "" {
			title = rawTargetURL
		}

		snippet := ""
		descMatch := ahmiaDescRegex.FindStringSubmatch(content)
		if len(descMatch) >= 2 {
			snippet = html.UnescapeString(strings.TrimSpace(htmlTagStrip.ReplaceAllString(descMatch[1], "")))
		}

		var pubTime *time.Time
		dateMatch := ahmiaDateRegex.FindStringSubmatch(content)
		if len(dateMatch) >= 2 {
			dateStr := strings.TrimSpace(dateMatch[1])
			if t, err := time.Parse("2006-01-02", dateStr); err == nil {
				utc := t.UTC()
				pubTime = &utc
			}
		}

		results = append(results, ahmiaResult{
			URL:         rawTargetURL,
			Title:       title,
			Snippet:     snippet,
			PublishedAt: pubTime,
		})
	}

	return results, nil
}

// harvestHTML scrapes leak cards and links from an arbitrary .onion HTML leak site.
func (h *DarkwebOnionHarvester) harvestHTML(ctx context.Context, torClient *http.Client, target config.DarkwebSourceConfig, since *time.Time) ([]models.ThreatItem, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, target.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0")

	resp, err := torClient.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}

	htmlStr := string(body)

	// Extract page title
	pageTitleRegex := regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	pageTitle := target.Name
	if tm := pageTitleRegex.FindStringSubmatch(htmlStr); len(tm) >= 2 {
		clean := html.UnescapeString(strings.TrimSpace(htmlTagStrip.ReplaceAllString(tm[1], "")))
		if clean != "" {
			pageTitle = fmt.Sprintf("%s - %s", target.Name, clean)
		}
	}

	// Extract card/post structures
	cardRegex := regexp.MustCompile(`(?is)<(article|div)[^>]*(class|id)=["'][^"']*(post|card|leak|victim|item)[^"']*["'][^>]*>(.*?)</(article|div)>`)
	cards := cardRegex.FindAllStringSubmatch(htmlStr, -1)

	var items []models.ThreatItem
	now := time.Now().UTC()

	if len(cards) > 0 {
		for i, c := range cards {
			if i >= 20 {
				break
			}
			cardContent := c[4]

			// Extract title inside card (h2, h3, h4, or strong)
			hRegex := regexp.MustCompile(`(?is)<(h1|h2|h3|h4|strong)[^>]*>(.*?)</(h1|h2|h3|h4|strong)>`)
			title := ""
			if hm := hRegex.FindStringSubmatch(cardContent); len(hm) >= 3 {
				title = html.UnescapeString(strings.TrimSpace(htmlTagStrip.ReplaceAllString(hm[2], "")))
			}
			if title == "" {
				continue
			}

			// Extract link inside card if present
			link := target.URL
			aRegex := regexp.MustCompile(`(?is)<a[^>]*href=["']([^"']+)["'][^>]*>`)
			if am := aRegex.FindStringSubmatch(cardContent); len(am) >= 2 {
				href := am[1]
				if strings.HasPrefix(href, "http") {
					link = href
				} else if strings.HasPrefix(href, "/") {
					u, _ := url.Parse(target.URL)
					if u != nil {
						link = fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, href)
					}
				}
			}

			desc := html.UnescapeString(strings.TrimSpace(htmlTagStrip.ReplaceAllString(cardContent, " ")))
			if len(desc) > 300 {
				desc = desc[:300] + "..."
			}

			itemTitle := fmt.Sprintf("[%s DLS] %s", target.Name, title)
			item := models.NewThreatItem(
				models.SourceTypeDarkwebOnion,
				target.Name,
				itemTitle,
				link,
				desc,
				desc,
				&now,
				map[string]interface{}{"is_onion": true, "type": "html_scraper"},
			)
			items = append(items, item)
		}
	}

	// Fallback: if no individual cards found, emit one page summary threat item if relevant
	if len(items) == 0 && isCTIRelevant(htmlStr) {
		cleanText := html.UnescapeString(strings.TrimSpace(htmlTagStrip.ReplaceAllString(htmlStr, " ")))
		if len(cleanText) > 400 {
			cleanText = cleanText[:400] + "..."
		}
		item := models.NewThreatItem(
			models.SourceTypeDarkwebOnion,
			target.Name,
			pageTitle,
			target.URL,
			cleanText,
			cleanText,
			&now,
			map[string]interface{}{"is_onion": true, "type": "html_snapshot"},
		)
		items = append(items, item)
	}

	return items, nil
}

// isCTIRelevant determines whether a text snippet has cybersecurity threat context.
func isCTIRelevant(text string) bool {
	lower := strings.ToLower(text)
	keywords := []string{
		"ransomware", "leak", "breach", "dump", "database", "stolen", "victim",
		"exfiltrat", "exploit", "0day", "zero-day", "hacked", "access broker",
		"compromis", "payload", "cve", "dls", "extortion", "attack", "malware",
		"cyber", "pwned", "darknet", "threat", "gang", "target", "proof", "corp",
		"japan", "japanese", "tokyo", "data leak",
		// Japanese CTI keywords
		"ランサムウェア", "身代金", "不正アクセス", "情報漏洩", "漏洩", "データ侵害",
		"脆弱性", "ゼロデイ", "サイバー攻撃", "標的型", "侵害", "マルウェア", "暴露", "二重脅迫",
	}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

type searxngResult struct {
	URL           string   `json:"url"`
	Title         string   `json:"title"`
	Content       string   `json:"content"`
	Engine        string   `json:"engine"`
	Engines       []string `json:"engines,omitempty"`
	PublishedDate string   `json:"publishedDate,omitempty"`
}

type searxngResponse struct {
	Query   string          `json:"query"`
	Results []searxngResult `json:"results"`
}

var defaultSearxngTransport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}

// harvestSearXNG executes unified meta-search via SearXNG API (format=json)
func (h *DarkwebOnionHarvester) harvestSearXNG(ctx context.Context, target config.DarkwebSourceConfig, since *time.Time) ([]models.ThreatItem, error) {
	var queries []string
	if strings.TrimSpace(target.Directive) != "" {
		directive := strings.TrimSpace(target.Directive)
		aiQueries, err := h.analyzer.GenerateSearchQueries(ctx, directive, "darkweb_onion", 3)
		if err == nil && len(aiQueries) > 0 {
			queries = aiQueries
		} else {
			queries = []string{directive}
		}
	} else if strings.TrimSpace(target.Query) != "" {
		queries = []string{strings.TrimSpace(target.Query)}
	} else {
		return nil, nil
	}

	timeoutSec := target.TimeoutSeconds
	if timeoutSec <= 0 {
		timeoutSec = 30
	}

	client := &http.Client{
		Transport: defaultSearxngTransport,
		Timeout:   time.Duration(timeoutSec) * time.Second,
	}

	var items []models.ThreatItem
	seenURLs := make(map[string]bool)

	baseURL := target.URL
	if baseURL == "" {
		baseURL = "https://searxng.lab.internal/search"
	}

	for _, q := range queries {
		log.Printf("[DarkWeb] Executing SearXNG query: '%s' (Target: %s, URL: %s)", q, target.Name, baseURL)
		results, err := h.querySearXNG(ctx, client, baseURL, q, target.Engines, target.Categories)
		if err != nil {
			log.Printf("[DarkWeb] SearXNG search query '%s' failed: %v", q, err)
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

			isOnion := strings.Contains(res.URL, ".onion")
			rawContent := fmt.Sprintf("%s\n\n[SearXNG Query: %s]\n[Engine: %s]\n[URL: %s]", res.Content, q, res.Engine, res.URL)

			meta := map[string]interface{}{
				"is_onion":       isOnion,
				"engine":         res.Engine,
				"searxng_query":  q,
				"fetch_status":   "pending",
				"source_engine":  res.Engine,
			}
			if len(res.Engines) > 0 {
				meta["engines"] = res.Engines
			}

			item := models.NewThreatItem(
				models.SourceTypeDarkwebOnion,
				target.Name,
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

	log.Printf("[DarkWeb] SearXNG harvested %d items for target %s", len(items), target.Name)
	return items, nil
}

// querySearXNG calls SearXNG format=json API
func (h *DarkwebOnionHarvester) querySearXNG(ctx context.Context, client *http.Client, endpoint, query, engines, categories string) ([]searxngResult, error) {
	return QuerySearXNGAPI(ctx, client, endpoint, query, engines, categories)
}

// QuerySearXNGAPI calls SearXNG format=json API and returns parsed results
func QuerySearXNGAPI(ctx context.Context, client *http.Client, endpoint, query, engines, categories string) ([]searxngResult, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid searxng endpoint: %w", err)
	}

	qParams := u.Query()
	qParams.Set("q", query)
	qParams.Set("format", "json")
	if strings.TrimSpace(engines) != "" {
		qParams.Set("engines", strings.TrimSpace(engines))
	}
	if strings.TrimSpace(categories) != "" {
		qParams.Set("categories", strings.TrimSpace(categories))
	}
	u.RawQuery = qParams.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create searxng request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0 ThreatHarvesterBot/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("searxng request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("searxng returned status %d: %s", resp.StatusCode, string(body))
	}

	var data searxngResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode searxng response: %w", err)
	}

	return data.Results, nil
}
