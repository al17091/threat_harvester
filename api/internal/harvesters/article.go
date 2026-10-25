package harvesters

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/proxy"

	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/models"
)

var (
	// Default HTTP client with relaxed TLS and 10s timeout for public news scraping
	articleHTTPClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // handles SAN / host mismatches on certs like news portals
			},
		},
	}

	multiNewlineRegex = regexp.MustCompile(`\n{3,}`)
	multiSpaceRegex   = regexp.MustCompile(`[ \t]{2,}`)
	urlRegex          = regexp.MustCompile(`https?://[^\s<>"'()]+`)
)

// FetchArticleContent fetches the given article URL and extracts its main body text.
func FetchArticleContent(ctx context.Context, targetURL string) (string, error) {
	return FetchArticleContentWithTimeout(ctx, targetURL, 15)
}

// FetchArticleContentWithTimeout fetches the given article URL with custom timeout and extracts its main body text.
func FetchArticleContentWithTimeout(ctx context.Context, targetURL string, timeoutSec int) (string, error) {
	trimmedURL := strings.TrimSpace(targetURL)
	if trimmedURL == "" {
		return "", fmt.Errorf("empty URL")
	}

	// Never scrape onion URLs via standard clearnet client
	if strings.Contains(trimmedURL, ".onion") {
		return "", fmt.Errorf("onion URLs must use Tor harvester")
	}

	if !strings.HasPrefix(trimmedURL, "http://") && !strings.HasPrefix(trimmedURL, "https://") {
		return "", fmt.Errorf("invalid URL scheme: %s", trimmedURL)
	}

	u, err := url.Parse(trimmedURL)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	if timeoutSec <= 0 {
		timeoutSec = 15
	}
	client := &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	cfg := config.GetSettings().GetConfig()
	browserlessURL := cfg.Scraper.BrowserlessURL
	bTimeout := cfg.Scraper.BrowserlessTimeoutSec
	if bTimeout <= 0 {
		bTimeout = 25
	}

	body, err := doFetchHTMLWithClient(ctx, client, trimmedURL)
	if err != nil && !strings.HasPrefix(u.Host, "www.") {
		u.Host = "www." + u.Host
		if altBody, altErr := doFetchHTMLWithClient(ctx, client, u.String()); altErr == nil {
			body = altBody
			err = nil
		}
	}

	var extracted string
	var extractErr error
	if err == nil {
		extracted, extractErr = ExtractArticleTextFromHTML(body)
	}

	// Dynamic fallback for JS/SPA rendered pages or HTTP fetch blocks
	needsBrowserless := (err != nil) || (extractErr != nil) || isLikelySPAShell(body, extracted)
	if needsBrowserless && browserlessURL != "" {
		if renderedHTML, bErr := fetchHTMLWithBrowserless(ctx, browserlessURL, trimmedURL, bTimeout); bErr == nil && len(renderedHTML) > 0 {
			if bExtracted, bExtractErr := ExtractArticleTextFromHTML(renderedHTML); bExtractErr == nil && len(strings.TrimSpace(bExtracted)) > len(strings.TrimSpace(extracted)) {
				return bExtracted, nil
			}
		}
	}

	if err != nil {
		return "", err
	}
	if extractErr != nil {
		return "", extractErr
	}

	return extracted, nil
}

func isLikelySPAShell(htmlStr string, extractedText string) bool {
	if len(strings.TrimSpace(extractedText)) < 150 {
		lower := strings.ToLower(htmlStr)
		if strings.Contains(lower, `id="root"`) ||
			strings.Contains(lower, `id="__next"`) ||
			strings.Contains(lower, `id="app"`) ||
			strings.Contains(lower, `id="__nuxt"`) ||
			strings.Contains(lower, `javascript is required`) ||
			strings.Contains(lower, `enable javascript`) {
			return true
		}
	}
	return false
}

func fetchHTMLWithBrowserless(ctx context.Context, browserlessURL, targetURL string, timeoutSec int) (string, error) {
	if browserlessURL == "" {
		return "", fmt.Errorf("browserless URL not configured")
	}
	endpoint := fmt.Sprintf("%s/content", strings.TrimRight(browserlessURL, "/"))
	if timeoutSec <= 0 {
		timeoutSec = 25
	}

	payload := map[string]interface{}{
		"url": targetURL,
		"gotoOptions": map[string]interface{}{
			"waitUntil": "networkidle2",
			"timeout":   timeoutSec * 1000,
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	bClient := &http.Client{
		Timeout: time.Duration(timeoutSec+5) * time.Second,
	}
	resp, err := bClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("browserless request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("browserless returned HTTP %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// FetchOnionArticleContent fetches the given .onion URL via Tor SOCKS5h proxy and extracts its main body text.
func FetchOnionArticleContent(ctx context.Context, targetURL string, proxyURLStr string, timeoutSec int) (string, error) {
	trimmedURL := strings.TrimSpace(targetURL)
	if trimmedURL == "" {
		return "", fmt.Errorf("empty URL")
	}

	if !strings.Contains(trimmedURL, ".onion") {
		return "", fmt.Errorf("not an onion URL: %s", trimmedURL)
	}

	if !strings.HasPrefix(trimmedURL, "http://") && !strings.HasPrefix(trimmedURL, "https://") {
		trimmedURL = "http://" + trimmedURL
	}

	if proxyURLStr == "" {
		proxyURLStr = "socks5h://127.0.0.1:9050"
	}
	if timeoutSec <= 0 {
		timeoutSec = 45
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
		return "", fmt.Errorf("failed to create tor SOCKS5 dialer: %w", err)
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		DisableKeepAlives: true,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
	}

	torClient := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeoutSec) * time.Second,
	}

	body, err := doFetchHTMLWithTorClient(ctx, torClient, trimmedURL)
	if err != nil {
		return "", err
	}

	return ExtractArticleTextFromHTML(body)
}

func doFetchHTMLWithClient(ctx context.Context, client *http.Client, reqURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 ThreatHarvester/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,ja;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", err
	}

	return doc.Html()
}

func doFetchHTMLWithTorClient(ctx context.Context, client *http.Client, reqURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", err
	}

	return doc.Html()
}

func doFetchHTML(ctx context.Context, reqURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 ThreatHarvester/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.9,en;q=0.8")

	resp, err := articleHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP status %d", resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return "", err
	}

	htmlStr, err := doc.Html()
	if err != nil {
		return "", err
	}

	return htmlStr, nil
}

// ExtractArticleTextFromHTML extracts clean article text from raw HTML using goquery.
func ExtractArticleTextFromHTML(htmlStr string) (string, error) {
	if strings.TrimSpace(htmlStr) == "" {
		return "", fmt.Errorf("empty HTML content")
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlStr))
	if err != nil {
		return "", err
	}

	// Strip noise elements
	doc.Find("script, style, noscript, iframe, nav, header, footer, aside, svg, form").Remove()
	doc.Find(".ad, .advertisement, .sns-share, .social-share, .share-buttons, .related-posts, .comments, #comments, .side-content, .widget").Remove()

	// 1. Try finding container elements commonly used for article bodies
	selectors := []string{
		"article.arti-body",
		".article-body",
		".article_body",
		".entry-body",
		".entry-content",
		".post-content",
		"[itemprop=\"articleBody\"]",
		".story-body",
		".news-body",
		".main-content",
		"article",
		"main",
		"[role=\"main\"]",
		"#article-body",
		"#news-body",
	}

	var articleSel *goquery.Selection
	for _, sel := range selectors {
		s := doc.Find(sel).First()
		if s.Length() > 0 {
			cleanText := strings.TrimSpace(s.Text())
			if len([]rune(cleanText)) >= 80 {
				articleSel = s
				break
			}
		}
	}

	var paras []string
	if articleSel != nil {
		articleSel.Find("p, h2, h3, h4, li, blockquote, pre").Each(func(i int, s *goquery.Selection) {
			t := strings.TrimSpace(s.Text())
			if isMeaningfulParagraph(t) {
				paras = append(paras, t)
			}
		})
	}

	// 2. Fallback to all <p> in doc if container was not found or yielded too few paragraphs
	if len(paras) == 0 {
		doc.Find("p").Each(func(i int, s *goquery.Selection) {
			t := strings.TrimSpace(s.Text())
			if isMeaningfulParagraph(t) {
				paras = append(paras, t)
			}
		})
	}

	// 3. Fallback to meta description if still empty
	if len(paras) == 0 {
		metaDesc, exists := doc.Find("meta[property=\"og:description\"], meta[name=\"description\"]").Attr("content")
		if exists && strings.TrimSpace(metaDesc) != "" {
			paras = append(paras, strings.TrimSpace(metaDesc))
		}
	}

	if len(paras) == 0 {
		return "", fmt.Errorf("no readable article text found in HTML")
	}

	rawText := strings.Join(paras, "\n\n")
	rawText = html.UnescapeString(rawText)
	rawText = multiSpaceRegex.ReplaceAllString(rawText, " ")
	rawText = multiNewlineRegex.ReplaceAllString(rawText, "\n\n")
	rawText = strings.TrimSpace(rawText)

	// Truncate to safety limit
	rawText = models.TruncateRunes(rawText, 8000)

	return rawText, nil
}

func isMeaningfulParagraph(t string) bool {
	rLen := len([]rune(t))
	if rLen < 8 {
		return false
	}
	lower := strings.ToLower(t)
	// Filter out boilerplate notices
	if strings.Contains(lower, "cookie") && (strings.Contains(lower, "policy") || strings.Contains(lower, "consent") || strings.Contains(lower, "同意")) {
		return false
	}
	if strings.Contains(lower, "all rights reserved") || strings.Contains(lower, "copyright ©") || strings.Contains(lower, "copyright (c)") {
		return false
	}
	if strings.Contains(lower, "シェア") || strings.Contains(lower, "ツイート") || strings.Contains(lower, "フォローする") {
		return false
	}
	return true
}

// ExtractURLsFromText extracts valid http/https URLs from plain text.
func ExtractURLsFromText(text string) []string {
	matches := urlRegex.FindAllString(text, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	var urls []string
	for _, m := range matches {
		cleaned := strings.TrimRight(m, ".,;:!?)>]}\"'")
		if IsCrawleableURL(cleaned) && !seen[cleaned] {
			seen[cleaned] = true
			urls = append(urls, cleaned)
		}
	}
	return urls
}

// IsCrawleableURL checks if a URL is eligible for article content scraping.
func IsCrawleableURL(rawURL string) bool {
	trimmed := strings.TrimSpace(rawURL)
	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		return false
	}
	if strings.Contains(trimmed, ".onion") {
		return false
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return false
	}

	hostLower := strings.ToLower(u.Host)
	// Skip social networks that require authentication or where static scraping fails
	skipHosts := []string{
		"t.me", "telegram.me",
		"twitter.com", "x.com",
		"facebook.com", "fb.com",
		"instagram.com",
		"youtube.com", "youtu.be",
		"tiktok.com",
		"linkedin.com",
		"reddit.com",
	}
	for _, sh := range skipHosts {
		if hostLower == sh || strings.HasSuffix(hostLower, "."+sh) {
			return false
		}
	}

	// Skip non-HTML media assets
	pathLower := strings.ToLower(u.Path)
	skipExts := []string{
		".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
		".mp4", ".mp3", ".avi", ".mov", ".zip", ".tar.gz", ".gz",
		".exe", ".dmg", ".pkg", ".css", ".js", ".json", ".xml",
	}
	for _, ext := range skipExts {
		if strings.HasSuffix(pathLower, ext) {
			return false
		}
	}

	return true
}

// ExtractExternalLinksFromHTML extracts potential external article/advisory reference links from HTML.
func ExtractExternalLinksFromHTML(htmlStr string, sourceURL string) []string {
	if strings.TrimSpace(htmlStr) == "" {
		return nil
	}
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlStr))
	if err != nil {
		return nil
	}

	baseU, _ := url.Parse(sourceURL)
	baseHost := ""
	if baseU != nil {
		baseHost = strings.ToLower(baseU.Host)
	}

	seen := make(map[string]bool)
	var links []string

	// Look inside article body containers and paragraphs
	doc.Find("article a, main a, [role=\"main\"] a, .article-body a, .entry-content a, p a").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}
		href = strings.TrimSpace(href)
		if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") || strings.HasPrefix(href, "mailto:") {
			return
		}

		var targetURL string
		if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
			targetURL = href
		} else if baseU != nil {
			relU, err := url.Parse(href)
			if err == nil {
				targetURL = baseU.ResolveReference(relU).String()
			}
		}

		if targetURL == "" || !IsCrawleableURL(targetURL) {
			return
		}

		tU, err := url.Parse(targetURL)
		if err != nil || tU.Host == "" {
			return
		}

		// Only follow external domains (not internal site navigation)
		tHost := strings.ToLower(tU.Host)
		if baseHost != "" && (tHost == baseHost || strings.HasSuffix(tHost, "."+baseHost) || strings.HasSuffix(baseHost, "."+tHost)) {
			return
		}

		if !seen[targetURL] {
			seen[targetURL] = true
			links = append(links, targetURL)
		}
	})

	if len(links) > 3 {
		links = links[:3]
	}
	return links
}

// FollowAndScrapeLinkedArticles recursively crawls and scrapes linked articles up to maxDepth.
// Returns enriched text representing all scraped articles and the list of visited URLs.
func FollowAndScrapeLinkedArticles(ctx context.Context, initialURLs []string, maxDepth int) (string, []string) {
	if maxDepth <= 0 {
		maxDepth = 2
	}
	if maxDepth > 3 {
		maxDepth = 3
	}

	visited := make(map[string]bool)
	var visitedURLs []string
	var scrapedBlocks []string

	currentQueue := make([]string, 0, len(initialURLs))
	for _, u := range initialURLs {
		cleaned := strings.TrimSpace(u)
		if IsCrawleableURL(cleaned) && !visited[cleaned] {
			currentQueue = append(currentQueue, cleaned)
		}
	}

	for depth := 1; depth <= maxDepth && len(currentQueue) > 0; depth++ {
		var nextQueue []string

		for _, reqURL := range currentQueue {
			if visited[reqURL] {
				continue
			}
			visited[reqURL] = true

			// Fetch HTML with child context timeout to avoid blocking the pipeline
			reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
			htmlBody, err := doFetchHTML(reqCtx, reqURL)
			cancel()
			if err != nil {
				continue
			}

			articleText, err := ExtractArticleTextFromHTML(htmlBody)
			if err != nil || len([]rune(strings.TrimSpace(articleText))) < 50 {
				continue
			}

			visitedURLs = append(visitedURLs, reqURL)
			header := fmt.Sprintf("--- [Linked Content (Depth %d): %s] ---", depth, reqURL)
			scrapedBlocks = append(scrapedBlocks, header+"\n"+articleText)

			// Discover further links for next depth if depth < maxDepth
			if depth < maxDepth {
				discovered := ExtractExternalLinksFromHTML(htmlBody, reqURL)
				for _, d := range discovered {
					if !visited[d] {
						nextQueue = append(nextQueue, d)
						if len(nextQueue) >= 4 {
							break
						}
					}
				}
			}
		}

		currentQueue = nextQueue
	}

	if len(scrapedBlocks) == 0 {
		return "", visitedURLs
	}

	return strings.Join(scrapedBlocks, "\n\n"), visitedURLs
}

