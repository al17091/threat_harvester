package harvesters

import (
	"net/url"
	"strings"
)

type geminiGroundingChunk struct {
	Web struct {
		URI   string `json:"uri"`
		Title string `json:"title"`
	} `json:"web"`
}

var genericSearchDomains = map[string]bool{
	"google.com":     true,
	"google.co.jp":   true,
	"bing.com":       true,
	"duckduckgo.com": true,
	"yahoo.co.jp":    true,
	"yahoo.com":      true,
	"x.com":          true,
	"twitter.com":    true,
	"t.me":           true,
	"facebook.com":   true,
}

func isGenericDomain(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return true
	}
	host := strings.TrimPrefix(strings.ToLower(u.Host), "www.")
	if genericSearchDomains[host] {
		cleanPath := strings.Trim(u.Path, "/")
		if cleanPath == "" || cleanPath == "search" || cleanPath == "home" {
			return true
		}
	}
	return false
}

func matchGroundingChunkURL(title, victim string, chunks []geminiGroundingChunk) string {
	lowerTitle := strings.ToLower(title)
	lowerVictim := strings.ToLower(victim)

	// 1. Look for chunk whose title or URI matches victim org
	if lowerVictim != "" {
		for _, c := range chunks {
			uri := strings.TrimSpace(c.Web.URI)
			if uri == "" || isGenericDomain(uri) {
				continue
			}
			cTitle := strings.ToLower(c.Web.Title)
			if strings.Contains(cTitle, lowerVictim) || strings.Contains(strings.ToLower(uri), lowerVictim) {
				return uri
			}
		}
	}

	// 2. Look for chunk whose title contains significant words from the incident title
	words := strings.Fields(lowerTitle)
	for _, c := range chunks {
		uri := strings.TrimSpace(c.Web.URI)
		if uri == "" || isGenericDomain(uri) {
			continue
		}
		cTitle := strings.ToLower(c.Web.Title)
		matchCount := 0
		for _, w := range words {
			if len([]rune(w)) >= 3 && strings.Contains(cTitle, w) {
				matchCount++
			}
		}
		if matchCount >= 2 {
			return uri
		}
	}

	// 3. Fallback: first valid non-generic chunk URI
	for _, c := range chunks {
		uri := strings.TrimSpace(c.Web.URI)
		if uri != "" && !isGenericDomain(uri) {
			return uri
		}
	}

	return ""
}
