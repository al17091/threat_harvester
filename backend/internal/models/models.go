package models

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"
	"unicode"
)

type SourceType string

const (
	SourceTypeVendorRSS         SourceType = "vendor_rss"
	SourceTypeWebSearch         SourceType = "web_search"
	SourceTypeDarkwebOnion      SourceType = "darkweb_onion"
	SourceTypeRansomwareTracker SourceType = "ransomware_tracker"
	SourceTypeTelegram          SourceType = "telegram"
	SourceTypeXMonitor          SourceType = "x_monitor"
)

type Severity string

const (
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
	SeverityUnknown  Severity = "Unknown"
)

type JapanRelevance string

const (
	JapanRelevanceDirect   JapanRelevance = "Direct"
	JapanRelevanceIndirect JapanRelevance = "Indirect"
	JapanRelevanceNone     JapanRelevance = "None"
	JapanRelevanceUnknown  JapanRelevance = "Unknown"
)

// ThreatItem represents raw normalized threat data gathered from external feeds.
type ThreatItem struct {
	ID          string                 `json:"id"`
	IncidentID  string                 `json:"incident_id,omitempty"`
	ContentHash string                 `json:"content_hash,omitempty"`
	SourceType  SourceType             `json:"source_type"`
	SourceName  string                 `json:"source_name"`
	Title       string                 `json:"title"`
	URL         string                 `json:"url,omitempty"`
	Summary     string                 `json:"summary"`
	RawContent  string                 `json:"raw_content,omitempty"`
	PublishedAt *time.Time             `json:"published_at,omitempty"`
	HarvestedAt time.Time              `json:"harvested_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// TruncateRunes safely truncates a string to max runes without splitting multibyte UTF-8 characters.
func TruncateRunes(s string, maxRunes int) string {
	r := []rune(s)
	if len(r) > maxRunes {
		return string(r[:maxRunes])
	}
	return s
}

// NormalizeURL strips tracking parameters, fragments, www prefix, and trailing slashes.
func NormalizeURL(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return ""
	}
	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		if strings.Contains(trimmed, ".") && !strings.Contains(trimmed, " ") {
			trimmed = "https://" + trimmed
		} else {
			return trimmed
		}
	}

	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return trimmed
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Host = strings.TrimPrefix(u.Host, "www.")
	u.Fragment = ""

	if u.RawQuery != "" {
		q := u.Query()
		trackingPrefixes := []string{
			"utm_", "ref", "fbclid", "gclid", "source", "feed",
			"feature", "cmpid", "ocid", "taid", "mkt_tok",
		}
		for key := range q {
			lowerKey := strings.ToLower(key)
			for _, prefix := range trackingPrefixes {
				if strings.HasPrefix(lowerKey, prefix) || lowerKey == prefix {
					q.Del(key)
					break
				}
			}
		}
		u.RawQuery = q.Encode()
	}

	cleanPath := path.Clean(u.Path)
	if cleanPath == "." || cleanPath == "/" {
		u.Path = ""
	} else {
		u.Path = strings.TrimSuffix(cleanPath, "/")
	}

	return u.String()
}

// isGenericURL returns true if the URL points to a generic domain root or social platform home.
func isGenericURL(uStr string) bool {
	u, err := url.Parse(uStr)
	if err != nil || u.Host == "" {
		return true
	}
	host := strings.TrimPrefix(strings.ToLower(u.Host), "www.")
	genericHosts := map[string]bool{
		"x.com":          true,
		"twitter.com":    true,
		"t.me":           true,
		"telegram.org":   true,
		"google.com":     true,
		"bing.com":       true,
		"duckduckgo.com": true,
		"yahoo.co.jp":    true,
		"yahoo.com":      true,
		"facebook.com":   true,
		"instagram.com":  true,
		"linkedin.com":   true,
	}

	cleanPath := strings.Trim(u.Path, "/")
	if genericHosts[host] {
		if cleanPath == "" || cleanPath == "search" || cleanPath == "home" {
			return true
		}
	}

	if cleanPath == "" && u.RawQuery == "" {
		return true
	}

	return false
}

// NewThreatItem creates a new ThreatItem with a deterministic SHA256 hash ID.
func NewThreatItem(
	sourceType SourceType,
	sourceName string,
	title string,
	rawURL string,
	summary string,
	rawContent string,
	publishedAt *time.Time,
	metadata map[string]interface{},
) ThreatItem {
	cleanTitle := strings.TrimSpace(title)
	normURL := NormalizeURL(rawURL)
	cleanSummary := strings.TrimSpace(summary)

	var identifier string
	if normURL != "" && !isGenericURL(normURL) {
		identifier = fmt.Sprintf("url:%s", normURL)
	} else {
		normTitle := strings.ToLower(cleanTitle)
		if idx := strings.Index(normTitle, "]"); idx != -1 && strings.HasPrefix(normTitle, "[") {
			normTitle = strings.TrimSpace(normTitle[idx+1:])
		}
		if normTitle != "" {
			identifier = fmt.Sprintf("title:%s", normTitle)
		} else {
			identifier = fmt.Sprintf("%s:%s:%s", sourceType, sourceName, strings.ToLower(cleanSummary))
		}
	}

	hash := sha256.Sum256([]byte(identifier))
	itemID := hex.EncodeToString(hash[:])

	if metadata == nil {
		metadata = make(map[string]interface{})
	}

	cleanRaw := strings.TrimSpace(rawContent)
	if cleanRaw == "" {
		cleanRaw = cleanSummary
	}

	item := ThreatItem{
		ID:          itemID,
		SourceType:  sourceType,
		SourceName:  sourceName,
		Title:       cleanTitle,
		URL:         normURL,
		Summary:     cleanSummary,
		RawContent:  cleanRaw,
		PublishedAt: publishedAt,
		HarvestedAt: time.Now().UTC(),
		Metadata:    metadata,
	}
	item.ContentHash = ComputeContentHash(item)
	return item
}

// ComputeContentHash computes a canonical SHA256 hash used for pre-analysis deduplication.
func ComputeContentHash(item ThreatItem) string {
	normURL := NormalizeURL(item.URL)
	if normURL != "" && !isGenericURL(normURL) {
		h := sha256.Sum256([]byte("url:" + normURL))
		return hex.EncodeToString(h[:])
	}

	cleanTitle := strings.ToLower(strings.TrimSpace(item.Title))
	if idx := strings.Index(cleanTitle, "]"); idx != -1 && strings.HasPrefix(cleanTitle, "[") {
		cleanTitle = strings.TrimSpace(cleanTitle[idx+1:])
	}
	var b strings.Builder
	for _, r := range cleanTitle {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	normTitle := b.String()
	if normTitle != "" {
		h := sha256.Sum256([]byte("title:" + normTitle))
		return hex.EncodeToString(h[:])
	}

	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", item.SourceType, item.SourceName, strings.ToLower(strings.TrimSpace(item.Summary)))))
	return hex.EncodeToString(h[:])
}

// EnrichedThreat represents analyzed intelligence generated by Gemini AI.
type EnrichedThreat struct {
	ItemID               string         `json:"item_id"`
	Item                 ThreatItem     `json:"item"`
	Severity             Severity       `json:"severity"`
	JapanRelevance       JapanRelevance `json:"japan_relevance"`
	TitleJa              string         `json:"title_ja"`
	SummaryJa            string         `json:"summary_ja"`
	ImpactAnalysisJa     string         `json:"impact_analysis_ja"`
	VictimOrgs           []string       `json:"victim_orgs"`
	ThreatActors         []string       `json:"threat_actors"`
	AttackType           string         `json:"attack_type,omitempty"`
	RecommendedActionsJa []string       `json:"recommended_actions_ja"`
	AnalyzedAt           time.Time      `json:"analyzed_at"`
}
