package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
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
	SeverityCritical      Severity = "Critical"
	SeverityHigh          Severity = "High"
	SeverityMedium        Severity = "Medium"
	SeverityLow           Severity = "Low"
	SeverityInformational Severity = "Informational"
	SeverityInfo          Severity = "Info"
	SeverityUnknown       Severity = "Unknown"
)

// NormalizeDisplaySeverity converts empty, Unknown, or legacy Info severities to Informational for display and storage.
func NormalizeDisplaySeverity(s Severity) Severity {
	trimmed := Severity(strings.TrimSpace(string(s)))
	switch trimmed {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational:
		return trimmed
	default:
		return SeverityInformational
	}
}

type JapanRelevance string

const (
	JapanRelevanceDirect   JapanRelevance = "Direct"
	JapanRelevanceIndirect JapanRelevance = "Indirect"
	JapanRelevanceNone     JapanRelevance = "None"
	JapanRelevanceUnknown  JapanRelevance = "Unknown"
)

// QueueBacklogStats represents current queue depth, pending translations, and accumulated items in the pipeline.
type QueueBacklogStats struct {
	UntranslatedIncidents int `json:"untranslated_incidents"`
	PendingAnalysisItems  int `json:"pending_analysis_items"`
	TotalIncidents        int `json:"total_incidents"`
	TotalThreatItems      int `json:"total_threat_items"`
}

// ThreatItem represents raw normalized threat data gathered from external feeds.
type ThreatItem struct {
	ID            string                 `json:"id"`
	IncidentID    string                 `json:"incident_id,omitempty"`
	ContentHash   string                 `json:"content_hash,omitempty"`
	SourceType    SourceType             `json:"source_type"`
	SourceName    string                 `json:"source_name"`
	Title         string                 `json:"title"`
	URL           string                 `json:"url,omitempty"`
	Summary       string                 `json:"summary"`
	RawContent    string                 `json:"raw_content,omitempty"`
	FetchStatus   string                 `json:"fetch_status,omitempty"` // none, pending, fetching, completed, failed
	FetchAttempts int                    `json:"fetch_attempts,omitempty"`
	FetchError    string                 `json:"fetch_error,omitempty"`
	FetchedAt     *time.Time             `json:"fetched_at,omitempty"`
	PublishedAt   *time.Time             `json:"published_at,omitempty"`
	HarvestedAt   time.Time              `json:"harvested_at"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
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

var (
	accountHandleRegex  = regexp.MustCompile(`(?i)\s*\(@?[A-Za-z0-9_]+(?:\s*[\/&,]\s*@?[A-Za-z0-9_]+)*\)`)
	rawSearchQueryRegex = regexp.MustCompile(`(?i)^(?:WebSearch|X|XMonitor|DarkWeb):\s*[\(\[].*`)
	SearXNGQueryRegex   = regexp.MustCompile(`(?s)\n*\s*\[SearXNG Query:[^\]]*\]\s*(\n\s*\[Engine:[^\]]*\])?\s*(\n\s*\[URL:[^\]]*\])?`)

	knownPublishers = map[string]string{
		"scan.netsecurity.ne.jp":   "ScanNetSecurity",
		"security-next.com":        "Security Next",
		"news.yahoo.co.jp":         "Yahoo! ニュース",
		"nikkei.com":               "日本経済新聞",
		"asahi.com":                "朝日新聞",
		"mainichi.jp":              "毎日新聞",
		"yomiuri.co.jp":            "読売新聞",
		"nhk.or.jp":                "NHK NEWS",
		"jiji.com":                 "時事通信",
		"kyodo.co.jp":              "共同通信",
		"itmedia.co.jp":            "ITmedia",
		"zdnet.com":                "ZDNet Japan",
		"japan.zdnet.com":          "ZDNet Japan",
		"japan.cnet.com":           "CNET Japan",
		"techcrunch.com":           "TechCrunch",
		"bleepingcomputer.com":     "BleepingComputer",
		"thehackernews.com":        "The Hacker News",
		"krebsonsecurity.com":      "Krebs on Security",
		"darkreading.com":          "Dark Reading",
		"securityweek.com":         "SecurityWeek",
		"cyberplace.jp":            "CyberPlace",
		"jpcert.or.jp":             "JPCERT/CC",
		"ipa.go.jp":                "IPA",
		"cisa.gov":                 "CISA",
		"ransomware.live":          "Ransomware.live",
		"ransomfeed.it":            "RansomFeed",
		"sbbit.jp":                 "ビジネス+IT (sbbit.jp)",
		"speedsystem-jp.com":       "SpeedSystem Blog",
		"minpo.jp":                 "民報ニュース",
		"chiba-tv.com":             "千葉テレビ",
		"socradar.io":              "SOCRadar",
		"crowdsec.net":             "CrowdSec",
		"cysec148.hatenablog.com":  "CySec148 Blog",
		"mytech-blog.com":          "MY TECH BLOG",
		"cyber.spool.co.jp":        "Cyber Spool",
		"cyberhubpodcast.com":      "CyberHub Podcast",
		"dailysecurityreview.com":  "Daily Security Review",
		"mylinux.work":             "MyLinux.work",
		"dev.to":                   "DEV Community",
		"hub.ivanti.com":           "Ivanti Security Advisory",
	}
)

// ExtractSourceFromURL derives the human-readable publisher name or clean domain from a URL.
// Search engines (like SearXNG) are discovery mechanisms, not sources.
func ExtractSourceFromURL(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "Web Source"
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return "Web Source"
	}

	host := strings.ToLower(u.Host)
	if colonIdx := strings.Index(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}
	cleanHost := strings.TrimPrefix(host, "www.")
	cleanHost = strings.TrimPrefix(cleanHost, "www3.")

	// Direct match
	if pub, ok := knownPublishers[cleanHost]; ok {
		return pub
	}

	// Suffix match (e.g. news.itmedia.co.jp -> ITmedia)
	for d, pub := range knownPublishers {
		if strings.HasSuffix(cleanHost, "."+d) {
			return pub
		}
	}

	// X (Twitter) status
	if cleanHost == "x.com" || cleanHost == "twitter.com" {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) >= 1 && parts[0] != "" && parts[0] != "i" && parts[0] != "search" {
			return fmt.Sprintf("X: @%s", parts[0])
		}
		return "X (Twitter)"
	}

	// Onion leak site / service
	if strings.HasSuffix(cleanHost, ".onion") {
		if len(cleanHost) > 24 {
			return fmt.Sprintf("Onion: %s...onion", cleanHost[:16])
		}
		return fmt.Sprintf("Onion: %s", cleanHost)
	}

	return cleanHost
}

// SanitizeSourceNameWithURL standardizes source names using both the declared name and the actual URL.
// If the source name refers to a search engine (e.g. SearXNG) or is a query leak, the true source
// is extracted from the publisher's URL.
func SanitizeSourceNameWithURL(sourceType SourceType, name string, rawURL string) string {
	s := strings.TrimSpace(name)
	isSearXNG := strings.Contains(strings.ToLower(s), "searxng")
	isQueryLeak := rawSearchQueryRegex.MatchString(s) || strings.Contains(s, " OR ") || strings.Contains(s, " AND ") || strings.Contains(s, "site:")
	isGeneric := s == "" || s == "Web Search" || s == "WebSearch" || s == "Web Search (Tor)" || s == "Tor / Onion"

	if (isSearXNG || isQueryLeak || isGeneric) && rawURL != "" {
		extracted := ExtractSourceFromURL(rawURL)
		if extracted != "" && extracted != "Web Source" {
			return extracted
		}
	}

	return SanitizeSourceName(sourceType, name)
}

// SanitizeSourceName standardizes source names:
// 1. Replaces engine branding ("SearXNG Web" -> "Web News", "SearXNG Cross-Search" -> "Tor / Onion")
// 2. Strips specific account names/handles e.g. "(piyokango / JPCERT)"
// 3. Sanitizes boolean query leaks e.g. "WebSearch:(..."
func SanitizeSourceName(sourceType SourceType, name string) string {
	s := strings.TrimSpace(name)
	if s == "" {
		switch sourceType {
		case SourceTypeVendorRSS:
			return "Vendor Security Advisory"
		case SourceTypeTelegram:
			return "Telegram CTI Feed"
		case SourceTypeDarkwebOnion:
			return "Tor / Onion"
		case SourceTypeRansomwareTracker:
			return "Ransomware Tracker"
		case SourceTypeXMonitor:
			return "X / SNS: 国内セキュリティ速報"
		case SourceTypeWebSearch:
			return "Web News"
		default:
			return "Threat Intelligence Source"
		}
	}

	// Replace SearXNG references with clean semantic names
	s = strings.ReplaceAll(s, "SearXNG Web:", "Web News:")
	s = strings.ReplaceAll(s, "SearXNG Cross-Search:", "Tor / Onion:")
	s = strings.ReplaceAll(s, "SearXNG Web", "Web News")
	s = strings.ReplaceAll(s, "SearXNG Cross-Search", "Tor / Onion")
	s = strings.ReplaceAll(s, "SearXNG", "Web Source")

	// Strip specific account handles in parentheses e.g. "(piyokango / JPCERT)"
	s = accountHandleRegex.ReplaceAllString(s, "")
	if strings.HasPrefix(s, "X:@") || strings.HasPrefix(s, "XMonitor:@") {
		s = "X: 国内セキュリティ速報"
	}

	// Clean raw boolean query leaks e.g. "WebSearch:(ランサムウェア OR サイバー攻撃)"
	if rawSearchQueryRegex.MatchString(s) || strings.Contains(s, " OR ") || strings.Contains(s, " AND ") || strings.Contains(s, "site:x.com") {
		switch sourceType {
		case SourceTypeXMonitor:
			s = "X: 国内セキュリティ速報"
		case SourceTypeDarkwebOnion:
			s = "Tor / Onion: 脅威探索"
		default:
			s = "Web News: 国内脅威速報"
		}
	}

	s = strings.TrimSpace(s)
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	return s
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
	cleanSourceName := SanitizeSourceNameWithURL(sourceType, sourceName, normURL)

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
			identifier = fmt.Sprintf("%s:%s:%s", sourceType, cleanSourceName, strings.ToLower(cleanSummary))
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
	} else {
		// Strip any internal search query leaks
		cleanRaw = strings.TrimSpace(SearXNGQueryRegex.ReplaceAllString(cleanRaw, ""))
		if cleanRaw == "" {
			cleanRaw = cleanSummary
		}
	}

	item := ThreatItem{
		ID:          itemID,
		SourceType:  sourceType,
		SourceName:  cleanSourceName,
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

// EnrichedThreat represents analyzed intelligence generated by AI.
type EnrichedThreat struct {
	ItemID               string         `json:"item_id"`
	Item                 ThreatItem     `json:"item"`
	Severity             Severity       `json:"severity"`
	JapanRelevance       JapanRelevance `json:"japan_relevance"`
	Title                string         `json:"title,omitempty"`
	TitleJa              string         `json:"title_ja,omitempty"`
	Summary              string         `json:"summary,omitempty"`
	SummaryJa            string         `json:"summary_ja,omitempty"`
	ImpactAnalysis       string         `json:"impact_analysis,omitempty"`
	ImpactAnalysisJa     string         `json:"impact_analysis_ja,omitempty"`
	VictimOrgs           []string          `json:"victim_orgs"`
	ThreatActors         []string          `json:"threat_actors"`
	ThreatActorReasons   map[string]string `json:"threat_actor_reasons,omitempty"`
	AttackType           string            `json:"attack_type,omitempty"`
	CVEs                 []string          `json:"cves,omitempty"`
	AffectedProducts     []string          `json:"affected_products,omitempty"`
	RecommendedActions   []string          `json:"recommended_actions,omitempty"`
	RecommendedActionsJa []string          `json:"recommended_actions_ja,omitempty"`
	AnalyzedAt           time.Time         `json:"analyzed_at"`
}

var flexibleTimeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02 15:04:05.999999999-0700",
	"2006-01-02 15:04:05-0700",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
}

// ParseFlexibleTime parses RFC3339 as well as Python str(datetime) space-separated timestamps.
func ParseFlexibleTime(raw string) (time.Time, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || s == "null" {
		return time.Time{}, false
	}
	for _, layout := range flexibleTimeLayouts {
		if parsed, err := time.Parse(layout, s); err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}

// UnmarshalJSON supports both RFC3339 and Python space-separated timestamps in ThreatItem JSON.
func (t *ThreatItem) UnmarshalJSON(data []byte) error {
	type Alias ThreatItem
	aux := &struct {
		FetchedAt   *string `json:"fetched_at"`
		PublishedAt *string `json:"published_at"`
		HarvestedAt string  `json:"harvested_at"`
		*Alias
	}{
		Alias: (*Alias)(t),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.FetchedAt != nil {
		if parsed, ok := ParseFlexibleTime(*aux.FetchedAt); ok {
			t.FetchedAt = &parsed
		} else {
			t.FetchedAt = nil
		}
	}
	if aux.PublishedAt != nil {
		if parsed, ok := ParseFlexibleTime(*aux.PublishedAt); ok {
			t.PublishedAt = &parsed
		} else {
			t.PublishedAt = nil
		}
	}
	if parsed, ok := ParseFlexibleTime(aux.HarvestedAt); ok {
		t.HarvestedAt = parsed
	}
	return nil
}

// UnmarshalJSON supports both RFC3339 and Python space-separated timestamps in EnrichedThreat JSON.
func (e *EnrichedThreat) UnmarshalJSON(data []byte) error {
	type Alias EnrichedThreat
	aux := &struct {
		AnalyzedAt string `json:"analyzed_at"`
		*Alias
	}{
		Alias: (*Alias)(e),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if parsed, ok := ParseFlexibleTime(aux.AnalyzedAt); ok {
		e.AnalyzedAt = parsed
	}
	return nil
}
