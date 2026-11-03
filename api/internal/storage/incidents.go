package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/al17091/threat_harvester/api/internal/models"
)

const incidentSelectCols = `
	id, victim_org, normalized_victim_org, cves, affected_product, title, summary_ja, impact_analysis_ja,
	severity, japan_relevance, attack_type, raw_content, primary_url, source_urls, sources_detail,
	first_seen_at, last_seen_at, report_count, threat_actors, created_at, updated_at,
	COALESCE(title_ja, ''), COALESCE(victim_org_en, ''), COALESCE(victim_org_ja, ''), COALESCE(affected_product_en, ''), COALESCE(affected_product_ja, ''),
	COALESCE(summary, ''), COALESCE(impact_analysis, '')
`

// normalizeClusterURL sanitizes a URL for incident clustering by removing tracking query parameters and trailing slashes.
func normalizeClusterURL(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return ""
	}
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""

	// Strip common tracking and referral query parameters
	if u.RawQuery != "" {
		q := u.Query()
		trackingParams := []string{
			"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
			"ref", "source", "fbclid", "gclid", "yclid", "mc_cid", "mc_eid",
		}
		for _, p := range trackingParams {
			q.Del(p)
		}
		u.RawQuery = q.Encode()
	}

	clean := u.String()
	// Trim trailing slash for path > 1 to unify "example.com/path/" and "example.com/path"
	if len(u.Path) > 1 && strings.HasSuffix(clean, "/") {
		clean = strings.TrimSuffix(clean, "/")
	}
	return clean
}

// isClusterableURL checks if a URL is specific and stable enough to be used as an incident clustering key.
func isClusterableURL(rawURL string) bool {
	norm := normalizeClusterURL(rawURL)
	if norm == "" || len(norm) < 15 {
		return false
	}
	u, err := url.Parse(norm)
	if err != nil || u.Host == "" {
		return false
	}

	// Reject domain root URLs (no path or just "/")
	if u.Path == "" || u.Path == "/" {
		return false
	}

	host := strings.ToLower(u.Host)
	path := strings.ToLower(u.Path)

	// Reject social, bookmark, search redirect hubs
	excludedHosts := []string{
		"b.hatena.ne.jp", "twitter.com", "x.com", "t.co", "facebook.com",
		"vertexaisearch.cloud.google.com", "google.com", "search.yahoo.co.jp",
		"bing.com", "duckduckgo.com",
	}
	for _, eh := range excludedHosts {
		if host == eh || strings.HasSuffix(host, "."+eh) {
			return false
		}
	}

	// Reject common generic catalog/definition directories
	genericPaths := []string{
		"/known-exploited-vulnerabilities-catalog",
		"/data/definitions",
		"/rss", "/feed", "/atom",
	}
	for _, gp := range genericPaths {
		if path == gp || strings.HasSuffix(path, gp) {
			return false
		}
	}

	return true
}

func sliceContainsExact(list []string, target string) bool {
	for _, s := range list {
		if normalizeClusterURL(s) == target || s == target {
			return true
		}
	}
	return false
}

// isWithinWindow checks if itemTime falls within sliding window of the incident.
func isWithinWindow(inc *models.Incident, itemTime time.Time, windowDuration time.Duration) bool {
	if !itemTime.Before(inc.LastSeenAt) {
		return itemTime.Sub(inc.LastSeenAt) <= windowDuration
	}
	if itemTime.Before(inc.FirstSeenAt) {
		return inc.FirstSeenAt.Sub(itemTime) <= windowDuration
	}
	return true
}

// FindOrCreateIncident matches an incoming report to an existing clustered incident
// using matching CVEs, same affected products, or victim organizations within a sliding window,
// or creates a new STIX 2.1 compliant parent incident.
func (s *SQLStore) FindOrCreateIncident(
	ctx context.Context,
	item models.ThreatItem,
	enriched *models.EnrichedThreat,
	windowDays int,
) (*models.Incident, error) {
	if windowDays <= 0 {
		windowDays = 30
	}
	windowDuration := time.Duration(windowDays) * 24 * time.Hour

	itemTime := time.Now().UTC()
	if item.PublishedAt != nil && !item.PublishedAt.IsZero() {
		itemTime = item.PublishedAt.UTC()
	} else if !item.HarvestedAt.IsZero() {
		itemTime = item.HarvestedAt.UTC()
	}

	rawVictim, normVictim := models.ExtractVictimOrg(item, enriched)

	// Extract CVEs strictly from targeted report fields (Title, Summary, enriched.CVEs).
	// Do NOT extract from RawContent or URL, which contain third-party crawler noise, linked articles, and external summaries.
	cves := models.ExtractCVEs(item.Title, item.Summary)
	if enriched != nil && len(enriched.CVEs) > 0 {
		cves = models.ExtractCVEs(append(cves, enriched.CVEs...)...)
	}

	// Extract Affected Product
	rawProduct, normProduct := models.ExtractAffectedProduct(item, enriched)

	attackType := ""
	if enriched != nil {
		attackType = enriched.AttackType
	}

	// Non-threat content, service releases, PR announcements, corporate PR notices, and Info-level reports MUST NOT be treated as STIX cyber threat incidents.
	if (enriched != nil && enriched.Severity == models.SeverityInfo) ||
		models.IsServiceReleaseOrNonThreat(item, enriched) ||
		models.IsCorporatePRNotice(item.Title, item.Summary, item.RawContent) {
		return nil, nil
	}

	isVuln := len(cves) > 0 || normProduct != "" || strings.EqualFold(attackType, "Vulnerability") || strings.EqualFold(attackType, "Zero-day")

	// Detail record for this source report
	detail := models.SourceDetail{
		Type:        item.SourceType,
		Name:        item.SourceName,
		Title:       item.Title,
		URL:         item.URL,
		PublishedAt: item.PublishedAt,
		HarvestedAt: item.HarvestedAt,
	}

	// Canonical article URLs for exact Track 0 clustering
	// Only valid, specific, article-level URLs are allowed (domain roots, search redirects, and generic catalogs are excluded).
	var candidateURLs []string
	if isClusterableURL(item.URL) {
		candidateURLs = append(candidateURLs, normalizeClusterURL(item.URL))
	}
	if item.Metadata != nil {
		if rawLinks, ok := item.Metadata["linked_urls"]; ok {
			switch links := rawLinks.(type) {
			case []string:
				for _, l := range links {
					if isClusterableURL(l) {
						candidateURLs = append(candidateURLs, normalizeClusterURL(l))
					}
				}
			case []interface{}:
				for _, l := range links {
					if str, ok := l.(string); ok && isClusterableURL(str) {
						candidateURLs = append(candidateURLs, normalizeClusterURL(str))
					}
				}
			}
		}
	}
	candidateURLs = mergeUniqueStrings(nil, candidateURLs)

	var matched *models.Incident

	// TRACK 0: Exact Canonical Article URL Matching
	// Matches incoming reports sharing the exact same specific external article/advisory URL.
	// Uses exact element matching to prevent substring collision across different articles.
	for _, candURL := range candidateURLs {
		candPattern := "%\"" + candURL + "\"%"
		var urlQuery string
		if s.isSQLite {
			urlQuery = `
				SELECT ` + incidentSelectCols + `
				FROM incidents
				WHERE (primary_url = ? OR source_urls LIKE ?)
				ORDER BY last_seen_at DESC
				LIMIT 5
			`
		} else {
			urlQuery = `
				SELECT ` + incidentSelectCols + `
				FROM incidents
				WHERE (primary_url = $1 OR source_urls LIKE $2)
				ORDER BY last_seen_at DESC
				LIMIT 5
			`
		}

		rows, err := s.db.QueryContext(ctx, urlQuery, candURL, candPattern)
		if err == nil {
			for rows.Next() {
				inc, err := scanIncident(rows)
				if err != nil {
					continue
				}
				if isWithinWindow(inc, itemTime, windowDuration) {
					if inc.PrimaryURL == candURL || sliceContainsExact(inc.SourceURLs, candURL) {
						matched = inc
						break
					}
				}
			}
			_ = rows.Close()
		}
		if matched != nil {
			break
		}
	}

	// TRACK 1: Vulnerability & CVE Clustering
	if matched == nil && isVuln && (len(cves) > 0 || normProduct != "") {
		// 1-A. Try matching by identical CVEs
		if len(cves) > 0 {
			var cveConds []string
			var cveArgs []interface{}
			for _, c := range cves {
				cPattern := "%" + c + "%"
				if s.isSQLite {
					cveConds = append(cveConds, "(cves LIKE ? OR title LIKE ?)")
				} else {
					cveConds = append(cveConds, fmt.Sprintf("(cves LIKE $%d OR title ILIKE $%d)", len(cveArgs)+1, len(cveArgs)+2))
				}
				cveArgs = append(cveArgs, cPattern, cPattern)
			}

			cveQuery := `
				SELECT ` + incidentSelectCols + `
				FROM incidents
				WHERE ` + strings.Join(cveConds, " OR ") + `
				ORDER BY last_seen_at DESC
				LIMIT 10
			`
			rows, err := s.db.QueryContext(ctx, cveQuery, cveArgs...)
			if err == nil {
				for rows.Next() {
					inc, err := scanIncident(rows)
					if err != nil {
						continue
					}
					cveWindow := windowDuration
					if cveWindow < 60*24*time.Hour {
						cveWindow = 60 * 24 * time.Hour
					}
					if isWithinWindow(inc, itemTime, cveWindow) {
						// Disjoint CVE guard: must share at least one identical CVE
						if !hasOverlappingCVEs(cves, inc.CVEs) {
							continue
						}
						// Product mismatch guard: if both identify products and they differ, do not merge
						incNorm := models.NormalizeProduct(inc.AffectedProduct)
						if normProduct != "" && incNorm != "" && normProduct != incNorm {
							continue
						}
						// Aggregated digest guard: if existing incident already holds >= 5 CVEs (patch roundup),
						// do not merge an incoming single-product report into the digest
						if len(inc.CVEs) >= 5 && normProduct != "" && incNorm == "" {
							continue
						}
						matched = inc
						break
					}
				}
				_ = rows.Close()
			}
		}

		// 1-B. If no CVE match found, try matching by same affected product
		if matched == nil && normProduct != "" {
			prodPattern := "%" + normProduct + "%"
			prodQuery := `
				SELECT ` + incidentSelectCols + `
				FROM incidents
				WHERE ((affected_product IS NOT NULL AND affected_product != '' AND LOWER(affected_product) LIKE ?) OR LOWER(title) LIKE ?)
				ORDER BY last_seen_at DESC
				LIMIT 10
			`
			if !s.isSQLite {
				prodQuery = `
					SELECT ` + incidentSelectCols + `
					FROM incidents
					WHERE ((affected_product IS NOT NULL AND affected_product != '' AND affected_product ILIKE $1) OR title ILIKE $2)
					ORDER BY last_seen_at DESC
					LIMIT 10
				`
			}

			rows, err := s.db.QueryContext(ctx, prodQuery, prodPattern, prodPattern)
			if err == nil {
				for rows.Next() {
					inc, err := scanIncident(rows)
					if err != nil {
						continue
					}
					if isWithinWindow(inc, itemTime, windowDuration) {
						incNorm := models.NormalizeProduct(inc.AffectedProduct)
						if incNorm == normProduct || strings.Contains(strings.ToLower(inc.Title), normProduct) {
							// Disjoint CVE guard: If both have CVEs and none overlap, they are different vulnerabilities!
							if len(cves) > 0 && len(inc.CVEs) > 0 && !hasOverlappingCVEs(cves, inc.CVEs) {
								continue
							}
							// Zero-day / active exploit isolation guard: Don't cluster an active zero-day RCE with a generic advisory/DoS without shared CVE
							incIsZeroDay := strings.EqualFold(inc.AttackType, "Zero-day") || inc.Severity == models.SeverityCritical
							itemIsZeroDay := strings.EqualFold(attackType, "Zero-day") || (enriched != nil && enriched.Severity == models.SeverityCritical)
							if incIsZeroDay != itemIsZeroDay && (len(cves) == 0 || len(inc.CVEs) == 0) {
								continue
							}
							matched = inc
							break
						}
					}
				}
				_ = rows.Close()
			}
		}
	}

	// TRACK 1.5: Target Organization + Affected Product Clustering
	// Aggregates reports concerning the same specific product/service belonging to a target organization
	// (e.g. GMO + Onamae Desktop Cloud) regardless of attack type, while preventing false mergers
	// across distinct products or different organizations with similarly named products.
	if matched == nil && normVictim != "" && !models.IsGenericVictimOrg(rawVictim) && (normProduct != "" || rawProduct != "") {
		prodTarget := normProduct
		if prodTarget == "" {
			prodTarget = strings.ToLower(rawProduct)
		}
		prodPattern := "%" + prodTarget + "%"

		var orgProdQuery string
		if s.isSQLite {
			orgProdQuery = `
				SELECT ` + incidentSelectCols + `
				FROM incidents
				WHERE normalized_victim_org = ?
				  AND (
					(affected_product IS NOT NULL AND affected_product != '' AND LOWER(affected_product) LIKE ?)
					OR LOWER(title) LIKE ?
					OR LOWER(title_ja) LIKE ?
				  )
				ORDER BY last_seen_at DESC
				LIMIT 5
			`
		} else {
			orgProdQuery = `
				SELECT ` + incidentSelectCols + `
				FROM incidents
				WHERE normalized_victim_org = $1
				  AND (
					(affected_product IS NOT NULL AND affected_product != '' AND (affected_product ILIKE $2 OR LOWER(affected_product) LIKE $3))
					OR title ILIKE $2
					OR title_ja ILIKE $2
				  )
				ORDER BY last_seen_at DESC
				LIMIT 5
			`
		}

		var rows *sql.Rows
		var err error
		if s.isSQLite {
			rows, err = s.db.QueryContext(ctx, orgProdQuery, normVictim, prodPattern, prodPattern, prodPattern)
		} else {
			rows, err = s.db.QueryContext(ctx, orgProdQuery, normVictim, prodPattern, prodPattern)
		}

		if err == nil {
			for rows.Next() {
				inc, err := scanIncident(rows)
				if err != nil {
					continue
				}
				if isWithinWindow(inc, itemTime, windowDuration) {
					// Guard: Disjoint CVEs indicate separate vulnerabilities even within the same organization/product
					if len(cves) > 0 && len(inc.CVEs) > 0 && !hasOverlappingCVEs(cves, inc.CVEs) {
						continue
					}
					matched = inc
					break
				}
			}
			_ = rows.Close()
		}
	}

	// TRACK 2: Specific Victim Org Clustering (Targeted Cyberattacks, Ransomware, Data Breaches)
	if matched == nil && normVictim != "" && !models.IsGenericVictimOrg(rawVictim) {
		query := `
			SELECT ` + incidentSelectCols + `
			FROM incidents
			WHERE normalized_victim_org = ?
			ORDER BY last_seen_at DESC
			LIMIT 5
		`
		if !s.isSQLite {
			query = `
				SELECT ` + incidentSelectCols + `
				FROM incidents
				WHERE normalized_victim_org = $1
				ORDER BY last_seen_at DESC
				LIMIT 5
			`
		}

		rows, err := s.db.QueryContext(ctx, query, normVictim)
		if err == nil {
			for rows.Next() {
				inc, err := scanIncident(rows)
				if err != nil {
					continue
				}
				if isWithinWindow(inc, itemTime, windowDuration) {
					// Guard: If both existing incident and incoming report identify specific distinct products,
					// do not merge them under the general organization (e.g. GMO infoQ vs GMO Desktop Cloud).
					incNormProd := models.NormalizeProduct(inc.AffectedProduct)
					if incNormProd != "" && normProduct != "" && incNormProd != normProduct {
						continue
					}
					// Guard: Disjoint CVEs indicate distinct security advisories
					if len(cves) > 0 && len(inc.CVEs) > 0 && !hasOverlappingCVEs(cves, inc.CVEs) {
						continue
					}
					matched = inc
					break
				}
			}
			_ = rows.Close()
		}
	}

	// If matched, merge details & save
	if matched != nil {
		if itemTime.After(matched.LastSeenAt) {
			matched.LastSeenAt = itemTime
		}
		if itemTime.Before(matched.FirstSeenAt) {
			matched.FirstSeenAt = itemTime
		}

		// Prevent double counting of the same report if it was already processed or scraped
		alreadyContained := false
		for _, sd := range matched.SourcesDetail {
			if (item.URL != "" && sd.URL == item.URL) || (item.Title != "" && sd.Title == item.Title) {
				alreadyContained = true
				break
			}
		}
		if !alreadyContained {
			matched.ReportCount++
		}

		matched.CVEs = mergeUniqueStrings(matched.CVEs, cves)
		if matched.AffectedProduct == "" && rawProduct != "" {
			matched.AffectedProduct = rawProduct
		}

		if enriched != nil {
			newSevScore := models.SeverityScore(enriched.Severity)
			oldSevScore := models.SeverityScore(matched.Severity)

			// Elevate severity & relevance to the highest observed level across all clustered reports
			matched.Severity = models.HigherSeverity(matched.Severity, enriched.Severity)
			matched.JapanRelevance = models.HigherRelevance(matched.JapanRelevance, enriched.JapanRelevance)

			// Priority update for title, summary, and impact analysis:
			// If incoming report has strictly HIGHER severity score, its title/summary/impact takes precedence.
			// If incoming report has LOWER severity, do NOT overwrite the existing higher-severity title/summary.
			// If EQUAL severity, fill in empty fields only.
			if newSevScore > oldSevScore {
				if enriched.Title != "" {
					matched.Title = enriched.Title
				}
				if enriched.TitleJa != "" {
					matched.TitleJa = enriched.TitleJa
				}
				if enriched.Summary != "" {
					matched.Summary = enriched.Summary
				}
				if enriched.SummaryJa != "" {
					matched.SummaryJa = enriched.SummaryJa
				}
				if enriched.ImpactAnalysis != "" {
					matched.ImpactAnalysis = enriched.ImpactAnalysis
				}
				if enriched.ImpactAnalysisJa != "" {
					matched.ImpactAnalysisJa = enriched.ImpactAnalysisJa
				}
				if enriched.AttackType != "" {
					matched.AttackType = enriched.AttackType
				}
			} else {
				// Equal or lower severity: only fill in missing fields, never overwrite existing higher/equal
				if matched.Title == "" && enriched.Title != "" {
					matched.Title = enriched.Title
				} else if isJapaneseText(matched.Title) && enriched.Title != "" && !isJapaneseText(enriched.Title) {
					// Prefer English canonical title for matched.Title if previously assigned Japanese text
					matched.Title = enriched.Title
				}
				if matched.TitleJa == "" && enriched.TitleJa != "" {
					matched.TitleJa = enriched.TitleJa
				}
				if matched.Summary == "" && enriched.Summary != "" {
					matched.Summary = enriched.Summary
				}
				if (matched.SummaryJa == "" || matched.SummaryJa == matched.Summary) && enriched.SummaryJa != "" && enriched.SummaryJa != enriched.Summary {
					matched.SummaryJa = enriched.SummaryJa
				} else if matched.SummaryJa == "" && enriched.SummaryJa != "" {
					matched.SummaryJa = enriched.SummaryJa
				}
				if matched.ImpactAnalysis == "" && enriched.ImpactAnalysis != "" {
					matched.ImpactAnalysis = enriched.ImpactAnalysis
				}
				if (matched.ImpactAnalysisJa == "" || matched.ImpactAnalysisJa == matched.ImpactAnalysis) && enriched.ImpactAnalysisJa != "" && enriched.ImpactAnalysisJa != enriched.ImpactAnalysis {
					matched.ImpactAnalysisJa = enriched.ImpactAnalysisJa
				} else if matched.ImpactAnalysisJa == "" && enriched.ImpactAnalysisJa != "" {
					matched.ImpactAnalysisJa = enriched.ImpactAnalysisJa
				}
				if matched.AttackType == "" && enriched.AttackType != "" {
					matched.AttackType = enriched.AttackType
				}
			}

			matched.ThreatActors = models.FilterGroundedThreatActors(
				mergeUniqueStrings(matched.ThreatActors, enriched.ThreatActors),
				matched.Title, matched.TitleJa, matched.RawContent, matched.Summary, matched.SummaryJa,
				item.Title, item.RawContent, item.Summary,
			)
		}

		if matched.AttackType == "" && isVuln {
			matched.AttackType = "Vulnerability"
		}

		// Merge raw content from newly incoming report
		newRaw := strings.TrimSpace(item.RawContent)
		if newRaw == "" {
			newRaw = strings.TrimSpace(item.Summary)
		}
		if newRaw != "" && !strings.Contains(matched.RawContent, newRaw) {
			if matched.RawContent != "" {
				matched.RawContent += "\n\n---\n\n" + newRaw
			} else {
				matched.RawContent = newRaw
			}
		}

		if matched.PrimaryURL == "" && len(candidateURLs) > 0 {
			matched.PrimaryURL = candidateURLs[0]
		} else if matched.PrimaryURL == "" && item.URL != "" {
			matched.PrimaryURL = item.URL
		}

		for _, u := range candidateURLs {
			matched.SourceURLs = appendUniqueString(matched.SourceURLs, u)
		}
		matched.SourcesDetail = appendSourceDetail(matched.SourcesDetail, detail)
		if item.Metadata != nil {
			if rawLinks, ok := item.Metadata["linked_urls"]; ok {
				matched.SourcesDetail = appendLinkedSourceDetails(matched.SourcesDetail, rawLinks, item.PublishedAt)
			}
		}
		matched.UpdatedAt = time.Now().UTC()

		if err := s.updateIncident(ctx, matched); err != nil {
			return nil, err
		}
		return matched, nil
	}

	// TRACK 3: No match found within sliding window -> create new incident
	inc := s.buildNewIncident(item, enriched, rawVictim, normVictim, cves, rawProduct, itemTime, detail, candidateURLs)
	if inc.AttackType == "" && isVuln {
		inc.AttackType = "Vulnerability"
	}
	if err := s.insertIncident(ctx, inc); err != nil {
		return nil, err
	}
	return inc, nil
}

func (s *SQLStore) buildNewIncident(
	item models.ThreatItem,
	enriched *models.EnrichedThreat,
	rawVictim, normVictim string,
	cves []string,
	rawProduct string,
	itemTime time.Time,
	detail models.SourceDetail,
	candidateURLs []string,
) *models.Incident {
	id := models.NewSTIXIncidentID()
	title := item.Title
	titleJa := ""
	summary := item.Summary
	summaryJa := item.Summary
	impact := ""
	impactJa := ""
	sev := models.SeverityUnknown
	jrel := models.JapanRelevanceUnknown
	attackType := ""
	var threatActors []string

	if enriched != nil {
		if enriched.Title != "" {
			title = enriched.Title
		}
		if enriched.TitleJa != "" {
			titleJa = enriched.TitleJa
		} else if strings.TrimSpace(item.Title) != "" && isJapaneseText(item.Title) {
			titleJa = strings.TrimSpace(item.Title)
		}

		if enriched.Summary != "" {
			summary = enriched.Summary
		}
		if enriched.SummaryJa != "" {
			summaryJa = enriched.SummaryJa
		} else if enriched.Summary != "" {
			summaryJa = enriched.Summary
		} else if strings.TrimSpace(item.Summary) != "" {
			summaryJa = strings.TrimSpace(item.Summary)
		}

		if enriched.ImpactAnalysis != "" {
			impact = enriched.ImpactAnalysis
		}
		if enriched.ImpactAnalysisJa != "" {
			impactJa = enriched.ImpactAnalysisJa
		} else if enriched.ImpactAnalysis != "" {
			impactJa = enriched.ImpactAnalysis
		}
		sev = enriched.Severity
		jrel = enriched.JapanRelevance
		attackType = enriched.AttackType
		threatActors = models.FilterGroundedThreatActors(
			enriched.ThreatActors,
			item.Title, item.Summary, item.RawContent, item.URL,
		)
	}

	if attackType == "" && (len(cves) > 0 || rawProduct != "") {
		attackType = "Vulnerability"
	}

	vOrg := rawVictim
	if vOrg == "" {
		vOrg = "Unknown"
	}

	rawContent := strings.TrimSpace(item.RawContent)
	if rawContent == "" {
		rawContent = strings.TrimSpace(item.Summary)
	}

	var sourceURLs []string
	for _, u := range candidateURLs {
		if u != "" {
			sourceURLs = appendUniqueString(sourceURLs, u)
		}
	}
	if len(sourceURLs) == 0 && item.URL != "" {
		sourceURLs = append(sourceURLs, item.URL)
	}

	sourcesDetail := []models.SourceDetail{detail}
	if item.Metadata != nil {
		if rawLinks, ok := item.Metadata["linked_urls"]; ok {
			sourcesDetail = appendLinkedSourceDetails(sourcesDetail, rawLinks, item.PublishedAt)
		}
	}

	now := time.Now().UTC()
	return &models.Incident{
		ID:                  id,
		VictimOrg:           vOrg,
		NormalizedVictimOrg: normVictim,
		CVEs:                cves,
		AffectedProduct:     rawProduct,
		Title:               title,
		TitleJa:             titleJa,
		Summary:             summary,
		SummaryJa:           summaryJa,
		ImpactAnalysis:      impact,
		ImpactAnalysisJa:    impactJa,
		Severity:            sev,
		JapanRelevance:      jrel,
		AttackType:          attackType,
		RawContent:          rawContent,
		PrimaryURL:          item.URL,
		SourceURLs:          sourceURLs,
		SourcesDetail:       sourcesDetail,
		FirstSeenAt:         itemTime,
		LastSeenAt:          itemTime,
		ReportCount:         1,
		ThreatActors:        threatActors,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
}

func appendLinkedSourceDetails(details []models.SourceDetail, rawLinks interface{}, pubDate *time.Time) []models.SourceDetail {
	var urls []string
	switch links := rawLinks.(type) {
	case []string:
		urls = links
	case []interface{}:
		for _, l := range links {
			if str, ok := l.(string); ok && str != "" {
				urls = append(urls, str)
			}
		}
	}

	for _, u := range urls {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		domain := extractDomainFromURL(u)
		linkedDetail := models.SourceDetail{
			Type:        models.SourceTypeVendorRSS,
			Name:        fmt.Sprintf("Ref:%s", domain),
			Title:       fmt.Sprintf("Linked Reference: %s", u),
			URL:         u,
			PublishedAt: pubDate,
			HarvestedAt: time.Now().UTC(),
		}
		details = appendSourceDetail(details, linkedDetail)
	}
	return details
}

func extractDomainFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Host
}

func (s *SQLStore) insertIncident(ctx context.Context, inc *models.Incident) error {
	cvesJSON, _ := json.Marshal(inc.CVEs)
	srcURLsJSON, _ := json.Marshal(inc.SourceURLs)
	srcDetailJSON, _ := json.Marshal(inc.SourcesDetail)
	actorsJSON, _ := json.Marshal(inc.ThreatActors)

	firstStr := inc.FirstSeenAt.UTC().Format(time.RFC3339)
	lastStr := inc.LastSeenAt.UTC().Format(time.RFC3339)
	createdStr := inc.CreatedAt.UTC().Format(time.RFC3339)
	updatedStr := inc.UpdatedAt.UTC().Format(time.RFC3339)

	var query string
	if s.isSQLite {
		query = `
			INSERT INTO incidents (
				id, victim_org, normalized_victim_org, cves, affected_product, title, summary_ja, impact_analysis_ja,
				severity, japan_relevance, attack_type, raw_content, primary_url, source_urls, sources_detail,
				first_seen_at, last_seen_at, report_count, threat_actors, created_at, updated_at,
				title_ja, victim_org_en, victim_org_ja, affected_product_en, affected_product_ja,
				summary, impact_analysis
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`
	} else {
		query = `
			INSERT INTO incidents (
				id, victim_org, normalized_victim_org, cves, affected_product, title, summary_ja, impact_analysis_ja,
				severity, japan_relevance, attack_type, raw_content, primary_url, source_urls, sources_detail,
				first_seen_at, last_seen_at, report_count, threat_actors, created_at, updated_at,
				title_ja, victim_org_en, victim_org_ja, affected_product_en, affected_product_ja,
				summary, impact_analysis
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)
		`
	}

	_, err := s.db.ExecContext(ctx, query,
		inc.ID,
		inc.VictimOrg,
		inc.NormalizedVictimOrg,
		string(cvesJSON),
		inc.AffectedProduct,
		inc.Title,
		inc.SummaryJa,
		inc.ImpactAnalysisJa,
		string(inc.Severity),
		string(inc.JapanRelevance),
		inc.AttackType,
		inc.RawContent,
		inc.PrimaryURL,
		string(srcURLsJSON),
		string(srcDetailJSON),
		firstStr,
		lastStr,
		inc.ReportCount,
		string(actorsJSON),
		createdStr,
		updatedStr,
		inc.TitleJa,
		inc.VictimOrgEn,
		inc.VictimOrgJa,
		inc.AffectedProductEn,
		inc.AffectedProductJa,
		inc.Summary,
		inc.ImpactAnalysis,
	)
	return err
}

func (s *SQLStore) updateIncident(ctx context.Context, inc *models.Incident) error {
	cvesJSON, _ := json.Marshal(inc.CVEs)
	srcURLsJSON, _ := json.Marshal(inc.SourceURLs)
	srcDetailJSON, _ := json.Marshal(inc.SourcesDetail)
	actorsJSON, _ := json.Marshal(inc.ThreatActors)

	firstStr := inc.FirstSeenAt.UTC().Format(time.RFC3339)
	lastStr := inc.LastSeenAt.UTC().Format(time.RFC3339)
	updatedStr := inc.UpdatedAt.UTC().Format(time.RFC3339)

	var query string
	if s.isSQLite {
		query = `
			UPDATE incidents SET
				cves = ?,
				affected_product = ?,
				title = ?,
				summary_ja = ?,
				impact_analysis_ja = ?,
				severity = ?,
				japan_relevance = ?,
				attack_type = ?,
				raw_content = ?,
				primary_url = ?,
				source_urls = ?,
				sources_detail = ?,
				first_seen_at = ?,
				last_seen_at = ?,
				report_count = ?,
				threat_actors = ?,
				updated_at = ?,
				title_ja = COALESCE(NULLIF(?, ''), title_ja),
				victim_org_en = COALESCE(NULLIF(?, ''), victim_org_en),
				victim_org_ja = COALESCE(NULLIF(?, ''), victim_org_ja),
				affected_product_en = COALESCE(NULLIF(?, ''), affected_product_en),
				affected_product_ja = COALESCE(NULLIF(?, ''), affected_product_ja),
				summary = COALESCE(NULLIF(?, ''), summary),
				impact_analysis = COALESCE(NULLIF(?, ''), impact_analysis)
			WHERE id = ?
		`
	} else {
		query = `
			UPDATE incidents SET
				cves = $1,
				affected_product = $2,
				title = $3,
				summary_ja = $4,
				impact_analysis_ja = $5,
				severity = $6,
				japan_relevance = $7,
				attack_type = $8,
				raw_content = $9,
				primary_url = $10,
				source_urls = $11,
				sources_detail = $12,
				first_seen_at = $13,
				last_seen_at = $14,
				report_count = $15,
				threat_actors = $16,
				updated_at = $17,
				title_ja = COALESCE(NULLIF($18, ''), title_ja),
				victim_org_en = COALESCE(NULLIF($19, ''), victim_org_en),
				victim_org_ja = COALESCE(NULLIF($20, ''), victim_org_ja),
				affected_product_en = COALESCE(NULLIF($21, ''), affected_product_en),
				affected_product_ja = COALESCE(NULLIF($22, ''), affected_product_ja),
				summary = COALESCE(NULLIF($23, ''), summary),
				impact_analysis = COALESCE(NULLIF($24, ''), impact_analysis)
			WHERE id = $25
		`
	}

	var err error
	if s.isSQLite {
		_, err = s.db.ExecContext(ctx, query,
			string(cvesJSON),
			inc.AffectedProduct,
			inc.Title,
			inc.SummaryJa,
			inc.ImpactAnalysisJa,
			string(inc.Severity),
			string(inc.JapanRelevance),
			inc.AttackType,
			inc.RawContent,
			inc.PrimaryURL,
			string(srcURLsJSON),
			string(srcDetailJSON),
			firstStr,
			lastStr,
			inc.ReportCount,
			string(actorsJSON),
			updatedStr,
			inc.TitleJa,
			inc.VictimOrgEn,
			inc.VictimOrgJa,
			inc.AffectedProductEn,
			inc.AffectedProductJa,
			inc.Summary,
			inc.ImpactAnalysis,
			inc.ID,
		)
	} else {
		_, err = s.db.ExecContext(ctx, query,
			string(cvesJSON),
			inc.AffectedProduct,
			inc.Title,
			inc.SummaryJa,
			inc.ImpactAnalysisJa,
			string(inc.Severity),
			string(inc.JapanRelevance),
			inc.AttackType,
			inc.RawContent,
			inc.PrimaryURL,
			string(srcURLsJSON),
			string(srcDetailJSON),
			firstStr,
			lastStr,
			inc.ReportCount,
			string(actorsJSON),
			updatedStr,
			inc.TitleJa,
			inc.VictimOrgEn,
			inc.VictimOrgJa,
			inc.AffectedProductEn,
			inc.AffectedProductJa,
			inc.Summary,
			inc.ImpactAnalysis,
			inc.ID,
		)
	}
	return err
}

func scanIncident(scanner interface {
	Scan(dest ...interface{}) error
}) (*models.Incident, error) {
	var (
		id, victimOrg, title, firstSeen, lastSeen, created, updated string
		normVictim, cvesRaw, affProduct                              sql.NullString
		sumJa, impJa, attackType, rawContent, primURL, srcURLs, srcDetail, actors sql.NullString
		sev, jrel                                                    string
		reportCount                                                  int
		titleJa, vOrgEn, vOrgJa, affProdEn, affProdJa                sql.NullString
		sumEn, impEn                                                 sql.NullString
	)

	err := scanner.Scan(
		&id, &victimOrg, &normVictim, &cvesRaw, &affProduct, &title, &sumJa, &impJa,
		&sev, &jrel, &attackType, &rawContent, &primURL, &srcURLs, &srcDetail,
		&firstSeen, &lastSeen, &reportCount, &actors, &created, &updated,
		&titleJa, &vOrgEn, &vOrgJa, &affProdEn, &affProdJa,
		&sumEn, &impEn,
	)
	if err != nil {
		return nil, err
	}

	firstT, _ := time.Parse(time.RFC3339, firstSeen)
	lastT, _ := time.Parse(time.RFC3339, lastSeen)
	createdT, _ := time.Parse(time.RFC3339, created)
	updatedT, _ := time.Parse(time.RFC3339, updated)

	var cves []string
	if cvesRaw.Valid && cvesRaw.String != "" {
		_ = json.Unmarshal([]byte(cvesRaw.String), &cves)
	}

	var sourceURLs []string
	if srcURLs.Valid && srcURLs.String != "" {
		_ = json.Unmarshal([]byte(srcURLs.String), &sourceURLs)
	}

	var sourcesDetail []models.SourceDetail
	if srcDetail.Valid && srcDetail.String != "" {
		_ = json.Unmarshal([]byte(srcDetail.String), &sourcesDetail)
	}

	var threatActors []string
	if actors.Valid && actors.String != "" {
		_ = json.Unmarshal([]byte(actors.String), &threatActors)
	}

	return &models.Incident{
		ID:                  id,
		VictimOrg:           victimOrg,
		VictimOrgEn:         vOrgEn.String,
		VictimOrgJa:         vOrgJa.String,
		NormalizedVictimOrg: normVictim.String,
		CVEs:                cves,
		AffectedProduct:     affProduct.String,
		AffectedProductEn:   affProdEn.String,
		AffectedProductJa:   affProdJa.String,
		Title:               title,
		TitleJa:             titleJa.String,
		Summary:             sumEn.String,
		SummaryJa:           sumJa.String,
		ImpactAnalysis:      impEn.String,
		ImpactAnalysisJa:    impJa.String,
		Severity:            models.Severity(sev),
		JapanRelevance:      models.JapanRelevance(jrel),
		AttackType:          attackType.String,
		RawContent:          rawContent.String,
		PrimaryURL:          primURL.String,
		SourceURLs:          sourceURLs,
		SourcesDetail:       sourcesDetail,
		FirstSeenAt:         firstT,
		LastSeenAt:          lastT,
		ReportCount:         reportCount,
		ThreatActors:        threatActors,
		CreatedAt:           createdT,
		UpdatedAt:           updatedT,
	}, nil
}

func (s *SQLStore) buildIncidentsConditions(f HistoryFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	if f.JapanOnly {
		conditions = append(conditions, "japan_relevance = 'Direct'")
	}
	if f.Severity != "" {
		if s.isSQLite {
			conditions = append(conditions, "severity = ?")
		} else {
			conditions = append(conditions, fmt.Sprintf("severity = $%d", argIdx))
			argIdx++
		}
		args = append(args, f.Severity)
	}
	if f.SourceType != "" {
		srcPattern := fmt.Sprintf(`%%"source_type":"%s"%%`, f.SourceType)
		if s.isSQLite {
			conditions = append(conditions, "sources_detail LIKE ?")
		} else {
			conditions = append(conditions, fmt.Sprintf("sources_detail LIKE $%d", argIdx))
			argIdx++
		}
		args = append(args, srcPattern)
	}
	if f.Search != "" {
		pattern := "%" + f.Search + "%"
		if s.isSQLite {
			conditions = append(conditions, "(title LIKE ? OR victim_org LIKE ? OR summary_ja LIKE ? OR impact_analysis_ja LIKE ? OR threat_actors LIKE ? OR cves LIKE ? OR affected_product LIKE ?)")
			args = append(args, pattern, pattern, pattern, pattern, pattern, pattern, pattern)
		} else {
			conditions = append(conditions, fmt.Sprintf("(title ILIKE $%d OR victim_org ILIKE $%d OR summary_ja ILIKE $%d OR impact_analysis_ja ILIKE $%d OR threat_actors ILIKE $%d OR cves ILIKE $%d OR affected_product ILIKE $%d)",
				argIdx, argIdx+1, argIdx+2, argIdx+3, argIdx+4, argIdx+5, argIdx+6))
			argIdx += 7
			args = append(args, pattern, pattern, pattern, pattern, pattern, pattern, pattern)
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}
	return whereClause, args
}

// GetIncidents returns paginated clustered incidents.
func (s *SQLStore) GetIncidents(ctx context.Context, f HistoryFilter) ([]map[string]interface{}, error) {
	whereClause, args := s.buildIncidentsConditions(f)
	query := `
		SELECT ` + incidentSelectCols + `
		FROM incidents
	` + whereClause

	if f.OrderBy == "first_seen_at" {
		query += " ORDER BY first_seen_at DESC"
	} else {
		query += " ORDER BY last_seen_at DESC"
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, f.Offset)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			continue
		}
		results = append(results, formatIncidentMap(inc))
	}

	return results, nil
}

// GetIncidentsTotal returns the total count of clustered incidents matching filter.
func (s *SQLStore) GetIncidentsTotal(ctx context.Context, f HistoryFilter) (int, error) {
	whereClause, args := s.buildIncidentsConditions(f)
	query := "SELECT COUNT(*) FROM incidents" + whereClause
	var total int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&total)
	return total, err
}

// GetIncident retrieves a single incident by ID along with all attached child reports.
func (s *SQLStore) GetIncident(ctx context.Context, incidentID string) (map[string]interface{}, error) {
	query := `
		SELECT ` + incidentSelectCols + `
		FROM incidents
		WHERE id = ? OR id LIKE ?
		LIMIT 1
	`
	prefix := incidentID + "%"
	args := []interface{}{incidentID, prefix}
	if !s.isSQLite {
		query = `
			SELECT ` + incidentSelectCols + `
			FROM incidents
			WHERE id = $1 OR id LIKE $2
			LIMIT 1
		`
	}

	row := s.db.QueryRowContext(ctx, query, args...)
	inc, err := scanIncident(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	res := formatIncidentMap(inc)

	// Fetch child threat items
	childQuery := `
		SELECT id, source_type, source_name, title, url, summary, raw_content, published_at, harvested_at,
		       severity, japan_relevance, notified_at, enriched_data
		FROM threat_items
		WHERE incident_id = ?
		ORDER BY COALESCE(NULLIF(published_at, ''), harvested_at) DESC
	`
	if !s.isSQLite {
		childQuery = `
			SELECT id, source_type, source_name, title, url, summary, raw_content, published_at, harvested_at,
			       severity, japan_relevance, notified_at, enriched_data
			FROM threat_items
			WHERE incident_id = $1
			ORDER BY COALESCE(NULLIF(published_at, ''), harvested_at) DESC
		`
	}

	cRows, err := s.db.QueryContext(ctx, childQuery, inc.ID)
	if err == nil {
		defer cRows.Close()
		var childItems []map[string]interface{}
		for cRows.Next() {
			var (
				cid, srcType, srcName, cTitle, harvestedAt string
				url, summary, rawContent, pubAt, sev, jrel, notifAt, enrichedData sql.NullString
			)
			if err := cRows.Scan(&cid, &srcType, &srcName, &cTitle, &url, &summary, &rawContent, &pubAt, &harvestedAt, &sev, &jrel, &notifAt, &enrichedData); err == nil {
				cItem := map[string]interface{}{
					"id":              cid,
					"source_type":     srcType,
					"source_name":     srcName,
					"title":           cTitle,
					"url":             nullStringVal(url),
					"summary":         nullStringVal(summary),
					"raw_content":     nullStringVal(rawContent),
					"published_at":    nullStringVal(pubAt),
					"harvested_at":    harvestedAt,
					"severity":        nullStringVal(sev),
					"japan_relevance": nullStringVal(jrel),
					"notified_at":     nullStringVal(notifAt),
				}
				if enrichedData.Valid && enrichedData.String != "" {
					var parsed map[string]interface{}
					if err := json.Unmarshal([]byte(enrichedData.String), &parsed); err == nil {
						cItem["enriched_parsed"] = parsed
					}
				}
				childItems = append(childItems, cItem)
			}
		}
		res["child_items"] = childItems

		// Propagate factual entities (affected products, specific victim orgs) and threat actor attribution reasons from child items
		var childProducts []string
		var childVictims []string
		actorReasonsEn, _ := res["threat_actor_reasons"].(map[string]string)
		if actorReasonsEn == nil {
			actorReasonsEn = make(map[string]string)
		}
		actorReasonsJa, _ := res["threat_actor_reasons_ja"].(map[string]string)
		if actorReasonsJa == nil {
			actorReasonsJa = make(map[string]string)
		}
		cleanActors, _ := res["threat_actors"].([]string)

		for _, c := range childItems {
			cSrcName, _ := c["source_name"].(string)
			if cSrcName == "" {
				cSrcName, _ = c["source_type"].(string)
			}
			cTitle, _ := c["title"].(string)
			cRaw, _ := c["raw_content"].(string)
			cSum, _ := c["summary"].(string)

			if ep, ok := c["enriched_parsed"].(map[string]interface{}); ok {
				delete(ep, "recommended_actions")
				delete(ep, "recommended_actions_ja")
				if prods, ok := ep["affected_products"].([]interface{}); ok {
					for _, p := range prods {
						if ps, ok := p.(string); ok && models.NormalizeProduct(ps) != "" {
							childProducts = appendUniqueString(childProducts, strings.TrimSpace(ps))
						}
					}
				}
				if vorgs, ok := ep["victim_orgs"].([]interface{}); ok {
					for _, v := range vorgs {
						if vs, ok := v.(string); ok && strings.TrimSpace(vs) != "" && !models.IsGenericVictimOrg(vs) {
							childVictims = appendUniqueString(childVictims, strings.TrimSpace(vs))
						}
					}
				}
				if rawReasons, ok := ep["threat_actor_reasons"].(map[string]interface{}); ok {
					for _, actor := range cleanActors {
						for rk, rv := range rawReasons {
							if strings.EqualFold(strings.TrimSpace(rk), actor) {
								if rStr, ok := rv.(string); ok && strings.TrimSpace(rStr) != "" {
									actorReasonsEn[actor] = strings.TrimSpace(rStr)
								}
							}
						}
					}
				}
			}

			for _, actor := range cleanActors {
				if snip := models.ExtractActorSnippet(cTitle, actor, 140); snip != "" {
					actorReasonsEn[actor] = fmt.Sprintf("Mentioned in [%s] report title: \"%s\"", cSrcName, snip)
					actorReasonsJa[actor] = fmt.Sprintf("情報源「%s」のタイトルに記載: 「%s」", cSrcName, snip)
					continue
				}
				if snip := models.ExtractActorSnippet(cRaw, actor, 160); snip != "" {
					actorReasonsEn[actor] = fmt.Sprintf("Mentioned in [%s] report body: \"%s\"", cSrcName, snip)
					actorReasonsJa[actor] = fmt.Sprintf("情報源「%s」の本文に記載: 「%s」", cSrcName, snip)
					continue
				}
				if snip := models.ExtractActorSnippet(cSum, actor, 160); snip != "" {
					actorReasonsEn[actor] = fmt.Sprintf("Mentioned in [%s] summary: \"%s\"", cSrcName, snip)
					actorReasonsJa[actor] = fmt.Sprintf("情報源「%s」の概要に記載: 「%s」", cSrcName, snip)
					continue
				}
			}
		}

		res["threat_actor_reasons"] = actorReasonsEn
		res["threat_actor_reasons_ja"] = actorReasonsJa

		if ep, ok := res["enriched_parsed"].(map[string]interface{}); ok {
			delete(ep, "recommended_actions")
			delete(ep, "recommended_actions_ja")
			if len(childProducts) > 0 {
				if existing, ok := ep["affected_products"].([]string); ok {
					for _, p := range childProducts {
						existing = appendUniqueString(existing, p)
					}
					ep["affected_products"] = existing
				} else {
					ep["affected_products"] = childProducts
				}
			}
			if len(childVictims) > 0 {
				if existing, ok := ep["victim_orgs"].([]string); ok {
					for _, v := range childVictims {
						existing = appendUniqueString(existing, v)
					}
					ep["victim_orgs"] = existing
				} else {
					ep["victim_orgs"] = childVictims
				}
			}
			ep["threat_actor_reasons"] = actorReasonsEn
			ep["threat_actor_reasons_ja"] = actorReasonsJa
		}

		// If incident raw_content is empty, synthesize from child items
		if rawStr, ok := res["raw_content"].(string); !ok || strings.TrimSpace(rawStr) == "" {
			var rawParts []string
			for _, c := range childItems {
				cRaw, _ := c["raw_content"].(string)
				if strings.TrimSpace(cRaw) == "" {
					cRaw, _ = c["summary"].(string)
				}
				cRaw = strings.TrimSpace(cRaw)
				if cRaw != "" {
					header := fmt.Sprintf("=== [%s / %s] %s ===", c["source_type"], c["source_name"], c["title"])
					urlStr, _ := c["url"].(string)
					if urlStr != "" {
						header += "\nURL: " + urlStr
					}
					rawParts = append(rawParts, header+"\n\n"+cRaw)
				}
			}
			if len(rawParts) > 0 {
				res["raw_content"] = strings.Join(rawParts, "\n\n---\n\n")
			}
		}
	}

	return res, nil
}

// BackfillIncidents clusters all existing threat_items in chronological order.
func (s *SQLStore) BackfillIncidents(ctx context.Context, windowDays int) (int, error) {
	if windowDays <= 0 {
		windowDays = 30
	}

	log.Printf("[Clustering] Starting BackfillIncidents (sliding window: %d days)...", windowDays)

	// Clean reset to re-cluster from scratch and prevent duplicate fragmentation
	_, _ = s.db.ExecContext(ctx, "DELETE FROM incidents")
	_, _ = s.db.ExecContext(ctx, "UPDATE threat_items SET incident_id = NULL")

	query := `
		SELECT id, source_type, source_name, title, url, summary, raw_content, published_at, harvested_at, enriched_data
		FROM threat_items
		ORDER BY COALESCE(NULLIF(published_at, ''), harvested_at) ASC
	`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to query threat_items for backfill: %w", err)
	}
	defer rows.Close()

	type rawItemRow struct {
		item            models.ThreatItem
		enriched        *models.EnrichedThreat
		newEnrichedJSON string
	}

	var batch []rawItemRow
	for rows.Next() {
		var (
			id, srcType, srcName, title, harvestedAt string
			url, summary, rawContent, pubAt, enrichedData sql.NullString
		)
		if err := rows.Scan(&id, &srcType, &srcName, &title, &url, &summary, &rawContent, &pubAt, &harvestedAt, &enrichedData); err != nil {
			continue
		}

		var pubTime *time.Time
		if pubAt.Valid && pubAt.String != "" {
			if t, ok := models.ParseFlexibleTime(pubAt.String); ok {
				pubTime = &t
			}
		}
		harvTime, _ := models.ParseFlexibleTime(harvestedAt)

		item := models.ThreatItem{
			ID:          id,
			SourceType:  models.SourceType(srcType),
			SourceName:  srcName,
			Title:       title,
			URL:         url.String,
			Summary:     summary.String,
			RawContent:  rawContent.String,
			PublishedAt: pubTime,
			HarvestedAt: harvTime,
		}
		item.ContentHash = models.ComputeContentHash(item)

		var enriched *models.EnrichedThreat
		var newEnrichedJSON string
		if enrichedData.Valid && enrichedData.String != "" {
			var parsed models.EnrichedThreat
			if err := json.Unmarshal([]byte(enrichedData.String), &parsed); err == nil {
				// Pure Go deterministic normalization (NO Gemini/LLM calls)
				models.NormalizeEnrichedThreat(item, &parsed)
				enriched = &parsed
				if b, mErr := json.Marshal(enriched); mErr == nil {
					newEnrichedJSON = string(b)
				}
			} else {
				log.Printf("[Clustering] Warning: failed to unmarshal enriched_data for item %s: %v", id, err)
			}
		}

		batch = append(batch, rawItemRow{item: item, enriched: enriched, newEnrichedJSON: newEnrichedJSON})
	}

	log.Printf("[Clustering] Loaded %d threat items to cluster.", len(batch))

	clusteredCount := 0
	for _, row := range batch {
		inc, err := s.FindOrCreateIncident(ctx, row.item, row.enriched, windowDays)
		if err != nil {
			log.Printf("[Clustering] Failed to cluster item %s: %v", row.item.ID, err)
			continue
		}
		if inc == nil {
			// Item is non-threat, service release, or Info severity: mark as Info and clear incident_id
			if row.enriched != nil && row.newEnrichedJSON != "" {
				updateInfoQ := "UPDATE threat_items SET severity = 'Info', japan_relevance = ?, incident_id = NULL, content_hash = ?, enriched_data = ? WHERE id = ?"
				if !s.isSQLite {
					updateInfoQ = "UPDATE threat_items SET severity = 'Info', japan_relevance = $1, incident_id = NULL, content_hash = $2, enriched_data = $3 WHERE id = $4"
				}
				_, _ = s.db.ExecContext(ctx, updateInfoQ, string(row.enriched.JapanRelevance), row.item.ContentHash, row.newEnrichedJSON, row.item.ID)
			} else {
				updateInfoQ := "UPDATE threat_items SET severity = 'Info', incident_id = NULL, content_hash = ? WHERE id = ?"
				if !s.isSQLite {
					updateInfoQ = "UPDATE threat_items SET severity = 'Info', incident_id = NULL, content_hash = $1 WHERE id = $2"
				}
				_, _ = s.db.ExecContext(ctx, updateInfoQ, row.item.ContentHash, row.item.ID)
			}
			continue
		}

		// Update threat_items row with incident_id, content_hash, and normalized severity/japan_relevance/enriched_data
		if row.enriched != nil && row.newEnrichedJSON != "" {
			updateQ := "UPDATE threat_items SET incident_id = ?, content_hash = ?, severity = ?, japan_relevance = ?, enriched_data = ? WHERE id = ?"
			if !s.isSQLite {
				updateQ = "UPDATE threat_items SET incident_id = $1, content_hash = $2, severity = $3, japan_relevance = $4, enriched_data = $5 WHERE id = $6"
			}
			_, _ = s.db.ExecContext(ctx, updateQ, inc.ID, row.item.ContentHash, string(row.enriched.Severity), string(row.enriched.JapanRelevance), row.newEnrichedJSON, row.item.ID)
		} else {
			updateQ := "UPDATE threat_items SET incident_id = ?, content_hash = ? WHERE id = ?"
			if !s.isSQLite {
				updateQ = "UPDATE threat_items SET incident_id = $1, content_hash = $2 WHERE id = $3"
			}
			_, _ = s.db.ExecContext(ctx, updateQ, inc.ID, row.item.ContentHash, row.item.ID)
		}
		clusteredCount++
	}

	// Clean up any empty/orphan incidents or Info severity incidents left behind after re-clustering
	cleanupQ := "DELETE FROM incidents WHERE severity = 'Info' OR attack_type = 'Service Release' OR id NOT IN (SELECT DISTINCT incident_id FROM threat_items WHERE incident_id IS NOT NULL)"
	_, _ = s.db.ExecContext(ctx, cleanupQ)

	var incCount int
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM incidents").Scan(&incCount)
	log.Printf("[Clustering] Backfill complete. Clustered %d items into %d STIX incidents.", clusteredCount, incCount)
	return incCount, nil
}

func formatIncidentMap(inc *models.Incident) map[string]interface{} {
	firstStr := inc.FirstSeenAt.UTC().Format(time.RFC3339)
	lastStr := inc.LastSeenAt.UTC().Format(time.RFC3339)
	createdStr := inc.CreatedAt.UTC().Format(time.RFC3339)
	updatedStr := inc.UpdatedAt.UTC().Format(time.RFC3339)

	titleEn := inc.Title
	titleJa := inc.TitleJa
	if titleJa == "" && isJapaneseText(inc.Title) {
		titleJa = inc.Title
	}

	victimOrgEn := inc.VictimOrgEn
	if victimOrgEn == "" && !isJapaneseText(inc.VictimOrg) {
		victimOrgEn = inc.VictimOrg
	}
	victimOrgJa := inc.VictimOrgJa
	if victimOrgJa == "" {
		victimOrgJa = inc.VictimOrg
	}

	productEn := inc.AffectedProductEn
	if productEn == "" && !isJapaneseText(inc.AffectedProduct) {
		productEn = inc.AffectedProduct
	}
	productJa := inc.AffectedProductJa
	if productJa == "" {
		productJa = inc.AffectedProduct
	}

	displayVictim := victimOrgEn
	if displayVictim == "" {
		displayVictim = inc.VictimOrg
	}
	displayProduct := productEn
	if displayProduct == "" {
		displayProduct = inc.AffectedProduct
	}

	var victimOrgs []string
	if displayVictim != "" && displayVictim != "Unknown" {
		victimOrgs = []string{displayVictim}
	}

	var affProds []string
	if displayProduct != "" {
		affProds = []string{displayProduct}
	}

	var srcDetailTexts []string
	for _, sd := range inc.SourcesDetail {
		srcDetailTexts = append(srcDetailTexts, sd.Title, sd.Name, sd.URL)
	}
	cleanActors := models.FilterGroundedThreatActors(
		inc.ThreatActors,
		append([]string{inc.Title, inc.TitleJa, inc.Summary, inc.SummaryJa, inc.RawContent, inc.PrimaryURL, strings.Join(inc.SourceURLs, " ")}, srcDetailTexts...)...,
	)
	if cleanActors == nil {
		cleanActors = []string{}
	}

	sumEn := inc.Summary
	if sumEn == "" {
		sumEn = inc.SummaryJa
	}
	sumJa := inc.SummaryJa
	if sumJa == "" {
		sumJa = inc.Summary
	}
	impEn := inc.ImpactAnalysis
	if impEn == "" {
		impEn = inc.ImpactAnalysisJa
	}
	impJa := inc.ImpactAnalysisJa
	if impJa == "" {
		impJa = inc.ImpactAnalysis
	}

	actorReasonsEn, actorReasonsJa := buildIncidentActorReasons(inc, cleanActors)

	return map[string]interface{}{
		"id":                      inc.ID,
		"victim_org":              displayVictim,
		"victim_org_en":           victimOrgEn,
		"victim_org_ja":           victimOrgJa,
		"normalized_victim_org":   inc.NormalizedVictimOrg,
		"cves":                    inc.CVEs,
		"affected_product":        displayProduct,
		"affected_product_en":     productEn,
		"affected_product_ja":     productJa,
		"title":                   titleEn,
		"title_ja":                titleJa,
		"summary":                 sumEn,
		"summary_ja":              sumJa,
		"impact_analysis":         impEn,
		"impact_analysis_ja":      impJa,
		"severity":                string(inc.Severity),
		"japan_relevance":         string(inc.JapanRelevance),
		"attack_type":             inc.AttackType,
		"raw_content":             inc.RawContent,
		"url":                     inc.PrimaryURL,
		"primary_url":             inc.PrimaryURL,
		"source_urls":             inc.SourceURLs,
		"sources_detail":          inc.SourcesDetail,
		"first_seen_at":           firstStr,
		"last_seen_at":            lastStr,
		"published_at":            lastStr,  // compatible with frontend Incident interface
		"harvested_at":            firstStr, // compatible with frontend Incident interface
		"report_count":            inc.ReportCount,
		"threat_actors":           cleanActors,
		"threat_actor_reasons":    actorReasonsEn,
		"threat_actor_reasons_ja": actorReasonsJa,
		"created_at":              createdStr,
		"updated_at":              updatedStr,
		"enriched_parsed": map[string]interface{}{
			"title":                   titleEn,
			"title_ja":                titleJa,
			"summary":                 sumEn,
			"summary_ja":              sumJa,
			"impact_analysis":         impEn,
			"impact_analysis_ja":      impJa,
			"victim_orgs":             victimOrgs,
			"victim_org_en":           victimOrgEn,
			"victim_org_ja":           victimOrgJa,
			"threat_actors":           cleanActors,
			"threat_actor_reasons":    actorReasonsEn,
			"threat_actor_reasons_ja": actorReasonsJa,
			"attack_type":             inc.AttackType,
			"cves":                    inc.CVEs,
			"affected_products":       affProds,
			"affected_product_en":     productEn,
			"affected_product_ja":     productJa,
		},
	}
}

func buildIncidentActorReasons(inc *models.Incident, cleanActors []string) (map[string]string, map[string]string) {
	reasonsEn := make(map[string]string, len(cleanActors))
	reasonsJa := make(map[string]string, len(cleanActors))
	if len(cleanActors) == 0 {
		return reasonsEn, reasonsJa
	}

	primarySource := ""
	if len(inc.SourcesDetail) > 0 {
		primarySource = inc.SourcesDetail[0].Name
	}

	for _, actor := range cleanActors {
		matched := false
		// 1. Check source details titles
		for _, sd := range inc.SourcesDetail {
			if snip := models.ExtractActorSnippet(sd.Title, actor, 140); snip != "" {
				reasonsEn[actor] = fmt.Sprintf("Mentioned in [%s] report title: \"%s\"", sd.Name, snip)
				reasonsJa[actor] = fmt.Sprintf("情報源「%s」のタイトルに記載: 「%s」", sd.Name, snip)
				matched = true
				break
			}
		}
		if matched {
			continue
		}

		// 2. Check incident title
		if snip := models.ExtractActorSnippet(inc.Title, actor, 140); snip != "" {
			if primarySource != "" {
				reasonsEn[actor] = fmt.Sprintf("Mentioned in [%s] title: \"%s\"", primarySource, snip)
				reasonsJa[actor] = fmt.Sprintf("情報源「%s」のタイトルに記載: 「%s」", primarySource, snip)
			} else {
				reasonsEn[actor] = fmt.Sprintf("Mentioned in incident title: \"%s\"", snip)
				reasonsJa[actor] = fmt.Sprintf("インシデントタイトルに記載: 「%s」", snip)
			}
			continue
		}
		if snip := models.ExtractActorSnippet(inc.TitleJa, actor, 140); snip != "" {
			reasonsEn[actor] = fmt.Sprintf("Mentioned in incident title: \"%s\"", snip)
			reasonsJa[actor] = fmt.Sprintf("インシデントタイトルに記載: 「%s」", snip)
			continue
		}

		// 3. Check raw_content
		if snip := models.ExtractActorSnippet(inc.RawContent, actor, 160); snip != "" {
			if primarySource != "" {
				reasonsEn[actor] = fmt.Sprintf("Mentioned in [%s] article body: \"%s\"", primarySource, snip)
				reasonsJa[actor] = fmt.Sprintf("情報源「%s」の本文に記載: 「%s」", primarySource, snip)
			} else {
				reasonsEn[actor] = fmt.Sprintf("Mentioned in source article body: \"%s\"", snip)
				reasonsJa[actor] = fmt.Sprintf("収集した元記事の本文に記載: 「%s」", snip)
			}
			continue
		}

		// 4. Check summary / impact analysis
		if snip := models.ExtractActorSnippet(inc.Summary, actor, 160); snip != "" {
			reasonsEn[actor] = fmt.Sprintf("Mentioned in intelligence summary: \"%s\"", snip)
			reasonsJa[actor] = fmt.Sprintf("AI要約・レポート概要に記載: 「%s」", snip)
			continue
		}
		if snip := models.ExtractActorSnippet(inc.SummaryJa, actor, 160); snip != "" {
			reasonsEn[actor] = fmt.Sprintf("Mentioned in intelligence summary: \"%s\"", snip)
			reasonsJa[actor] = fmt.Sprintf("AI要約・レポート概要に記載: 「%s」", snip)
			continue
		}
		if snip := models.ExtractActorSnippet(inc.ImpactAnalysis, actor, 160); snip != "" {
			reasonsEn[actor] = fmt.Sprintf("Referenced in impact analysis: \"%s\"", snip)
			reasonsJa[actor] = fmt.Sprintf("影響分析に記載: 「%s」", snip)
			continue
		}

		// 5. Fallback (feed metadata, darkweb leak site attribution, or AI/analyst correlation)
		if primarySource != "" {
			reasonsEn[actor] = fmt.Sprintf("Attributed via [%s] feed metadata or AI threat correlation", primarySource)
			reasonsJa[actor] = fmt.Sprintf("情報源「%s」のメタデータまたはAI脅威分析により特定", primarySource)
		} else {
			reasonsEn[actor] = "Attributed via AI threat intelligence analysis"
			reasonsJa[actor] = "AI脅威インテリジェンス分析により特定"
		}
	}

	return reasonsEn, reasonsJa
}

func mergeUniqueStrings(existing, incoming []string) []string {
	seen := make(map[string]bool)
	var res []string
	for _, s := range existing {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" && !seen[trimmed] {
			seen[trimmed] = true
			res = append(res, trimmed)
		}
	}
	for _, s := range incoming {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" && !seen[trimmed] {
			seen[trimmed] = true
			res = append(res, trimmed)
		}
	}
	return res
}

func hasOverlappingCVEs(a, b []string) bool {
	set := make(map[string]struct{}, len(a))
	for _, c := range a {
		norm := strings.ToUpper(strings.TrimSpace(c))
		if norm != "" {
			set[norm] = struct{}{}
		}
	}
	for _, c := range b {
		norm := strings.ToUpper(strings.TrimSpace(c))
		if _, ok := set[norm]; ok {
			return true
		}
	}
	return false
}

func appendUniqueString(list []string, item string) []string {
	trimmed := strings.TrimSpace(item)
	if trimmed == "" {
		return list
	}
	for _, s := range list {
		if s == trimmed {
			return list
		}
	}
	return append(list, trimmed)
}

func appendSourceDetail(list []models.SourceDetail, d models.SourceDetail) []models.SourceDetail {
	for _, existing := range list {
		if existing.URL != "" && existing.URL == d.URL {
			return list
		}
		if existing.URL == "" && existing.Title == d.Title {
			return list
		}
	}
	return append(list, d)
}

func isJapaneseText(s string) bool {
	for _, r := range s {
		if (r >= 0x3040 && r <= 0x309F) || (r >= 0x30A0 && r <= 0x30FF) || (r >= 0x4E00 && r <= 0x9FAF) {
			return true
		}
	}
	return false
}

// UpdateIncidentTranslations updates title, summary, impact analysis, victim_org_en, and affected_product_en of an incident.
// Child threat_items preserve their original article-specific enrichment to prevent cross-contamination.
func (s *SQLStore) UpdateIncidentTranslations(ctx context.Context, id, title, summary, impact, victimEn, productEn string, actions []string) error {
	var query string
	nowStr := time.Now().UTC().Format(time.RFC3339)
	if s.isSQLite {
		query = `UPDATE incidents SET
			title_ja = CASE WHEN title_ja IS NULL OR title_ja = '' THEN title ELSE title_ja END,
			summary_ja = CASE WHEN summary_ja IS NULL OR summary_ja = '' THEN summary ELSE summary_ja END,
			impact_analysis_ja = CASE WHEN impact_analysis_ja IS NULL OR impact_analysis_ja = '' THEN impact_analysis ELSE impact_analysis_ja END,
			title = ?, summary = ?, impact_analysis = ?,
			victim_org_en = COALESCE(NULLIF(?, ''), victim_org_en),
			affected_product_en = COALESCE(NULLIF(?, ''), affected_product_en),
			updated_at = ?
		WHERE id = ?`
		_, err := s.db.ExecContext(ctx, query, title, summary, impact, victimEn, productEn, nowStr, id)
		return err
	}

	query = `UPDATE incidents SET
		title_ja = CASE WHEN title_ja IS NULL OR title_ja = '' THEN title ELSE title_ja END,
		summary_ja = CASE WHEN summary_ja IS NULL OR summary_ja = '' THEN summary ELSE summary_ja END,
		impact_analysis_ja = CASE WHEN impact_analysis_ja IS NULL OR impact_analysis_ja = '' THEN impact_analysis ELSE impact_analysis_ja END,
		title = $1, summary = $2, impact_analysis = $3,
		victim_org_en = COALESCE(NULLIF($4, ''), victim_org_en),
		affected_product_en = COALESCE(NULLIF($5, ''), affected_product_en),
		updated_at = $6
	WHERE id = $7`
	_, err := s.db.ExecContext(ctx, query, title, summary, impact, victimEn, productEn, nowStr, id)
	return err
}

// UpdateIncidentJapaneseTranslations updates title_ja, summary_ja, impact_analysis_ja of an incident.
// Child threat_items preserve their original article-specific enrichment to prevent cross-contamination.
func (s *SQLStore) UpdateIncidentJapaneseTranslations(ctx context.Context, id, titleJa, summaryJa, impactJa string, actions []string) error {
	var query string
	nowStr := time.Now().UTC().Format(time.RFC3339)
	if s.isSQLite {
		query = `UPDATE incidents SET
			title_ja = ?, summary_ja = ?, impact_analysis_ja = ?, updated_at = ?
		WHERE id = ?`
		_, err := s.db.ExecContext(ctx, query, titleJa, summaryJa, impactJa, nowStr, id)
		return err
	}

	query = `UPDATE incidents SET
		title_ja = $1, summary_ja = $2, impact_analysis_ja = $3, updated_at = $4
	WHERE id = $5`
	_, err := s.db.ExecContext(ctx, query, titleJa, summaryJa, impactJa, nowStr, id)
	return err
}

// CleanChineseCTITermsInDatabase performs direct SQL replacements of prominent Chinese CTI terms in title_ja and summary_ja.
func (s *SQLStore) CleanChineseCTITermsInDatabase(ctx context.Context) (int64, error) {
	type pair struct {
		cn string
		ja string
	}
	pairs := []pair{
		{"不正当访问", "不正アクセス"},
		{"不正当", "不正な"},
		{"非法入侵", "不正アクセス"},
		{"不法访问", "不正アクセス"},
		{"未经授权的访问", "不正アクセス"},
		{"未经授权", "未認可の"},
		{"个人数据泄露", "個人情報漏洩"},
		{"个人数据", "個人情報"},
		{"数据泄露", "データ漏洩"},
		{"泄露", "漏洩"},
		{"被盗", "窃取"},
		{"遭勒索", "ランサムウェア被害を受け"},
		{"两阶段认证", "2段階認証"},
		{"兩階段認證", "2段階認証"},
		{"关于", "に関する"},
		{"修复旧版本中的安全漏洞", "旧バージョンのセキュリティ脆弱性を修正"},
		{"更新版本", "アップデート"},
		{"解决了", "修正しました"},
		{"调查结果公布", "調査結果公表"},
		{"宣布", "発表"},
		{"遭受", "被害を受け"},
		{"邮件杂志", "メールマガジン"},
		{"零日漏洞", "ゼロデイ脆弱性"},
		{"后门", "バックドア"},
		{"木马", "トロイの木馬"},
		{"间谍软件", "スパイウェア"},
		{"攻击活动", "攻撃活動"},
		{"恶意软件", "マルウェア"},
		{"勒索软件", "ランサムウェア"},
		{"云计算", "クラウド"},
		{"报道指出", "報道によると"},
		{"据悉", "報道によると"},
		{"根据报告", "レポートによると"},
		{"漏洞", "脆弱性"},
		{"黑客", "攻撃者"},
		{"钓鱼", "フィッシング"},
		{"非法访问", "不正アクセス"},
		{"子公司", "子会社"},
		{"遭遇的", ""},
		{"导致", "により"},
		{"客户", "顧客"},
		{"东证主板上市公司", "東証プライム上場企業の"},
		{"公司発表，其", "社は、その"},
		{"电商巨头", "大手小売"},
		{"巨头", "大手"},
		{"其服务器", "サーバーが"},
		{"导致约", "約"},
		{"名会员的个人信息被漏洩", "名の会員の個人情報が漏洩"},
		{"该公司已暂停相关服务并通知受影响的客户", "同社は関連サービスを停止し、影響を受ける顧客に通知を行っています"},
		{"用户个人信息", "ユーザーの個人情報"},
		{"窃取取", "窃取"},
		{"盗取", "窃取"},
		{"超过", "超の"},
		{"个电子邮件地址及其他信息", "件のメールアドレスおよびその他の個人情報"},
		{"个人身份信息", "個人情報"},
		{"的网络访问", "のネットワークアクセス"},
		{"调查结果显示约", "調査の結果、約"},
		{"已漏洩", "漏洩した可能性があります"},
		{"已暂停", "停止し"},
		{"相关服务", "関連サービス"},
		{"受影响的客户", "影響を受ける顧客"},
		{"非法", "不正"},
	}

	var totalAffected int64
	for _, p := range pairs {
		var q string
		if s.isSQLite {
			q = `UPDATE incidents SET
				title = REPLACE(title, ?, ?),
				summary = REPLACE(summary, ?, ?),
				impact_analysis = REPLACE(impact_analysis, ?, ?),
				title_ja = REPLACE(title_ja, ?, ?),
				summary_ja = REPLACE(summary_ja, ?, ?),
				impact_analysis_ja = REPLACE(impact_analysis_ja, ?, ?)
			WHERE title LIKE '%' || ? || '%' OR summary LIKE '%' || ? || '%' OR impact_analysis LIKE '%' || ? || '%' OR title_ja LIKE '%' || ? || '%' OR summary_ja LIKE '%' || ? || '%' OR impact_analysis_ja LIKE '%' || ? || '%'`
			res, err := s.db.ExecContext(ctx, q, p.cn, p.ja, p.cn, p.ja, p.cn, p.ja, p.cn, p.ja, p.cn, p.ja, p.cn, p.ja, p.cn, p.cn, p.cn, p.cn, p.cn, p.cn)
			if err == nil && res != nil {
				n, _ := res.RowsAffected()
				totalAffected += n
			}
		} else {
			q = `UPDATE incidents SET
				title = REPLACE(title, $1, $2),
				summary = REPLACE(summary, $1, $2),
				impact_analysis = REPLACE(impact_analysis, $1, $2),
				title_ja = REPLACE(title_ja, $1, $2),
				summary_ja = REPLACE(summary_ja, $1, $2),
				impact_analysis_ja = REPLACE(impact_analysis_ja, $1, $2)
			WHERE title LIKE '%' || $1 || '%' OR summary LIKE '%' || $1 || '%' OR impact_analysis LIKE '%' || $1 || '%' OR title_ja LIKE '%' || $1 || '%' OR summary_ja LIKE '%' || $1 || '%' OR impact_analysis_ja LIKE '%' || $1 || '%'`
			res, err := s.db.ExecContext(ctx, q, p.cn, p.ja)
			if err == nil && res != nil {
				n, _ := res.RowsAffected()
				totalAffected += n
			}
		}
	}
	return totalAffected, nil
}

// GetIncidentsNeedingJapaneseRemediation returns incidents where title_ja or summary_ja has Chinese CTI terms,
// contains Hanzi/Kanji without Kana, or is completely missing Japanese localization.
func (s *SQLStore) GetIncidentsNeedingJapaneseRemediation(ctx context.Context, limit int) ([]models.Incident, error) {
	if limit <= 0 {
		limit = 50
	}

	var query string
	if s.isSQLite {
		query = `
			SELECT ` + incidentSelectCols + `
			FROM incidents
			ORDER BY last_seen_at DESC
			LIMIT ?
		`
	} else {
		query = `
			SELECT ` + incidentSelectCols + `
			FROM incidents
			WHERE (
				title_ja ~ '(关于|不正当|泄露|数据|服务|攻击|漏洞|恶意|黑客|据悉|报道|宣布|遭受|未经授权|被盗|不法访问|更新版本|针对|修复旧版本|解决了|两阶段|两阶段认证|官方应用|会员管理系统|已暂停|通用漏洞披露|网络安全和基础设施安全局)'
				OR summary_ja ~ '(关于|不正当|泄露|数据|服务|攻击|漏洞|恶意|黑客|据悉|报道|宣布|遭受|未经授权|被盗|不法访问|更新版本|针对|修复旧版本|解决了|两阶段|两阶段认证|官方应用|会员管理系统|已暂停|通用漏洞披露|网络安全和基础设施安全局)'
				OR (title_ja ~ '[\u4e00-\u9faf]' AND title_ja !~ '[\u3040-\u30ff]')
				OR (summary_ja ~ '[\u4e00-\u9faf]' AND summary_ja !~ '[\u3040-\u30ff]')
				OR (COALESCE(title_ja, '') = '' AND COALESCE(title, '') != '')
			)
			ORDER BY last_seen_at DESC
			LIMIT $1
		`
	}

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var incidents []models.Incident
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			continue
		}
		if s.isSQLite {
			if models.IsChineseOrCorruptedJapanese(inc.TitleJa) ||
				models.IsChineseOrCorruptedJapanese(inc.SummaryJa) ||
				(inc.TitleJa == "" && inc.Title != "") {
				incidents = append(incidents, *inc)
			}
		} else {
			incidents = append(incidents, *inc)
		}
	}

	return incidents, nil
}

// GetIncidentsNeedingTranslation returns incidents that have Japanese characters in their title, summary, impact analysis, victim org, or affected product and lack English translations.
func (s *SQLStore) GetIncidentsNeedingTranslation(ctx context.Context, limit int) ([]models.Incident, error) {
	if limit <= 0 {
		limit = 50
	}

	var query string
	if s.isSQLite {
		query = `
			SELECT ` + incidentSelectCols + `
			FROM incidents
			ORDER BY last_seen_at DESC
			LIMIT ?
		`
	} else {
		query = `
			SELECT ` + incidentSelectCols + `
			FROM incidents
			WHERE (
				title ~ '[\u3040-\u30ff\u4e00-\u9faf]'
				OR summary ~ '[\u3040-\u30ff\u4e00-\u9faf]'
				OR (COALESCE(summary, '') = '' AND summary_ja ~ '[\u3040-\u30ff\u4e00-\u9faf]')
				OR impact_analysis ~ '[\u3040-\u30ff\u4e00-\u9faf]'
				OR (COALESCE(impact_analysis, '') = '' AND impact_analysis_ja ~ '[\u3040-\u30ff\u4e00-\u9faf]')
				OR (victim_org ~ '[\u3040-\u30ff\u4e00-\u9faf]' AND COALESCE(victim_org_en, '') = '')
				OR (affected_product ~ '[\u3040-\u30ff\u4e00-\u9faf]' AND COALESCE(affected_product_en, '') = '')
			)
			ORDER BY last_seen_at DESC
			LIMIT $1
		`
	}

	rows, err := s.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var incidents []models.Incident
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			continue
		}
		if s.isSQLite {
			if isJapaneseText(inc.Title) ||
				isJapaneseText(inc.Summary) ||
				(inc.Summary == "" && isJapaneseText(inc.SummaryJa)) ||
				isJapaneseText(inc.ImpactAnalysis) ||
				(inc.ImpactAnalysis == "" && isJapaneseText(inc.ImpactAnalysisJa)) ||
				(isJapaneseText(inc.VictimOrg) && inc.VictimOrgEn == "") ||
				(isJapaneseText(inc.AffectedProduct) && inc.AffectedProductEn == "") {
				incidents = append(incidents, *inc)
			}
		} else {
			incidents = append(incidents, *inc)
		}
	}

	return incidents, nil
}

// UpdateIncidentLabels allows administrator to override/fix automatic labels for an incident.
func (s *SQLStore) UpdateIncidentLabels(ctx context.Context, id string, threatActors []string, severity, japanRelevance, attackType, victimOrg string) error {
	actorsJSON, _ := json.Marshal(models.CleanThreatActors(threatActors))
	nowStr := time.Now().UTC().Format(time.RFC3339)

	var query string
	if s.isSQLite {
		query = `
			UPDATE incidents SET
				threat_actors = ?,
				severity = CASE WHEN ? != '' THEN ? ELSE severity END,
				japan_relevance = CASE WHEN ? != '' THEN ? ELSE japan_relevance END,
				attack_type = CASE WHEN ? != '' THEN ? ELSE attack_type END,
				victim_org = CASE WHEN ? != '' THEN ? ELSE victim_org END,
				updated_at = ?
			WHERE id = ?
		`
		_, err := s.db.ExecContext(ctx, query,
			string(actorsJSON),
			severity, severity,
			japanRelevance, japanRelevance,
			attackType, attackType,
			victimOrg, victimOrg,
			nowStr,
			id,
		)
		return err
	}

	query = `
		UPDATE incidents SET
			threat_actors = $1,
			severity = CASE WHEN $2 != '' THEN $2 ELSE severity END,
			japan_relevance = CASE WHEN $3 != '' THEN $3 ELSE japan_relevance END,
			attack_type = CASE WHEN $4 != '' THEN $4 ELSE attack_type END,
			victim_org = CASE WHEN $5 != '' THEN $5 ELSE victim_org END,
			updated_at = $6
		WHERE id = $7
	`
	_, err := s.db.ExecContext(ctx, query,
		string(actorsJSON),
		severity,
		japanRelevance,
		attackType,
		victimOrg,
		nowStr,
		id,
	)
	return err
}

// GetEntityStats aggregates threat actors and victims observed across all incidents.
func (s *SQLStore) GetEntityStats(ctx context.Context, limit int, japanOnly bool) (*models.EntityStats, error) {
	if limit <= 0 {
		limit = 50
	}

	query := `
		SELECT threat_actors, victim_org, victim_org_ja, victim_org_en, normalized_victim_org, japan_relevance, last_seen_at
		FROM incidents
	`
	if japanOnly {
		query += " WHERE japan_relevance IN ('Direct', 'Indirect')"
	}

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query incidents for entity stats: %w", err)
	}
	defer rows.Close()

	type actorAgg struct {
		displayName string
		count       int
		japanCount  int
		lastSeenAt  string
	}

	type victimAgg struct {
		displayName string
		nameJa      string
		nameEn      string
		count       int
		japanCount  int
		lastSeenAt  string
	}

	actorsMap := make(map[string]*actorAgg)
	victimsMap := make(map[string]*victimAgg)

	for rows.Next() {
		var taStr, vOrg, vJa, vEn, normV, jRel, lastSeen sql.NullString
		if err := rows.Scan(&taStr, &vOrg, &vJa, &vEn, &normV, &jRel, &lastSeen); err != nil {
			continue
		}

		isJapan := jRel.String == "Direct" || jRel.String == "Indirect"
		lastSeenVal := lastSeen.String

		// Aggregate Threat Actors
		if taStr.Valid && strings.HasPrefix(strings.TrimSpace(taStr.String), "[") {
			var rawActors []string
			if err := json.Unmarshal([]byte(taStr.String), &rawActors); err == nil {
				cleaned := models.CleanThreatActors(rawActors)
				for _, actor := range cleaned {
					actor = strings.TrimSpace(actor)
					if actor == "" {
						continue
					}
					key := strings.ToLower(actor)
					entry, exists := actorsMap[key]
					if !exists {
						entry = &actorAgg{
							displayName: actor,
							lastSeenAt:  lastSeenVal,
						}
						actorsMap[key] = entry
					}
					entry.count++
					if isJapan {
						entry.japanCount++
					}
					// Prefer capitalized/TitleCase name as display name
					if len(actor) > 0 && len(entry.displayName) > 0 {
						if unicode.IsUpper(rune(actor[0])) && !unicode.IsUpper(rune(entry.displayName[0])) {
							entry.displayName = actor
						}
					}
					if lastSeenVal > entry.lastSeenAt {
						entry.lastSeenAt = lastSeenVal
					}
				}
			}
		}

		// Aggregate Victims
		vDisplay := ""
		if vJa.Valid && strings.TrimSpace(vJa.String) != "" {
			vDisplay = strings.TrimSpace(vJa.String)
		} else if vOrg.Valid && strings.TrimSpace(vOrg.String) != "" {
			vDisplay = strings.TrimSpace(vOrg.String)
		} else if normV.Valid && strings.TrimSpace(normV.String) != "" {
			vDisplay = strings.TrimSpace(normV.String)
		}

		if vDisplay != "" && !models.IsGenericVictimOrg(vDisplay) {
			lowKey := strings.ToLower(vDisplay)
			vEntry, exists := victimsMap[lowKey]
			if !exists {
				vEntry = &victimAgg{
					displayName: vDisplay,
					nameJa:      vJa.String,
					nameEn:      vEn.String,
					lastSeenAt:  lastSeenVal,
				}
				victimsMap[lowKey] = vEntry
			}
			vEntry.count++
			if isJapan {
				vEntry.japanCount++
			}
			if vJa.Valid && vJa.String != "" {
				vEntry.nameJa = vJa.String
			}
			if vEn.Valid && vEn.String != "" {
				vEntry.nameEn = vEn.String
			}
			if lastSeenVal > vEntry.lastSeenAt {
				vEntry.lastSeenAt = lastSeenVal
			}
		}
	}

	// Convert and sort
	var sortedActors []models.ActorStat
	for _, a := range actorsMap {
		sortedActors = append(sortedActors, models.ActorStat{
			Name:       a.displayName,
			Count:      a.count,
			JapanCount: a.japanCount,
			LastSeenAt: a.lastSeenAt,
		})
	}
	sort.Slice(sortedActors, func(i, j int) bool {
		if sortedActors[i].Count == sortedActors[j].Count {
			return sortedActors[i].Name < sortedActors[j].Name
		}
		return sortedActors[i].Count > sortedActors[j].Count
	})

	var sortedVictims []models.VictimStat
	for _, v := range victimsMap {
		sortedVictims = append(sortedVictims, models.VictimStat{
			Name:       v.displayName,
			NameJa:     v.nameJa,
			NameEn:     v.nameEn,
			Count:      v.count,
			JapanCount: v.japanCount,
			LastSeenAt: v.lastSeenAt,
		})
	}
	sort.Slice(sortedVictims, func(i, j int) bool {
		if sortedVictims[i].Count == sortedVictims[j].Count {
			return sortedVictims[i].Name < sortedVictims[j].Name
		}
		return sortedVictims[i].Count > sortedVictims[j].Count
	})

	totalUniqueActors := len(sortedActors)
	totalUniqueVictims := len(sortedVictims)

	if len(sortedActors) > limit {
		sortedActors = sortedActors[:limit]
	}
	if len(sortedVictims) > limit {
		sortedVictims = sortedVictims[:limit]
	}

	return &models.EntityStats{
		TotalUniqueActors:  totalUniqueActors,
		TotalUniqueVictims: totalUniqueVictims,
		TopActors:          sortedActors,
		TopVictims:         sortedVictims,
	}, nil
}


