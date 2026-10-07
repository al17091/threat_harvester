package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/dapt/information_harvester/backend/internal/models"
)

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

	// Extract CVEs from raw texts + enriched metadata
	cves := models.ExtractCVEs(item.Title, item.Summary, item.RawContent, item.URL)
	if enriched != nil && len(enriched.CVEs) > 0 {
		cves = models.ExtractCVEs(append(cves, enriched.CVEs...)...)
	}

	// Extract Affected Product
	rawProduct, normProduct := models.ExtractAffectedProduct(item, enriched)

	attackType := ""
	if enriched != nil {
		attackType = enriched.AttackType
	}

	// Non-threat content, service releases, PR announcements, and Info-level reports MUST NOT be treated as STIX cyber threat incidents.
	if (enriched != nil && enriched.Severity == models.SeverityInfo) || models.IsServiceReleaseOrNonThreat(item, enriched) {
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

	var matched *models.Incident

	// TRACK 1: Vulnerability & CVE Clustering
	if isVuln && (len(cves) > 0 || normProduct != "") {
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
				SELECT id, victim_org, normalized_victim_org, cves, affected_product, title, summary_ja, impact_analysis_ja,
				       severity, japan_relevance, attack_type, primary_url, source_urls, sources_detail,
				       first_seen_at, last_seen_at, report_count, threat_actors, created_at, updated_at
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
				SELECT id, victim_org, normalized_victim_org, cves, affected_product, title, summary_ja, impact_analysis_ja,
				       severity, japan_relevance, attack_type, primary_url, source_urls, sources_detail,
				       first_seen_at, last_seen_at, report_count, threat_actors, created_at, updated_at
				FROM incidents
				WHERE ((affected_product IS NOT NULL AND affected_product != '' AND LOWER(affected_product) LIKE ?) OR LOWER(title) LIKE ?)
				ORDER BY last_seen_at DESC
				LIMIT 10
			`
			if !s.isSQLite {
				prodQuery = `
					SELECT id, victim_org, normalized_victim_org, cves, affected_product, title, summary_ja, impact_analysis_ja,
					       severity, japan_relevance, attack_type, primary_url, source_urls, sources_detail,
					       first_seen_at, last_seen_at, report_count, threat_actors, created_at, updated_at
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
							matched = inc
							break
						}
					}
				}
				_ = rows.Close()
			}
		}
	}

	// TRACK 2: Specific Victim Org Clustering (Targeted Cyberattacks, Ransomware, Data Breaches)
	if matched == nil && normVictim != "" && !models.IsGenericVictimOrg(rawVictim) {
		query := `
			SELECT id, victim_org, normalized_victim_org, cves, affected_product, title, summary_ja, impact_analysis_ja,
			       severity, japan_relevance, attack_type, primary_url, source_urls, sources_detail,
			       first_seen_at, last_seen_at, report_count, threat_actors, created_at, updated_at
			FROM incidents
			WHERE normalized_victim_org = ?
			ORDER BY last_seen_at DESC
			LIMIT 5
		`
		if !s.isSQLite {
			query = `
				SELECT id, victim_org, normalized_victim_org, cves, affected_product, title, summary_ja, impact_analysis_ja,
				       severity, japan_relevance, attack_type, primary_url, source_urls, sources_detail,
				       first_seen_at, last_seen_at, report_count, threat_actors, created_at, updated_at
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
		matched.ReportCount++

		matched.CVEs = mergeUniqueStrings(matched.CVEs, cves)
		if matched.AffectedProduct == "" && rawProduct != "" {
			matched.AffectedProduct = rawProduct
		}

		if enriched != nil {
			matched.Severity = models.HigherSeverity(matched.Severity, enriched.Severity)
			matched.JapanRelevance = models.HigherRelevance(matched.JapanRelevance, enriched.JapanRelevance)
			matched.ThreatActors = mergeUniqueStrings(matched.ThreatActors, enriched.ThreatActors)
			if matched.AttackType == "" && enriched.AttackType != "" {
				matched.AttackType = enriched.AttackType
			}
			if matched.SummaryJa == "" && enriched.SummaryJa != "" {
				matched.SummaryJa = enriched.SummaryJa
			}
			if matched.ImpactAnalysisJa == "" && enriched.ImpactAnalysisJa != "" {
				matched.ImpactAnalysisJa = enriched.ImpactAnalysisJa
			}
		}

		if matched.AttackType == "" && isVuln {
			matched.AttackType = "Vulnerability"
		}

		if matched.PrimaryURL == "" && item.URL != "" {
			matched.PrimaryURL = item.URL
		}
		if item.URL != "" {
			matched.SourceURLs = appendUniqueString(matched.SourceURLs, item.URL)
		}
		matched.SourcesDetail = appendSourceDetail(matched.SourcesDetail, detail)
		matched.UpdatedAt = time.Now().UTC()

		if err := s.updateIncident(ctx, matched); err != nil {
			return nil, err
		}
		return matched, nil
	}

	// TRACK 3: No match found within sliding window -> create new incident
	inc := s.buildNewIncident(item, enriched, rawVictim, normVictim, cves, rawProduct, itemTime, detail)
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
) *models.Incident {
	id := models.NewSTIXIncidentID()
	title := item.Title
	summaryJa := item.Summary
	impactJa := ""
	sev := models.SeverityUnknown
	jrel := models.JapanRelevanceUnknown
	attackType := ""
	var threatActors []string

	if enriched != nil {
		if enriched.TitleJa != "" {
			title = enriched.TitleJa
		}
		if enriched.SummaryJa != "" {
			summaryJa = enriched.SummaryJa
		}
		impactJa = enriched.ImpactAnalysisJa
		sev = enriched.Severity
		jrel = enriched.JapanRelevance
		attackType = enriched.AttackType
		threatActors = enriched.ThreatActors
	}

	if attackType == "" && (len(cves) > 0 || rawProduct != "") {
		attackType = "Vulnerability"
	}

	vOrg := rawVictim
	if vOrg == "" {
		vOrg = "Unknown"
	}

	var sourceURLs []string
	if item.URL != "" {
		sourceURLs = append(sourceURLs, item.URL)
	}

	now := time.Now().UTC()
	return &models.Incident{
		ID:                  id,
		VictimOrg:           vOrg,
		NormalizedVictimOrg: normVictim,
		CVEs:                cves,
		AffectedProduct:     rawProduct,
		Title:               title,
		SummaryJa:           summaryJa,
		ImpactAnalysisJa:    impactJa,
		Severity:            sev,
		JapanRelevance:      jrel,
		AttackType:          attackType,
		PrimaryURL:          item.URL,
		SourceURLs:          sourceURLs,
		SourcesDetail:       []models.SourceDetail{detail},
		FirstSeenAt:         itemTime,
		LastSeenAt:          itemTime,
		ReportCount:         1,
		ThreatActors:        threatActors,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
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
				severity, japan_relevance, attack_type, primary_url, source_urls, sources_detail,
				first_seen_at, last_seen_at, report_count, threat_actors, created_at, updated_at
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`
	} else {
		query = `
			INSERT INTO incidents (
				id, victim_org, normalized_victim_org, cves, affected_product, title, summary_ja, impact_analysis_ja,
				severity, japan_relevance, attack_type, primary_url, source_urls, sources_detail,
				first_seen_at, last_seen_at, report_count, threat_actors, created_at, updated_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
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
		inc.PrimaryURL,
		string(srcURLsJSON),
		string(srcDetailJSON),
		firstStr,
		lastStr,
		inc.ReportCount,
		string(actorsJSON),
		createdStr,
		updatedStr,
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
				primary_url = ?,
				source_urls = ?,
				sources_detail = ?,
				first_seen_at = ?,
				last_seen_at = ?,
				report_count = ?,
				threat_actors = ?,
				updated_at = ?
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
				primary_url = $9,
				source_urls = $10,
				sources_detail = $11,
				first_seen_at = $12,
				last_seen_at = $13,
				report_count = $14,
				threat_actors = $15,
				updated_at = $16
			WHERE id = $17
		`
	}

	_, err := s.db.ExecContext(ctx, query,
		string(cvesJSON),
		inc.AffectedProduct,
		inc.Title,
		inc.SummaryJa,
		inc.ImpactAnalysisJa,
		string(inc.Severity),
		string(inc.JapanRelevance),
		inc.AttackType,
		inc.PrimaryURL,
		string(srcURLsJSON),
		string(srcDetailJSON),
		firstStr,
		lastStr,
		inc.ReportCount,
		string(actorsJSON),
		updatedStr,
		inc.ID,
	)
	return err
}

func scanIncident(scanner interface {
	Scan(dest ...interface{}) error
}) (*models.Incident, error) {
	var (
		id, victimOrg, title, firstSeen, lastSeen, created, updated string
		normVictim, cvesRaw, affProduct                              sql.NullString
		sumJa, impJa, attackType, primURL, srcURLs, srcDetail, actors sql.NullString
		sev, jrel                                                    string
		reportCount                                                  int
	)

	err := scanner.Scan(
		&id, &victimOrg, &normVictim, &cvesRaw, &affProduct, &title, &sumJa, &impJa,
		&sev, &jrel, &attackType, &primURL, &srcURLs, &srcDetail,
		&firstSeen, &lastSeen, &reportCount, &actors, &created, &updated,
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
		NormalizedVictimOrg: normVictim.String,
		CVEs:                cves,
		AffectedProduct:     affProduct.String,
		Title:               title,
		SummaryJa:           sumJa.String,
		ImpactAnalysisJa:    impJa.String,
		Severity:            models.Severity(sev),
		JapanRelevance:      models.JapanRelevance(jrel),
		AttackType:          attackType.String,
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
		SELECT id, victim_org, normalized_victim_org, cves, affected_product, title, summary_ja, impact_analysis_ja,
		       severity, japan_relevance, attack_type, primary_url, source_urls, sources_detail,
		       first_seen_at, last_seen_at, report_count, threat_actors, created_at, updated_at
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
		SELECT id, victim_org, normalized_victim_org, cves, affected_product, title, summary_ja, impact_analysis_ja,
		       severity, japan_relevance, attack_type, primary_url, source_urls, sources_detail,
		       first_seen_at, last_seen_at, report_count, threat_actors, created_at, updated_at
		FROM incidents
		WHERE id = ? OR id LIKE ?
		LIMIT 1
	`
	prefix := incidentID + "%"
	args := []interface{}{incidentID, prefix}
	if !s.isSQLite {
		query = `
			SELECT id, victim_org, normalized_victim_org, cves, affected_product, title, summary_ja, impact_analysis_ja,
			       severity, japan_relevance, attack_type, primary_url, source_urls, sources_detail,
			       first_seen_at, last_seen_at, report_count, threat_actors, created_at, updated_at
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
		item     models.ThreatItem
		enriched *models.EnrichedThreat
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
			if t, err := time.Parse(time.RFC3339, pubAt.String); err == nil {
				pubTime = &t
			}
		}
		harvTime, _ := time.Parse(time.RFC3339, harvestedAt)

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
		if enrichedData.Valid && enrichedData.String != "" {
			var parsed models.EnrichedThreat
			if err := json.Unmarshal([]byte(enrichedData.String), &parsed); err == nil {
				enriched = &parsed
			}
		}

		batch = append(batch, rawItemRow{item: item, enriched: enriched})
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
			updateInfoQ := "UPDATE threat_items SET severity = 'Info', incident_id = NULL, content_hash = ? WHERE id = ?"
			if !s.isSQLite {
				updateInfoQ = "UPDATE threat_items SET severity = 'Info', incident_id = NULL, content_hash = $1 WHERE id = $2"
			}
			_, _ = s.db.ExecContext(ctx, updateInfoQ, row.item.ContentHash, row.item.ID)
			continue
		}

		// Update threat_items row with incident_id and content_hash
		updateQ := "UPDATE threat_items SET incident_id = ?, content_hash = ? WHERE id = ?"
		if !s.isSQLite {
			updateQ = "UPDATE threat_items SET incident_id = $1, content_hash = $2 WHERE id = $3"
		}
		_, _ = s.db.ExecContext(ctx, updateQ, inc.ID, row.item.ContentHash, row.item.ID)
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

	var victimOrgs []string
	if inc.VictimOrg != "" && inc.VictimOrg != "Unknown" {
		victimOrgs = []string{inc.VictimOrg}
	}

	var affProds []string
	if inc.AffectedProduct != "" {
		affProds = []string{inc.AffectedProduct}
	}

	return map[string]interface{}{
		"id":                    inc.ID,
		"victim_org":            inc.VictimOrg,
		"normalized_victim_org": inc.NormalizedVictimOrg,
		"cves":                  inc.CVEs,
		"affected_product":      inc.AffectedProduct,
		"title":                 inc.Title,
		"summary":               inc.SummaryJa,
		"summary_ja":            inc.SummaryJa,
		"impact_analysis_ja":    inc.ImpactAnalysisJa,
		"severity":              string(inc.Severity),
		"japan_relevance":       string(inc.JapanRelevance),
		"attack_type":           inc.AttackType,
		"url":                   inc.PrimaryURL,
		"primary_url":           inc.PrimaryURL,
		"source_urls":           inc.SourceURLs,
		"sources_detail":        inc.SourcesDetail,
		"first_seen_at":         firstStr,
		"last_seen_at":          lastStr,
		"published_at":          lastStr,  // compatible with frontend Incident interface
		"harvested_at":          firstStr, // compatible with frontend Incident interface
		"report_count":          inc.ReportCount,
		"threat_actors":         inc.ThreatActors,
		"created_at":            createdStr,
		"updated_at":            updatedStr,
		"enriched_parsed": map[string]interface{}{
			"title_ja":           inc.Title,
			"summary_ja":         inc.SummaryJa,
			"impact_analysis_ja": inc.ImpactAnalysisJa,
			"victim_orgs":        victimOrgs,
			"threat_actors":      inc.ThreatActors,
			"attack_type":        inc.AttackType,
			"cves":               inc.CVEs,
			"affected_products":  affProds,
		},
	}
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
