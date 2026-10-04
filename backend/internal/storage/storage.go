package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/dapt/information_harvester/backend/internal/models"
)

type HistoryFilter struct {
	Limit      int
	Offset     int
	JapanOnly  bool
	Severity   string
	SourceType string
	Search     string
	OrderBy    string
}

type Store interface {
	IsSeen(ctx context.Context, itemID string) (bool, error)
	IsSeenItem(ctx context.Context, item models.ThreatItem) (bool, error)
	IsRecentlyNotified(ctx context.Context, victimOrgs []string, title string, withinHours int) (bool, error)
	MarkSeen(ctx context.Context, item models.ThreatItem, enriched *models.EnrichedThreat, notified bool) error
	GetStats(ctx context.Context) (map[string]interface{}, error)
	GetHistory(ctx context.Context, filter HistoryFilter) ([]map[string]interface{}, error)
	GetItem(ctx context.Context, itemID string) (map[string]interface{}, error)
	Close() error
}

type SQLStore struct {
	db       *sql.DB
	driver   string
	dbURL    string
	isSQLite bool
}

func NewStore(dbURL, sqlitePath string) (Store, error) {
	var driver, targetURL string
	var isSQLite bool

	if dbURL != "" && strings.Contains(dbURL, "postgres") {
		driver = "pgx"
		targetURL = normalizePostgresURL(dbURL)
		isSQLite = false
	} else if host := os.Getenv("DB_HOST"); host != "" {
		driver = "pgx"
		user := os.Getenv("DB_USER")
		if user == "" {
			user = "postgres"
		}
		pass := os.Getenv("DB_PASSWORD")
		port := os.Getenv("DB_PORT")
		if port == "" {
			port = "5432"
		}
		name := os.Getenv("DB_NAME")
		if name == "" {
			name = "information_harvester"
		}
		ssl := os.Getenv("DB_SSLMODE")
		if ssl == "" {
			ssl = "prefer"
		}
		auth := user
		if pass != "" {
			auth = fmt.Sprintf("%s:%s", user, pass)
		}
		targetURL = fmt.Sprintf("postgres://%s@%s:%s/%s?sslmode=%s", auth, host, port, name, ssl)
		isSQLite = false
	} else {
		driver = "sqlite"
		path := sqlitePath
		if path == "" {
			path = os.Getenv("CACHE_DB_PATH")
		}
		if path == "" {
			path = "data/threat_cache.db"
		}
		if path != ":memory:" {
			_ = os.MkdirAll(filepath.Dir(path), 0755)
		}
		targetURL = path
		isSQLite = true
	}

	db, err := sql.Open(driver, targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database (%s): %w", driver, err)
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	store := &SQLStore{
		db:       db,
		driver:   driver,
		dbURL:    targetURL,
		isSQLite: isSQLite,
	}

	if err := store.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return store, nil
}

func normalizePostgresURL(url string) string {
	if strings.HasPrefix(url, "postgresql+psycopg://") {
		return "postgres://" + url[len("postgresql+psycopg://"):]
	}
	if strings.HasPrefix(url, "postgresql://") {
		return "postgres://" + url[len("postgresql://"):]
	}
	return url
}

func (s *SQLStore) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS threat_items (
		id VARCHAR(64) PRIMARY KEY,
		source_type VARCHAR(32) NOT NULL,
		source_name VARCHAR(128) NOT NULL,
		title TEXT NOT NULL,
		url TEXT,
		summary TEXT,
		published_at TEXT,
		harvested_at TEXT NOT NULL,
		severity VARCHAR(32),
		japan_relevance VARCHAR(32),
		notified_at TEXT,
		enriched_data TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_harvested_at ON threat_items(harvested_at);
	CREATE INDEX IF NOT EXISTS idx_published_at ON threat_items(published_at);
	CREATE INDEX IF NOT EXISTS idx_source_type ON threat_items(source_type);
	CREATE INDEX IF NOT EXISTS idx_url ON threat_items(url);
	CREATE INDEX IF NOT EXISTS idx_notified_at ON threat_items(notified_at);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *SQLStore) IsSeen(ctx context.Context, itemID string) (bool, error) {
	query := "SELECT 1 FROM threat_items WHERE id = ? LIMIT 1"
	if !s.isSQLite {
		query = "SELECT 1 FROM threat_items WHERE id = $1 LIMIT 1"
	}
	var exists int
	err := s.db.QueryRowContext(ctx, query, itemID).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *SQLStore) IsSeenItem(ctx context.Context, item models.ThreatItem) (bool, error) {
	if item.ID == "" && item.URL == "" {
		return false, nil
	}

	var query string
	var args []interface{}

	if item.URL != "" {
		if s.isSQLite {
			query = "SELECT 1 FROM threat_items WHERE id = ? OR (url IS NOT NULL AND url != '' AND url = ?) LIMIT 1"
		} else {
			query = "SELECT 1 FROM threat_items WHERE id = $1 OR (url IS NOT NULL AND url != '' AND url = $2) LIMIT 1"
		}
		args = []interface{}{item.ID, item.URL}
	} else {
		if s.isSQLite {
			query = "SELECT 1 FROM threat_items WHERE id = ? LIMIT 1"
		} else {
			query = "SELECT 1 FROM threat_items WHERE id = $1 LIMIT 1"
		}
		args = []interface{}{item.ID}
	}

	var exists int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

var genericOrgNames = map[string]bool{
	"japan": true, "japanese": true, "日本": true, "日本企業": true, "日本組織": true,
	"国内企業": true, "国内組織": true, "政府機関": true, "各企業": true, "複数企業": true,
	"multiple": true, "unknown": true, "n/a": true, "none": true, "various": true,
	"victim": true, "target": true, "organization": true,
}

func isGenericOrg(name string) bool {
	cleaned := strings.ToLower(strings.TrimSpace(name))
	return genericOrgNames[cleaned]
}

func (s *SQLStore) IsRecentlyNotified(ctx context.Context, victimOrgs []string, title string, withinHours int) (bool, error) {
	if withinHours <= 0 {
		withinHours = 48
	}
	cutoffStr := time.Now().UTC().Add(-time.Duration(withinHours) * time.Hour).Format(time.RFC3339)

	var query string
	if s.isSQLite {
		query = "SELECT title, enriched_data FROM threat_items WHERE notified_at IS NOT NULL AND notified_at >= ? LIMIT 100"
	} else {
		query = "SELECT title, enriched_data FROM threat_items WHERE notified_at IS NOT NULL AND notified_at >= $1 LIMIT 100"
	}

	rows, err := s.db.QueryContext(ctx, query, cutoffStr)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	cveRegex := regexp.MustCompile(`(?i)CVE-\d{4}-\d+`)
	currentCVEs := cveRegex.FindAllString(title, -1)
	lowerTitle := strings.ToLower(strings.TrimSpace(title))

	for rows.Next() {
		var rowTitle string
		var rowEnriched sql.NullString
		if err := rows.Scan(&rowTitle, &rowEnriched); err != nil {
			continue
		}

		lowerRowTitle := strings.ToLower(strings.TrimSpace(rowTitle))

		// Check CVE match
		if len(currentCVEs) > 0 {
			rowCVEs := cveRegex.FindAllString(rowTitle, -1)
			if rowEnriched.Valid {
				rowCVEs = append(rowCVEs, cveRegex.FindAllString(rowEnriched.String, -1)...)
			}
			for _, curCVE := range currentCVEs {
				for _, rCVE := range rowCVEs {
					if strings.EqualFold(curCVE, rCVE) {
						return true, nil
					}
				}
			}
		}

		// Check victim org match
		for _, org := range victimOrgs {
			trimmedOrg := strings.TrimSpace(org)
			if len([]rune(trimmedOrg)) >= 2 && !isGenericOrg(trimmedOrg) {
				lowerOrg := strings.ToLower(trimmedOrg)
				if strings.Contains(lowerRowTitle, lowerOrg) {
					return true, nil
				}
				if rowEnriched.Valid && strings.Contains(strings.ToLower(rowEnriched.String), lowerOrg) {
					return true, nil
				}
			}
		}

		// Exact or high title similarity
		if lowerTitle != "" && lowerRowTitle != "" && (lowerTitle == lowerRowTitle || strings.Contains(lowerTitle, lowerRowTitle) || strings.Contains(lowerRowTitle, lowerTitle)) {
			return true, nil
		}
	}

	return false, nil
}

func (s *SQLStore) MarkSeen(ctx context.Context, item models.ThreatItem, enriched *models.EnrichedThreat, notified bool) error {
	nowStr := time.Now().UTC().Format(time.RFC3339)
	var pubStr *string
	if item.PublishedAt != nil {
		formatted := item.PublishedAt.UTC().Format(time.RFC3339)
		pubStr = &formatted
	}

	var severityStr, japanRelStr *string
	var enrichedJSON *string
	if enriched != nil {
		sev := string(enriched.Severity)
		severityStr = &sev
		rel := string(enriched.JapanRelevance)
		japanRelStr = &rel
		if b, err := json.Marshal(enriched); err == nil {
			str := string(b)
			enrichedJSON = &str
		}
	}

	var notifiedStr *string
	if notified {
		notifiedStr = &nowStr
	}

	var query string
	if s.isSQLite {
		query = `
		INSERT INTO threat_items (
			id, source_type, source_name, title, url, summary, published_at, harvested_at,
			severity, japan_relevance, notified_at, enriched_data
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			title = excluded.title,
			summary = excluded.summary,
			harvested_at = excluded.harvested_at,
			severity = excluded.severity,
			japan_relevance = excluded.japan_relevance,
			notified_at = excluded.notified_at,
			enriched_data = excluded.enriched_data
		`
	} else {
		query = `
		INSERT INTO threat_items (
			id, source_type, source_name, title, url, summary, published_at, harvested_at,
			severity, japan_relevance, notified_at, enriched_data
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT(id) DO UPDATE SET
			title = EXCLUDED.title,
			summary = EXCLUDED.summary,
			harvested_at = EXCLUDED.harvested_at,
			severity = EXCLUDED.severity,
			japan_relevance = EXCLUDED.japan_relevance,
			notified_at = EXCLUDED.notified_at,
			enriched_data = EXCLUDED.enriched_data
		`
	}

	_, err := s.db.ExecContext(ctx, query,
		item.ID,
		string(item.SourceType),
		item.SourceName,
		item.Title,
		item.URL,
		item.Summary,
		pubStr,
		nowStr,
		severityStr,
		japanRelStr,
		notifiedStr,
		enrichedJSON,
	)
	return err
}

func (s *SQLStore) GetStats(ctx context.Context) (map[string]interface{}, error) {
	var total, notified, japanDirect int
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM threat_items").Scan(&total)
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM threat_items WHERE notified_at IS NOT NULL").Scan(&notified)
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM threat_items WHERE japan_relevance = 'Direct'").Scan(&japanDirect)

	backendName := "sqlite"
	if !s.isSQLite {
		backendName = "postgresql"
	}

	maskedURL := s.maskURL(s.dbURL)

	return map[string]interface{}{
		"total_items":        total,
		"notified_items":     notified,
		"japan_direct_items": japanDirect,
		"backend":            backendName,
		"database_url":       maskedURL,
		"db_path":            s.dbURL,
	}, nil
}

func (s *SQLStore) maskURL(url string) string {
	re := regexp.MustCompile(`:([^:@]+)@`)
	return re.ReplaceAllString(url, ":****@")
}

func (s *SQLStore) GetHistory(ctx context.Context, f HistoryFilter) ([]map[string]interface{}, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	if f.JapanOnly {
		if s.isSQLite {
			conditions = append(conditions, "japan_relevance = 'Direct'")
		} else {
			conditions = append(conditions, "japan_relevance = 'Direct'")
		}
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
		if s.isSQLite {
			conditions = append(conditions, "source_type = ?")
		} else {
			conditions = append(conditions, fmt.Sprintf("source_type = $%d", argIdx))
			argIdx++
		}
		args = append(args, f.SourceType)
	}
	if f.Search != "" {
		pattern := "%" + f.Search + "%"
		if s.isSQLite {
			conditions = append(conditions, "(title LIKE ? OR summary LIKE ? OR source_name LIKE ? OR enriched_data LIKE ?)")
			args = append(args, pattern, pattern, pattern, pattern)
		} else {
			conditions = append(conditions, fmt.Sprintf("(title ILIKE $%d OR summary ILIKE $%d OR source_name ILIKE $%d OR enriched_data ILIKE $%d)",
				argIdx, argIdx+1, argIdx+2, argIdx+3))
			argIdx += 4
			args = append(args, pattern, pattern, pattern, pattern)
		}
	}

	query := "SELECT id, source_type, source_name, title, url, summary, published_at, harvested_at, severity, japan_relevance, notified_at, enriched_data FROM threat_items"
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	if f.OrderBy == "harvested_at" {
		query += " ORDER BY harvested_at DESC"
	} else {
		query += " ORDER BY COALESCE(NULLIF(published_at, ''), harvested_at) DESC, harvested_at DESC"
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if s.isSQLite {
		query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, f.Offset)
	} else {
		query += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, f.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []map[string]interface{}
	for rows.Next() {
		var (
			id, srcType, srcName, title, harvestedAt string
			url, summary, pubAt, sev, jrel, notifAt, enrichedData sql.NullString
		)
		if err := rows.Scan(&id, &srcType, &srcName, &title, &url, &summary, &pubAt, &harvestedAt, &sev, &jrel, &notifAt, &enrichedData); err != nil {
			continue
		}

		item := map[string]interface{}{
			"id":              id,
			"source_type":     srcType,
			"source_name":     srcName,
			"title":           title,
			"harvested_at":    harvestedAt,
			"url":             nullStringVal(url),
			"summary":         nullStringVal(summary),
			"published_at":    nullStringVal(pubAt),
			"severity":        nullStringVal(sev),
			"japan_relevance": nullStringVal(jrel),
			"notified_at":     nullStringVal(notifAt),
			"enriched_data":   nullStringVal(enrichedData),
		}

		if enrichedData.Valid && enrichedData.String != "" {
			var parsed map[string]interface{}
			if err := json.Unmarshal([]byte(enrichedData.String), &parsed); err == nil {
				item["enriched_parsed"] = parsed
			}
		}

		items = append(items, item)
	}

	return items, nil
}

func (s *SQLStore) GetItem(ctx context.Context, itemID string) (map[string]interface{}, error) {
	query := "SELECT id, source_type, source_name, title, url, summary, published_at, harvested_at, severity, japan_relevance, notified_at, enriched_data FROM threat_items WHERE id = ? OR id LIKE ? LIMIT 1"
	prefix := itemID + "%"
	args := []interface{}{itemID, prefix}
	if !s.isSQLite {
		query = "SELECT id, source_type, source_name, title, url, summary, published_at, harvested_at, severity, japan_relevance, notified_at, enriched_data FROM threat_items WHERE id = $1 OR id LIKE $2 LIMIT 1"
	}

	var (
		id, srcType, srcName, title, harvestedAt string
		url, summary, pubAt, sev, jrel, notifAt, enrichedData sql.NullString
	)

	err := s.db.QueryRowContext(ctx, query, args...).Scan(&id, &srcType, &srcName, &title, &url, &summary, &pubAt, &harvestedAt, &sev, &jrel, &notifAt, &enrichedData)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	item := map[string]interface{}{
		"id":              id,
		"source_type":     srcType,
		"source_name":     srcName,
		"title":           title,
		"harvested_at":    harvestedAt,
		"url":             nullStringVal(url),
		"summary":         nullStringVal(summary),
		"published_at":    nullStringVal(pubAt),
		"severity":        nullStringVal(sev),
		"japan_relevance": nullStringVal(jrel),
		"notified_at":     nullStringVal(notifAt),
		"enriched_data":   nullStringVal(enrichedData),
	}

	if enrichedData.Valid && enrichedData.String != "" {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(enrichedData.String), &parsed); err == nil {
			item["enriched_parsed"] = parsed
		}
	}

	return item, nil
}

func (s *SQLStore) Close() error {
	return s.db.Close()
}

func nullStringVal(ns sql.NullString) interface{} {
	if ns.Valid {
		return ns.String
	}
	return nil
}
