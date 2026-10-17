package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/al17091/threat_harvester/api/internal/models"
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
	GetHistoryTotal(ctx context.Context, filter HistoryFilter) (int, error)
	GetItem(ctx context.Context, itemID string) (map[string]interface{}, error)

	FindOrCreateIncident(ctx context.Context, item models.ThreatItem, enriched *models.EnrichedThreat, windowDays int) (*models.Incident, error)
	GetIncidents(ctx context.Context, filter HistoryFilter) ([]map[string]interface{}, error)
	GetIncidentsTotal(ctx context.Context, filter HistoryFilter) (int, error)
	GetIncident(ctx context.Context, incidentID string) (map[string]interface{}, error)
	BackfillIncidents(ctx context.Context, windowDays int) (int, error)
	BackfillArticleContents(ctx context.Context, fetcher func(ctx context.Context, url string) (string, error)) (int, error)
	GetLatestHarvestTime(ctx context.Context) (*time.Time, error)
	UpdateIncidentTranslations(ctx context.Context, id, title, summary, impact, victimEn, productEn string, actions []string) error
	UpdateIncidentLabels(ctx context.Context, id string, threatActors []string, severity, japanRelevance, attackType, victimOrg string) error
	GetIncidentsNeedingTranslation(ctx context.Context, limit int) ([]models.Incident, error)
	GetEntityStats(ctx context.Context, limit int, japanOnly bool) (*models.EntityStats, error)

	GetPendingFetchItems(ctx context.Context, limit int, maxAttempts int, torOnly bool) ([]models.ThreatItem, error)
	UpdateFetchStatus(ctx context.Context, itemID string, status string, attempts int, fetchError string, rawContent string) error

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
			name = "threat_harvester"
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
			targetURL = path
		} else {
			targetURL = "file::memory:?cache=shared"
		}
		isSQLite = true
	}

	db, err := sql.Open(driver, targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database (%s): %w", driver, err)
	}

	if isSQLite {
		if targetURL == "file::memory:?cache=shared" || sqlitePath == ":memory:" {
			db.SetMaxOpenConns(1)
		} else {
			db.SetMaxOpenConns(5)
		}
	} else {
		db.SetMaxOpenConns(25)
	}
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

	// Trigger automatic backfill if incidents table is empty but threat items exist
	if sqlitePath != ":memory:" {
		go func() {
			var incCount, itemCount int
			_ = store.db.QueryRow("SELECT COUNT(*) FROM incidents").Scan(&incCount)
			_ = store.db.QueryRow("SELECT COUNT(*) FROM threat_items").Scan(&itemCount)
			if incCount == 0 && itemCount > 0 {
				log.Printf("[Storage] Incidents table empty but %d threat items exist. Starting automatic backfill...", itemCount)
				_, _ = store.BackfillIncidents(context.Background(), 30)
			}
		}()
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
		raw_content TEXT,
		published_at TEXT,
		harvested_at TEXT NOT NULL,
		severity VARCHAR(32),
		japan_relevance VARCHAR(32),
		notified_at TEXT,
		enriched_data TEXT,
		fetch_status VARCHAR(32) DEFAULT 'none',
		fetch_attempts INT DEFAULT 0,
		fetch_error TEXT,
		fetched_at TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_harvested_at ON threat_items(harvested_at);
	CREATE INDEX IF NOT EXISTS idx_published_at ON threat_items(published_at);
	CREATE INDEX IF NOT EXISTS idx_source_type ON threat_items(source_type);
	CREATE INDEX IF NOT EXISTS idx_url ON threat_items(url);
	CREATE INDEX IF NOT EXISTS idx_notified_at ON threat_items(notified_at);

	CREATE TABLE IF NOT EXISTS incidents (
		id VARCHAR(64) PRIMARY KEY,
		victim_org VARCHAR(255) NOT NULL,
		normalized_victim_org VARCHAR(255),
		cves TEXT,
		affected_product VARCHAR(255),
		title VARCHAR(512) NOT NULL,
		summary_ja TEXT,
		impact_analysis_ja TEXT,
		severity VARCHAR(32) NOT NULL,
		japan_relevance VARCHAR(32) NOT NULL,
		attack_type VARCHAR(64),
		raw_content TEXT,
		primary_url TEXT,
		source_urls TEXT,
		sources_detail TEXT,
		first_seen_at TEXT NOT NULL,
		last_seen_at TEXT NOT NULL,
		report_count INT DEFAULT 1,
		threat_actors TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_incidents_victim ON incidents(normalized_victim_org);
	CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents(last_seen_at);
	CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	// Migrate existing tables
	if s.isSQLite {
		_, _ = s.db.Exec("ALTER TABLE threat_items ADD COLUMN raw_content TEXT")
		_, _ = s.db.Exec("ALTER TABLE threat_items ADD COLUMN incident_id VARCHAR(64)")
		_, _ = s.db.Exec("ALTER TABLE threat_items ADD COLUMN content_hash VARCHAR(64)")
		_, _ = s.db.Exec("ALTER TABLE threat_items ADD COLUMN fetch_status VARCHAR(32) DEFAULT 'none'")
		_, _ = s.db.Exec("ALTER TABLE threat_items ADD COLUMN fetch_attempts INT DEFAULT 0")
		_, _ = s.db.Exec("ALTER TABLE threat_items ADD COLUMN fetch_error TEXT")
		_, _ = s.db.Exec("ALTER TABLE threat_items ADD COLUMN fetched_at TEXT")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN cves TEXT")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN affected_product VARCHAR(255)")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN raw_content TEXT")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN title_ja VARCHAR(512)")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN victim_org_en VARCHAR(255)")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN victim_org_ja VARCHAR(255)")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN affected_product_en VARCHAR(255)")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN affected_product_ja VARCHAR(255)")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN summary TEXT")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN impact_analysis TEXT")
	} else {
		_, _ = s.db.Exec("ALTER TABLE threat_items ADD COLUMN IF NOT EXISTS raw_content TEXT")
		_, _ = s.db.Exec("ALTER TABLE threat_items ADD COLUMN IF NOT EXISTS incident_id VARCHAR(64)")
		_, _ = s.db.Exec("ALTER TABLE threat_items ADD COLUMN IF NOT EXISTS content_hash VARCHAR(64)")
		_, _ = s.db.Exec("ALTER TABLE threat_items ADD COLUMN IF NOT EXISTS fetch_status VARCHAR(32) DEFAULT 'none'")
		_, _ = s.db.Exec("ALTER TABLE threat_items ADD COLUMN IF NOT EXISTS fetch_attempts INT DEFAULT 0")
		_, _ = s.db.Exec("ALTER TABLE threat_items ADD COLUMN IF NOT EXISTS fetch_error TEXT")
		_, _ = s.db.Exec("ALTER TABLE threat_items ADD COLUMN IF NOT EXISTS fetched_at TEXT")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS cves TEXT")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS affected_product VARCHAR(255)")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS raw_content TEXT")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS title_ja VARCHAR(512)")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS victim_org_en VARCHAR(255)")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS victim_org_ja VARCHAR(255)")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS affected_product_en VARCHAR(255)")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS affected_product_ja VARCHAR(255)")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS summary TEXT")
		_, _ = s.db.Exec("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS impact_analysis TEXT")
	}
	_, _ = s.db.Exec("CREATE INDEX IF NOT EXISTS idx_threat_items_incident ON threat_items(incident_id)")
	_, _ = s.db.Exec("CREATE INDEX IF NOT EXISTS idx_threat_items_content_hash ON threat_items(content_hash)")
	_, _ = s.db.Exec("CREATE INDEX IF NOT EXISTS idx_threat_items_fetch_status ON threat_items(fetch_status)")
	_, _ = s.db.Exec("CREATE INDEX IF NOT EXISTS idx_incidents_affected_product ON incidents(affected_product)")

	// Backfill existing records if raw_content is NULL
	_, _ = s.db.Exec("UPDATE threat_items SET raw_content = summary WHERE raw_content IS NULL AND summary IS NOT NULL")

	// Migrate historical clearnet ransomware tracker items away from darkweb_onion
	_, _ = s.db.Exec("UPDATE threat_items SET source_type = 'ransomware_tracker' WHERE source_type = 'darkweb_onion' AND (url NOT LIKE '%.onion%' OR source_name LIKE 'Ransomlook%')")
	_, _ = s.db.Exec("UPDATE incidents SET sources_detail = REPLACE(sources_detail, '\"source_type\":\"darkweb_onion\"', '\"source_type\":\"ransomware_tracker\"') WHERE sources_detail LIKE '%Ransomlook Tracker%'")

	// Backfill incidents.raw_content from threat_items if empty
	if s.isSQLite {
		_, _ = s.db.Exec(`
			UPDATE incidents SET raw_content = (
				SELECT group_concat(COALESCE(NULLIF(raw_content, ''), summary), char(10) || '---' || char(10))
				FROM threat_items WHERE threat_items.incident_id = incidents.id
			) WHERE raw_content IS NULL OR raw_content = ''
		`)
	} else {
		_, _ = s.db.Exec(`
			UPDATE incidents i
			SET raw_content = sub.combined
			FROM (
				SELECT incident_id, string_agg(COALESCE(NULLIF(raw_content, ''), summary), E'\n\n---\n\n') AS combined
				FROM threat_items
				WHERE incident_id IS NOT NULL AND (raw_content IS NOT NULL OR summary IS NOT NULL)
				GROUP BY incident_id
			) sub
			WHERE i.id = sub.incident_id AND (i.raw_content IS NULL OR i.raw_content = '')
		`)
	}

	// Migrate service releases / non-threat announcements to Info severity and detach from incidents
	serviceReleaseSQL := `
		UPDATE threat_items 
		SET severity = 'Info', incident_id = NULL 
		WHERE (severity IS NULL OR severity IN ('Low', 'Medium', 'Unknown')) AND (
			title LIKE '%新機能%' OR title LIKE '%提供開始%' OR title LIKE '%提供を開始%' OR 
			title LIKE '%新サービス%' OR title LIKE '%業務提携%' OR title LIKE '%セミナー%' OR 
			title LIKE '%出展%' OR title LIKE '%Anthropic asks Claude%' OR title LIKE '%RemoteThreat Bets%' OR 
			title LIKE '%協業を開始%' OR title LIKE '%パートナーシップ%' OR title LIKE '%サービスリリース%' OR 
			title LIKE '%HENNGE%' OR title LIKE '%ChatGPT%広告%' OR title LIKE '%アクセスランキング%' OR 
			title LIKE '%雑談%' OR title LIKE '%減量%' OR title LIKE '%セキュリティ脅威なし%'
		)
	`
	_, _ = s.db.Exec(serviceReleaseSQL)
	_, _ = s.db.Exec("DELETE FROM incidents WHERE severity = 'Info' OR attack_type = 'Service Release'")
	_, _ = s.db.Exec("DELETE FROM incidents WHERE id NOT IN (SELECT DISTINCT incident_id FROM threat_items WHERE incident_id IS NOT NULL)")

	// Sanitize legacy ungrounded threat actors from existing incidents
	s.cleanUngroundedIncidentThreatActors()

	return nil
}

// cleanUngroundedIncidentThreatActors sanitizes legacy incidents with hallucinated or ungrounded threat actors.
func (s *SQLStore) cleanUngroundedIncidentThreatActors() {
	query := "SELECT id, title, COALESCE(raw_content, ''), COALESCE(summary, ''), COALESCE(sources_detail, ''), threat_actors FROM incidents WHERE threat_actors IS NOT NULL AND threat_actors != '[]' AND threat_actors != ''"
	rows, err := s.db.Query(query)
	if err != nil {
		return
	}
	defer rows.Close()

	type updateItem struct {
		id     string
		actors string
	}
	var updates []updateItem

	for rows.Next() {
		var id, title, rawContent, summary, sourcesDetail, rawActors string
		if err := rows.Scan(&id, &title, &rawContent, &summary, &sourcesDetail, &rawActors); err != nil {
			continue
		}
		rawActors = strings.TrimSpace(rawActors)
		if !strings.HasPrefix(rawActors, "[") {
			continue
		}
		var actors []string
		if err := json.Unmarshal([]byte(rawActors), &actors); err != nil {
			continue
		}
		if len(actors) == 0 {
			continue
		}

		grounded := models.FilterGroundedThreatActors(actors, title, rawContent, summary, sourcesDetail)
		changed := len(grounded) != len(actors)
		if !changed {
			for i := range actors {
				if actors[i] != grounded[i] {
					changed = true
					break
				}
			}
		}
		if changed {
			if grounded == nil {
				grounded = []string{}
			}
			newBytes, _ := json.Marshal(grounded)
			updates = append(updates, updateItem{id: id, actors: string(newBytes)})
		}
	}

	for _, up := range updates {
		if s.isSQLite {
			_, _ = s.db.Exec("UPDATE incidents SET threat_actors = ? WHERE id = ?", up.actors, up.id)
		} else {
			_, _ = s.db.Exec("UPDATE incidents SET threat_actors = $1 WHERE id = $2", up.actors, up.id)
		}
	}
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
	if item.ID == "" && item.URL == "" && item.ContentHash == "" {
		return false, nil
	}

	var conditions []string
	var args []interface{}
	argIdx := 1

	if item.ID != "" {
		if s.isSQLite {
			conditions = append(conditions, "id = ?")
		} else {
			conditions = append(conditions, fmt.Sprintf("id = $%d", argIdx))
			argIdx++
		}
		args = append(args, item.ID)
	}

	if item.URL != "" {
		if s.isSQLite {
			conditions = append(conditions, "(url IS NOT NULL AND url != '' AND url = ?)")
		} else {
			conditions = append(conditions, fmt.Sprintf("(url IS NOT NULL AND url != '' AND url = $%d)", argIdx))
			argIdx++
		}
		args = append(args, item.URL)
	}

	if item.ContentHash != "" {
		if s.isSQLite {
			conditions = append(conditions, "(content_hash IS NOT NULL AND content_hash != '' AND content_hash = ?)")
		} else {
			conditions = append(conditions, fmt.Sprintf("(content_hash IS NOT NULL AND content_hash != '' AND content_hash = $%d)", argIdx))
			argIdx++
		}
		args = append(args, item.ContentHash)
	}

	if len(conditions) == 0 {
		return false, nil
	}

	query := "SELECT 1 FROM threat_items WHERE " + strings.Join(conditions, " OR ") + " LIMIT 1"
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

	var rawStr *string
	if item.RawContent != "" {
		rawStr = &item.RawContent
	} else if item.Summary != "" {
		rawStr = &item.Summary
	}

	fetchStatus := item.FetchStatus
	if fetchStatus == "" {
		if fs, ok := item.Metadata["fetch_status"].(string); ok && fs != "" {
			fetchStatus = fs
		} else if item.URL != "" {
			fetchStatus = "pending"
		} else {
			fetchStatus = "none"
		}
	}

	var query string
	if s.isSQLite {
		query = `
		INSERT INTO threat_items (
			id, source_type, source_name, title, url, summary, raw_content, published_at, harvested_at,
			severity, japan_relevance, notified_at, enriched_data, incident_id, content_hash, fetch_status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			title = excluded.title,
			summary = excluded.summary,
			raw_content = COALESCE(NULLIF(excluded.raw_content, ''), threat_items.raw_content),
			harvested_at = excluded.harvested_at,
			severity = excluded.severity,
			japan_relevance = excluded.japan_relevance,
			notified_at = excluded.notified_at,
			enriched_data = excluded.enriched_data,
			incident_id = CASE WHEN excluded.severity = 'Info' THEN NULL ELSE COALESCE(NULLIF(excluded.incident_id, ''), threat_items.incident_id) END,
			content_hash = COALESCE(NULLIF(excluded.content_hash, ''), threat_items.content_hash),
			fetch_status = CASE WHEN threat_items.fetch_status IN ('completed', 'fetching') THEN threat_items.fetch_status ELSE excluded.fetch_status END
		`
	} else {
		query = `
		INSERT INTO threat_items (
			id, source_type, source_name, title, url, summary, raw_content, published_at, harvested_at,
			severity, japan_relevance, notified_at, enriched_data, incident_id, content_hash, fetch_status
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		ON CONFLICT(id) DO UPDATE SET
			title = EXCLUDED.title,
			summary = EXCLUDED.summary,
			raw_content = COALESCE(NULLIF(EXCLUDED.raw_content, ''), threat_items.raw_content),
			harvested_at = EXCLUDED.harvested_at,
			severity = EXCLUDED.severity,
			japan_relevance = EXCLUDED.japan_relevance,
			notified_at = EXCLUDED.notified_at,
			enriched_data = EXCLUDED.enriched_data,
			incident_id = CASE WHEN EXCLUDED.severity = 'Info' THEN NULL ELSE COALESCE(NULLIF(EXCLUDED.incident_id, ''), threat_items.incident_id) END,
			content_hash = COALESCE(NULLIF(EXCLUDED.content_hash, ''), threat_items.content_hash),
			fetch_status = CASE WHEN threat_items.fetch_status IN ('completed', 'fetching') THEN threat_items.fetch_status ELSE EXCLUDED.fetch_status END
		`
	}

	_, err := s.db.ExecContext(ctx, query,
		item.ID,
		string(item.SourceType),
		item.SourceName,
		item.Title,
		item.URL,
		item.Summary,
		rawStr,
		pubStr,
		nowStr,
		severityStr,
		japanRelStr,
		notifiedStr,
		enrichedJSON,
		item.IncidentID,
		item.ContentHash,
		fetchStatus,
	)
	return err
}

func (s *SQLStore) GetStats(ctx context.Context) (map[string]interface{}, error) {
	var total, notified, japanDirect, totalIncidents int
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM threat_items").Scan(&total)
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM threat_items WHERE notified_at IS NOT NULL").Scan(&notified)
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM threat_items WHERE japan_relevance = 'Direct'").Scan(&japanDirect)
	_ = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM incidents").Scan(&totalIncidents)

	backendName := "sqlite"
	if !s.isSQLite {
		backendName = "postgresql"
	}

	maskedURL := s.maskURL(s.dbURL)

	return map[string]interface{}{
		"total_items":        total,
		"total_incidents":    totalIncidents,
		"notified_items":     notified,
		"japan_direct_items": japanDirect,
		"backend":            backendName,
		"database_url":       maskedURL,
		"db_path":            s.dbURL,
	}, nil
}

func (s *SQLStore) GetLatestHarvestTime(ctx context.Context) (*time.Time, error) {
	var maxHarvested sql.NullString
	err := s.db.QueryRowContext(ctx, "SELECT MAX(harvested_at) FROM threat_items WHERE harvested_at IS NOT NULL AND harvested_at != ''").Scan(&maxHarvested)
	if err != nil || !maxHarvested.Valid || maxHarvested.String == "" {
		return nil, err
	}

	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, fmtStr := range formats {
		if t, err := time.Parse(fmtStr, strings.TrimSpace(maxHarvested.String)); err == nil {
			utc := t.UTC()
			return &utc, nil
		}
	}

	return nil, fmt.Errorf("unable to parse harvested_at timestamp: %s", maxHarvested.String)
}

func (s *SQLStore) maskURL(url string) string {
	re := regexp.MustCompile(`:([^:@]+)@`)
	return re.ReplaceAllString(url, ":****@")
}

func (s *SQLStore) buildHistoryConditions(f HistoryFilter) (string, []interface{}) {
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
			conditions = append(conditions, "(title LIKE ? OR summary LIKE ? OR raw_content LIKE ? OR source_name LIKE ? OR enriched_data LIKE ?)")
			args = append(args, pattern, pattern, pattern, pattern, pattern)
		} else {
			conditions = append(conditions, fmt.Sprintf("(title ILIKE $%d OR summary ILIKE $%d OR raw_content ILIKE $%d OR source_name ILIKE $%d OR enriched_data ILIKE $%d)",
				argIdx, argIdx+1, argIdx+2, argIdx+3, argIdx+4))
			argIdx += 5
			args = append(args, pattern, pattern, pattern, pattern, pattern)
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}
	return whereClause, args
}

func (s *SQLStore) GetHistoryTotal(ctx context.Context, f HistoryFilter) (int, error) {
	whereClause, args := s.buildHistoryConditions(f)
	query := "SELECT COUNT(*) FROM threat_items" + whereClause
	var total int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&total)
	return total, err
}

func (s *SQLStore) GetHistory(ctx context.Context, f HistoryFilter) ([]map[string]interface{}, error) {
	whereClause, args := s.buildHistoryConditions(f)
	query := "SELECT id, source_type, source_name, title, url, summary, raw_content, published_at, harvested_at, severity, japan_relevance, notified_at, enriched_data, fetch_status, fetch_attempts, fetch_error, fetched_at FROM threat_items" + whereClause
	if f.OrderBy == "harvested_at" {
		query += " ORDER BY harvested_at DESC"
	} else {
		query += " ORDER BY COALESCE(NULLIF(published_at, ''), harvested_at) DESC, harvested_at DESC"
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

	var items []map[string]interface{}
	for rows.Next() {
		var (
			id, srcType, srcName, title, harvestedAt                          string
			url, summary, rawContent, pubAt, sev, jrel, notifAt, enrichedData sql.NullString
			fetchStatus, fetchError, fetchedAt                               sql.NullString
			fetchAttempts                                                    sql.NullInt64
		)
		if err := rows.Scan(
			&id, &srcType, &srcName, &title, &url, &summary, &rawContent, &pubAt, &harvestedAt,
			&sev, &jrel, &notifAt, &enrichedData,
			&fetchStatus, &fetchAttempts, &fetchError, &fetchedAt,
		); err != nil {
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
			"raw_content":     nullStringVal(rawContent),
			"published_at":    nullStringVal(pubAt),
			"severity":        nullStringVal(sev),
			"japan_relevance": nullStringVal(jrel),
			"notified_at":     nullStringVal(notifAt),
			"enriched_data":   nullStringVal(enrichedData),
			"fetch_status":    nullStringVal(fetchStatus),
			"fetch_attempts":  fetchAttempts.Int64,
			"fetch_error":     nullStringVal(fetchError),
			"fetched_at":      nullStringVal(fetchedAt),
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
	query := "SELECT id, source_type, source_name, title, url, summary, raw_content, published_at, harvested_at, severity, japan_relevance, notified_at, enriched_data, fetch_status, fetch_attempts, fetch_error, fetched_at FROM threat_items WHERE id = ? OR id LIKE ? LIMIT 1"
	prefix := itemID + "%"
	args := []interface{}{itemID, prefix}
	if !s.isSQLite {
		query = "SELECT id, source_type, source_name, title, url, summary, raw_content, published_at, harvested_at, severity, japan_relevance, notified_at, enriched_data, fetch_status, fetch_attempts, fetch_error, fetched_at FROM threat_items WHERE id = $1 OR id LIKE $2 LIMIT 1"
	}

	var (
		id, srcType, srcName, title, harvestedAt                          string
		url, summary, rawContent, pubAt, sev, jrel, notifAt, enrichedData sql.NullString
		fetchStatus, fetchError, fetchedAt                               sql.NullString
		fetchAttempts                                                    sql.NullInt64
	)

	err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&id, &srcType, &srcName, &title, &url, &summary, &rawContent, &pubAt, &harvestedAt,
		&sev, &jrel, &notifAt, &enrichedData,
		&fetchStatus, &fetchAttempts, &fetchError, &fetchedAt,
	)
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
		"raw_content":     nullStringVal(rawContent),
		"published_at":    nullStringVal(pubAt),
		"severity":        nullStringVal(sev),
		"japan_relevance": nullStringVal(jrel),
		"notified_at":     nullStringVal(notifAt),
		"enriched_data":   nullStringVal(enrichedData),
		"fetch_status":    nullStringVal(fetchStatus),
		"fetch_attempts":  fetchAttempts.Int64,
		"fetch_error":     nullStringVal(fetchError),
		"fetched_at":      nullStringVal(fetchedAt),
	}

	if enrichedData.Valid && enrichedData.String != "" {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(enrichedData.String), &parsed); err == nil {
			item["enriched_parsed"] = parsed
		}
	}

	return item, nil
}

// BackfillArticleContents retrieves full text for threat_items with missing or very brief raw_content.
func (s *SQLStore) BackfillArticleContents(ctx context.Context, fetcher func(ctx context.Context, url string) (string, error)) (int, error) {
	if fetcher == nil {
		return 0, fmt.Errorf("fetcher function is nil")
	}

	query := `
		SELECT id, incident_id, url, title
		FROM threat_items
		WHERE url IS NOT NULL AND url != '' 
		  AND url NOT LIKE '%.onion%'
		  AND (raw_content IS NULL OR TRIM(raw_content) = '' OR (source_type = 'vendor_rss' AND LENGTH(raw_content) < 150))
		ORDER BY harvested_at DESC
		LIMIT 150
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type targetRow struct {
		id         string
		incidentID sql.NullString
		url        string
		title      string
	}

	var targets []targetRow
	for rows.Next() {
		var r targetRow
		if err := rows.Scan(&r.id, &r.incidentID, &r.url, &r.title); err == nil {
			targets = append(targets, r)
		}
	}

	if len(targets) == 0 {
		return 0, nil
	}

	log.Printf("[Backfill] Found %d articles needing full content extraction", len(targets))

	type resultItem struct {
		target targetRow
		text   string
	}

	resultsChan := make(chan resultItem, len(targets))
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		go func(row targetRow) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fetchCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()

			text, err := fetcher(fetchCtx, row.url)
			if err == nil && len(strings.TrimSpace(text)) > 0 {
				resultsChan <- resultItem{target: row, text: text}
			}
		}(t)
	}

	wg.Wait()
	close(resultsChan)

	updatedCount := 0
	for res := range resultsChan {
		updateItemQ := "UPDATE threat_items SET raw_content = ?, summary = CASE WHEN (summary IS NULL OR summary = '') THEN ? ELSE summary END WHERE id = ?"
		if !s.isSQLite {
			updateItemQ = "UPDATE threat_items SET raw_content = $1, summary = CASE WHEN (summary IS NULL OR summary = '') THEN $2 ELSE summary END WHERE id = $3"
		}
		summaryTeaser := models.TruncateRunes(res.text, 400)
		_, _ = s.db.ExecContext(ctx, updateItemQ, res.text, summaryTeaser, res.target.id)

		if res.target.incidentID.Valid && res.target.incidentID.String != "" {
			updateIncQ := "UPDATE incidents SET raw_content = ? WHERE id = ? AND (raw_content IS NULL OR TRIM(raw_content) = '' OR LENGTH(raw_content) < 150)"
			if !s.isSQLite {
				updateIncQ = "UPDATE incidents SET raw_content = $1 WHERE id = $2 AND (raw_content IS NULL OR TRIM(raw_content) = '' OR LENGTH(raw_content) < 150)"
			}
			_, _ = s.db.ExecContext(ctx, updateIncQ, res.text, res.target.incidentID.String)
		}
		updatedCount++
	}

	log.Printf("[Backfill] Completed article backfill: successfully enriched %d/%d articles", updatedCount, len(targets))
	return updatedCount, nil
}

func (s *SQLStore) GetPendingFetchItems(ctx context.Context, limit int, maxAttempts int, torOnly bool) ([]models.ThreatItem, error) {
	if limit <= 0 {
		limit = 20
	}
	if maxAttempts <= 0 {
		maxAttempts = 2
	}

	var query string
	if s.isSQLite {
		if torOnly {
			query = `
			SELECT id, source_type, source_name, title, url, summary, raw_content, published_at, harvested_at,
			       fetch_status, fetch_attempts, fetch_error, fetched_at, incident_id
			FROM threat_items
			WHERE fetch_status IN ('pending', 'failed')
			  AND fetch_attempts < ?
			  AND url IS NOT NULL AND url != ''
			  AND url LIKE '%.onion%'
			ORDER BY harvested_at DESC LIMIT ?
			`
		} else {
			query = `
			SELECT id, source_type, source_name, title, url, summary, raw_content, published_at, harvested_at,
			       fetch_status, fetch_attempts, fetch_error, fetched_at, incident_id
			FROM threat_items
			WHERE fetch_status IN ('pending', 'failed')
			  AND fetch_attempts < ?
			  AND url IS NOT NULL AND url != ''
			  AND url NOT LIKE '%.onion%'
			ORDER BY harvested_at DESC LIMIT ?
			`
		}
	} else {
		if torOnly {
			query = `
			SELECT id, source_type, source_name, title, url, summary, raw_content, published_at, harvested_at,
			       fetch_status, fetch_attempts, fetch_error, fetched_at, incident_id
			FROM threat_items
			WHERE fetch_status IN ('pending', 'failed')
			  AND fetch_attempts < $1
			  AND url IS NOT NULL AND url != ''
			  AND url LIKE '%.onion%'
			ORDER BY harvested_at DESC LIMIT $2
			`
		} else {
			query = `
			SELECT id, source_type, source_name, title, url, summary, raw_content, published_at, harvested_at,
			       fetch_status, fetch_attempts, fetch_error, fetched_at, incident_id
			FROM threat_items
			WHERE fetch_status IN ('pending', 'failed')
			  AND fetch_attempts < $1
			  AND url IS NOT NULL AND url != ''
			  AND url NOT LIKE '%.onion%'
			ORDER BY harvested_at DESC LIMIT $2
			`
		}
	}

	rows, err := s.db.QueryContext(ctx, query, maxAttempts, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []models.ThreatItem
	for rows.Next() {
		var (
			id, sourceType, sourceName, title string
			url, summary, rawContent          sql.NullString
			pubAt, harvAt                     sql.NullString
			fetchStatus                       sql.NullString
			fetchAttempts                     int
			fetchError, fetchedAt             sql.NullString
			incidentID                        sql.NullString
		)

		if err := rows.Scan(
			&id, &sourceType, &sourceName, &title,
			&url, &summary, &rawContent, &pubAt, &harvAt,
			&fetchStatus, &fetchAttempts, &fetchError, &fetchedAt, &incidentID,
		); err != nil {
			continue
		}

		var parsedPub *time.Time
		if pubAt.Valid && pubAt.String != "" {
			if t, err := time.Parse(time.RFC3339, pubAt.String); err == nil {
				parsedPub = &t
			}
		}

		var parsedHarv time.Time
		if harvAt.Valid && harvAt.String != "" {
			if t, err := time.Parse(time.RFC3339, harvAt.String); err == nil {
				parsedHarv = t
			}
		}
		if parsedHarv.IsZero() {
			parsedHarv = time.Now().UTC()
		}

		var parsedFetched *time.Time
		if fetchedAt.Valid && fetchedAt.String != "" {
			if t, err := time.Parse(time.RFC3339, fetchedAt.String); err == nil {
				parsedFetched = &t
			}
		}

		fStatus := "pending"
		if fetchStatus.Valid && fetchStatus.String != "" {
			fStatus = fetchStatus.String
		}

		item := models.ThreatItem{
			ID:            id,
			IncidentID:    incidentID.String,
			SourceType:    models.SourceType(sourceType),
			SourceName:    sourceName,
			Title:         title,
			URL:           url.String,
			Summary:       summary.String,
			RawContent:    rawContent.String,
			FetchStatus:   fStatus,
			FetchAttempts: fetchAttempts,
			FetchError:    fetchError.String,
			FetchedAt:     parsedFetched,
			PublishedAt:   parsedPub,
			HarvestedAt:   parsedHarv,
			Metadata: map[string]interface{}{
				"is_onion": strings.Contains(url.String, ".onion"),
			},
		}
		items = append(items, item)
	}

	return items, nil
}

func (s *SQLStore) UpdateFetchStatus(ctx context.Context, itemID string, status string, attempts int, fetchError string, rawContent string) error {
	var query string
	var fetchedAtStr *string
	if status == "completed" {
		now := time.Now().UTC().Format(time.RFC3339)
		fetchedAtStr = &now
	}

	if s.isSQLite {
		query = `
		UPDATE threat_items
		SET fetch_status = ?,
		    fetch_attempts = ?,
		    fetch_error = ?,
		    raw_content = COALESCE(NULLIF(?, ''), raw_content),
		    fetched_at = COALESCE(?, fetched_at)
		WHERE id = ?
		`
		_, err := s.db.ExecContext(ctx, query, status, attempts, fetchError, rawContent, fetchedAtStr, itemID)
		return err
	}

	query = `
	UPDATE threat_items
	SET fetch_status = $1,
	    fetch_attempts = $2,
	    fetch_error = $3,
	    raw_content = COALESCE(NULLIF($4, ''), raw_content),
	    fetched_at = COALESCE($5, fetched_at)
	WHERE id = $6
	`
	_, err := s.db.ExecContext(ctx, query, status, attempts, fetchError, rawContent, fetchedAtStr, itemID)
	return err
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
