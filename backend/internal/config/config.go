package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(?::-([^}]*))?\}`)

func expandEnvVars(input string) string {
	return envVarPattern.ReplaceAllStringFunc(input, func(m string) string {
		sub := envVarPattern.FindStringSubmatch(m)
		if len(sub) >= 2 {
			varName := sub[1]
			defaultVal := ""
			if len(sub) >= 3 {
				defaultVal = sub[2]
			}
			val := os.Getenv(varName)
			if val == "" {
				return defaultVal
			}
			return val
		}
		return m
	})
}

const (
	TierCommercialReady          = "commercial_ready"
	TierCommercialViaOfficialAPI = "commercial_via_official_api"
	TierToSRestricted            = "tos_restricted"
	TierDarkwebAccess            = "darkweb_access"

	ComplianceModeAll              = "all"
	ComplianceModeCommercialOnly   = "commercial_only"
	ComplianceModeOfficialAPIReady = "official_api_ready"
	ComplianceModeCustom           = "custom"
)

type ComplianceTiersConfig struct {
	CommercialReady          bool `yaml:"commercial_ready" json:"commercial_ready"`
	CommercialViaOfficialAPI bool `yaml:"commercial_via_official_api" json:"commercial_via_official_api"`
	ToSRestricted            bool `yaml:"tos_restricted" json:"tos_restricted"`
	DarkwebAccess            bool `yaml:"darkweb_access" json:"darkweb_access"`
}

type ComplianceConfig struct {
	Mode  string                `yaml:"mode" json:"mode"`
	Tiers ComplianceTiersConfig `yaml:"tiers" json:"tiers"`
}

func (c *ComplianceConfig) IsTierEnabled(tier string) bool {
	switch tier {
	case TierCommercialReady:
		return c.Tiers.CommercialReady
	case TierCommercialViaOfficialAPI:
		return c.Tiers.CommercialViaOfficialAPI
	case TierToSRestricted:
		return c.Tiers.ToSRestricted
	case TierDarkwebAccess:
		return c.Tiers.DarkwebAccess
	default:
		return true
	}
}

func (c *ComplianceConfig) ApplyMode(mode string) {
	c.Mode = mode
	switch mode {
	case ComplianceModeCommercialOnly:
		c.Tiers.CommercialReady = true
		c.Tiers.CommercialViaOfficialAPI = false
		c.Tiers.ToSRestricted = false
		c.Tiers.DarkwebAccess = false
	case ComplianceModeOfficialAPIReady:
		c.Tiers.CommercialReady = true
		c.Tiers.CommercialViaOfficialAPI = true
		c.Tiers.ToSRestricted = false
		c.Tiers.DarkwebAccess = false
	case ComplianceModeAll:
		c.Tiers.CommercialReady = true
		c.Tiers.CommercialViaOfficialAPI = true
		c.Tiers.ToSRestricted = true
		c.Tiers.DarkwebAccess = true
	case ComplianceModeCustom:
		// Keep individual tiers as is
	}
}

func GetDefaultTierForSource(sourceType string, subType string) string {
	switch sourceType {
	case "vendor_rss":
		return TierCommercialReady
	case "telegram":
		return TierToSRestricted
	case "darkweb_onion":
		return TierDarkwebAccess
	case "ransomware_tracker":
		if subType == "api" {
			return TierCommercialViaOfficialAPI
		}
		return TierCommercialReady
	case "x_monitor":
		return TierCommercialViaOfficialAPI
	case "web_search":
		return TierCommercialViaOfficialAPI
	default:
		return TierCommercialReady
	}
}

type FeedSourceConfig struct {
	Name           string `yaml:"name" json:"name"`
	URL            string `yaml:"url" json:"url"`
	Category       string `yaml:"category" json:"category"`
	ComplianceTier string `yaml:"compliance_tier,omitempty" json:"compliance_tier,omitempty"`
	Enabled        bool   `yaml:"enabled" json:"enabled"`
}

type TelegramSourceConfig struct {
	Channel        string `yaml:"channel" json:"channel"`
	ComplianceTier string `yaml:"compliance_tier,omitempty" json:"compliance_tier,omitempty"`
	Enabled        bool   `yaml:"enabled" json:"enabled"`
}

type DarkwebSourceConfig struct {
	Name           string `yaml:"name" json:"name"`
	URL            string `yaml:"url" json:"url"`
	Type           string `yaml:"type" json:"type"` // "api", "rss", or "onion"
	ComplianceTier string `yaml:"compliance_tier,omitempty" json:"compliance_tier,omitempty"`
	Enabled        bool   `yaml:"enabled" json:"enabled"`
}

type RansomwareSourceConfig struct {
	Name           string `yaml:"name" json:"name"`
	URL            string `yaml:"url" json:"url"`
	Type           string `yaml:"type" json:"type"` // "api", "rss"
	ComplianceTier string `yaml:"compliance_tier,omitempty" json:"compliance_tier,omitempty"`
	Enabled        bool   `yaml:"enabled" json:"enabled"`
}

type QuerySourceConfig struct {
	Name           string `yaml:"name,omitempty" json:"name,omitempty"`
	Directive      string `yaml:"directive,omitempty" json:"directive,omitempty"`
	Query          string `yaml:"query,omitempty" json:"query,omitempty"`
	ComplianceTier string `yaml:"compliance_tier,omitempty" json:"compliance_tier,omitempty"`
	Enabled        bool   `yaml:"enabled" json:"enabled"`
}

type SourcesConfig struct {
	VendorRSS         []FeedSourceConfig       `yaml:"vendor_rss" json:"vendor_rss"`
	Telegram          []TelegramSourceConfig   `yaml:"telegram" json:"telegram"`
	DarkwebOnion      []DarkwebSourceConfig    `yaml:"darkweb_onion" json:"darkweb_onion"`
	RansomwareTracker []RansomwareSourceConfig `yaml:"ransomware_tracker" json:"ransomware_tracker"`
	XMonitor          []QuerySourceConfig      `yaml:"x_monitor" json:"x_monitor"`
	WebSearch         []QuerySourceConfig      `yaml:"web_search" json:"web_search"`
}

type DatabaseConfig struct {
	Type       string `yaml:"type" json:"type"` // "postgres" or "sqlite"
	URL        string `yaml:"url" json:"url"`
	Host       string `yaml:"host" json:"host"`
	Port       int    `yaml:"port" json:"port"`
	Name       string `yaml:"name" json:"name"`
	User       string `yaml:"user" json:"user"`
	Password   string `yaml:"password" json:"password"`
	SSLMode    string `yaml:"sslmode" json:"sslmode"`
	SQLitePath string `yaml:"sqlite_path" json:"sqlite_path"`
}

type AiConfig struct {
	GeminiAPIKey string `yaml:"gemini_api_key" json:"gemini_api_key"`
	GeminiModel  string `yaml:"gemini_model" json:"gemini_model"`
}

type SinkConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	WebhookURL string `yaml:"webhook_url" json:"webhook_url"`
}

type NotionSinkConfig struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	APIKey     string `yaml:"api_key" json:"api_key"`
	DatabaseID string `yaml:"database_id" json:"database_id"`
}

type SinksConfig struct {
	Discord        SinkConfig       `yaml:"discord" json:"discord"`
	Slack          SinkConfig       `yaml:"slack" json:"slack"`
	GenericWebhook SinkConfig       `yaml:"generic_webhook" json:"generic_webhook"`
	Notion         NotionSinkConfig `yaml:"notion" json:"notion"`
}

type NetworkConfig struct {
	TorProxyURL    string `yaml:"tor_proxy_url" json:"tor_proxy_url"`
	RequestTimeout int    `yaml:"request_timeout" json:"request_timeout"`
}

type PipelineConfig struct {
	CheckIntervalHours int  `yaml:"check_interval_hours" json:"check_interval_hours"`
	NotifyDirectOnly   bool `yaml:"notify_direct_only" json:"notify_direct_only"`
}

type AppConfig struct {
	Version    string           `yaml:"version" json:"version"`
	Compliance ComplianceConfig `yaml:"compliance" json:"compliance"`
	Database   DatabaseConfig   `yaml:"database" json:"database"`
	AI         AiConfig         `yaml:"ai" json:"ai"`
	Sinks      SinksConfig      `yaml:"sinks" json:"sinks"`
	Network    NetworkConfig    `yaml:"network" json:"network"`
	Pipeline   PipelineConfig   `yaml:"pipeline" json:"pipeline"`
	Sources    SourcesConfig    `yaml:"sources" json:"sources"`
}

func DefaultConfig() AppConfig {
	return AppConfig{
		Version: "1.0",
		Compliance: ComplianceConfig{
			Mode: ComplianceModeAll,
			Tiers: ComplianceTiersConfig{
				CommercialReady:          true,
				CommercialViaOfficialAPI: true,
				ToSRestricted:            true,
				DarkwebAccess:            true,
			},
		},
		Database: DatabaseConfig{
			Type:       "sqlite",
			Host:       "postgres-cluster-rw",
			Port:       5432,
			Name:       "information_harvester",
			User:       "postgres",
			SSLMode:    "prefer",
			SQLitePath: "data/threat_cache.db",
		},
		AI: AiConfig{
			GeminiModel: "gemini-2.5-flash",
		},
		Network: NetworkConfig{
			TorProxyURL:    "socks5h://127.0.0.1:9050",
			RequestTimeout: 25,
		},
		Pipeline: PipelineConfig{
			CheckIntervalHours: 1,
			NotifyDirectOnly:   false,
		},
		Sources: SourcesConfig{
			VendorRSS: []FeedSourceConfig{
				{Name: "JPCERT/CC 注意喚起", URL: "https://www.jpcert.or.jp/rss/jpcert.rdf", Category: "jp_cert", ComplianceTier: TierCommercialReady, Enabled: true},
				{Name: "IPA 重要なセキュリティ情報", URL: "https://www.ipa.go.jp/security/rss/alert.rdf", Category: "jp_cert", ComplianceTier: TierCommercialReady, Enabled: true},
				{Name: "ScanNetSecurity", URL: "https://scan.netsecurity.ne.jp/rss/index.rdf", Category: "jp_news", ComplianceTier: TierCommercialReady, Enabled: true},
				{Name: "Security Next", URL: "https://www.security-next.com/feed", Category: "jp_news", ComplianceTier: TierCommercialReady, Enabled: true},
				{Name: "BleepingComputer", URL: "https://www.bleepingcomputer.com/feed/", Category: "global_news", ComplianceTier: TierCommercialReady, Enabled: true},
				{Name: "The Hacker News", URL: "https://thehackernews.com/rss.xml", Category: "global_news", ComplianceTier: TierCommercialReady, Enabled: true},
				{Name: "CISA Alerts", URL: "https://www.cisa.gov/uscert/ncas/alerts.xml", Category: "global_cert", ComplianceTier: TierCommercialReady, Enabled: true},
			},
			Telegram: []TelegramSourceConfig{
				{Channel: "redabyss_cti", ComplianceTier: TierToSRestricted, Enabled: true},
				{Channel: "malware_traffic", ComplianceTier: TierToSRestricted, Enabled: true},
				{Channel: "ransomfeed", ComplianceTier: TierToSRestricted, Enabled: true},
				{Channel: "cybersecurity_news_hub", ComplianceTier: TierToSRestricted, Enabled: true},
			},
			DarkwebOnion: []DarkwebSourceConfig{},
			RansomwareTracker: []RansomwareSourceConfig{
				{Name: "Ransomlook Tracker", URL: "https://www.ransomlook.io/api/recent", Type: "api", ComplianceTier: TierCommercialViaOfficialAPI, Enabled: true},
				{Name: "RansomFeed Aggregator", URL: "https://ransomfeed.it/news.rss", Type: "rss", ComplianceTier: TierCommercialReady, Enabled: true},
			},
			XMonitor: []QuerySourceConfig{
				{Query: "cyber attack Japan victim site:x.com OR site:twitter.com", ComplianceTier: TierCommercialViaOfficialAPI, Enabled: true},
				{Query: "ランサムウェア 日本 標的 site:x.com OR site:twitter.com", ComplianceTier: TierCommercialViaOfficialAPI, Enabled: true},
				{Query: "JPCERT CyberThreat site:x.com OR site:twitter.com", ComplianceTier: TierCommercialViaOfficialAPI, Enabled: true},
			},
			WebSearch: []QuerySourceConfig{
				{Query: "最新 サイバー攻撃 日本 企業 組織 被害 ランサムウェア", ComplianceTier: TierCommercialViaOfficialAPI, Enabled: true},
				{Query: "Japan targeted cyber attack data breach ransomware recent", ComplianceTier: TierCommercialViaOfficialAPI, Enabled: true},
				{Query: "セキュリティインシデント 漏洩 日本 国内 最近", ComplianceTier: TierCommercialViaOfficialAPI, Enabled: true},
			},
		},
	}
}

type SettingsManager struct {
	mu         sync.RWMutex
	ConfigPath string
	Config     AppConfig
}

var (
	globalSettings *SettingsManager
	once           sync.Once
)

func GetSettings() *SettingsManager {
	once.Do(func() {
		configPath := os.Getenv("CONFIG_PATH")
		if configPath == "" {
			configPath = "config.yaml"
		}
		globalSettings = &SettingsManager{
			ConfigPath: configPath,
			Config:     DefaultConfig(),
		}
		globalSettings.Reload(configPath)
	})
	return globalSettings
}

func (s *SettingsManager) Reload(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if path != "" {
		s.ConfigPath = path
	}

	raw, err := os.ReadFile(s.ConfigPath)
	if err == nil {
		expanded := expandEnvVars(string(raw))
		var cfg AppConfig
		if err := yaml.Unmarshal([]byte(expanded), &cfg); err == nil {
			s.Config = cfg
		}
	}

	// Apply environment variable overrides
	s.applyEnvOverrides()
	return nil
}

func (s *SettingsManager) applyEnvOverrides() {
	if v := os.Getenv("GEMINI_API_KEY"); v != "" {
		s.Config.AI.GeminiAPIKey = v
	}
	if v := os.Getenv("GEMINI_MODEL"); v != "" {
		s.Config.AI.GeminiModel = v
	}
	if v := os.Getenv("DATABASE_URL"); v != "" {
		s.Config.Database.URL = v
		if strings.Contains(v, "postgres") {
			s.Config.Database.Type = "postgres"
		} else {
			s.Config.Database.Type = "sqlite"
		}
	}
	if v := os.Getenv("DISCORD_WEBHOOK_URL"); v != "" {
		s.Config.Sinks.Discord.WebhookURL = v
	}
	if v := os.Getenv("SLACK_WEBHOOK_URL"); v != "" {
		s.Config.Sinks.Slack.WebhookURL = v
	}
	if v := os.Getenv("GENERIC_WEBHOOK_URL"); v != "" {
		s.Config.Sinks.GenericWebhook.WebhookURL = v
	}
	if v := os.Getenv("NOTION_API_KEY"); v != "" {
		s.Config.Sinks.Notion.APIKey = v
	}
	if v := os.Getenv("NOTION_DATABASE_ID"); v != "" {
		s.Config.Sinks.Notion.DatabaseID = v
	}
	if v := os.Getenv("TOR_PROXY_URL"); v != "" {
		s.Config.Network.TorProxyURL = v
	}
	if v := os.Getenv("CACHE_DB_PATH"); v != "" {
		s.Config.Database.SQLitePath = v
	}
	if v := os.Getenv("COMPLIANCE_MODE"); v != "" {
		s.Config.Compliance.ApplyMode(v)
	}
}

func (s *SettingsManager) GetConfig() AppConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Config
}

func (s *SettingsManager) ToSafeMap() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, _ := yaml.Marshal(s.Config)
	var m map[string]interface{}
	_ = yaml.Unmarshal(data, &m)

	if ai, ok := m["ai"].(map[string]interface{}); ok {
		if k, ok := ai["gemini_api_key"].(string); ok && len(k) > 0 {
			if len(k) > 8 {
				ai["gemini_api_key"] = k[:4] + "..." + k[len(k)-4:]
			} else {
				ai["gemini_api_key"] = "***"
			}
		}
	}
	if db, ok := m["database"].(map[string]interface{}); ok {
		if p, ok := db["password"].(string); ok && len(p) > 0 {
			db["password"] = "******"
		}
	}
	return m
}

func (s *SettingsManager) ExportYAML(maskSecrets bool) string {
	s.mu.RLock()
	cfg := s.Config
	s.mu.RUnlock()

	if maskSecrets {
		if cfg.AI.GeminiAPIKey != "" {
			cfg.AI.GeminiAPIKey = "********"
		}
		if cfg.Database.Password != "" {
			cfg.Database.Password = "********"
		}
		if cfg.Sinks.Discord.WebhookURL != "" {
			cfg.Sinks.Discord.WebhookURL = "https://...[masked]"
		}
		if cfg.Sinks.Slack.WebhookURL != "" {
			cfg.Sinks.Slack.WebhookURL = "https://...[masked]"
		}
		if cfg.Sinks.GenericWebhook.WebhookURL != "" {
			cfg.Sinks.GenericWebhook.WebhookURL = "https://...[masked]"
		}
		if cfg.Sinks.Notion.APIKey != "" {
			cfg.Sinks.Notion.APIKey = "********"
		}
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return ""
	}
	header := "# Threat Information Harvester Configuration\n# Exported from Web GUI\n\n"
	return header + string(data)
}

func (s *SettingsManager) Save(path string) error {
	s.mu.RLock()
	targetPath := path
	if targetPath == "" {
		targetPath = s.ConfigPath
	}
	yamlContent := s.ExportYAML(false)
	s.mu.RUnlock()

	return os.WriteFile(targetPath, []byte(yamlContent), 0644)
}

func (s *SettingsManager) AddSource(sourceType string, data map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tier, _ := data["compliance_tier"].(string)

	switch sourceType {
	case "vendor_rss":
		name, _ := data["name"].(string)
		url, _ := data["url"].(string)
		category, _ := data["category"].(string)
		if category == "" {
			category = "general"
		}
		if name == "" || url == "" {
			return fmt.Errorf("name and url are required")
		}
		if tier == "" {
			tier = TierCommercialReady
		}
		s.Config.Sources.VendorRSS = append(s.Config.Sources.VendorRSS, FeedSourceConfig{
			Name:           name,
			URL:            url,
			Category:       category,
			ComplianceTier: tier,
			Enabled:        true,
		})
	case "telegram":
		ch, _ := data["channel"].(string)
		if ch == "" {
			return fmt.Errorf("channel is required")
		}
		if tier == "" {
			tier = TierToSRestricted
		}
		s.Config.Sources.Telegram = append(s.Config.Sources.Telegram, TelegramSourceConfig{
			Channel:        strings.TrimPrefix(ch, "@"),
			ComplianceTier: tier,
			Enabled:        true,
		})
	case "darkweb_onion":
		name, _ := data["name"].(string)
		url, _ := data["url"].(string)
		t, _ := data["type"].(string)
		if t == "" {
			t = "onion"
		}
		if name == "" || url == "" {
			return fmt.Errorf("name and url are required")
		}
		if !strings.Contains(url, ".onion") {
			return fmt.Errorf("darkweb sources must use a .onion address")
		}
		if tier == "" {
			tier = TierDarkwebAccess
		}
		s.Config.Sources.DarkwebOnion = append(s.Config.Sources.DarkwebOnion, DarkwebSourceConfig{
			Name:           name,
			URL:            url,
			Type:           t,
			ComplianceTier: tier,
			Enabled:        true,
		})
	case "ransomware_tracker":
		name, _ := data["name"].(string)
		url, _ := data["url"].(string)
		t, _ := data["type"].(string)
		if t == "" {
			t = "api"
		}
		if name == "" || url == "" {
			return fmt.Errorf("name and url are required")
		}
		if tier == "" {
			if t == "api" {
				tier = TierCommercialViaOfficialAPI
			} else {
				tier = TierCommercialReady
			}
		}
		s.Config.Sources.RansomwareTracker = append(s.Config.Sources.RansomwareTracker, RansomwareSourceConfig{
			Name:           name,
			URL:            url,
			Type:           t,
			ComplianceTier: tier,
			Enabled:        true,
		})
	case "x_monitor":
		directive, _ := data["directive"].(string)
		q, _ := data["query"].(string)
		name, _ := data["name"].(string)
		if strings.TrimSpace(directive) == "" && strings.TrimSpace(q) == "" {
			return fmt.Errorf("directive or query is required")
		}
		if tier == "" {
			tier = TierCommercialViaOfficialAPI
		}
		s.Config.Sources.XMonitor = append(s.Config.Sources.XMonitor, QuerySourceConfig{
			Name:           strings.TrimSpace(name),
			Directive:      strings.TrimSpace(directive),
			Query:          strings.TrimSpace(q),
			ComplianceTier: tier,
			Enabled:        true,
		})
	case "web_search":
		directive, _ := data["directive"].(string)
		q, _ := data["query"].(string)
		name, _ := data["name"].(string)
		if strings.TrimSpace(directive) == "" && strings.TrimSpace(q) == "" {
			return fmt.Errorf("directive or query is required")
		}
		if tier == "" {
			tier = TierCommercialViaOfficialAPI
		}
		s.Config.Sources.WebSearch = append(s.Config.Sources.WebSearch, QuerySourceConfig{
			Name:           strings.TrimSpace(name),
			Directive:      strings.TrimSpace(directive),
			Query:          strings.TrimSpace(q),
			ComplianceTier: tier,
			Enabled:        true,
		})
	default:
		return fmt.Errorf("unsupported source type: %s", sourceType)
	}
	return nil
}

func (s *SettingsManager) UpdateSource(sourceType, identifier string, data map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tier, _ := data["compliance_tier"].(string)

	switch sourceType {
	case "vendor_rss":
		for i := range s.Config.Sources.VendorRSS {
			if s.Config.Sources.VendorRSS[i].URL == identifier || s.Config.Sources.VendorRSS[i].Name == identifier {
				if name, ok := data["name"].(string); ok && strings.TrimSpace(name) != "" {
					s.Config.Sources.VendorRSS[i].Name = strings.TrimSpace(name)
				}
				if u, ok := data["url"].(string); ok && strings.TrimSpace(u) != "" {
					s.Config.Sources.VendorRSS[i].URL = strings.TrimSpace(u)
				}
				if cat, ok := data["category"].(string); ok && strings.TrimSpace(cat) != "" {
					s.Config.Sources.VendorRSS[i].Category = strings.TrimSpace(cat)
				}
				if tier != "" {
					s.Config.Sources.VendorRSS[i].ComplianceTier = tier
				}
				if en, ok := data["enabled"].(bool); ok {
					s.Config.Sources.VendorRSS[i].Enabled = en
				}
				return nil
			}
		}
		return fmt.Errorf("vendor_rss source not found: %s", identifier)

	case "telegram":
		cleanID := strings.TrimPrefix(identifier, "@")
		for i := range s.Config.Sources.Telegram {
			if s.Config.Sources.Telegram[i].Channel == cleanID {
				if ch, ok := data["channel"].(string); ok && strings.TrimSpace(ch) != "" {
					s.Config.Sources.Telegram[i].Channel = strings.TrimPrefix(strings.TrimSpace(ch), "@")
				}
				if tier != "" {
					s.Config.Sources.Telegram[i].ComplianceTier = tier
				}
				if en, ok := data["enabled"].(bool); ok {
					s.Config.Sources.Telegram[i].Enabled = en
				}
				return nil
			}
		}
		return fmt.Errorf("telegram source not found: %s", identifier)

	case "darkweb_onion":
		for i := range s.Config.Sources.DarkwebOnion {
			if s.Config.Sources.DarkwebOnion[i].URL == identifier || s.Config.Sources.DarkwebOnion[i].Name == identifier {
				if name, ok := data["name"].(string); ok && strings.TrimSpace(name) != "" {
					s.Config.Sources.DarkwebOnion[i].Name = strings.TrimSpace(name)
				}
				if u, ok := data["url"].(string); ok && strings.TrimSpace(u) != "" {
					if !strings.Contains(u, ".onion") {
						return fmt.Errorf("darkweb sources must use a .onion address")
					}
					s.Config.Sources.DarkwebOnion[i].URL = strings.TrimSpace(u)
				}
				if t, ok := data["type"].(string); ok && strings.TrimSpace(t) != "" {
					s.Config.Sources.DarkwebOnion[i].Type = strings.TrimSpace(t)
				}
				if tier != "" {
					s.Config.Sources.DarkwebOnion[i].ComplianceTier = tier
				}
				if en, ok := data["enabled"].(bool); ok {
					s.Config.Sources.DarkwebOnion[i].Enabled = en
				}
				return nil
			}
		}
		return fmt.Errorf("darkweb_onion source not found: %s", identifier)

	case "ransomware_tracker":
		for i := range s.Config.Sources.RansomwareTracker {
			if s.Config.Sources.RansomwareTracker[i].URL == identifier || s.Config.Sources.RansomwareTracker[i].Name == identifier {
				if name, ok := data["name"].(string); ok && strings.TrimSpace(name) != "" {
					s.Config.Sources.RansomwareTracker[i].Name = strings.TrimSpace(name)
				}
				if u, ok := data["url"].(string); ok && strings.TrimSpace(u) != "" {
					s.Config.Sources.RansomwareTracker[i].URL = strings.TrimSpace(u)
				}
				if t, ok := data["type"].(string); ok && strings.TrimSpace(t) != "" {
					s.Config.Sources.RansomwareTracker[i].Type = strings.TrimSpace(t)
				}
				if tier != "" {
					s.Config.Sources.RansomwareTracker[i].ComplianceTier = tier
				}
				if en, ok := data["enabled"].(bool); ok {
					s.Config.Sources.RansomwareTracker[i].Enabled = en
				}
				return nil
			}
		}
		return fmt.Errorf("ransomware_tracker source not found: %s", identifier)

	case "x_monitor":
		for i := range s.Config.Sources.XMonitor {
			item := &s.Config.Sources.XMonitor[i]
			if matchQuerySource(item, identifier) {
				if d, ok := data["directive"].(string); ok {
					item.Directive = strings.TrimSpace(d)
				}
				if q, ok := data["query"].(string); ok {
					item.Query = strings.TrimSpace(q)
				}
				if n, ok := data["name"].(string); ok {
					item.Name = strings.TrimSpace(n)
				}
				if tier != "" {
					item.ComplianceTier = tier
				}
				if en, ok := data["enabled"].(bool); ok {
					item.Enabled = en
				}
				return nil
			}
		}
		return fmt.Errorf("x_monitor source not found: %s", identifier)

	case "web_search":
		for i := range s.Config.Sources.WebSearch {
			item := &s.Config.Sources.WebSearch[i]
			if matchQuerySource(item, identifier) {
				if d, ok := data["directive"].(string); ok {
					item.Directive = strings.TrimSpace(d)
				}
				if q, ok := data["query"].(string); ok {
					item.Query = strings.TrimSpace(q)
				}
				if n, ok := data["name"].(string); ok {
					item.Name = strings.TrimSpace(n)
				}
				if tier != "" {
					item.ComplianceTier = tier
				}
				if en, ok := data["enabled"].(bool); ok {
					item.Enabled = en
				}
				return nil
			}
		}
		return fmt.Errorf("web_search source not found: %s", identifier)

	default:
		return fmt.Errorf("unsupported source type: %s", sourceType)
	}
}

func matchQuerySource(item *QuerySourceConfig, id string) bool {
	return item.Query == id || item.Directive == id || (item.Name != "" && item.Name == id)
}

func (s *SettingsManager) ToggleSource(sourceType, identifier string, enabled bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch sourceType {
	case "vendor_rss":
		for i := range s.Config.Sources.VendorRSS {
			if s.Config.Sources.VendorRSS[i].URL == identifier || s.Config.Sources.VendorRSS[i].Name == identifier {
				s.Config.Sources.VendorRSS[i].Enabled = enabled
				return true
			}
		}
	case "telegram":
		cleanCh := strings.TrimPrefix(identifier, "@")
		for i := range s.Config.Sources.Telegram {
			if s.Config.Sources.Telegram[i].Channel == cleanCh {
				s.Config.Sources.Telegram[i].Enabled = enabled
				return true
			}
		}
	case "darkweb_onion":
		for i := range s.Config.Sources.DarkwebOnion {
			if s.Config.Sources.DarkwebOnion[i].URL == identifier || s.Config.Sources.DarkwebOnion[i].Name == identifier {
				s.Config.Sources.DarkwebOnion[i].Enabled = enabled
				return true
			}
		}
	case "ransomware_tracker":
		for i := range s.Config.Sources.RansomwareTracker {
			if s.Config.Sources.RansomwareTracker[i].URL == identifier || s.Config.Sources.RansomwareTracker[i].Name == identifier {
				s.Config.Sources.RansomwareTracker[i].Enabled = enabled
				return true
			}
		}
	case "x_monitor":
		for i := range s.Config.Sources.XMonitor {
			if matchQuerySource(&s.Config.Sources.XMonitor[i], identifier) {
				s.Config.Sources.XMonitor[i].Enabled = enabled
				return true
			}
		}
	case "web_search":
		for i := range s.Config.Sources.WebSearch {
			if matchQuerySource(&s.Config.Sources.WebSearch[i], identifier) {
				s.Config.Sources.WebSearch[i].Enabled = enabled
				return true
			}
		}
	}
	return false
}

func (s *SettingsManager) DeleteSource(sourceType, identifier string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch sourceType {
	case "vendor_rss":
		orig := len(s.Config.Sources.VendorRSS)
		filtered := make([]FeedSourceConfig, 0, orig)
		for _, f := range s.Config.Sources.VendorRSS {
			if f.URL != identifier && f.Name != identifier {
				filtered = append(filtered, f)
			}
		}
		s.Config.Sources.VendorRSS = filtered
		return len(filtered) < orig
	case "telegram":
		cleanCh := strings.TrimPrefix(identifier, "@")
		orig := len(s.Config.Sources.Telegram)
		filtered := make([]TelegramSourceConfig, 0, orig)
		for _, c := range s.Config.Sources.Telegram {
			if c.Channel != cleanCh {
				filtered = append(filtered, c)
			}
		}
		s.Config.Sources.Telegram = filtered
		return len(filtered) < orig
	case "darkweb_onion":
		orig := len(s.Config.Sources.DarkwebOnion)
		filtered := make([]DarkwebSourceConfig, 0, orig)
		for _, d := range s.Config.Sources.DarkwebOnion {
			if d.URL != identifier && d.Name != identifier {
				filtered = append(filtered, d)
			}
		}
		s.Config.Sources.DarkwebOnion = filtered
		return len(filtered) < orig
	case "ransomware_tracker":
		orig := len(s.Config.Sources.RansomwareTracker)
		filtered := make([]RansomwareSourceConfig, 0, orig)
		for _, r := range s.Config.Sources.RansomwareTracker {
			if r.URL != identifier && r.Name != identifier {
				filtered = append(filtered, r)
			}
		}
		s.Config.Sources.RansomwareTracker = filtered
		return len(filtered) < orig
	case "x_monitor":
		orig := len(s.Config.Sources.XMonitor)
		filtered := make([]QuerySourceConfig, 0, orig)
		for _, q := range s.Config.Sources.XMonitor {
			if !matchQuerySource(&q, identifier) {
				filtered = append(filtered, q)
			}
		}
		s.Config.Sources.XMonitor = filtered
		return len(filtered) < orig
	case "web_search":
		orig := len(s.Config.Sources.WebSearch)
		filtered := make([]QuerySourceConfig, 0, orig)
		for _, q := range s.Config.Sources.WebSearch {
			if !matchQuerySource(&q, identifier) {
				filtered = append(filtered, q)
			}
		}
		s.Config.Sources.WebSearch = filtered
		return len(filtered) < orig
	}
	return false
}

func (s *SettingsManager) SetComplianceMode(mode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Config.Compliance.ApplyMode(mode)
	return nil
}

func (s *SettingsManager) ToggleComplianceTier(tier string, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Config.Compliance.Mode = ComplianceModeCustom
	switch tier {
	case TierCommercialReady:
		s.Config.Compliance.Tiers.CommercialReady = enabled
	case TierCommercialViaOfficialAPI:
		s.Config.Compliance.Tiers.CommercialViaOfficialAPI = enabled
	case TierToSRestricted:
		s.Config.Compliance.Tiers.ToSRestricted = enabled
	case TierDarkwebAccess:
		s.Config.Compliance.Tiers.DarkwebAccess = enabled
	default:
		return fmt.Errorf("unknown compliance tier: %s", tier)
	}
	return nil
}

func (s *SettingsManager) UpdateCompliance(mode string, tiers ComplianceTiersConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if mode != "" && mode != ComplianceModeCustom {
		s.Config.Compliance.ApplyMode(mode)
	} else {
		s.Config.Compliance.Mode = ComplianceModeCustom
		s.Config.Compliance.Tiers = tiers
	}
	return nil
}

func (s *SettingsManager) IsSourceActive(sourceType string, enabled bool, tier string) bool {
	if !enabled {
		return false
	}
	effectiveTier := tier
	if effectiveTier == "" {
		effectiveTier = GetDefaultTierForSource(sourceType, "")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Config.Compliance.IsTierEnabled(effectiveTier)
}

func (s *SettingsManager) GetComplianceSummary() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	counts := map[string]struct{ total, active int }{
		TierCommercialReady:          {0, 0},
		TierCommercialViaOfficialAPI: {0, 0},
		TierToSRestricted:            {0, 0},
		TierDarkwebAccess:            {0, 0},
	}

	checkItem := func(sourceType string, enabled bool, tier string) {
		t := tier
		if t == "" {
			t = GetDefaultTierForSource(sourceType, "")
		}
		c := counts[t]
		c.total++
		if enabled && s.Config.Compliance.IsTierEnabled(t) {
			c.active++
		}
		counts[t] = c
	}

	for _, feed := range s.Config.Sources.VendorRSS {
		checkItem("vendor_rss", feed.Enabled, feed.ComplianceTier)
	}
	for _, tg := range s.Config.Sources.Telegram {
		checkItem("telegram", tg.Enabled, tg.ComplianceTier)
	}
	for _, dw := range s.Config.Sources.DarkwebOnion {
		tier := dw.ComplianceTier
		if tier == "" {
			tier = GetDefaultTierForSource("darkweb_onion", dw.Type)
		}
		checkItem("darkweb_onion", dw.Enabled, tier)
	}
	for _, rw := range s.Config.Sources.RansomwareTracker {
		tier := rw.ComplianceTier
		if tier == "" {
			tier = GetDefaultTierForSource("ransomware_tracker", rw.Type)
		}
		checkItem("ransomware_tracker", rw.Enabled, tier)
	}
	for _, x := range s.Config.Sources.XMonitor {
		checkItem("x_monitor", x.Enabled, x.ComplianceTier)
	}
	for _, w := range s.Config.Sources.WebSearch {
		checkItem("web_search", w.Enabled, w.ComplianceTier)
	}

	breakdown := make(map[string]map[string]int)
	for k, v := range counts {
		breakdown[k] = map[string]int{
			"total":  v.total,
			"active": v.active,
		}
	}

	return map[string]interface{}{
		"mode":            s.Config.Compliance.Mode,
		"tiers":           s.Config.Compliance.Tiers,
		"tier_breakdown":  breakdown,
	}
}
