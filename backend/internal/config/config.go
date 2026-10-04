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

type FeedSourceConfig struct {
	Name     string `yaml:"name" json:"name"`
	URL      string `yaml:"url" json:"url"`
	Category string `yaml:"category" json:"category"`
	Enabled  bool   `yaml:"enabled" json:"enabled"`
}

type TelegramSourceConfig struct {
	Channel string `yaml:"channel" json:"channel"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
}

type DarkwebSourceConfig struct {
	Name    string `yaml:"name" json:"name"`
	URL     string `yaml:"url" json:"url"`
	Type    string `yaml:"type" json:"type"` // "api", "rss", or "onion"
	Enabled bool   `yaml:"enabled" json:"enabled"`
}

type QuerySourceConfig struct {
	Query   string `yaml:"query" json:"query"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
}

type SourcesConfig struct {
	VendorRSS    []FeedSourceConfig     `yaml:"vendor_rss" json:"vendor_rss"`
	Telegram     []TelegramSourceConfig `yaml:"telegram" json:"telegram"`
	DarkwebOnion []DarkwebSourceConfig  `yaml:"darkweb_onion" json:"darkweb_onion"`
	XMonitor     []QuerySourceConfig    `yaml:"x_monitor" json:"x_monitor"`
	WebSearch    []QuerySourceConfig    `yaml:"web_search" json:"web_search"`
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
	Version  string         `yaml:"version" json:"version"`
	Database DatabaseConfig `yaml:"database" json:"database"`
	AI       AiConfig       `yaml:"ai" json:"ai"`
	Sinks    SinksConfig    `yaml:"sinks" json:"sinks"`
	Network  NetworkConfig  `yaml:"network" json:"network"`
	Pipeline PipelineConfig `yaml:"pipeline" json:"pipeline"`
	Sources  SourcesConfig  `yaml:"sources" json:"sources"`
}

func DefaultConfig() AppConfig {
	return AppConfig{
		Version: "1.0",
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
				{Name: "JPCERT/CC 注意喚起", URL: "https://www.jpcert.or.jp/rss/jpcert.rdf", Category: "jp_cert", Enabled: true},
				{Name: "IPA 重要なセキュリティ情報", URL: "https://www.ipa.go.jp/security/rss/alert.rdf", Category: "jp_cert", Enabled: true},
				{Name: "ScanNetSecurity", URL: "https://scan.netsecurity.ne.jp/rss/index.rdf", Category: "jp_news", Enabled: true},
				{Name: "Security Next", URL: "https://www.security-next.com/feed", Category: "jp_news", Enabled: true},
				{Name: "BleepingComputer", URL: "https://www.bleepingcomputer.com/feed/", Category: "global_news", Enabled: true},
				{Name: "The Hacker News", URL: "https://thehackernews.com/rss.xml", Category: "global_news", Enabled: true},
				{Name: "CISA Alerts", URL: "https://www.cisa.gov/uscert/ncas/alerts.xml", Category: "global_cert", Enabled: true},
			},
			Telegram: []TelegramSourceConfig{
				{Channel: "redabyss_cti", Enabled: true},
				{Channel: "malware_traffic", Enabled: true},
				{Channel: "ransomfeed", Enabled: true},
				{Channel: "cybersecurity_news_hub", Enabled: true},
			},
			DarkwebOnion: []DarkwebSourceConfig{
				{Name: "Ransomlook Tracker", URL: "https://www.ransomlook.io/api/recent", Type: "api", Enabled: true},
				{Name: "RansomFeed Aggregator", URL: "https://ransomfeed.it/news.rss", Type: "rss", Enabled: true},
			},
			XMonitor: []QuerySourceConfig{
				{Query: "cyber attack Japan victim site:x.com OR site:twitter.com", Enabled: true},
				{Query: "ランサムウェア 日本 標的 site:x.com OR site:twitter.com", Enabled: true},
				{Query: "JPCERT CyberThreat site:x.com OR site:twitter.com", Enabled: true},
			},
			WebSearch: []QuerySourceConfig{
				{Query: "最新 サイバー攻撃 日本 企業 組織 被害 ランサムウェア", Enabled: true},
				{Query: "Japan targeted cyber attack data breach ransomware recent", Enabled: true},
				{Query: "セキュリティインシデント 漏洩 日本 国内 最近", Enabled: true},
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
		s.Config.Sources.VendorRSS = append(s.Config.Sources.VendorRSS, FeedSourceConfig{
			Name:     name,
			URL:      url,
			Category: category,
			Enabled:  true,
		})
	case "telegram":
		ch, _ := data["channel"].(string)
		if ch == "" {
			return fmt.Errorf("channel is required")
		}
		s.Config.Sources.Telegram = append(s.Config.Sources.Telegram, TelegramSourceConfig{
			Channel: strings.TrimPrefix(ch, "@"),
			Enabled: true,
		})
	case "darkweb_onion":
		name, _ := data["name"].(string)
		url, _ := data["url"].(string)
		t, _ := data["type"].(string)
		if t == "" {
			t = "rss"
		}
		if name == "" || url == "" {
			return fmt.Errorf("name and url are required")
		}
		s.Config.Sources.DarkwebOnion = append(s.Config.Sources.DarkwebOnion, DarkwebSourceConfig{
			Name:    name,
			URL:     url,
			Type:    t,
			Enabled: true,
		})
	case "x_monitor":
		q, _ := data["query"].(string)
		if q == "" {
			return fmt.Errorf("query is required")
		}
		s.Config.Sources.XMonitor = append(s.Config.Sources.XMonitor, QuerySourceConfig{
			Query:   q,
			Enabled: true,
		})
	case "web_search":
		q, _ := data["query"].(string)
		if q == "" {
			return fmt.Errorf("query is required")
		}
		s.Config.Sources.WebSearch = append(s.Config.Sources.WebSearch, QuerySourceConfig{
			Query:   q,
			Enabled: true,
		})
	default:
		return fmt.Errorf("unsupported source type: %s", sourceType)
	}
	return nil
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
	case "x_monitor":
		for i := range s.Config.Sources.XMonitor {
			if s.Config.Sources.XMonitor[i].Query == identifier {
				s.Config.Sources.XMonitor[i].Enabled = enabled
				return true
			}
		}
	case "web_search":
		for i := range s.Config.Sources.WebSearch {
			if s.Config.Sources.WebSearch[i].Query == identifier {
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
	case "x_monitor":
		orig := len(s.Config.Sources.XMonitor)
		filtered := make([]QuerySourceConfig, 0, orig)
		for _, q := range s.Config.Sources.XMonitor {
			if q.Query != identifier {
				filtered = append(filtered, q)
			}
		}
		s.Config.Sources.XMonitor = filtered
		return len(filtered) < orig
	case "web_search":
		orig := len(s.Config.Sources.WebSearch)
		filtered := make([]QuerySourceConfig, 0, orig)
		for _, q := range s.Config.Sources.WebSearch {
			if q.Query != identifier {
				filtered = append(filtered, q)
			}
		}
		s.Config.Sources.WebSearch = filtered
		return len(filtered) < orig
	}
	return false
}
