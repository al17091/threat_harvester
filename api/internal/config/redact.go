package config

import (
	"net/url"
	"strings"
)

// RedactedSecret replaces credential values in anything returned to API clients.
const RedactedSecret = "********"

const (
	redactedURL     = "[redacted]"
	redactedWebhook = "https://...[masked]"
)

// RedactURL removes credentials, query parameters and fragments from a URL or connection string.
// Values that cannot be reliably separated from their credentials are replaced entirely.
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		// A bare path or host:port is safe; "key=value" DSNs and "user:pass@host" are not.
		if strings.ContainsAny(raw, "@=") {
			return redactedURL
		}
		return raw
	}

	u, err := url.Parse(raw)
	// An "@" without parsed user info means an unescaped password was read as host or path.
	if err != nil || (u.User == nil && strings.Contains(raw, "@")) {
		return redactedURL
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.RawFragment = ""
	if cleaned := u.String(); !strings.Contains(cleaned, "@") {
		return cleaned
	}
	return redactedURL
}

func maskValue(value, mask string) string {
	if value == "" {
		return ""
	}
	return mask
}

// Redacted returns a copy of the configuration without credentials. Source definitions are left
// untouched because the dashboard sends them back when they are edited.
func (c AppConfig) Redacted() AppConfig {
	c.Database.URL = RedactURL(c.Database.URL)
	c.Database.Password = maskValue(c.Database.Password, RedactedSecret)

	c.AI.Endpoint = RedactURL(c.AI.Endpoint)
	c.AI.APIKey = maskValue(c.AI.APIKey, RedactedSecret)
	c.AI.GeminiAPIKey = maskValue(c.AI.GeminiAPIKey, RedactedSecret)
	c.AI.Escalation.GeminiAPIKey = maskValue(c.AI.Escalation.GeminiAPIKey, RedactedSecret)

	// The secret part of a webhook URL is its path, so nothing of it is kept.
	c.Sinks.Discord.WebhookURL = maskValue(c.Sinks.Discord.WebhookURL, redactedWebhook)
	c.Sinks.Slack.WebhookURL = maskValue(c.Sinks.Slack.WebhookURL, redactedWebhook)
	c.Sinks.GenericWebhook.WebhookURL = maskValue(c.Sinks.GenericWebhook.WebhookURL, redactedWebhook)
	c.Sinks.Notion.APIKey = maskValue(c.Sinks.Notion.APIKey, RedactedSecret)

	c.Network.TorProxyURL = RedactURL(c.Network.TorProxyURL)
	c.Network.HTTPProxy = RedactURL(c.Network.HTTPProxy)
	c.Scraper.BrowserlessURL = RedactURL(c.Scraper.BrowserlessURL)
	return c
}
