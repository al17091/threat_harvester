package harvesters

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"

	"github.com/dapt/information_harvester/backend/internal/config"
	"github.com/dapt/information_harvester/backend/internal/models"
)

type VendorRSSHarvester struct {
	client *http.Client
	parser *gofeed.Parser
}

func NewVendorRSSHarvester() *VendorRSSHarvester {
	return &VendorRSSHarvester{
		client: &http.Client{
			Timeout: 25 * time.Second,
		},
		parser: gofeed.NewParser(),
	}
}

func (h *VendorRSSHarvester) Name() string {
	return "Vendor & CERT RSS"
}

func (h *VendorRSSHarvester) SourceType() models.SourceType {
	return models.SourceTypeVendorRSS
}

func (h *VendorRSSHarvester) Harvest(ctx context.Context, since *time.Time) ([]models.ThreatItem, error) {
	cfg := config.GetSettings().GetConfig()
	var items []models.ThreatItem

	for _, feedCfg := range cfg.Sources.VendorRSS {
		tier := feedCfg.ComplianceTier
		if tier == "" {
			tier = config.TierCommercialReady
		}
		if !feedCfg.Enabled || !cfg.Compliance.IsTierEnabled(tier) {
			continue
		}

		log.Printf("[RSS] Checking feed: %s (%s)", feedCfg.Name, feedCfg.URL)

		// Support CISA KEV JSON catalog
		if strings.Contains(feedCfg.URL, "known_exploited_vulnerabilities") {
			kevItems, err := h.harvestCISAKEV(ctx, feedCfg, since)
			if err != nil {
				log.Printf("[RSS] Failed to fetch CISA KEV %s: %v", feedCfg.Name, err)
				continue
			}
			items = append(items, kevItems...)
			continue
		}

		// Support GitHub Security Advisories JSON API
		if strings.Contains(feedCfg.URL, "api.github.com/advisories") {
			ghsaItems, err := h.harvestGitHubAdvisories(ctx, feedCfg, since)
			if err != nil {
				log.Printf("[RSS] Failed to fetch GitHub Advisories %s: %v", feedCfg.Name, err)
				continue
			}
			items = append(items, ghsaItems...)
			continue
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedCfg.URL, nil)
		if err != nil {
			log.Printf("[RSS] Failed to create request for %s: %v", feedCfg.Name, err)
			continue
		}
		req.Header.Set("User-Agent", "ThreatHarvesterBot/1.0 (+https://github.com/dapt/information_harvester)")

		resp, err := h.client.Do(req)
		if err != nil {
			log.Printf("[RSS] Failed to fetch feed %s: %v", feedCfg.Name, err)
			continue
		}

		feed, err := h.parser.Parse(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			log.Printf("[RSS] Failed to parse feed %s: %v", feedCfg.Name, err)
			continue
		}

		for _, entry := range feed.Items {
			var pubDate *time.Time
			if entry.PublishedParsed != nil {
				t := entry.PublishedParsed.UTC()
				pubDate = &t
			} else if entry.UpdatedParsed != nil {
				t := entry.UpdatedParsed.UTC()
				pubDate = &t
			}

			if since != nil && pubDate != nil && pubDate.Before(*since) {
				continue
			}

			summary := entry.Description
			if summary == "" {
				summary = entry.Content
			}

			item := models.NewThreatItem(
				models.SourceTypeVendorRSS,
				feedCfg.Name,
				entry.Title,
				entry.Link,
				summary,
				entry.Content,
				pubDate,
				map[string]interface{}{"category": feedCfg.Category},
			)
			items = append(items, item)
		}
	}

	log.Printf("[RSS] VendorRSSHarvester collected %d items", len(items))
	return items, nil
}

func (h *VendorRSSHarvester) harvestCISAKEV(ctx context.Context, feedCfg config.FeedSourceConfig, since *time.Time) ([]models.ThreatItem, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedCfg.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ThreatHarvesterBot/1.0 (+https://github.com/dapt/information_harvester)")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var kevPayload struct {
		Count           int `json:"count"`
		Vulnerabilities []struct {
			CveID                      string `json:"cveID"`
			VendorProject              string `json:"vendorProject"`
			Product                    string `json:"product"`
			VulnerabilityName          string `json:"vulnerabilityName"`
			DateAdded                  string `json:"dateAdded"`
			ShortDescription           string `json:"shortDescription"`
			KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
			Notes                      string `json:"notes"`
		} `json:"vulnerabilities"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&kevPayload); err != nil {
		return nil, err
	}

	var items []models.ThreatItem
	total := len(kevPayload.Vulnerabilities)
	for i := total - 1; i >= 0 && len(items) < 30; i-- {
		v := kevPayload.Vulnerabilities[i]
		var pubDate *time.Time
		if v.DateAdded != "" {
			if t, err := time.Parse("2006-01-02", v.DateAdded); err == nil {
				utc := t.UTC()
				pubDate = &utc
			}
		}

		if since != nil && pubDate != nil && pubDate.Before(*since) {
			continue
		}

		title := fmt.Sprintf("[%s] %s %s - Known Exploited Vulnerability", v.CveID, v.VendorProject, v.Product)
		summary := fmt.Sprintf("Vulnerability: %s\nVendor: %s\nProduct: %s\nDate Added: %s\nRansomware Campaign: %s\nDescription: %s",
			v.VulnerabilityName, v.VendorProject, v.Product, v.DateAdded, v.KnownRansomwareCampaignUse, v.ShortDescription)

		link := v.Notes
		if link == "" || !strings.HasPrefix(link, "http") {
			link = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.CveID)
		}

		item := models.NewThreatItem(
			models.SourceTypeVendorRSS,
			feedCfg.Name,
			title,
			link,
			summary,
			v.ShortDescription,
			pubDate,
			map[string]interface{}{
				"cve":        v.CveID,
				"vendor":     v.VendorProject,
				"product":    v.Product,
				"ransomware": v.KnownRansomwareCampaignUse,
				"category":   feedCfg.Category,
			},
		)
		items = append(items, item)
	}

	log.Printf("[RSS] CISA KEV parsed %d items", len(items))
	return items, nil
}

func (h *VendorRSSHarvester) harvestGitHubAdvisories(ctx context.Context, feedCfg config.FeedSourceConfig, since *time.Time) ([]models.ThreatItem, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedCfg.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ThreatHarvesterBot/1.0 (+https://github.com/dapt/information_harvester)")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var ghsaList []struct {
		GhsaID      string `json:"ghsa_id"`
		CveID       string `json:"cve_id"`
		Summary     string `json:"summary"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		PublishedAt string `json:"published_at"`
		HtmlURL     string `json:"html_url"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghsaList); err != nil {
		return nil, err
	}

	var items []models.ThreatItem
	for _, a := range ghsaList {
		var pubDate *time.Time
		if a.PublishedAt != "" {
			if t, err := time.Parse(time.RFC3339, a.PublishedAt); err == nil {
				utc := t.UTC()
				pubDate = &utc
			}
		}

		if since != nil && pubDate != nil && pubDate.Before(*since) {
			continue
		}

		title := fmt.Sprintf("[%s] %s", a.GhsaID, a.Summary)
		if a.CveID != "" {
			title = fmt.Sprintf("[%s/%s] %s", a.GhsaID, a.CveID, a.Summary)
		}

		summary := fmt.Sprintf("GHSA: %s\nCVE: %s\nSeverity: %s\nSummary: %s\n\n%s",
			a.GhsaID, a.CveID, a.Severity, a.Summary, a.Description)

		item := models.NewThreatItem(
			models.SourceTypeVendorRSS,
			feedCfg.Name,
			title,
			a.HtmlURL,
			summary,
			a.Description,
			pubDate,
			map[string]interface{}{
				"ghsa_id":  a.GhsaID,
				"cve_id":   a.CveID,
				"severity": a.Severity,
				"category": feedCfg.Category,
			},
		)
		items = append(items, item)
	}

	log.Printf("[RSS] GitHub Advisories parsed %d items", len(items))
	return items, nil
}

func (h *VendorRSSHarvester) TestConnection(ctx context.Context) bool {
	cfg := config.GetSettings().GetConfig()
	for i, feed := range cfg.Sources.VendorRSS {
		if i >= 2 {
			break
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, feed.URL, nil)
		if err != nil {
			continue
		}
		resp, err := h.client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode < 400 {
				return true
			}
		}
	}
	return false
}
