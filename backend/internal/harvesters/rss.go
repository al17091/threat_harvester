package harvesters

import (
	"context"
	"log"
	"net/http"
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
		if !feedCfg.Enabled {
			continue
		}

		log.Printf("[RSS] Checking feed: %s (%s)", feedCfg.Name, feedCfg.URL)
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
