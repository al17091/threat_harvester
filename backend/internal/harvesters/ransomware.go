package harvesters

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/al17091/threat_harvester/backend/internal/config"
	"github.com/al17091/threat_harvester/backend/internal/models"
	"github.com/mmcdole/gofeed"
)

type RansomwareTrackerHarvester struct {
	client *http.Client
	parser *gofeed.Parser
}

func NewRansomwareTrackerHarvester() *RansomwareTrackerHarvester {
	return &RansomwareTrackerHarvester{
		client: &http.Client{
			Timeout: 25 * time.Second,
		},
		parser: gofeed.NewParser(),
	}
}

func (h *RansomwareTrackerHarvester) Name() string {
	return "RansomwareTracker"
}

func (h *RansomwareTrackerHarvester) SourceType() models.SourceType {
	return models.SourceTypeRansomwareTracker
}

func (h *RansomwareTrackerHarvester) TestConnection(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.ransomlook.io/api/recent", nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "ThreatHarvesterBot/1.0 (+https://github.com/al17091/threat_harvester)")

	resp, err := h.client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode < 500
}

func (h *RansomwareTrackerHarvester) Harvest(ctx context.Context, since *time.Time) ([]models.ThreatItem, error) {
	cfg := config.GetSettings().GetConfig()
	var items []models.ThreatItem

	for _, target := range cfg.Sources.RansomwareTracker {
		tier := target.ComplianceTier
		if tier == "" {
			if target.Type == "api" {
				tier = config.TierCommercialViaOfficialAPI
			} else {
				tier = config.TierCommercialReady
			}
		}
		if !target.Enabled || !cfg.Compliance.IsTierEnabled(tier) {
			continue
		}

		log.Printf("[RansomwareTracker] Checking target: %s (%s)", target.Name, target.URL)

		if target.Type == "rss" {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

			resp, err := h.client.Do(req)
			if err != nil {
				log.Printf("[RansomwareTracker] Failed to fetch RSS %s: %v", target.Name, err)
				continue
			}

			if resp.StatusCode != http.StatusOK {
				log.Printf("[RansomwareTracker] Target %s returned HTTP %d, skipping", target.Name, resp.StatusCode)
				_ = resp.Body.Close()
				continue
			}

			feed, err := h.parser.Parse(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				log.Printf("[RansomwareTracker] Failed to parse RSS %s: %v", target.Name, err)
				continue
			}

			for _, entry := range feed.Items {
				var pubDate *time.Time
				if entry.PublishedParsed != nil {
					t := entry.PublishedParsed.UTC()
					pubDate = &t
				}

				if since != nil && pubDate != nil && pubDate.Before(*since) {
					continue
				}

				summary := entry.Description
				if summary == "" {
					summary = entry.Content
				}

				link := entry.Link
				if link == "" {
					link = target.URL
				}

				item := models.NewThreatItem(
					models.SourceTypeRansomwareTracker,
					target.Name,
					entry.Title,
					link,
					summary,
					entry.Content,
					pubDate,
					map[string]interface{}{"type": "rss", "is_ransomware": true},
				)
				items = append(items, item)
			}

		} else if target.Type == "api" {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

			resp, err := h.client.Do(req)
			if err != nil {
				log.Printf("[RansomwareTracker] Failed to fetch API %s: %v", target.Name, err)
				continue
			}

			if resp.StatusCode != http.StatusOK {
				log.Printf("[RansomwareTracker] Target %s returned HTTP %d, skipping", target.Name, resp.StatusCode)
				_ = resp.Body.Close()
				continue
			}

			var posts []map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&posts)
			_ = resp.Body.Close()
			if err == nil {
					for i, post := range posts {
						if i >= 30 {
							break
						}
						victimName, _ := post["victim"].(string)
						if victimName == "" {
							victimName, _ = post["post_title"].(string)
						}
						groupName, _ := post["group_name"].(string)
						if groupName == "" {
							groupName = "Unknown Group"
						}
						description, _ := post["description"].(string)
						country, _ := post["country"].(string)
						permalink, _ := post["permalink"].(string)
						if permalink == "" {
							permalink, _ = post["website"].(string)
						}
						if permalink == "" {
							if groupName != "" && groupName != "Unknown Group" {
								permalink = fmt.Sprintf("https://www.ransomlook.io/group/%s", url.PathEscape(groupName))
							} else if target.URL != "" {
								permalink = target.URL
							} else {
								permalink = "https://www.ransomlook.io/recent"
							}
						}

						var pubDate *time.Time
						if discStr, ok := post["discovered"].(string); ok && discStr != "" {
							layouts := []string{
								"2006-01-02 15:04:05.999999",
								"2006-01-02 15:04:05",
								"2006-01-02T15:04:05Z07:00",
								"2006-01-02",
							}
							for _, layout := range layouts {
								if t, err := time.Parse(layout, strings.TrimSpace(discStr)); err == nil {
									utc := t.UTC()
									pubDate = &utc
									break
								}
							}
						}

						if since != nil && pubDate != nil && pubDate.Before(*since) {
							continue
						}

						upperVictim := strings.ToUpper(victimName)
						upperCountry := strings.ToUpper(country)
						upperDesc := strings.ToUpper(description)
						isJapan := upperCountry == "JP" || strings.Contains(upperVictim, "JAPAN") || strings.Contains(upperDesc, "JAPAN")

						countrySuffix := ""
						if country != "" {
							countrySuffix = fmt.Sprintf(" [%s]", country)
						}
						title := fmt.Sprintf("%s Ransomware: %s Listed on Data Leak Site%s", groupName, victimName, countrySuffix)
						summaryText := fmt.Sprintf("The %s ransomware group published %s on its dark web leak site.", groupName, victimName)
						if strings.TrimSpace(description) != "" {
							summaryText += fmt.Sprintf(" Details: %s", strings.TrimSpace(description))
						}
						summary := summaryText

						item := models.NewThreatItem(
							models.SourceTypeRansomwareTracker,
							fmt.Sprintf("%s (%s)", target.Name, groupName),
							title,
							permalink,
							summary,
							description,
							pubDate,
							map[string]interface{}{
								"victim":        victimName,
								"group":         groupName,
								"country":       country,
								"is_japan":      isJapan,
								"is_ransomware": true,
							},
						)
						items = append(items, item)
					}
				}
			}
		}

	log.Printf("[RansomwareTracker] Collected %d items", len(items))
	return items, nil
}
