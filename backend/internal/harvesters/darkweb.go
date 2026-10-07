package harvesters

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mmcdole/gofeed"
	"golang.org/x/net/proxy"

	"github.com/dapt/information_harvester/backend/internal/config"
	"github.com/dapt/information_harvester/backend/internal/models"
)

type DarkwebOnionHarvester struct {
	parser *gofeed.Parser
}

func NewDarkwebOnionHarvester() *DarkwebOnionHarvester {
	return &DarkwebOnionHarvester{
		parser: gofeed.NewParser(),
	}
}

func (h *DarkwebOnionHarvester) Name() string {
	return "Dark Web (.onion) & Ransomware DLS"
}

func (h *DarkwebOnionHarvester) SourceType() models.SourceType {
	return models.SourceTypeDarkwebOnion
}

func (h *DarkwebOnionHarvester) getTorClient(proxyURLStr string) *http.Client {
	timeout := 25 * time.Second
	if proxyURLStr == "" {
		proxyURLStr = "socks5h://127.0.0.1:9050"
	}

	u, err := url.Parse(proxyURLStr)
	host := proxyURLStr
	if err == nil && u.Host != "" {
		host = u.Host
	} else {
		host = strings.TrimPrefix(proxyURLStr, "socks5h://")
		host = strings.TrimPrefix(host, "socks5://")
	}

	dialer, err := proxy.SOCKS5("tcp", host, nil, proxy.Direct)
	if err != nil {
		return &http.Client{Timeout: timeout}
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		},
		DisableKeepAlives: true,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}
}

func (h *DarkwebOnionHarvester) TestConnection(ctx context.Context) bool {
	cfg := config.GetSettings().GetConfig()
	client := h.getTorClient(cfg.Network.TorProxyURL)
	testCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(testCtx, http.MethodGet, "https://check.torproject.org/api/ip", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var data struct {
			IsTor bool   `json:"IsTor"`
			IP    string `json:"IP"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err == nil {
			return data.IsTor
		}
	}
	return false
}

func (h *DarkwebOnionHarvester) Harvest(ctx context.Context, since *time.Time) ([]models.ThreatItem, error) {
	cfg := config.GetSettings().GetConfig()
	torClient := h.getTorClient(cfg.Network.TorProxyURL)
	directClient := &http.Client{Timeout: 25 * time.Second}

	var items []models.ThreatItem

	for _, target := range cfg.Sources.DarkwebOnion {
		tier := target.ComplianceTier
		if tier == "" {
			if target.Type == "api" {
				tier = config.TierCommercialViaOfficialAPI
			} else {
				tier = config.TierDarkwebAccess
			}
		}
		if !target.Enabled || !cfg.Compliance.IsTierEnabled(tier) {
			continue
		}

		log.Printf("[DarkWeb] Checking target: %s (%s)", target.Name, target.URL)
		isOnion := strings.Contains(target.URL, ".onion")
		client := directClient
		if isOnion {
			client = torClient
		}

		if target.Type == "rss" {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "ThreatHarvesterBot/1.0 (+https://github.com/dapt/information_harvester)")

			resp, err := client.Do(req)
			if err != nil {
				// Fallback to tor client if direct failed on clearnet
				if !isOnion {
					resp, err = torClient.Do(req)
				}
			}
			if err != nil {
				log.Printf("[DarkWeb] Failed to fetch RSS %s: %v", target.Name, err)
				continue
			}

			feed, err := h.parser.Parse(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				log.Printf("[DarkWeb] Failed to parse RSS %s: %v", target.Name, err)
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
					models.SourceTypeDarkwebOnion,
					target.Name,
					entry.Title,
					link,
					summary,
					entry.Content,
					pubDate,
					map[string]interface{}{"is_onion": isOnion, "type": "rss"},
				)
				items = append(items, item)
			}

		} else if target.Type == "api" {
			// JSON API (e.g. Ransomlook API)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "ThreatHarvesterBot/1.0 (+https://github.com/dapt/information_harvester)")

			resp, err := client.Do(req)
			if err != nil && !isOnion {
				resp, err = torClient.Do(req)
			}
			if err != nil {
				log.Printf("[DarkWeb] Failed to fetch API %s: %v", target.Name, err)
				continue
			}

			if resp.StatusCode == http.StatusOK {
				var posts []map[string]interface{}
				if err := json.NewDecoder(resp.Body).Decode(&posts); err == nil {
					_ = resp.Body.Close()
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

						title := fmt.Sprintf("[%s DLS] Victim: %s (%s)", groupName, victimName, country)
						summary := fmt.Sprintf("Group: %s\nVictim: %s\nCountry: %s\nDetails: %s", groupName, victimName, country, description)

						item := models.NewThreatItem(
							models.SourceTypeDarkwebOnion,
							fmt.Sprintf("%s (%s)", target.Name, groupName),
							title,
							permalink,
							summary,
							description,
							pubDate,
							map[string]interface{}{
								"victim":   victimName,
								"group":    groupName,
								"country":  country,
								"is_japan": isJapan,
							},
						)
						items = append(items, item)
					}
				} else {
					_ = resp.Body.Close()
				}
			} else {
				_ = resp.Body.Close()
			}
		}
	}

	log.Printf("[DarkWeb] DarkwebOnionHarvester collected %d items", len(items))
	return items, nil
}
