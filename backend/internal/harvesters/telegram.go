package harvesters

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"

	"github.com/al17091/threat_harvester/backend/internal/config"
	"github.com/al17091/threat_harvester/backend/internal/models"
)

type TelegramHarvester struct {
	client *http.Client
}

func NewTelegramHarvester() *TelegramHarvester {
	return &TelegramHarvester{
		client: &http.Client{
			Timeout: 25 * time.Second,
		},
	}
}

func (h *TelegramHarvester) Name() string {
	return "Telegram Channel Monitor"
}

func (h *TelegramHarvester) SourceType() models.SourceType {
	return models.SourceTypeTelegram
}

func (h *TelegramHarvester) Harvest(ctx context.Context, since *time.Time) ([]models.ThreatItem, error) {
	cfg := config.GetSettings().GetConfig()
	var items []models.ThreatItem

	for _, ch := range cfg.Sources.Telegram {
		tier := ch.ComplianceTier
		if tier == "" {
			tier = config.TierToSRestricted
		}
		if !ch.Enabled || !cfg.Compliance.IsTierEnabled(tier) {
			continue
		}

		cleanCh := strings.TrimPrefix(ch.Channel, "@")
		url := fmt.Sprintf("https://t.me/s/%s", cleanCh)
		log.Printf("[Telegram] Checking channel: @%s (%s)", cleanCh, url)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

		resp, err := h.client.Do(req)
		if err != nil {
			log.Printf("[Telegram] Failed to fetch channel @%s: %v", cleanCh, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			log.Printf("[Telegram] Channel @%s returned HTTP status %d", cleanCh, resp.StatusCode)
			continue
		}

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			log.Printf("[Telegram] Failed to parse HTML for @%s: %v", cleanCh, err)
			continue
		}

		doc.Find("div.tgme_widget_message").Each(func(i int, s *goquery.Selection) {
			textDiv := s.Find("div.tgme_widget_message_text")
			if textDiv.Length() == 0 {
				return
			}
			text := strings.TrimSpace(textDiv.Text())
			if len(text) < 20 {
				return
			}

			// Timestamp
			var pubDate *time.Time
			timeTag := s.Find("time")
			if dtStr, exists := timeTag.Attr("datetime"); exists && dtStr != "" {
				if t, err := time.Parse(time.RFC3339, dtStr); err == nil {
					utcTime := t.UTC()
					pubDate = &utcTime
				}
			}

			if since != nil && pubDate != nil && pubDate.Before(*since) {
				return
			}

			// Permlink
			msgLink := url
			linkTag := s.Find("a.tgme_widget_message_date")
			if href, exists := linkTag.Attr("href"); exists && href != "" {
				msgLink = href
			}

			// Title from first line
			lines := strings.Split(text, "\n")
			firstLine := strings.TrimSpace(lines[0])
			if len([]rune(firstLine)) > 80 {
				firstLine = models.TruncateRunes(firstLine, 80) + "..."
			}
			title := fmt.Sprintf("[@%s] %s", cleanCh, firstLine)

			summary := models.TruncateRunes(text, 1000)

			// Extract links referenced in the Telegram message
			var targetURLs []string
			textDiv.Find("a").Each(func(_ int, a *goquery.Selection) {
				if href, ok := a.Attr("href"); ok {
					targetURLs = append(targetURLs, href)
				}
			})
			s.Find("a.tgme_widget_message_link_preview").Each(func(_ int, a *goquery.Selection) {
				if href, ok := a.Attr("href"); ok {
					targetURLs = append(targetURLs, href)
				}
			})
			targetURLs = append(targetURLs, ExtractURLsFromText(text)...)

			rawContent := text
			meta := map[string]interface{}{"channel": cleanCh}

			if len(targetURLs) > 0 {
				enrichedScraped, visitedURLs := FollowAndScrapeLinkedArticles(ctx, targetURLs, 2)
				if enrichedScraped != "" {
					rawContent = text + "\n\n" + enrichedScraped
				}
				if len(visitedURLs) > 0 {
					meta["linked_urls"] = visitedURLs
					log.Printf("[Telegram] @%s: recursively followed %d links (%d chars)", cleanCh, len(visitedURLs), len([]rune(enrichedScraped)))
				}
			}

			item := models.NewThreatItem(
				models.SourceTypeTelegram,
				fmt.Sprintf("Telegram:@%s", cleanCh),
				title,
				msgLink,
				summary,
				rawContent,
				pubDate,
				meta,
			)
			items = append(items, item)
		})
	}

	log.Printf("[Telegram] TelegramHarvester collected %d items", len(items))
	return items, nil
}

func (h *TelegramHarvester) TestConnection(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://t.me/s/telegram", nil)
	if err != nil {
		return false
	}
	resp, err := h.client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	return false
}
