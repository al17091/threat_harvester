package harvesters

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"

	"github.com/dapt/information_harvester/backend/internal/config"
	"github.com/dapt/information_harvester/backend/internal/models"
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
		if !ch.Enabled {
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
			if len(firstLine) > 80 {
				firstLine = firstLine[:80] + "..."
			}
			title := fmt.Sprintf("[@%s] %s", cleanCh, firstLine)

			summary := text
			if len(summary) > 1000 {
				summary = summary[:1000]
			}

			item := models.NewThreatItem(
				models.SourceTypeTelegram,
				fmt.Sprintf("Telegram:@%s", cleanCh),
				title,
				msgLink,
				summary,
				text,
				pubDate,
				map[string]interface{}{"channel": cleanCh},
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
