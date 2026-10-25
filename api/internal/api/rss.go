package api

import (
	"encoding/xml"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/storage"
)

type rssFeed struct {
	XMLName xml.Name   `xml:"rss"`
	Version string     `xml:"version,attr"`
	AtomNS  string     `xml:"xmlns:atom,attr"`
	Channel rssChannel `xml:"channel"`
}

type rssChannel struct {
	Title         string    `xml:"title"`
	Link          string    `xml:"link"`
	Description   string    `xml:"description"`
	Language      string    `xml:"language"`
	LastBuildDate string    `xml:"lastBuildDate"`
	Generator     string    `xml:"generator"`
	AtomLink      atomLink  `xml:"atom:link"`
	Items         []rssItem `xml:"item"`
}

type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
	Type string `xml:"type,attr"`
}

type rssItem struct {
	Title       string        `xml:"title"`
	Link        string        `xml:"link"`
	GUID        rssGUID       `xml:"guid"`
	PubDate     string        `xml:"pubDate"`
	Categories  []string      `xml:"category"`
	Description rssCDataField `xml:"description"`
}

type rssGUID struct {
	IsPermaLink bool   `xml:"isPermaLink,attr"`
	Value       string `xml:",chardata"`
}

type rssCDataField struct {
	Value string `xml:",cdata"`
}

func (s *Server) handleRSSFeed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()

	lang := strings.ToLower(strings.TrimSpace(q.Get("lang")))
	if lang == "" {
		lang = strings.ToLower(strings.TrimSpace(chi.URLParam(r, "lang")))
	}
	if lang == "" {
		cfg := config.GetSettings().GetConfig()
		if cfg.Pipeline.NotifyLanguage != "" {
			lang = cfg.Pipeline.NotifyLanguage
		} else {
			lang = "en"
		}
	}
	if lang != "ja" && lang != "en" {
		lang = "en"
	}

	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	japanOnly := q.Get("japan_only") == "true"
	if lang == "ja" && q.Get("japan_only") == "" {
		japanOnly = true
	}

	filter := storage.HistoryFilter{
		Limit:     limit,
		Offset:    0,
		JapanOnly: japanOnly,
		Severity:  q.Get("severity"),
		Search:    q.Get("search"),
	}

	incidents, err := s.store.GetIncidents(ctx, filter)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to retrieve incidents for RSS: %v", err), http.StatusInternalServerError)
		return
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost:8000"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, host)
	feedURL := fmt.Sprintf("%s%s", baseURL, r.URL.RequestURI())

	items := make([]rssItem, 0, len(incidents))
	for _, inc := range incidents {
		id, _ := inc["id"].(string)
		titleEn, _ := inc["title"].(string)
		titleJa, _ := inc["title_ja"].(string)
		victimOrg, _ := inc["victim_org"].(string)
		victimOrgEn, _ := inc["victim_org_en"].(string)
		victimOrgJa, _ := inc["victim_org_ja"].(string)
		sev, _ := inc["severity"].(string)
		jrel, _ := inc["japan_relevance"].(string)
		attackType, _ := inc["attack_type"].(string)
		primURL, _ := inc["primary_url"].(string)
		summaryEn, _ := inc["summary"].(string)
		summaryJa, _ := inc["summary_ja"].(string)
		impactEn, _ := inc["impact_analysis"].(string)
		impactJa, _ := inc["impact_analysis_ja"].(string)
		lastSeen, _ := inc["last_seen_at"].(string)
		firstSeen, _ := inc["first_seen_at"].(string)
		reportCount, _ := inc["report_count"].(int)

		if primURL == "" {
			primURL = fmt.Sprintf("%s/api/incidents/%s", baseURL, id)
		}

		itemPubDate := time.Now().Format(time.RFC1123Z)
		if t, err := time.Parse(time.RFC3339, lastSeen); err == nil {
			itemPubDate = t.Format(time.RFC1123Z)
		}

		// Categories
		var categories []string
		if sev != "" {
			categories = append(categories, sev)
		}
		if jrel != "" {
			categories = append(categories, fmt.Sprintf("Relevance:%s", jrel))
		}
		if attackType != "" {
			categories = append(categories, attackType)
		}

		// Language-specific selection
		var itemTitle, displayVictim, displaySummary, displayImpact string
		if lang == "ja" {
			itemTitleText := titleJa
			if itemTitleText == "" || (!isJapaneseText(itemTitleText) && isJapaneseText(titleEn)) {
				itemTitleText = titleEn
			}
			displayVictim = victimOrgJa
			if displayVictim == "" {
				displayVictim = victimOrg
			}
			if displayVictim == "" {
				displayVictim = victimOrgEn
			}
			if displayVictim != "" && displayVictim != "Unknown" {
				itemTitle = fmt.Sprintf("[%s] [%s] %s: %s", sev, jrel, displayVictim, itemTitleText)
			} else {
				itemTitle = fmt.Sprintf("[%s] [%s] %s", sev, jrel, itemTitleText)
			}

			if isJapaneseText(summaryJa) {
				displaySummary = summaryJa
			} else if isJapaneseText(summaryEn) {
				displaySummary = summaryEn
			} else {
				displaySummary = summaryJa
				if displaySummary == "" {
					displaySummary = summaryEn
				}
			}

			if isJapaneseText(impactJa) {
				displayImpact = impactJa
			} else if isJapaneseText(impactEn) {
				displayImpact = impactEn
			} else {
				displayImpact = impactJa
				if displayImpact == "" {
					displayImpact = impactEn
				}
			}
		} else {
			itemTitleText := titleEn
			if itemTitleText == "" || (isJapaneseText(itemTitleText) && !isJapaneseText(titleJa) && titleJa != "") {
				itemTitleText = titleJa
			}
			displayVictim = victimOrgEn
			if displayVictim == "" {
				displayVictim = victimOrg
			}
			if displayVictim == "" {
				displayVictim = victimOrgJa
			}
			if displayVictim != "" && displayVictim != "Unknown" {
				itemTitle = fmt.Sprintf("[%s] [%s] %s: %s", sev, jrel, displayVictim, itemTitleText)
			} else {
				itemTitle = fmt.Sprintf("[%s] [%s] %s", sev, jrel, itemTitleText)
			}

			if summaryEn != "" && !isJapaneseText(summaryEn) {
				displaySummary = summaryEn
			} else if summaryJa != "" && !isJapaneseText(summaryJa) {
				displaySummary = summaryJa
			} else {
				displaySummary = summaryEn
				if displaySummary == "" {
					displaySummary = summaryJa
				}
			}

			if impactEn != "" && !isJapaneseText(impactEn) {
				displayImpact = impactEn
			} else if impactJa != "" && !isJapaneseText(impactJa) {
				displayImpact = impactJa
			} else {
				displayImpact = impactEn
				if displayImpact == "" {
					displayImpact = impactJa
				}
			}
		}

		// Format HTML description
		var descBuilder strings.Builder
		if lang == "ja" {
			if displayVictim != "" {
				descBuilder.WriteString(fmt.Sprintf("<p><strong>【被害組織】</strong> %s</p>\n", html.EscapeString(displayVictim)))
			}
			descBuilder.WriteString(fmt.Sprintf("<p><strong>【重要度】</strong> %s | <strong>【日本関連性】</strong> %s</p>\n", html.EscapeString(sev), html.EscapeString(jrel)))
			if attackType != "" {
				descBuilder.WriteString(fmt.Sprintf("<p><strong>【攻撃種別】</strong> %s</p>\n", html.EscapeString(attackType)))
			}
			if actors, ok := inc["threat_actors"].([]string); ok && len(actors) > 0 {
				descBuilder.WriteString(fmt.Sprintf("<p><strong>【攻撃者】</strong> %s</p>\n", html.EscapeString(strings.Join(actors, ", "))))
			}
			if displaySummary != "" {
				descBuilder.WriteString(fmt.Sprintf("<p><strong>【要約】</strong><br/>%s</p>\n", strings.ReplaceAll(html.EscapeString(displaySummary), "\n", "<br/>")))
			}
			if displayImpact != "" {
				descBuilder.WriteString(fmt.Sprintf("<p><strong>【日本への影響】</strong><br/>%s</p>\n", strings.ReplaceAll(html.EscapeString(displayImpact), "\n", "<br/>")))
			}
			descBuilder.WriteString(fmt.Sprintf("<p><strong>【関連レポート】</strong> %d件 (初報: %s / 最新報: %s)</p>\n", reportCount, firstSeen, lastSeen))
			if details, ok := inc["sources_detail"].([]interface{}); ok && len(details) > 0 {
				descBuilder.WriteString("<hr/>\n<p><strong>【情報ソース一覧】</strong></p>\n<ul>\n")
				for _, d := range details {
					if dMap, ok := d.(map[string]interface{}); ok {
						sURL, _ := dMap["url"].(string)
						sName, _ := dMap["source_name"].(string)
						sType, _ := dMap["source_type"].(string)
						sTitle, _ := dMap["title"].(string)
						if sURL != "" {
							descBuilder.WriteString(fmt.Sprintf("  <li>[%s] <a href=\"%s\" target=\"_blank\">%s: %s</a></li>\n",
								html.EscapeString(sType), html.EscapeString(sURL), html.EscapeString(sName), html.EscapeString(sTitle)))
						} else {
							descBuilder.WriteString(fmt.Sprintf("  <li>[%s] %s: %s</li>\n",
								html.EscapeString(sType), html.EscapeString(sName), html.EscapeString(sTitle)))
						}
					}
				}
				descBuilder.WriteString("</ul>\n")
			} else if sURLs, ok := inc["source_urls"].([]string); ok && len(sURLs) > 0 {
				descBuilder.WriteString("<hr/>\n<p><strong>【参照URL一覧】</strong></p>\n<ul>\n")
				for _, u := range sURLs {
					descBuilder.WriteString(fmt.Sprintf("  <li><a href=\"%s\" target=\"_blank\">%s</a></li>\n", html.EscapeString(u), html.EscapeString(u)))
				}
				descBuilder.WriteString("</ul>\n")
			}
		} else {
			if displayVictim != "" {
				descBuilder.WriteString(fmt.Sprintf("<p><strong>[Victim Organization]</strong> %s</p>\n", html.EscapeString(displayVictim)))
			}
			descBuilder.WriteString(fmt.Sprintf("<p><strong>[Severity]</strong> %s | <strong>[Japan Relevance]</strong> %s</p>\n", html.EscapeString(sev), html.EscapeString(jrel)))
			if attackType != "" {
				descBuilder.WriteString(fmt.Sprintf("<p><strong>[Attack Type]</strong> %s</p>\n", html.EscapeString(attackType)))
			}
			if actors, ok := inc["threat_actors"].([]string); ok && len(actors) > 0 {
				descBuilder.WriteString(fmt.Sprintf("<p><strong>[Threat Actors]</strong> %s</p>\n", html.EscapeString(strings.Join(actors, ", "))))
			}
			if displaySummary != "" {
				descBuilder.WriteString(fmt.Sprintf("<p><strong>[Summary]</strong><br/>%s</p>\n", strings.ReplaceAll(html.EscapeString(displaySummary), "\n", "<br/>")))
			}
			if displayImpact != "" {
				descBuilder.WriteString(fmt.Sprintf("<p><strong>[Impact Analysis]</strong><br/>%s</p>\n", strings.ReplaceAll(html.EscapeString(displayImpact), "\n", "<br/>")))
			}
			descBuilder.WriteString(fmt.Sprintf("<p><strong>[Correlated Reports]</strong> %d report(s) (First seen: %s / Last seen: %s)</p>\n", reportCount, firstSeen, lastSeen))
			if details, ok := inc["sources_detail"].([]interface{}); ok && len(details) > 0 {
				descBuilder.WriteString("<hr/>\n<p><strong>[Intelligence Sources]</strong></p>\n<ul>\n")
				for _, d := range details {
					if dMap, ok := d.(map[string]interface{}); ok {
						sURL, _ := dMap["url"].(string)
						sName, _ := dMap["source_name"].(string)
						sType, _ := dMap["source_type"].(string)
						sTitle, _ := dMap["title"].(string)
						if sURL != "" {
							descBuilder.WriteString(fmt.Sprintf("  <li>[%s] <a href=\"%s\" target=\"_blank\">%s: %s</a></li>\n",
								html.EscapeString(sType), html.EscapeString(sURL), html.EscapeString(sName), html.EscapeString(sTitle)))
						} else {
							descBuilder.WriteString(fmt.Sprintf("  <li>[%s] %s: %s</li>\n",
								html.EscapeString(sType), html.EscapeString(sName), html.EscapeString(sTitle)))
						}
					}
				}
				descBuilder.WriteString("</ul>\n")
			} else if sURLs, ok := inc["source_urls"].([]string); ok && len(sURLs) > 0 {
				descBuilder.WriteString("<hr/>\n<p><strong>[Source URLs]</strong></p>\n<ul>\n")
				for _, u := range sURLs {
					descBuilder.WriteString(fmt.Sprintf("  <li><a href=\"%s\" target=\"_blank\">%s</a></li>\n", html.EscapeString(u), html.EscapeString(u)))
				}
				descBuilder.WriteString("</ul>\n")
			}
		}

		items = append(items, rssItem{
			Title:       itemTitle,
			Link:        primURL,
			GUID:        rssGUID{IsPermaLink: false, Value: id},
			PubDate:     itemPubDate,
			Categories:  categories,
			Description: rssCDataField{Value: descBuilder.String()},
		})
	}

	channelTitle := "Threat Information Harvester - Threat Intelligence Feed (English)"
	channelDesc := "Automated Cyber Threat Intelligence feed focusing on global cyber attacks, ransomware incidents, and vulnerabilities (STIX 2.1 compliant)."
	if lang == "ja" {
		channelTitle = "Threat Information Harvester - 脅威インテリジェンスフィード (日本語)"
		channelDesc = "日本国内組織を標的とするサイバー攻撃・ランサムウェア被害・重要脆弱性の自動収集脅威インテリジェンスフィード (STIX 2.1準拠)"
	}

	feed := rssFeed{
		Version: "2.0",
		AtomNS:  "http://www.w3.org/2005/Atom",
		Channel: rssChannel{
			Title:         channelTitle,
			Link:          baseURL,
			Description:   channelDesc,
			Language:      lang,
			LastBuildDate: time.Now().UTC().Format(time.RFC1123Z),
			Generator:     "Threat Information Harvester 2.0 (STIX 2.1 Compliant)",
			AtomLink: atomLink{
				Href: feedURL,
				Rel:  "self",
				Type: "application/rss+xml",
			},
			Items: items,
		},
	}

	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	_ = enc.Encode(feed)
}
