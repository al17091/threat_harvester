package models

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// Regex to strip X/Twitter wrapper: e.g. 'someone on X: "..."', 'someone (@handle) on X: "..."'
	xPrefixRegex = regexp.MustCompile(`(?i)^.+?(\s+on\s+X:\s*["“]?|\s*\(@[^\)]+\)\s+on\s+X:\s*["“]?)`)
	xSuffixRegex = regexp.MustCompile(`(?i)["”]?\s*(/\s*X)?$`)

	// Regex to strip media publisher suffixes: e.g. ' - 日本経済新聞', ' | NHKニュース', ' (毎日新聞)', ': Security NEXT'
	mediaSuffixRegex = regexp.MustCompile(`(?i)\s*[-|｜]\s*[\w\p{Han}\p{Hiragana}\p{Katakana}\s]+(ニュース|新聞|オンライン|ブログ|Media|NEXT).*$`)
	mediaParensRegex = regexp.MustCompile(`(?i)\s*\([\w\p{Han}\p{Hiragana}\p{Katakana}\s]+(ニュース|新聞|オンライン)\)$`)

	// Regex to strip clickbait / news buzzword prefixes: e.g. '【速報】', '【独自】', '【緊急】'
	sensationalPrefixRegex = regexp.MustCompile(`^【(速報|独自|緊急|注目|重要|注目記事)】\s*`)

	// Regex to detect casual conversational tweets: replies, rants, emotional outbursts
	conversationalNoiseRegex = regexp.MustCompile(`(?i)^(@\w+|〜って|ってすごいな|信頼できなくな|なんか|結局、|だよね|お願いだから|やめてほしい|怖いな|草|w{2,})`)
)

// CleanRawIncidentTitle strips Twitter wrappers, publisher watermarks, and clickbait prefixes.
func CleanRawIncidentTitle(raw string) string {
	t := strings.TrimSpace(raw)
	if t == "" {
		return ""
	}

	// 1. Strip X / Twitter quote wrapper
	t = xPrefixRegex.ReplaceAllString(t, "")
	t = xSuffixRegex.ReplaceAllString(t, "")

	// 2. Strip news publisher suffixes
	t = mediaSuffixRegex.ReplaceAllString(t, "")
	t = mediaParensRegex.ReplaceAllString(t, "")

	// 3. Strip clickbait prefixes
	t = sensationalPrefixRegex.ReplaceAllString(t, "")

	// 4. Strip surrounding quotes and whitespace
	t = strings.Trim(t, "\"'“” \t\r\n")

	// 5. Unescape HTML quotes if present
	t = strings.ReplaceAll(t, "&quot;", "\"")
	t = strings.ReplaceAll(t, "&#39;", "'")
	t = strings.ReplaceAll(t, "&amp;", "&")

	return strings.TrimSpace(t)
}

// IsNoisySocialMediaTitle checks if a title is casual social media noise rather than an informative CTI headline.
func IsNoisySocialMediaTitle(title string) bool {
	cleaned := CleanRawIncidentTitle(title)
	if cleaned == "" {
		return true
	}

	// Starts with reply or conversational outburst
	if conversationalNoiseRegex.MatchString(cleaned) {
		return true
	}

	// Contains pure commentary without concrete nouns
	lower := strings.ToLower(cleaned)
	if strings.Contains(lower, "ってすごいな") ||
		strings.Contains(lower, "信頼できなくなっ") ||
		strings.Contains(lower, "単年度予算主義") ||
		strings.Contains(lower, "誘発地震") {
		return true
	}

	// Title is too short and purely emojis or punctuation
	runes := []rune(cleaned)
	if len(runes) < 6 {
		return true
	}

	return false
}

// SynthesizeIncidentTitles generates consistent, informative incident titles for both English and Japanese.
func SynthesizeIncidentTitles(
	item ThreatItem,
	enriched *EnrichedThreat,
	victim string,
	product string,
	cves []string,
	attackType string,
	threatActors []string,
) (titleEn string, titleJa string) {
	cleanVictim := SanitizeVictimOrgName(victim)
	if IsGenericVictimOrg(cleanVictim) {
		cleanVictim = ""
	}
	cleanProduct := strings.TrimSpace(product)
	if IsInvalidAffectedProduct(cleanProduct) {
		cleanProduct = ""
	}

	// Normalize attack type
	normAttack := strings.TrimSpace(attackType)
	if normAttack == "" && enriched != nil {
		normAttack = enriched.AttackType
	}
	if normAttack == "" {
		if len(cves) > 0 || cleanProduct != "" {
			normAttack = "Vulnerability"
		} else {
			normAttack = "Cyber Attack"
		}
	}

	// Candidate titles from enriched threat if provided by AI
	candEn := ""
	candJa := ""
	if enriched != nil {
		candEn = CleanRawIncidentTitle(enriched.Title)
		candJa = CleanRawIncidentTitle(enriched.TitleJa)
	}

	// If candidate Japanese title is valid and not noisy, use it
	if candJa != "" && !IsNoisySocialMediaTitle(candJa) && len([]rune(candJa)) >= 8 {
		titleJa = candJa
	}

	// If candidate English title is valid and not noisy, use it
	if candEn != "" && !IsNoisySocialMediaTitle(candEn) && len(candEn) >= 8 {
		titleEn = candEn
	}

	// Synthesize fallback titles if missing or noisy
	if titleJa == "" || IsNoisySocialMediaTitle(titleJa) {
		titleJa = synthesizeJapaneseTitle(cleanVictim, cleanProduct, cves, normAttack, threatActors, item)
	}
	if titleEn == "" || IsNoisySocialMediaTitle(titleEn) {
		titleEn = synthesizeEnglishTitle(cleanVictim, cleanProduct, cves, normAttack, threatActors, item)
	}

	return titleEn, titleJa
}

func getIncidentTagJa(attackType string) string {
	switch strings.ToLower(attackType) {
	case "ransomware":
		return "【ランサムウェア】"
	case "vulnerability":
		return "【脆弱性】"
	case "data breach", "leak", "unauthorized access":
		return "【不正アクセス】"
	case "zero-day":
		return "【ゼロデイ】"
	case "ddos":
		return "【DDoS攻撃】"
	case "phishing":
		return "【フィッシング】"
	case "supply chain":
		return "【サプライチェーン攻撃】"
	default:
		return "【サイバー攻撃】"
	}
}

func getIncidentTagEn(attackType string) string {
	switch strings.ToLower(attackType) {
	case "ransomware":
		return "[Ransomware] "
	case "vulnerability":
		return "[Vulnerability] "
	case "data breach", "leak", "unauthorized access":
		return "[Data Breach] "
	case "zero-day":
		return "[Zero-day] "
	case "ddos":
		return "[DDoS] "
	case "phishing":
		return "[Phishing] "
	case "supply chain":
		return "[Supply Chain] "
	default:
		return "[Cyber Threat] "
	}
}

func synthesizeJapaneseTitle(victim, product string, cves []string, attackType string, actors []string, item ThreatItem) string {
	tag := getIncidentTagJa(attackType)
	cleanItemTitle := CleanRawIncidentTitle(item.Title)

	switch strings.ToLower(attackType) {
	case "vulnerability":
		if product != "" && len(cves) > 0 {
			return fmt.Sprintf("%s%sにおける脆弱性 (%s)", tag, product, strings.Join(cves, ", "))
		}
		if product != "" {
			return fmt.Sprintf("%s%sにおけるセキュリティ脆弱性", tag, product)
		}
		if len(cves) > 0 {
			return fmt.Sprintf("%s%sに関するセキュリティアドバイザリ", tag, strings.Join(cves, ", "))
		}
		if cleanItemTitle != "" && !IsNoisySocialMediaTitle(cleanItemTitle) {
			return tag + cleanItemTitle
		}
		return "【脆弱性】ソフトウェア製品におけるセキュリティ脆弱性"

	case "ransomware":
		actorStr := ""
		if len(actors) > 0 && actors[0] != "" {
			actorStr = actors[0] + "による"
		}
		if victim != "" {
			if actorStr != "" {
				return fmt.Sprintf("%s%sに対する%sランサムウェア攻撃被害", tag, victim, actorStr)
			}
			return fmt.Sprintf("%s%sに対するランサムウェア攻撃被害", tag, victim)
		}
		if cleanItemTitle != "" && !IsNoisySocialMediaTitle(cleanItemTitle) {
			return tag + cleanItemTitle
		}
		return "【ランサムウェア】組織に対するランサムウェア感染被害"

	case "data breach", "leak", "unauthorized access":
		if victim != "" {
			return fmt.Sprintf("%s%sにおける不正アクセスおよび情報流出事案", tag, victim)
		}
		if cleanItemTitle != "" && !IsNoisySocialMediaTitle(cleanItemTitle) {
			return tag + cleanItemTitle
		}
		return "【不正アクセス】国内組織における不正アクセス・情報流出事案"

	default:
		if victim != "" {
			return fmt.Sprintf("%s%sにおけるセキュリティインシデント", tag, victim)
		}
		if cleanItemTitle != "" && !IsNoisySocialMediaTitle(cleanItemTitle) {
			return tag + cleanItemTitle
		}
		return "【サイバー攻撃】セキュリティインシデントの観測"
	}
}

func synthesizeEnglishTitle(victim, product string, cves []string, attackType string, actors []string, item ThreatItem) string {
	tag := getIncidentTagEn(attackType)
	cleanItemTitle := CleanRawIncidentTitle(item.Title)

	switch strings.ToLower(attackType) {
	case "vulnerability":
		if product != "" && len(cves) > 0 {
			return fmt.Sprintf("%s%s Vulnerability (%s)", tag, product, strings.Join(cves, ", "))
		}
		if product != "" {
			return fmt.Sprintf("%sSecurity Vulnerability in %s", tag, product)
		}
		if len(cves) > 0 {
			return fmt.Sprintf("%sSecurity Advisory for %s", tag, strings.Join(cves, ", "))
		}
		if cleanItemTitle != "" && !IsNoisySocialMediaTitle(cleanItemTitle) {
			return tag + cleanItemTitle
		}
		return "[Vulnerability] Security Vulnerability in Software Product"

	case "ransomware":
		actorStr := ""
		if len(actors) > 0 && actors[0] != "" {
			actorStr = " by " + actors[0]
		}
		if victim != "" {
			return fmt.Sprintf("%s%s Hit by Ransomware Attack%s", tag, victim, actorStr)
		}
		if cleanItemTitle != "" && !IsNoisySocialMediaTitle(cleanItemTitle) {
			return tag + cleanItemTitle
		}
		return "[Ransomware] Organization Targeted in Ransomware Attack"

	case "data breach", "leak", "unauthorized access":
		if victim != "" {
			return fmt.Sprintf("%sUnauthorized Access and Potential Data Breach at %s", tag, victim)
		}
		if cleanItemTitle != "" && !IsNoisySocialMediaTitle(cleanItemTitle) {
			return tag + cleanItemTitle
		}
		return "[Data Breach] Unauthorized Access and Data Leak Incident"

	default:
		if victim != "" {
			return fmt.Sprintf("%sSecurity Incident at %s", tag, victim)
		}
		if cleanItemTitle != "" && !IsNoisySocialMediaTitle(cleanItemTitle) {
			return tag + cleanItemTitle
		}
		return "[Cyber Threat] Cybersecurity Incident Detected"
	}
}
