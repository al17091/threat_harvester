package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dapt/information_harvester/backend/internal/config"
	"github.com/dapt/information_harvester/backend/internal/models"
)

type queryCacheEntry struct {
	queries  []string
	cachedAt time.Time
}

type GeminiThreatAnalyzer struct {
	client     *http.Client
	cacheMu    sync.RWMutex
	queryCache map[string]queryCacheEntry
	cacheTTL   time.Duration
}

func NewGeminiThreatAnalyzer() *GeminiThreatAnalyzer {
	return &GeminiThreatAnalyzer{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		queryCache: make(map[string]queryCacheEntry),
		cacheTTL:   12 * time.Hour,
	}
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiGenConfig struct {
	ResponseMimeType string `json:"responseMimeType,omitempty"`
}

type geminiRequest struct {
	Contents         []geminiContent  `json:"contents"`
	GenerationConfig *geminiGenConfig `json:"generationConfig,omitempty"`
}

type geminiCandidate struct {
	Content struct {
		Parts []geminiPart `json:"parts"`
	} `json:"content"`
}

type geminiResponse struct {
	Candidates []geminiCandidate `json:"candidates"`
}

type analysisOutput struct {
	Index                int      `json:"index,omitempty"`
	Severity             string   `json:"severity"`
	JapanRelevance       string   `json:"japan_relevance"`
	TitleJa              string   `json:"title_ja"`
	SummaryJa            string   `json:"summary_ja"`
	ImpactAnalysisJa     string   `json:"impact_analysis_ja"`
	VictimOrgs           []string `json:"victim_orgs"`
	ThreatActors         []string `json:"threat_actors"`
	AttackType           string   `json:"attack_type"`
	CVEs                 []string `json:"cves,omitempty"`
	AffectedProducts     []string `json:"affected_products,omitempty"`
	RecommendedActionsJa []string `json:"recommended_actions_ja"`
}

func cleanJSONFences(raw string) string {
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	return strings.TrimSpace(raw)
}

func buildEnrichedThreat(item models.ThreatItem, out analysisOutput) *models.EnrichedThreat {
	severity := models.Severity(out.Severity)
	switch severity {
	case models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo:
	default:
		severity = models.SeverityUnknown
	}

	attackType := out.AttackType
	// Only fall back to heuristic detection if Gemini returned unknown severity
	if severity == models.SeverityUnknown {
		if models.IsServiceReleaseOrNonThreat(item, nil) {
			severity = models.SeverityInfo
			if attackType == "" {
				attackType = "Service Release"
			}
		}
	}

	japanRel := models.JapanRelevance(out.JapanRelevance)
	switch japanRel {
	case models.JapanRelevanceDirect, models.JapanRelevanceIndirect, models.JapanRelevanceNone:
	default:
		japanRel = models.JapanRelevanceUnknown
	}

	titleJa := out.TitleJa
	if titleJa == "" {
		titleJa = item.Title
	}
	summaryJa := out.SummaryJa
	if summaryJa == "" {
		summaryJa = item.Summary
	}

	// Deterministic CVE extraction merged with LLM output
	cves := models.ExtractCVEs(item.Title, item.Summary, item.RawContent, item.URL)
	if len(out.CVEs) > 0 {
		cves = append(cves, models.ExtractCVEs(out.CVEs...)...)
	}
	seenCVE := make(map[string]bool)
	var uniqueCVEs []string
	for _, c := range cves {
		if !seenCVE[c] {
			seenCVE[c] = true
			uniqueCVEs = append(uniqueCVEs, c)
		}
	}

	// Affected products from LLM merged with heuristic detection
	var affectedProducts []string
	for _, p := range out.AffectedProducts {
		norm := models.NormalizeProduct(p)
		if norm != "" {
			affectedProducts = append(affectedProducts, strings.TrimSpace(p))
		}
	}
	if len(affectedProducts) == 0 {
		rawProd, _ := models.ExtractAffectedProduct(item, nil)
		if rawProd != "" {
			affectedProducts = append(affectedProducts, rawProd)
		}
	}

	return &models.EnrichedThreat{
		ItemID:               item.ID,
		Item:                 item,
		Severity:             severity,
		JapanRelevance:       japanRel,
		TitleJa:              titleJa,
		SummaryJa:            summaryJa,
		ImpactAnalysisJa:     out.ImpactAnalysisJa,
		VictimOrgs:           out.VictimOrgs,
		ThreatActors:         out.ThreatActors,
		AttackType:           attackType,
		CVEs:                 uniqueCVEs,
		AffectedProducts:     affectedProducts,
		RecommendedActionsJa: out.RecommendedActionsJa,
		AnalyzedAt:           time.Now().UTC(),
	}
}

func (a *GeminiThreatAnalyzer) Analyze(ctx context.Context, item models.ThreatItem) (*models.EnrichedThreat, error) {
	cfg := config.GetSettings().GetConfig()
	apiKey := cfg.AI.GeminiAPIKey
	model := cfg.AI.GeminiModel
	if model == "" {
		model = "gemini-3.5-flash-lite"
	}

	if apiKey == "" {
		log.Printf("[Analyzer] Gemini API key not configured. Returning basic enrichment for %s", item.Title)
		summaryJa := models.TruncateRunes(item.Summary, 200)
		cves := models.ExtractCVEs(item.Title, item.Summary, item.RawContent, item.URL)
		rawProd, _ := models.ExtractAffectedProduct(item, nil)
		var prods []string
		if rawProd != "" {
			prods = append(prods, rawProd)
		}
		sev := models.SeverityUnknown
		attackType := ""
		if models.IsServiceReleaseOrNonThreat(item, nil) {
			sev = models.SeverityInfo
			attackType = "Service Release"
		}
		return &models.EnrichedThreat{
			ItemID:               item.ID,
			Item:                 item,
			Severity:             sev,
			JapanRelevance:       models.JapanRelevanceUnknown,
			TitleJa:              item.Title,
			SummaryJa:            summaryJa,
			ImpactAnalysisJa:     "Gemini APIキーが未設定のため未分析です。",
			VictimOrgs:           nil,
			ThreatActors:         nil,
			AttackType:           attackType,
			CVEs:                 cves,
			AffectedProducts:     prods,
			RecommendedActionsJa: nil,
			AnalyzedAt:           time.Now().UTC(),
		}, nil
	}

	contentToAnalyze := strings.TrimSpace(item.RawContent)
	if contentToAnalyze == "" {
		contentToAnalyze = strings.TrimSpace(item.Summary)
	}
	contentToAnalyze = models.TruncateRunes(contentToAnalyze, 4000)

	metaJSON, _ := json.Marshal(item.Metadata)
	prompt := fmt.Sprintf(`
あなたは日本を拠点とする最高峰のサイバー脅威インテリジェンス（CTI）アナリストです。
以下の脅威情報の原文データ（記事本文やリーク情報）を精読して詳細に分析し、特に「日本国内の組織・企業・政府・インフラへの影響」を最重要視して評価してください。

# 評価基準
1. japan_relevance (日本への関連性):
   - "Direct": 被害対象が日本企業、日本の官公庁・自治体、国内組織、または日本特有のサプライチェーン。
   - "Indirect": 世界規模の大規模攻撃（日本でも普及している製品・OSの悪用中ゼロデイ、グローバルクラウド障害等）。
   - "None": 日本国内への直接的・間接的な関連性がほぼ見られない事象。

2. severity (重要度):
   - "Critical": 悪用確認済みのゼロデイ、国内主要インフラ停止、大規模サプライチェーン侵害、日本大手組織へのランサムウェア・データ破綻。
   - "High": PoC公開済み深刻脆弱性、国内組織の情報漏洩発表、ランサムウェアDLSへの新規掲載。
   - "Medium": 通常のセキュリティアップデート、注意喚起、影響が限定的なインシデント。
   - "Low": マイナーなバグ修正、実害のない技術調査、セキュリティ啓蒙・コラム。
   - "Info": 新サービス・新機能のリリース告知、製品発表・提供開始、企業PR、マーケティング、脅威・侵害・脆弱性と直接関係のない情報。

# 判定上の重要注意事項（見落とし・情報欠落の防止）
- 「新機能」「製品アップデート」「サービス開始」「リリース」「提供開始」等の単語が含まれる記事であっても、その新機能や製品に関する脆弱性、攻撃・悪用、データ侵害、不正アクセス、セキュリティリスクに言及している場合は、決して「Info」に分類せず、脅威の実態に応じた適切な重要度（Critical / High / Medium / Low）および attack_type（Vulnerability, Zero-day, Data Breach 等）を設定してください。
- 脅威・脆弱性・侵害・セキュリティリスクに一切触れていない単なる機能紹介・PR・マーケティング告知のみを「Info」と判定してください。
- 原文本文データに含まれる被害組織名、攻撃グループ名、影響を受ける製品および具体的なバージョン範囲、CVE識別子、推奨対処法を漏れなく抽出してください。

# 対象インシデント情報
ソース種別: %s
情報源: %s
タイトル: %s
URL: %s
原文本文データ: %s
付加情報: %s

# 出力形式 (必ず以下のJSONフォーマットのみを出力してください)
{
    "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
    "japan_relevance": "Direct" | "Indirect" | "None",
    "title_ja": "日本語での的確で簡潔なインシデント名",
    "summary_ja": "技術的背景と被害状況の日本語3行以内要約",
    "impact_analysis_ja": "日本国内への具体的な影響・脅威評価",
    "victim_orgs": ["被害組織名（判明している場合）"],
    "threat_actors": ["関与している攻撃グループ名（判明している場合）"],
    "attack_type": "Ransomware" | "Data Breach" | "Zero-day" | "Supply Chain" | "DDoS" | "Phishing" | "Vulnerability" | "Service Release" | "None",
    "cves": ["関連するCVE識別子（例: CVE-2026-88771）"],
    "affected_products": ["影響を受ける製品・ソフトウェア名（例: FortiMail, NetScaler ADC, WordPress）"],
    "recommended_actions_ja": ["推奨される初動対応・防御策"]
}
`, item.SourceType, item.SourceName, item.Title, item.URL, contentToAnalyze, string(metaJSON))

	reqBody := geminiRequest{
		Contents: []geminiContent{
			{
				Parts: []geminiPart{
					{Text: prompt},
				},
			},
		},
		GenerationConfig: &geminiGenConfig{
			ResponseMimeType: "application/json",
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gemini api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gemini api returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var geminiResp geminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
		return nil, fmt.Errorf("failed to decode gemini response: %w", err)
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("empty gemini candidates returned")
	}

	rawJSONText := cleanJSONFences(geminiResp.Candidates[0].Content.Parts[0].Text)

	var out analysisOutput
	if err := json.Unmarshal([]byte(rawJSONText), &out); err != nil {
		return nil, fmt.Errorf("failed to parse structured intelligence JSON: %w (raw: %s)", err, rawJSONText)
	}

	return buildEnrichedThreat(item, out), nil
}

// AnalyzeBatch analyzes multiple threat items together in a single structured Gemini API request.
func (a *GeminiThreatAnalyzer) AnalyzeBatch(ctx context.Context, items []models.ThreatItem) ([]*models.EnrichedThreat, error) {
	if len(items) == 0 {
		return nil, nil
	}

	cfg := config.GetSettings().GetConfig()
	apiKey := cfg.AI.GeminiAPIKey
	model := cfg.AI.GeminiModel
	if model == "" {
		model = "gemini-3.5-flash-lite"
	}

	if apiKey == "" {
		log.Printf("[Analyzer] Gemini API key not configured. Returning basic enrichment for %d items", len(items))
		results := make([]*models.EnrichedThreat, len(items))
		for i, it := range items {
			enriched, _ := a.Analyze(ctx, it)
			results[i] = enriched
		}
		return results, nil
	}

	if len(items) == 1 {
		enriched, err := a.Analyze(ctx, items[0])
		if err != nil {
			return nil, err
		}
		return []*models.EnrichedThreat{enriched}, nil
	}

	type batchInputItem struct {
		Index      int    `json:"index"`
		SourceType string `json:"source_type"`
		SourceName string `json:"source_name"`
		Title      string `json:"title"`
		URL        string `json:"url"`
		Content    string `json:"content"`
	}

	inputList := make([]batchInputItem, len(items))
	for i, it := range items {
		content := strings.TrimSpace(it.RawContent)
		if content == "" {
			content = strings.TrimSpace(it.Summary)
		}
		inputList[i] = batchInputItem{
			Index:      i,
			SourceType: string(it.SourceType),
			SourceName: it.SourceName,
			Title:      it.Title,
			URL:        it.URL,
			Content:    models.TruncateRunes(content, 3500),
		}
	}
	itemsJSON, err := json.Marshal(inputList)
	if err != nil {
		return a.fallbackSequential(ctx, items)
	}

	prompt := fmt.Sprintf(`あなたは日本を拠点とする最高峰のサイバー脅威インテリジェンス（CTI）アナリストです。
以下の複数の脅威情報（計 %d 件）の原文データ（"content" フィールドの元記事本文・リーク詳細）を精読して個別に分析し、各インシデントについて「日本国内の組織・企業・政府・インフラへの影響」を最重要視して評価してください。

# 評価基準
1. japan_relevance (日本への関連性):
   - "Direct": 被害対象が日本企業、日本の官公庁・自治体、国内組織、または日本特有のサプライチェーン。
   - "Indirect": 世界規模の大規模攻撃（日本でも普及している製品・OSの悪用中ゼロデイ、グローバルクラウド障害等）。
   - "None": 日本国内への直接的・間接的な関連性がほぼ見られない事象。

2. severity (重要度):
   - "Critical": 悪用確認済みのゼロデイ、国内主要インフラ停止、大規模サプライチェーン侵害、日本大手組織へのランサムウェア・データ破綻。
   - "High": PoC公開済み深刻脆弱性、国内組織の情報漏洩発表、ランサムウェアDLSへの新規掲載。
   - "Medium": 通常のセキュリティアップデート、注意喚起、影響が限定的なインシデント。
   - "Low": マイナーなバグ修正、実害のない技術調査、セキュリティ啓蒙・コラム。
   - "Info": 新サービス・新機能のリリース告知、製品発表・提供開始、企業PR、マーケティング、脅威・侵害・脆弱性と直接関係のない情報。

# 判定上の重要注意事項（見落とし・情報欠落の防止）
- 「新機能」「製品アップデート」「サービス開始」「リリース」「提供開始」等の単語が含まれる記事であっても、その新機能や製品に関する脆弱性、攻撃・悪用、データ侵害、不正アクセス、セキュリティリスクに言及している場合は、決して「Info」に分類せず、脅威の実態に応じた適切な重要度（Critical / High / Medium / Low）および attack_type（Vulnerability, Zero-day, Data Breach 等）を設定してください。
- 脅威・脆弱性・侵害・セキュリティリスクに一切触れていない単なる機能紹介・PR・マーケティング告知のみを「Info」と判定してください。
- 原文本文データに含まれる被害組織名、攻撃グループ名、影響を受ける製品および具体的なバージョン範囲、CVE識別子、推奨対処法を漏れなく抽出してください。

# 対象インシデント一覧 (JSON)
%s

# 出力形式 (必ず入力の各 "index" に対応する JSON 配列のみを出力してください)
[
  {
    "index": 0,
    "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
    "japan_relevance": "Direct" | "Indirect" | "None",
    "title_ja": "日本語での的確で簡潔なインシデント名",
    "summary_ja": "技術的背景と被害状況の日本語3行以内要約",
    "impact_analysis_ja": "日本国内への具体的な影響・脅威評価",
    "victim_orgs": ["被害組織名（判明している場合）"],
    "threat_actors": ["関与している攻撃グループ名（判明している場合）"],
    "attack_type": "Ransomware" | "Data Breach" | "Zero-day" | "Supply Chain" | "DDoS" | "Phishing" | "Vulnerability" | "Service Release" | "None",
    "cves": ["関連するCVE識別子（例: CVE-2026-88771）"],
    "affected_products": ["影響を受ける製品・ソフトウェア名（例: FortiMail, NetScaler ADC, WordPress）"],
    "recommended_actions_ja": ["推奨される初動対応・防御策"]
  }
]
`, len(items), string(itemsJSON))

	reqBody := geminiRequest{
		Contents: []geminiContent{
			{
				Parts: []geminiPart{
					{Text: prompt},
				},
			},
		},
		GenerationConfig: &geminiGenConfig{
			ResponseMimeType: "application/json",
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return a.fallbackSequential(ctx, items)
	}

	apiURL := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return a.fallbackSequential(ctx, items)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		log.Printf("[Analyzer] Gemini batch request failed (%v), falling back to sequential", err)
		return a.fallbackSequential(ctx, items)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("[Analyzer] Gemini batch returned status %d (%s), falling back to sequential", resp.StatusCode, string(respBody))
		return a.fallbackSequential(ctx, items)
	}

	var geminiResp geminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil || len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		log.Printf("[Analyzer] Failed to decode batch candidates, falling back to sequential")
		return a.fallbackSequential(ctx, items)
	}

	rawJSONText := cleanJSONFences(geminiResp.Candidates[0].Content.Parts[0].Text)
	var outputs []analysisOutput
	if err := json.Unmarshal([]byte(rawJSONText), &outputs); err != nil {
		log.Printf("[Analyzer] Failed to parse batch JSON (%v), falling back to sequential. Raw: %s", err, rawJSONText)
		return a.fallbackSequential(ctx, items)
	}

	outMap := make(map[int]analysisOutput)
	for idx, out := range outputs {
		if out.Index >= 0 && out.Index < len(items) {
			outMap[out.Index] = out
		} else if idx < len(items) {
			outMap[idx] = out
		}
	}

	results := make([]*models.EnrichedThreat, len(items))
	for i, it := range items {
		if out, ok := outMap[i]; ok {
			results[i] = buildEnrichedThreat(it, out)
		} else {
			enriched, err := a.Analyze(ctx, it)
			if err != nil {
				enriched, _ = a.Analyze(ctx, it)
			}
			results[i] = enriched
		}
	}

	return results, nil
}

func (a *GeminiThreatAnalyzer) fallbackSequential(ctx context.Context, items []models.ThreatItem) ([]*models.EnrichedThreat, error) {
	results := make([]*models.EnrichedThreat, len(items))
	for i, item := range items {
		enriched, err := a.Analyze(ctx, item)
		if err != nil {
			log.Printf("[Analyzer] Sequential fallback error on item %s: %v", item.Title, err)
		}
		results[i] = enriched
	}
	return results, nil
}

// ClearQueryCache empties the in-memory cache of generated search queries.
func (a *GeminiThreatAnalyzer) ClearQueryCache() {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	a.queryCache = make(map[string]queryCacheEntry)
}

// GenerateSearchQueries dynamically expands a natural language threat monitoring directive into focused search queries.
func (a *GeminiThreatAnalyzer) GenerateSearchQueries(ctx context.Context, directive string, targetType string, count int) ([]string, error) {
	directive = strings.TrimSpace(directive)
	if directive == "" {
		return nil, fmt.Errorf("directive cannot be empty")
	}

	if count <= 0 {
		count = 3
	}
	if count > 5 {
		count = 5
	}

	// Check cache
	cacheKey := fmt.Sprintf("%s:%s:%d", targetType, directive, count)
	a.cacheMu.RLock()
	if entry, ok := a.queryCache[cacheKey]; ok {
		if time.Since(entry.cachedAt) < a.cacheTTL && len(entry.queries) > 0 {
			a.cacheMu.RUnlock()
			log.Printf("[Analyzer] Reusing cached search queries for [%s] '%s' (cached %s ago, count: %d)",
				targetType, models.TruncateRunes(directive, 25), time.Since(entry.cachedAt).Round(time.Minute), len(entry.queries))
			return entry.queries, nil
		}
	}
	a.cacheMu.RUnlock()

	cfg := config.GetSettings().GetConfig()
	apiKey := cfg.AI.GeminiAPIKey
	model := cfg.AI.GeminiModel
	if model == "" {
		model = "gemini-3.5-flash-lite"
	}
	if apiKey == "" {
		log.Printf("[Analyzer] Gemini API key not configured. Returning directive as literal query.")
		return []string{directive}, nil
	}

	currentDate := time.Now().UTC().Format("2006-01-02")
	targetDesc := "Google Web Search (CTI breach reports, blogs, security vendor alerts, official government/IPA advisories)"
	guidance := `
- Mix targeted Japanese threat-hunting terms with English keywords.
- Include precise incident terms (e.g. "サイバー攻撃", "ランサムウェア", "不正アクセス", "被害", "漏洩", "調査中", "身代金").
- For vulnerability or technical topics, include "PoC", "悪用", "CVE", "アドバイザリ".
- Avoid single words or over-generic phrases; construct 3 to 6 word targeted keyword search phrases.`

	if targetType == "x_monitor" {
		targetDesc = "X (Twitter) search queries to discover breaking threat disclosures from security researchers, CERTs, and tracking bots"
		guidance = `
- Include X/Twitter operators where appropriate (e.g. "site:x.com" or "site:twitter.com").
- You can include reputable researcher handles (e.g. "from:piyokango", "from:jpcert", "from:FalconFeedsio", "from:ransomfeed", "from:DarkTracer_Int") or combine with Japanese breach terms.
- Focus on breaking leak announcements, initial access disclosures, and ransomware victims.`
	} else if targetType == "darkweb_search" || targetType == "darkweb_onion" {
		targetDesc = "Tor Dark Web (.onion) search engine (Ahmia) to discover ransomware leak posts, darkweb forums, and breach dumps"
		guidance = `
- Output English-focused search terms optimized for Tor hidden services search indices (Ahmia).
- Include darkweb CTI terms (e.g. "ransomware", "leak", "breach", "database", "dump", "victim", "access", "0day").
- If the directive focuses on Japan, include "japan" or specific targeted organizations.
- Keep queries concise and keyword-dense (2 to 4 keywords per query, e.g. "japan ransomware leak", "japanese company breach database").`
	}

	prompt := fmt.Sprintf(`Today's date is %s.
You are a senior Cyber Threat Intelligence (CTI) analyst monitoring cybersecurity threats targeting Japan and critical global threats relevant to Japanese defenders.

The user has specified the following threat monitoring directive / focus instruction:
"%s"

Target platform: %s

Guidelines for query generation:
%s
- Generate exactly %d diverse, complementary search queries that together comprehensively cover this directive.
- Queries must be optimized to discover recent, active 2026 events and freshly reported threat disclosures.

Return ONLY a JSON array of %d string queries, with no markdown code fences or extra text.
Example:
["query 1", "query 2", "query 3"]
`, currentDate, directive, targetDesc, guidance, count, count)

	reqPayload := geminiRequest{
		Contents: []geminiContent{
			{
				Parts: []geminiPart{
					{Text: prompt},
				},
			},
		},
		GenerationConfig: &geminiGenConfig{
			ResponseMimeType: "application/json",
		},
	}

	bodyBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return []string{directive}, err
	}

	apiURL := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return []string{directive}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		log.Printf("[Analyzer] GenerateSearchQueries HTTP request failed: %v", err)
		return []string{directive}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		log.Printf("[Analyzer] GenerateSearchQueries returned status %d: %s", resp.StatusCode, string(respBody))
		return []string{directive}, nil
	}

	var geminiResp geminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil || len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return []string{directive}, nil
	}

	rawJSONText := cleanJSONFences(geminiResp.Candidates[0].Content.Parts[0].Text)

	var queries []string
	if err := json.Unmarshal([]byte(rawJSONText), &queries); err != nil {
		log.Printf("[Analyzer] Failed to parse generated queries JSON: %v (raw: %s)", err, rawJSONText)
		return []string{directive}, nil
	}

	var cleanQueries []string
	for _, q := range queries {
		q = strings.TrimSpace(q)
		if q != "" {
			cleanQueries = append(cleanQueries, q)
		}
	}
	if len(cleanQueries) == 0 {
		return []string{directive}, nil
	}

	// Cache successful generated queries
	a.cacheMu.Lock()
	a.queryCache[cacheKey] = queryCacheEntry{
		queries:  cleanQueries,
		cachedAt: time.Now().UTC(),
	}
	a.cacheMu.Unlock()

	return cleanQueries, nil
}
