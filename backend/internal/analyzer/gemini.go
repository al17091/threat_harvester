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

	"github.com/al17091/threat_harvester/backend/internal/config"
	"github.com/al17091/threat_harvester/backend/internal/models"
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
	Title                string   `json:"title"`
	TitleJa              string   `json:"title_ja"`
	Summary              string   `json:"summary"`
	SummaryJa            string   `json:"summary_ja"`
	ImpactAnalysis       string   `json:"impact_analysis"`
	ImpactAnalysisJa     string   `json:"impact_analysis_ja"`
	VictimOrgs           []string          `json:"victim_orgs"`
	ThreatActors         []string          `json:"threat_actors"`
	ThreatActorReasons   map[string]string `json:"threat_actor_reasons,omitempty"`
	AttackType           string            `json:"attack_type"`
	CVEs                 []string          `json:"cves,omitempty"`
	AffectedProducts     []string          `json:"affected_products,omitempty"`
	RecommendedActions   []string          `json:"recommended_actions,omitempty"`
	RecommendedActionsJa []string          `json:"recommended_actions_ja,omitempty"`
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

	title := strings.TrimSpace(out.Title)
	if title == "" {
		title = strings.TrimSpace(out.TitleJa)
	}
	if title == "" {
		title = item.Title
	}

	titleJa := strings.TrimSpace(out.TitleJa)
	if titleJa == "" {
		titleJa = title
	}

	summary := strings.TrimSpace(out.Summary)
	if summary == "" {
		summary = strings.TrimSpace(out.SummaryJa)
	}
	if summary == "" {
		summary = item.Summary
	}

	summaryJa := strings.TrimSpace(out.SummaryJa)
	if summaryJa == "" {
		summaryJa = summary
	}

	impact := strings.TrimSpace(out.ImpactAnalysis)
	if impact == "" {
		impact = strings.TrimSpace(out.ImpactAnalysisJa)
	}

	actions := out.RecommendedActions
	if len(actions) == 0 {
		actions = out.RecommendedActionsJa
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

	cleanActors := models.CleanThreatActors(out.ThreatActors)
	actorReasons := ResolveThreatActorReasons(item, cleanActors, out.ThreatActorReasons)

	return &models.EnrichedThreat{
		ItemID:               item.ID,
		Item:                 item,
		Severity:             severity,
		JapanRelevance:       japanRel,
		Title:                title,
		TitleJa:              titleJa,
		Summary:              summary,
		SummaryJa:            summaryJa,
		ImpactAnalysis:       impact,
		ImpactAnalysisJa:     out.ImpactAnalysisJa,
		VictimOrgs:           out.VictimOrgs,
		ThreatActors:         cleanActors,
		ThreatActorReasons:   actorReasons,
		AttackType:           attackType,
		CVEs:                 uniqueCVEs,
		AffectedProducts:     affectedProducts,
		RecommendedActions:   actions,
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
- 【重要】脅威アクター（threat_actors）の抽出ルール:
  - 原文記事（中国語や外国語の脅威インテリジェンス・リーク情報含む）において具体的な攻撃グループ名・アクター名（例: "银狐", "海莲花", "暗雪", "毒云藤", "Volt Typhoon", "APT41", "Lazarus", "LockBit" 等）が明記されている場合は、原文の固有グループ名・表記のまま正確に抽出してそのまま保持してください。
  - ただし、「未知威胁行为者」「中国国家支援型アクター」「ハッカー」「Cybercriminals」「Attackers」「未確認」等の抽象的・一般的な表現や未特定を示す記述は除外し、特定グループ名がない場合は空配列 [] としてください。

# 対象インシデント情報
ソース種別: %s
情報源: %s
タイトル: %s
URL: %s
原文本文データ: %s
付加情報: %s

# 出力形式 (必ず以下のJSONフォーマットのみを出力してください。title, summary, impact_analysis, recommended_actions は必ずプロフェッショナルな英語で記述してください)
{
    "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
    "japan_relevance": "Direct" | "Indirect" | "None",
    "title": "Concise and accurate English incident title",
    "summary": "Technical background and victim impact summary in English (2-3 sentences)",
    "impact_analysis": "Concrete evaluation of threat impact and risks in English",
    "recommended_actions": ["Recommended initial defensive and mitigation steps in English"],
    "title_ja": "日本語での的確で簡潔なインシデント名",
    "summary_ja": "技術的背景と被害状況の日本語要約",
    "impact_analysis_ja": "日本国内への具体的な影響・脅威評価",
    "victim_orgs": ["Identified victim organization names"],
    "threat_actors": ["Identified threat actors / cybercrime groups"],
    "threat_actor_reasons": {"ActorName": "Brief explanation of where/how this actor was mentioned in the text or metadata"},
    "attack_type": "Ransomware" | "Data Breach" | "Zero-day" | "Supply Chain" | "DDoS" | "Phishing" | "Vulnerability" | "Service Release" | "None",
    "cves": ["CVE identifiers e.g. CVE-2026-88771"],
    "affected_products": ["Affected product/software names e.g. FortiMail, NetScaler ADC, WordPress"],
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
- 【重要】脅威アクター（threat_actors）の抽出ルール:
  - 原文記事（中国語や外国語の脅威インテリジェンス・リーク情報含む）において具体的な攻撃グループ名・アクター名（例: "银狐", "海莲花", "暗雪", "毒云藤", "Volt Typhoon", "APT41", "Lazarus", "LockBit" 等）が明記されている場合は、原文の固有グループ名・表記のまま正確に抽出してそのまま保持してください。
  - ただし、「未知威胁行为者」「中国国家支援型アクター」「ハッカー」「Cybercriminals」「Attackers」「未確認」等の抽象的・一般的な表現や未特定を示す記述は除外し、特定グループ名がない場合は空配列 [] としてください。

# 対象インシデント一覧 (JSON)
%s

# 出力形式 (必ず入力の各 "index" に対応する JSON 配列のみを出力してください。title, summary, impact_analysis, recommended_actions は必ずプロフェッショナルな英語で記述してください)
[
  {
    "index": 0,
    "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
    "japan_relevance": "Direct" | "Indirect" | "None",
    "title": "Concise and accurate English incident title",
    "summary": "Technical background and victim impact summary in English (2-3 sentences)",
    "impact_analysis": "Concrete evaluation of threat impact and risks in English",
    "recommended_actions": ["Recommended initial defensive and mitigation steps in English"],
    "title_ja": "日本語での的確で簡潔なインシデント名",
    "summary_ja": "技術的背景と被害状況の日本語3行以内要約",
    "impact_analysis_ja": "日本国内への具体的な影響・脅威評価",
    "victim_orgs": ["被害組織名（判明している場合）"],
    "threat_actors": ["関与している攻撃グループ名（判明している場合）"],
    "threat_actor_reasons": {"ActorName": "Brief explanation of where/how this actor was mentioned in the text or metadata"},
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

// TranslateIncidentFields translates Japanese incident fields into clear, professional English using Gemini.
func (a *GeminiThreatAnalyzer) TranslateIncidentFields(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	cfg := config.GetSettings().GetConfig()
	apiKey := cfg.AI.GeminiAPIKey
	if apiKey == "" {
		apiKey = cfg.AI.Escalation.GeminiAPIKey
	}
	if apiKey == "" {
		return title, summary, impact, actions, fmt.Errorf("no gemini api key configured")
	}
	model := cfg.AI.GeminiModel
	if model == "" {
		model = "gemini-3.5-flash-lite"
	}

	payload := map[string]interface{}{
		"title":               title,
		"summary":             summary,
		"impact_analysis":     impact,
		"recommended_actions": actions,
	}
	payloadBytes, _ := json.Marshal(payload)

	prompt := fmt.Sprintf(`You are an expert Cyber Threat Intelligence (CTI) editor and translator.
Translate the following cyber threat incident fields into professional, clear, fluent English suitable for an executive CTI intelligence portal.
CRITICAL RULES:
- Every field in the output JSON ('title', 'summary', 'impact_analysis', 'recommended_actions') MUST BE 100%% IN FLUENT ENGLISH.
- Translate Japanese organization descriptions, threat details, and actions into standard English terminology.
- Maintain CVE IDs, threat actor group names, and victim names accurately.
- Return ONLY valid JSON with keys "title", "summary", "impact_analysis", "recommended_actions".

Input to translate:
%s
`, string(payloadBytes))

	reqBody := geminiRequest{
		Contents: []geminiContent{
			{Parts: []geminiPart{{Text: prompt}}},
		},
		GenerationConfig: &geminiGenConfig{
			ResponseMimeType: "application/json",
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return title, summary, impact, actions, err
	}

	apiURL := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return title, summary, impact, actions, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return title, summary, impact, actions, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return title, summary, impact, actions, fmt.Errorf("gemini translation status %d: %s", resp.StatusCode, string(respBody))
	}

	var geminiResp geminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil || len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return title, summary, impact, actions, fmt.Errorf("empty translation candidate from gemini")
	}

	rawJSONText := cleanJSONFences(geminiResp.Candidates[0].Content.Parts[0].Text)
	var out struct {
		Title              string          `json:"title"`
		Summary            string          `json:"summary"`
		ImpactAnalysis     string          `json:"impact_analysis"`
		RecommendedActions json.RawMessage `json:"recommended_actions"`
	}
	if err := json.Unmarshal([]byte(rawJSONText), &out); err != nil {
		return title, summary, impact, actions, err
	}

	tTitle := strings.TrimSpace(out.Title)
	if tTitle == "" {
		tTitle = title
	}
	tSummary := strings.TrimSpace(out.Summary)
	if tSummary == "" {
		tSummary = summary
	}
	tImpact := strings.TrimSpace(out.ImpactAnalysis)
	if tImpact == "" {
		tImpact = impact
	}
	tActions := ParseActionsFlexible(out.RecommendedActions)
	if len(tActions) == 0 {
		tActions = actions
	}

	return tTitle, tSummary, tImpact, tActions, nil
}

func (a *GeminiThreatAnalyzer) TranslateIncident(ctx context.Context, input IncidentTranslationInput) (*IncidentTranslationOutput, error) {
	tTitle, tSummary, tImpact, tActions, err := a.TranslateIncidentFields(ctx, input.Title, input.Summary, input.ImpactAnalysis, input.RecommendedActions)
	if err != nil {
		return &IncidentTranslationOutput{
			ID:                 input.ID,
			Title:              input.Title,
			Summary:            input.Summary,
			ImpactAnalysis:     input.ImpactAnalysis,
			VictimOrgEn:        input.VictimOrg,
			AffectedProductEn:  input.AffectedProduct,
			RecommendedActions: input.RecommendedActions,
		}, err
	}
	return &IncidentTranslationOutput{
		ID:                 input.ID,
		Title:              tTitle,
		Summary:            tSummary,
		ImpactAnalysis:     tImpact,
		VictimOrgEn:        input.VictimOrg,
		AffectedProductEn:  input.AffectedProduct,
		RecommendedActions: tActions,
	}, nil
}

// TranslateBatch translates multiple incidents in a single Gemini call.
func (a *GeminiThreatAnalyzer) TranslateBatch(ctx context.Context, items []BatchTranslateItem) ([]BatchTranslateResult, error) {
	if len(items) == 0 {
		return nil, nil
	}
	cfg := config.GetSettings().GetConfig()
	apiKey := cfg.AI.GeminiAPIKey
	if apiKey == "" {
		apiKey = cfg.AI.Escalation.GeminiAPIKey
	}
	if apiKey == "" {
		return nil, fmt.Errorf("no gemini api key configured")
	}
	model := cfg.AI.GeminiModel
	if model == "" {
		model = "gemini-3.5-flash-lite"
	}

	itemsJSON, _ := json.Marshal(items)
	prompt := fmt.Sprintf(`You are an expert Cyber Threat Intelligence (CTI) editor and translator.
Translate each incident item in the JSON array from Japanese into professional, fluent, cybersecurity-standard English.
CRITICAL RULES:
- Every field ('title', 'summary', 'impact_analysis', 'recommended_actions') in the output MUST BE 100%% IN FLUENT ENGLISH.
- Keep the 'id' field exactly as provided in the input.
- 'recommended_actions' MUST BE an array of strings, e.g. ["Action 1", "Action 2"].
- Maintain CVE numbers, victim organizations, and threat actors accurately.
- Return ONLY a valid JSON array corresponding to the input items.

Input items:
%s
`, string(itemsJSON))

	reqBody := geminiRequest{
		Contents: []geminiContent{
			{Parts: []geminiPart{{Text: prompt}}},
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
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gemini batch status %d: %s", resp.StatusCode, string(respBody))
	}

	var geminiResp geminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil || len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("empty batch response from gemini")
	}

	type rawResult struct {
		ID                 string          `json:"id"`
		Title              string          `json:"title"`
		Summary            string          `json:"summary"`
		ImpactAnalysis     string          `json:"impact_analysis"`
		RecommendedActions json.RawMessage `json:"recommended_actions"`
	}

	rawJSONText := cleanJSONFences(geminiResp.Candidates[0].Content.Parts[0].Text)
	var rawList []rawResult
	if err := json.Unmarshal([]byte(rawJSONText), &rawList); err != nil {
		var wrapped map[string]json.RawMessage
		if err2 := json.Unmarshal([]byte(rawJSONText), &wrapped); err2 == nil {
			for _, val := range wrapped {
				var subList []rawResult
				if err3 := json.Unmarshal(val, &subList); err3 == nil && len(subList) > 0 {
					rawList = subList
					break
				}
			}
		}
		if len(rawList) == 0 {
			return nil, fmt.Errorf("failed to parse batch translation json: %w", err)
		}
	}

	results := make([]BatchTranslateResult, 0, len(rawList))
	for _, raw := range rawList {
		results = append(results, BatchTranslateResult{
			ID:                 raw.ID,
			Title:              raw.Title,
			Summary:            raw.Summary,
			ImpactAnalysis:     raw.ImpactAnalysis,
			RecommendedActions: ParseActionsFlexible(raw.RecommendedActions),
		})
	}

	return results, nil
}

// TranslateFieldsToJapanese translates English CTI fields into natural, professional Japanese
// adhering strictly to JPCERT/CC and IPA cybersecurity terminology, with zero Chinese characters/expressions.
func (a *GeminiThreatAnalyzer) TranslateFieldsToJapanese(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	cfg := config.GetSettings().GetConfig()
	apiKey := cfg.AI.GeminiAPIKey
	if apiKey == "" {
		apiKey = cfg.AI.Escalation.GeminiAPIKey
	}
	if apiKey == "" {
		return title, summary, impact, actions, fmt.Errorf("no gemini api key configured")
	}
	model := cfg.AI.GeminiModel
	if model == "" {
		model = "gemini-3.5-flash-lite"
	}

	payload := map[string]interface{}{
		"title":               title,
		"summary":             summary,
		"impact_analysis":     impact,
		"recommended_actions": actions,
	}
	payloadBytes, _ := json.Marshal(payload)

	prompt := fmt.Sprintf(`You are an expert Cyber Threat Intelligence (CTI) editor and translator specializing in Japanese cybersecurity terminology.
Translate the following cyber threat incident fields from English into professional, fluent, cybersecurity-standard Japanese (suitable for JPCERT/CC or IPA security advisories).

CRITICAL RULES:
1. STRICTLY NO CHINESE CHARACTERS OR PHRASINGS (簡体字や中国語表現は一切禁止):
   - Do NOT use Chinese terms like: 恶意软件 (malware), 攻击者/威胁行为者 (threat actor), 漏洞 (vulnerability), 勒索软件 (ransomware), 钓鱼 (phishing), 数据泄露 (data breach), 网络安全 (cybersecurity).
   - Use standard Japanese cybersecurity terminology:
     - Malware -> マルウェア
     - Threat actor / Cybercrime group -> 攻撃グループ / 脅威アクター / 攻撃者
     - Vulnerability -> 脆弱性
     - Ransomware -> ランサムウェア
     - Data breach -> 情報漏洩 / データ侵害
     - Zero-day -> ゼロデイ
     - Exploitation / Attack -> 悪用 / 攻撃
2. PRESERVE TECHNICAL IDENTIFIERS:
   - Keep CVE identifiers (e.g. CVE-2026-106931), product names (e.g. SiteGuard Server Edition, FortiMail, Windows Server), and company/victim names in standard form.
   - Do NOT translate proper nouns or product names awkwardly.
3. CONCISE & PROFESSIONAL:
   - "title_ja": Concise Japanese incident headline.
   - "summary_ja": Clear 2-3 sentence Japanese technical summary.
   - "impact_analysis_ja": Concrete evaluation of impact and risk to Japanese organizations.
   - "recommended_actions_ja": Array of recommended mitigation/defense steps in Japanese.

Input to translate:
%s

Output ONLY a valid JSON object with keys: "title_ja", "summary_ja", "impact_analysis_ja", "recommended_actions_ja".`, string(payloadBytes))

	reqBody := geminiRequest{
		Contents: []geminiContent{
			{Parts: []geminiPart{{Text: prompt}}},
		},
		GenerationConfig: &geminiGenConfig{
			ResponseMimeType: "application/json",
		},
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return title, summary, impact, actions, err
	}

	apiURL := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return title, summary, impact, actions, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return title, summary, impact, actions, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return title, summary, impact, actions, fmt.Errorf("gemini translation status %d: %s", resp.StatusCode, string(respBody))
	}

	var geminiResp geminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil || len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return title, summary, impact, actions, fmt.Errorf("empty translation candidate from gemini")
	}

	rawJSONText := cleanJSONFences(geminiResp.Candidates[0].Content.Parts[0].Text)
	var out struct {
		TitleJa              string          `json:"title_ja"`
		SummaryJa            string          `json:"summary_ja"`
		ImpactAnalysisJa     string          `json:"impact_analysis_ja"`
		RecommendedActionsJa json.RawMessage `json:"recommended_actions_ja"`
	}
	if err := json.Unmarshal([]byte(rawJSONText), &out); err != nil {
		return title, summary, impact, actions, err
	}

	tTitle := strings.TrimSpace(out.TitleJa)
	if tTitle == "" {
		tTitle = title
	}
	tSummary := strings.TrimSpace(out.SummaryJa)
	if tSummary == "" {
		tSummary = summary
	}
	tImpact := strings.TrimSpace(out.ImpactAnalysisJa)
	if tImpact == "" {
		tImpact = impact
	}
	tActions := ParseActionsFlexible(out.RecommendedActionsJa)
	if len(tActions) == 0 {
		tActions = actions
	}

	return tTitle, tSummary, tImpact, tActions, nil
}

// LocalizeThreatToJapanese enriches an EnrichedThreat with high quality Japanese fields using Gemini.
func (a *GeminiThreatAnalyzer) LocalizeThreatToJapanese(ctx context.Context, enriched *models.EnrichedThreat) error {
	if enriched == nil {
		return nil
	}
	tTitle, tSummary, tImpact, tActions, err := a.TranslateFieldsToJapanese(
		ctx,
		enriched.Title,
		enriched.Summary,
		enriched.ImpactAnalysis,
		enriched.RecommendedActions,
	)
	if err != nil {
		return err
	}
	enriched.TitleJa = tTitle
	enriched.SummaryJa = tSummary
	enriched.ImpactAnalysisJa = tImpact
	enriched.RecommendedActionsJa = tActions
	return nil
}

