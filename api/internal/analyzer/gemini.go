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

	"github.com/al17091/threat_harvester/api/internal/config"
	"github.com/al17091/threat_harvester/api/internal/models"
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
	case models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInformational, models.SeverityInfo:
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
		} else {
			severity = models.SeverityInformational
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

	// Deterministic CVE extraction merged with LLM output, sanitized against prompt placeholders
	cves := models.ExtractCVEs(item.Title, item.Summary, item.RawContent, item.URL)
	if len(out.CVEs) > 0 {
		cves = append(cves, models.ExtractCVEs(out.CVEs...)...)
	}
	uniqueCVEs := models.SanitizeHallucinatedCVEs(item, cves)

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

	metaBytes, _ := json.Marshal(item.Metadata)
	prelim := &models.EnrichedThreat{
		Title:            title,
		TitleJa:          titleJa,
		Summary:          summary,
		SummaryJa:        summaryJa,
		VictimOrgs:       out.VictimOrgs,
		ThreatActors:     out.ThreatActors,
		AffectedProducts: out.AffectedProducts,
	}
	groundedActors := models.ExtractThreatActors(item, prelim, string(metaBytes))
	actorReasons := ResolveThreatActorReasons(item, groundedActors, out.ThreatActorReasons)

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
		VictimOrgs:           models.CleanVictimOrgs(out.VictimOrgs),
		ThreatActors:         groundedActors,
		ThreatActorReasons:   actorReasons,
		AttackType:           attackType,
		CVEs:                 uniqueCVEs,
		AffectedProducts:     models.CleanAffectedProducts(affectedProducts),
		RecommendedActions:   nil,
		RecommendedActionsJa: nil,
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
		sev := models.SeverityInformational
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
			ThreatActors:         models.ExtractThreatActors(item, nil),
			AttackType:           attackType,
			CVEs:                 cves,
			AffectedProducts:     models.CleanAffectedProducts(prods),
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
あなたは日本を拠点とするサイバー脅威インテリジェンス（CTI）アナリストです。
以下の脅威情報の原文データを精読し、客観的な事実（ファクト）のみを抽出・構造化してください。

# 評価基準（厳守）
1. japan_relevance (日本への関連性):
   - "Direct": 具体的な日本企業・日本の官公庁・自治体・国内組織が実際の被害対象となっている事案、またはJPCERT/CC・IPA・JVNによる公式発信。（※海外製品・海外組織の事案は、日本語メディアの記事であっても "Indirect" または "None" とすること）
   - "Indirect": 日本国内の特定被害組織は確認されていないが、日本でも利用されているソフトウェア・OSの脆弱性やグローバルな攻撃キャンペーン。
   - "None": 日本国内との直接的・間接的な関連性が見られない海外ローカル事象。

2. severity (重要度 - 上方バイアス厳禁):
   - 【絶対ルール1】japan_relevance が "Direct" 以外（"Indirect" または "None"）の場合、"Critical" を付与することは絶対に禁止（最大でも "High" まで）。
   - 【絶対ルール2】具体的な被害組織を伴わない一般的な注意喚起（JPCERT/CC・IPAの注意喚起を含む）、週報・まとめ記事、FAQ、動向レポートは最大でも "Medium" までとすること。
   - "Critical": japan_relevance が "Direct" であり、かつ日本国内の特定組織における深刻な実被害（ランサムウェア感染・大規模情報漏洩・重要システム停止・ゼロデイ悪用による侵害）が確認された事案のみ。
   - "High": 国内組織での不正アクセス・情報漏洩事案、ランサムウェアDLSへの新規掲載、または悪用確認済み（In-the-wild）/PoC公開済みの深刻な脆弱性（グローバル事象を含む）。
   - "Medium": JPCERT/IPA等の注意喚起、週報・まとめ記事、DoSのみの脆弱性、影響が限定的なインシデント。
   - "Low": 悪用やPoCが確認されていない定例のセキュリティパッチ公開、マイナーなバグ修正、技術調査・コラム。
   - "Info": 脅威・脆弱性・侵害と直接関係のない新サービス・機能リリース告知、企業PR、マーケティング情報。

# 事実記載ルール（説教・対策アドバイスの完全禁止）
- summary / summary_ja および impact_analysis / impact_analysis_ja には、原文で確認された【客観的な事実のみ】（誰が被害を受けたか、確認された被害規模・漏洩件数・漏洩項目、侵入経路・攻撃手口、悪用CVE、対象製品および影響バージョン範囲）を簡潔に記述してください。
- 「パッチを適用すべき」「多要素認証（MFA）やIAMの強化が必要」「不審なメールに注意」「従業員教育を実施すべき」といった一般的な対策アドバイス・推奨アクション・教訓・説教的な表現は【一切記述しないでください】。
- CVE識別子（cves）は原文テキストに明記されているもののみを抽出し、記載がない場合は必ず空配列 [] としてください（例示番号の捏造厳禁）。
- 【重要】脅威アクター（threat_actors）の厳格な抽出ルール:
  - タイトルや原文本文中に具体的なサイバー攻撃グループ・APTグループ・ランサムウェア集団の名称が【直接かつ明示的に記載されている場合】は、必ず threat_actors（例: "Qilin", "MirrorFace", "BlackTech", "APT10", "UAT-11473"）として抽出し、victim_orgs や affected_products には絶対に入れないでください。記載がない場合は空配列 [] にしてください。
  - 文脈からの推測や、「中国系APT」「ハッカー」「Cybercriminals」「Attackers」「未確認」等の一般表現の抽出は絶対禁止です。

# 対象インシデント情報
ソース種別: %s
情報源: %s
タイトル: %s
URL: %s
原文本文データ: %s
付加情報: %s

# 出力形式 (必ず以下のJSONフォーマットのみを出力してください。title, summary, impact_analysis はプロフェッショナルな英語で記述してください)
{
    "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
    "japan_relevance": "Direct" | "Indirect" | "None",
    "title": "Concise factual English incident title",
    "summary": "Objective factual summary in English (victim, attack method, compromised systems/data, affected product/versions; NO security advice)",
    "impact_analysis": "Confirmed scope of damage, affected versions, or technical exploitability facts in English (NO recommendations or preaching)",
    "title_ja": "日本語での的確で簡潔な事実ベースのインシデント名",
    "summary_ja": "確認された事実（被害対象・手口・対象製品/バージョン等）の日本語要約（対策助言は書かないこと）",
    "impact_analysis_ja": "確認された被害規模・漏洩件数・影響範囲の客観的事実（推測や対策の説教は書かないこと）",
    "victim_orgs": [],
    "threat_actors": [],
    "threat_actor_reasons": {"ActorName": "Direct quote from source text where this actor was named"},
    "attack_type": "Ransomware" | "Data Breach" | "Zero-day" | "Supply Chain" | "DDoS" | "Phishing" | "Vulnerability" | "Service Release" | "None",
    "cves": [],
    "affected_products": []
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

	prompt := fmt.Sprintf(`あなたは日本を拠点とするサイバー脅威インテリジェンス（CTI）アナリストです。
以下の複数の脅威情報（計 %d 件）の原文データ（"content" フィールド）を精読して個別に分析し、客観的な事実（ファクト）のみを抽出・構造化してください。

# 評価基準（厳守）
1. japan_relevance (日本への関連性):
   - "Direct": 具体的な日本企業・日本の官公庁・自治体・国内組織が実際の被害対象となっている事案、またはJPCERT/CC・IPA・JVNによる公式発信。（※海外製品・海外組織の事案は、日本語メディアの記事であっても "Indirect" または "None" とすること）
   - "Indirect": 日本国内の特定被害組織は確認されていないが、日本でも利用されているソフトウェア・OSの脆弱性やグローバルな攻撃キャンペーン。
   - "None": 日本国内との直接的・間接的な関連性が見られない海外ローカル事象。

2. severity (重要度 - 上方バイアス厳禁):
   - 【絶対ルール1】japan_relevance が "Direct" 以外（"Indirect" または "None"）の場合、"Critical" を付与することは絶対に禁止（最大でも "High" まで）。
   - 【絶対ルール2】具体的な被害組織を伴わない一般的な注意喚起（JPCERT/CC・IPAの注意喚起を含む）、週報・まとめ記事、FAQ、動向レポートは最大でも "Medium" までとすること。
   - "Critical": japan_relevance が "Direct" であり、かつ日本国内の特定組織における深刻な実被害（ランサムウェア感染・大規模情報漏洩・重要システム停止・ゼロデイ悪用による侵害）が確認された事案のみ。
   - "High": 国内組織での不正アクセス・情報漏洩事案、ランサムウェアDLSへの新規掲載、または悪用確認済み（In-the-wild）/PoC公開済みの深刻な脆弱性（グローバル事象を含む）。
   - "Medium": JPCERT/IPA等の注意喚起、週報・まとめ記事、DoSのみの脆弱性、影響が限定的なインシデント。
   - "Low": 悪用やPoCが確認されていない定例のセキュリティパッチ公開、マイナーなバグ修正、技術調査・コラム。
   - "Info": 脅威・脆弱性・侵害と直接関係のない新サービス・機能リリース告知、企業PR、マーケティング情報。

# 事実記載ルール（説教・対策アドバイスの完全禁止）
- summary / summary_ja および impact_analysis / impact_analysis_ja には、原文で確認された【客観的な事実のみ】（被害組織、確認された被害規模・漏洩件数・漏洩項目、侵入経路・攻撃手口、悪用CVE、対象製品および影響バージョン範囲）を記述してください。
- 「パッチを適用すべき」「MFAやIAM強化が必要」「従業員教育を実施すべき」といった一般的な対策アドバイス・推奨アクション・説教的な表現は【一切記述しないでください】。
- CVE識別子（cves）は原文テキストに明記されているもののみを抽出し、記載がない場合は空配列 [] としてください（例示番号の捏造厳禁）。
- 【重要】脅威アクター（threat_actors）はタイトルや原文本文中に具体的なグループ名が【直接かつ明示的に記載されている場合のみ】抽出し、記載がない場合は必ず空配列 [] としてください。推測や一般表現（「ハッカー」「Cybercriminals」「中国系APT」等）は禁止です。

# 対象インシデント一覧 (JSON)
%s

# 出力形式 (必ず入力の各 "index" に対応する JSON 配列のみを出力してください。title, summary, impact_analysis はプロフェッショナルな英語で記述してください)
[
  {
    "index": 0,
    "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
    "japan_relevance": "Direct" | "Indirect" | "None",
    "title": "Concise factual English incident title",
    "summary": "Objective factual summary in English (NO security advice)",
    "impact_analysis": "Confirmed scope of damage, affected versions, or exploitability facts in English (NO recommendations)",
    "title_ja": "日本語での的確で簡潔な事実ベースのインシデント名",
    "summary_ja": "確認された事実の日本語3行以内要約（対策助言は書かないこと）",
    "impact_analysis_ja": "確認された被害規模・漏洩件数・影響範囲の客観的事実（対策の説教は書かないこと）",
    "victim_orgs": [],
    "threat_actors": [],
    "threat_actor_reasons": {"ActorName": "Direct quote from source text where this actor was named"},
    "attack_type": "Ransomware" | "Data Breach" | "Zero-day" | "Supply Chain" | "DDoS" | "Phishing" | "Vulnerability" | "Service Release" | "None",
    "cves": [],
    "affected_products": []
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

// TranslateBatchToJapanese translates multiple incidents into natural, professional Japanese in a single Gemini call.
// It strictly forbids Chinese / Simplified Chinese characters and runs CleanChineseCTITerms as a safeguard.
func (a *GeminiThreatAnalyzer) TranslateBatchToJapanese(ctx context.Context, items []BatchTranslateItem) ([]BatchTranslateResult, error) {
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
	prompt := fmt.Sprintf(`You are an expert Cyber Threat Intelligence (CTI) editor and translator specializing in Japanese cybersecurity terminology.
Translate each incident item in the JSON array from English into professional, fluent, cybersecurity-standard Japanese (suitable for JPCERT/CC or IPA security advisories).

CRITICAL RULES:
1. STRICTLY NO CHINESE CHARACTERS OR PHRASINGS (簡体字や中国語表現は一切禁止):
   - Do NOT use Chinese terms like: 恶意软件 (malware), 攻击者/威胁行为者 (threat actor), 漏洞 (vulnerability), 勒索软件 (ransomware), 钓鱼 (phishing), 数据泄露/泄露 (data breach), 网络安全 (cybersecurity), 不正当访问 (unauthorized access), 个人数据 (personal data), 遭受 (suffered), 宣布 (announced).
   - Use standard Japanese cybersecurity terminology:
     - Malware -> マルウェア
     - Threat actor / Cybercrime group -> 攻撃グループ / 脅威アクター / 攻撃者
     - Vulnerability -> 脆弱性
     - Ransomware -> ランサムウェア
     - Data breach / Leak -> 情報漏洩 / データ侵害
     - Unauthorized access -> 不正アクセス
     - Personal data -> 個人情報
     - Zero-day -> ゼロデイ
     - Exploitation / Attack -> 悪用 / 攻撃
2. MUST CONTAIN HIRAGANA AND KATAKANA:
   - Output MUST be natural Japanese sentences containing Hiragana and Katakana.
3. Keep the 'id' field exactly as provided in the input.
4. 'title' -> concise Japanese headline (title_ja).
5. 'summary' -> 2-3 sentence Japanese technical summary (summary_ja).
6. 'impact_analysis' -> concrete impact and risk evaluation in Japanese (impact_analysis_ja).
7. 'recommended_actions' -> array of strings in Japanese.
8. Return ONLY a valid JSON array corresponding to the input items.

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
			Title:              CleanChineseCTITerms(strings.TrimSpace(raw.Title), true),
			Summary:            CleanChineseCTITerms(strings.TrimSpace(raw.Summary), true),
			ImpactAnalysis:     CleanChineseCTITerms(strings.TrimSpace(raw.ImpactAnalysis), true),
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
	tTitle, tSummary, tImpact, _, err := a.TranslateFieldsToJapanese(
		ctx,
		enriched.Title,
		enriched.Summary,
		enriched.ImpactAnalysis,
		nil,
	)
	if err != nil {
		return err
	}
	enriched.TitleJa = CleanChineseCTITerms(tTitle, true)
	enriched.SummaryJa = CleanChineseCTITerms(tSummary, true)
	enriched.ImpactAnalysisJa = CleanChineseCTITerms(tImpact, true)
	enriched.RecommendedActions = nil
	enriched.RecommendedActionsJa = nil
	return nil
}

