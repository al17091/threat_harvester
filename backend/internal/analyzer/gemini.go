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
	"time"

	"github.com/dapt/information_harvester/backend/internal/config"
	"github.com/dapt/information_harvester/backend/internal/models"
)

type GeminiThreatAnalyzer struct {
	client *http.Client
}

func NewGeminiThreatAnalyzer() *GeminiThreatAnalyzer {
	return &GeminiThreatAnalyzer{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
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
	Severity             string   `json:"severity"`
	JapanRelevance       string   `json:"japan_relevance"`
	TitleJa              string   `json:"title_ja"`
	SummaryJa            string   `json:"summary_ja"`
	ImpactAnalysisJa     string   `json:"impact_analysis_ja"`
	VictimOrgs           []string `json:"victim_orgs"`
	ThreatActors         []string `json:"threat_actors"`
	AttackType           string   `json:"attack_type"`
	RecommendedActionsJa []string `json:"recommended_actions_ja"`
}

func (a *GeminiThreatAnalyzer) Analyze(ctx context.Context, item models.ThreatItem) (*models.EnrichedThreat, error) {
	cfg := config.GetSettings().GetConfig()
	apiKey := cfg.AI.GeminiAPIKey
	model := cfg.AI.GeminiModel
	if model == "" {
		model = "gemini-2.5-flash"
	}

	if apiKey == "" {
		log.Printf("[Analyzer] Gemini API key not configured. Returning basic enrichment for %s", item.Title)
		summaryJa := models.TruncateRunes(item.Summary, 200)
		return &models.EnrichedThreat{
			ItemID:               item.ID,
			Item:                 item,
			Severity:             models.SeverityUnknown,
			JapanRelevance:       models.JapanRelevanceUnknown,
			TitleJa:              item.Title,
			SummaryJa:            summaryJa,
			ImpactAnalysisJa:     "Gemini APIキーが未設定のため未分析です。",
			VictimOrgs:           nil,
			ThreatActors:         nil,
			RecommendedActionsJa: nil,
			AnalyzedAt:           time.Now().UTC(),
		}, nil
	}

	metaJSON, _ := json.Marshal(item.Metadata)
	prompt := fmt.Sprintf(`
あなたは日本を拠点とする最高峰のサイバー脅威インテリジェンス（CTI）アナリストです。
以下の脅威情報を分析し、特に「日本国内の組織・企業・政府・インフラへの影響」を最重要視して評価してください。

# 評価基準
1. japan_relevance (日本への関連性):
   - "Direct": 被害対象が日本企業、日本の官公庁・自治体、国内組織、または日本特有のサプライチェーン。
   - "Indirect": 世界規模の大規模攻撃（日本でも普及している製品・OSの悪用中ゼロデイ、グローバルクラウド障害等）。
   - "None": 日本国内への直接的・間接的な関連性がほぼ見られない事象。

2. severity (重要度):
   - "Critical": 悪用確認済みのゼロデイ、国内主要インフラ停止、大規模サプライチェーン侵害、日本大手組織へのランサムウェア・データ破綻。
   - "High": PoC公開済み深刻脆弱性、国内組織の情報漏洩発表、ランサムウェアDLSへの新規掲載。
   - "Medium": 通常のセキュリティアップデート、注意喚起、影響が限定的なインシデント。
   - "Low": 製品宣伝、マイナーなバグ修正、コラム。

# 対象インシデント情報
ソース種別: %s
情報源: %s
タイトル: %s
URL: %s
本文/要約: %s
付加情報: %s

# 出力形式 (必ず以下のJSONフォーマットのみを出力してください)
{
    "severity": "Critical" | "High" | "Medium" | "Low",
    "japan_relevance": "Direct" | "Indirect" | "None",
    "title_ja": "日本語での的確で簡潔なインシデント名",
    "summary_ja": "技術的背景と被害状況の日本語3行以内要約",
    "impact_analysis_ja": "日本国内への具体的な影響・脅威評価",
    "victim_orgs": ["被害組織名（判明している場合）"],
    "threat_actors": ["関与している攻撃グループ名（判明している場合）"],
    "attack_type": "Ransomware" | "Data Breach" | "Zero-day" | "Supply Chain" | "DDoS" | "Phishing" | "Vulnerability",
    "recommended_actions_ja": ["推奨される初動対応・防御策"]
}
`, item.SourceType, item.SourceName, item.Title, item.URL, item.Summary, string(metaJSON))

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

	rawJSONText := geminiResp.Candidates[0].Content.Parts[0].Text
	rawJSONText = strings.TrimPrefix(rawJSONText, "```json")
	rawJSONText = strings.TrimPrefix(rawJSONText, "```")
	rawJSONText = strings.TrimSuffix(rawJSONText, "```")
	rawJSONText = strings.TrimSpace(rawJSONText)

	var out analysisOutput
	if err := json.Unmarshal([]byte(rawJSONText), &out); err != nil {
		return nil, fmt.Errorf("failed to parse structured intelligence JSON: %w (raw: %s)", err, rawJSONText)
	}

	severity := models.Severity(out.Severity)
	switch severity {
	case models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow:
	default:
		severity = models.SeverityUnknown
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
		AttackType:           out.AttackType,
		RecommendedActionsJa: out.RecommendedActionsJa,
		AnalyzedAt:           time.Now().UTC(),
	}, nil
}
