package analyzer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/al17091/threat_harvester/api/internal/models"
)

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
}

type chatCompletionResponse struct {
	ID      string `json:"id"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

type OpenAICompatibleAnalyzer struct {
	client      *http.Client
	endpoint    string
	model       string
	apiKey      string
	temperature float64
}

func NewOpenAICompatibleAnalyzer(endpoint, model, apiKey string, temperature float64, insecureSkipVerify bool, timeoutSec int) *OpenAICompatibleAnalyzer {
	if endpoint == "" {
		endpoint = "https://litellm.lab.internal/v1/chat/completions"
	}
	if model == "" {
		model = "qwen2.5-3b-instruct"
	}
	if timeoutSec <= 0 {
		timeoutSec = 60
	}
	if temperature <= 0 {
		temperature = 0.1
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
	}

	return &OpenAICompatibleAnalyzer{
		client: &http.Client{
			Transport: transport,
			Timeout:   time.Duration(timeoutSec) * time.Second,
		},
		endpoint:    endpoint,
		model:       model,
		apiKey:      apiKey,
		temperature: temperature,
	}
}

// TestConnection performs a lightweight health probe to verify LiteLLM / local model responsiveness.
func (a *OpenAICompatibleAnalyzer) TestConnection(ctx context.Context) bool {
	ctxTimeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	reqBody := chatCompletionRequest{
		Model:       a.model,
		Messages:    []chatMessage{{Role: "user", Content: "ping"}},
		Temperature: 0.1,
		MaxTokens:   1,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return false
	}

	req, err := http.NewRequestWithContext(ctxTimeout, http.MethodPost, a.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

func (a *OpenAICompatibleAnalyzer) sendChatCompletion(ctx context.Context, messages []chatMessage) (string, error) {
	reqBody := chatCompletionRequest{
		Model:       a.model,
		Messages:    messages,
		Temperature: a.temperature,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.apiKey)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("llm request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read llm response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("llm api returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp chatCompletionResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return "", fmt.Errorf("failed to decode llm response: %w", err)
	}

	if chatResp.Error != nil && chatResp.Error.Message != "" {
		return "", fmt.Errorf("llm api error: %s", chatResp.Error.Message)
	}

	if len(chatResp.Choices) == 0 {
		return "", fmt.Errorf("empty choices returned from llm")
	}

	return CleanJSONFences(chatResp.Choices[0].Message.Content), nil
}

func (a *OpenAICompatibleAnalyzer) Analyze(ctx context.Context, item models.ThreatItem) (*models.EnrichedThreat, error) {
	contentToAnalyze := strings.TrimSpace(item.RawContent)
	if contentToAnalyze == "" {
		contentToAnalyze = strings.TrimSpace(item.Summary)
	}
	contentToAnalyze = models.TruncateRunes(contentToAnalyze, 4000)

	metaJSON, _ := json.Marshal(item.Metadata)

	systemPrompt := `You are an elite Cyber Threat Intelligence (CTI) analyst.
Analyze the provided threat intelligence raw text carefully and produce structured analysis in professional English.
Focus heavily on assessing relevance and potential impact on organizations, critical infrastructure, supply chains, and Japanese entities.

# Evaluation Criteria:
1. japan_relevance:
   - "Direct": Targets Japanese companies, government/municipalities, domestic organizations, or Japan-specific supply chains.
   - "Indirect": Global cyber incidents, widespread 0days in enterprise software/OS prevalent in Japan, major global cloud outages.
   - "None": Purely local foreign incidents with no direct or indirect impact on Japanese organizations.

2. severity:
   - "Critical": Actively exploited zero-day, critical infrastructure shutdown, major supply chain breach, enterprise ransomware/leak with high impact.
   - "High": Public PoC for severe vulnerabilities, corporate data leak disclosures, new ransomware DLS victim publication.
   - "Medium": Standard security updates, informational advisories, limited impact incidents.
   - "Low": Minor bug fixes, low-risk technical research, awareness/educational blogs.
   - "Info": New product/feature releases, marketing announcements, non-threat events. (Note: if an update mentions a vulnerability or exploit, classify according to actual threat severity, NOT Info).

# Threat Actor Attribution Rules:
- "threat_actors": Array of specific, recognized threat actor names or cybercrime groups ONLY when explicitly and directly named in the source text.
- STRICT RULE (GROUNDING): You must ONLY include a threat actor if their specific name appears directly in the provided title or raw content.
- If no specific, named threat actor is explicitly mentioned in the source intelligence, you MUST return an empty array [].
- ABSOLUTELY NEVER guess, speculate, extrapolate, or inject threat actor names from prior training data or general background knowledge.
- NEVER copy or hallucinate threat actor names from prompt guidelines or examples. If unsure or if only general tactics/methods are described without a named group, return [].
- NEVER output generic categories, speculative labels, or descriptive phrases such as:
  "Hackers", "Cybercriminals", "Attackers", "Unknown", "Not specified", "AI-assisted attackers",
  "AIを使用した不正アクセスの攻撃者", "AI-driven Threat Actor", "State-sponsored actors",
  "国家支援型アクター", "中国国家支援型アクター", "Chinese APT", "Rogue OpenAI agents", etc.
- IMPORTANT: If a specific cybercrime group or APT is explicitly named in the source article in Chinese, Russian, or another native language, preserve that exact native name AS-IS. Do NOT translate or drop explicitly named groups.

# Language & Output Rules:
- STRICTLY FLUENT PROFESSIONAL ENGLISH ONLY for all textual descriptions ('title', 'summary', 'impact_analysis', 'recommended_actions').
- ABSOLUTELY NEVER output Chinese (Simplified or Traditional) words, characters, or grammar in summary, title, or impact analysis descriptions. Do NOT use terms like "未知威胁", "行为者", "恶意软件", "黑客", "漏洞", "网络安全", etc.
- (Exception: Specific named threat actors in 'threat_actors' should retain their original native name if specified in the source intelligence).
- Return ONLY a valid JSON object matching the following structure. Do NOT include any markdown code fences, greetings, or conversational filler. All text fields must be in English.
{
  "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
  "japan_relevance": "Direct" | "Indirect" | "None",
  "title": "Concise and accurate English incident title",
  "summary": "Technical background and victim impact summary in English (2-3 sentences)",
  "impact_analysis": "Concrete evaluation of threat impact and risks in English",
  "victim_orgs": ["Identified victim organization names"],
  "threat_actors": [],
  "threat_actor_reasons": {"ActorName": "Direct quote from source text where this actor was named"},
  "attack_type": "Ransomware" | "Data Breach" | "Zero-day" | "Supply Chain" | "DDoS" | "Phishing" | "Vulnerability" | "Service Release" | "None",
  "cves": ["CVE identifiers e.g. CVE-2026-9999"],
  "affected_products": ["Affected product/software names e.g. FortiMail, Citrix ADC"],
  "recommended_actions": ["Recommended initial defensive and mitigation steps in English"]
}`

	userPrompt := fmt.Sprintf(`Target Threat Intelligence:
- Source Type: %s
- Source Name: %s
- Title: %s
- URL: %s
- Raw Content: %s
- Metadata: %s`, item.SourceType, item.SourceName, item.Title, item.URL, contentToAnalyze, string(metaJSON))

	messages := []chatMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}

	rawJSON, err := a.sendChatCompletion(ctx, messages)
	if err != nil {
		return nil, err
	}

	var out AnalysisOutput
	if err := json.Unmarshal([]byte(rawJSON), &out); err != nil {
		return nil, fmt.Errorf("failed to parse structured intelligence JSON: %w (raw: %s)", err, rawJSON)
	}

	return BuildEnrichedThreatFromOutput(item, out), nil
}

func (a *OpenAICompatibleAnalyzer) AnalyzeBatch(ctx context.Context, items []models.ThreatItem) ([]*models.EnrichedThreat, error) {
	if len(items) == 0 {
		return nil, nil
	}
	if len(items) == 1 {
		enriched, err := a.Analyze(ctx, items[0])
		if err != nil {
			return nil, err
		}
		return []*models.EnrichedThreat{enriched}, nil
	}

	// Sequential fallback with concurrency limit
	results := make([]*models.EnrichedThreat, len(items))
	for i, it := range items {
		en, err := a.Analyze(ctx, it)
		if err != nil {
			log.Printf("[OpenAICompatibleAnalyzer] Batch item %d failed: %v", i, err)
			// Return fallback
			en = BuildEnrichedThreatFromOutput(it, AnalysisOutput{
				Severity:       string(models.SeverityUnknown),
				JapanRelevance: string(models.JapanRelevanceUnknown),
				Title:          it.Title,
				Summary:        it.Summary,
			})
		}
		results[i] = en
	}
	return results, nil
}

func (a *OpenAICompatibleAnalyzer) GenerateSearchQueries(ctx context.Context, directive string, targetType string, count int) ([]string, error) {
	if count <= 0 {
		count = 3
	}
	currentDate := time.Now().UTC().Format("2006-01-02")
	targetDesc := "Web Search for cyber threat intelligence, ransomware leak disclosures, and exploit advisories"
	if targetType == "darkweb_search" || targetType == "darkweb_onion" {
		targetDesc = "Dark Web search engine (Ahmia/Torch) for ransomware DLS, leak forums, and breach dumps"
	}

	systemPrompt := `You are a senior Cyber Threat Intelligence (CTI) analyst.
Generate concise, high-impact search queries based on the user directive.
Include both English and Japanese keywords/queries where relevant to maximize hit coverage on domestic and international intelligence.
Output ONLY a JSON array of strings, e.g. ["query 1", "query 2"]. No markdown fences or explanations.`

	userPrompt := fmt.Sprintf(`Today is %s.
Generate %d distinct, effective search queries for target platform: %s.
User Monitoring Directive: "%s"

Format: JSON array of %d strings.`, currentDate, count, targetDesc, directive, count)

	messages := []chatMessage{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userPrompt},
	}

	rawJSON, err := a.sendChatCompletion(ctx, messages)
	if err != nil {
		log.Printf("[OpenAICompatibleAnalyzer] GenerateSearchQueries failed: %v", err)
		return []string{directive}, nil
	}

	var queries []string
	if err := json.Unmarshal([]byte(rawJSON), &queries); err != nil {
		log.Printf("[OpenAICompatibleAnalyzer] Failed to unmarshal queries JSON: %v (raw: %s)", err, rawJSON)
		return []string{directive}, nil
	}

	var clean []string
	for _, q := range queries {
		q = strings.TrimSpace(q)
		if q != "" {
			clean = append(clean, q)
		}
	}
	if len(clean) == 0 {
		return []string{directive}, nil
	}
	return clean, nil
}

func (a *OpenAICompatibleAnalyzer) TranslateIncident(ctx context.Context, input IncidentTranslationInput) (*IncidentTranslationOutput, error) {
	inputJSON, _ := json.Marshal(input)

	messages := []chatMessage{
		{
			Role: "system",
			Content: `You are an expert Cyber Threat Intelligence (CTI) editor and translator.
Translate the provided Japanese cybersecurity incident information into professional, fluent, cybersecurity-standard English.
CRITICAL RULES:
- Output fields ('title', 'summary', 'impact_analysis', 'victim_org_en', 'affected_product_en', 'recommended_actions') MUST BE IN FLUENT ENGLISH.
- For 'victim_org_en':
  - If 'victim_org' is in Japanese (e.g. '株式会社ローソン'), output the official or standard English entity name (e.g. 'Lawson, Inc.').
  - If 'victim_org' is already in English or Roman alphabet (e.g. 'Chugoku Bend', 'SonicWall'), keep it exactly as-is.
- For 'affected_product_en':
  - If 'affected_product' is an English software/hardware name (e.g. 'SonicWall SMA 1000', 'WordPress'), keep it as-is.
  - If it has Japanese general descriptions, translate to standard technical English.
- 'recommended_actions' must be an array of strings in English.
- Return ONLY a valid JSON object matching the requested schema, without markdown code fences or conversational filler.`,
		},
		{
			Role:    "user",
			Content: string(inputJSON),
		},
	}

	content, err := a.sendChatCompletion(ctx, messages)
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

	var out struct {
		Title              string          `json:"title"`
		Summary            string          `json:"summary"`
		ImpactAnalysis     string          `json:"impact_analysis"`
		VictimOrgEn        string          `json:"victim_org_en"`
		AffectedProductEn  string          `json:"affected_product_en"`
		RecommendedActions json.RawMessage `json:"recommended_actions"`
	}
	if err := json.Unmarshal([]byte(content), &out); err != nil {
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

	tTitle := strings.TrimSpace(out.Title)
	if tTitle == "" {
		tTitle = input.Title
	}
	tSummary := strings.TrimSpace(out.Summary)
	if tSummary == "" {
		tSummary = input.Summary
	}
	tImpact := strings.TrimSpace(out.ImpactAnalysis)
	if tImpact == "" {
		tImpact = input.ImpactAnalysis
	}
	vOrgEn := strings.TrimSpace(out.VictimOrgEn)
	if vOrgEn == "" {
		vOrgEn = input.VictimOrg
	}
	affProdEn := strings.TrimSpace(out.AffectedProductEn)
	if affProdEn == "" {
		affProdEn = input.AffectedProduct
	}
	tActions := ParseActionsFlexible(out.RecommendedActions)
	if len(tActions) == 0 {
		tActions = input.RecommendedActions
	}

	return &IncidentTranslationOutput{
		ID:                 input.ID,
		Title:              tTitle,
		Summary:            tSummary,
		ImpactAnalysis:     tImpact,
		VictimOrgEn:        vOrgEn,
		AffectedProductEn:  affProdEn,
		RecommendedActions: tActions,
	}, nil
}

func (a *OpenAICompatibleAnalyzer) TranslateIncidentFields(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	out, err := a.TranslateIncident(ctx, IncidentTranslationInput{
		Title:              title,
		Summary:            summary,
		ImpactAnalysis:     impact,
		RecommendedActions: actions,
	})
	if err != nil {
		return title, summary, impact, actions, err
	}
	return out.Title, out.Summary, out.ImpactAnalysis, out.RecommendedActions, nil
}

func (a *OpenAICompatibleAnalyzer) TranslateBatch(ctx context.Context, items []BatchTranslateItem) ([]BatchTranslateResult, error) {
	results := make([]BatchTranslateResult, len(items))
	for i, item := range items {
		out, err := a.TranslateIncident(ctx, IncidentTranslationInput{
			ID:                 item.ID,
			Title:              item.Title,
			Summary:            item.Summary,
			ImpactAnalysis:     item.ImpactAnalysis,
			VictimOrg:          item.VictimOrg,
			AffectedProduct:    item.AffectedProduct,
			RecommendedActions: item.RecommendedActions,
		})
		if err != nil {
			results[i] = BatchTranslateResult{
				ID:                 item.ID,
				Title:              item.Title,
				Summary:            item.Summary,
				ImpactAnalysis:     item.ImpactAnalysis,
				VictimOrgEn:        item.VictimOrg,
				AffectedProductEn:  item.AffectedProduct,
				RecommendedActions: item.RecommendedActions,
			}
			continue
		}
		results[i] = BatchTranslateResult{
			ID:                 item.ID,
			Title:              out.Title,
			Summary:            out.Summary,
			ImpactAnalysis:     out.ImpactAnalysis,
			VictimOrgEn:        out.VictimOrgEn,
			AffectedProductEn:  out.AffectedProductEn,
			RecommendedActions: out.RecommendedActions,
		}
	}
	return results, nil
}

// TranslateFieldsToJapanese is a fallback on OpenAICompatibleAnalyzer (primary uses English).
func (a *OpenAICompatibleAnalyzer) TranslateFieldsToJapanese(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error) {
	return title, summary, impact, actions, fmt.Errorf("japanese translation not supported directly on primary local model")
}

// LocalizeThreatToJapanese is a fallback on OpenAICompatibleAnalyzer.
func (a *OpenAICompatibleAnalyzer) LocalizeThreatToJapanese(ctx context.Context, enriched *models.EnrichedThreat) error {
	return nil
}

