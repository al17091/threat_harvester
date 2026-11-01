package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/al17091/threat_harvester/api/internal/models"
)

// BatchTranslateItem defines input structure for incident translation.
type BatchTranslateItem struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Summary            string   `json:"summary"`
	ImpactAnalysis     string   `json:"impact_analysis"`
	VictimOrg          string   `json:"victim_org,omitempty"`
	AffectedProduct    string   `json:"affected_product,omitempty"`
	RecommendedActions []string `json:"recommended_actions,omitempty"`
}

// BatchTranslateResult defines translated output structure.
type BatchTranslateResult struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Summary            string   `json:"summary"`
	ImpactAnalysis     string   `json:"impact_analysis"`
	VictimOrgEn        string   `json:"victim_org_en,omitempty"`
	AffectedProductEn  string   `json:"affected_product_en,omitempty"`
	RecommendedActions []string `json:"recommended_actions"`
}

// IncidentTranslationInput defines input for translating an entire incident.
type IncidentTranslationInput struct {
	ID                 string   `json:"id,omitempty"`
	Title              string   `json:"title"`
	Summary            string   `json:"summary"`
	ImpactAnalysis     string   `json:"impact_analysis"`
	VictimOrg          string   `json:"victim_org,omitempty"`
	AffectedProduct    string   `json:"affected_product,omitempty"`
	RecommendedActions []string `json:"recommended_actions,omitempty"`
}

// IncidentTranslationOutput defines translated English incident fields.
type IncidentTranslationOutput struct {
	ID                 string   `json:"id,omitempty"`
	Title              string   `json:"title"`
	Summary            string   `json:"summary"`
	ImpactAnalysis     string   `json:"impact_analysis"`
	VictimOrgEn        string   `json:"victim_org_en,omitempty"`
	AffectedProductEn  string   `json:"affected_product_en,omitempty"`
	RecommendedActions []string `json:"recommended_actions,omitempty"`
}

// ThreatAnalyzer defines common capabilities for AI threat intelligence analysis.
type ThreatAnalyzer interface {
	Analyze(ctx context.Context, item models.ThreatItem) (*models.EnrichedThreat, error)
	AnalyzeBatch(ctx context.Context, items []models.ThreatItem) ([]*models.EnrichedThreat, error)
	GenerateSearchQueries(ctx context.Context, directive string, targetType string, count int) ([]string, error)
	TranslateIncidentFields(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error)
	TranslateFieldsToJapanese(ctx context.Context, title, summary, impact string, actions []string) (string, string, string, []string, error)
	LocalizeThreatToJapanese(ctx context.Context, enriched *models.EnrichedThreat) error
	TranslateIncident(ctx context.Context, input IncidentTranslationInput) (*IncidentTranslationOutput, error)
	TranslateBatch(ctx context.Context, items []BatchTranslateItem) ([]BatchTranslateResult, error)
	TranslateBatchToJapanese(ctx context.Context, items []BatchTranslateItem) ([]BatchTranslateResult, error)
}

// AnalysisOutput represents the structured JSON output from LLM analysis.
type AnalysisOutput struct {
	Index                int      `json:"index,omitempty"`
	Severity             string   `json:"severity"`
	JapanRelevance       string   `json:"japan_relevance"`
	Title                string   `json:"title,omitempty"`
	TitleEn              string   `json:"title_en,omitempty"`
	TitleJa              string   `json:"title_ja,omitempty"`
	Summary              string   `json:"summary,omitempty"`
	SummaryEn            string   `json:"summary_en,omitempty"`
	SummaryJa            string   `json:"summary_ja,omitempty"`
	ImpactAnalysis       string   `json:"impact_analysis,omitempty"`
	ImpactAnalysisEn     string   `json:"impact_analysis_en,omitempty"`
	ImpactAnalysisJa     string   `json:"impact_analysis_ja,omitempty"`
	VictimOrgs           []string          `json:"victim_orgs"`
	ThreatActors         []string          `json:"threat_actors"`
	ThreatActorReasons   map[string]string `json:"threat_actor_reasons,omitempty"`
	AttackType           string            `json:"attack_type"`
	CVEs                 []string          `json:"cves,omitempty"`
	AffectedProducts     []string          `json:"affected_products,omitempty"`
	RecommendedActions   []string          `json:"recommended_actions,omitempty"`
	RecommendedActionsEn []string          `json:"recommended_actions_en,omitempty"`
	RecommendedActionsJa []string          `json:"recommended_actions_ja,omitempty"`
}

// ResolveThreatActorReasons normalizes LLM-provided reasons and falls back to extracting context snippets from the ThreatItem.
func ResolveThreatActorReasons(item models.ThreatItem, cleanActors []string, rawReasons map[string]string) map[string]string {
	if len(cleanActors) == 0 {
		return nil
	}
	reasons := make(map[string]string, len(cleanActors))
	srcLabel := strings.TrimSpace(item.SourceName)
	if srcLabel == "" {
		srcLabel = string(item.SourceType)
	}

	for _, actor := range cleanActors {
		var matchedReason string
		for k, v := range rawReasons {
			if strings.EqualFold(strings.TrimSpace(k), actor) && strings.TrimSpace(v) != "" {
				matchedReason = strings.TrimSpace(v)
				break
			}
		}
		if matchedReason != "" {
			if srcLabel != "" && !strings.Contains(strings.ToLower(matchedReason), strings.ToLower(srcLabel)) {
				matchedReason = fmt.Sprintf("[%s] %s", srcLabel, matchedReason)
			}
			reasons[actor] = matchedReason
			continue
		}

		// Automatic snippet extraction from item fields
		if snip := models.ExtractActorSnippet(item.Title, actor, 140); snip != "" {
			reasons[actor] = fmt.Sprintf("[%s] Mentioned in report title: \"%s\"", srcLabel, snip)
			continue
		}
		if snip := models.ExtractActorSnippet(item.RawContent, actor, 160); snip != "" {
			reasons[actor] = fmt.Sprintf("[%s] Mentioned in report body: \"%s\"", srcLabel, snip)
			continue
		}
		if snip := models.ExtractActorSnippet(item.Summary, actor, 160); snip != "" {
			reasons[actor] = fmt.Sprintf("[%s] Mentioned in report summary: \"%s\"", srcLabel, snip)
			continue
		}
		if item.Metadata != nil {
			metaBytes, _ := json.Marshal(item.Metadata)
			if snip := models.ExtractActorSnippet(string(metaBytes), actor, 140); snip != "" {
				reasons[actor] = fmt.Sprintf("[%s] Attributed in feed metadata: %s", srcLabel, snip)
				continue
			}
		}
		reasons[actor] = fmt.Sprintf("[%s] Identified by AI analysis from report context", srcLabel)
	}
	return reasons
}

// CleanJSONFences removes markdown code fences around JSON outputs.
func CleanJSONFences(raw string) string {
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	return strings.TrimSpace(raw)
}

// ParseActionsFlexible parses recommended actions from either a string slice or a single string with newlines.
func ParseActionsFlexible(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		var res []string
		for _, a := range arr {
			a = strings.TrimSpace(a)
			if a != "" {
				res = append(res, a)
			}
		}
		return res
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil
		}
		lines := strings.Split(s, "\n")
		var clean []string
		for _, l := range lines {
			l = strings.TrimSpace(l)
			l = strings.TrimLeft(l, "-*0123456789. ")
			l = strings.TrimSpace(l)
			if l != "" {
				clean = append(clean, l)
			}
		}
		if len(clean) > 0 {
			return clean
		}
		return []string{s}
	}
	return nil
}

// BuildEnrichedThreatFromOutput builds models.EnrichedThreat from raw AnalysisOutput.
func BuildEnrichedThreatFromOutput(item models.ThreatItem, out AnalysisOutput) *models.EnrichedThreat {
	severity := models.Severity(out.Severity)
	switch severity {
	case models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo:
	default:
		severity = models.SeverityUnknown
	}

	attackType := out.AttackType
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

	// Resolve title (prefer English, fallback to Ja or item title)
	title := out.Title
	if title == "" {
		title = out.TitleEn
	}
	if title == "" {
		title = out.TitleJa
	}
	if title == "" {
		title = item.Title
	}

	// Resolve summary
	summary := out.Summary
	if summary == "" {
		summary = out.SummaryEn
	}
	if summary == "" {
		summary = out.SummaryJa
	}
	if summary == "" {
		summary = item.Summary
	}

	// Resolve impact analysis
	impact := out.ImpactAnalysis
	if impact == "" {
		impact = out.ImpactAnalysisEn
	}
	if impact == "" {
		impact = out.ImpactAnalysisJa
	}

	// Resolve recommended actions
	actions := out.RecommendedActions
	if len(actions) == 0 {
		actions = out.RecommendedActionsEn
	}
	if len(actions) == 0 {
		actions = out.RecommendedActionsJa
	}

	// Extract & merge CVEs
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

	// Extract & merge Affected products
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

	titleJa := strings.TrimSpace(out.TitleJa)
	if titleJa == "" {
		if models.IsJapaneseText(item.Title) {
			titleJa = strings.TrimSpace(item.Title)
		} else {
			titleJa = title
		}
	}
	summaryJa := strings.TrimSpace(out.SummaryJa)
	if summaryJa == "" {
		if models.IsJapaneseText(item.Summary) {
			summaryJa = strings.TrimSpace(item.Summary)
		} else {
			summaryJa = summary
		}
	}
	impactJa := strings.TrimSpace(out.ImpactAnalysisJa)
	if impactJa == "" {
		impactJa = impact
	}
	actionsJa := out.RecommendedActionsJa
	if len(actionsJa) == 0 {
		actionsJa = actions
	}

	title = CleanChineseCTITerms(title, false)
	titleJa = CleanChineseCTITerms(titleJa, true)
	summary = CleanChineseCTITerms(summary, false)
	summaryJa = CleanChineseCTITerms(summaryJa, true)
	impact = CleanChineseCTITerms(impact, false)
	impactJa = CleanChineseCTITerms(impactJa, true)

	metaBytes, _ := json.Marshal(item.Metadata)
	groundedActors := models.FilterGroundedThreatActors(
		out.ThreatActors,
		item.Title,
		item.Summary,
		item.RawContent,
		item.URL,
		string(metaBytes),
	)
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
		ImpactAnalysisJa:     impactJa,
		VictimOrgs:           out.VictimOrgs,
		ThreatActors:         groundedActors,
		ThreatActorReasons:   actorReasons,
		AttackType:           attackType,
		CVEs:                 uniqueCVEs,
		AffectedProducts:     affectedProducts,
		RecommendedActions:   actions,
		RecommendedActionsJa: actionsJa,
		AnalyzedAt:           time.Now().UTC(),
	}
}

// CleanChineseCTITerms replaces recurring Chinese/Simplified Chinese CTI terminology leaked by models with standard terminology.
func CleanChineseCTITerms(s string, isJa bool) string {
	if s == "" {
		return s
	}

	type replacement struct {
		cn string
		ja string
		en string
	}

	terms := []replacement{
		{cn: "恶意软件", ja: "マルウェア", en: "Malware"},
		{cn: "勒索软件", ja: "ランサムウェア", en: "Ransomware"},
		{cn: "威胁行为者", ja: "脅威アクター", en: "Threat Actor"},
		{cn: "网络安全", ja: "サイバーセキュリティ", en: "Cybersecurity"},
		{cn: "数据泄露", ja: "データ漏洩", en: "Data Breach"},
		{cn: "犯罪集团", ja: "サイバー犯罪グループ", en: "Cybercrime Group"},
		{cn: "黑客", ja: "攻撃者", en: "Attackers"},
		{cn: "漏洞", ja: "脆弱性", en: "Vulnerability"},
		{cn: "钓鱼", ja: "フィッシング", en: "Phishing"},
		{cn: "不正当访问", ja: "不正アクセス", en: "Unauthorized Access"},
		{cn: "不正当", ja: "不正な", en: "Unauthorized"},
		{cn: "非法入侵", ja: "不正アクセス", en: "Unauthorized Intrusion"},
		{cn: "不法访问", ja: "不正アクセス", en: "Unauthorized Access"},
		{cn: "未经授权的访问", ja: "不正アクセス", en: "Unauthorized Access"},
		{cn: "未经授权", ja: "未認可の", en: "Unauthorized"},
		{cn: "个人数据泄露", ja: "個人情報漏洩", en: "Personal Data Leak"},
		{cn: "个人数据", ja: "個人情報", en: "Personal Data"},
		{cn: "数据泄露", ja: "データ漏洩", en: "Data Breach"},
		{cn: "泄露", ja: "漏洩", en: "Leak"},
		{cn: "被盗", ja: "窃取", en: "Stolen"},
		{cn: "遭勒索", ja: "ランサムウェア被害を受け", en: "Suffered Ransomware Attack"},
		{cn: "赎金", ja: "身代金", en: "Ransom"},
		{cn: "两阶段认证", ja: "2段階認証", en: "Two-Factor Authentication"},
		{cn: "兩階段認證", ja: "2段階認証", en: "Two-Factor Authentication"},
		{cn: "关于", ja: "に関する", en: "Regarding"},
		{cn: "针对", ja: "向け", en: "Targeting"},
		{cn: "修复旧版本中的安全漏洞", ja: "旧バージョンのセキュリティ脆弱性を修正", en: "Fixed security vulnerabilities in older versions"},
		{cn: "更新版本", ja: "アップデート", en: "Update Version"},
		{cn: "解决了", ja: "修正しました", en: "Resolved"},
		{cn: "调查结果公布", ja: "調査結果公表", en: "Investigation Results Disclosed"},
		{cn: "宣布", ja: "発表", en: "Announced"},
		{cn: "遭受", ja: "被害を受け", en: "Suffered"},
		{cn: "邮件杂志", ja: "メールマガジン", en: "Newsletter"},
		{cn: "零日漏洞", ja: "ゼロデイ脆弱性", en: "Zero-day Vulnerability"},
		{cn: "后门", ja: "バックドア", en: "Backdoor"},
		{cn: "木马", ja: "トロイの木馬", en: "Trojan"},
		{cn: "间谍软件", ja: "スパイウェア", en: "Spyware"},
		{cn: "攻击活动", ja: "攻撃活動", en: "Attack Campaign"},
		{cn: "云计算", ja: "クラウド", en: "Cloud"},
		{cn: "报道指出", ja: "報道によると", en: "Reports indicate"},
		{cn: "据悉", ja: "報道によると", en: "According to sources"},
		{cn: "根据报告", ja: "レポートによると", en: "According to the report"},
		{cn: "未确认", ja: "未確認", en: "Unconfirmed"},
		{cn: "未提及", ja: "言及なし", en: "Not specified"},
		{cn: "非法访问", ja: "不正アクセス", en: "Unauthorized Access"},
		{cn: "子公司", ja: "子会社", en: "Subsidiary"},
		{cn: "遭遇的", ja: "", en: ""},
		{cn: "导致", ja: "により", en: "resulting in"},
		{cn: "客户", ja: "顧客", en: "Customers"},
		{cn: "东证主板上市公司", ja: "東証プライム上場企業の", en: "TSE-listed company"},
		{cn: "公司発表，其", ja: "社は、その", en: "announced that its"},
		{cn: "电商巨头", ja: "大手小売", en: "Major Retailer"},
		{cn: "巨头", ja: "大手", en: "Major"},
		{cn: "其服务器", ja: "サーバーが", en: "its servers"},
		{cn: "导致约", ja: "約", en: "approximately"},
		{cn: "名会员的个人信息被漏洩", ja: "名の会員の個人情報が漏洩", en: "members' personal information was leaked"},
		{cn: "该公司已暂停相关服务并通知受影响的客户", ja: "同社は関連サービスを停止し、影響を受ける顧客に通知を行っています", en: "The company suspended related services and notified affected customers"},
		{cn: "用户个人信息", ja: "ユーザーの個人情報", en: "user personal information"},
		{cn: "窃取取", ja: "窃取", en: "stolen"},
		{cn: "盗取", ja: "窃取", en: "stolen"},
		{cn: "超过", ja: "超の", en: "over"},
		{cn: "个电子邮件地址及其他信息", ja: "件のメールアドレスおよびその他の個人情報", en: "email addresses and other personal information"},
		{cn: "个人身份信息", ja: "個人情報", en: "personal identifiable information"},
		{cn: "的网络访问", ja: "のネットワークアクセス", en: "network access"},
		{cn: "调查结果显示约", ja: "調査の結果、約", en: "investigation results show approximately"},
		{cn: "已漏洩", ja: "漏洩した可能性があります", en: "may have been leaked"},
		{cn: "已暂停", ja: "停止し", en: "suspended"},
		{cn: "相关服务", ja: "関連サービス", en: "related services"},
		{cn: "受影响的客户", ja: "影響を受ける顧客", en: "affected customers"},
		{cn: "非法", ja: "不正", en: "unauthorized"},
	}

	res := s
	for _, t := range terms {
		if strings.Contains(res, t.cn) {
			if isJa {
				res = strings.ReplaceAll(res, t.cn, t.ja)
			} else {
				res = strings.ReplaceAll(res, t.cn, t.en)
			}
		}
	}
	return res
}

