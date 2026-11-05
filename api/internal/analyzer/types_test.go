package analyzer

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/al17091/threat_harvester/api/internal/models"
)

func TestTypesAndHelpers(t *testing.T) {
	// 1. Test ParseActionsFlexible with array JSON
	rawArr := json.RawMessage(`["Action 1", "Action 2"]`)
	arrActions := ParseActionsFlexible(rawArr)
	if len(arrActions) != 2 || arrActions[0] != "Action 1" {
		t.Errorf("expected 2 actions from array, got %v", arrActions)
	}

	// Test ParseActionsFlexible with multiline string JSON
	rawMultiline := json.RawMessage(`"- Step 1\n* Step 2\n3. Step 3"`)
	strActions := ParseActionsFlexible(rawMultiline)
	if len(strActions) < 2 {
		t.Errorf("expected multiline parsed actions, got %v", strActions)
	}

	// Test ParseActionsFlexible with nil
	emptyActions := ParseActionsFlexible(nil)
	if len(emptyActions) != 0 {
		t.Errorf("expected empty actions for nil, got %v", emptyActions)
	}

	// 2. Test BuildEnrichedThreatFromOutput
	item := models.ThreatItem{
		ID:          "threat-item-001",
		Title:       "Sample Threat",
		HarvestedAt: time.Now(),
	}
	out := AnalysisOutput{
		Severity:             "Critical",
		JapanRelevance:       "Direct",
		Title:                "Enriched Title EN",
		TitleJa:              "脅威タイトル JA",
		Summary:              "Summary text EN",
		SummaryJa:            "要約テキスト JA",
		ImpactAnalysis:       "Impact analysis EN",
		ImpactAnalysisJa:     "影響分析 JA",
		VictimOrgs:           []string{"Company Alpha"},
		ThreatActors:         []string{"APT99"},
		RecommendedActions:   []string{"Block C2"},
		RecommendedActionsJa: []string{"C2通信の遮断"},
	}

	enriched := BuildEnrichedThreatFromOutput(item, out)
	if enriched == nil {
		t.Fatalf("expected non-nil enriched threat")
	}
	if enriched.Severity != models.SeverityCritical {
		t.Errorf("expected Critical, got %s", enriched.Severity)
	}
	if enriched.JapanRelevance != models.JapanRelevanceDirect {
		t.Errorf("expected Direct, got %s", enriched.JapanRelevance)
	}
	if enriched.TitleJa != "脅威タイトル JA" {
		t.Errorf("expected TitleJa '脅威タイトル JA', got '%s'", enriched.TitleJa)
	}

	// 3. Test ResolveThreatActorReasons
	itemReason := models.ThreatItem{
		SourceName: "ThreatIntel Org",
		RawContent: "APT99 is suspected to be behind this breach due to overlapping C2 infrastructure.",
	}
	reasons := ResolveThreatActorReasons(itemReason, []string{"APT99"}, map[string]string{"APT99": "Overlapping C2 infrastructure"})
	if len(reasons) == 0 || reasons["APT99"] == "" {
		t.Errorf("expected extracted reason snippet for APT99, got %v", reasons)
	}
}

func TestOpenAICompatibleAnalyzerTestConnection(t *testing.T) {
	// Test Connection failure
	badAI := NewOpenAICompatibleAnalyzer("http://127.0.0.1:9/v1", "model", "key", 0.0, false, 1)
	if badAI.TestConnection(context.Background()) {
		t.Errorf("expected TestConnection to fail for unreachable endpoint")
	}
}

func TestFlexibleStringSlice(t *testing.T) {
	// Test standard []string
	var f1 FlexibleStringSlice
	if err := json.Unmarshal([]byte(`["Actor1", "Actor2"]`), &f1); err != nil || len(f1) != 2 {
		t.Fatalf("failed standard slice: %v, len=%d", err, len(f1))
	}

	// Test single string
	var f2 FlexibleStringSlice
	if err := json.Unmarshal([]byte(`"SingleActor"`), &f2); err != nil || len(f2) != 1 || f2[0] != "SingleActor" {
		t.Fatalf("failed single string: %v, val=%v", err, f2)
	}

	// Test nested [][]string (the exact issue causing Qwen unmarshal failure)
	var f3 FlexibleStringSlice
	if err := json.Unmarshal([]byte(`[["NestedActor1", "NestedActor2"]]`), &f3); err != nil || len(f3) != 2 {
		t.Fatalf("failed nested slice: %v, len=%d", err, len(f3))
	}

	// Test slice of objects
	var f4 FlexibleStringSlice
	if err := json.Unmarshal([]byte(`[{"name": "ObjActor"}]`), &f4); err != nil || len(f4) != 1 || f4[0] != "ObjActor" {
		t.Fatalf("failed obj slice: %v, val=%v", err, f4)
	}

	// Test null
	var f5 FlexibleStringSlice
	if err := json.Unmarshal([]byte(`null`), &f5); err != nil || f5 != nil {
		t.Fatalf("failed null slice: %v, val=%v", err, f5)
	}
}

func TestCreateBaselineEnrichedThreat(t *testing.T) {
	item := models.NewThreatItem(
		models.SourceTypeWebSearch,
		"SearXNG Web",
		"人気ゲーム「NIKKE」公式PCランチャーで不正プログラム実行か CDN上でスクリプト改ざん",
		"https://example.com/nikke",
		"Summary",
		"Raw",
		nil,
		nil,
	)

	en := CreateBaselineEnrichedThreat(item)
	if en == nil {
		t.Fatalf("expected non-nil baseline enriched threat")
	}
	if en.Severity != models.SeverityHigh {
		t.Errorf("expected SeverityHigh for NIKKE, got %s", en.Severity)
	}
	if en.JapanRelevance != models.JapanRelevanceDirect {
		t.Errorf("expected JapanRelevanceDirect for NIKKE, got %s", en.JapanRelevance)
	}
}

