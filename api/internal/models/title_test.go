package models

import (
	"strings"
	"testing"
)

func TestCleanRawIncidentTitle(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    `マンゼンADHD on X: "【GMOお名前.com VPS不正アクセス事件 ...`,
			expected: `【GMOお名前.com VPS不正アクセス事件 ...`,
		},
		{
			input:    `天坂らいとγ on X: "不正アクセス被害1億件ってすごいな。" / X`,
			expected: `不正アクセス被害1億件ってすごいな。`,
		},
		{
			input:    `ii4gsp (@ii4gsp) on X: "LibreOffice RCE — just opening the spreadsheet ..."`,
			expected: `LibreOffice RCE — just opening the spreadsheet ...`,
		},
		{
			input:    `政府システム 侵入許す 会議資料など流出か 9月に続き (毎日新聞)`,
			expected: `政府システム 侵入許す 会議資料など流出か 9月に続き`,
		},
		{
			input:    `【速報】ランサムウェア被害で病院の電子カルテが停止 - 日本経済新聞`,
			expected: `ランサムウェア被害で病院の電子カルテが停止`,
		},
		{
			input:    `【独自】大規模データ流出の疑い | NHKニュース`,
			expected: `大規模データ流出の疑い`,
		},
	}

	for _, tt := range tests {
		got := CleanRawIncidentTitle(tt.input)
		if got != tt.expected {
			t.Errorf("CleanRawIncidentTitle(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestIsNoisySocialMediaTitle(t *testing.T) {
	noisy := []string{
		`CCSは誘発地震を起こす可能性ある on X: "@jimin_koho ..."`,
		`@someone これってランサムウェアじゃない？`,
		`天坂らいとγ on X: "不正アクセス被害1億件ってすごいな。" / X`,
		`県庁に殺された女（はる） on X: "メルカリのこと信頼できなくなっ ..."`,
		`Evening (Sophia.R) on X: "結局、単年度予算主義という ..."`,
		` ‍♂️`,
	}

	for _, title := range noisy {
		if !IsNoisySocialMediaTitle(title) {
			t.Errorf("expected title to be detected as noisy: %q", title)
		}
	}

	legit := []string{
		`【GMOお名前.com VPS不正アクセス事件】サーバー侵害による情報流出`,
		`LibreOffice RCE — opening malicious spreadsheet executes code`,
		`六花亭、クレジットカード不正利用確認 情報流出で被害1件、5万円`,
		`Apache HTTP Server における重大なリモートコード実行の脆弱性 (CVE-2026-1234)`,
	}

	for _, title := range legit {
		if IsNoisySocialMediaTitle(title) {
			t.Errorf("expected legitimate title NOT to be noisy: %q", title)
		}
	}
}

func TestSynthesizeIncidentTitles(t *testing.T) {
	// 1. Vulnerability incident
	itemVuln := ThreatItem{Title: `ii4gsp on X: "LibreOffice RCE — just opening the spreadsheet ..."`}
	enTitle, jaTitle := SynthesizeIncidentTitles(itemVuln, nil, "", "LibreOffice", []string{"CVE-2026-1111"}, "Vulnerability", nil)
	if !strings.HasPrefix(jaTitle, "【脆弱性】") || !strings.Contains(jaTitle, "LibreOffice") || !strings.Contains(jaTitle, "CVE-2026-1111") {
		t.Errorf("unexpected synthesized vulnerability jaTitle: %q", jaTitle)
	}
	if !strings.HasPrefix(enTitle, "[Vulnerability]") || !strings.Contains(enTitle, "LibreOffice") {
		t.Errorf("unexpected synthesized vulnerability enTitle: %q", enTitle)
	}

	// 2. Ransomware incident with threat actor and victim
	itemRansom := ThreatItem{Title: `FalconFeeds.io on X: "Ransomware Alert: TopGroup listed on Qilin DLS"`}
	enRansom, jaRansom := SynthesizeIncidentTitles(itemRansom, nil, "TopGroup", "", nil, "Ransomware", []string{"Qilin"})
	if !strings.HasPrefix(jaRansom, "【ランサムウェア】") || !strings.Contains(jaRansom, "TopGroup") || !strings.Contains(jaRansom, "Qilin") {
		t.Errorf("unexpected synthesized ransomware jaTitle: %q", jaRansom)
	}
	if !strings.HasPrefix(enRansom, "[Ransomware]") || !strings.Contains(enRansom, "TopGroup") {
		t.Errorf("unexpected synthesized ransomware enTitle: %q", enRansom)
	}

	// 3. Data breach incident with victim
	itemBreach := ThreatItem{Title: `マンゼンADHD on X: "【GMOお名前.com VPS不正アクセス事件 ..."`}
	enBreach, jaBreach := SynthesizeIncidentTitles(itemBreach, nil, "GMOお名前.com", "", nil, "Data Breach", nil)
	if !strings.HasPrefix(jaBreach, "【不正アクセス】") || !strings.Contains(jaBreach, "GMOお名前.com") {
		t.Errorf("unexpected synthesized data breach jaTitle: %q", jaBreach)
	}
	if !strings.HasPrefix(enBreach, "[Data Breach]") || !strings.Contains(enBreach, "GMOお名前.com") {
		t.Errorf("unexpected synthesized data breach enTitle: %q", enBreach)
	}

	// 4. Incident with high quality AI-provided candidate title
	enrichedGood := &EnrichedThreat{
		Title:   "Unauthorized Access into Government Infrastructure",
		TitleJa: "【不正アクセス】政府共通基盤システムへの不正侵入および会議資料流出事案",
	}
	itemGov := ThreatItem{Title: `政府システム 侵入許す 会議資料など流出か 9月に続き (毎日新聞)`}
	enGov, jaGov := SynthesizeIncidentTitles(itemGov, enrichedGood, "デジタル庁", "", nil, "Unauthorized Access", nil)
	if jaGov != "【不正アクセス】政府共通基盤システムへの不正侵入および会議資料流出事案" {
		t.Errorf("expected AI title to be preserved when good: %q", jaGov)
	}
	if enGov != "Unauthorized Access into Government Infrastructure" {
		t.Errorf("expected AI English title to be preserved when good: %q", enGov)
	}
}
