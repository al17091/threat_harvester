import json
import logging

from google import genai
from google.genai import types

from worker.config import settings
from worker.models import EnrichedThreat, JapanRelevance, Severity, ThreatItem

logger = logging.getLogger(__name__)


class GeminiThreatAnalyzer:
    """Analyzes raw threat items to assess Japan-target relevance, severity, and actionable insights."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or settings.gemini_api_key
        self.model = model or settings.gemini_model
        self.client = genai.Client(api_key=self.api_key) if self.api_key else None

    def analyze(self, item: ThreatItem) -> EnrichedThreat | None:
        """Assess threat item and return structured intelligence enrichment."""
        if not self.client:
            logger.warning("Gemini API key is not configured. Returning basic enrichment.")
            return EnrichedThreat(
                item_id=item.id,
                item=item,
                severity=Severity.UNKNOWN,
                japan_relevance=JapanRelevance.UNKNOWN,
                title_ja=item.title,
                summary_ja=item.summary[:200],
                impact_analysis_ja="Gemini APIキーが未設定のため未分析です。",
                victim_orgs=[],
                threat_actors=[],
                recommended_actions_ja=[],
            )

        prompt = f"""
        あなたは日本を拠点とするサイバー脅威インテリジェンス（CTI）アナリストです。
        以下の脅威情報の原文を精読し、客観的な事実（ファクト）のみを抽出してください。

        # 評価基準（厳守）
        1. japan_relevance (日本への関連性):
           - "Direct": 具体的な日本企業・日本の官公庁・国内組織が被害対象である事案、またはJPCERT/CC・IPA・JVNによる公式発信。
           - "Indirect": 日本国内の特定被害組織は確認されていないが、日本でも普及しているソフトウェア・OSの脆弱性や世界規模の攻撃事象。
           - "None": 日本国内との関連性が見られない海外ローカル事象。

        2. severity (重要度 - 上方バイアス厳禁):
           - 【絶対ルール1】japan_relevance が "Direct" 以外の場合、"Critical" を付与することは絶対に禁止（最大 "High" まで）。
           - 【絶対ルール2】具体的な被害組織を伴わない一般的な注意喚起（JPCERT/IPA注意喚起を含む）、週報・まとめ記事は最大 "Medium" まで。
           - "Critical": japan_relevance が "Direct" かつ国内特定組織における深刻な実被害（ランサムウェア感染・大規模情報漏洩・重要システム停止）が確認された事案のみ。
           - "High": 国内組織での情報漏洩事案、ランサムウェアDLSへの新規掲載、または悪用確認済み/PoC公開済みの深刻脆弱性。
           - "Medium": JPCERT/IPA等の注意喚起、週報、通常のセキュリティアドバイザリ、影響が限定的なインシデント。
           - "Low": 悪用やPoCが確認されていない修正パッチ公開、マイナーなバグ修正、コラム。

        # 事実記載ルール（説教・対策アドバイスの完全禁止）
        - summary_ja および impact_analysis_ja には確認された客観的事実のみを記述し、「MFA導入」「パッチ適用」等の一般的な対策助言は一切書かないでください。

        # 対象インシデント情報
        ソース種別: {item.source_type.value}
        情報源: {item.source_name}
        タイトル: {item.title}
        URL: {item.url or "N/A"}
        本文/要約: {item.summary[:1500]}
        付加情報: {json.dumps(item.metadata, ensure_ascii=False)}

        # 出力形式 (必ず以下のJSONフォーマットのみを出力してください)
        {{
            "severity": "Critical" | "High" | "Medium" | "Low",
            "japan_relevance": "Direct" | "Indirect" | "None",
            "title_ja": "日本語での的確で簡潔な事実ベースのインシデント名",
            "summary_ja": "確認された事実（被害対象・手口・対象製品等）の日本語3行以内要約",
            "impact_analysis_ja": "確認された被害規模・漏洩件数・影響範囲の客観的事実",
            "victim_orgs": [],
            "threat_actors": [],
            "attack_type": "Ransomware" | "Data Breach" | "Zero-day" | "Supply Chain" | "DDoS" | "Phishing" | "Vulnerability"
        }}
        """

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                ),
            )

            data = json.loads(response.text)

            # Map enums safely
            severity = (
                Severity(data.get("severity", Severity.UNKNOWN.value))
                if data.get("severity") in [e.value for e in Severity]
                else Severity.UNKNOWN
            )
            japan_rel = (
                JapanRelevance(data.get("japan_relevance", JapanRelevance.UNKNOWN.value))
                if data.get("japan_relevance") in [e.value for e in JapanRelevance]
                else JapanRelevance.UNKNOWN
            )
            if japan_rel != JapanRelevance.DIRECT and severity == Severity.CRITICAL:
                severity = Severity.HIGH

            return EnrichedThreat(
                item_id=item.id,
                item=item,
                severity=severity,
                japan_relevance=japan_rel,
                title_ja=data.get("title_ja", item.title),
                summary_ja=data.get("summary_ja", item.summary[:200]),
                impact_analysis_ja=data.get("impact_analysis_ja", ""),
                victim_orgs=data.get("victim_orgs", []),
                threat_actors=data.get("threat_actors", []),
                attack_type=data.get("attack_type"),
                recommended_actions_ja=[],
            )

        except Exception as e:
            logger.error(f"Failed to analyze item '{item.title}' with Gemini: {e}")
            return None
