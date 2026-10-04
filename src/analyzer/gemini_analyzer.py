import json
import logging

from google import genai
from google.genai import types

from src.config import settings
from src.models import EnrichedThreat, JapanRelevance, Severity, ThreatItem

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
            "title_ja": "日本語での的確で簡潔なインシデント名",
            "summary_ja": "技術的背景と被害状況の日本語3行以内要約",
            "impact_analysis_ja": "日本国内への具体的な影響・脅威評価",
            "victim_orgs": ["被害組織名（判明している場合）"],
            "threat_actors": ["関与している攻撃グループ名（判明している場合）"],
            "attack_type": "Ransomware" | "Data Breach" | "Zero-day" | "Supply Chain" | "DDoS" | "Phishing" | "Vulnerability",
            "recommended_actions_ja": ["推奨される初動対応・防御策"]
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
                recommended_actions_ja=data.get("recommended_actions_ja", []),
            )

        except Exception as e:
            logger.error(f"Failed to analyze item '{item.title}' with Gemini: {e}")
            return None
