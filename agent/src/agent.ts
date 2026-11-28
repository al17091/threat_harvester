import { buildExcerpt } from "./context/excerpt.js";
import {
  applyAdvisoryCap,
  applyRetrospectiveDemotion,
  clampSeverityForRelevance,
  normalizeJapanRelevance,
  normalizeSeverity,
} from "./guardrails/rules.js";
import {
  cleanAffectedProducts,
  cleanVictimOrgs,
  reconcileCves,
  sanitizeThreatActors,
} from "./guardrails/sanitizer.js";
import {
  cleanIncidentTitle,
  isNoisyTitleEn,
  isNoisyTitleJa,
  synthesizeTitleEn,
  synthesizeTitleJa,
} from "./guardrails/title.js";
import { EntityResolutionResult, resolveJapaneseEntity } from "./tools/entity_resolver.js";
import { PLaMoTranslator } from "./translator/plamo.js";
import { ThreatItem, EnrichedThreat } from "./types.js";
import { request } from "undici";

export interface AgentConfig {
  generalLlmEndpoint?: string;
  generalLlmModel?: string;
  maxLoopTurns?: number;
  plamoBaseUrl?: string;
  // Deprecated compatibility fields
  ollamaEndpoint?: string;
  extractorModel?: string;
}

export type ChatMessage = { role: string; content: string };

/** External collaborators, injectable for offline tests. */
export interface AgentDeps {
  callLLM: (messages: ChatMessage[]) => Promise<string>;
  translate: (text: string, glossary: Record<string, string>) => Promise<string>;
  resolveEntity: (name: string) => Promise<EntityResolutionResult>;
}

export const SYSTEM_PROMPT = `You are an elite Cyber Threat Intelligence (CTI) analyst.
Your objective: Extract strictly verified facts from the raw intelligence report and format as structured JSON.

Evaluation Criteria:
1. japan_relevance:
   - "Direct": Real domestic Japanese organization/government/critical infrastructure confirmed as victim, or official advisory by JPCERT/CC / IPA.
   - "Indirect": Japan-relevant software/OS/global campaign, but no specific domestic victim named.
   - "None": Overseas local event without Japan impact.

2. severity (Strict Guardrails):
   - RULE 1: If japan_relevance != "Direct", severity MUST NOT be "Critical" (Maximum "High").
   - RULE 2: Vulnerability advisories, security patches, PoC releases, or vulnerability observation reports without a confirmed compromised organization MUST be "Medium" or lower ("Low", "Info"). NEVER "Critical" or "High".
   - RULE 3: General summaries, weekly digests, or FAQs without specific victim organizations MUST be "Medium" or lower.
   - RULE 4 (Historical / Retrospective Reports & Annual Summaries):
     If the report is a retrospective review, annual report, multi-year statistical survey, case study summary, or primarily discusses past incidents from prior years (e.g. 2025, 2024 or earlier) rather than a new live incident, severity MUST be "Info" (or "Low" if general advisory). NEVER "Critical" or "High".
   - "Critical": japan_relevance == "Direct" AND severe confirmed damage (ransomware encryption, major data breach, critical system outage).
   - "High": Confirmed breach of enterprise/government, or actively exploited (In-the-wild) zero-day against confirmed targets.
   - "Medium": Vulnerability advisory, minor incident, or generic summary.
   - "Low": Routine patch, low severity bug fix.
   - "Info": PR announcements, product launches, corporate notices, historical retrospective summaries, and annual reviews.

3. victim_orgs (Strict Invariant):
   - A victim is STRICTLY a real enterprise, government agency, educational institution, or healthcare facility that suffered a confirmed breach, ransomware encryption, or unauthorized data access.
   - NEVER put software names, products, open source libraries, vulnerability advisories, or CVE numbers into victim_orgs!
   - NEVER put generic categories into victim_orgs, such as:
     "中小企業", "中小企業等", "国内企業", "国内組織", "SMEs", "small and medium businesses", "Japanese enterprises", "companies", "organizations", "users", "customers".
   - If an article is a vulnerability advisory, patch release, or general observation without a named, confirmed breached organization, victim_orgs MUST BE EMPTY [].

4. threat_actors (Strict Invariant):
   - Only include threat group/APT names explicitly named in text as conducting malicious activity (e.g. "Volt Typhoon", "BlackTech", "LockBit", "Qilin").
   - NEVER extract security researchers, vulnerability reporters, security bloggers, news posters, or defensive organizations (e.g. accounts ending with "on X", handles starting with "@", "JPCERT", "IPA", "Trend Micro", "Kaspersky") as threat_actors! They are reporters/researchers, NOT threat actors.
   - If an entity is the author, poster, or discoverer of a report (e.g., "<Author> on X: ...", "reported by <Author>"), they are the REPORTER, NEVER a threat actor.
   - For vulnerability advisories or observation reports that lack concrete breach reports or specific attack attribution, threat_actors MUST be empty [].
   - NEVER guess or output vague terms like "Chinese APT", "Cybercriminals", "Attackers".

5. title and title_ja (Incident Title Rules):
   - You MUST generate an objective, concise, incident-focused title based on the verified security event, NOT the raw webpage or tweet headline.
   - NEVER copy social media commentary, reporter account names, or informal quotes (e.g. NEVER '<Author> on X: ...', NEVER '@handle', NEVER quotes).
   - NEVER include news publisher names or clickbait words (e.g. NEVER '(毎日新聞)', NEVER '| NHKニュース', NEVER '【独自】', NEVER '【速報】', NEVER 'ってすごいな').
   - Standard format for 'title_ja':
     - Unauthorized Access / Data Leak: "【不正アクセス】<被害組織>における情報流出事案" または "【情報漏洩】<被害組織>における顧客情報漏洩"
     - Ransomware: "【ランサムウェア】<被害組織>に対する<攻撃者名>による攻撃" (攻撃者名が不明な場合は組織名のみ)
     - Vulnerability: "【脆弱性】<対象製品名>における<影響/脆弱性内容> (<CVE番号>)"
     - DDoS: "【DDoS攻撃】<被害組織>におけるサービス停止事案"
     - If no specific victim/product is confirmed: "【サイバー攻撃】<観測された具体的な脅威事象>"
   - Standard format for 'title':
     - Same structure in technical English:
       e.g., "[Unauthorized Access] Data Breach Incident at XYZ Corp", "[Ransomware] XYZ Corp Targeted by Qilin Gang", "[Vulnerability] Remote Code Execution in Apache HTTP Server (CVE-2026-XXXX)".

Output pure JSON matching this exact schema:
{
  "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
  "japan_relevance": "Direct" | "Indirect" | "None",
  "title": "Concise factual English incident title based on content",
  "title_ja": "客観的な事実に基づく正確な日本語インシデントタイトル",
  "summary": "Objective facts: victim, entry vector, compromised data (NO security advice/preaching)",
  "impact_analysis": "Confirmed scope of damage, affected versions, or exploitability (NO preaching)",
  "victim_orgs": ["Organization names mentioned in text"],
  "threat_actors": ["Explicit threat actor group names mentioned in text"],
  "threat_actor_reasons": {"Actor": "Direct quote from source text where named"},
  "attack_type": "Ransomware" | "Data Breach" | "Zero-day" | "Vulnerability" | "DDoS" | "None",
  "cves": ["CVE-YYYY-NNNNN"],
  "affected_products": ["Affected software or hardware"]
}`;

function resolveMaxLoopTurns(configured?: number): number {
  const candidate = configured ?? (process.env.AGENT_MAX_LOOP_TURNS ? parseInt(process.env.AGENT_MAX_LOOP_TURNS, 10) : 1);
  return Number.isFinite(candidate) && candidate >= 1 ? Math.floor(candidate) : 1;
}

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

/** Parses model output into a non-empty JSON object, tolerating Markdown code fences. */
export function parseModelJSON(raw: string): Record<string, unknown> | null {
  try {
    const cleaned = (raw || "").replace(/```json\s*|\s*```/g, "").trim();
    const obj = JSON.parse(cleaned);
    if (!obj || typeof obj !== "object" || Array.isArray(obj) || Object.keys(obj).length === 0) return null;
    return obj as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Autonomous CTI agent: single-turn extraction with the general LLM, deterministic
 * guardrails over the extracted keys, Japanese entity resolution, and PLaMo translation.
 */
export class CTIAgentService {
  private generalLlmEndpoint: string;
  private generalLlmModel: string;
  private maxLoopTurns: number;
  private deps: AgentDeps;

  constructor(config?: AgentConfig, deps?: Partial<AgentDeps>) {
    this.generalLlmEndpoint =
      config?.generalLlmEndpoint ||
      config?.ollamaEndpoint ||
      process.env.GENERAL_LLM_ENDPOINT ||
      process.env.LITELLM_ENDPOINT ||
      "http://litellm-service.litellm.svc.cluster.local:4000/v1/chat/completions";

    this.generalLlmModel =
      config?.generalLlmModel ||
      config?.extractorModel ||
      process.env.GENERAL_LLM_MODEL ||
      process.env.LITELLM_MODEL ||
      "lab/qwen2.5-3b-instruct";

    this.maxLoopTurns = resolveMaxLoopTurns(config?.maxLoopTurns);

    const translator = new PLaMoTranslator({
      plamoBaseUrl: config?.plamoBaseUrl || process.env.JAPANESE_SPECIALIZED_ENDPOINT || process.env.PLAMO_BASE_URL,
    });
    this.deps = {
      callLLM: deps?.callLLM ?? ((messages) => this.callLLM(messages)),
      translate: deps?.translate ?? ((text, glossary) => translator.translateToJapanese(text, glossary)),
      resolveEntity: deps?.resolveEntity ?? ((name) => resolveJapaneseEntity(name)),
    };
  }

  /**
   * Runs extraction turns. Retries happen ONLY on JSON parse / empty-object failures;
   * rule violations are fixed deterministically afterwards and never discard output.
   */
  private async extract(item: ThreatItem, excerpt: string): Promise<Record<string, unknown> | null> {
    const messages: ChatMessage[] = [
      { role: "system", content: SYSTEM_PROMPT },
      {
        role: "user",
        content: `Source: ${item.source_type} (${item.source_name})
Title: ${item.title}
URL: ${item.url}
Raw Content:
${excerpt}`,
      },
    ];

    for (let turn = 1; turn <= this.maxLoopTurns; turn++) {
      const responseText = await this.deps.callLLM(messages);
      const parsed = parseModelJSON(responseText);
      if (parsed) return parsed;
      messages.push({ role: "assistant", content: responseText });
      messages.push({
        role: "user",
        content: "Your response was not valid JSON. Please output strictly valid JSON matching the schema.",
      });
    }
    return null;
  }

  /** Analyzes a single threat item. */
  async analyze(item: ThreatItem): Promise<EnrichedThreat> {
    const excerpt = buildExcerpt(item.raw_content || item.summary || "");
    // Extraction failure falls back to the source title/summary; severity/relevance default to Info/None.
    const extracted = (await this.extract(item, excerpt)) ?? { title: item.title, summary: item.summary || item.title };

    // Full (non-excerpted) source text used for grounding and CVE rescue.
    const sourceText = [item.title, item.summary, item.raw_content].filter(Boolean).join("\n");

    // === Deterministic key sanitization ===
    let japanRelevance = normalizeJapanRelevance(extracted.japan_relevance);
    let severity = normalizeSeverity(extracted.severity);
    const attackType = asString(extracted.attack_type) || "None";
    const cves = reconcileCves(extracted.cves, sourceText);
    const victimOrgs = cleanVictimOrgs(extracted.victim_orgs);
    const affectedProducts = cleanAffectedProducts(extracted.affected_products);
    let { threat_actors: threatActors, threat_actor_reasons: threatActorReasons } = sanitizeThreatActors(
      extracted.threat_actors,
      extracted.threat_actor_reasons,
      sourceText
    );

    // === Deterministic severity rules ===
    severity = applyRetrospectiveDemotion(severity, item.title);
    const cap = applyAdvisoryCap(severity, { title: item.title, cves, attackType }, victimOrgs.length);
    severity = cap.severity;
    if (cap.stripActors) {
      threatActors = [];
      threatActorReasons = {};
    }
    severity = clampSeverityForRelevance(severity, japanRelevance);

    // === Tool Invocation: Japanese Entity Resolution ===
    const resolvedVictimOrgs: string[] = [];
    const entityGlossary: Record<string, string> = {};
    for (const victim of victimOrgs) {
      const resolution = await this.deps.resolveEntity(victim);
      const resolved = resolution.officialNameJa || victim;
      if (!resolvedVictimOrgs.includes(resolved)) resolvedVictimOrgs.push(resolved);
      entityGlossary[victim] = resolved;
      // Only high-confidence resolutions (dictionary / native Japanese name) may elevate relevance.
      if (resolution.isJapaneseEntity && resolution.confidence === "high" && japanRelevance === "None") {
        japanRelevance = "Direct";
      }
    }
    for (const term of [...threatActors, ...cves, ...affectedProducts]) {
      entityGlossary[term] = term;
    }

    // === Titles & PLaMo 3 translation with glossary ===
    const titleCtx = { victims: resolvedVictimOrgs, attackType, affectedProducts, cves };
    let titleEn = cleanIncidentTitle(asString(extracted.title));
    let titleJa = cleanIncidentTitle(asString(extracted.title_ja));
    if (!titleJa) {
      titleJa = titleEn ? await this.deps.translate(titleEn, entityGlossary) : cleanIncidentTitle(item.title);
    }
    if (isNoisyTitleJa(titleJa)) titleJa = synthesizeTitleJa(titleCtx) ?? titleJa;
    if (isNoisyTitleEn(titleEn)) titleEn = synthesizeTitleEn(titleCtx) ?? titleEn;

    const summary = asString(extracted.summary);
    const impactAnalysis = asString(extracted.impact_analysis);
    const summaryJa = await this.deps.translate(summary || item.summary, entityGlossary);
    const impactJa = impactAnalysis ? await this.deps.translate(impactAnalysis, entityGlossary) : "";

    return {
      item_id: item.id,
      severity,
      japan_relevance: japanRelevance,
      title: titleEn || item.title,
      summary,
      impact_analysis: impactAnalysis,
      title_ja: titleJa || item.title,
      summary_ja: summaryJa || item.summary || item.title,
      impact_analysis_ja: impactJa || "",
      victim_orgs: resolvedVictimOrgs,
      threat_actors: threatActors,
      threat_actor_reasons: threatActorReasons,
      attack_type: attackType,
      cves,
      affected_products: affectedProducts,
      recommended_actions_ja: [],
      analyzed_at: new Date().toISOString(),
    };
  }

  private async callLLM(messages: ChatMessage[]): Promise<string> {
    try {
      const res = await request(this.generalLlmEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        headersTimeout: 300000,
        bodyTimeout: 300000,
        body: JSON.stringify({
          model: this.generalLlmModel,
          messages,
          temperature: 0.1,
          max_tokens: 1500,
          response_format: { type: "json_object" },
        }),
      });

      if (res.statusCode !== 200) {
        throw new Error(`LLM call failed with HTTP ${res.statusCode}`);
      }

      const body = (await res.body.json()) as any;
      return body.choices?.[0]?.message?.content || "";
    } catch (err: any) {
      console.error(`[CTIAgentService] LLM invocation failed: ${err.message}`);
      return "{}";
    }
  }
}
