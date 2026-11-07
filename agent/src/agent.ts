import { resolveJapaneseEntity } from "./tools/entity_resolver.js";
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

/**
 * Autonomous CTI Agent orchestrating extraction with General LLM,
 * entity resolution tools, and translation with Japanese Specialized Model.
 */
export class CTIAgentService {
  private generalLlmEndpoint: string;
  private generalLlmModel: string;
  private maxLoopTurns: number;
  private translator: PLaMoTranslator;

  constructor(config?: AgentConfig) {
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

    this.maxLoopTurns = config?.maxLoopTurns || 3;
    this.translator = new PLaMoTranslator({
      plamoBaseUrl:
        config?.plamoBaseUrl ||
        process.env.JAPANESE_SPECIALIZED_ENDPOINT ||
        process.env.PLAMO_BASE_URL,
    });
  }

  /**
   * Main agent loop for analyzing a single threat item.
   */
  async analyze(item: ThreatItem): Promise<EnrichedThreat> {
    const rawContent = (item.raw_content || item.summary || "").slice(0, 4000);

    // Initial system prompt enforcing CTI rules & fact extraction
    const systemPrompt = `You are an elite Cyber Threat Intelligence (CTI) analyst.
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
   - "Critical": japan_relevance == "Direct" AND severe confirmed damage (ransomware encryption, major data breach, critical system outage).
   - "High": Confirmed breach of enterprise/government, or actively exploited (In-the-wild) zero-day against confirmed targets.
   - "Medium": Vulnerability advisory, minor incident, or generic summary.
   - "Low": Routine patch, low severity bug fix.
   - "Info": PR announcements, product launches, corporate notices.

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

Output pure JSON matching this exact schema:
{
  "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
  "japan_relevance": "Direct" | "Indirect" | "None",
  "title": "Concise factual English incident title",
  "summary": "Objective facts: victim, entry vector, compromised data (NO security advice/preaching)",
  "impact_analysis": "Confirmed scope of damage, affected versions, or exploitability (NO preaching)",
  "victim_orgs": ["Organization names mentioned in text"],
  "threat_actors": ["Explicit threat actor group names mentioned in text"],
  "threat_actor_reasons": {"Actor": "Direct quote from source text where named"},
  "attack_type": "Ransomware" | "Data Breach" | "Zero-day" | "Vulnerability" | "DDoS" | "None",
  "cves": ["CVE-YYYY-NNNNN"],
  "affected_products": ["Affected software or hardware"]
}`;

    let currentMessages = [
      { role: "system", content: systemPrompt },
      {
        role: "user",
        content: `Source: ${item.source_type} (${item.source_name})
Title: ${item.title}
URL: ${item.url}
Raw Content:
${rawContent}`
      }
    ];

    let structuredOutput: any = null;

    // === Agent Self-Correction & Verification Loop ===
    for (let turn = 1; turn <= this.maxLoopTurns; turn++) {
      const responseText = await this.callLLM(currentMessages);
      const parsed = this.cleanAndParseJSON(responseText);

      if (!parsed) {
        currentMessages.push({ role: "assistant", content: responseText });
        currentMessages.push({
          role: "user",
          content: "Your response was not valid JSON. Please output strictly valid JSON matching the schema."
        });
        continue;
      }

      // Verification Step: Check rule violations
      const violations: string[] = [];
      if (parsed.japan_relevance !== "Direct" && parsed.severity === "Critical") {
        violations.push("Violation: Severity cannot be 'Critical' when japan_relevance is not 'Direct'. Lower severity to 'High'.");
      }

      if (violations.length > 0) {
        currentMessages.push({ role: "assistant", content: responseText });
        currentMessages.push({
          role: "user",
          content: `Validation failed:\n${violations.join("\n")}\nPlease correct your output and return valid JSON.`
        });
        continue;
      }

      // All guardrails passed
      structuredOutput = parsed;
      break;
    }

    // Fallback if parsing failed across all turns
    if (!structuredOutput) {
      structuredOutput = {
        severity: "Info",
        japan_relevance: "None",
        title: item.title,
        summary: item.summary || item.title,
        impact_analysis: "",
        victim_orgs: [],
        threat_actors: [],
        attack_type: "None",
        cves: [],
        affected_products: []
      };
    }

    // === Post-Processing Guardrails ===
    // 1. Sanitize victim_orgs: strip generic categories, products, or CVE IDs
    const genericVictimPattern = /(?:中小企業|中小事業者|小規模事業者|中小|国内企業|日本企業|複数企業|各社|sme|small\s+and\s+medium|enterprise|organization|company|user|customer|vulnerability|advisory|patch|cve-\d+)/i;
    const rawVictims: string[] = Array.isArray(structuredOutput.victim_orgs) ? structuredOutput.victim_orgs : [];
    const validVictims = rawVictims.filter((v: string) => {
      const trimmed = v.trim();
      if (!trimmed || trimmed.length < 2) return false;
      if (genericVictimPattern.test(trimmed)) return false;
      if (/^cve-\d+/i.test(trimmed)) return false;
      return true;
    });

    // 2. Sanitize threat_actors: strip reporters, security researchers, or social media handles
    const invalidActorPattern = /(?:researcher|reporter|blogger|journalist|analyst|報告者|研究者|調査員|アナリスト|記者|投稿者|jpcert|ipa|trend\s*micro|kaspersky|google\s*tag|\bon\s+x\b|\bon\s+twitter\b|\bon\s+bluesky\b)/i;
    let validActors: string[] = Array.isArray(structuredOutput.threat_actors) ? structuredOutput.threat_actors : [];
    validActors = validActors.filter((a: string) => {
      const trimmed = a.trim();
      if (!trimmed || trimmed.length < 2) return false;
      if (trimmed.startsWith("@")) return false; // Social media handles are never threat actors
      if (invalidActorPattern.test(trimmed)) return false;
      return true;
    });

    // 3. Vulnerability observation guardrail:
    // If it's a vulnerability advisory or CVE observation without confirmed breached victim organizations,
    // severity MUST be capped at Medium, and threat_actors MUST NOT be attached.
    const isVulnerabilityAdvisory =
      (structuredOutput.cves && structuredOutput.cves.length > 0) ||
      structuredOutput.attack_type === "Vulnerability" ||
      /vulnerability\s+advisory|脆弱性速報|脆弱性観測|cve-\d+/i.test(item.title);

    if (isVulnerabilityAdvisory && validVictims.length === 0) {
      if (structuredOutput.severity === "Critical" || structuredOutput.severity === "High") {
        structuredOutput.severity = "Medium";
      }
      validActors = [];
      structuredOutput.threat_actor_reasons = {};
    }

    structuredOutput.victim_orgs = validVictims;
    structuredOutput.threat_actors = validActors;

    // === Tool Invocation: Japanese Entity Resolution ===
    const resolvedVictimOrgs: string[] = [];
    const entityGlossary: Record<string, string> = {};
    const victimList: string[] = structuredOutput.victim_orgs;

    for (const victim of victimList) {
      const resolution = await resolveJapaneseEntity(victim);
      if (resolution.officialNameJa) {
        resolvedVictimOrgs.push(resolution.officialNameJa);
        entityGlossary[victim] = resolution.officialNameJa;
        // Elevate to Direct if official Japanese entity was confirmed
        if (resolution.isJapaneseEntity && structuredOutput.japan_relevance === "None") {
          structuredOutput.japan_relevance = "Direct";
        }
      } else {
        resolvedVictimOrgs.push(victim);
        entityGlossary[victim] = victim;
      }
    }

    // Preserve threat actors, CVEs, and affected products in glossary
    for (const actor of (structuredOutput.threat_actors || [])) {
      if (actor && actor.trim()) entityGlossary[actor.trim()] = actor.trim();
    }
    for (const cve of (structuredOutput.cves || [])) {
      if (cve && cve.trim()) entityGlossary[cve.trim()] = cve.trim();
    }
    for (const prod of (structuredOutput.affected_products || [])) {
      if (prod && prod.trim()) entityGlossary[prod.trim()] = prod.trim();
    }

    // === Final Stage: PLaMo 3 Translation with Native PFML3 Glossary (Sequential to maximize CPU throughput) ===
    const titleJa = await this.translator.translateToJapanese(
      structuredOutput.title || item.title,
      entityGlossary
    );
    const summaryJa = await this.translator.translateToJapanese(
      structuredOutput.summary || item.summary,
      entityGlossary
    );
    const impactJa = structuredOutput.impact_analysis
      ? await this.translator.translateToJapanese(structuredOutput.impact_analysis, entityGlossary)
      : "";

    return {
      item_id: item.id,
      severity: structuredOutput.severity || "Info",
      japan_relevance: structuredOutput.japan_relevance || "None",
      title: structuredOutput.title || item.title,
      summary: structuredOutput.summary || "",
      impact_analysis: structuredOutput.impact_analysis || "",
      title_ja: titleJa || item.title,
      summary_ja: summaryJa || item.summary || item.title,
      impact_analysis_ja: impactJa || "",
      victim_orgs: resolvedVictimOrgs,
      threat_actors: structuredOutput.threat_actors || [],
      threat_actor_reasons: structuredOutput.threat_actor_reasons || {},
      attack_type: structuredOutput.attack_type || "None",
      cves: structuredOutput.cves || [],
      affected_products: structuredOutput.affected_products || [],
      recommended_actions_ja: [],
      analyzed_at: new Date().toISOString()
    };
  }

  private async callLLM(messages: Array<{ role: string; content: string }>): Promise<string> {
    try {
      const res = await request(this.generalLlmEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: this.generalLlmModel,
          messages: messages,
          temperature: 0.1,
          response_format: { type: "json_object" }
        })
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

  private cleanAndParseJSON(raw: string): any | null {
    try {
      const cleaned = raw.replace(/```json\s*|\s*```/g, "").trim();
      return JSON.parse(cleaned);
    } catch {
      return null;
    }
  }
}

