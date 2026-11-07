import { resolveJapaneseEntity } from "./tools/entity_resolver.js";
import { PLaMoTranslator } from "./translator/plamo.js";
import { ThreatItem, EnrichedThreat } from "./types.js";
import { request } from "undici";

export interface AgentConfig {
  ollamaEndpoint?: string;
  extractorModel?: string;
  maxLoopTurns?: number;
}

/**
 * Autonomous CTI Agent orchestrating extraction, tool invocation, and PLaMo translation.
 */
export class CTIAgentService {
  private ollamaEndpoint: string;
  private extractorModel: string;
  private maxLoopTurns: number;
  private translator: PLaMoTranslator;

  constructor(config?: AgentConfig) {
    this.ollamaEndpoint = config?.ollamaEndpoint || process.env.LITELLM_ENDPOINT || "http://litellm-service.litellm.svc.cluster.local:4000/v1/chat/completions";
    this.extractorModel = config?.extractorModel || process.env.LITELLM_MODEL || "qwen2.5-3b-instruct";
    this.maxLoopTurns = config?.maxLoopTurns || 3;
    this.translator = new PLaMoTranslator();
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
   - RULE 2: General summaries, weekly digests, or FAQs without specific victim organizations MUST be "Medium" or lower.
   - "Critical": japan_relevance == "Direct" AND severe confirmed damage (ransomware encryption, major data breach, critical system outage).
   - "High": Confirmed breach of enterprise/government, or actively exploited (In-the-wild) zero-day.
   - "Medium": Vulnerability advisory, minor incident, or generic summary.
   - "Low": Routine patch, low severity bug fix.
   - "Info": PR announcements, product launches, corporate notices.

3. threat_actors:
   - Only include threat group/APT names explicitly named in text (e.g. "Qilin", "BlackTech", "APT10").
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

    // === Tool Invocation: Japanese Entity Resolution ===
    const resolvedVictimOrgs: string[] = [];
    const victimList: string[] = Array.isArray(structuredOutput.victim_orgs) ? structuredOutput.victim_orgs : [];

    for (const victim of victimList) {
      const resolution = await resolveJapaneseEntity(victim);
      if (resolution.officialNameJa) {
        resolvedVictimOrgs.push(resolution.officialNameJa);
        // Elevate to Direct if official Japanese entity was confirmed
        if (resolution.isJapaneseEntity && structuredOutput.japan_relevance === "None") {
          structuredOutput.japan_relevance = "Direct";
        }
      } else {
        resolvedVictimOrgs.push(victim);
      }
    }

    // === Final Stage: PLaMo 3 Translation with Preserved Entities ===
    const preservedTerms = [
      ...resolvedVictimOrgs,
      ...(structuredOutput.threat_actors || []),
      ...(structuredOutput.cves || []),
      ...(structuredOutput.affected_products || [])
    ];

    const [titleJa, summaryJa, impactJa] = await Promise.all([
      this.translator.translateToJapanese(structuredOutput.title || item.title, preservedTerms),
      this.translator.translateToJapanese(structuredOutput.summary || item.summary, preservedTerms),
      this.translator.translateToJapanese(structuredOutput.impact_analysis || "", preservedTerms)
    ]);

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
      const res = await request(this.ollamaEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: this.extractorModel,
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

