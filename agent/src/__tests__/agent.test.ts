import { describe, it, expect, vi } from "vitest";
import { CTIAgentService, parseModelJSON, type AgentDeps, type ChatMessage } from "../agent.js";
import type { EntityResolutionResult } from "../tools/entity_resolver.js";
import { ThreatItemSchema } from "../types.js";

const unresolved: EntityResolutionResult = { officialNameJa: null, isJapaneseEntity: false, confidence: "low", source: "none" };

function makeAgent(llmResponses: string[], overrides: Partial<AgentDeps> = {}, maxLoopTurns = 1) {
  const calls: ChatMessage[][] = [];
  const callLLM = vi.fn(async (messages: ChatMessage[]) => {
    calls.push(messages.map((m) => ({ ...m })));
    return llmResponses[Math.min(calls.length - 1, llmResponses.length - 1)];
  });
  const translate = vi.fn(async (text: string) => `JA:${text}`);
  const resolveEntity = vi.fn(async () => unresolved);
  const agent = new CTIAgentService({ maxLoopTurns }, { callLLM, translate, resolveEntity, ...overrides });
  return { agent, calls, callLLM, translate, resolveEntity };
}

const item = (over: Record<string, unknown>) =>
  ThreatItemSchema.parse({ title: "Untitled", source_type: "rss", source_name: "test", ...over });

describe("parseModelJSON", () => {
  it("handles code fences and rejects empty/array payloads", () => {
    expect(parseModelJSON('```json\n{"a":1}\n```')).toEqual({ a: 1 });
    expect(parseModelJSON("{}")).toBeNull();
    expect(parseModelJSON("[1]")).toBeNull();
    expect(parseModelJSON("not json")).toBeNull();
  });
});

describe("CTIAgentService.analyze", () => {
  it("clamps Critical to High instead of discarding valid fields with maxLoopTurns=1 (defect 2)", async () => {
    const { agent, callLLM } = makeAgent([
      JSON.stringify({
        severity: "Critical",
        japan_relevance: "Indirect",
        title: "[Ransomware] Acme Corp Targeted by Akira",
        title_ja: "【ランサムウェア】Acme Corpに対するAkiraによる攻撃",
        summary: "Akira encrypted Acme Corp servers.",
        impact_analysis: "Operations halted.",
        victim_orgs: ["Acme Corp"],
        threat_actors: ["Akira"],
        threat_actor_reasons: { Akira: "Akira claimed responsibility" },
        attack_type: "Ransomware",
        cves: [],
        affected_products: [],
      }),
    ]);
    const res = await agent.analyze(item({ title: "Akira hits Acme Corp", raw_content: "Akira ransomware encrypted Acme Corp servers." }));
    expect(callLLM).toHaveBeenCalledTimes(1);
    expect(res.severity).toBe("High");
    expect(res.japan_relevance).toBe("Indirect");
    expect(res.victim_orgs).toEqual(["Acme Corp"]);
    expect(res.threat_actors).toEqual(["Akira"]);
    expect(res.attack_type).toBe("Ransomware");
    expect(res.title).toBe("[Ransomware] Acme Corp Targeted by Akira");
  });

  it("retries only on JSON failures and falls back to source title when all turns fail", async () => {
    const { agent, calls, callLLM } = makeAgent(["garbage", "{}"], {}, 2);
    const res = await agent.analyze(item({ title: "Vendor ships patch for CVE-2026-4242", summary: "Patch notes." }));
    expect(callLLM).toHaveBeenCalledTimes(2);
    expect(calls[1].at(-1)?.content).toMatch(/not valid JSON/);
    expect(res.severity).toBe("Info");
    expect(res.japan_relevance).toBe("None");
    expect(res.cves).toEqual(["CVE-2026-4242"]);
    expect(res.title).toBe("Vendor ships patch for CVE-2026-4242");
  });

  it("does not retry on rule violations", async () => {
    const { agent, callLLM } = makeAgent(
      [JSON.stringify({ severity: "Critical", japan_relevance: "None", title: "Something happened somewhere" })],
      {},
      3
    );
    const res = await agent.analyze(item({ title: "x" }));
    expect(callLLM).toHaveBeenCalledTimes(1);
    expect(res.severity).toBe("High");
  });

  it("keeps real orgs containing 'Company' and resolves them (defect 3)", async () => {
    const resolveEntity = vi.fn(async (name: string): Promise<EntityResolutionResult> =>
      name === "Tokyo Electric Power Company"
        ? { officialNameJa: "東京電力ホールディングス株式会社", isJapaneseEntity: true, confidence: "high", source: "dictionary" }
        : unresolved
    );
    const { agent } = makeAgent(
      [
        JSON.stringify({
          severity: "High",
          japan_relevance: "None",
          title: "[Data Breach] Unauthorized Access at Tokyo Electric Power Company",
          victim_orgs: ["Tokyo Electric Power Company", "customers"],
          attack_type: "Data Breach",
        }),
      ],
      { resolveEntity }
    );
    const res = await agent.analyze(item({ title: "TEPCO breach", raw_content: "Tokyo Electric Power Company disclosed unauthorized access." }));
    expect(res.victim_orgs).toEqual(["東京電力ホールディングス株式会社"]);
    expect(res.japan_relevance).toBe("Direct");
  });

  it("drops defensive orgs from victims so they cannot elevate japan_relevance (defect 4)", async () => {
    const resolveEntity = vi.fn(async () => unresolved);
    const { agent } = makeAgent(
      [
        JSON.stringify({
          severity: "High",
          japan_relevance: "None",
          title: "[Vulnerability] Advisory published by JPCERT/CC",
          victim_orgs: ["JPCERT/CC", "IPA", "Foo Corp - Ransomware.live", "Ca***ka", "LockBit"],
          threat_actors: [],
          attack_type: "Data Breach",
        }),
      ],
      { resolveEntity }
    );
    const res = await agent.analyze(item({ title: "JPCERT/CC advisory", raw_content: "JPCERT/CC and IPA warned about Foo Corp breach." }));
    expect(resolveEntity).toHaveBeenCalledTimes(1);
    expect(resolveEntity).toHaveBeenCalledWith("Foo Corp");
    expect(res.victim_orgs).toEqual(["Foo Corp"]);
    expect(res.japan_relevance).toBe("None");
  });

  it("does not elevate japan_relevance on medium-confidence search matches", async () => {
    const resolveEntity = vi.fn(async (): Promise<EntityResolutionResult> => ({
      officialNameJa: "株式会社なにか",
      isJapaneseEntity: true,
      confidence: "medium",
      source: "search",
    }));
    const { agent } = makeAgent(
      [JSON.stringify({ severity: "High", japan_relevance: "None", title: "[Data Breach] Breach at Globex", victim_orgs: ["Globex"], attack_type: "Data Breach" })],
      { resolveEntity }
    );
    const res = await agent.analyze(item({ title: "Globex breach", raw_content: "Globex was breached." }));
    expect(res.japan_relevance).toBe("None");
  });

  it("verifies/rescues CVEs and grounds threat actors in source text (defect 5)", async () => {
    const { agent } = makeAgent([
      JSON.stringify({
        severity: "High",
        japan_relevance: "Direct",
        title: "[Ransomware] 株式会社サンプル Targeted by Qilin",
        title_ja: "【ランサムウェア】株式会社サンプルに対するQilinによる攻撃",
        victim_orgs: ["株式会社サンプル"],
        threat_actors: ["Qilin", "Lazarus", "Kaspersky"],
        threat_actor_reasons: { Qilin: "キリンが犯行声明", Lazarus: "hallucinated" },
        attack_type: "Ransomware",
        cves: ["CVE-2026-0001", "CVE-2099-9999"],
      }),
    ]);
    const res = await agent.analyze(
      item({
        title: "株式会社サンプルにランサムウェア攻撃",
        raw_content: "ランサムウェアグループ「キリン」が犯行声明を出した。侵入経路はCVE-2026-0001とcve-2026-0002とみられる。",
      })
    );
    expect(res.threat_actors).toEqual(["Qilin"]);
    expect(res.threat_actor_reasons).toEqual({ Qilin: "キリンが犯行声明" });
    expect(res.cves).toEqual(["CVE-2026-0001", "CVE-2026-0002"]);
    expect(res.severity).toBe("High");
  });

  it("caps advisories without victims and strips actors", async () => {
    const { agent } = makeAgent([
      JSON.stringify({
        severity: "Critical",
        japan_relevance: "Indirect",
        title: "[Vulnerability] RCE in FooServer (CVE-2026-7777)",
        threat_actors: ["Volt Typhoon"],
        threat_actor_reasons: { "Volt Typhoon": "mentioned" },
        attack_type: "Vulnerability",
        affected_products: ["FooServer"],
      }),
    ]);
    const res = await agent.analyze(item({ title: "FooServer advisory", raw_content: "CVE-2026-7777 in FooServer. Volt Typhoon previously targeted similar products." }));
    expect(res.severity).toBe("Medium");
    expect(res.threat_actors).toEqual([]);
    expect(res.threat_actor_reasons).toEqual({});
    expect(res.cves).toEqual(["CVE-2026-7777"]);
  });

  it("sends a bounded smart excerpt to the LLM (defect 5)", async () => {
    const { agent, calls } = makeAgent([JSON.stringify({ severity: "Info", japan_relevance: "None", title: "Some long article title" })]);
    const filler = Array.from({ length: 150 }, (_, i) => `Ordinary paragraph ${i} with narrative text only.`).join("\n\n");
    const raw = `Lead paragraph.\n\n${filler}\n\nBar Corp. confirmed a breach via CVE-2026-31337.`;
    await agent.analyze(item({ title: "Long", raw_content: raw }));
    const userMsg = calls[0][1].content;
    const excerpt = userMsg.split("Raw Content:\n")[1];
    expect(excerpt.length).toBeLessThanOrEqual(4000);
    expect(excerpt).toContain("CVE-2026-31337");
  });

  it("translates the English title when title_ja is missing and builds a glossary", async () => {
    const { agent, translate } = makeAgent([
      JSON.stringify({ severity: "Medium", japan_relevance: "None", title: "[Vulnerability] Flaw in FooServer", affected_products: ["FooServer"], summary: "A flaw." }),
    ]);
    const res = await agent.analyze(item({ title: "FooServer flaw", raw_content: "FooServer flaw." }));
    expect(res.title_ja).toBe("JA:[Vulnerability] Flaw in FooServer");
    expect(translate).toHaveBeenCalledWith("[Vulnerability] Flaw in FooServer", expect.objectContaining({ FooServer: "FooServer" }));
  });
});
