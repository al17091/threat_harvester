import { describe, it, expect } from "vitest";
import { ThreatItemSchema, EnrichedThreatSchema } from "./types.js";

describe("Agent Schemas", () => {
  it("validates ThreatItemSchema defaults", () => {
    const item = ThreatItemSchema.parse({
      title: "LockBit ransomware advisory",
      url: "https://example.com/advisory",
    });
    expect(item.title).toBe("LockBit ransomware advisory");
    expect(item.metadata).toEqual({});
  });

  it("validates EnrichedThreatSchema correctly", () => {
    const enriched = EnrichedThreatSchema.parse({
      title: "LockBit attack on Enterprise Inc",
      summary: "Ransomware extortion group claims victim",
      impact_analysis: "Operational disruption",
      title_ja: "LockBitによるEnterprise社への攻撃",
      summary_ja: "ランサムウェアグループによる被害報告",
      impact_analysis_ja: "業務停止の影響",
      severity: "High",
      japan_relevance: "Direct",
    });
    expect(enriched.severity).toBe("High");
    expect(enriched.japan_relevance).toBe("Direct");
    expect(enriched.victim_orgs).toEqual([]);
  });
});
