import { describe, it, expect } from "vitest";
import {
  applyAdvisoryCap,
  applyRetrospectiveDemotion,
  clampSeverityForRelevance,
  normalizeJapanRelevance,
  normalizeSeverity,
} from "../guardrails/rules.js";
import {
  cleanAffectedProducts,
  cleanVictimOrgs,
  extractCves,
  isActorGrounded,
  isGenericVictimOrg,
  normalizeForGrounding,
  reconcileCves,
  sanitizeThreatActors,
  sanitizeVictimOrgName,
} from "../guardrails/sanitizer.js";
import { cleanIncidentTitle, synthesizeTitleEn, synthesizeTitleJa } from "../guardrails/title.js";

describe("rules (defect 2: deterministic clamp)", () => {
  it("clamps Critical to High when relevance is not Direct", () => {
    expect(clampSeverityForRelevance("Critical", "Indirect")).toBe("High");
    expect(clampSeverityForRelevance("Critical", "None")).toBe("High");
    expect(clampSeverityForRelevance("Critical", "Direct")).toBe("Critical");
    expect(clampSeverityForRelevance("Medium", "None")).toBe("Medium");
  });

  it("normalizes free-form enum values", () => {
    expect(normalizeSeverity("critical")).toBe("Critical");
    expect(normalizeSeverity("Informational")).toBe("Info");
    expect(normalizeSeverity(42)).toBe("Info");
    expect(normalizeJapanRelevance(" direct ")).toBe("Direct");
    expect(normalizeJapanRelevance("Unknown")).toBe("None");
  });

  it("demotes retrospective / annual reports to Info", () => {
    expect(applyRetrospectiveDemotion("High", "2025 Year in Review: Ransomware")).toBe("Info");
    expect(applyRetrospectiveDemotion("High", "ランサムウェア被害の事例まとめ")).toBe("Info");
    expect(applyRetrospectiveDemotion("High", "Acme hit by ransomware")).toBe("High");
  });

  it("caps advisories without victims at Medium and strips actors", () => {
    const input = { title: "Patch released", cves: ["CVE-2026-1111"], attackType: "Vulnerability" };
    expect(applyAdvisoryCap("Critical", input, 0)).toEqual({ severity: "Medium", stripActors: true });
    expect(applyAdvisoryCap("Low", input, 0)).toEqual({ severity: "Low", stripActors: true });
    expect(applyAdvisoryCap("High", input, 1)).toEqual({ severity: "High", stripActors: false });
    expect(applyAdvisoryCap("High", { title: "Breach", cves: [], attackType: "Data Breach" }, 0)).toEqual({
      severity: "High",
      stripActors: false,
    });
  });
});

describe("victim sanitization (defects 3 & 4)", () => {
  it("preserves real organizations containing Company / Organization / Enterprise", () => {
    expect(cleanVictimOrgs(["Tokyo Electric Power Company", "World Health Organization", "Enterprise Holdings"])).toEqual([
      "Tokyo Electric Power Company",
      "World Health Organization",
      "Enterprise Holdings",
    ]);
  });

  it("rejects exact generic placeholders and generic phrases", () => {
    for (const g of ["company", "Organization", "users", "中小企業", "multiple organizations", "Japanese enterprises", "Acme customers", "SMEs"]) {
      expect(isGenericVictimOrg(g), g).toBe(true);
    }
  });

  it("matches short generic tokens on word boundaries only", () => {
    expect(isGenericVictimOrg("Smeg S.p.A.")).toBe(false);
    expect(isGenericVictimOrg("Japanese SME sector")).toBe(true);
  });

  it("strips scraper suffixes", () => {
    expect(sanitizeVictimOrgName("Acme Corp - Ransomware.live")).toBe("Acme Corp");
    expect(sanitizeVictimOrgName("Acme Corp – RansomLook")).toBe("Acme Corp");
    expect(sanitizeVictimOrgName("Acme Corp - Qilin")).toBe("Acme Corp");
    expect(cleanVictimOrgs(["Acme Corp - Ransomware.live", "acme corp"])).toEqual(["Acme Corp"]);
  });

  it("rejects masked placeholders, CVEs and known threat actors", () => {
    expect(cleanVictimOrgs(["Ca***ka", "A... F...", "CVE-2026-1234", "LockBit", "Qilin ransomware group", "APT29"])).toEqual([]);
  });

  it("rejects defensive / advisory organizations", () => {
    expect(cleanVictimOrgs(["JPCERT/CC", "IPA", "NISC", "CISA", "FBI", "一般社団法人JPCERTコーディネーションセンター"])).toEqual([]);
  });

  it("coerces non-array input safely", () => {
    expect(cleanVictimOrgs(undefined)).toEqual([]);
    expect(cleanVictimOrgs([null, 3, " Toyota "])).toEqual(["Toyota"]);
  });
});

describe("CVE extraction & verification (defect 5)", () => {
  it("extracts uppercased, deduplicated CVEs in order and caps the list", () => {
    expect(extractCves("cve-2026-0001 and CVE-2026-0001, then CVE‑2025‑123456")).toEqual(["CVE-2026-0001", "CVE-2025-123456"]);
    const many = Array.from({ length: 30 }, (_, i) => `CVE-2026-${String(1000 + i)}`).join(" ");
    expect(extractCves(many)).toHaveLength(20);
  });

  it("drops hallucinated / malformed CVEs and rescues missed ones", () => {
    const source = "Fix for CVE-2026-1111. Also CVE-2026-2222 is exploited.";
    expect(reconcileCves(["CVE-2026-2222", "CVE-2026-9999", "CVE-26-1"], source)).toEqual(["CVE-2026-2222", "CVE-2026-1111"]);
    expect(reconcileCves([], source)).toEqual(["CVE-2026-1111", "CVE-2026-2222"]);
    expect(reconcileCves(["CVE-2026-1234"], "no ids here")).toEqual([]);
  });
});

describe("threat actor sanitization & grounding (defect 5)", () => {
  const source = normalizeForGrounding(
    "ランサムウェアグループ「キリン」が犯行声明。Lock-Bit affiliates and Volt  Typhoon were also referenced. Acme Inc. responded."
  );

  it("grounds actors via spacing/hyphenation and aliases", () => {
    expect(isActorGrounded("Qilin", source)).toBe(true);
    expect(isActorGrounded("LockBit", source)).toBe(true);
    expect(isActorGrounded("Volt Typhoon", source)).toBe(true);
    expect(isActorGrounded("Lazarus", source)).toBe(false);
  });

  it("does not ground INC Ransom on a corporate 'Inc.' suffix", () => {
    expect(isActorGrounded("INC Ransom", source)).toBe(false);
  });

  it("filters researchers, handles, vendors, defensive orgs and ungrounded actors; prunes reasons", () => {
    const src = "Qilin claimed the attack, per Trend Micro and JPCERT. @malwarehunter on X posted it.";
    const result = sanitizeThreatActors(
      ["Qilin ransomware group", "@malwarehunter", "MalwareHunter on X", "Trend Micro", "JPCERT/CC", "Lazarus", "Attackers"],
      { Qilin: "Qilin claimed the attack", Lazarus: "made up", "Trend Micro": "vendor" },
      src
    );
    expect(result.threat_actors).toEqual(["Qilin"]);
    expect(result.threat_actor_reasons).toEqual({ Qilin: "Qilin claimed the attack" });
  });

  it("canonicalizes and de-duplicates alias spellings", () => {
    const result = sanitizeThreatActors(["clop", "Cl0p"], { clop: "Clop leak site" }, "The Clop gang listed victims.");
    expect(result.threat_actors).toEqual(["Cl0p"]);
    expect(result.threat_actor_reasons).toEqual({ "Cl0p": "Clop leak site" });
  });

  it("drops non-string reasons", () => {
    const result = sanitizeThreatActors(["Akira"], { Akira: { nested: true } }, "Akira ransomware");
    expect(result.threat_actor_reasons).toEqual({});
  });
});

describe("affected products", () => {
  it("drops CVE IDs and placeholders, dedupes", () => {
    expect(cleanAffectedProducts(["FortiOS", "fortios", "CVE-2026-1234", "None", ""])).toEqual(["FortiOS"]);
  });
});

describe("title module", () => {
  it("cleans X framing, media suffixes and clickbait prefixes", () => {
    expect(cleanIncidentTitle('Someone on X: "Big breach at Acme"')).toBe("Big breach at Acme");
    expect(cleanIncidentTitle("【速報】大手企業で情報流出 - 日本経済新聞")).toBe("大手企業で情報流出");
    expect(cleanIncidentTitle("大手企業で情報流出 (毎日新聞)")).toBe("大手企業で情報流出");
  });

  it("synthesizes structured fallback titles", () => {
    const ctx = { victims: ["トヨタ自動車株式会社"], attackType: "Ransomware", affectedProducts: [], cves: [] };
    expect(synthesizeTitleJa(ctx)).toBe("【ランサムウェア】トヨタ自動車株式会社に対する攻撃被害");
    expect(synthesizeTitleEn(ctx)).toBe("[Ransomware] トヨタ自動車株式会社 Hit by Ransomware Attack");
    const vuln = { victims: [], attackType: "Vulnerability", affectedProducts: ["FortiOS"], cves: ["CVE-2026-1"] };
    expect(synthesizeTitleJa(vuln)).toBe("【脆弱性】FortiOSにおける脆弱性 (CVE-2026-1)");
    expect(synthesizeTitleEn({ ...vuln, affectedProducts: [] })).toBe("[Vulnerability] Security Advisory for CVE-2026-1");
    expect(synthesizeTitleJa({ victims: [], attackType: "None", affectedProducts: [], cves: [] })).toBeNull();
  });
});
