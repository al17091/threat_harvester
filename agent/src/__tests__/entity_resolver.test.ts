import { describe, it, expect, vi } from "vitest";
import { resolveJapaneseEntity } from "../tools/entity_resolver.js";
import { isDefensiveOrAdvisoryOrg, lookupJapanOrgAlias } from "../tools/org_dictionary.js";

describe("org dictionary (defect 4)", () => {
  it("no longer maps defensive/advisory orgs as Japanese victim aliases", () => {
    for (const name of ["jpcert", "JPCERT/CC", "ipa", "nisc"]) {
      expect(lookupJapanOrgAlias(name), name).toBeNull();
    }
    expect(lookupJapanOrgAlias("Toyota")).toBe("トヨタ自動車株式会社");
  });

  it("recognizes defensive/advisory orgs across forms", () => {
    for (const name of ["JPCERT/CC", "IPA (Information-technology Promotion Agency)", "CISA", "FBI", "独立行政法人情報処理推進機構 (IPA)", "内閣サイバーセキュリティセンター"]) {
      expect(isDefensiveOrAdvisoryOrg(name), name).toBe(true);
    }
    expect(isDefensiveOrAdvisoryOrg("Toyota")).toBe(false);
    expect(isDefensiveOrAdvisoryOrg("Ipanema Inc.")).toBe(false);
  });
});

describe("resolveJapaneseEntity", () => {
  it("never resolves defensive orgs and never calls search for them", async () => {
    const search = vi.fn(async () => "株式会社なにか");
    for (const name of ["JPCERT/CC", "IPA", "NISC", "CISA"]) {
      const r = await resolveJapaneseEntity(name, search);
      expect(r.isJapaneseEntity, name).toBe(false);
      expect(r.officialNameJa, name).toBeNull();
    }
    expect(search).not.toHaveBeenCalled();
  });

  it("does not over-delete real orgs containing 'Company' (defect 3)", async () => {
    const search = vi.fn(async () => null);
    const r = await resolveJapaneseEntity("Tokyo Electric Power Company", search);
    expect(search).toHaveBeenCalledWith("Tokyo Electric Power Company");
    expect(r.source).toBe("none");
  });

  it("resolves dictionary aliases with high confidence without searching", async () => {
    const search = vi.fn(async () => null);
    const r = await resolveJapaneseEntity("NTT Docomo", search);
    expect(r).toMatchObject({ officialNameJa: "株式会社NTTドコモ", isJapaneseEntity: true, confidence: "high", source: "dictionary" });
    expect(search).not.toHaveBeenCalled();
  });

  it("treats names already in Japanese script as high-confidence Japanese entities", async () => {
    const r = await resolveJapaneseEntity("株式会社サンプル", async () => null);
    expect(r).toMatchObject({ officialNameJa: "株式会社サンプル", isJapaneseEntity: true, confidence: "high" });
  });

  it("returns medium confidence for search-based matches", async () => {
    const r = await resolveJapaneseEntity("Sample Trading", async () => "株式会社サンプル商事");
    expect(r).toMatchObject({ officialNameJa: "株式会社サンプル商事", confidence: "medium", source: "search" });
  });
});
