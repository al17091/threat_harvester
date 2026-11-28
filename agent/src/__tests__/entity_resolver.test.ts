import { describe, it, expect, vi } from "vitest";
import { request } from "undici";
import { resolveJapaneseEntity, searchOfficialName } from "../tools/entity_resolver.js";
import { isDefensiveOrAdvisoryOrg, lookupJapanOrgAlias } from "../tools/org_dictionary.js";

vi.mock("undici", () => ({ request: vi.fn() }));

function mockSearch(results: Array<{ title?: string; url?: string; content?: string }>) {
  vi.mocked(request).mockResolvedValueOnce({
    statusCode: 200,
    body: { json: async () => ({ results }) }
  } as any);
}

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

describe("lookupJapanOrgAlias boundaries", () => {
  it("rejects unrelated names that merely contain an alias", () => {
    for (const name of [
      "Delta Line", "Maersk Line", "Line Dynamics", "Red Line Group", "Santa Ana", "Ana Maria Foundation",
      "Canon City School District", "Olympus Medical Staffing", "Honda of Ruritania Dealers",
      "SoftBank Group", "Sony Pictures", "NEC Laboratories Europe", "Group Docomo",
      "constructor", "__proto__", ""
    ]) {
      expect(lookupJapanOrgAlias(name), name).toBeNull();
    }
  });

  it("matches aliases exactly, ignoring punctuation and legal suffixes", () => {
    const cases: Array<[string, string]> = [
      ["LINE", "LINEヤフー株式会社"],
      ["Line Corporation", "LINEヤフー株式会社"],
      ["LY Corporation", "LINEヤフー株式会社"],
      ["Toyota Motor Corporation", "トヨタ自動車株式会社"],
      ["Honda Motor Co., Ltd.", "本田技研工業株式会社"],
      ["The Sony Group Corp.", "ソニーグループ株式会社"],
      ["Canon Inc.", "キヤノン株式会社"],
      ["Hitachi, Ltd.", "株式会社日立製作所"],
      ["Fujitsu Limited", "富士通株式会社"],
      ["NTT (Nippon Telegraph and Telephone)", "日本電信電話株式会社 (NTT)"],
      ["  ntt   docomo ", "株式会社NTTドコモ"],
      ["Japan Airlines Co., Ltd.", "日本航空株式会社 (JAL)"],
      ["MS&AD", "MS&ADインシュアランスグループホールディングス株式会社"]
    ];
    for (const [name, expected] of cases) {
      expect(lookupJapanOrgAlias(name), name).toBe(expected);
    }
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

describe("searchOfficialName", () => {
  const search = (query: string) => searchOfficialName(query, "http://searxng.test/search");

  it("returns null when a foreign victim's snippet mentions a Japanese publisher", async () => {
    for (const publisher of ["株式会社インプレス", "株式会社マイナビ", "株式会社日経BP", "アイティメディア株式会社", "株式会社KADOKAWA", "ヤフー株式会社"]) {
      mockSearch([
        {
          title: `Acme Logistics breach - ${publisher}`,
          url: "https://news.example.jp/acme",
          content: `Acme Logistics (${publisher}) reported a ransomware attack.`
        }
      ]);
      expect(await search("Acme Logistics"), publisher).toBeNull();
    }
  });

  it("rejects an unrelated company that merely shares a page with the query", async () => {
    mockSearch([
      {
        title: "Acme Logistics ransomware attack",
        url: "https://blog.example.com/acme",
        content: "Acme Logistics was attacked. セキュリティ対策なら株式会社無関係へ。"
      }
    ]);
    expect(await search("Acme Logistics")).toBeNull();
  });

  it("rejects results that never mention the queried entity", async () => {
    mockSearch([{ title: "株式会社サンプル商事 (Sample Trading)", url: "https://sample.co.jp/" }]);
    expect(await search("Acme Logistics")).toBeNull();
  });

  it("resolves a Japanese company from an English query", async () => {
    mockSearch([
      { title: "株式会社サンプル商事（Sample Trading Co., Ltd.）| 会社概要", url: "https://example.co.jp/about" }
    ]);
    expect(await search("Sample Trading Co., Ltd.")).toBe("株式会社サンプル商事");
  });

  it("accepts a name titled on the company's own .jp domain", async () => {
    mockSearch([{ title: "サンプル商事株式会社 公式サイト", url: "https://www.sample-trading.co.jp/" }]);
    expect(await search("Sample Trading")).toBe("サンプル商事株式会社");
  });

  it("skips publisher boilerplate and picks the later matching name", async () => {
    mockSearch([
      { title: "Sample Trading news - 株式会社インプレス", content: "Sample Trading（株式会社サンプル商事）の発表" }
    ]);
    expect(await search("Sample Trading")).toBe("株式会社サンプル商事");
  });

  it("allows a publisher when the query targets it", async () => {
    mockSearch([{ title: "株式会社インプレス (Impress Corporation)" }]);
    expect(await search("Impress Corporation")).toBe("株式会社インプレス");
  });

  it("strips trailing punctuation, brackets and particles", async () => {
    const cases: Array<[string, string]> = [
      ["Sample（株式会社サンプル）", "株式会社サンプル"],
      ["Sample「株式会社サンプル」など", "株式会社サンプル"],
      ["Sample(株式会社サンプル)。", "株式会社サンプル"],
      ["Sample | 株式会社サンプルなど", "株式会社サンプル"],
      ["Sample | 株式会社サンプルは不正アクセスを公表した", "株式会社サンプル"],
      ["Sample | 株式会社サンプルの会社概要", "株式会社サンプル"],
      ["Sample | 当社はサンプル株式会社", "サンプル株式会社"]
    ];
    for (const [title, expected] of cases) {
      mockSearch([{ title, url: "https://sample.co.jp/" }]);
      expect(await search("Sample"), title).toBe(expected);
    }
  });

  it("keeps names that contain particle characters", async () => {
    for (const name of ["株式会社はてな", "株式会社ぐるなび"]) {
      mockSearch([{ title: `Sample (${name})` }]);
      expect(await search("Sample"), name).toBe(name);
    }
  });

  it("returns null on non-200 responses", async () => {
    vi.mocked(request).mockResolvedValueOnce({ statusCode: 503 } as any);
    expect(await search("Sample Trading")).toBeNull();
  });
});
