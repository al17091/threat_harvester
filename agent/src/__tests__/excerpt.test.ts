import { describe, it, expect } from "vitest";
import { buildExcerpt, normalizeWhitespace, scoreSegment, EXCERPT_BUDGET } from "../context/excerpt.js";

const filler = (n: number, word = "Lorem ipsum dolor sit amet consectetur") =>
  Array.from({ length: n }, (_, i) => `${word} paragraph ${i} with ordinary narrative text and nothing notable.`).join("\n\n");

describe("normalizeWhitespace", () => {
  it("collapses runs of spaces, tabs, NBSP and blank lines but keeps paragraphs", () => {
    const out = normalizeWhitespace("A\t\tB  C\r\n\r\n\r\n\r\nD   E  ");
    expect(out).toBe("A B C\n\nD E");
  });
});

describe("buildExcerpt", () => {
  it("returns short content unchanged (after normalization)", () => {
    expect(buildExcerpt("Short  article.")).toBe("Short article.");
  });

  it("never exceeds the 4000-character budget", () => {
    const raw = filler(200);
    const out = buildExcerpt(raw);
    expect(out.length).toBeLessThanOrEqual(EXCERPT_BUDGET);
  });

  it("keeps the lead block and rescues late CVEs, victims and breach cues (defect 5)", () => {
    const lead = "Security news roundup for this week.";
    const late =
      "Acme Holdings Co., Ltd. confirmed a ransomware attack exploiting CVE-2026-12345; data was exfiltrated.";
    const raw = [lead, filler(120), late, filler(40)].join("\n\n");
    expect(raw.slice(0, 4000)).not.toContain("CVE-2026-12345");

    const out = buildExcerpt(raw);
    expect(out.startsWith(lead)).toBe(true);
    expect(out).toContain("CVE-2026-12345");
    expect(out).toContain("Acme Holdings Co., Ltd.");
    expect(out).toContain("\n...\n");
  });

  it("emits selected paragraphs in original document order", () => {
    const a = "First signal: CVE-2026-11111 affects Foo Corp. systems after a breach.";
    const b = "Second signal: CVE-2026-22222 exploited in the wild against Bar Inc. with data stolen.";
    const raw = [filler(60), a, filler(30), b, filler(30)].join("\n\n");
    const out = buildExcerpt(raw);
    expect(out.indexOf("CVE-2026-11111")).toBeGreaterThan(-1);
    expect(out.indexOf("CVE-2026-11111")).toBeLessThan(out.indexOf("CVE-2026-22222"));
  });

  it("splits a single giant paragraph so late signals are still reachable", () => {
    const sentences = Array.from({ length: 200 }, (_, i) => `Sentence ${i} is unremarkable.`);
    sentences.push("株式会社サンプルでランサムウェア被害が発生し、CVE-2026-99999が悪用された。");
    const out = buildExcerpt(sentences.join(" "));
    expect(out.length).toBeLessThanOrEqual(EXCERPT_BUDGET);
    expect(out).toContain("CVE-2026-99999");
  });
});

describe("scoreSegment", () => {
  it("rewards CTI signals and penalizes boilerplate", () => {
    expect(scoreSegment("CVE-2026-1234 exploited against 株式会社テスト; data leaked.")).toBeGreaterThan(5);
    expect(scoreSegment("Subscribe to our newsletter. Share on Facebook. All rights reserved ©.")).toBeLessThan(0);
  });
});
