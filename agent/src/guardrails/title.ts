/**
 * Incident title cleanup and deterministic fallback synthesis.
 */

const CJK_CLASS = "\\w\\u3000-\\u303f\\u3040-\\u309f\\u30a0-\\u30ff\\uff00-\\uffef\\u4e00-\\u9faf\\s";
const MEDIA_SUFFIX_RE = new RegExp(`\\s*[-|｜]\\s*[${CJK_CLASS}]+(ニュース|新聞|オンライン|ブログ|Media|NEXT).*$`, "i");
const MEDIA_PAREN_SUFFIX_RE = new RegExp(`\\s*\\([${CJK_CLASS}]+(ニュース|新聞|オンライン)\\)$`, "i");

/** Strips social-media quote framing, news-publisher suffixes, and clickbait prefixes. */
export function cleanIncidentTitle(rawTitle: string): string {
  if (!rawTitle) return "";
  let t = rawTitle.trim();
  // X / Twitter quote prefix: 'Someone on X: "..."', 'Someone (@handle) on X: "..."'
  t = t.replace(/^.+?(\s+on\s+X:\s*["“]?|\s*\(@[^\)]+\)\s+on\s+X:\s*["“]?)/i, "");
  // Trailing quote and " / X"
  t = t.replace(/["”]?\s*(\/\s*X)?$/i, "");
  // News media suffixes: ' - 日本経済新聞', ' | NHKニュース', ' (毎日新聞)', ': Security NEXT'
  t = t.replace(MEDIA_SUFFIX_RE, "");
  t = t.replace(MEDIA_PAREN_SUFFIX_RE, "");
  // Sensational prefixes: '【速報】', '【独自】', '【緊急】'
  t = t.replace(/^【(速報|独自|緊急|注目|重要|注目記事)】\s*/, "");
  t = t.replace(/^["'“”]/, "").replace(/["'“”]$/, "").trim();
  return t;
}

const NOISY_JA_RE = /^(@|〜って|ってすごいな|信頼できなくな|なんか|結局|草|w{2,})/i;
const NOISY_EN_RE = /^(@|someone on X)/i;
const MIN_TITLE_LENGTH = 6;

export function isNoisyTitleJa(title: string): boolean {
  return !title || NOISY_JA_RE.test(title) || title.length < MIN_TITLE_LENGTH;
}

export function isNoisyTitleEn(title: string): boolean {
  return !title || NOISY_EN_RE.test(title) || title.length < MIN_TITLE_LENGTH;
}

export interface TitleContext {
  victims: string[];
  attackType: string;
  affectedProducts: string[];
  cves: string[];
}

/** Synthesizes a structured Japanese title from extracted keys, or null when no key is usable. */
export function synthesizeTitleJa(ctx: TitleContext): string | null {
  const victim = ctx.victims[0];
  if (victim) {
    if (ctx.attackType === "Ransomware") return `【ランサムウェア】${victim}に対する攻撃被害`;
    if (ctx.attackType === "Data Breach") return `【不正アクセス】${victim}における情報流出事案`;
    return `【サイバー攻撃】${victim}におけるセキュリティインシデント`;
  }
  const cveStr = ctx.cves.length > 0 ? ` (${ctx.cves.join(", ")})` : "";
  if (ctx.affectedProducts.length > 0) return `【脆弱性】${ctx.affectedProducts[0]}における脆弱性${cveStr}`;
  if (ctx.attackType === "Vulnerability" && ctx.cves.length > 0) {
    return `【脆弱性】${ctx.cves.join(", ")}に関するセキュリティアドバイザリ`;
  }
  return null;
}

/** Synthesizes a structured English title from extracted keys, or null when no key is usable. */
export function synthesizeTitleEn(ctx: TitleContext): string | null {
  const victim = ctx.victims[0];
  if (victim) {
    if (ctx.attackType === "Ransomware") return `[Ransomware] ${victim} Hit by Ransomware Attack`;
    if (ctx.attackType === "Data Breach") return `[Data Breach] Unauthorized Access and Potential Data Breach at ${victim}`;
    return `[Cyber Threat] Security Incident at ${victim}`;
  }
  const cveStr = ctx.cves.length > 0 ? ` (${ctx.cves.join(", ")})` : "";
  if (ctx.affectedProducts.length > 0) return `[Vulnerability] Security Vulnerability in ${ctx.affectedProducts[0]}${cveStr}`;
  if (ctx.attackType === "Vulnerability" && ctx.cves.length > 0) {
    return `[Vulnerability] Security Advisory for ${ctx.cves.join(", ")}`;
  }
  return null;
}
