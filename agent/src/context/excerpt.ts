/**
 * Deterministic CTI-aware excerpting.
 *
 * The 3B extraction model runs single-turn on CPU, so the prompt budget is fixed.
 * Instead of blindly keeping the first N characters, we keep the lead block and then
 * fill the remaining budget with the paragraphs that carry the most CTI signal
 * (CVE IDs, named organizations, breach cues, IOCs), emitted in original order.
 */

export const EXCERPT_BUDGET = 4000;
export const LEAD_BUDGET = 2000;
/** Paragraphs longer than this are split into sentence-aligned chunks before scoring. */
const MAX_SEGMENT_CHARS = 600;
const GAP_SEPARATOR = "\n...\n";
const CONTIGUOUS_SEPARATOR = "\n\n";

interface Segment {
  index: number;
  text: string;
}

/** Normalizes whitespace while preserving paragraph boundaries. */
export function normalizeWhitespace(raw: string): string {
  return (raw || "")
    .replace(/\r\n?/g, "\n")
    .replace(/[\t\f\v  -​  　]+/g, " ")
    .split("\n")
    .map((line) => line.replace(/ {2,}/g, " ").trim())
    .join("\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

/** Splits an oversized paragraph at sentence boundaries, hard-wrapping anything still too long. */
function chunkParagraph(paragraph: string): string[] {
  if (paragraph.length <= MAX_SEGMENT_CHARS) return [paragraph];
  const sentences = paragraph.split(/(?<=[.!?。！？])\s*/u).filter((s) => s.length > 0);
  const chunks: string[] = [];
  let current = "";
  const flush = () => {
    if (current) chunks.push(current.trim());
    current = "";
  };
  for (const sentence of sentences) {
    if (sentence.length > MAX_SEGMENT_CHARS) {
      flush();
      for (let i = 0; i < sentence.length; i += MAX_SEGMENT_CHARS) {
        chunks.push(sentence.slice(i, i + MAX_SEGMENT_CHARS).trim());
      }
      continue;
    }
    // CJK sentences join without a space; Latin sentences join with one.
    const sep = current && !/[。！？]$/u.test(current) ? " " : "";
    if (current.length + sep.length + sentence.length > MAX_SEGMENT_CHARS) {
      flush();
      current = sentence;
    } else {
      current += sep + sentence;
    }
  }
  flush();
  return chunks.filter((c) => c.length > 0);
}

function segment(text: string): Segment[] {
  // Prefer blank-line paragraphs; fall back to single lines for line-oriented scrapes.
  let paragraphs = text.split(/\n\n+/);
  if (paragraphs.length < 3) paragraphs = text.split(/\n+/);
  const out: Segment[] = [];
  for (const p of paragraphs) {
    const trimmed = p.trim();
    if (!trimmed) continue;
    for (const chunk of chunkParagraph(trimmed)) {
      out.push({ index: out.length, text: chunk });
    }
  }
  return out;
}

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const CORP_RE =
  /株式会社|有限会社|独立行政法人|一般社団法人|一般財団法人|国立大学法人|学校法人|医療法人|地方独立行政法人|\bInc\.|\bCorp\.|\bCorporation\b|\bCo\.,?\s*Ltd\.?|\bLtd\.|\bLLC\b|\bGmbH\b|\bS\.A\.|\bPLC\b|病院|大学|市役所|県庁|町役場/gi;
const BREACH_RE =
  /ransomware|ランサムウェア|breach|data leak|leaked|exfiltrat|unauthori[sz]ed access|不正アクセス|情報漏え?洩|漏えい|流出|暗号化|encrypt|compromis|stolen|窃取|被害|extortion|恐喝|leak site|リークサイト|attack(?:ed)? by|threat actor|攻撃グループ|in the wild|actively exploited|悪用/gi;
const VERSION_RE = /\b(?:v|version\s*)?\d+\.\d+(?:\.\d+)+\b|\bversion\b|バージョン/gi;
const DATE_RE =
  /\b20\d{2}[-/.]\d{1,2}(?:[-/.]\d{1,2})?\b|20\d{2}年\d{1,2}月|\b(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\.?\s+\d{1,2},?\s+20\d{2}\b/gi;
const IOC_RE =
  /\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b|hxxps?:\/\/|\[\.\]|\[dot\]/gi;
const BOILERPLATE_RE =
  /cookie|subscribe|newsletter|sign up|share (?:this|on)|follow us|all rights reserved|copyright|©|privacy policy|terms of (?:use|service)|related (?:articles|posts|stories)|read more|advertisement|関連記事|この記事をシェア|シェアする|ログイン|会員登録|メルマガ|広告|お問い合わせ|プライバシーポリシー|利用規約|著作権/gi;
const URL_RE = /https?:\/\/\S+/gi;

function countMatches(text: string, re: RegExp): number {
  re.lastIndex = 0;
  const m = text.match(re);
  return m ? m.length : 0;
}

function countDistinct(text: string, re: RegExp): number {
  re.lastIndex = 0;
  const m = text.match(re);
  return m ? new Set(m.map((s) => s.toLowerCase())).size : 0;
}

/** Scores a paragraph for CTI signal density. Positive scores are candidates for inclusion. */
export function scoreSegment(text: string): number {
  let score = 0;
  score += Math.min(countDistinct(text, CVE_RE), 4) * 5;
  score += Math.min(countDistinct(text, CORP_RE), 3) * 3;
  score += Math.min(countDistinct(text, BREACH_RE), 4) * 2;
  score += Math.min(countDistinct(text, IOC_RE), 3) * 2;
  score += Math.min(countMatches(text, VERSION_RE), 2);
  score += Math.min(countMatches(text, DATE_RE), 2);
  score -= Math.min(countDistinct(text, BOILERPLATE_RE), 3) * 4;
  if (countMatches(text, URL_RE) >= 3) score -= 2;
  if (text.length < 40) score -= 1;
  return score;
}

/**
 * Builds a budget-bounded excerpt: lead block (~LEAD_BUDGET chars) plus the highest-signal
 * remaining paragraphs in original document order, with "\n...\n" marking skipped content.
 * Output length never exceeds `budget`.
 */
export function buildExcerpt(raw: string, budget: number = EXCERPT_BUDGET, leadBudget: number = LEAD_BUDGET): string {
  const text = normalizeWhitespace(raw);
  if (text.length <= budget) return text;

  const segments = segment(text);
  const selected = new Set<number>();
  let used = 0;

  // 1. Lead block: contiguous segments from the top.
  let leadEnd = 0;
  for (const seg of segments) {
    const cost = (selected.size > 0 ? CONTIGUOUS_SEPARATOR.length : 0) + seg.text.length;
    if (used + cost > leadBudget) break;
    selected.add(seg.index);
    used += cost;
    leadEnd = seg.index + 1;
  }

  // 2. Highest-signal remaining segments (stable on ties: earlier first).
  const candidates = segments
    .slice(leadEnd)
    .map((seg) => ({ seg, score: scoreSegment(seg.text) }))
    .filter((c) => c.score > 0)
    .sort((a, b) => b.score - a.score || a.seg.index - b.seg.index);

  for (const { seg } of candidates) {
    // Reserve the worst-case separator so the final assembly always fits.
    const cost = GAP_SEPARATOR.length + seg.text.length;
    if (used + cost > budget) continue;
    selected.add(seg.index);
    used += cost;
  }

  // 3. Assemble in original order.
  let out = "";
  let prev = -1;
  for (const seg of segments) {
    if (!selected.has(seg.index)) continue;
    if (prev >= 0) out += seg.index === prev + 1 ? CONTIGUOUS_SEPARATOR : GAP_SEPARATOR;
    out += seg.text;
    prev = seg.index;
  }
  if (prev < segments.length - 1 && out.length + GAP_SEPARATOR.trimEnd().length <= budget) {
    out += GAP_SEPARATOR.trimEnd();
  }
  return out.slice(0, budget);
}
