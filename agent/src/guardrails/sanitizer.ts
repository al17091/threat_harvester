/**
 * Deterministic entity sanitization and source-text grounding for primary-extraction keys.
 * Victim and actor rules mirror api/internal/models/incident.go so agent output is already
 * clean before mechanical correlation downstream.
 */
import { isDefensiveOrAdvisoryOrg } from "../tools/org_dictionary.js";
import {
  ACTOR_ALIAS_GROUNDINGS,
  CANONICAL_ACTOR_NAMES,
  GENERIC_VICTIM_EXACT,
  GENERIC_VICTIM_SUBSTRINGS,
  INVALID_ACTOR_EXACT,
  INVALID_ACTOR_SUBSTRINGS,
} from "./lexicon.js";

export const MAX_CVES = 20;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/** Coerces an untrusted LLM value into a list of trimmed, non-empty strings. */
export function toStringList(value: unknown): string[] {
  const raw = Array.isArray(value) ? value : typeof value === "string" ? value.split(/[,、;]/) : [];
  const out: string[] = [];
  for (const v of raw) {
    if (typeof v !== "string") continue;
    const t = v.trim();
    if (t) out.push(t);
  }
  return out;
}

function dedupeCaseInsensitive(values: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of values) {
    const key = v.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(v);
  }
  return out;
}

const TRIM_CHARS = "[]\"'「」『』【】“” .,;:";
function trimChars(s: string, chars: string): string {
  let start = 0;
  let end = s.length;
  while (start < end && chars.includes(s[start])) start++;
  while (end > start && chars.includes(s[end - 1])) end--;
  return s.slice(start, end);
}

// ---------------------------------------------------------------------------
// Threat actor normalization (port of stripActorGroupQualifiers / IsKnownThreatActor)
// ---------------------------------------------------------------------------

const ACTOR_CODE_ID_RE =
  /\b(APT-?(?:C-)?\d{1,3}|UNC\d{4}|UAT-\d{4,5}|UTA\d{4}|FIN\d{1,2}|Storm-\d{4}|CL-STA-\d{4}|TA-SC-\d{2,3})\b/i;
const ACTOR_NAMED_FAMILY_RE =
  /\b(Earth\s+[A-Z][a-z]{2,15}|(?:Volt|Salt|Flax|Silk|Brass|Granite)\s+Typhoon|(?:Charming|Static|Imperial)\s+Kitten|(?:Mustang|Stone|Emissary|Aquatic|Warp)\s+Panda|(?:Cozy|Fancy|Venomous)\s+Bear|BRONZE\s+[A-Z]{3,15}|GOLD\s+[A-Z]{3,15}|Silent\s+Lynx|Luna\s+Moth|Seven\s+Deadly\s+Sins)\b/;

const ACTOR_PREFIXES = [
  "cyber threat group ", "cyber attack group ", "ransomware group ", "ransomware gang ",
  "extortion group ", "threat group ", "apt group ", "aka ", "a.k.a. ", "別名：", "別名:",
  "サイバー攻撃グループ", "ランサムウェアグループ", "ランサムウェア集団", "攻撃グループ", "脅威グループ", "aptグループ",
];
const ACTOR_SUFFIXES = [
  " ransomware leak site", " ransomware group", " ransomware gang", " ransomware dls", " ransomware",
  " cyber threat group", " cyber attack group", " cybercrime group", " extortion group",
  " threat group", " threat actor", " apt group", " supply chain products",
  "ランサムウェアグループ", "ランサムウェア集団", "ランサムウェア", "サイバー攻撃グループ", "攻撃グループ", "脅威アクター",
];

/** Removes generic group/ransomware qualifiers and maps to the canonical actor label when known. */
export function stripActorGroupQualifiers(raw: string): string {
  let s = trimChars((raw || "").trim(), TRIM_CHARS);
  if (!s) return "";
  let changed = true;
  while (changed) {
    changed = false;
    let low = s.toLowerCase();
    for (const p of ACTOR_PREFIXES) {
      if (low.startsWith(p) && s.length > p.length + 1) {
        s = trimChars(s.slice(p.length).trim(), TRIM_CHARS);
        changed = true;
        break;
      }
    }
    low = s.toLowerCase();
    for (const suf of ACTOR_SUFFIXES) {
      if (low.endsWith(suf) && s.length > suf.length + 1) {
        s = trimChars(s.slice(0, s.length - suf.length).trim(), TRIM_CHARS);
        changed = true;
        break;
      }
    }
  }
  const canon = CANONICAL_ACTOR_NAMES[s.toLowerCase()];
  if (canon) return canon;
  if (ACTOR_CODE_ID_RE.test(s) && s.split(/\s+/).length === 1) return s.toUpperCase();
  return s;
}

/** Splits parenthetical aliases ("MirrorFace (Earth Kasha)") and strips group qualifiers. */
export function normalizeActorCandidates(raw: string): string[] {
  const trimmed = (raw || "").trim();
  if (!trimmed) return [];
  const parens = trimmed.replace(/（/g, "(").replace(/）/g, ")");
  const parts: string[] = [];
  const openIdx = parens.indexOf("(");
  if (openIdx > 0 && parens.endsWith(")")) {
    const inner = parens.slice(openIdx + 1, -1).trim();
    if (/\p{L}/u.test(inner)) {
      parts.push(parens.slice(0, openIdx).trim(), inner);
    } else {
      parts.push(trimmed);
    }
  } else {
    parts.push(trimmed);
  }
  return parts.map(stripActorGroupQualifiers).filter((p) => p !== "");
}

export function isKnownThreatActor(s: string): boolean {
  for (const cand of normalizeActorCandidates(s)) {
    if (CANONICAL_ACTOR_NAMES[cand.toLowerCase()]) return true;
    const words = cand.split(/\s+/).length;
    if (ACTOR_CODE_ID_RE.test(cand) && words === 1) return true;
    if (ACTOR_NAMED_FAMILY_RE.test(cand) && words === 2) return true;
  }
  return false;
}

/** Port of IsValidThreatActor plus agent-specific defensive-org and vendor exclusions. */
export function isValidThreatActor(actor: string): boolean {
  const s = stripActorGroupQualifiers(actor);
  if (!s || [...s].length < 2 || s.length > 40) return false;
  if (s.startsWith("@")) return false;
  const low = s.toLowerCase();
  if (INVALID_ACTOR_EXACT.has(low) || low.startsWith("not ") || low.startsWith("unknown")) return false;
  if (/ on (?:x|twitter|bluesky|threads)\b/.test(low)) return false;
  if (INVALID_ACTOR_SUBSTRINGS.some((sub) => low.includes(sub))) return false;
  if (/google\s*tag|trend\s*micro|blogger|journalist|研究者|投稿者/.test(low)) return false;
  if (isDefensiveOrAdvisoryOrg(s)) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Victim organizations (port of SanitizeVictimOrgName / IsGenericVictimOrg)
// ---------------------------------------------------------------------------

const SCRAPER_SUFFIXES = new Set(["ransomware.live", "ransomlook", "ransomlook.io"]);

/** Strips scraper title suffixes such as " - Ransomware.live" or " – <ActorName>". */
export function sanitizeVictimOrgName(name: string): string {
  let s = trimChars((name || "").trim(), "[]\"' ");
  if (!s) return "";
  for (const sep of [" - ", " – ", " — "]) {
    const idx = s.lastIndexOf(sep);
    if (idx > 0) {
      const tail = s.slice(idx + sep.length).trim();
      if (SCRAPER_SUFFIXES.has(tail.toLowerCase()) || isKnownThreatActor(tail)) {
        s = s.slice(0, idx).trim();
      }
    }
  }
  return s;
}

/** Short ASCII substrings (e.g. "sme", "sdk") match whole words only so names like "Smeg" survive. */
const SHORT_ASCII_WORD = /^[a-z]{1,4}$/;
function containsGenericSubstring(cleaned: string): boolean {
  return GENERIC_VICTIM_SUBSTRINGS.some((sub) => {
    if (SHORT_ASCII_WORD.test(sub)) return new RegExp(`(?<![a-z0-9])${sub}s?(?![a-z0-9])`).test(cleaned);
    return cleaned.includes(sub);
  });
}

/**
 * True when a victim name is generic, masked, a CVE/product token, a threat actor, or a
 * defensive/advisory organization. Exact-match generic words ("company", "organization")
 * are rejected, but real names containing them ("Tokyo Electric Power Company") survive.
 */
export function isGenericVictimOrg(name: string): boolean {
  const sanitized = sanitizeVictimOrgName(name);
  const cleaned = trimChars(sanitized.trim(), "[]\"' ").toLowerCase();
  if (!cleaned || [...cleaned].length < 2) return true;
  if (cleaned.includes("***") || cleaned.includes("...") || cleaned.includes("…")) return true;
  if (cleaned.includes("cve-") || cleaned.startsWith("cve")) return true;
  if (isKnownThreatActor(cleaned) || cleaned === "breachforums" || cleaned === "darknet army") return true;
  if (isDefensiveOrAdvisoryOrg(sanitized)) return true;
  if (GENERIC_VICTIM_EXACT.has(cleaned)) return true;
  if (/^(?:multiple |various |not |unknown|unspecified|no specific|approximately )/.test(cleaned)) return true;
  if (/ (?:users|customers)$/.test(cleaned) || / (?:users|customers) \(/.test(cleaned)) return true;
  return containsGenericSubstring(cleaned);
}

/** Sanitizes, filters, and de-duplicates victim organizations. */
export function cleanVictimOrgs(orgs: unknown): string[] {
  const out: string[] = [];
  for (const o of toStringList(orgs)) {
    const s = sanitizeVictimOrgName(o);
    if (!isGenericVictimOrg(s)) out.push(s);
  }
  return dedupeCaseInsensitive(out);
}

// ---------------------------------------------------------------------------
// CVE extraction & verification
// ---------------------------------------------------------------------------

const CVE_GLOBAL_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const CVE_EXACT_RE = /^CVE-\d{4}-\d{4,7}$/;

/** Extracts unique, uppercased CVE IDs from text in order of first appearance. */
export function extractCves(text: string, cap: number = MAX_CVES): string[] {
  const normalized = (text || "").normalize("NFKC").replace(/[‐‑‒–—―]/g, "-");
  const found = normalized.match(CVE_GLOBAL_RE) || [];
  return dedupeCaseInsensitive(found.map((c) => c.toUpperCase())).slice(0, cap);
}

/**
 * Keeps model-reported CVEs only when they are well-formed and present in the source,
 * then rescues source CVEs the model missed. Verified model CVEs keep priority under the cap.
 */
export function reconcileCves(modelCves: unknown, sourceText: string, cap: number = MAX_CVES): string[] {
  const sourceCves = extractCves(sourceText, Number.MAX_SAFE_INTEGER);
  const sourceSet = new Set(sourceCves);
  const verified = toStringList(modelCves)
    .map((c) => c.normalize("NFKC").replace(/[‐‑‒–—―]/g, "-").toUpperCase())
    .filter((c) => CVE_EXACT_RE.test(c) && sourceSet.has(c));
  return dedupeCaseInsensitive([...verified, ...sourceCves]).slice(0, cap);
}

// ---------------------------------------------------------------------------
// Threat actor grounding
// ---------------------------------------------------------------------------

/** Lowercase NFKC text with separators collapsed to single spaces, for grounding checks. */
export function normalizeForGrounding(text: string): string {
  return (text || "")
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[‐‑‒–—―]/g, "-")
    .replace(/\s+/g, " ");
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const NON_ASCII = /[^\x00-\x7f]/;

/** Matches a term in normalized text tolerating spacing/hyphenation ("Lock-Bit", "Volt  Typhoon"). */
function termAppears(term: string, normalizedSource: string): boolean {
  const t = normalizeForGrounding(term).trim();
  if (!t) return false;
  // CJK has no word boundaries; plain substring matching is the only meaningful check.
  if (NON_ASCII.test(t)) return normalizedSource.includes(t);
  const compact = t.replace(/[\s\-_.]+/g, "");
  if (!compact) return false;
  const body = [...compact].map(escapeRegExp).join("[\\s\\-_.]*");
  return new RegExp(`(?<![a-z0-9])${body}(?![a-z0-9])`).test(normalizedSource);
}

/**
 * All spellings that ground a canonical actor: lexicon aliases plus every key mapping to it.
 * Short ASCII aliases (e.g. "inc" for INC Ransom) are skipped because they collide with
 * ordinary words such as corporate suffixes ("Acme Inc."); the actor's own spelling is always kept.
 */
function groundingAliases(actor: string): string[] {
  const canonical = stripActorGroupQualifiers(actor);
  const aliases = new Set<string>([actor, canonical]);
  const canonLow = canonical.toLowerCase();
  const addAlias = (a: string) => {
    if (NON_ASCII.test(a) || a.replace(/[\s\-_.]+/g, "").length >= 4) aliases.add(a);
  };
  for (const [key, value] of Object.entries(CANONICAL_ACTOR_NAMES)) {
    if (value.toLowerCase() === canonLow) addAlias(key);
  }
  for (const a of ACTOR_ALIAS_GROUNDINGS[canonLow] || []) addAlias(a);
  return [...aliases];
}

export function isActorGrounded(actor: string, normalizedSource: string): boolean {
  return groundingAliases(actor).some((a) => termAppears(a, normalizedSource));
}

export interface SanitizedActors {
  threat_actors: string[];
  threat_actor_reasons: Record<string, string>;
}

/**
 * Filters researchers/handles/vendors/defensive orgs/stopwords, canonicalizes names,
 * drops actors not grounded in the source text, and prunes reasons to surviving actors.
 */
export function sanitizeThreatActors(actors: unknown, reasons: unknown, sourceText: string): SanitizedActors {
  const normalizedSource = normalizeForGrounding(sourceText);
  const surviving: string[] = [];
  const originByCanonical = new Map<string, string[]>();

  for (const raw of toStringList(actors)) {
    if (raw.startsWith("@") || !isValidThreatActor(raw)) continue;
    const canonical = stripActorGroupQualifiers(raw);
    if (!isActorGrounded(raw, normalizedSource) && !isActorGrounded(canonical, normalizedSource)) continue;
    const key = canonical.toLowerCase();
    if (!originByCanonical.has(key)) {
      originByCanonical.set(key, []);
      surviving.push(canonical);
    }
    originByCanonical.get(key)!.push(raw.toLowerCase());
  }

  const prunedReasons: Record<string, string> = {};
  if (reasons && typeof reasons === "object" && !Array.isArray(reasons)) {
    for (const [k, v] of Object.entries(reasons as Record<string, unknown>)) {
      if (typeof v !== "string" || !v.trim()) continue;
      const canonKey = stripActorGroupQualifiers(k).toLowerCase();
      const match = surviving.find(
        (a) => a.toLowerCase() === canonKey || originByCanonical.get(a.toLowerCase())?.includes(k.trim().toLowerCase())
      );
      if (match && !(match in prunedReasons)) prunedReasons[match] = v.trim();
    }
  }

  return { threat_actors: surviving, threat_actor_reasons: prunedReasons };
}

// ---------------------------------------------------------------------------
// Affected products
// ---------------------------------------------------------------------------

/** Trims, de-duplicates, and drops CVE IDs or placeholder tokens from affected_products. */
export function cleanAffectedProducts(products: unknown): string[] {
  return dedupeCaseInsensitive(
    toStringList(products).filter((p) => !/^cve-\d{4}-\d+$/i.test(p) && !GENERIC_VICTIM_EXACT.has(p.toLowerCase()))
  );
}
