import { isDefensiveOrAdvisoryOrg, lookupJapanOrgAlias } from "./org_dictionary.js";
import { isGenericVictimOrg } from "../guardrails/sanitizer.js";
import { request } from "undici";

export interface EntityResolutionResult {
  officialNameJa: string | null;
  isJapaneseEntity: boolean;
  confidence: "high" | "medium" | "low";
  source: "dictionary" | "search" | "none";
}

export type OfficialNameSearcher = (query: string) => Promise<string | null>;

interface SearchResult {
  title?: string;
  url?: string;
  content?: string;
}

/**
 * News publishers and portals whose legal names appear in page boilerplate.
 * They are only accepted when the query itself names them (`aliases`).
 */
const PUBLISHER_ORGS: ReadonlyArray<{ core: string; exact?: boolean; aliases: string[] }> = [
  { core: "インプレス", aliases: ["impress"] },
  { core: "マイナビ", aliases: ["mynavi"] },
  { core: "日経bp", aliases: ["nikkeibp"] },
  { core: "日本経済新聞", aliases: ["nikkei"] },
  { core: "朝日新聞", aliases: ["asahi"] },
  { core: "アイティメディア", aliases: ["itmedia"] },
  { core: "itmedia", aliases: ["itmedia"] },
  { core: "kadokawa", aliases: ["kadokawa"] },
  { core: "翔泳社", aliases: ["shoeisha"] },
  { core: "prtimes", aliases: ["prtimes"] },
  // Exact match only, so that LINEヤフー is not treated as portal boilerplate.
  { core: "ヤフー", exact: true, aliases: ["yahoo"] }
];

// Query words that carry no identifying information.
const QUERY_STOPWORDS = new Set([
  "the", "of", "and", "co", "corp", "corporation", "inc", "incorporated", "ltd", "limited",
  "llc", "plc", "kk", "company", "group", "holdings", "japan"
]);

const LEGAL_FORMS = ["株式会社", "独立行政法人", "一般社団法人"];

// Characters that may appear inside a legal name: no whitespace, brackets or sentence punctuation.
const NAME_CHAR = String.raw`[^\s、。,!?()\[\]{}<>「」『』【】〈〉《》"'“”‘’:;|/…]`;

const ORG_PATTERNS = [
  new RegExp(`(?:株式会社|独立行政法人|一般社団法人)${NAME_CHAR}+`, "g"),
  new RegExp(`${NAME_CHAR}+?株式会社`, "g")
];

// Particles and connectives after which the remaining text is sentence, not name.
// Each requires a preceding non-hiragana character so that names such as "はてな" survive.
const CLAUSE_PARTICLES = /(?<=[^぀-ゟ])(?:では|は|が|を|など|について|により|による|における|に関する|として|から).*$/u;
const POSSESSIVE_CLAUSE = /(?:(?<=[゠-ヿA-Za-z0-9])の|(?<=[^぀-ゟ])の(?=公式|会社|企業|概要|サイト|ホームページ|ウェブサイト|情報|発表|採用|製品|サービス)).*$/u;
const TRAILING_PARTICLE = /(?<=[^぀-ゟ])[のにとでもへや]$/u;
const LEADING_CLAUSE = /^.*(?<=[^぀-ゟ])(?:は|が|を)/u;

/** Strips surrounding sentence fragments from a captured legal name; null if nothing is left. */
function cleanLegalName(captured: string): string | null {
  const form = LEGAL_FORMS.find((f) => captured.startsWith(f));
  let core: string;
  if (form) {
    core = captured.slice(form.length);
    core = core.replace(CLAUSE_PARTICLES, "").replace(POSSESSIVE_CLAUSE, "");
    core = core.replace(/[.\-・&~]+$/u, "").replace(TRAILING_PARTICLE, "");
  } else {
    core = captured.slice(0, -"株式会社".length).replace(LEADING_CLAUSE, "").replace(/^[.\-・&~]+/u, "");
  }
  // A core that still holds a legal form means two names were run together.
  if ([...core].length < 2 || LEGAL_FORMS.some((f) => core.includes(f))) return null;
  return form ? `${form}${core}` : `${core}株式会社`;
}

function significantTokens(query: string): string[] {
  return query
    .normalize("NFKC")
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter((t) => t.length >= 2 && !QUERY_STOPWORDS.has(t));
}

function isUnrequestedPublisher(name: string, tokens: string[]): boolean {
  const core = LEGAL_FORMS.reduce((n, f) => n.replace(f, ""), name.toLowerCase()).replace(/[\s\-_]/g, "");
  const query = tokens.join("");
  return PUBLISHER_ORGS.some(
    (p) => (p.exact ? core === p.core : core.startsWith(p.core)) && !p.aliases.some((a) => query.includes(a))
  );
}

/**
 * Requires the result to tie the captured name to the queried entity. Mere co-occurrence on a
 * page is not enough: the query must be part of the name, own the .jp domain whose title carries
 * the name, or stand directly next to the name.
 */
function refersToQuery(name: string, tokens: string[], item: SearchResult, fields: string[]): boolean {
  const joined = tokens.join("");
  const bounded = new RegExp(`(?<![a-z0-9])${joined}(?![a-z0-9])`, "u");
  if (bounded.test(name.toLowerCase().replace(/[\-_.&]/g, ""))) return true;

  const host = URL.canParse(item.url || "") ? new URL(item.url as string).hostname : "";
  const ownsDomain = host.endsWith(".jp") && host.split(".").some((label) => label.replace(/-/g, "") === joined);
  if (ownsDomain && fields[0].includes(name)) return true;

  const phrase = tokens.join(String.raw`[\s\-_.&,]*`);
  const suffix = String.raw`(?:[\s,.]*(?:co|corp|corporation|inc|ltd|limited|company|group|holdings|japan|kk)(?![a-z0-9])[.,]*)*`;
  const gap = String.raw`[\s(|/\-–—:]{0,4}`;
  const before = new RegExp(`(?<![a-z0-9])${phrase}${suffix}${gap}$`, "iu");
  const after = new RegExp(`^${gap}${phrase}(?![a-z0-9])`, "iu");
  return fields.some((text) => {
    for (let at = text.indexOf(name); at !== -1; at = text.indexOf(name, at + 1)) {
      if (before.test(text.slice(0, at)) || after.test(text.slice(at + name.length))) return true;
    }
    return false;
  });
}

/** Returns the first legal name in the results that verifiably belongs to the queried entity. */
function pickOfficialName(query: string, results: SearchResult[]): string | null {
  const tokens = significantTokens(query);
  if (tokens.length === 0) return null;

  for (const item of results) {
    const fields = [item.title, item.content].map((f) => (f || "").normalize("NFKC"));
    // Every identifying query word must occur somewhere in the result.
    const haystack = `${fields.join(" ")} ${item.url || ""}`.toLowerCase();
    if (!tokens.every((t) => haystack.includes(t))) continue;

    for (const text of fields) {
      for (const pattern of ORG_PATTERNS) {
        for (const match of text.matchAll(pattern)) {
          const name = cleanLegalName(match[0]);
          if (!name || isDefensiveOrAdvisoryOrg(name) || isUnrequestedPublisher(name, tokens)) continue;
          if (refersToQuery(name, tokens, item, fields)) return name;
        }
      }
    }
  }
  return null;
}

/**
 * Searches SearXNG for Japanese official company/organization name if not found in dictionary.
 */
export async function searchOfficialName(
  query: string,
  searxngUrl: string = process.env.SEARXNG_URL || "http://searxng-service.searxng.svc.cluster.local:8080/search"
): Promise<string | null> {
  try {
    const encoded = encodeURIComponent(`${query} 正式名称 会社 日本`);
    const target = `${searxngUrl}?q=${encoded}&format=json`;
    const res = await request(target, {
      method: "GET",
      headers: { "Accept": "application/json" },
      headersTimeout: 4000,
      bodyTimeout: 4000
    });

    if (res.statusCode !== 200) {
      return null;
    }

    const data = (await res.body.json()) as any;
    if (!data || !Array.isArray(data.results)) {
      return null;
    }

    return pickOfficialName(query, data.results.slice(0, 3));
  } catch (err) {
    // Graceful fallback on search errors
  }
  return null;
}

/**
 * Resolves an entity string to its official Japanese representation.
 */
export async function resolveJapaneseEntity(
  rawName: string,
  search: OfficialNameSearcher = searchOfficialName
): Promise<EntityResolutionResult> {
  const trimmed = (rawName || "").trim();
  // Generic placeholders and defensive/advisory organizations (JPCERT/CC, IPA, NISC, CISA, ...)
  // are never resolved as victims, so they can never elevate japan_relevance.
  if (!trimmed || isGenericVictimOrg(trimmed) || isDefensiveOrAdvisoryOrg(trimmed)) {
    return {
      officialNameJa: null,
      isJapaneseEntity: false,
      confidence: "low",
      source: "none"
    };
  }

  const dictMatch = lookupJapanOrgAlias(trimmed);
  if (dictMatch) {
    return {
      officialNameJa: dictMatch,
      isJapaneseEntity: true,
      confidence: "high",
      source: "dictionary"
    };
  }

  // Check if string already contains Japanese characters
  const hasJapanese = /[\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FAF]/.test(rawName);
  if (hasJapanese) {
    return {
      officialNameJa: rawName.trim(),
      isJapaneseEntity: true,
      confidence: "high",
      source: "none"
    };
  }

  // Try SearXNG fallback for unknown English corporate names
  const searchMatch = await search(trimmed);
  if (searchMatch) {
    return {
      officialNameJa: searchMatch,
      isJapaneseEntity: true,
      confidence: "medium",
      source: "search"
    };
  }

  return {
    officialNameJa: null,
    isJapaneseEntity: false,
    confidence: "low",
    source: "none"
  };
}

