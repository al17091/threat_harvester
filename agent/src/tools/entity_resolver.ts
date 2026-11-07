import { lookupJapanOrgAlias } from "./org_dictionary.js";
import { request } from "undici";

export interface EntityResolutionResult {
  officialNameJa: string | null;
  isJapaneseEntity: boolean;
  confidence: "high" | "medium" | "low";
  source: "dictionary" | "search" | "none";
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
    if (!data || !Array.isArray(data.results) || data.results.length === 0) {
      return null;
    }

    // Scan top 3 search results for "株式会社..." or "独立行政法人..."
    const orgRegex = /(株式会社[^\s、。]+|[^\s、。]+株式会社|独立行政法人[^\s、。]+|一般社団法人[^\s、。]+)/;
    for (const item of data.results.slice(0, 3)) {
      const text = `${item.title || ""} ${item.content || ""}`;
      const match = text.match(orgRegex);
      if (match && match[1]) {
        return match[1].trim();
      }
    }
  } catch (err) {
    // Graceful fallback on search errors
  }
  return null;
}

/**
 * Resolves an entity string to its official Japanese representation.
 */
export async function resolveJapaneseEntity(rawName: string): Promise<EntityResolutionResult> {
  const dictMatch = lookupJapanOrgAlias(rawName);
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
  const searchMatch = await searchOfficialName(rawName);
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

