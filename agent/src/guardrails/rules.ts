/**
 * Pure, deterministic severity / relevance rules applied after LLM extraction.
 * These replace LLM self-correction turns so single-turn CPU inference never
 * discards otherwise valid extractions.
 */

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";
export type JapanRelevance = "Direct" | "Indirect" | "None";

const SEVERITY_MAP: Record<string, Severity> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  moderate: "Medium",
  low: "Low",
  info: "Info",
  informational: "Info",
  information: "Info",
};

const RELEVANCE_MAP: Record<string, JapanRelevance> = {
  direct: "Direct",
  indirect: "Indirect",
  none: "None",
};

/** Maps a free-form severity value to the schema enum (defaults to "Info"). */
export function normalizeSeverity(value: unknown): Severity {
  return (typeof value === "string" && SEVERITY_MAP[value.trim().toLowerCase()]) || "Info";
}

/** Maps a free-form japan_relevance value to the schema enum (defaults to "None"). */
export function normalizeJapanRelevance(value: unknown): JapanRelevance {
  return (typeof value === "string" && RELEVANCE_MAP[value.trim().toLowerCase()]) || "None";
}

/** RULE 1: "Critical" requires Direct Japan relevance; otherwise clamp to "High". */
export function clampSeverityForRelevance(severity: Severity, relevance: JapanRelevance): Severity {
  return severity === "Critical" && relevance !== "Direct" ? "High" : severity;
}

const RETROSPECTIVE_TITLE_MARKERS = [
  "事例まとめ",
  "事案一覧",
  "事例一覧",
  "統合報告書",
  "年次報告",
  "annual report",
  "year in review",
  "case studies",
];

/** RULE 4: retrospective reviews / annual summaries detected by title. */
export function isRetrospectiveTitle(title: string): boolean {
  const low = (title || "").toLowerCase();
  return RETROSPECTIVE_TITLE_MARKERS.some((m) => low.includes(m));
}

export function applyRetrospectiveDemotion(severity: Severity, title: string): Severity {
  return isRetrospectiveTitle(title) ? "Info" : severity;
}

export interface AdvisoryInput {
  title: string;
  cves: string[];
  attackType: string;
}

/** True when the item is a vulnerability advisory / CVE observation. */
export function isVulnerabilityAdvisory({ title, cves, attackType }: AdvisoryInput): boolean {
  return (
    cves.length > 0 ||
    attackType === "Vulnerability" ||
    /vulnerability\s+advisory|脆弱性速報|脆弱性観測|cve-\d+/i.test(title || "")
  );
}

export interface AdvisoryCapResult {
  severity: Severity;
  stripActors: boolean;
}

/**
 * RULE 2: an advisory without a confirmed victim is capped at "Medium" and
 * must not carry threat actor attribution.
 */
export function applyAdvisoryCap(severity: Severity, input: AdvisoryInput, victimCount: number): AdvisoryCapResult {
  if (victimCount > 0 || !isVulnerabilityAdvisory(input)) return { severity, stripActors: false };
  const capped = severity === "Critical" || severity === "High" ? "Medium" : severity;
  return { severity: capped, stripActors: true };
}
