import { z } from "zod";

export const JapanRelevanceEnum = z.enum(["Direct", "Indirect", "None", "Unknown"]);
export type JapanRelevance = z.infer<typeof JapanRelevanceEnum>;

export const SeverityEnum = z.enum(["Critical", "High", "Medium", "Low", "Info", "Informational"]);
export type Severity = z.infer<typeof SeverityEnum>;

export const ThreatItemSchema = z.object({
  id: z.string().optional(),
  title: z.string(),
  url: z.string().default(""),
  source_type: z.string().default(""),
  source_name: z.string().default(""),
  summary: z.string().default(""),
  raw_content: z.string().default(""),
  metadata: z.record(z.any()).optional().default({}),
});
export type ThreatItem = z.infer<typeof ThreatItemSchema>;

export const EnrichedThreatSchema = z.object({
  item_id: z.string().optional(),
  severity: SeverityEnum,
  japan_relevance: JapanRelevanceEnum,
  title: z.string(),
  summary: z.string(),
  impact_analysis: z.string(),
  title_ja: z.string(),
  summary_ja: z.string(),
  impact_analysis_ja: z.string(),
  victim_orgs: z.array(z.string()).default([]),
  threat_actors: z.array(z.string()).default([]),
  threat_actor_reasons: z.record(z.string()).optional().default({}),
  attack_type: z.string().default("None"),
  cves: z.array(z.string()).default([]),
  affected_products: z.array(z.string()).default([]),
  recommended_actions_ja: z.array(z.string()).optional().default([]),
  analyzed_at: z.string().optional(),
});
export type EnrichedThreat = z.infer<typeof EnrichedThreatSchema>;

