/**
 * Major Japanese Corporate & Organization CTI Alias Dictionary
 * Maps common English / colloquial names to official Japanese organization names.
 */
export const JAPAN_ORGANIZATION_ALIASES: Record<string, string> = {
  // Telecom & Tech
  "ntt": "日本電信電話株式会社 (NTT)",
  "ntt docomo": "株式会社NTTドコモ",
  "docomo": "株式会社NTTドコモ",
  "ntt east": "東日本電信電話株式会社 (NTT東日本)",
  "ntt west": "西日本電信電話株式会社 (NTT西日本)",
  "ntt data": "株式会社NTTデータ",
  "kddi": "KDDI株式会社",
  "softbank": "ソフトバンク株式会社",
  "rakuten": "楽天グループ株式会社",
  "line": "LINEヤフー株式会社",
  "line yahoo": "LINEヤフー株式会社",
  "ly corporation": "LINEヤフー株式会社",
  "yahoo japan": "LINEヤフー株式会社",
  "gmo": "GMOインターネットグループ株式会社",
  "gmo internet": "GMOインターネットグループ株式会社",
  "sakura internet": "さくらインターネット株式会社",
  "idc frontier": "株式会社IDCフロンティア",

  // Insurance & Finance
  "ms&ad": "MS&ADインシュアランスグループホールディングス株式会社",
  "ms and ad": "MS&ADインシュアランスグループホールディングス株式会社",
  "mitsui sumitomo insurance": "三井住友海上火災保険株式会社",
  "aioi nissay dowa": "あいおいニッセイ同和損害保険株式会社",
  "sompo": "SOMPOホールディングス株式会社",
  "tokio marine": "東京海上日動火災保険株式会社",
  "mufg": "株式会社三菱UFJフィナンシャル・グループ",
  "smbc": "株式会社三井住友フィナンシャルグループ",
  "mizuho": "株式会社みずほフィナンシャルグループ",

  // Manufacturing, Auto & Electronics
  "toyota": "トヨタ自動車株式会社",
  "honda": "本田技研工業株式会社",
  "nissan": "日産自動車株式会社",
  "sony": "ソニーグループ株式会社",
  "panasonic": "パナソニック ホールディングス株式会社",
  "hitachi": "株式会社日立製作所",
  "mitsubishi electric": "三菱電機株式会社",
  "fujitsu": "富士通株式会社",
  "nec": "日本電気株式会社 (NEC)",
  "toshiba": "株式会社東芝",
  "canon": "キヤノン株式会社",
  "olympus": "オリンパス株式会社",

  // Critical Infrastructure, Healthcare, Public
  "tepco": "東京電力ホールディングス株式会社",
  "kepco": "関西電力株式会社",
  "ana": "全日本空輸株式会社 (ANA)",
  "jal": "日本航空株式会社 (JAL)",
  "jr east": "東日本旅客鉄道株式会社 (JR東日本)",
  "jr west": "西日本旅客鉄道株式会社 (JR西日本)",
  "digital agency": "デジタル庁"
};

/**
 * Defensive, advisory, and law-enforcement organizations.
 * These publish advisories or investigate incidents; they must never be treated as victims,
 * resolved into victim_orgs, or used to elevate japan_relevance via victim resolution.
 * Keys are normalized lowercase aliases; values are official display names.
 */
export const DEFENSIVE_OR_ADVISORY_ORGS: Record<string, string> = {
  "jpcert": "一般社団法人JPCERTコーディネーションセンター (JPCERT/CC)",
  "jpcert/cc": "一般社団法人JPCERTコーディネーションセンター (JPCERT/CC)",
  "jpcert cc": "一般社団法人JPCERTコーディネーションセンター (JPCERT/CC)",
  "jpcertコーディネーションセンター": "一般社団法人JPCERTコーディネーションセンター (JPCERT/CC)",
  "ipa": "独立行政法人情報処理推進機構 (IPA)",
  "情報処理推進機構": "独立行政法人情報処理推進機構 (IPA)",
  "nisc": "内閣サイバーセキュリティセンター (NISC)",
  "内閣サイバーセキュリティセンター": "内閣サイバーセキュリティセンター (NISC)",
  "国家サイバー統括室": "国家サイバー統括室",
  "jvn": "Japan Vulnerability Notes (JVN)",
  "cisa": "Cybersecurity and Infrastructure Security Agency (CISA)",
  "us-cert": "US-CERT",
  "fbi": "Federal Bureau of Investigation (FBI)",
  "nsa": "National Security Agency (NSA)",
  "ncsc": "National Cyber Security Centre (NCSC)",
  "enisa": "European Union Agency for Cybersecurity (ENISA)",
  "europol": "Europol",
  "interpol": "Interpol",
  "cert-eu": "CERT-EU",
  "acsc": "Australian Cyber Security Centre (ACSC)",
  "bsi": "Bundesamt für Sicherheit in der Informationstechnik (BSI)",
};

function normalizeOrgKey(rawName: string): string {
  return (rawName || "")
    .normalize("NFKC")
    .trim()
    .toLowerCase()
    .replace(/^["'\[\]「」『』]+|["'\[\]「」『』]+$/g, "")
    .replace(/\s+/g, " ");
}

/**
 * Returns true when the name denotes a defensive/advisory organization, including
 * forms such as "JPCERT/CC", "IPA (Information-technology Promotion Agency)" or
 * "一般社団法人JPCERTコーディネーションセンター".
 */
export function isDefensiveOrAdvisoryOrg(rawName: string): boolean {
  const clean = normalizeOrgKey(rawName);
  if (!clean) return false;
  if (DEFENSIVE_OR_ADVISORY_ORGS[clean]) return true;
  // Strip a trailing parenthetical alias, e.g. "IPA (Information-technology Promotion Agency)".
  const head = clean.replace(/\s*\([^)]*\)\s*$/, "").trim();
  if (head && DEFENSIVE_OR_ADVISORY_ORGS[head]) return true;
  for (const [key, official] of Object.entries(DEFENSIVE_OR_ADVISORY_ORGS)) {
    if (clean === official.toLowerCase()) return true;
    // Japanese keys are distinctive enough for substring matching (e.g. "一般社団法人...").
    if (/[^\x00-\x7f]/.test(key) && clean.includes(key)) return true;
  }
  return /\bjpcert\b/.test(clean);
}

/**
 * Normalizes query string and resolves known Japanese entity names.
 */
export function lookupJapanOrgAlias(rawName: string): string | null {
  if (!rawName) return null;
  const clean = rawName.trim().toLowerCase().replace(/[\r\n\t]+/g, " ");
  if (JAPAN_ORGANIZATION_ALIASES[clean]) {
    return JAPAN_ORGANIZATION_ALIASES[clean];
  }
  for (const [key, val] of Object.entries(JAPAN_ORGANIZATION_ALIASES)) {
    if (clean === key || clean.startsWith(key + " ") || clean.endsWith(" " + key)) {
      return val;
    }
  }
  return null;
}

