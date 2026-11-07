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
  "jpcert": "一般社団法人JPCERTコーディネーションセンター (JPCERT/CC)",
  "jpcert/cc": "一般社団法人JPCERTコーディネーションセンター (JPCERT/CC)",
  "ipa": "独立行政法人情報処理推進機構 (IPA)",
  "nisc": "内閣サイバーセキュリティセンター (NISC)",
  "digital agency": "デジタル庁"
};

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

