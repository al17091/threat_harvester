/**
 * Date and time formatting utility with timezone awareness for Threat Harvester.
 * Formats dates explicitly as "YYYY-MM-DD HH:mm UTC" or "YYYY-MM-DD HH:mm JST".
 * - English view ("en"): Displays timestamps in UTC (e.g. "2026-11-02 08:08 UTC").
 * - Japanese view ("ja"): Explicitly displays timestamps in JST (Asia/Tokyo) (e.g. "2026-11-02 17:08 JST").
 */

export function formatDate(
  isoStr: string | null | undefined,
  lang: "en" | "ja" = "en"
): string {
  if (!isoStr) return "";
  try {
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return isoStr;

    const timeZone = lang === "ja" ? "Asia/Tokyo" : "UTC";
    const zoneSuffix = lang === "ja" ? "JST" : "UTC";

    const fmt = new Intl.DateTimeFormat("en-US", {
      timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
      hourCycle: "h23",
    });

    const parts = fmt.formatToParts(d).reduce<Record<string, string>>((acc, p) => {
      acc[p.type] = p.value;
      return acc;
    }, {});

    return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute} ${zoneSuffix}`;
  } catch {
    return isoStr;
  }
}
