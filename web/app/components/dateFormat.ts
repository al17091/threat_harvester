/**
 * Date and time formatting utility with timezone awareness for Threat Harvester.
 * - English view ("en"): Displays timestamps in UTC (e.g. "Oct 17, 16:47 UTC").
 * - Japanese view ("ja"): Explicitly displays timestamps in JST (Asia/Tokyo) (e.g. "10月18日 01:47 JST").
 */

export function formatDate(
  isoStr: string | null | undefined,
  lang: "en" | "ja" = "en"
): string {
  if (!isoStr) return "";
  try {
    const d = new Date(isoStr);
    if (isNaN(d.getTime())) return isoStr;
    const now = new Date();

    if (lang === "ja") {
      const yearInJst = new Intl.DateTimeFormat("ja-JP", {
        timeZone: "Asia/Tokyo",
        year: "numeric",
      }).format(d);
      const currentYearInJst = new Intl.DateTimeFormat("ja-JP", {
        timeZone: "Asia/Tokyo",
        year: "numeric",
      }).format(now);
      const includeYear = yearInJst !== currentYearInJst;

      const datePart = d.toLocaleDateString("ja-JP", {
        timeZone: "Asia/Tokyo",
        ...(includeYear ? { year: "numeric" } : {}),
        month: "short",
        day: "numeric",
      });
      const timePart = d.toLocaleTimeString("ja-JP", {
        timeZone: "Asia/Tokyo",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });
      return `${datePart} ${timePart} JST`;
    } else {
      const yearInUtc = new Intl.DateTimeFormat("en-US", {
        timeZone: "UTC",
        year: "numeric",
      }).format(d);
      const currentYearInUtc = new Intl.DateTimeFormat("en-US", {
        timeZone: "UTC",
        year: "numeric",
      }).format(now);
      const includeYear = yearInUtc !== currentYearInUtc;

      const datePart = d.toLocaleDateString("en-US", {
        timeZone: "UTC",
        ...(includeYear ? { year: "numeric" } : {}),
        month: "short",
        day: "numeric",
      });
      const timePart = d.toLocaleTimeString("en-US", {
        timeZone: "UTC",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });
      return `${datePart}, ${timePart} UTC`;
    }
  } catch {
    return isoStr;
  }
}

