const ROOT_SEGMENTS = new Set([
  "",
  "en",
  "ja",
  "admin",
  "api",
  "rss",
  "feed.xml",
  "_next",
  "icon.svg",
  "favicon.ico",
  "apple-touch-icon.png",
]);

/**
 * Detects the active subpath prefix (e.g. "/thhv") at runtime from window.location.pathname
 * or falls back to NEXT_PUBLIC_BASE_PATH. Returns "" when served at root "/".
 */
export function getRuntimeBasePath(pathname?: string | null): string {
  const envBase = (process.env.NEXT_PUBLIC_BASE_PATH || "").replace(/\/+$/, "");
  const currentPath =
    typeof window !== "undefined" ? window.location.pathname : pathname || "";

  if (currentPath) {
    const parts = currentPath.split("/").filter(Boolean);
    if (parts.length > 0 && !ROOT_SEGMENTS.has(parts[0])) {
      return `/${parts[0]}`;
    }
  }
  return envBase;
}

/**
 * Prefixes an app-relative path (e.g. "/api/incidents", "/ja", "/en") with the active subpath.
 */
export function withBasePath(path: string, pathname?: string | null): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const base = getRuntimeBasePath(pathname);
  if (!base) return normalizedPath;
  if (normalizedPath === base || normalizedPath.startsWith(`${base}/`)) {
    return normalizedPath;
  }
  return `${base}${normalizedPath}`;
}

/**
 * Checks whether the current path is an admin route (supports both "/admin" and "/<subpath>/admin").
 */
export function isAdminPath(pathname?: string | null): boolean {
  const currentPath =
    typeof window !== "undefined" ? window.location.pathname : pathname || "";
  if (!currentPath) return false;
  const parts = currentPath.split("/").filter(Boolean);
  return parts.includes("admin");
}

