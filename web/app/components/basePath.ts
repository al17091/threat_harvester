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
  // 1. Injected at runtime by server.js HTML rewrite
  if (typeof window !== "undefined") {
    const injected = (window as unknown as { __RUNTIME_BASE_PATH__?: string }).__RUNTIME_BASE_PATH__;
    if (typeof injected === "string" && injected.trim() !== "") {
      return injected.trim().replace(/\/+$/, "");
    }
  }

  // 2. Client-side URL detection from window.location.pathname
  if (typeof window !== "undefined" && window.location.pathname) {
    const parts = window.location.pathname.split("/").filter(Boolean);
    const rootIdx = parts.findIndex((p) => ROOT_SEGMENTS.has(p));
    if (rootIdx > 0) {
      return `/${parts.slice(0, rootIdx).join("/")}`;
    }
    if (rootIdx === -1 && parts.length > 0) {
      return `/${parts.join("/")}`;
    }
  }

  // 3. SSR pathname inspection
  if (pathname) {
    const parts = pathname.split("/").filter(Boolean);
    const rootIdx = parts.findIndex((p) => ROOT_SEGMENTS.has(p));
    if (rootIdx > 0) {
      return `/${parts.slice(0, rootIdx).join("/")}`;
    }
    if (rootIdx === -1 && parts.length > 0) {
      return `/${parts.join("/")}`;
    }
  }

  // 4. Fallback to environment variables
  const envBase = (
    process.env.NEXT_PUBLIC_BASE_PATH ||
    process.env.BASE_PATH ||
    ""
  ).replace(/\/+$/, "");

  if (envBase) {
    return envBase.startsWith("/") ? envBase : `/${envBase}`;
  }

  return "";
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

