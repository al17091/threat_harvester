/**
 * Returns the active subpath prefix (e.g. "/threat"), or "" at the root. In the browser it is
 * the value injected by server.js for subpath requests; during server rendering it is the
 * configured BASE_PATH. It is never guessed from the URL.
 */
export function getRuntimeBasePath(): string {
  if (typeof window !== "undefined") {
    const injected = (window as unknown as { __RUNTIME_BASE_PATH__?: string }).__RUNTIME_BASE_PATH__;
    return typeof injected === "string" ? injected.trim().replace(/\/+$/, "") : "";
  }

  const envBase = (process.env.NEXT_PUBLIC_BASE_PATH || process.env.BASE_PATH || "")
    .trim()
    .replace(/^\/*/, "/")
    .replace(/\/+$/, "");
  return /^(\/[A-Za-z0-9_-]+)+$/.test(envBase) ? envBase : "";
}

/**
 * Prefixes an app-relative path (e.g. "/api/incidents", "/ja", "/en") with the active subpath.
 */
export function withBasePath(path: string): string {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const base = getRuntimeBasePath();
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

