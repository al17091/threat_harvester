// Access rules for the backend API proxy. Anything not listed as public requires an administrator.

const SAFE_SEGMENT_RE = /^[A-Za-z0-9_.:-]+$/;

const PUBLIC_READ_PATHS: readonly RegExp[] = [
  /^status$/,
  /^stats\/entities$/,
  /^incidents(\/[^/]+)?$/,
  /^(rss|feed\.xml)(\/[^/]+)?$/,
];

/**
 * Builds the backend path from route segments. Returns null for anything the backend or the URL
 * parser could interpret differently from the access check, such as dot segments or encoded slashes.
 */
export function canonicalApiPath(segments: readonly string[]): string | null {
  const decoded: string[] = [];
  for (const segment of segments) {
    let value: string;
    try {
      value = decodeURIComponent(segment);
    } catch {
      return null;
    }
    if (!SAFE_SEGMENT_RE.test(value) || /^\.+$/.test(value)) return null;
    decoded.push(value);
  }
  return decoded.join("/");
}

export function isPublicApiRequest(method: string, path: string): boolean {
  if (method !== "GET" && method !== "HEAD") return false;
  return PUBLIC_READ_PATHS.some((pattern) => pattern.test(path));
}
