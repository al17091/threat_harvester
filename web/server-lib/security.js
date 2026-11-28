// Pure security helpers for the custom Next.js server. CommonJS so that server.js can require it
// and the node:test suite can import it without a build step.
const crypto = require("crypto");

// Subpath prefixes end up inside HTML attributes and inline script, so only plain segments pass.
const SAFE_PREFIX_RE = /^(?:\/[A-Za-z0-9_-]+)+$/;
const MAX_PREFIX_LENGTH = 64;

const DOCUMENT_CACHE_CONTROL = "private, no-store, max-age=0";

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

function generateNonce() {
  return crypto.randomBytes(16).toString("base64");
}

/** Returns a safe "/segment[/segment]" prefix, or "" when the value is absent or unsafe. */
function normalizePrefix(raw) {
  if (!raw || typeof raw !== "string") return "";
  const collapsed = `/${raw.trim()}`.replace(/\/{2,}/g, "/").replace(/\/$/, "");
  if (collapsed.length > MAX_PREFIX_LENGTH || !SAFE_PREFIX_RE.test(collapsed)) return "";
  return collapsed;
}

/** Resolves the subpath prefix from the proxy header, configuration, or request path. */
function detectSubpathPrefix(headers, pathname, configuredBasePath) {
  const headerPrefix = normalizePrefix(headers["x-forwarded-prefix"]);
  if (headerPrefix) return headerPrefix;

  if (
    configuredBasePath &&
    (pathname === configuredBasePath || pathname.startsWith(`${configuredBasePath}/`))
  ) {
    return configuredBasePath;
  }

  const parts = (pathname || "").split("/").filter(Boolean);
  const rootIdx = parts.findIndex((p) => ROOT_SEGMENTS.has(p));
  if (rootIdx === 0 || parts.length === 0) return "";
  return normalizePrefix((rootIdx > 0 ? parts.slice(0, rootIdx) : parts).join("/"));
}

function buildCsp(nonce, { dev = false } = {}) {
  // Development needs eval (React Refresh), inline styles (error overlay) and the HMR socket.
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}`,
    `style-src 'self'${dev ? " 'unsafe-inline'" : ""}`,
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src 'self'${dev ? " ws: wss:" : ""}`,
    "object-src 'none'",
    "base-uri 'self'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ].join("; ");
}

function securityHeaders(nonce, options) {
  return {
    "Content-Security-Policy": buildCsp(nonce, options),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
  };
}

/** JSON.stringify that cannot terminate the surrounding <script> element. */
function scriptJson(value) {
  return JSON.stringify(value).replace(
    /[<>&\u2028\u2029]/g,
    (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`
  );
}

/** Tells the client runtime about the subpath so the Turbopack chunk loader prepends it. */
function buildBootstrapScript(prefix, nonce) {
  return (
    `<script nonce="${nonce}">window.__RUNTIME_BASE_PATH__=${scriptJson(prefix)};` +
    `window.TURBOPACK_CHUNK_BASE_PATH=${scriptJson(`${prefix}/_next/`)};</script>`
  );
}

function rewriteHtmlAssets(body, prefix, nonce) {
  if (!prefix) return body;
  // Function replacers: "$" sequences are never expanded in the inserted text.
  const addPrefix = (_match, open, path, close) => `${open}${prefix}/${path}${close}`;
  return body
    .replace(/(["'])\/_next\//g, (_match, quote) => `${quote}${prefix}/_next/`)
    .replace(/\\\/_next\\\//g, () => `\\${prefix}\\/_next\\/`)
    .replace(/(href=["'])\/(icon\.svg|favicon\.ico[^\s"'>]*|apple-touch-icon\.png)(["'])/g, addPrefix)
    .replace(/(href=["'])\/(en|ja|admin|api\/[^\s"'>]+|rss|feed\.xml)(["'])/g, addPrefix)
    .replace(/(\\"href\\":\s*\\")\/(en|ja|admin|api\/[^"\\\s]+|rss|feed\.xml)(\\")/g, addPrefix)
    .replace(/("href":\s*")\/(en|ja|admin|api\/[^"\s]+|rss|feed\.xml)(")/g, addPrefix)
    .replace("<head>", () => `<head>${buildBootstrapScript(prefix, nonce)}`);
}

function isStaticOrApiPath(path) {
  return (
    path.startsWith("/_next/") ||
    path.startsWith("/api/") ||
    path === "/rss" ||
    path === "/feed.xml" ||
    path === "/icon.svg" ||
    path === "/favicon.ico" ||
    path === "/apple-touch-icon.png"
  );
}

/** HTML and RSC payloads embed the per-request nonce. */
function isDocumentContentType(contentType) {
  const value = String(contentType || "");
  return value.includes("text/html") || value.includes("text/x-component");
}

module.exports = {
  DOCUMENT_CACHE_CONTROL,
  generateNonce,
  normalizePrefix,
  detectSubpathPrefix,
  buildCsp,
  securityHeaders,
  scriptJson,
  buildBootstrapScript,
  rewriteHtmlAssets,
  isStaticOrApiPath,
  isDocumentContentType,
};
