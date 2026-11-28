// Pure security helpers for the custom Next.js server. CommonJS so that server.js can require it
// and the node:test suite can import it without a build step.
const crypto = require("crypto");
const { createFlightRewriter } = require("./flight");

// Subpath prefixes end up inside HTML attributes and inline script, so only plain segments pass.
const SAFE_PREFIX_RE = /^(?:\/[A-Za-z0-9_-]+)+$/;
const MAX_PREFIX_LENGTH = 64;

const DOCUMENT_CACHE_CONTROL = "private, no-store, max-age=0";

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

/**
 * Resolves whether a request is served under the configured subpath. Only that prefix is ever
 * used: either the path carries it, or a proxy that strips it names it in X-Forwarded-Prefix.
 */
function detectSubpathPrefix(headers, pathname, configuredBasePath) {
  const base = normalizePrefix(configuredBasePath);
  if (!base) return "";
  if (pathname === base || pathname.startsWith(`${base}/`)) return base;
  return normalizePrefix(headers["x-forwarded-prefix"]) === base ? base : "";
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

// The inline scripts through which Next.js streams the RSC payload into HTML.
const FLIGHT_PUSH_RE =
  /(<script[^>]*>self\.__next_f\.push\()\[([13]),("[^"\\]*(?:\\.[^"\\]*)*")\](\)<\/script>)/g;

/** Rewrites the payload chunks as one stream, because rows may span several scripts. */
function rewriteInlineFlight(html, prefix) {
  const matches = [...html.matchAll(FLIGHT_PUSH_RE)];
  if (!matches.length) return html;

  const rewriter = createFlightRewriter(prefix);
  // Type 1 chunks are text, type 3 chunks are base64-encoded binary.
  const encodingOf = (match) => (match[2] === "1" ? "utf8" : "base64");
  const chunks = matches.map((m) => rewriter.push(Buffer.from(JSON.parse(m[3]), encodingOf(m))));
  chunks[chunks.length - 1] = Buffer.concat([chunks[chunks.length - 1], rewriter.flush()]);

  let out = "";
  let last = 0;
  matches.forEach((m, i) => {
    const payload = scriptJson(chunks[i].toString(encodingOf(m)));
    out += `${html.slice(last, m.index)}${m[1]}[${m[2]},${payload}]${m[4]}`;
    last = m.index + m[0].length;
  });
  return out + html.slice(last);
}

function rewriteHtmlAssets(body, prefix, nonce) {
  if (!prefix) return body;
  // Only asset attributes are touched: page links are already built with the prefix, and the
  // quotes of any text content are entity-encoded. Function replacers never expand "$".
  return rewriteInlineFlight(body, prefix)
    .replace(
      /\b(href|src)=(["'])\/(_next\/|icon\.svg|favicon\.ico|apple-touch-icon\.png)/g,
      (_match, attribute, quote, path) => `${attribute}=${quote}${prefix}/${path}`
    )
    .replace("<head>", () => `<head>${buildBootstrapScript(prefix, nonce)}`);
}

/** Rewrites a complete HTML or RSC response body for the subpath. */
function rewriteDocument(body, contentType, prefix, nonce) {
  if (String(contentType).includes("text/x-component")) {
    const rewriter = createFlightRewriter(prefix);
    return Buffer.concat([rewriter.push(body), rewriter.flush()]);
  }
  return Buffer.from(rewriteHtmlAssets(body.toString("utf8"), prefix, nonce), "utf8");
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
  rewriteDocument,
  isStaticOrApiPath,
  isDocumentContentType,
};
