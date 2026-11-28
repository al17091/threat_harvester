const { parse } = require("url");
const security = require("./security");

/** Moves headers passed to writeHead onto the response so they can be inspected and amended. */
function absorbHeaders(res, headers) {
  if (!headers) return;
  let pairs;
  if (!Array.isArray(headers)) pairs = Object.entries(headers);
  else if (Array.isArray(headers[0])) pairs = headers;
  else pairs = headers.flatMap((v, i) => (i % 2 === 0 ? [[v, headers[i + 1]]] : []));

  for (const [name] of pairs) res.removeHeader(name);
  for (const [name, value] of pairs) {
    if (value !== undefined) res.appendHeader(name, Array.isArray(value) ? value.map(String) : String(value));
  }
}

/** Documents carry a per-request nonce: shared caches must never store or revalidate them. */
function finalizeDocumentHeaders(res) {
  if (!security.isDocumentContentType(res.getHeader("content-type"))) return;
  res.setHeader("Cache-Control", security.DOCUMENT_CACHE_CONTROL);
  res.removeHeader("etag");
  res.removeHeader("last-modified");
}

/** Redirects issued for the stripped path must point back under the subpath. */
function prefixLocation(res, prefix) {
  const location = res.getHeader("location");
  if (!prefix || typeof location !== "string") return;
  if (!location.startsWith("/") || location.startsWith("//")) return;
  if (location === prefix || location.startsWith(`${prefix}/`)) return;
  res.setHeader("location", `${prefix}${location}`);
}

function hookWriteHead(res, prefix) {
  const origWriteHead = res.writeHead;
  res.writeHead = function (status, reason, headers) {
    const hasReason = typeof reason === "string";
    absorbHeaders(this, hasReason ? headers : reason);
    finalizeDocumentHeaders(this);
    prefixLocation(this, prefix);
    return hasReason ? origWriteHead.call(this, status, reason) : origWriteHead.call(this, status);
  };
}

function toBuffer(chunk, encoding) {
  return typeof chunk === "string" ? Buffer.from(chunk, encoding || "utf8") : Buffer.from(chunk);
}

/**
 * Buffers a document response so asset paths can be rewritten for the subpath.
 * Returns a function that abandons the buffered output.
 */
function bufferAndRewrite(req, res, prefix, nonce) {
  const orig = { write: res.write, end: res.end, writeHead: res.writeHead };
  const chunks = [];
  const restore = () => Object.assign(res, orig);

  res.writeHead = function (status, reason, headers) {
    this.statusCode = status;
    if (typeof reason === "string") this.statusMessage = reason;
    absorbHeaders(this, typeof reason === "string" ? headers : reason);
    return this;
  };

  res.write = function (chunk, encoding, cb) {
    const done = typeof encoding === "function" ? encoding : cb;
    if (chunk) chunks.push(toBuffer(chunk, typeof encoding === "string" ? encoding : undefined));
    if (typeof done === "function") process.nextTick(done);
    return true;
  };

  res.end = function (chunk, encoding, cb) {
    const done = [chunk, encoding, cb].find((arg) => typeof arg === "function");
    if (chunk && typeof chunk !== "function") {
      chunks.push(toBuffer(chunk, typeof encoding === "string" ? encoding : undefined));
    }
    restore();

    let body = Buffer.concat(chunks);
    const bodyless = req.method === "HEAD" || res.statusCode === 204 || res.statusCode === 304;
    if (security.isDocumentContentType(res.getHeader("content-type")) && !res.getHeader("content-encoding")) {
      if (bodyless) {
        // The unrewritten length would be wrong for the corresponding GET.
        res.removeHeader("content-length");
      } else {
        body = Buffer.from(security.rewriteHtmlAssets(body.toString("utf8"), prefix, nonce), "utf8");
        res.removeHeader("transfer-encoding");
        res.setHeader("content-length", body.length);
      }
    }
    res.writeHead(res.statusCode);
    return res.end(body, done);
  };

  return () => {
    chunks.length = 0;
    restore();
  };
}

/**
 * Wraps the Next.js request handler with security headers, per-request CSP nonces and dynamic
 * subpath support.
 */
function createRequestListener({ handle, dev = false, configuredBasePath = "" }) {
  return async function listener(req, res) {
    let discardBuffered = null;
    try {
      const nonce = security.generateNonce();
      const headers = security.securityHeaders(nonce, { dev });
      for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
      // Next.js reads the nonce from the request's CSP header, so client-supplied values must go.
      delete req.headers["content-security-policy"];
      delete req.headers["content-security-policy-report-only"];

      const parsedUrl = parse(req.url || "/", true);
      const pathname = parsedUrl.pathname || "/";
      const prefix = security.detectSubpathPrefix(req.headers, pathname, configuredBasePath);

      let path = pathname;
      if (prefix && (pathname === prefix || pathname.startsWith(`${prefix}/`))) {
        path = pathname.slice(prefix.length) || "/";
        req.url = `${path}${parsedUrl.search || ""}`;
      }
      // API requests are proxied to the backend and render no scripts.
      if (!path.startsWith("/api/")) {
        req.headers["content-security-policy"] = headers["Content-Security-Policy"];
      }

      hookWriteHead(res, prefix);
      if (prefix && !security.isStaticOrApiPath(path)) {
        // Ensure uncompressed HTML/RSC output so asset paths can be rewritten cleanly.
        delete req.headers["accept-encoding"];
        discardBuffered = bufferAndRewrite(req, res, prefix, nonce);
      }

      await handle(req, res, parse(req.url || "/", true));
    } catch (err) {
      console.error("Error handling request:", req.url, err);
      if (discardBuffered) discardBuffered();
      if (res.headersSent) {
        res.end();
        return;
      }
      res.statusCode = 500;
      res.setHeader("content-type", "text/plain; charset=utf-8");
      res.setHeader("Cache-Control", security.DOCUMENT_CACHE_CONTROL);
      res.removeHeader("content-length");
      res.end("Internal Server Error");
    }
  };
}

module.exports = { createRequestListener };
