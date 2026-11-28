import test from "node:test";
import assert from "node:assert/strict";
import nextNonce from "next/dist/server/app-render/get-script-nonce-from-header.js";
import security from "../server-lib/security.js";

const {
  generateNonce,
  normalizePrefix,
  detectSubpathPrefix,
  buildCsp,
  securityHeaders,
  scriptJson,
  buildBootstrapScript,
  rewriteHtmlAssets,
} = security;
const { getScriptNonceFromHeader } = nextNonce as any;

const directives = (csp: string) =>
  new Map(csp.split("; ").map((d) => [d.split(" ")[0], d.split(" ").slice(1).join(" ")]));

test("nonces are unique and readable by the Next.js CSP parser", () => {
  const seen = new Set<string>();
  for (let i = 0; i < 200; i++) {
    const nonce = generateNonce();
    seen.add(nonce);
    assert.equal(getScriptNonceFromHeader(buildCsp(nonce)), nonce);
  }
  assert.equal(seen.size, 200);
});

test("production CSP is strict", () => {
  const csp = directives(buildCsp("abc"));
  assert.equal(csp.get("default-src"), "'self'");
  assert.equal(csp.get("script-src"), "'self' 'nonce-abc' 'strict-dynamic'");
  assert.equal(csp.get("style-src"), "'self'");
  assert.equal(csp.get("img-src"), "'self' data:");
  assert.equal(csp.get("font-src"), "'self'");
  assert.equal(csp.get("connect-src"), "'self'");
  assert.equal(csp.get("object-src"), "'none'");
  assert.equal(csp.get("base-uri"), "'self'");
  assert.equal(csp.get("frame-ancestors"), "'none'");
  assert.equal(csp.get("form-action"), "'self'");
  assert.doesNotMatch(buildCsp("abc"), /unsafe-/);
});

test("baseline security headers are defined", () => {
  const headers = securityHeaders("abc");
  assert.equal(headers["Cross-Origin-Opener-Policy"], "same-origin");
  assert.equal(headers["Cross-Origin-Resource-Policy"], "same-origin");
  assert.equal(headers["Permissions-Policy"], "camera=(), microphone=(), geolocation=(), payment=()");
  assert.equal(headers["X-Content-Type-Options"], "nosniff");
  assert.equal(headers["X-Frame-Options"], "DENY");
  assert.equal(headers["Referrer-Policy"], "strict-origin-when-cross-origin");
});

test("normalizePrefix accepts plain path segments only", () => {
  assert.equal(normalizePrefix("threat"), "/threat");
  assert.equal(normalizePrefix("threat/"), "/threat");
  assert.equal(normalizePrefix("//threat//"), "/threat");
  assert.equal(normalizePrefix("/a/b-c_d"), "/a/b-c_d");
  for (const bad of ['/x";alert(1)//', '/a"><svg>', "/$&", "/..", "/a/../b", "/a.b", "/%22", "/a b", "/a, /b", `/${"a".repeat(64)}`, "/", "", 42, undefined, ["/a"]]) {
    assert.equal(normalizePrefix(bad), "", String(bad));
  }
});

test("detectSubpathPrefix only ever returns the configured prefix", () => {
  const header = (value: string) => ({ "x-forwarded-prefix": value });
  assert.equal(detectSubpathPrefix({}, "/threat", "/threat"), "/threat");
  assert.equal(detectSubpathPrefix({}, "/threat/ja", "/threat"), "/threat");
  // A proxy that strips the prefix names it in the header.
  assert.equal(detectSubpathPrefix(header("/threat"), "/ja", "/threat"), "/threat");
  assert.equal(detectSubpathPrefix(header("/threat/"), "/ja", "/threat"), "/threat");
  for (const [headers, path] of [
    [{}, "/ja"],
    [{}, "/"],
    [{}, "/nope"],
    [{}, "/foo/ja"],
    [{}, "/threatening/ja"],
    [header("/other"), "/ja"],
    [header('/x";alert(1)//'), "/ja"],
    [{}, '/a"><img/src/onerror=alert(1)>/ja'],
  ] as const) {
    assert.equal(detectSubpathPrefix(headers, path, "/threat"), "", path);
  }
  // Without a configured prefix there is no subpath mode at all.
  assert.equal(detectSubpathPrefix(header("/threat"), "/threat/ja", ""), "");
});

test("inline bootstrap script cannot be broken out of", () => {
  assert.doesNotMatch(scriptJson("</script><script>&\u2028"), /[<>&\u2028]/);
  assert.equal(JSON.parse(scriptJson("</script>")), "</script>");
  assert.equal(
    buildBootstrapScript("/threat", "n0nce"),
    '<script nonce="n0nce">window.__RUNTIME_BASE_PATH__="/threat";window.TURBOPACK_CHUNK_BASE_PATH="/threat/_next/";</script>'
  );
});

test("rewriteHtmlAssets prefixes asset attributes and injects one nonce-bearing bootstrap", () => {
  const text = 'a href=&quot;/_next/x&quot; "/_next/y" href="/en"';
  const html = `<html><head><link href="/icon.svg"></head><body><a href="/en">en</a><script src="/_next/a.js"></script><p>${text}</p><head></body></html>`;
  const out = rewriteHtmlAssets(html, "/threat", "n0nce");
  assert.match(out, /^<html><head><script nonce="n0nce">/);
  assert.equal(out.match(/__RUNTIME_BASE_PATH__/g)?.length, 1);
  assert.ok(out.includes('href="/threat/icon.svg"'));
  assert.ok(out.includes('src="/threat/_next/a.js"'));
  // Page links are built with the prefix by the app, and text content is never touched.
  assert.ok(out.includes('<a href="/en">'));
  assert.ok(out.includes(`<p>${text}</p>`));
  assert.equal(rewriteHtmlAssets(html, "", "n0nce"), html);
});
