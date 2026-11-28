import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import nextNonce from "next/dist/server/app-render/get-script-nonce-from-header.js";
import listenerModule from "../server-lib/listener.js";

const { createRequestListener } = listenerModule;
const { getScriptNonceFromHeader } = nextNonce as any;

/** Stand-in for the Next.js handler: stamps the request nonce on streamed HTML. */
async function fakeHandle(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = req.url || "/";
  if (url.includes("boom")) throw new Error("boom");
  if (url.startsWith("/_next/static/")) {
    res.writeHead(200, { "content-type": "application/javascript", "cache-control": "public, max-age=31536000, immutable" });
    res.end("1");
    return;
  }
  if (url.startsWith("/api/")) {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ csp: req.headers["content-security-policy"] ?? null }));
    return;
  }
  if (url.includes("redirect")) {
    res.writeHead(307, { location: "/ja" });
    res.end();
    return;
  }
  if (url.includes("encoded")) {
    res.writeHead(200, { "content-type": "text/html", "content-encoding": "identity" });
    res.end('<head></head><a href="/en">');
    return;
  }
  const nonce = getScriptNonceFromHeader(req.headers["content-security-policy"] as string);
  const status = url.includes("missing") ? 404 : 200;
  res.setHeader("Cache-Control", "public, max-age=60");
  res.writeHead(status, ["content-type", "text/html; charset=utf-8", "etag", '"abc"', "content-length", "9999"].slice(0, url.includes("sized") ? 6 : 4));
  res.write(new TextEncoder().encode(`<html><head><script nonce="${nonce}" src="/_next/static/a.js"></script></head>`));
  res.write(`<body><a href="/en">日本語</a><script nonce="${nonce}">1</script>`);
  res.end("</body></html>");
}

let origin = "";
const server = http.createServer(createRequestListener({ handle: fakeHandle }));

test.before(async () => {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
test.after(() => {
  server.closeAllConnections();
  server.close();
});

/** Raw request so that hostile paths are sent without URL normalization. */
function request(path: string, headers: Record<string, string> = {}, method = "GET") {
  return new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string; bytes: number }>((resolve, reject) => {
    const req = http.request(origin, { path, headers, method }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const buf = Buffer.concat(chunks);
        resolve({ status: res.statusCode!, headers: res.headers, body: buf.toString("utf8"), bytes: buf.length });
      });
    });
    req.on("error", reject);
    req.end();
  });
}

function assertNonces(res: Awaited<ReturnType<typeof request>>) {
  const nonce = getScriptNonceFromHeader(res.headers["content-security-policy"] as string);
  assert.ok(nonce);
  const scripts = res.body.match(/<script[^>]*>/g) ?? [];
  assert.ok(scripts.length > 0);
  for (const tag of scripts) assert.ok(tag.includes(`nonce="${nonce}"`), tag);
}

test("security headers are present on HTML, static, API, 404 and 500 responses", async () => {
  for (const path of ["/ja", "/_next/static/a.js", "/api/incidents", "/ja/missing", "/ja/boom", "/threat/ja", "/threat/ja/boom"]) {
    const res = await request(path);
    assert.match(res.headers["content-security-policy"] as string, /script-src 'self' 'nonce-/, path);
    assert.equal(res.headers["x-content-type-options"], "nosniff", path);
    assert.equal(res.headers["x-frame-options"], "DENY", path);
    assert.equal(res.headers["cross-origin-opener-policy"], "same-origin", path);
  }
});

test("direct documents carry matching nonces and are never shared-cached", async () => {
  for (const path of ["/", "/ja", "/ja/missing"]) {
    const res = await request(path);
    assertNonces(res);
    assert.equal(res.headers["cache-control"], "private, no-store, max-age=0", path);
    assert.equal(res.headers.etag, undefined, path);
    assert.doesNotMatch(res.body, /__RUNTIME_BASE_PATH__/);
  }
});

test("each request gets a fresh nonce and ignores a client-supplied policy", async () => {
  const injected = { "content-security-policy": "script-src 'nonce-attacker'" };
  const [a, b] = [await request("/ja", injected), await request("/ja", injected)];
  assert.notEqual(a.headers["content-security-policy"], b.headers["content-security-policy"]);
  assert.doesNotMatch(a.body, /attacker/);
  const api = await request("/api/incidents", injected);
  assert.equal(JSON.parse(api.body).csp, null);
});

test("subpath documents are rewritten with a nonce-bearing bootstrap first in head", async () => {
  const cases: Array<[string, Record<string, string>]> = [
    ["/threat/ja", {}],
    ["/ja", { "x-forwarded-prefix": "/threat" }],
    ["/threat/ja", { "x-forwarded-prefix": "/threat" }],
    // The handler passes a stale content-length through writeHead.
    ["/ja/sized", { "x-forwarded-prefix": "/threat" }],
  ];
  for (const [path, headers] of cases) {
    const res = await request(path, headers);
    assert.equal(res.status, 200);
    assertNonces(res);
    assert.match(res.body, /<head><script nonce="[^"]+">window\.__RUNTIME_BASE_PATH__="\/threat";/);
    assert.ok(res.body.includes('href="/threat/en"'));
    assert.ok(res.body.includes('src="/threat/_next/static/a.js"'));
    assert.ok(res.body.includes("日本語"));
    assert.equal(Number(res.headers["content-length"]), res.bytes);
    assert.equal(res.headers["cache-control"], "private, no-store, max-age=0");
    assert.equal(res.headers.etag, undefined);
  }
});

test("hostile prefixes are not reflected", async () => {
  const cases: Array<[string, Record<string, string>]> = [
    ['/a"><img/src/onerror=alert(1)>/ja', {}],
    ["/ja", { "x-forwarded-prefix": '/x";alert(1)//' }],
    ["/ja", { "x-forwarded-prefix": "/$&" }],
  ];
  for (const [path, headers] of cases) {
    const res = await request(path, headers);
    assert.doesNotMatch(res.body, /alert|onerror|\$&|__RUNTIME_BASE_PATH__/, path);
  }
});

test("static assets keep immutable caching and redirects stay under the subpath", async () => {
  for (const path of ["/_next/static/a.js", "/threat/_next/static/a.js"]) {
    const res = await request(path);
    assert.equal(res.headers["cache-control"], "public, max-age=31536000, immutable", path);
  }
  assert.equal((await request("/threat/ja/redirect")).headers.location, "/threat/ja");
  assert.equal((await request("/ja/redirect")).headers.location, "/ja");
});

test("encoded bodies pass through and HEAD reports no rewritten length", async () => {
  const encoded = await request("/threat/ja/encoded");
  assert.equal(encoded.body, '<head></head><a href="/en">');
  const head = await request("/threat/ja", {}, "HEAD");
  assert.equal(head.status, 200);
  assert.equal(head.headers["content-length"], undefined);
});
