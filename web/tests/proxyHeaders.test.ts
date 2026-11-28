import test from "node:test";
import assert from "node:assert/strict";
import { buildBackendHeaders } from "../app/security/proxyHeaders.ts";

const incoming = new Headers({
  accept: "application/json",
  "content-type": "application/json",
  authorization: "Bearer from-client",
  "proxy-authorization": "Basic x",
  cookie: "admin_session=secret",
  host: "example.test",
  "x-forwarded-for": "203.0.113.5",
  "x-forwarded-proto": "https",
  "x-real-ip": "203.0.113.5",
  "x-harvester-client-ip": "203.0.113.5",
});

test("only allowlisted headers reach the backend", () => {
  const headers = buildBackendHeaders(incoming, { privileged: false, token: "service-token" });
  assert.deepEqual([...headers.keys()].sort(), ["accept", "content-type", "x-forwarded-proto"]);
});

test("the service token is attached to privileged requests only and replaces client values", () => {
  const headers = buildBackendHeaders(incoming, { privileged: true, token: " service-token\n" });
  assert.equal(headers.get("authorization"), "Bearer service-token");
  assert.equal(headers.get("cookie"), null);
});

test("no authorization is sent without a configured token", () => {
  for (const token of [undefined, "", "   "]) {
    assert.equal(buildBackendHeaders(incoming, { privileged: true, token }).get("authorization"), null);
  }
});

test("an unexpected forwarded protocol is dropped", () => {
  const headers = buildBackendHeaders(new Headers({ "x-forwarded-proto": "gopher" }), { privileged: false, token: "" });
  assert.equal(headers.get("x-forwarded-proto"), null);
});
