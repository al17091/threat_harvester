import test from "node:test";
import assert from "node:assert/strict";
import { canonicalApiPath, isPublicApiRequest } from "../app/security/apiPolicy.ts";

test("dashboard and feed reads are public", () => {
  for (const path of ["status", "stats/entities", "incidents", "incidents/incident--0b7e", "rss", "rss/ja", "feed.xml", "feed.xml/en"]) {
    assert.equal(isPublicApiRequest("GET", path), true, path);
    assert.equal(isPublicApiRequest("HEAD", path), true, path);
  }
});

test("everything else requires an administrator", () => {
  for (const path of ["", "config", "config/raw", "config/export", "pipeline/logs", "pipeline/stream", "pipeline/stage", "incidents/abc/update", "status/extra", "stats", "auth", "unknown"]) {
    assert.equal(isPublicApiRequest("GET", path), false, path);
  }
  for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
    assert.equal(isPublicApiRequest(method, "incidents"), false, method);
  }
});

test("canonicalApiPath rejects segments that could change meaning downstream", () => {
  assert.equal(canonicalApiPath(["incidents", "incident--0b7e"]), "incidents/incident--0b7e");
  assert.equal(canonicalApiPath(["incidents", "a%3Ab"]), "incidents/a:b");
  assert.equal(canonicalApiPath(["feed.xml"]), "feed.xml");
  for (const bad of ["..", ".", "%2e%2e", "%2E%2E", "", "a%2Fb", "a/b", "a\\b", "%5C", "%252e%252e", "a%3Fb", "a%23b", "%", "a b"]) {
    assert.equal(canonicalApiPath(["incidents", bad, "raw"]), null, bad);
  }
});
