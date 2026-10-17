import test from "node:test";
import assert from "node:assert/strict";
import { getRuntimeBasePath, withBasePath, isAdminPath } from "../app/components/basePath.ts";

test("getRuntimeBasePath returns empty string for standard root segments", () => {
  assert.equal(getRuntimeBasePath("/en"), "");
  assert.equal(getRuntimeBasePath("/ja"), "");
  assert.equal(getRuntimeBasePath("/admin"), "");
  assert.equal(getRuntimeBasePath("/api/incidents"), "");
  assert.equal(getRuntimeBasePath("/rss"), "");
  assert.equal(getRuntimeBasePath("/feed.xml"), "");
  assert.equal(getRuntimeBasePath("/"), "");
  assert.equal(getRuntimeBasePath(null), "");
});

test("getRuntimeBasePath extracts subpath prefix when deployed on a subpath", () => {
  assert.equal(getRuntimeBasePath("/thhv/en"), "/thhv");
  assert.equal(getRuntimeBasePath("/thhv/ja"), "/thhv");
  assert.equal(getRuntimeBasePath("/thhv/admin"), "/thhv");
  assert.equal(getRuntimeBasePath("/my-portal/api/incidents"), "/my-portal");
});

test("getRuntimeBasePath falls back to NEXT_PUBLIC_BASE_PATH when no window/pathname is provided", () => {
  const orig = process.env.NEXT_PUBLIC_BASE_PATH;
  try {
    process.env.NEXT_PUBLIC_BASE_PATH = "/subpath/";
    assert.equal(getRuntimeBasePath(""), "/subpath");
  } finally {
    if (orig === undefined) {
      delete process.env.NEXT_PUBLIC_BASE_PATH;
    } else {
      process.env.NEXT_PUBLIC_BASE_PATH = orig;
    }
  }
});

test("withBasePath prefixes relative paths correctly", () => {
  assert.equal(withBasePath("/api/incidents", "/thhv/ja"), "/thhv/api/incidents");
  assert.equal(withBasePath("api/incidents", "/thhv/ja"), "/thhv/api/incidents");
  assert.equal(withBasePath("/ja", "/thhv/ja"), "/thhv/ja");
  assert.equal(withBasePath("/api/incidents", "/ja"), "/api/incidents");
});

test("withBasePath does not duplicate existing base prefix", () => {
  assert.equal(withBasePath("/thhv/api/incidents", "/thhv/ja"), "/thhv/api/incidents");
  assert.equal(withBasePath("/thhv", "/thhv/ja"), "/thhv");
});

test("isAdminPath accurately identifies admin routes", () => {
  assert.equal(isAdminPath("/admin"), true);
  assert.equal(isAdminPath("/admin/settings"), true);
  assert.equal(isAdminPath("/thhv/admin"), true);
  assert.equal(isAdminPath("/thhv/admin/logs"), true);
  assert.equal(isAdminPath("/ja"), false);
  assert.equal(isAdminPath("/en"), false);
  assert.equal(isAdminPath("/api/incidents"), false);
  assert.equal(isAdminPath(""), false);
  assert.equal(isAdminPath(null), false);
});
