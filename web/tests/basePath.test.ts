import test from "node:test";
import assert from "node:assert/strict";
import { getRuntimeBasePath, withBasePath, isAdminPath } from "../app/components/basePath.ts";

function withWindow(injected: string | undefined, pathname: string, run: () => void) {
  const original = (globalThis as any).window;
  (globalThis as any).window = { location: { pathname }, __RUNTIME_BASE_PATH__: injected };
  try {
    run();
  } finally {
    if (original === undefined) delete (globalThis as any).window;
    else (globalThis as any).window = original;
  }
}

function withEnv(value: string | undefined, run: () => void) {
  const { BASE_PATH, NEXT_PUBLIC_BASE_PATH } = process.env;
  delete process.env.NEXT_PUBLIC_BASE_PATH;
  if (value === undefined) delete process.env.BASE_PATH;
  else process.env.BASE_PATH = value;
  try {
    run();
  } finally {
    for (const [name, original] of Object.entries({ BASE_PATH, NEXT_PUBLIC_BASE_PATH })) {
      if (original === undefined) delete process.env[name];
      else process.env[name] = original;
    }
  }
}

test("the browser uses only the prefix injected by the server", () => {
  withWindow("/threat/", "/threat/ja", () => {
    assert.equal(getRuntimeBasePath(), "/threat");
    assert.equal(withBasePath("/en"), "/threat/en");
  });
  // The URL is never used to guess a prefix.
  withEnv("/threat", () => {
    for (const pathname of ["/ja", "/nope", "/foo/ja"]) {
      withWindow(undefined, pathname, () => assert.equal(getRuntimeBasePath(), "", pathname));
    }
  });
});

test("server rendering uses the configured BASE_PATH", () => {
  withEnv(undefined, () => assert.equal(getRuntimeBasePath(), ""));
  withEnv("/", () => assert.equal(getRuntimeBasePath(), ""));
  withEnv("threat/", () => assert.equal(getRuntimeBasePath(), "/threat"));
  withEnv('/x"><svg>', () => assert.equal(getRuntimeBasePath(), ""));
});

test("withBasePath prefixes relative paths without duplicating the prefix", () => {
  withEnv("/thhv", () => {
    assert.equal(withBasePath("/api/incidents"), "/thhv/api/incidents");
    assert.equal(withBasePath("api/incidents"), "/thhv/api/incidents");
    assert.equal(withBasePath("/"), "/thhv/");
    assert.equal(withBasePath("/thhv/en"), "/thhv/en");
    assert.equal(withBasePath("/thhv"), "/thhv");
  });
  withEnv(undefined, () => assert.equal(withBasePath("/api/incidents"), "/api/incidents"));
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
