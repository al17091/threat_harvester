import test from "node:test";
import assert from "node:assert/strict";
import {
  SESSION_TTL_SECONDS,
  createSessionToken,
  getAdminPassword,
  revokeSessionToken,
  revokedSessionCount,
  verifyPassword,
  verifySessionToken,
} from "../app/security/adminAuth.ts";

const env = { ADMIN_PASSWORD: "correct horse battery", SESSION_SECRET: "s".repeat(32) };
const now = Date.UTC(2026, 10, 28);

test("admin login is disabled without a configured password", () => {
  for (const disabled of [{}, { ADMIN_PASSWORD: "" }, { ADMIN_PASSWORD: "   " }]) {
    assert.equal(getAdminPassword(disabled), null);
    assert.equal(createSessionToken(disabled), null);
    assert.equal(verifyPassword("harvester2026", disabled), false);
    assert.equal(verifySessionToken(createSessionToken(env)!, disabled), false);
  }
});

test("verifyPassword accepts only the exact password", () => {
  assert.equal(verifyPassword("correct horse battery", env), true);
  for (const wrong of ["", "correct horse batter", "correct horse battery ", "harvester2026"]) {
    assert.equal(verifyPassword(wrong, env), false, wrong);
  }
});

test("issued tokens verify until they expire", () => {
  const token = createSessionToken(env, now)!;
  assert.equal(verifySessionToken(token, env, now), true);
  assert.equal(verifySessionToken(token, env, now + (SESSION_TTL_SECONDS - 1) * 1000), true);
  assert.equal(verifySessionToken(token, env, now + SESSION_TTL_SECONDS * 1000), false);
  assert.notEqual(createSessionToken(env, now), token);
});

test("forged and tampered tokens are rejected", () => {
  const token = createSessionToken(env, now)!;
  const [version, expires, id, signature] = token.split(".");
  const flipped = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
  const forged = [
    undefined,
    "",
    "authenticated",
    `${version}.${expires}.${id}`,
    `${version}.${expires}.${id}.`,
    `${version}.${expires}.${id}.${flipped}`,
    `${version}.${expires}.${id}.${signature}=`,
    `${version}.${Number(expires) + 3600}.${id}.${signature}`,
    `${version}.${expires}.other.${signature}`,
    `v2.${expires}.${id}.${signature}`,
    `${token}.extra`,
  ];
  for (const candidate of forged) {
    assert.equal(verifySessionToken(candidate, env, now), false, String(candidate));
  }
});

test("changing the password or the secret revokes sessions", () => {
  const token = createSessionToken(env, now)!;
  assert.equal(verifySessionToken(token, { ...env, ADMIN_PASSWORD: "rotated" }, now), false);
  assert.equal(verifySessionToken(token, { ...env, SESSION_SECRET: "t".repeat(32) }, now), false);
});

test("a per-process secret is used when SESSION_SECRET is unset", () => {
  const ephemeral = { ADMIN_PASSWORD: env.ADMIN_PASSWORD };
  const token = createSessionToken(ephemeral, now)!;
  assert.equal(verifySessionToken(token, ephemeral, now), true);
  assert.equal(verifySessionToken(token, env, now), false);
});

test("logout revokes only that session, until it would have expired", () => {
  const [first, second] = [createSessionToken(env, now)!, createSessionToken(env, now)!];
  revokeSessionToken(first, env, now);
  assert.equal(verifySessionToken(first, env, now), false);
  assert.equal(verifySessionToken(second, env, now), true);

  const before = revokedSessionCount();
  for (const junk of [undefined, "", "authenticated", `${second}x`]) revokeSessionToken(junk, env, now);
  assert.equal(revokedSessionCount(), before);

  revokeSessionToken(undefined, env, now + SESSION_TTL_SECONDS * 1000);
  assert.equal(revokedSessionCount(), 0);
});

test("revocations are shared between separately loaded module instances", async () => {
  const copy = await import(`../app/security/adminAuth.ts?copy=${Date.now()}`);
  const token = createSessionToken(env, now)!;
  copy.revokeSessionToken(token, env, now);
  assert.equal(verifySessionToken(token, env, now), false);
});
