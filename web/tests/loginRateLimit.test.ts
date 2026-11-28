import test from "node:test";
import assert from "node:assert/strict";
import {
  LOGIN_WINDOW_MS,
  MAX_FAILURES_GLOBAL,
  MAX_FAILURES_PER_CLIENT,
  MAX_TRACKED_CLIENTS,
  checkLogin,
  recordFailure,
  recordSuccess,
  resetLoginLimiterForTests,
  trackedClientCount,
} from "../app/security/loginRateLimit.ts";

const start = Date.UTC(2026, 10, 28, 12);
const fail = (key: string | null, times: number, at = start) => {
  for (let i = 0; i < times; i++) recordFailure(key, at);
};

test.beforeEach(() => resetLoginLimiterForTests());

test("a client is blocked after too many failures, with an accurate Retry-After", () => {
  fail("a", MAX_FAILURES_PER_CLIENT - 1);
  assert.deepEqual(checkLogin("a", start), { allowed: true, retryAfterSeconds: 0 });
  fail("a", 1);
  assert.deepEqual(checkLogin("a", start + 1000), { allowed: false, retryAfterSeconds: LOGIN_WINDOW_MS / 1000 - 1 });
  assert.equal(checkLogin("b", start).allowed, true);
  assert.equal(checkLogin("a", start + LOGIN_WINDOW_MS).allowed, true);
});

test("a successful login clears that client only", () => {
  fail("a", MAX_FAILURES_PER_CLIENT - 1);
  fail("b", MAX_FAILURES_PER_CLIENT);
  recordSuccess("a");
  fail("a", MAX_FAILURES_PER_CLIENT - 1);
  assert.equal(checkLogin("a", start).allowed, true);
  assert.equal(checkLogin("b", start).allowed, false);
});

test("the global limit covers distributed and unidentified clients", () => {
  for (let i = 0; i < MAX_FAILURES_GLOBAL - 1; i++) recordFailure(i % 2 ? `client-${i}` : null, start);
  assert.equal(checkLogin("fresh", start).allowed, true);
  recordFailure(null, start);
  const blocked = checkLogin("fresh", start);
  assert.equal(blocked.allowed, false);
  assert.ok(blocked.retryAfterSeconds > 0 && blocked.retryAfterSeconds <= LOGIN_WINDOW_MS / 1000);
  assert.equal(checkLogin("fresh", start + blocked.retryAfterSeconds * 1000).allowed, true);
});

test("memory stays bounded and flooding never evicts a blocked client", () => {
  const later = start + 5 * 60_000;
  fail("victim", MAX_FAILURES_PER_CLIENT, later);
  for (let i = 0; i < 20_000; i++) recordFailure(`flood-${i}`, start);
  assert.equal(trackedClientCount(), MAX_TRACKED_CLIENTS);
  // The flood has left the global window here, so only the victim's own entry can block it.
  const afterFlood = start + LOGIN_WINDOW_MS + 1000;
  assert.equal(checkLogin("other", afterFlood).allowed, true);
  assert.equal(checkLogin("victim", afterFlood).allowed, false);
  recordFailure("new", later + LOGIN_WINDOW_MS + 60_000);
  assert.equal(trackedClientCount(), 1);
});
