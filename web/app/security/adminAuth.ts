import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const SESSION_COOKIE = "admin_session";
export const SESSION_TTL_SECONDS = 12 * 60 * 60;

type Env = Record<string, string | undefined>;

const TOKEN_VERSION = "v1";

/** Returns the configured administrator password, or null when admin login is disabled. */
export function getAdminPassword(env: Env = process.env): string | null {
  const password = env.ADMIN_PASSWORD;
  return password && password.trim() ? password : null;
}

/**
 * Without SESSION_SECRET a random per-process secret is used, so sessions end on restart.
 * It lives on globalThis because route bundles may not share module state.
 */
function sessionSecret(env: Env): string {
  if (env.SESSION_SECRET) return env.SESSION_SECRET;
  const store = globalThis as typeof globalThis & { __adminSessionSecret?: string };
  store.__adminSessionSecret ??= randomBytes(32).toString("base64");
  return store.__adminSessionSecret;
}

/** The password is part of the key, so changing it revokes every issued session. */
function sign(payload: string, password: string, env: Env): Buffer {
  const key = createHmac("sha256", sessionSecret(env)).update(`admin-session:${password}`).digest();
  return createHmac("sha256", key).update(payload).digest();
}

export function verifyPassword(input: string, env: Env = process.env): boolean {
  const password = getAdminPassword(env);
  if (password === null) return false;
  // Comparing digests keeps the comparison constant-time for inputs of any length.
  const digest = (value: string) => createHash("sha256").update(value).digest();
  return timingSafeEqual(digest(input), digest(password));
}

/** Issues an expiring HMAC-signed token, or null when admin login is disabled. */
export function createSessionToken(env: Env = process.env, now: number = Date.now()): string | null {
  const password = getAdminPassword(env);
  if (password === null) return null;
  const expires = Math.floor(now / 1000) + SESSION_TTL_SECONDS;
  const payload = `${TOKEN_VERSION}.${expires}.${randomBytes(16).toString("base64url")}`;
  return `${payload}.${sign(payload, password, env).toString("base64url")}`;
}

export function verifySessionToken(
  token: string | undefined,
  env: Env = process.env,
  now: number = Date.now()
): boolean {
  const password = getAdminPassword(env);
  if (password === null || !token) return false;

  const parts = token.split(".");
  if (parts.length !== 4) return false;
  const [version, expires, id, signature] = parts;
  if (version !== TOKEN_VERSION || !/^\d+$/.test(expires)) return false;

  const expected = sign(`${version}.${expires}.${id}`, password, env);
  // Compare the encoded form so that only the canonical encoding is accepted.
  const actual = Buffer.from(signature);
  const wanted = Buffer.from(expected.toString("base64url"));
  if (actual.length !== wanted.length || !timingSafeEqual(actual, wanted)) return false;

  return Number(expires) > Math.floor(now / 1000);
}
