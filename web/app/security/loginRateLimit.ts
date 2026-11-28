// Sliding-window limits on failed administrator logins, kept in process memory.

export const LOGIN_WINDOW_MS = 15 * 60 * 1000;
export const MAX_FAILURES_PER_CLIENT = 10;
// Bounds guessing that is spread over many addresses. Reaching it blocks everyone, including
// the administrator, until old failures leave the window.
export const MAX_FAILURES_GLOBAL = 200;
export const MAX_TRACKED_CLIENTS = 5000;

const BUCKET_MS = 60 * 1000;
const WINDOW_BUCKETS = LOGIN_WINDOW_MS / BUCKET_MS;

interface LimiterState {
  clients: Map<string, number[]>;
  global: Map<number, number>;
  lastPrune: number;
}

export interface LimitDecision {
  allowed: boolean;
  retryAfterSeconds: number;
}

// Held on globalThis because route bundles may not share module state.
const store = globalThis as typeof globalThis & { __adminLoginLimiter?: LimiterState };

function limiter(): LimiterState {
  store.__adminLoginLimiter ??= { clients: new Map(), global: new Map(), lastPrune: 0 };
  return store.__adminLoginLimiter;
}

const recent = (failures: number[], now: number) => failures.filter((at) => now - at < LOGIN_WINDOW_MS);

function prune(state: LimiterState, now: number): void {
  state.lastPrune = now;
  for (const [key, failures] of state.clients) {
    const kept = recent(failures, now);
    if (kept.length) state.clients.set(key, kept);
    else state.clients.delete(key);
  }
}

/** Reports whether another attempt may be made. `key` is null when the client is unknown. */
export function checkLogin(key: string | null, now: number = Date.now()): LimitDecision {
  const state = limiter();
  let waitMs = 0;

  const failures = key === null ? [] : recent(state.clients.get(key) ?? [], now);
  if (failures.length >= MAX_FAILURES_PER_CLIENT) {
    waitMs = failures[0] + LOGIN_WINDOW_MS - now;
  }

  const oldestLive = Math.floor(now / BUCKET_MS) - WINDOW_BUCKETS + 1;
  let total = 0;
  let oldest = Infinity;
  for (const [bucket, count] of state.global) {
    if (bucket < oldestLive) {
      state.global.delete(bucket);
      continue;
    }
    total += count;
    oldest = Math.min(oldest, bucket);
  }
  if (total >= MAX_FAILURES_GLOBAL) {
    waitMs = Math.max(waitMs, (oldest + WINDOW_BUCKETS) * BUCKET_MS - now);
  }

  return { allowed: waitMs <= 0, retryAfterSeconds: Math.max(0, Math.ceil(waitMs / 1000)) };
}

export function recordFailure(key: string | null, now: number = Date.now()): void {
  const state = limiter();
  const bucket = Math.floor(now / BUCKET_MS);
  state.global.set(bucket, (state.global.get(bucket) ?? 0) + 1);
  if (key === null) return;

  if (now - state.lastPrune >= BUCKET_MS) prune(state, now);
  // When the table is full, new clients are covered by the global limit only; existing entries
  // are never evicted, so a flood of addresses cannot unblock anyone.
  if (!state.clients.has(key) && state.clients.size >= MAX_TRACKED_CLIENTS) return;

  const failures = recent(state.clients.get(key) ?? [], now);
  failures.push(now);
  state.clients.set(key, failures.slice(-MAX_FAILURES_PER_CLIENT));
}

export function recordSuccess(key: string | null): void {
  if (key !== null) limiter().clients.delete(key);
}

export function trackedClientCount(): number {
  return limiter().clients.size;
}

export function resetLoginLimiterForTests(): void {
  delete store.__adminLoginLimiter;
}
