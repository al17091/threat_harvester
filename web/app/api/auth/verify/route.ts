import { NextRequest, NextResponse } from "next/server";
import {
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
  createSessionToken,
  getAdminPassword,
  revokeSessionToken,
  verifyPassword,
  verifySessionToken,
} from "../../../security/adminAuth";
import { checkLogin, recordFailure, recordSuccess } from "../../../security/loginRateLimit";

export const dynamic = "force-dynamic";

function isHttps(req: NextRequest): boolean {
  const forwarded = req.headers.get("x-forwarded-proto")?.split(",")[0].trim();
  return (forwarded || req.nextUrl.protocol.replace(":", "")) === "https";
}

/**
 * The client address is set by the custom server, which overwrites any value sent by the client.
 * Without that server the header is untrustworthy and only the global limit applies.
 */
function clientKey(req: NextRequest): string | null {
  const trusted = (globalThis as { __harvesterClientIpTrusted?: boolean }).__harvesterClientIpTrusted;
  return trusted ? req.headers.get("x-harvester-client-ip") : null;
}

function tooManyAttempts(retryAfterSeconds: number) {
  return NextResponse.json(
    { success: false, error: "Too many login attempts. Try again later." },
    { status: 429, headers: { "Retry-After": String(retryAfterSeconds), "Cache-Control": "no-store" } }
  );
}

export async function POST(req: NextRequest) {
  if (getAdminPassword() === null) {
    return NextResponse.json(
      { success: false, error: "Administrator login is not configured (ADMIN_PASSWORD is unset)" },
      { status: 503 }
    );
  }

  const client = clientKey(req);
  const early = checkLogin(client);
  if (!early.allowed) return tooManyAttempts(early.retryAfterSeconds);

  const body = await req.json().catch(() => null);
  const inputPassword = body?.password;

  if (!inputPassword || typeof inputPassword !== "string") {
    return NextResponse.json({ success: false, error: "Password is required" }, { status: 400 });
  }

  // Checked again after the await: from here to recordFailure nothing yields, so parallel
  // requests cannot slip past the limit together.
  const limit = checkLogin(client);
  if (!limit.allowed) return tooManyAttempts(limit.retryAfterSeconds);

  const token = verifyPassword(inputPassword) ? createSessionToken() : null;
  if (!token) {
    recordFailure(client);
    return NextResponse.json({ success: false, error: "Invalid administrator password" }, { status: 401 });
  }

  recordSuccess(client);
  const response = NextResponse.json({ success: true, message: "Authentication successful" });
  response.cookies.set(SESSION_COOKIE, token, {
    path: "/",
    httpOnly: true,
    sameSite: "strict",
    secure: isHttps(req),
    maxAge: SESSION_TTL_SECONDS,
  });
  return response;
}

export async function GET(req: NextRequest) {
  const session = req.cookies.get(SESSION_COOKIE)?.value;
  return NextResponse.json({ authenticated: verifySessionToken(session) });
}

export async function DELETE(req: NextRequest) {
  revokeSessionToken(req.cookies.get(SESSION_COOKIE)?.value);
  const response = NextResponse.json({ success: true, message: "Logged out" });
  response.cookies.delete(SESSION_COOKIE);
  return response;
}
