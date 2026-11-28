import { NextRequest, NextResponse } from "next/server";
import {
  SESSION_COOKIE,
  SESSION_TTL_SECONDS,
  createSessionToken,
  getAdminPassword,
  verifyPassword,
  verifySessionToken,
} from "../../../security/adminAuth";

export const dynamic = "force-dynamic";

function isHttps(req: NextRequest): boolean {
  const forwarded = req.headers.get("x-forwarded-proto")?.split(",")[0].trim();
  return (forwarded || req.nextUrl.protocol.replace(":", "")) === "https";
}

export async function POST(req: NextRequest) {
  if (getAdminPassword() === null) {
    return NextResponse.json(
      { success: false, error: "Administrator login is not configured (ADMIN_PASSWORD is unset)" },
      { status: 503 }
    );
  }

  const body = await req.json().catch(() => null);
  const inputPassword = body?.password;

  if (!inputPassword || typeof inputPassword !== "string") {
    return NextResponse.json({ success: false, error: "Password is required" }, { status: 400 });
  }

  const token = verifyPassword(inputPassword) ? createSessionToken() : null;
  if (!token) {
    return NextResponse.json({ success: false, error: "Invalid administrator password" }, { status: 401 });
  }

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

export async function DELETE() {
  const response = NextResponse.json({ success: true, message: "Logged out" });
  response.cookies.delete(SESSION_COOKIE);
  return response;
}
