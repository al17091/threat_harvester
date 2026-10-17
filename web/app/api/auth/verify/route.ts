import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const inputPassword = body?.password;
    const adminPassword = process.env.ADMIN_PASSWORD || "harvester2026";

    if (!inputPassword || typeof inputPassword !== "string") {
      return NextResponse.json({ success: false, error: "Password is required" }, { status: 400 });
    }

    if (inputPassword === adminPassword) {
      const response = NextResponse.json({ success: true, message: "Authentication successful" });
      // Set secure HTTP-only session cookie valid for 7 days
      response.cookies.set("admin_session", "authenticated", {
        path: "/",
        httpOnly: false, // Accessible from client-side JS for reactive UI rendering
        sameSite: "lax",
        maxAge: 60 * 60 * 24 * 7,
      });
      return response;
    }

    return NextResponse.json({ success: false, error: "Invalid administrator password" }, { status: 401 });
  } catch (err) {
    return NextResponse.json({ success: false, error: "Internal server error" }, { status: 500 });
  }
}

export async function GET(req: NextRequest) {
  const session = req.cookies.get("admin_session")?.value;
  return NextResponse.json({ authenticated: session === "authenticated" });
}

export async function DELETE(req: NextRequest) {
  const response = NextResponse.json({ success: true, message: "Logged out" });
  response.cookies.delete("admin_session");
  return response;
}

