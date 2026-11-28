import { NextRequest, NextResponse } from "next/server";
import { SESSION_COOKIE, verifySessionToken } from "../../security/adminAuth";
import { canonicalApiPath, isPublicApiRequest } from "../../security/apiPolicy";
import { buildBackendHeaders } from "../../security/proxyHeaders";

export const dynamic = "force-dynamic";

const getBackendUrl = () => {
  return process.env.BACKEND_URL || "http://127.0.0.1:8000";
};

async function handleProxy(
  req: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const resolvedParams = await params;
  const path = canonicalApiPath(resolvedParams.path ?? []);
  if (path === null) {
    return NextResponse.json({ error: "Invalid API path" }, { status: 400 });
  }
  const search = req.nextUrl.search;
  const targetUrl = `${getBackendUrl()}/api/${path}${search}`;

  // Deny by default: only the listed read endpoints are available without an admin session
  const privileged = !isPublicApiRequest(req.method, path);
  if (privileged) {
    if (!verifySessionToken(req.cookies.get(SESSION_COOKIE)?.value)) {
      return NextResponse.json(
        { error: "Unauthorized: Administrator authentication required" },
        { status: 401 }
      );
    }
  }

  // Past the check above, a privileged request has a verified administrator session
  const headers = buildBackendHeaders(req.headers, { privileged, token: process.env.INTERNAL_API_TOKEN });

  try {
    const init: RequestInit = {
      method: req.method,
      headers: headers,
      cache: "no-store",
    };

    if (req.method !== "GET" && req.method !== "HEAD") {
      const body = await req.arrayBuffer();
      init.body = body;
    }

    const res = await fetch(targetUrl, init);
    const resHeaders = new Headers(res.headers);
    if (resHeaders.get("content-type")?.includes("text/event-stream")) {
      resHeaders.set("Cache-Control", "no-cache, no-transform");
      resHeaders.set("Connection", "keep-alive");
      resHeaders.set("X-Accel-Buffering", "no");
    }

    return new NextResponse(res.body, {
      status: res.status,
      statusText: res.statusText,
      headers: resHeaders,
    });
  } catch (error) {
    console.error(`[API Proxy Error] Failed to proxy to ${targetUrl}:`, error);
    return NextResponse.json(
      // The error detail names the internal service host, so it is only logged
      { error: "Backend service unreachable" },
      { status: 502 }
    );
  }
}

export const GET = handleProxy;
export const POST = handleProxy;
export const PUT = handleProxy;
export const DELETE = handleProxy;
export const PATCH = handleProxy;
export const HEAD = handleProxy;

