import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

const getBackendUrl = () => {
  return process.env.BACKEND_URL || "http://127.0.0.1:8000";
};

async function handleProxy(req: NextRequest, { params }: { params: { path: string[] } }) {
  const path = params.path ? params.path.join("/") : "";
  const search = req.nextUrl.search;
  const targetUrl = `${getBackendUrl()}/api/${path}${search}`;

  const headers = new Headers(req.headers);
  headers.delete("host");

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
      { error: "Backend service unreachable", detail: String(error) },
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

