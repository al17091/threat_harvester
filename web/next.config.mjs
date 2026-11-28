/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // HTML carries a per-request CSP nonce, so it must not be revalidated against an ETag.
  generateEtags: false,
  poweredByHeader: false,
  // Security headers and document caching are applied per request in server-lib/listener.js.
  async headers() {
    const revalidate = [{ key: "Cache-Control", value: "public, max-age=0, must-revalidate" }];
    return [
      { source: "/rss", headers: revalidate },
      { source: "/feed.xml", headers: revalidate },
      {
        source: "/api/:path*",
        headers: [
          {
            key: "Cache-Control",
            value: "no-store, max-age=0",
          },
        ],
      },
    ];
  },
  async rewrites() {
    return [
      {
        source: "/rss",
        destination: "/api/rss",
      },
      {
        source: "/feed.xml",
        destination: "/api/feed.xml",
      },
    ];
  },
};

export default nextConfig;
