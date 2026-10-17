/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
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
