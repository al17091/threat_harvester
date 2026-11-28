const net = require("net");

/** Reduces an address to the unit that rate limits apply to: IPv4 address or IPv6 /64. */
function bucketAddress(address) {
  const bare = address.split("%")[0];
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(bare);
  if (mapped) return mapped[1];
  if (net.isIP(bare) !== 6) return bare;

  const [head, tail] = bare.split("::");
  const groups = (part) =>
    part ? part.split(":").flatMap((g) => (g.includes(".") ? ["0", "0"] : [g])) : [];
  const start = groups(head);
  const end = groups(tail);
  const fill = tail === undefined ? [] : Array(8 - start.length - end.length).fill("0");
  const network = [...start, ...fill, ...end].slice(0, 4);
  return `${network.map((g) => parseInt(g, 16).toString(16)).join(":")}::/64`;
}

/**
 * Determines the client address. With `hops` trusted proxies in front of this server, only the
 * hops-th X-Forwarded-For entry from the right was written by one of them; anything further left
 * is client-controlled. With 0 hops no header is trusted.
 */
function resolveClientIp(remoteAddress, forwardedFor, hops) {
  if (hops > 0 && typeof forwardedFor === "string") {
    const entries = forwardedFor.split(",").map((entry) => entry.trim());
    const candidate = entries[entries.length - hops];
    if (candidate && net.isIP(candidate)) return bucketAddress(candidate);
  }
  return remoteAddress ? bucketAddress(remoteAddress) : null;
}

/** Parses TRUSTED_PROXY_HOPS; anything but a small non-negative integer means "trust nothing". */
function parseTrustedProxyHops(raw) {
  const value = String(raw ?? "").trim();
  if (value === "") return 0;
  if (/^\d$/.test(value)) return Number(value);
  console.warn(`Ignoring invalid TRUSTED_PROXY_HOPS "${value}"; forwarded addresses are not trusted`);
  return 0;
}

module.exports = { bucketAddress, resolveClientIp, parseTrustedProxyHops };
