import test from "node:test";
import assert from "node:assert/strict";
import clientIp from "../server-lib/clientIp.js";

const { bucketAddress, resolveClientIp, parseTrustedProxyHops } = clientIp;

test("forwarded addresses are ignored unless proxies are trusted", () => {
  assert.equal(resolveClientIp("10.0.0.1", "203.0.113.5", 0), "10.0.0.1");
});

test("only the entry written by a trusted proxy is used", () => {
  const chain = "1.1.1.1, 203.0.113.5, 198.51.100.7";
  assert.equal(resolveClientIp("10.0.0.1", chain, 1), "198.51.100.7");
  assert.equal(resolveClientIp("10.0.0.1", chain, 2), "203.0.113.5");
});

test("short or malformed chains fall back to the socket address", () => {
  for (const chain of [undefined, "", "unknown", "203.0.113.5, not-an-ip", "203.0.113.5:1234"]) {
    assert.equal(resolveClientIp("10.0.0.1", chain, 1), "10.0.0.1", String(chain));
  }
  assert.equal(resolveClientIp("10.0.0.1", "203.0.113.5", 2), "10.0.0.1");
  assert.equal(resolveClientIp(undefined, undefined, 1), null);
});

test("IPv6 clients share a /64 bucket and mapped IPv4 is unwrapped", () => {
  const bucket = "2001:db8:1:2::/64";
  for (const address of ["2001:db8:1:2::1", "2001:0db8:0001:0002:ffff:ffff:ffff:ffff", "2001:db8:1:2:0:0:192.0.2.1"]) {
    assert.equal(bucketAddress(address), bucket, address);
  }
  assert.equal(bucketAddress("::1"), "0:0:0:0::/64");
  assert.equal(bucketAddress("::ffff:192.0.2.9"), "192.0.2.9");
  assert.equal(bucketAddress("fe80::1%eth0"), "fe80:0:0:0::/64");
});

test("TRUSTED_PROXY_HOPS accepts small integers only", () => {
  assert.equal(parseTrustedProxyHops(undefined), 0);
  assert.equal(parseTrustedProxyHops(" 2 "), 2);
  for (const bad of ["-1", "1.5", "all", "100"]) assert.equal(parseTrustedProxyHops(bad), 0, bad);
});
