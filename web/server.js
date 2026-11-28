const http = require("http");
const next = require("next");
const { createRequestListener } = require("./server-lib/listener");
const { normalizePrefix } = require("./server-lib/security");
const { parseTrustedProxyHops } = require("./server-lib/clientIp");

const dev = process.env.NODE_ENV !== "production";
const hostname = "0.0.0.0";
const port = parseInt(process.env.PORT || "3000", 10);

const app = next({ dev, hostname, port });
const handle = app.getRequestHandler();

const rawBasePath = process.env.BASE_PATH || process.env.NEXT_PUBLIC_BASE_PATH || "";
const configuredBasePath = normalizePrefix(rawBasePath);
if (!configuredBasePath && rawBasePath.replace(/\//g, "").trim()) {
  console.warn("Ignoring invalid BASE_PATH; serving at the root path only");
}
const trustedProxyHops = parseTrustedProxyHops(process.env.TRUSTED_PROXY_HOPS);

app.prepare().then(() => {
  http
    .createServer(createRequestListener({ handle, dev, configuredBasePath, trustedProxyHops }))
    .listen(port, hostname, () => {
      console.log(
        `> Threat Harvester Web Ready on http://${hostname}:${port}${
          configuredBasePath ? ` ( also serving subpath ${configuredBasePath} )` : " ( root path only; set BASE_PATH to serve a subpath )"
        }`
      );
    });
});
