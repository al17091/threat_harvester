const http = require("http");
const next = require("next");
const { createRequestListener } = require("./server-lib/listener");
const { normalizePrefix } = require("./server-lib/security");

const dev = process.env.NODE_ENV !== "production";
const hostname = "0.0.0.0";
const port = parseInt(process.env.PORT || "3000", 10);

const app = next({ dev, hostname, port });
const handle = app.getRequestHandler();

const configuredBasePath = normalizePrefix(
  process.env.BASE_PATH || process.env.NEXT_PUBLIC_BASE_PATH || ""
);

app.prepare().then(() => {
  http
    .createServer(createRequestListener({ handle, dev, configuredBasePath }))
    .listen(port, hostname, () => {
      console.log(
        `> Threat Harvester Web Ready on http://${hostname}:${port}${
          configuredBasePath ? ` ( also serving subpath ${configuredBasePath} )` : " ( dynamic subpath routing enabled, e.g. /thhv )"
        }`
      );
    });
});
