const http = require("http");
const { parse } = require("url");
const next = require("next");

const dev = process.env.NODE_ENV !== "production";
const hostname = "0.0.0.0";
const port = parseInt(process.env.PORT || "3000", 10);

const app = next({ dev, hostname, port });
const handle = app.getRequestHandler();

const ROOT_SEGMENTS = new Set([
  "",
  "en",
  "ja",
  "admin",
  "api",
  "rss",
  "feed.xml",
  "_next",
  "icon.svg",
  "favicon.ico",
  "apple-touch-icon.png",
]);

function normalizePrefix(raw) {
  if (!raw || typeof raw !== "string") return "";
  const trimmed = raw.trim().replace(/\/+$/, "");
  if (!trimmed || trimmed === "/") return "";
  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}

const configuredBasePath = normalizePrefix(
  process.env.BASE_PATH || process.env.NEXT_PUBLIC_BASE_PATH || ""
);

function detectSubpathPrefix(req, pathname) {
  const headerPrefix = normalizePrefix(req.headers["x-forwarded-prefix"]);
  if (headerPrefix) {
    return headerPrefix;
  }

  if (
    configuredBasePath &&
    (pathname === configuredBasePath || pathname.startsWith(`${configuredBasePath}/`))
  ) {
    return configuredBasePath;
  }

  const parts = (pathname || "").split("/").filter(Boolean);
  if (parts.length > 0 && !ROOT_SEGMENTS.has(parts[0])) {
    return `/${parts[0]}`;
  }

  return "";
}

function rewriteHtmlAssets(bodyStr, prefix) {
  if (!prefix) return bodyStr;
  return bodyStr
    .replace(/(["'])\/_next\//g, `$1${prefix}/_next/`)
    .replace(/\\\/_next\\\//g, `\\${prefix}\\/_next\\/`)
    .replace(/(href=["'])\/(icon\.svg|favicon\.ico|apple-touch-icon\.png)(["'])/g, `$1${prefix}/$2$3`);
}

app.prepare().then(() => {
  http
    .createServer(async (req, res) => {
      try {
        const parsedUrl = parse(req.url || "/", true);
        const pathname = parsedUrl.pathname || "/";
        const search = parsedUrl.search || "";

        const prefix = detectSubpathPrefix(req, pathname);
        if (prefix) {
          let strippedPath = pathname;
          if (pathname === prefix) {
            strippedPath = "/";
          } else if (pathname.startsWith(`${prefix}/`)) {
            strippedPath = pathname.slice(prefix.length) || "/";
          }
          req.url = `${strippedPath}${search}`;
          const strippedParsedUrl = parse(req.url, true);

          const isStaticOrApi =
            strippedPath.startsWith("/_next/") ||
            strippedPath.startsWith("/api/") ||
            strippedPath === "/rss" ||
            strippedPath === "/feed.xml" ||
            strippedPath === "/icon.svg" ||
            strippedPath === "/favicon.ico" ||
            strippedPath === "/apple-touch-icon.png";

          if (!isStaticOrApi) {
            // Ensure uncompressed HTML/RSC output so asset paths can be rewritten cleanly
            delete req.headers["accept-encoding"];

            const chunks = [];
            const origWrite = res.write.bind(res);
            const origEnd = res.end.bind(res);

            res.write = function (chunk, encoding, cb) {
              if (chunk) {
                chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding));
              }
              if (typeof encoding === "function") encoding();
              if (typeof cb === "function") cb();
              return true;
            };

            res.end = function (chunk, encoding, cb) {
              if (chunk && typeof chunk !== "function") {
                chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding));
              }
              const fullBuffer = Buffer.concat(chunks);
              const contentType = String(res.getHeader("content-type") || "");
              if (
                contentType.includes("text/html") ||
                contentType.includes("text/x-component")
              ) {
                const rewritten = rewriteHtmlAssets(fullBuffer.toString("utf8"), prefix);
                const outBuf = Buffer.from(rewritten, "utf8");
                if (res.getHeader("content-length")) {
                  res.setHeader("content-length", outBuf.length);
                }
                res.write = origWrite;
                res.end = origEnd;
                return origEnd(outBuf, cb);
              }
              res.write = origWrite;
              res.end = origEnd;
              return origEnd(fullBuffer, cb);
            };
          }

          await handle(req, res, strippedParsedUrl);
          return;
        }

        await handle(req, res, parsedUrl);
      } catch (err) {
        console.error("Error handling request:", req.url, err);
        res.statusCode = 500;
        res.end("Internal Server Error");
      }
    })
    .listen(port, hostname, () => {
      console.log(
        `> Threat Harvester Web Ready on http://${hostname}:${port}${
          configuredBasePath ? ` ( also serving subpath ${configuredBasePath} )` : " ( dynamic subpath routing enabled, e.g. /thhv )"
        }`
      );
    });
});

