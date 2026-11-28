// Prefix-aware rewriting of React Server Components ("flight") streams.
//
// A stream is a sequence of rows "<hex id>:<tag>...". Rows with a length-prefixed tag carry
// exactly that many bytes (text and binary data) and must stay byte-identical, otherwise the
// client reads past the row. Only newline-terminated rows, which hold JSON, are rewritten.

const bytes = (chars) => new Set([...chars].map((c) => c.charCodeAt(0)));

// Mirrors processBinaryChunk in react-server-dom-turbopack's client.
const LENGTH_TAGS = bytes("TAOobUSsLlGgMmV");
const OTHER_TAGS = bytes("#rx");
const COLON = 58;
const COMMA = 44;
const NEWLINE = 10;

// An escaped quote means the text is part of a string value, not a URL of its own.
const ASSET_URL_RE = /(?<!\\)"\/(_next\/|icon\.svg|favicon\.ico|apple-touch-icon\.png)/g;

/**
 * Returns a streaming rewriter. Chunks may split rows anywhere; push() returns the bytes that
 * can be emitted so far and flush() whatever is still held back.
 */
function createFlightRewriter(prefix) {
  let state = "id";
  let length = 0;
  let held = []; // bytes of the current row header or newline-terminated row

  const rewriteRow = (row) =>
    Buffer.from(
      row.toString("utf8").replace(ASSET_URL_RE, (_match, path) => `"${prefix}/${path}`),
      "utf8"
    );

  function push(chunk) {
    const out = [];
    let i = 0;
    while (i < chunk.length) {
      if (state === "id") {
        const byte = chunk[i++];
        held.push(chunk.subarray(i - 1, i));
        if (byte === COLON) state = "tag";
      } else if (state === "tag") {
        const byte = chunk[i];
        if (LENGTH_TAGS.has(byte)) {
          held.push(chunk.subarray(i, ++i));
          state = "length";
          length = 0;
        } else {
          if ((byte > 64 && byte < 91) || OTHER_TAGS.has(byte)) held.push(chunk.subarray(i, ++i));
          state = "line";
        }
      } else if (state === "length") {
        const byte = chunk[i++];
        held.push(chunk.subarray(i - 1, i));
        if (byte === COMMA) {
          out.push(...held);
          held = [];
          state = length > 0 ? "data" : "id";
        } else {
          length = length * 16 + parseInt(String.fromCharCode(byte), 16);
        }
      } else if (state === "data") {
        const take = Math.min(length, chunk.length - i);
        out.push(chunk.subarray(i, i + take));
        i += take;
        length -= take;
        if (length === 0) state = "id";
      } else {
        const end = chunk.indexOf(NEWLINE, i);
        if (end === -1) {
          held.push(chunk.subarray(i));
          i = chunk.length;
        } else {
          held.push(chunk.subarray(i, end + 1));
          i = end + 1;
          out.push(rewriteRow(Buffer.concat(held)));
          held = [];
          state = "id";
        }
      }
    }
    return Buffer.concat(out);
  }

  function flush() {
    const rest = Buffer.concat(held);
    held = [];
    return rest;
  }

  return { push, flush };
}

module.exports = { createFlightRewriter };
