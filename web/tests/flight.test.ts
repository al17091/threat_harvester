import test from "node:test";
import assert from "node:assert/strict";
import flight from "../server-lib/flight.js";
import security from "../server-lib/security.js";

const { createFlightRewriter } = flight;
const { rewriteDocument, rewriteHtmlAssets, scriptJson } = security;

const textRow = (id: string, text: string) => `${id}:T${Buffer.byteLength(text).toString(16)},${text}`;
// Text content containing everything the rewriter looks for, including newlines and multibyte text.
const content = 'see "/_next/static/x.js"\n日本語 "/icon.svg"\n2:"/_next/fake"\n';
const stream =
  '2:"/_next/static/a.js"\n' +
  textRow("a", content) +
  ':HL["/_next/static/b.css","style"]\n' +
  '3:I[1,["$2","/_next/static/c.js"],"default"]\n' +
  '4:["$","p",null,{"children":"quoted \\"/_next/keep\\" text"}]\n' +
  textRow("b", "") +
  'c:{"href":"/favicon.ico"}\n';
const expected =
  '2:"/threat/_next/static/a.js"\n' +
  textRow("a", content) +
  ':HL["/threat/_next/static/b.css","style"]\n' +
  '3:I[1,["$2","/threat/_next/static/c.js"],"default"]\n' +
  '4:["$","p",null,{"children":"quoted \\"/_next/keep\\" text"}]\n' +
  textRow("b", "") +
  'c:{"href":"/threat/favicon.ico"}\n';

function rewrite(chunks: Buffer[]) {
  const rewriter = createFlightRewriter("/threat");
  return Buffer.concat([...chunks.map((c) => rewriter.push(c)), rewriter.flush()]);
}

test("JSON rows get the prefix while length-prefixed rows stay byte-identical", () => {
  assert.equal(rewrite([Buffer.from(stream)]).toString("utf8"), expected);
});

test("the result does not depend on where the stream is split", () => {
  const bytes = Buffer.from(stream);
  for (let at = 0; at <= bytes.length; at++) {
    assert.equal(rewrite([bytes.subarray(0, at), bytes.subarray(at)]).toString("utf8"), expected, `split ${at}`);
  }
  assert.equal(rewrite([...bytes].map((b) => Buffer.from([b]))).toString("utf8"), expected);
});

test("binary rows and incomplete rows are preserved", () => {
  const binary = Buffer.concat([Buffer.from("5:o4,"), Buffer.from([0xff, 0x0a, 0x22, 0x00])]);
  assert.deepEqual(rewrite([binary]), binary);
  assert.equal(rewrite([Buffer.from('6:["/_next/')]).toString(), '6:["/_next/');
});

test("RSC responses are rewritten as streams", () => {
  const out = rewriteDocument(Buffer.from(stream), "text/x-component", "/threat", "n");
  assert.equal(out.toString("utf8"), expected);
});

test("inline flight scripts are rewritten across pushes and keep their nonce", () => {
  const at = stream.indexOf("日本語");
  const pushes = [stream.slice(0, 10), stream.slice(10, at), stream.slice(at)];
  const script = (payload: string) => `<script nonce="n0">self.__next_f.push([1,${scriptJson(payload)}])</script>`;
  const html = `<head></head><script nonce="n0">(self.__next_f=self.__next_f||[]).push([0])</script>${pushes.map(script).join("<div></div>")}`;
  const out = rewriteHtmlAssets(html, "/threat", "n0");

  const payloads = [...out.matchAll(/<script nonce="n0">self\.__next_f\.push\(\[1,(".*?")\]\)<\/script>/g)];
  assert.equal(payloads.length, pushes.length);
  assert.equal(payloads.map((m) => JSON.parse(m[1])).join(""), expected);
  // The payload must not be able to close its script element.
  for (const [, literal] of payloads) assert.doesNotMatch(literal, /[<>]/);
});

test("binary pushes are passed through unchanged", () => {
  const data = Buffer.from([0xff, 0x00, 0x22]).toString("base64");
  const html =
    '<script>self.__next_f.push([1,"7:o3,"])</script>' + `<script>self.__next_f.push([3,"${data}"])</script>`;
  assert.equal(rewriteHtmlAssets(html, "/threat", "n"), html);
});
