import test from "node:test";
import assert from "node:assert/strict";
import { formatDate } from "../app/components/dateFormat.ts";

test("formatDate returns empty string for empty, null, or undefined input", () => {
  assert.equal(formatDate(""), "");
  assert.equal(formatDate(null), "");
  assert.equal(formatDate(undefined), "");
});

test("formatDate returns raw string if unparseable", () => {
  assert.equal(formatDate("not-a-date"), "not-a-date");
});

test("formatDate formats UTC for English (en)", () => {
  // 2026-10-17 16:45 UTC
  const iso = "2026-10-17T16:45:00Z";
  const formatted = formatDate(iso, "en");
  assert.ok(formatted.endsWith("UTC"), `Expected formatted string to end with UTC, got: ${formatted}`);
  assert.ok(formatted.includes("16:45"), `Expected 16:45 in formatted time, got: ${formatted}`);
  assert.ok(formatted.includes("Oct 17"), `Expected Oct 17 in formatted date, got: ${formatted}`);
});

test("formatDate formats JST (Asia/Tokyo) for Japanese (ja) with explicit JST suffix", () => {
  // 2026-10-17 16:45 UTC is 2026-10-18 01:45 JST (UTC+9)
  const iso = "2026-10-17T16:45:00Z";
  const formatted = formatDate(iso, "ja");
  assert.ok(formatted.endsWith("JST"), `Expected formatted string to end with JST, got: ${formatted}`);
  assert.ok(formatted.includes("01:45"), `Expected 01:45 in formatted time, got: ${formatted}`);
  assert.ok(formatted.includes("10月18日"), `Expected 10月18日 in formatted date, got: ${formatted}`);
});

test("formatDate preserves timezone calculation when ISO string has timezone offset", () => {
  // 2026-10-18 01:45 +09:00 -> same point in time
  const iso = "2026-10-18T01:45:00+09:00";
  const formattedEn = formatDate(iso, "en");
  const formattedJa = formatDate(iso, "ja");
  assert.ok(formattedEn.endsWith("UTC"));
  assert.ok(formattedEn.includes("16:45"));
  assert.ok(formattedJa.endsWith("JST"));
  assert.ok(formattedJa.includes("01:45"));
});

test("formatDate includes year if incident timestamp is from a different year", () => {
  const isoPast = "2024-05-12T08:30:00Z";
  const formattedEn = formatDate(isoPast, "en");
  const formattedJa = formatDate(isoPast, "ja");
  assert.ok(formattedEn.includes("2024"), `Expected 2024 in English past date, got: ${formattedEn}`);
  assert.ok(formattedEn.endsWith("UTC"));
  assert.ok(formattedJa.includes("2024年"), `Expected 2024年 in Japanese past date, got: ${formattedJa}`);
  assert.ok(formattedJa.endsWith("JST"));
});

