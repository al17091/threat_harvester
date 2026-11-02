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
  assert.equal(formatted, "2026-10-17 16:45 UTC");
});

test("formatDate formats JST (Asia/Tokyo) for Japanese (ja) with explicit JST suffix", () => {
  // 2026-10-17 16:45 UTC is 2026-10-18 01:45 JST (UTC+9)
  const iso = "2026-10-17T16:45:00Z";
  const formatted = formatDate(iso, "ja");
  assert.equal(formatted, "2026-10-18 01:45 JST");
});

test("formatDate preserves timezone calculation when ISO string has timezone offset", () => {
  // 2026-10-18 01:45 +09:00 -> same point in time
  const iso = "2026-10-18T01:45:00+09:00";
  const formattedEn = formatDate(iso, "en");
  const formattedJa = formatDate(iso, "ja");
  assert.equal(formattedEn, "2026-10-17 16:45 UTC");
  assert.equal(formattedJa, "2026-10-18 01:45 JST");
});

test("formatDate always includes 4-digit year", () => {
  const isoPast = "2024-05-12T08:30:00Z";
  const formattedEn = formatDate(isoPast, "en");
  const formattedJa = formatDate(isoPast, "ja");
  assert.equal(formattedEn, "2024-05-12 08:30 UTC");
  assert.equal(formattedJa, "2024-05-12 17:30 JST");

  const isoCurrent = "2026-11-02T08:00:00Z";
  const curEn = formatDate(isoCurrent, "en");
  const curJa = formatDate(isoCurrent, "ja");
  assert.equal(curEn, "2026-11-02 08:00 UTC");
  assert.equal(curJa, "2026-11-02 17:00 JST");
});
