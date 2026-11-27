#!/usr/bin/env python3
"""Regenerate agent/src/guardrails/lexicon.ts from api/internal/models/incident.go.

Usage (from repo root):
  python3 agent/scripts/gen_lexicon.py api/internal/models/incident.go > agent/src/guardrails/lexicon.ts
"""
import re, json, sys
src = open(sys.argv[1], encoding="utf-8").read()
def block(name):
    m = re.search(r"var " + name + r" = [^{]*\{\n(.*?)\n\}\n", src, re.S)
    return m.group(1)
def strip_comments(b):
    return "\n".join(l for l in b.split("\n") if not l.strip().startswith("//"))
def keys(name):
    b = strip_comments(block(name))
    return re.findall(r'"((?:[^"\\]|\\.)*)":\s*true', b)
def items(name):
    b = strip_comments(block(name))
    return re.findall(r'"((?:[^"\\]|\\.)*)"', b)
def pairs(name):
    b = strip_comments(block(name))
    return re.findall(r'"((?:[^"\\]|\\.)*)":\s*"((?:[^"\\]|\\.)*)"', b)
def unq(s): return json.loads('"' + s + '"')
def arr(xs): return "[\n" + "".join("  " + json.dumps(unq(x), ensure_ascii=False) + ",\n" for x in xs) + "]"
out = ["// AUTO-GENERATED mirror of api/internal/models/incident.go guardrail lexicons.",
       "// Regenerate with agent/scripts/gen_lexicon.py when the Go lists change so agent-side and api-side guardrails stay aligned.",
       ""]
out.append("export const GENERIC_VICTIM_EXACT: ReadonlySet<string> = new Set(" + arr(keys("genericVictimWords")) + ");\n")
out.append("export const GENERIC_VICTIM_SUBSTRINGS: readonly string[] = " + arr(items("genericVictimSubstrings")) + ";\n")
out.append("export const INVALID_ACTOR_SUBSTRINGS: readonly string[] = " + arr(items("invalidActorSubstrings")) + ";\n")
out.append("export const INVALID_ACTOR_EXACT: ReadonlySet<string> = new Set(" + arr(keys("invalidActorExact")) + ");\n")
p = pairs("canonicalActorNames")
out.append("export const CANONICAL_ACTOR_NAMES: Readonly<Record<string, string>> = {\n" + "".join(f"  {json.dumps(unq(k), ensure_ascii=False)}: {json.dumps(unq(v), ensure_ascii=False)},\n" for k,v in p) + "};\n")
b = strip_comments(block("actorAliasGroundings"))
g = re.findall(r'"([^"]+)":\s*\{([^}]*)\}', b)
out.append("export const ACTOR_ALIAS_GROUNDINGS: Readonly<Record<string, readonly string[]>> = {\n" + "".join(f"  {json.dumps(k, ensure_ascii=False)}: {json.dumps(re.findall(r'\"([^\"]+)\"', v), ensure_ascii=False)},\n" for k,v in g) + "};\n")
print("\n".join(out))
