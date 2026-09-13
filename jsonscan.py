# jsonscan.py — find JSON objects in a model response by **brace balance**.
#
# Why the regex was thrown out (measured):
#   All three adversaries were using `r'\{[^{}]*"key"[^{}]*\}'`. Because of
#   `[^{}]*`, the match breaks **the moment a value is an object**:
#
#       {"sustained": false, "evidence": {"va": "0x140017C92"}, "reason": "…"}
#
#   The model obeyed the schema and was scored `no_json`. When that happens the
#   fault counter **cannot separate "the model broke the format" from "the parser
#   could not read it"** — and separating those two was the entire reason the
#   third state (fault) exists, so this bug was quietly undoing that fix.
#
#   The blast radius was narrow: **arrays never broke** (`[^{}]` does not exclude
#   brackets); only object-valued fields did. That is why nobody noticed — most
#   responses were flat, and so were the regression tests.
#
# Contract: braces and escapes inside strings are understood.
# `{"reason": "a { b"}` does not break it.
import json


def spans(text):
    """The **top-level** balanced JSON object spans in `text`: [(start, end), …].

    Nested objects are not separate candidates — only the enclosing object.
    """
    out, depth, start = [], 0, -1
    in_str, esc = False, False
    for i, ch in enumerate(text or ""):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    out.append((start, i + 1))
                    start = -1
    return out


def find_last(text, key):
    """The source of the **last** top-level object containing `"key"`, else None.

    Taking the last one is the same convention the regex had: a model sometimes
    writes the schema example first and its conclusion afterwards.
    """
    t = text or ""
    needle = '"%s"' % key
    hit = None
    for s, e in spans(t):
        if needle in t[s:e]:
            hit = t[s:e]
    return hit


def parse_last(text, key):
    """(obj, fault, why) — (dict, None, "") on success, otherwise
    (None, 'no_json'|'bad_json', reason).

    If the last candidate is broken, **do not fall back to an earlier one.**
    Reading the example's verdict as the model's answer, because the model wrote
    a good example and a broken conclusion, is exactly the laundering this file
    exists to prevent.
    """
    raw = find_last(text, key)
    if raw is None:
        return None, "no_json", ""
    try:
        d = json.loads(raw)
    except Exception as e:
        return None, "bad_json", type(e).__name__
    if not isinstance(d, dict):
        return None, "bad_json", "top level is not an object (%s)" % type(d).__name__
    return d, None, ""
