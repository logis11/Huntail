#!/usr/bin/env python3
# test_faultstate.py — **is a checker's "cannot decide" laundered into a result?**
#
# The incident this file comes from:
#   The interrogator twice failed to emit JSON, and the agent was told "the
#   interrogator broke your rejection". The counters went up as `broke` too. So
#   `interrog_failed` / `refute_failed` were **0 in every single run** — meaning a
#   failure was never once counted as a failure. The agent could not tell
#   "my argument was wrong" from "the checker returned nothing", so it burned
#   rounds resubmitting the same claim in different words.
#
# Contract: undecidable is a **third state**.
#   refuted / sustained / escalated / verdict = None  +  fault='no_json'|'bad_json'
#   The consumer must branch on that **before** reading the verdict
#   (None is falsy and otherwise slips through silently).
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import adjudicator
import escalator
import interrogator
import refuter
import submit

FAIL = []
# The count is never hardcoded. A hardcoded total (a sum written by hand) once
# stayed at 28 while the suite grew to 93 checks, and the file reported "28/28".
# A self-reported number that differs from reality is the kind of bug this
# repository keeps losing to — do not count, **use what was counted.**
TOTAL = [0]

ADVERSARIES = ((interrogator, "sustained", "interrogator"),
               (refuter, "refuted", "refuter"),
               (escalator, "escalated", "escalator"))


def ck(name, cond, extra=""):
    TOTAL[0] += 1
    if not cond:
        FAIL.append(name)
        print("  FAIL  %s  %s" % (name, str(extra)[:200]))


def _func_src(modname, fnname):
    """The source of one function, by AST — not by slicing between two names.

    Slicing on `src.index("def _normalize")` looks like it works and silently
    measures the wrong region as soon as the definitions are reordered, which is
    exactly the kind of check that reports a number about nothing.
    """
    import ast
    src = open(os.path.join(HERE, modname + ".py"), encoding="utf-8").read()
    tree = ast.parse(src)
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == fnname:
            return ast.get_source_segment(src, n) or ""
    raise AssertionError("%s.%s not found" % (modname, fnname))


# ── the parser produces the third state ──────────────────────────
for mod, key, who in ADVERSARIES:
    v = mod.parse_verdict("I read all the evidence but never emitted any JSON")
    ck("%s: no JSON -> fault" % who, v.get("fault") == "no_json", v)
    ck("%s: no JSON -> verdict is None (not False)" % who, v.get(key) is None, v)
    v = mod.parse_verdict('{"%s": tru, "klass": "x"}' % key)          # broken JSON
    ck("%s: parse failure -> fault" % who, v.get("fault") == "bad_json", v)
    ck("%s: parse failure -> verdict is None" % who, v.get(key) is None, v)

# ── a normal response is untouched ───────────────────────────────
v = interrogator.parse_verdict('{"sustained": true, "klass": "guarded", "reason": "ok"}')
ck("interrogator: sustained -> no fault", v.get("sustained") is True and not v.get("fault"), v)
v = interrogator.parse_verdict('{"sustained": false, "klass": "g", "reason": "broke it"}')
ck("interrogator: collapsed -> no fault (that is a real result)",
   v.get("sustained") is False and not v.get("fault"), v)
v = refuter.parse_verdict('{"refuted": false, "klass": null, "reason": "survives"}')
ck("refuter: survives -> no fault", v.get("refuted") is False and not v.get("fault"), v)
v = refuter.parse_verdict('{"refuted": true, "klass": "by_design", "reason": "dead"}')
ck("refuter: killed -> no fault (that is a real result)",
   v.get("refuted") is True and not v.get("fault"), v)

# ── nested objects: a valid response must not be contaminated into a fault ──
# The old parser was r'\{[^{}]*"key"[^{}]*\}'. Because of `[^{}]*` the match broke
# as soon as a value was an object, and **a response that obeyed the schema was
# scored no_json.** The fault counter then cannot separate "the model broke the
# format" from "the parser could not read it" — which was the entire reason the
# third state exists, so the bug was undoing its own fix.
# (Arrays never broke. That is why nobody noticed, and why the regression test
#  only exercised flat objects.)
NEST = [
    ("nested object, 1 deep", '{"%s": false, "evidence": {"va": "0x140017C92"}, "reason": "x"}'),
    ("nested object, 2 deep", '{"%s": false, "e": {"a": {"b": 1}}, "reason": "x"}'),
    ("array value",           '{"%s": false, "anchors": ["0x1","0x2"], "reason": "x"}'),
    ("brace inside a string", '{"%s": false, "reason": "guard at { rsp+0x40 } is real"}'),
    ("code fence",            '```json\n{"%s": false, "reason": "x"}\n```'),
    ("example first",         'e.g. {"%s": true, "reason": "example"}\n\n'
                              'Conclusion:\n{"%s": false, "reason": "real"}'),
]
for mod, key, who in ADVERSARIES:
    for name, tpl in NEST:
        payload = tpl % ((key, key) if tpl.count("%s") == 2 else key)
        v = mod.parse_verdict(payload)
        ck("%s: %s -> not a fault" % (who, name), not v.get("fault"), v)
        ck("%s: %s -> verdict is False" % (who, name), v.get(key) is False, v)

# the LAST object is the answer — the conclusion (false), not the example (true)
v = refuter.parse_verdict('{"refuted": true, "reason": "example"}\n'
                          '{"refuted": false, "reason": "conclusion"}')
ck("refuter: the last object wins",
   v.get("refuted") is False and v.get("reason") == "conclusion", v)

# a broken last object must NOT fall back to an intact earlier one (laundering)
v = refuter.parse_verdict('{"refuted": true, "reason": "example"}\n'
                          '{"refuted": fals, "reason": "conclusion"}')
ck("refuter: a broken last object is not replaced by an earlier one",
   v.get("fault") == "bad_json", v)

# the old regex must be gone
for mod in (interrogator, refuter, escalator):
    src = open(os.path.join(HERE, mod.__name__ + ".py"), encoding="utf-8").read()
    ck("%s: the old _JSON regex is removed" % mod.__name__, "_JSON = re.compile" not in src)


# ── the submission-tool path ─────────────────────────────────────
# A text medium guarantees no format. Measured: of 20 confirmations killed by the
# refuter, 4 (20%) were actually parse failures, all laundered into `refuted`
# (`klass=None` is the fingerprint). The analyst never had this problem because it
# has tools => give the adversaries a submission tool too. It does not touch the
# ledger.
for key, mod, who in (("refuted", refuter, "refuter"),
                      ("sustained", interrogator, "interrogator"),
                      ("escalated", escalator, "escalator")):
    # with a bucket, the value is used with no parsing at all
    b = {key: True, "reason": "submitted through the tool", "principal": "AC SID"}
    v = mod.parse_verdict("the body contains no JSON whatsoever", b)
    ck("%s: tool submission -> no fault (even with an empty body)" % who, not v.get("fault"), v)
    ck("%s: tool submission -> via='tool'" % who, v.get("via") == "tool", v)
    ck("%s: the submitted value is carried through" % who, v.get(key) is True, v)
    # the text fallback stays distinguishable through `via`
    v = mod.parse_verdict('{"%s": true, "principal": "AC SID", "reason": "text"}' % key)
    ck("%s: text fallback -> via='text'" % who, v.get("via") == "text", v)
    # does run() build a per-session bucket? (a global one mixes concurrent runs)
    src = open(os.path.join(HERE, mod.__name__ + ".py"), encoding="utf-8").read()
    ck("%s: run() creates a submission server per session" % who, "submit.make(" in src)
    ck("%s: the submission tool is in BOTH tools and allowed_tools" % who,
       "tools=_tools, allowed_tools=_tools" in src and "submit.TOOL_FQN" in src)

# both paths pass the same rules — if the tool path is looser, it is a bypass
v = escalator.parse_verdict("", {"escalated": True, "principal": "  ", "reason": "x"})
ck("escalator: the principal check is NOT waived on the tool path",
   v.get("escalated") is False, v)
v = escalator.parse_verdict('{"escalated": true, "principal": "  ", "reason": "x"}')
ck("escalator: the text path gives the same answer", v.get("escalated") is False, v)

# buckets are per session (a global bucket lets the second run overwrite the first)
_s1, _b1 = submit.make("refuted")
_s2, _b2 = submit.make("refuted")
ck("submission buckets are separate per session", _b1 is not _b2)
ck("every adversary role has a submission schema",
   set(submit.SPECS) == {"refuted", "sustained", "escalated", "adjudicated"}, sorted(submit.SPECS))


# ── a fault is NEVER a verdict — the single enforcement point ─────
# This invariant used to rest only on control flow (the fault returns did not go
# through `_normalize`). It lived in the comments and the tests but had no
# enforcement point in the code, so adding a new fault path broke it silently —
# and None is falsy, so the consumer read it as a verdict.
for mod, key, who in ADVERSARIES + ((adjudicator, "verdict", "adjudicator"),):
    v = mod._normalize({key: True, "fault": "no_json", "principal": "invented"})
    ck("%s: fault + True is forced to None" % who, v.get(key) is None, v)
    v = mod._normalize({key: False, "fault": "bad_json"})
    ck("%s: fault + False is forced to None" % who, v.get(key) is None, v)
    # and does **every** return actually pass through it? (a dead guard is worse
    # than no guard)
    body = _func_src(mod.__name__, "parse_verdict")
    n_ret = body.count("return ")
    n_norm = body.count("_normalize(")
    ck("%s: every return in parse_verdict goes through _normalize" % who,
       n_ret == n_norm and n_ret >= 4, "return=%d normalize=%d" % (n_ret, n_norm))

# a retry must not resend the identical prompt — it breaks the same way twice
for mod, who in ((interrogator, "interrogator"), (refuter, "refuter"),
                 (escalator, "escalator"), (adjudicator, "adjudicator")):
    src = open(os.path.join(HERE, mod.__name__ + ".py"), encoding="utf-8").read()
    ck("%s: the retry appends an instruction" % who, "_nudge=submit.RETRY_NUDGE" in src)
    ck("%s: run() retries once on a fault" % who,
       "_retry=1" in src and 'v.get("fault") and _retry > 0' in src)


# ── the adjudicator: three slots, and confirm needs an anchor ─────
# Offering only confirm/reject launders "cannot be decided" into one of them.
ck("adjudicator: the vocabulary is exactly confirm|reject|exhaust",
   adjudicator.VERDICTS == ("confirm", "reject", "exhaust"), adjudicator.VERDICTS)
v = adjudicator.parse_verdict('{"verdict": "exhaust", "reason": "nobody measured it"}')
ck("adjudicator: exhaust is a real answer, not a fault",
   v.get("verdict") == "exhaust" and not v.get("fault"), v)
v = adjudicator.parse_verdict('{"verdict": "confirm-ish", "reason": "x"}')
ck("adjudicator: outside the vocabulary is not a verdict",
   v.get("verdict") is None and v.get("fault") == "bad_verdict", v)
ck("adjudicator: and the message names what was actually returned",
   "confirm-ish" in (v.get("reason") or ""), v.get("reason"))
v = adjudicator.parse_verdict('{"verdict": "confirm", "reason": "it stands"}')
ck("adjudicator: a confirm with no decisive anchor is downgraded to exhaust",
   v.get("verdict") == "exhaust" and v.get("downgraded_from") == "confirm", v)
v = adjudicator.parse_verdict('{"verdict": "confirm", "reason": "it stands", '
                              '"decisive": "0x140001000 cmp eax, 3"}')
ck("adjudicator: a confirm WITH an anchor stands",
   v.get("verdict") == "confirm" and not v.get("downgraded_from"), v)


# ── mandates: the defaults point in opposite directions ──────────
# refuter: unsure => kill (a false positive is expensive)
# interrogator: unsure => the rejection does not stand (a false rejection loses
#               the bug permanently)
ck("refuter: the default is refuted=True (kill mandate)",
   refuter._normalize({}).get("refuted") is True)
ck("interrogator: the default is sustained=False (the rejection does not stand)",
   interrogator._normalize({}).get("sustained") is False)
ck("escalator: the default is escalated=False (never invent one)",
   escalator._normalize({}).get("escalated") is False)

# Not covered here: that the CONSUMER branches on fault before reading the
# verdict, and that a fault increments `failed` rather than `killed`/`broke`.
# Those assertions live against the wiring (ledger + agent loop) and land with it.

N = TOTAL[0]
print("\n%s (%d/%d)" % ("ALL PASS" if not FAIL else "FAILED: " + ", ".join(FAIL),
                        N - len(FAIL), N))
raise SystemExit(1 if FAIL else 0)
