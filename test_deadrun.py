#!/usr/bin/env python3
# test_deadrun.py — the "dead run" gate regression.
#
# A failure here is expensive in BOTH directions:
#   false positive -> a healthy run is stamped invalid, and the runner drops into
#                     a multi-hour quota wait (this happened twice in one day)
#   false negative -> a rate-limited run's "0 confirmations" is scored as a real
#                     negative
# So every negative case below comes from an ACTUAL incident, not an invention.
#
# The regexes are NOT copied here — this imports deadrun.py. A copy is exactly how
# the Python side got fixed twice while five shell scripts kept the old version.
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import deadrun

FAIL = []


def dead(out):
    return bool(deadrun.dead(out))


def trans(out):
    return bool(deadrun.trans(out))


def ck(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + (("  " + str(extra)[:150]) if not cond else ""))
    if not cond:
        FAIL.append(name)


# ── DEAD positives — phrasing the API actually emits ─────────────────────────
ck("session limit", dead("Error: You've hit your session limit. Resets at 3pm."))
ck("usage limit", dead("usage limit reached for this account"))
ck("rate_limit_error", dead('{"type":"error","error":{"type":"rate_limit_error"}}'))
ck("429 (HTTP context)", dead("HTTP 429 Too Many Requests"))
ck("429 (status context)", dead('{"status_code": 429, "detail": "..."}'))
ck("429 (Retry-After present)", dead("429 — Retry-After: 60"))
ck("credit balance", dead("Your credit balance is too low to access the API"))
ck("authentication_error", dead('{"error":{"type":"authentication_error"}}'))

# ── DEAD negatives (1): the TARGET's own vocabulary ──────────────────────────
# The thing under analysis talks about quotas and rate limits. That is not the
# API rate-limiting the run.
real = ("[tool ] verdict({'action': 'blocked', 'id': 'row-cachequota', "
        "'target': 'cache entry/pool quota: unbounded entry creation by non-admin'})")
ck("does not read the target's 'quota' as an API quota", not dead(real), real[:80])
ck("target 'rate limit' analysis, likewise",
   not dead("[think] the change check has a 1-hour rate limit on a last-check timestamp"))
ck("agent content line is excluded even with real phrasing",
   not dead("[think] the docs mention you can hit your session limit here"))
ck("a non-content line still matches",
   dead("[think] analysing quota\nError: You've hit your session limit"))
ck("empty output is not a dead run", not dead(""))

# ── DEAD negatives (2): the harness's OWN summary lines printing a bare 429 ───
# Incident: one run (27 min, 100 turns, 98 tool calls, subtype=success) had a
# surface of 429 items; the RUN SUMMARY printed "unanalysed 429". Summary lines
# do not start with `[tool ]`/`[think]`, so they pass the content exclusion. A
# bare `\b429\b` rule read that count as an API 429 and stamped dead='429' into
# the ledger. => 429 is honoured ONLY with API context.
for line in ["  verdict   : confirmed 3 · rejected 15 · unanalysed 429 (367 BLOCKED — with reason)  (success)",
             "  coverage  : 3/429 (1%)   ⚠ do not drop unanalysed from the table",
             "  turns/calls : 429 turns · 640 calls (harness tools 600)",
             "  time/cost : 429.4s · $8.6432",
             "  coverage 6/429 (1%)",
             "[20:20:30]   indexed 429 driver paths",
             "  ⏱ cut off by case timeout (surface 428→429, verdicts 87→88)",
             "  09-02 20:27  4.7m O surface+429 verdicts+0"]:
    ck("harness's own 429 is not read as an API 429: %s" % line.strip()[:34],
       not dead(line), line)

# ── TRANS ────────────────────────────────────────────────────────────────────
# A run died with `[think] API Error: Server error mid-response.` after 22 calls,
# yet `=== DONE: success ===` was printed and it was recorded as a VALID run. The
# cause was the `[think]` exclusion added to defend against the quota false
# positive — but the SDK carries transport errors INSIDE the assistant text
# stream. So the two rules differ in character: DEAD EXCLUDES content lines; TRANS
# looks at EVERY line.
_DEADRUN = ("[tool ] verdict({'action':'reject'})\n"
            "[think] API Error: Server error mid-response. The response above may be incomplete.\n"
            "\n=== DONE: success ===\n  turns/calls : 24 turns · 23 calls (harness tools 21)")
_LIVE = ("[think] The quota field saturates at 4.\n"
         "[think] rate limit logic at 0x1400416c8 does not block the caller\n"
         "[tool ] disassemble\n  turns/calls : 187 turns · 640 calls (harness tools 600)")
ck("catches a run killed by transport error (even with DONE: success)", trans(_DEADRUN))
ck("does not catch a healthy run that merely TALKS about quota/rate", not trans(_LIVE))

# ── Single-source regression: breaks if a regex copy reappears ───────────────
# The same regexes once lived in the orchestrator + five shells. The Python side
# was fixed twice while the shells kept the old version. A copy diverges silently,
# so no other module in the tree is allowed to re-define the DEAD pattern.
_copies = []
for fn in sorted(os.listdir(HERE)):
    if fn == "deadrun.py" or fn.startswith("test_") or not fn.endswith((".py", ".sh")):
        continue
    try:
        body = open(os.path.join(HERE, fn), encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    # A tell-tale fragment of the DEAD regex. If another file carries it verbatim,
    # it has copied the pattern instead of importing deadrun.
    if "credit balance is too low" in body and "import deadrun" not in body:
        _copies.append(fn)
ck("no other file re-defines the DEAD regex (single source)", not _copies, _copies)

print("%d failed" % len(FAIL) if FAIL else "all passed")
sys.exit(1 if FAIL else 0)
