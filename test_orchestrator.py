#!/usr/bin/env python3
# test_orchestrator.py — the consensus core, without spawning an agent.
#
# The parts that matter here are the ones a false result would corrupt silently:
#   · an invalid run must NOT enter the denominator (else a dead run's 0 confirms
#     scores as a real negative)
#   · consensus must be UNDEFINED for K<2 (one trajectory cannot agree with itself)
#   · two runs that confirm the same defect must land on the SAME key (else real
#     agreement is invisible and everything looks like a singleton lead)
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import orchestrator as O

FAIL = []


def ck(name, cond, extra=""):
    print(("PASS  " if cond else "FAIL  ") + name + (("  " + str(extra)[:150]) if not cond else ""))
    if not cond:
        FAIL.append(name)


# ── classify_run (delegates to deadrun) ──────────────────────────────────────
ck("dead log classified dead", O.classify_run("Error: You've hit your session limit") == "dead")
ck("transport drop classified trans",
   O.classify_run("[think] ok\n[think] API Error: Server error mid-response.") == "trans")
ck("healthy log classified valid",
   O.classify_run("[tool ] disassemble\n=== DONE: success ===\n  coverage 3/10") == "valid")
ck("a run that only TALKS about rate limits is still valid",
   O.classify_run("[think] the target has a rate limit at 0x1400416c8") == "valid")

# ── finding_key: stable identity across independent runs ──────────────────────
a1 = {"target": "AfdSend", "anchors": ["0x140022648 mov"], "klass": "uaf"}
a2 = {"target": "afdsend (renamed by the model)", "anchors": ["0x140022648 add rax"]}
ck("same anchor addr -> same key across runs", O.finding_key(a1) == O.finding_key(a2))
ck("anchor keying beats the target string",
   O.finding_key(a1).startswith("anchor:"))
b1 = {"target": "  Foo::Bar  ", "anchors": []}
b2 = {"target": "foo::bar"}
ck("no anchors -> normalized target key (case/space)", O.finding_key(b1) == O.finding_key(b2))
ck("different targets -> different keys",
   O.finding_key({"target": "X"}) != O.finding_key({"target": "Y"}))

# ── consensus: the denominator is VALID runs, never attempted ─────────────────
runs = [
    {"status": "dead", "confirmed": []},
    {"status": "trans", "confirmed": []},
    {"status": "valid", "confirmed": [a1]},
    {"status": "valid", "confirmed": [a2]},           # same finding as a1 (anchor)
    {"status": "valid", "confirmed": [{"target": "Solo", "anchors": []}]},
]
s = O.consensus(runs)
ck("attempted counts every run", s["attempted"] == 5)
ck("valid excludes dead+trans", s["valid"] == 3, s["valid"])
ck("dead/trans tallied separately", s["dead"] == 1 and s["trans"] == 1)
ck("majority of 3 is 2", s["majority"] == 2, s["majority"])
by_key = {f["key"]: f for f in s["findings"]}
shared = by_key[O.finding_key(a1)]
ck("finding reached by 2/3 valid runs is CONFIRMED",
   shared["support"] == 2 and shared["tier"] == "confirmed", shared)
solo = by_key[O.finding_key({"target": "Solo"})]
ck("finding reached by 1/3 is a LEAD, not dropped",
   solo["support"] == 1 and solo["tier"] == "lead", solo)

# one run listing the same finding twice still counts once
dup = [{"status": "valid", "confirmed": [a1, a1, a2]}]
ck("a single run counts once toward a finding's support",
   O.consensus(dup)["findings"][0]["support"] == 1)

# ── consensus is UNDEFINED for fewer than 2 valid runs ────────────────────────
one = O.consensus([{"status": "valid", "confirmed": [a1]},
                   {"status": "dead", "confirmed": []}])
ck("K<2 -> majority is None", one["majority"] is None)
ck("K<2 -> the lone finding is a lead, never confirmed",
   one["findings"][0]["tier"] == "lead", one["findings"])

# ── confirmed_from_ledger: only 확정, robust to junk ──────────────────────────
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "t.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"verdicts": [
            {"status": "확정", "target": "A"},
            {"status": "기각", "target": "B"},
            {"status": "미분석", "target": "C"},
            "not-a-dict",
        ]}, f, ensure_ascii=False)
    got = O.confirmed_from_ledger(p)
    ck("only confirmed verdicts returned", len(got) == 1 and got[0]["target"] == "A", got)
    ck("missing ledger -> []", O.confirmed_from_ledger(os.path.join(d, "nope.json")) == [])
    bad = os.path.join(d, "bad.json")
    open(bad, "w").write("{ truncated")
    ck("truncated ledger -> [] (not a crash)", O.confirmed_from_ledger(bad) == [])

# ── render smoke: the load-bearing sentences are present ──────────────────────
r_multi = O.render(s, "demo")
ck("render states invalid runs are not negatives", "not negatives" in r_multi)
ck("render shows the majority threshold when K>=2", "Majority threshold" in r_multi)
r_one = O.render(one, "demo")
ck("render warns consensus is undefined for K<2", "undefined for fewer than 2" in r_one)

print("%d failed" % len(FAIL) if FAIL else "all passed")
sys.exit(1 if FAIL else 0)
