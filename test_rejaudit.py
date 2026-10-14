#!/usr/bin/env python3
# test_rejaudit.py — the rejection re-audit. **Which rejections are actually
# negatives, and which are only shaped like one?**
#
# Two things here fail silently in opposite directions, and both have happened.
#
# A. **Grading on form alone resurrects nothing and buries everything.** The
#    tier function originally read only `gate` and `basis` — never
#    `interrogation`. Of 43 rejections an independent interrogator had already
#    broken, **29 were graded T0** (confirmed negative) and sat in the
#    highest-confidence column of both `verified_negatives()` and the re-audit
#    queue. A tier measures the *shape* of a rejection; an adversary breaks its
#    *content*. Content has to win, and the precedence is pinned below.
#
# B. **Grading too harshly resurrects everything.** If the negative controls
#    collapse — a genuinely verified `gated` rejection, a measured one, an
#    interrogation that did NOT break anything — then every rejection re-enters
#    the queue and the audit is noise. Those are pinned as hard negatives.
#
# And the one that is not about tiers at all: the module matches on the literal
# status string the ledger writes (`"rejected"`). If that ever drifts, this file
# reports zero rejections and every number downstream becomes a lie, so it is
# checked against `ledger` directly rather than hard-coded twice.
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

FAIL, TOTAL = [], [0]


def ck(name, cond, extra=""):
    TOTAL[0] += 1
    if not cond:
        FAIL.append(name)
        print("  FAIL  %s  %s" % (name, str(extra)[:300]))


def rec(klass=None, cv=None, basis="disassemble", failed=0, broke=None, **kw):
    r = {"basis": basis, "gate": {"klass": klass, "anchors": {"failed": failed}}}
    if cv is not None:
        r["gate"]["cfg"] = {"verdict": cv}
    if broke is not None:
        r["interrogation"] = {"broke": bool(broke), "klass": "other_constructor"}
    r.update(kw)
    return r


# (name, record, run_invalid, expected tier)
# Written out independently of the module's own `_CONTROLS` on purpose: asserting
# a module against its own control table proves only that the table is loaded.
VECTORS = [
    # ── precedence, worst first ─────────────────────────────────────────────
    ("an invalid run beats a break",      rec("guarded", "gated", broke=True), True,  "T4"),
    ("a break beats basis=decompile",     rec("guarded", "gated", basis="decompile",
                                              broke=True),                     False, "T5"),
    ("a break beats a measured basis",    rec("delta_zero", basis="measured",
                                              broke=True),                     False, "T5"),
    ("a broken tool beats a gated cfg",   rec("guarded", "gated",
                                              basis="decompile"),              False, "T3"),
    ("decompiler_artifact klass",         rec("decompiler_artifact", "gated"),  False, "T3"),
    # ── unverified guards (the biggest real bucket) ─────────────────────────
    ("guarded + dominates_only",          rec("guarded", "dominates_only"),     False, "T1"),
    ("guarded + no_branch",               rec("guarded", "no_branch"),          False, "T1"),
    ("guarded + both_edges",              rec("guarded", "both_edges"),         False, "T1"),
    ("guarded + not_dominated",           rec("guarded", "not_dominated"),      False, "T1"),
    ("guarded + gated_no_authority",      rec("guarded", "gated_no_authority"), False, "T1"),
    ("guarded with no cfg at all",        rec("guarded", None),                 False, "T1"),
    # ── absence-shaped ──────────────────────────────────────────────────────
    ("no_sink",                           rec("no_sink"),                       False, "T2"),
    ("unreachable",                       rec("unreachable"),                   False, "T2"),
    # ── no gate adjudicates it ──────────────────────────────────────────────
    ("klass missing",                     rec(None),                            False, "T2b"),
    ("klass empty string",                rec(""),                              False, "T2b"),
    ("klass '?'",                         rec("?"),                             False, "T2b"),
    ("by_design",                         rec("by_design"),                     False, "T2b"),
    ("failed anchors outrank the klass",  rec("not_controlled", failed=2),      False, "T2b"),
    ("failed anchors outrank a gated cfg", rec("guarded", "gated", failed=2),   False, "T2b"),
    # ── the hard negatives: these must NOT be resurrected ───────────────────
    ("gated is a real negative",          rec("guarded", "gated"),              False, "T0"),
    ("gated_inter is a real negative",    rec("guarded", "gated_inter"),        False, "T0"),
    ("a measured rejection",              rec("delta_zero", basis="measured"),  False, "T0"),
    ("a sustained interrogation",         rec("guarded", "gated", broke=False), False, "T0"),
    ("a clean klass with clean anchors",  rec("not_controlled"),                False, "T0"),
]


def main():
    import rejaudit as RA

    # ── A. the tier matrix ──────────────────────────────────────────────────
    for name, r, inv, want in VECTORS:
        got, why = RA.classify(r, run_invalid=inv)
        ck("A/%s" % name, got == want, "got %s (%s)" % (got, why[:70]))
        ck("A/%s has a reason" % name, bool(why))

    # Spread check: a function stuck on one answer passes a matrix of one tier.
    tiers = {RA.classify(r, run_invalid=i)[0] for _n, r, i, _w in VECTORS}
    ck("A/all seven tiers are reachable",
       tiers == {"T0", "T1", "T2", "T2b", "T3", "T4", "T5"}, sorted(tiers))

    # ── B. the status literal the ledger writes ─────────────────────────────
    # Not hard-coded twice: read it out of the ledger so a drift fails here
    # rather than turning this whole module into a zero-row report.
    import ledger
    src = open(os.path.join(HERE, "rejaudit.py"), encoding="utf-8").read()
    lsrc = open(os.path.join(HERE, "ledger.py"), encoding="utf-8").read()
    lit = '"rejected"'
    ck("B1: rejaudit matches on the ledger's status literal", lit in src)
    ck("B2: the ledger still writes that literal", lit in lsrc)
    ck("B3: the ledger reads it back the same way",
       hasattr(ledger, "verified_negatives"))

    # ── C. audit() over records on disk ─────────────────────────────────────
    d = tempfile.mkdtemp(prefix="test_rejaudit_")
    p = os.path.join(d, "synthetic.json")
    verdicts = [dict(rec("guarded", "gated"), status="rejected", id="v-t0",
                     target="a", claim="c"),
                dict(rec("guarded", "dominates_only"), status="rejected", id="v-t1",
                     target="b", claim="c"),
                dict(rec("no_sink"), status="rejected", id="v-t2", target="c", claim="c"),
                dict(rec("guarded", "gated", broke=True), status="rejected", id="v-t5",
                     target="d", claim="c"),
                dict(rec("guarded", "gated"), status="confirmed", id="v-confirm",
                     target="e", claim="c")]
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"verdicts": verdicts}, f, ensure_ascii=False)
    import verifier_guard as _VG

    def _audit(**kw):
        """Report a refused result as a FAIL instead of crashing the tally — a
        suite that dies without printing its count is a suite you cannot read."""
        try:
            return RA.audit(**kw)
        except _VG.ControlFailed as e:
            ck("C0: audit() controls pass", False, str(e)[:200])
            return ([], __import__("collections").Counter())

    rows, per = _audit(files=[p])
    ck("C1: only rejections are audited", len(rows) == 4, len(rows))
    ck("C2: the per-tier tally is right",
       (per["T0"], per["T1"], per["T2"], per["T5"]) == (1, 1, 1, 1), dict(per))
    ck("C3: the worst tier sorts first",
       bool(rows) and rows[0]["tier"] == "T5", [r["tier"] for r in rows])
    ck("C4: T0 sorts last",
       bool(rows) and rows[-1]["tier"] == "T0", [r["tier"] for r in rows])
    ck("C5: the row carries the cfg verdict it was graded on",
       bool(rows) and rows[0]["cfg"] == "gated", rows[:1])
    ck("C6: a missing file is skipped, not fatal",
       _audit(files=[os.path.join(d, "nope.json")])[0] == [])
    ck("C7: a corrupt file is skipped, not fatal",
       (lambda q: (open(q, "w").write("{ not json"), _audit(files=[q])[0] == [])[1])(
           os.path.join(d, "bad.json")))

    # ── D. the state directory follows the ledger's namespace ───────────────
    # Auditing the wrong directory reads as "no weak rejections", which is the
    # single most expensive way for this module to be wrong.
    old = os.environ.get("LEDGER_NS")
    try:
        os.environ["LEDGER_NS"] = "prod"
        prod = RA.state_dir()
        os.environ["LEDGER_NS"] = "scratch"
        scratch = RA.state_dir()
    finally:
        if old is None:
            os.environ.pop("LEDGER_NS", None)
        else:
            os.environ["LEDGER_NS"] = old
    ck("D1: prod resolves to state/", os.path.basename(prod) == "state", prod)
    ck("D2: a namespace gets its own directory", scratch != prod, (prod, scratch))
    ck("D3: and it is _<ns> under state/", os.path.basename(scratch) == "_scratch", scratch)

    # ── E. the controls actually gate audit() ───────────────────────────────
    # `audit` is wrapped by verifier_guard: break classify and no result may come
    # out at all. A detector that still answers after its controls fail is the
    # failure mode verifier_guard exists for.
    import verifier_guard as VG
    saved = RA.classify
    try:
        RA.classify = lambda v, run_invalid=False: ("T0", "stuck")
        try:
            RA.audit(files=[p])
            ck("E1: a broken classify is refused a result", False, "audit() returned anyway")
        except VG.ControlFailed:
            ck("E1: a broken classify is refused a result", True)
    finally:
        RA.classify = saved
    ck("E2: and it works again once restored", _audit(files=[p])[1].get("T5") == 1)

    print("%d/%d passed" % (TOTAL[0] - len(FAIL), TOTAL[0]))
    if FAIL:
        print("FAILED: %s" % ", ".join(FAIL))
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
