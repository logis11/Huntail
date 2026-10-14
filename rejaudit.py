#!/usr/bin/env python3
# rejaudit.py — **re-audit the rejections.**
#
# Rejecting fast is CTF discipline. On a 0-day hunt one rejection is a decision
# to lose one bug permanently, and with nothing forcing a second look it sets.
# So every rejection in the ledger gets re-audited, exhaustively.
#
# The grounds are not guesswork — they are **what the ledger already recorded.**
# R3/R4 let a rejection through even when verification failed, but they were
# built to leave that fact in `cfg.verdict`:
#   "CFG dominance undecidable (%s) — recording as an unverified rejection.
#    **This is not a confirmed negative for coverage purposes.**"
#   "R4 currently only guarantees that a rejection is documented, not that it is
#    correct."
# The weak rejections were already marked. **Nobody was counting them.**
#
# Tiers (worst first, first match wins):
#   T5  adversary-broken  an independent interrogator **broke** this rejection.
#                         However good the form is, it is not a negative
#   T4  invalid run       the run itself was INVALID — that is absent data, not a
#                         negative
#   T3  broken tool       decompiler_artifact / basis=decompile — a verdict
#                         reached while the tool was dead
#   T1  unverified guard  klass=guarded but cfg.verdict is not in {gated,
#                         gated_inter}
#   T2  absence unverified  no_sink / unreachable — the class R4 admits it cannot
#                         vouch for
#   T2b no gate           no klass (pre-R2) / by_design — no dedicated gate exists
#   T0  confirmed negative  none of the above and the anchors are clean
#
# Ported notes:
#   · The verdict status string is matched literally (`"rejected"`) because that
#     is what the ledger writes. If the two ever drift apart this module matches
#     **nothing** and reports every rejection as a confirmed negative — the exact
#     failure it exists to prevent — so `test_rejaudit.py` reads the literal out
#     of `ledger.py` rather than hard-coding it twice.
#   · The state directory now follows the ledger's `LEDGER_NS` namespace.
#     Upstream read a flat `state/`, so a run under a non-prod namespace was
#     audited as zero files. Identical behaviour under the default namespace.
import collections
import json
import os
import sys

import verifier_guard as VG

OK_CFG = {"gated", "gated_inter"}


def state_dir():
    """Mirror the ledger's namespace resolution. Auditing the wrong directory
    reads as 'no weak rejections', so it must not be guessed."""
    ns = os.environ.get("LEDGER_NS", "prod")
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "state")
    if ns != "prod":
        d = os.path.join(d, "_" + ns)
    return d


STATE = state_dir()

TIER_WHY = {
    "T5": "an independent interrogator broke this rejection — what an adversary "
          "refuted is not a negative",
    "T4": "the run was INVALID — a run that did not happen is not a negative",
    "T3": "the verdict was reached with a broken tool (dead disassembler bridge / "
          "basis=decompile)",
    "T1": "R3 never confirmed it on the CFG — the ledger itself says this is not a "
          "confirmed negative",
    "T2": "R4 does not vouch for the correctness of an absence-shaped rejection (an "
          "xref over every executable section is documentation, nothing more)",
    "T2b": "no gate in R1..R6 adjudicates this klass",
    "T0": "a gate actually verified it",
}


def classify(v, run_invalid=False):
    """One rejection record -> (tier, why). A pure function, so it can be
    controlled."""
    g = v.get("gate") or {}
    klass = g.get("klass")
    basis = v.get("basis") or "?"
    cfg = g.get("cfg") if isinstance(g.get("cfg"), dict) else {}
    cv = cfg.get("verdict")
    an = g.get("anchors") or {}
    if run_invalid:
        return "T4", TIER_WHY["T4"]
    # **The form-based tier was not looking at the interrogation result.**
    #   Measured: of 43 rejections the interrogator had broken, 29 were graded T0
    #   (confirmed negative) here, and so sat in the **highest-confidence
    #   negative** column in both `verified_negatives()` and the re-audit queue.
    #   This function only ever read `gate` and `basis`; `interrogation` was never
    #   read at all.
    #   A tier measures the **shape** of a rejection. An adversary breaks its
    #   **content.** Content wins.
    ig = v.get("interrogation")
    if isinstance(ig, dict) and ig.get("broke"):
        return "T5", "%s (break klass=%s)" % (TIER_WHY["T5"], ig.get("klass") or "-")
    if klass == "decompiler_artifact" or basis == "decompile":
        return "T3", "%s (klass=%s, basis=%s)" % (TIER_WHY["T3"], klass, basis)
    if klass == "guarded" and cv not in OK_CFG:
        return "T1", "%s — cfg.verdict=%s" % (TIER_WHY["T1"], cv)
    if klass in ("no_sink", "unreachable"):
        return "T2", TIER_WHY["T2"]
    if klass in (None, "", "?", "by_design"):
        return "T2b", "%s (klass=%s)" % (TIER_WHY["T2b"], klass)
    if (an.get("failed") or 0) > 0:
        return "T2b", "%d anchor(s) failed machine verification" % an["failed"]
    return "T0", TIER_WHY["T0"]


# ── Positive / negative controls — no result until they pass ─────────────────
def _rec(klass=None, cv=None, basis="disassemble", failed=0, broke=None):
    r = {"basis": basis, "gate": {"klass": klass, "anchors": {"failed": failed}}}
    if cv is not None:
        r["gate"]["cfg"] = {"verdict": cv}
    if broke is not None:
        r["interrogation"] = {"broke": bool(broke), "klass": "other_constructor"}
    return r


_CONTROLS = {
    # Positive — a weak rejection **must** be caught
    "dominates_only is T1":       ("T1",  _rec("guarded", "dominates_only")),
    "no_branch is T1":            ("T1",  _rec("guarded", "no_branch")),
    "missing klass is T2b":       ("T2b", _rec(None)),
    "by_design is T2b":           ("T2b", _rec("by_design")),
    "no_sink is T2":              ("T2",  _rec("no_sink")),
    "decompiler_artifact is T3":  ("T3",  _rec("decompiler_artifact")),
    "basis=decompile is T3":      ("T3",  _rec("guarded", "gated", basis="decompile")),
    "anchor failure is T2b":      ("T2b", _rec("not_controlled", failed=2)),
    # Negative — a genuinely verified rejection **must not** be resurrected.
    # If this side collapses, the audit resurrects everything.
    "gated is T0":                ("T0",  _rec("guarded", "gated")),
    "gated_inter is T0":          ("T0",  _rec("guarded", "gated_inter")),
    "a measured rejection is T0": ("T0",  _rec("delta_zero", basis="measured")),
    # Interrogation axis — however **perfect** the form, a broken rejection is
    # not a negative (positive control)
    "broke beats any form -> T5": ("T5",  _rec("guarded", "gated", broke=True)),
    "broke beats measured -> T5": ("T5",  _rec("delta_zero", basis="measured", broke=True)),
    # Negative control — an interrogation that **did not** break anything must not
    # move the tier. If this collapses, the audit resurrects everything.
    "sustained stays T0":         ("T0",  _rec("guarded", "gated", broke=False)),
}


@VG.guarded("rejaudit", {k: want for k, (want, _r) in _CONTROLS.items()},
            probe=lambda k: classify(_CONTROLS[k][1])[0])
def audit(files=None, invalid_runs=()):
    files = files or sorted(f for f in os.listdir(STATE) if f.endswith(".json")) \
        if os.path.isdir(STATE) else []
    rows, per = [], collections.Counter()
    for f in files:
        p = f if os.path.sep in f else os.path.join(STATE, f)
        if not os.path.exists(p):
            continue
        drv = os.path.basename(p)[:-5]
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:
            continue
        inv = drv in invalid_runs
        for v in d.get("verdicts") or []:
            if (v.get("status") or "") != "rejected":
                continue
            t, why = classify(v, run_invalid=inv)
            per[t] += 1
            rows.append({"driver": drv, "id": v.get("id"), "target": v.get("target"),
                         "tier": t, "why": why,
                         "klass": (v.get("gate") or {}).get("klass"),
                         "basis": v.get("basis"),
                         "cfg": ((v.get("gate") or {}).get("cfg") or {}).get("verdict")
                                if isinstance((v.get("gate") or {}).get("cfg"), dict) else None,
                         "claim": (v.get("claim") or "")[:400]})
    order = {"T5": 0, "T4": 1, "T3": 2, "T1": 3, "T2": 4, "T2b": 5, "T0": 6}
    rows.sort(key=lambda r: (order[r["tier"]], r["driver"], r["id"] or ""))
    return rows, per


# ── Re-grading T0: policy drift ─────────────────────────────────────────────
#   R3's authority **narrows** over time (the bug-injection bench took back bound
#   constants and signed comparisons, and double fetch was taken back later). Old
#   verdicts became T0 under **the looser rules of their day.** So T0 does not
#   mean "verified", it means "verified **under the rules in force then**".
#
#   Most of them cannot be replayed, though — early ledgers **did not store the
#   guard/sink pair.** Approximating it from `cfg.branch_va` / `sink_block` makes
#   taint look at the wrong operand and produces a flood of fake
#   `dominates_only` (measured: 39 of 64). So approximations do not adjudicate.
def regrade(binpath_of, files=None):
    """Re-run only the T0 rows that have a persisted pair, under today's rules.
    Rows without one are counted as `no_pair`."""
    import cfg as CFG
    import pe as PEmod
    files = files or (sorted(f for f in os.listdir(STATE) if f.endswith(".json"))
                      if os.path.isdir(STATE) else [])
    out = {"regraded": [], "no_pair": [], "no_binary": [], "guard_only": []}
    for f in files:
        drv = f[:-5]
        d = json.load(open(os.path.join(STATE, f), encoding="utf-8"))
        for v in d.get("verdicts") or []:
            if (v.get("status") or "") != "rejected":
                continue
            g = v.get("gate") or {}
            c = g.get("cfg") if isinstance(g.get("cfg"), dict) else {}
            if c.get("verdict") not in ("gated", "gated_inter"):
                continue
            gu, sk = g.get("guard"), g.get("sink")
            if gu is None or sk is None:
                # Even with no pair, the authority classes that look **only at the
                #   guard** adjudicate exactly: `signed_compare` / `bound_compare`
                #   use nothing but the last cmp/jcc of the guard block, and the
                #   stored `branch_va` is exact. Double fetch needs the sink, so it
                #   cannot be replayed.
                bva = c.get("branch_va")
                bp2 = binpath_of(drv)
                verdict = None
                if bva and bp2:
                    try:
                        _p = PEmod.PE(bp2)
                        _fs, _fe = _p.func_bounds(bva)
                        if _fs is not None:
                            # NOTE (upstream behaviour, preserved): `_fe` lands in
                            # `build`'s `max_span` parameter, which disables the span
                            # cap on this path. Kept as-is so replayed verdicts match
                            # the recorded ones; do not "fix" it without re-grading
                            # every stored T0.
                            _g = CFG.build(_p, _fs, _fe)
                            _gb = CFG.block_of(_g, bva) if hasattr(CFG, "block_of") else None
                            if _gb is None:
                                for _a, _ins in _g["blocks"].items():
                                    if _ins and _ins[0].address <= bva <= _ins[-1].address:
                                        _gb = _a
                                        break
                            if _gb is not None:
                                verdict = CFG._reject_authority(_p, _g, _gb, bva, bva)
                    except Exception:
                        verdict = None
                if verdict:
                    out["guard_only"].append((drv, v.get("id"), verdict[0], verdict[1][:150]))
                else:
                    out["no_pair"].append((drv, v.get("id")))
                continue
            bp = binpath_of(drv)
            if not bp:
                out["no_binary"].append((drv, v.get("id")))
                continue
            try:
                r = CFG.gates(PEmod.PE(bp), int(gu), int(sk))
            except Exception as e:
                out["no_binary"].append((drv, "%s (%s)" % (v.get("id"), e)))
                continue
            if r.get("verdict") not in ("gated", "gated_inter"):
                out["regraded"].append((drv, v.get("id"), r.get("verdict"),
                                        r.get("class"), (r.get("why") or "")[:160]))
    return out


if __name__ == "__main__":
    inv = set(a for a in sys.argv[1:] if not a.startswith("-"))
    rows, per = audit(invalid_runs=inv)
    tot = len(rows)
    print("re-auditing %d rejection(s) in %s\n" % (tot, STATE))
    for t in ("T5", "T4", "T3", "T1", "T2", "T2b", "T0"):
        if per[t]:
            print("  %-4s %4d  %s" % (t, per[t], TIER_WHY[t]))
    live = [r for r in rows if r["tier"] != "T0"]
    print("\nOnly %d are confirmed negatives. The other %d are **not negatives, they are "
          "unanalysed.**" % (per["T0"], len(live)))
    byd = collections.Counter(r["driver"] for r in live)
    print("\nResurrection queue (by target):")
    for k, c in byd.most_common():
        print("   %-18s %d" % (k, c))

    def _bp(drv):
        for c in (os.path.join("work", "night", drv, drv),
                  os.path.join("targets", "samples", drv)):
            if os.path.exists(c):
                return c
        return None

    rg = regrade(_bp)
    print("\nT0 re-grade (replayed under today's R3 rules):")
    print("   no stored pair -> authority lost on the guard alone   %d" % len(rg["guard_only"]))
    for x in rg["guard_only"][:8]:
        print("      [%s] %-42s %s" % (x[0], (x[1] or "")[:42], x[2]))
    print("   no stored pair, undecidable from the guard            %d" % len(rg["no_pair"]))
    print("   binary unavailable                                   %d" % len(rg["no_binary"]))
    print("   replayed and **lost authority**                      %d" % len(rg["regraded"]))
    for x in rg["regraded"][:8]:
        print("      [%s] %s -> %s(%s)" % x[:4])
    outdir = os.path.join(os.path.dirname(STATE), "targets")
    os.makedirs(outdir, exist_ok=True)
    out = os.path.join(outdir, "resurrect-queue.json")
    json.dump(live, open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print("\n-> %s (%d rows)" % (out, len(live)))
