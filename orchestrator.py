#!/usr/bin/env python3
# orchestrator.py — many independent trajectories, then consensus.
#
# The single-run entry point (`agent_sdk.py <binary>`) produces one trajectory.
# The result borrowed from Naptime is that MANY independent trajectories beat one
# long run — pass@20 far exceeds pass@1 — because the failures are uncorrelated:
# a claim that only one trajectory reaches is a lead, but a claim that several
# INDEPENDENT trajectories reach on their own is a finding. This module runs N
# trajectories against one target and scores the agreement.
#
# Three things make the runs genuinely independent, and each is a scar:
#
#   1. ISOLATED LEDGERS. `agent_sdk` persists to state/<key>.json, and FRESH=1
#      wipes that ledger at start. If every run shared one ledger, run i+1 would
#      either wipe run i's confirmations or inherit them — and "inherited" is not
#      "independently reached". Worse, a shared ledger once leaked one target's
#      rows into another's file. So each run gets its own LEDGER_NS, which lands
#      its ledger in state/_<ns>/, untouched by every other run and by prod.
#
#   2. NO SHARED GOAL. A goal left in the parent environment silently applies to
#      a run that was never given one, so the gate checks a goal the seed never
#      set. Each child starts with OPERATOR_GOAL* stripped.
#
#   3. AN INVALID RUN IS NOT A NEGATIVE. A run the API refused (quota/auth) or the
#      transport dropped produced no analysis; scoring its "0 confirmations" as a
#      real negative is the most expensive lie in the pipeline. `deadrun` decides
#      validity, and only VALID runs enter the consensus denominator. This is why
#      the denominator below is K (valid runs), never N (runs attempted).
#
# Consensus is UNDEFINED for K < 2 — you cannot consense a single trajectory. With
# K >= 2, a finding reached by a majority of valid runs is consensus-confirmed; a
# finding reached by exactly one is a lead, reported as such, never dropped.
#
# The pure functions (classify_run / confirmed_from_ledger / finding_key /
# consensus / render) carry the logic and need no API to test. run_batch only
# spawns the children and writes artifacts as each finishes, so a crash mid-batch
# keeps every completed run.
import glob
import json
import os
import re
import subprocess
import sys
import time

import deadrun

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIRMED = "confirmed"            # the ledger's confirmed status (see ledger.STATUS)


# ── validity ─────────────────────────────────────────────────────────────────
def classify_run(log_text):
    """'valid' | 'dead' | 'trans' — mirrors the runner's asymmetry.

    dead  = the API refused the run (quota/auth/billing); the whole batch should
            rest, because further runs hit the same closed door.
    trans = the transport dropped mid-stream; that one slot can be retried.
    Order matters: `dead` is checked first because a refused run can also carry a
    stray 5xx, and resting is the safer response than retrying into a dead quota.
    """
    if deadrun.dead(log_text):
        return "dead"
    if deadrun.trans(log_text):
        return "trans"
    return "valid"


# ── reading a run's ledger ───────────────────────────────────────────────────
def ledger_path_for(ns):
    """The single ledger file a run wrote, given its LEDGER_NS. One target per
    run, so the namespace dir holds exactly one *.json — glob it rather than
    re-derive the key(target) filename, which is ledger-private."""
    d = os.path.join(HERE, "state", "_" + ns)
    hits = sorted(glob.glob(os.path.join(d, "*.json")))
    return hits[0] if hits else None


def confirmed_from_ledger(path):
    """The confirmed verdicts in one ledger file, or [] if none/unreadable."""
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return []
    return [v for v in (d.get("verdicts") or [])
            if isinstance(v, dict) and v.get("status") == CONFIRMED]


_ADDR = re.compile(r"0x[0-9a-fA-F]+")


def finding_key(v):
    """A stable identity for a confirmed finding across independent runs.

    The per-run `id` (V1, V2, ...) auto-increments and is NOT comparable between
    runs. Verified anchor addresses ARE stable across runs of the same build, so
    they key first; otherwise the normalized target/claim string does. Two runs
    that confirm the same defect must land on the same key or consensus cannot see
    the agreement."""
    addrs = sorted(set(_ADDR.findall(json.dumps(v.get("anchors") or "", ensure_ascii=False))))
    if addrs:
        return "anchor:" + ",".join(a.lower() for a in addrs)
    t = (v.get("target") or v.get("claim") or "").strip().lower()
    return "target:" + re.sub(r"\s+", " ", t)


# ── consensus ────────────────────────────────────────────────────────────────
def consensus(runs):
    """Score agreement across runs.

    `runs` is a list of dicts: {"status": "valid|dead|trans", "confirmed": [v...]}
    (confirmed is only read for valid runs). Returns a summary dict; each finding
    carries its support k out of K valid runs and a tier:
        confirmed = reached by a majority of valid runs
        lead      = reached by at least one but below majority
    With K < 2 every finding is a lead — consensus is undefined for one run."""
    valid = [r for r in runs if r.get("status") == "valid"]
    K = len(valid)
    dead = sum(1 for r in runs if r.get("status") == "dead")
    trans = sum(1 for r in runs if r.get("status") == "trans")

    tally = {}   # key -> {support, klass, target, claim, anchors}
    for r in valid:
        seen = set()
        for v in r.get("confirmed") or []:
            k = finding_key(v)
            if k in seen:
                continue          # one run counts once toward a finding's support
            seen.add(k)
            e = tally.setdefault(k, {"support": 0, "klass": v.get("klass") or "",
                                     "target": v.get("target") or "",
                                     "claim": v.get("claim") or "",
                                     "anchors": v.get("anchors")})
            e["support"] += 1

    majority = (K // 2) + 1 if K >= 2 else K + 1   # K<2 -> nothing reaches majority
    findings = []
    for k, e in tally.items():
        e = dict(e, key=k,
                 tier=("confirmed" if K >= 2 and e["support"] >= majority else "lead"))
        findings.append(e)
    findings.sort(key=lambda e: (-e["support"], e["target"]))

    return {"attempted": len(runs), "valid": K, "dead": dead, "trans": trans,
            "majority": majority if K >= 2 else None, "findings": findings}


# ── rendering ────────────────────────────────────────────────────────────────
def render(summary, tag=""):
    L = []
    L.append("# consensus%s" % ((" — " + tag) if tag else ""))
    L.append("")
    s = summary
    L.append("runs attempted: %d · **valid: %d** · dead(API-refused): %d · trans(dropped): %d"
             % (s["attempted"], s["valid"], s["dead"], s["trans"]))
    L.append("")
    L.append("_Invalid runs are not negatives; the consensus denominator is the %d valid run(s)._"
             % s["valid"])
    L.append("")
    if s["valid"] < 2:
        L.append("⚠ **Consensus is undefined for fewer than 2 valid runs.** "
                 "Every finding below is a single-trajectory lead, not a consensus finding.")
        L.append("")
    else:
        L.append("Majority threshold: **%d / %d**." % (s["majority"], s["valid"]))
        L.append("")
    if not s["findings"]:
        L.append("_No confirmations in any valid run._")
        return "\n".join(L)
    L.append("| support | tier | klass | target |")
    L.append("|--------:|------|-------|--------|")
    for f in s["findings"]:
        L.append("| %d/%d | %s | %s | %s |"
                 % (f["support"], s["valid"], f["tier"], f["klass"] or "—",
                    (f["target"] or f["claim"] or "?").replace("|", "\\|")[:90]))
    return "\n".join(L)


# ── the batch ────────────────────────────────────────────────────────────────
def _child_env(ns, tag, run_idx):
    env = dict(os.environ)
    # Subscription, not metered API billing (matches agent_sdk's own guard).
    env.pop("ANTHROPIC_API_KEY", None)
    # A goal only reaches a run that was explicitly given one.
    for k in ("OPERATOR_GOAL", "OPERATOR_GOAL_KIND", "OPERATOR_GOAL_BY"):
        env.pop(k, None)
    env["FRESH"] = "1"                       # each trajectory starts clean
    env["LEDGER_NS"] = ns                    # ... in its own isolated ledger dir
    env["RUN_TAG"] = "consensus:%s:r%d" % (tag, run_idx)
    env["WORK_DIR"] = os.path.join(HERE, "work", "consensus", tag, "r%d" % run_idx)
    os.makedirs(env["WORK_DIR"], exist_ok=True)
    return env


def _one_run(binary, corpus, ns, tag, run_idx, log_path, timeout):
    """Spawn one trajectory, capture its log, return (status, log_text)."""
    cmd = [sys.executable, os.path.join(HERE, "agent_sdk.py"), binary]
    if corpus:
        cmd.append(corpus)
    env = _child_env(ns, tag, run_idx)
    try:
        p = subprocess.run(cmd, env=env, cwd=HERE, timeout=timeout,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = p.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"").decode("utf-8", "replace") + "\n[orchestrator] TIMEOUT\n"
    try:
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(out)
    except OSError:
        pass
    return classify_run(out), out


def run_batch(binary, corpus=None, n=5, tag=None, timeout=2400, max_attempts=None,
              out_dir=None, log=print):
    """Run up to N valid trajectories against one target, then consense.

    Artifacts are written as each run finishes, so a crash keeps completed runs.
    On a `dead` run the batch STOPS — the API quota is closed and further runs
    would only reproduce it. A `trans` run is retried within the attempt budget."""
    tag = tag or time.strftime("%Y%m%d-%H%M%S")
    max_attempts = max_attempts or (n + 3)     # a few retries for transient drops
    out_dir = out_dir or os.path.join(HERE, "reports", "consensus", tag)
    os.makedirs(out_dir, exist_ok=True)
    summary_path = os.path.join(out_dir, "SUMMARY.md")

    runs, attempt, valid = [], 0, 0
    while valid < n and attempt < max_attempts:
        attempt += 1
        ns = "consensus-%s-a%d" % (tag, attempt)
        log_path = os.path.join(out_dir, "a%d.log" % attempt)
        log("[orchestrator] attempt %d (valid %d/%d) → %s" % (attempt, valid, n, ns))
        status, _ = _one_run(binary, corpus, ns, tag, attempt, log_path, timeout)
        rec = {"status": status, "ns": ns, "attempt": attempt, "confirmed": []}
        if status == "valid":
            rec["confirmed"] = confirmed_from_ledger(ledger_path_for(ns))
            valid += 1
            log("  valid — %d confirmation(s)" % len(rec["confirmed"]))
        else:
            log("  %s — not a result; not counted as a negative" % status)
        runs.append(rec)
        # Write the running summary after every run.
        try:
            with open(summary_path, "w", encoding="utf-8") as f:
                f.write(render(consensus(runs), tag))
        except OSError:
            pass
        if status == "dead":
            log("[orchestrator] API refused the run — resting the batch (quota closed).")
            break

    log("[orchestrator] done: %d valid of %d attempts → %s" % (valid, attempt, summary_path))
    return consensus(runs)


def main(argv):
    if len(argv) < 2:
        print("usage: python3 orchestrator.py <binary> [corpus.c]\n"
              "  env: RUNS (default 5) · CASE_TIMEOUT (default 2400) · CONSENSUS_TAG",
              file=sys.stderr)
        return 2
    binary = argv[1]
    corpus = argv[2] if len(argv) > 2 else None
    n = int(os.environ.get("RUNS", "5"))
    timeout = int(os.environ.get("CASE_TIMEOUT", "2400"))
    tag = os.environ.get("CONSENSUS_TAG") or None
    s = run_batch(binary, corpus, n=n, tag=tag, timeout=timeout)
    print(render(s, tag or ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
