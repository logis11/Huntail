# runlog.py — one metrics line per run. It does not touch how a run executes.
#
# `work/` stays a single directory as before (`rm -rf work/*` to clear it). What
# this adds is one metrics line appended to `runs.jsonl` when a run finishes, so
# the regression bench can tabulate it.
import json, os, re, time
import config

_JSONL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "runs.jsonl")
STATE = {"t0": None, "meta": {}, "transcript": None}


def _transcript_path(target=None):
    """Per-target reasoning transcript. This used to be **one**
    `work/transcript.log`.

    The moment two targets ran in parallel, both agents truncated and appended to
    the same file and **the reasoning transcripts interleaved.** The ledger and
    stdout are per-process, so the result data survived — but "why was it judged
    that way" was unusable for that whole round.
    Same reason the locks were split per target: a shared resource gets keyed by
    target.
    """
    if target:
        key = re.sub(r'[^A-Za-z0-9._-]', '_', os.path.basename(str(target)))[:50]
        return os.path.join(config.WORK_DIR, "transcript.%s.log" % key)
    return STATE.get("transcript") or os.path.join(config.WORK_DIR, "transcript.log")


# ── reasoning-transcript archive ────────────────────────────────────────
# Why: `work/transcript.<target>.log` is **truncated every round** ("this run
#   only"). What it holds is not the verdicts but **"why it was judged that
#   way"**, and that exists nowhere in the ledger. Measured losses:
#     · the grounds for 213 interrogator breaks went only here and were wiped
#       every round
#     · a single surviving line carried a new lead with it
#   There were preserved copies under `reports/logs/`, but **a human had been
#   copying them by hand.** This is the primary material for the layer that reads
#   across rounds and targets, so it gets automated.
#
# It goes to a file rather than the ledger: the between-round reader only loads
# `state/*.json`, so this costs it nothing.
ARCHIVE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "reports", "transcripts")


def _archive(path, target=""):
    """Append the previous round to the per-target cumulative file. A failure
    here never blocks the run."""
    try:
        if not (path and os.path.exists(path) and os.path.getsize(path) > 0):
            return None
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        key = re.sub(r'[^A-Za-z0-9._-]', '_', os.path.basename(str(target or "unknown")))[:50]
        dst = os.path.join(ARCHIVE_DIR, key + ".log")
        with open(path, encoding="utf-8", errors="replace") as f:
            body = f.read()
        with open(dst, "a", encoding="utf-8") as f:
            f.write("\n\n===== ROUND ARCHIVED %s · %s (%d bytes) =====\n"
                    % (time.strftime("%Y-%m-%d %H:%M"), key, len(body)))
            f.write(body)
        return dst
    except OSError:
        return None


_RUN = {}


def note_usage(u):
    """Accumulate `AssistantMessage.usage` while streaming.

    Why: cost and tokens only arrive on `ResultMessage`, but a case timeout is
    **SIGKILL**, so `finish()` never runs. Measured over 20 cases: the 5 that
    succeeded recorded $6-12 each and **all 15 timeouts recorded $0.00** — while
    each of those 15 really ran for 45 minutes of wall clock. `runs.jsonl` summed
    to $46.77 against an actual estimate of ~$180. **Zero and unmeasured were
    sharing a column.**
    => tokens are accumulated for real on every assistant message, and dollars
      are **not invented** (`total_cost_usd=None` plus `cost_unknown=True`, which
      is distinguishable from 0).
    """
    if not isinstance(u, dict):
        return
    acc = _RUN.setdefault("usage_acc", {})
    for k in ("input_tokens", "output_tokens",
              "cache_read_input_tokens", "cache_creation_input_tokens"):
        v = u.get(k)
        if isinstance(v, int):
            acc[k] = acc.get(k, 0) + v
    acc["messages"] = acc.get("messages", 0) + 1


def mark_baseline(triage_state):
    """Take the **per-round baseline** of the ledger's cumulative counters.

    This used to capture `denials0` **only**, so `rejected` (= len(graveyard)),
      `interrog_run` and `refute_killed` **sat in the per-round column as
      cumulative values**:
        interrog_run  165 -> 168 -> 184 -> 192 -> 202 -> 204  (the round was 2-3)
        refute_killed   8 ->   8 ->   9 ->   9 ->  10 ->  10  (the round was 0-1)
        rejected      = len(graveyard), cumulative
      A downstream scorer knew about it and was subtracting **on the reading
      side** — the fix went to the reader instead of the recorder, so the next
      reader steps on it again. The baseline is widened here and the `*_delta`
      columns are emitted separately.
    """
    _RUN["denials0"] = len(triage_state.get("denials") or [])
    _RUN["graveyard0"] = len(triage_state.get("graveyard") or [])
    _RUN["verdicts0"] = len(triage_state.get("verdicts") or [])
    _ig = triage_state.get("interrogs") or {}
    _rf = triage_state.get("refutes") or {}
    _RUN["interrog_run0"] = int(_ig.get("run") or 0)
    _RUN["interrog_broke0"] = int(_ig.get("broke") or 0)
    _RUN["interrog_sustained0"] = int(_ig.get("sustained") or 0)
    _RUN["refute_killed0"] = int(_rf.get("killed") or 0)
    _RUN["refute_survived0"] = int(_rf.get("survived") or 0)
    # **The debt baseline is taken here.** The first version read `ledger._RUN`,
    #   which is captured at `ledger.attach()` time while the metrics are computed
    #   in the orchestrating process. That process attaches after reading the final
    #   state, so its baseline IS the end state and the delta column fills with the
    #   **running total**. Measured: a round reported `debt_ask_dn=15`, exactly
    #   equal to the ledger's **total** of 15 answered — that round answered zero.
    #   (The same accident as the cumulative-counter-in-a-delta-column one, redone
    #   in a new column.)
    _A = triage_state.get("asks") or []
    _RUN["asks_open0"] = sum(1 for a in _A if (a.get("status") or "open") == "open")
    _RUN["asks_answered0"] = sum(1 for a in _A if a.get("status") == "answered")
    _RUN["blocked0"] = sum(1 for v in (triage_state.get("surface") or {}).values()
                           if isinstance(v, dict)
                           and str(v.get("why") or "").lstrip().upper().startswith("BLOCKED"))
    try:
        import ledger as _L0
        _RUN["leads_open0"] = len(_L0.open_leads(triage_state.get("target")))
    except Exception:
        _RUN["leads_open0"] = None
    return _RUN["denials0"]


def _deltas(triage_state, m):
    """Emit a **per-round** column next to each cumulative one. With no baseline
    the value is `None`, not 0 — zero and unmeasured do not share a column."""
    _ig = triage_state.get("interrogs") or {}
    _rf = triage_state.get("refutes") or {}
    src = {"rejected_delta": (len(triage_state.get("graveyard") or []), "graveyard0"),
           "verdicts_delta": (len(triage_state.get("verdicts") or []), "verdicts0"),
           "interrog_run_delta": (int(_ig.get("run") or 0), "interrog_run0"),
           "interrog_broke_delta": (int(_ig.get("broke") or 0), "interrog_broke0"),
           "interrog_sustained_delta": (int(_ig.get("sustained") or 0), "interrog_sustained0"),
           "refute_killed_delta": (int(_rf.get("killed") or 0), "refute_killed0"),
           "refute_survived_delta": (int(_rf.get("survived") or 0), "refute_survived0")}
    for k, (cur, base) in src.items():
        b = _RUN.get(base)
        m[k] = (cur - int(b)) if b is not None else None
    # **Put debt flow on the dashboard.** Measuring the effect of a WIP cap needs
    #   "opened minus closed" recorded every round. `debt_blocked_up` in particular
    #   is the third ablation metric: if the cap is on and that column grows, the
    #   work leaked into `blocked`, which is not a failed experiment but a
    #   **configuration mistake** — the cap was never extended to cover blocked.
    #   If a value cannot be derived it is None, not 0.
    # Only the baseline this module took at the start of the round is used
    #   (`_RUN[...0]`). `ledger._RUN` belongs to another process at another time,
    #   so deltas leak into running totals (see the baseline note above).
    #   With no baseline the value is **None, not 0**.
    try:
        import ledger as _L
        _A2 = triage_state.get("asks") or []
        _open_now = sum(1 for a in _A2 if (a.get("status") or "open") == "open")
        _ans_now = sum(1 for a in _A2 if a.get("status") == "answered")
        _blk_now = sum(1 for v in (triage_state.get("surface") or {}).values()
                       if isinstance(v, dict)
                       and str(v.get("why") or "").lstrip().upper().startswith("BLOCKED"))
        _leads_now = len(_L.open_leads(triage_state.get("target")))
        m["leads_open"] = _leads_now
        _b = _RUN.get("leads_open0")
        m["debt_lead_delta"] = (_leads_now - int(_b)) if _b is not None else None
        _b = _RUN.get("asks_answered0")
        m["debt_ask_dn"] = (_ans_now - int(_b)) if _b is not None else None
        _b = _RUN.get("asks_open0")
        m["debt_ask_up"] = (_open_now - int(_b)) if _b is not None else None
        _b = _RUN.get("blocked0")
        m["debt_blocked_up"] = (_blk_now - int(_b)) if _b is not None else None
        _parts = [m.get("debt_lead_delta"), m.get("debt_ask_up"), m.get("debt_blocked_up")]
        m["debt_net"] = (sum(_parts) if all(x is not None for x in _parts) else None)
    except Exception:
        for _k in ("lead_delta", "ask_up", "ask_dn", "blocked_up", "net"):
            m.setdefault("debt_" + _k, None)
    return m


def start(target, tag=""):
    STATE["t0"] = time.time()
    STATE["meta"] = {
        "run_id": time.strftime("%m-%d %H:%M"),
        "challenge": os.path.basename(os.path.dirname(os.path.abspath(target))),
        "tag": tag, "model": config.MODEL, "max_turns": config.MAX_TURNS,
        "tools": {}, "gate_denials": 0,
    }
    STATE["transcript"] = _transcript_path(target)
    _archive(STATE["transcript"], target)                     # preserve before clearing
    open(STATE["transcript"], "w").close()                    # this run only
    # Compatibility: for a single run, clear the old path too (tools and docs
    # still reference that name).
    try:
        open(os.path.join(config.WORK_DIR, "transcript.log"), "w").close()
    except OSError:
        pass


def bump(key, n=1):
    STATE["meta"][key] = STATE["meta"].get(key, 0) + n


def tool(name):
    t = STATE["meta"].setdefault("tools", {})
    t[name] = t.get(name, 0) + 1


def transcript(line):
    try:
        with open(_transcript_path(), "a") as f:
            f.write(line.rstrip() + "\n")
    except OSError:
        pass


def snapshot(triage_state, key=""):
    """An in-flight metrics snapshot. **A case timeout is SIGKILL, so the child
    never gets to finish** — one overnight round was cut that way, left no line in
    `runs.jsonl` at all, and without even `gate_denials` there was no way to
    diagnose "where did five completed analyses go". The parent picks this file up
    on the timeout path and records it."""
    try:
        m = dict(STATE.get("meta") or {})
        if not m:
            return None
        m["wall_seconds"] = round(time.time() - (STATE["t0"] or time.time()), 1)
        m["subtype"] = "partial"
        surf = triage_state.get("surface", {}) or {}
        m["surface_total"] = len(surf)
        m["confirmed"] = sum(1 for v in (triage_state.get("verdicts") or [])
                             if v.get("status") == "confirmed")
        m["rejected"] = len(triage_state.get("graveyard") or [])
        # Report the surface in **three columns**. Folding it into one percentage
        #   makes it a lie: measured coverage() 2.1% against settled() 90.2% on the
        #   same table — a factor of 45.
        m["surface_judged"] = sum(1 for v in surf.values() if v.get("status") != "unanalysed")
        m["surface_blocked"] = sum(1 for v in surf.values()
                                   if v.get("blocked")
                                   or str(v.get("why", "")).startswith("BLOCKED"))
        m["surface_untouched"] = max(0, len(surf) - m["surface_judged"] - m["surface_blocked"])
        m["verdicts_total"] = len(triage_state.get("verdicts") or [])
        try:
            import ledger as _L
            m["surface_sites"], _sr, m["surface_dup_rows"], _st = _L.surface_sites(triage_state)
        except Exception:
            pass
        # Put the **denial distribution** in the partial snapshot too. A timeout is
        #   SIGKILL, `finish()` never runs, and the whole round summary is lost.
        #   The denials themselves survive in the ledger, but "how many belong to
        #   this round" is known only to this process, which holds the baseline. It
        #   is salvaged here.
        _dn = triage_state.get("denials") or []
        _mine = _dn[int(_RUN.get("denials0") or 0):]
        _agg = {}
        for _d in _mine:
            _k = _d.get("rule") or "(no reason)"
            _agg[_k] = _agg.get(_k, 0) + 1
        m["denials_this_run"] = len(_mine)
        _deltas(triage_state, m)
        # A partial snapshot never sees `ResultMessage` — it does not record $0.
        _acc = _RUN.get("usage_acc") or {}
        if _acc:
            m["tokens"] = dict(_acc)
        m["total_cost_usd"] = None
        m["cost_unknown"] = True
        m["denial_rules"] = sorted(_agg.items(), key=lambda x: -x[1])[:12]
        p = os.path.join(config.WORK_DIR, "partial.%s.json" %
                         (re.sub(r'[^A-Za-z0-9._-]', '_', str(key or m.get("challenge") or "x"))[:40]))
        with open(p, "w", encoding="utf-8") as f:
            json.dump(m, f, ensure_ascii=False)
        return p
    except Exception:
        return None


def finish(result_msg, flag, triage_state):
    m = STATE["meta"]
    if not m:
        return {}
    m["wall_seconds"] = round(time.time() - (STATE["t0"] or time.time()), 1)
    m["flag"], m["solved"] = flag, bool(flag)
    for k in ("num_turns", "total_cost_usd", "session_id", "subtype", "is_error"):
        v = getattr(result_msg, k, None)
        if v is not None:
            m[k] = v
    u = getattr(result_msg, "usage", None)
    if isinstance(u, dict):
        m["tokens"] = {k: u[k] for k in ("input_tokens", "output_tokens",
                                         "cache_read_input_tokens") if u.get(k)}
    surf = triage_state.get("surface", {})
    done = sum(1 for v in surf.values() if v["status"] in ("confirmed", "rejected"))
    m["surface_total"] = len(surf)
    m["surface_done"] = done
    m["coverage"] = round(done / len(surf), 3) if surf else 0.0
    m["confirmed"] = sum(1 for v in triage_state.get("verdicts", []) if v["status"] == "confirmed")
    m["rejected"] = len(triage_state.get("graveyard", []))
    m["unaudited"] = len(surf) - done
    # The same three columns as the partial. `coverage` is kept, but never left
    # to be read on its own.
    m["surface_judged"] = sum(1 for v in surf.values() if v.get("status") != "unanalysed")
    m["surface_blocked"] = sum(1 for v in surf.values()
                               if v.get("blocked") or str(v.get("why", "")).startswith("BLOCKED"))
    m["surface_untouched"] = max(0, len(surf) - m["surface_judged"] - m["surface_blocked"])
    m["verdicts_total"] = len(triage_state.get("verdicts") or [])
    try:
        import ledger as _L
        m["surface_sites"], _sr, m["surface_dup_rows"], _st = _L.surface_sites(triage_state)
    except Exception:
        pass
    m["blocked"] = sum(1 for v in surf.values()
                       if str(v.get("why", "")).startswith("BLOCKED"))
    rf = triage_state.get("refutes", {})
    m["refute_killed"], m["refute_survived"] = rf.get("killed", 0), rf.get("survived", 0)
    ig = triage_state.get("interrogs", {}) or {}
    m["interrog_run"] = ig.get("run", 0)
    m["interrog_broke"] = ig.get("broke", 0)
    m["interrog_sustained"] = ig.get("sustained", 0)
    _deltas(triage_state, m)
    m["interrog_failed"] = ig.get("failed", 0)
    m["interrog_skipped"] = ig.get("skipped", 0)
    # A verified negative is a rejection that was interrogated and survived. A
    # rejection that was never interrogated does not count here.
    m["rejects_interrogated"] = sum(1 for v in triage_state.get("verdicts", [])
                                    if v.get("status") == "rejected" and v.get("interrogated"))
    m["refute_failed"] = rf.get("failed", 0)
    m["anchored_confirms"] = sum(1 for v in triage_state.get("verdicts", [])
                                 if v["status"] == "confirmed" and v.get("anchors"))
    m["hedges"] = triage_state.get("hedges", 0)
    m["controls"] = {k: len(v) for k, v in triage_state.get("controls", {}).items()}
    # The **per-reason distribution** of gate denials. When this was a single
    #   counter, the content of 692 denials existed nowhere. Now each round shows
    #   which rule caught what.
    _dn = triage_state.get("denials") or []
    _base = int(_RUN.get("denials0") or 0)
    _mine = _dn[_base:] if len(_dn) >= _base else _dn
    _agg = {}
    for _d in _mine:
        _k = _d.get("rule") or "(no reason)"
        _agg[_k] = _agg.get(_k, 0) + 1
    m["denials_this_run"] = len(_mine)
    m["denial_rules"] = sorted(_agg.items(), key=lambda x: -x[1])[:12]
    m["harness_tool_calls"] = sum(v for k, v in m["tools"].items() if k.startswith("mcp__vuln__"))
    m["total_tool_calls"] = sum(m["tools"].values())
    try:
        with open(_JSONL, "a") as f:
            f.write(json.dumps(m, ensure_ascii=False) + "\n")
    except OSError:
        pass
    return m


def summary(m):
    if not m:
        return ""
    dead = (m.get("harness_tool_calls", 0) == 0)
    top = ", ".join(f"{k.replace('mcp__vuln__', 'v:')}×{v}"
                    for k, v in sorted(m.get("tools", {}).items(), key=lambda x: -x[1])[:6])
    sid = m.get("session_id")
    return "\n".join([
        "",
        "══ RUN SUMMARY ═══════════════════════════════════════════",
        f"  verdicts   : confirmed {m.get('confirmed',0)} · rejected {m.get('rejected',0)} · "
        f"unanalysed {m.get('unaudited',0)}"
        + (f" ({m['blocked']} of them BLOCKED — with a reason)" if m.get('blocked') else "")
        + f"  ({m.get('subtype','?')})",
        f"  grounds    : anchor-verified confirmations {m.get('anchored_confirms',0)}/{m.get('confirmed',0)}"
        + (f" · refuter killed {m.get('refute_killed',0)} / survived {m.get('refute_survived',0)}"
           + (f" / failed to run {m['refute_failed']}" if m.get('refute_failed') else "")
           if (m.get('refute_killed') or m.get('refute_survived') or m.get('refute_failed'))
           else " · THE REFUTER DID NOT RUN"),
        (f"  rejections : {m.get('interrog_run',0)} interrogated — "
         f"broke {m.get('interrog_broke',0)} / sustained {m.get('interrog_sustained',0)}"
         + (f" / failed to run {m['interrog_failed']}" if m.get('interrog_failed') else "")
         + (f" / not sampled {m['interrog_skipped']}" if m.get('interrog_skipped') else "")
         + f"  => verified negatives {m.get('rejects_interrogated',0)}/{m.get('rejected',0)}"
         if m.get('interrog_run') or m.get('interrog_skipped')
         else f"  rejections : \033[91mTHE INTERROGATOR DID NOT RUN — all "
              f"{m.get('rejected',0)} rejection(s) are unverified negatives\033[0m"),
        f"  coverage   : {m.get('surface_done',0)}/{m.get('surface_total',0)} "
        f"({(m.get('coverage',0) or 0)*100:.0f}%)"
        + ("   WARNING: do not drop the unanalysed rows from the table"
           if m.get('unaudited') else ""),
        f"  turns/tools: {m.get('num_turns','?')} turns · {m.get('total_tool_calls',0)} calls "
        f"({m.get('harness_tool_calls',0)} to harness tools)",
        f"  time/cost  : {m.get('wall_seconds','?')}s · ${m.get('total_cost_usd', 0) or 0:.4f}",
        f"  quality    : controls {m.get('controls',{}) or 'none'} · "
        f"{m.get('hedges',0)} hedge(s) · {m.get('gate_denials',0)} gate block(s)",
        (("  gate denials: %d — " % m.get("denials_this_run", 0))
         + " · ".join("%d×%s" % (n, k[:44]) for k, n in (m.get("denial_rules") or [])[:4])
         if m.get("denials_this_run") else
         "  gate denials: 0 (nothing was stopped — either the gates idled or the "
         "wiring is broken)"),
        f"  tool mix   : {top}",
        f"  resume     : RESUME={sid} python agent_sdk.py <target>" if sid else "",
        ("\n  \033[91mX zero harness tool calls — the target was never touched. "
         "'Zero confirmations' from this run is not a result, it is a **malfunction**. "
         "(Check limits, credentials and the network first.)\033[0m" if dead else ""),
        "══════════════════════════════════════════════════════════",
    ])
