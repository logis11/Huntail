# ledger.py — the verdict ledger + coverage + persistence.
#
# What changed (with the grounds):
#  1) **It lives on disk.** The old ledger was process memory — even when a session was resumed with
#     RESUME, the ledger started from zero and the coverage became false. Findings vanishing when the
#     context is compacted in a long session is a really reported failure (Slyp answered it with
#     pre-compaction checkpointing, and there is a measurement showing accuracy dropping 13.9-85% on
#     long tasks from context length alone). The ledger is kept outside the context.
#  2) **The candidate lifecycle** — proposed → refuted / promoted. A refuted claim stays with its
#     reason (klass) and keeps showing up in the status block. This project really did resurrect a
#     dead candidate (A-12) twice.
#  3) **Scenario de-duplication** — by (function, hypothesis) pair. Source targets use ±20 lines; here it is ±0x40 VA.
#  4) **Anchor records** — every confirmation stores its machine-verified citations alongside. A report can use them as-is.
import atexit, hashlib, json, os, re, sys, tempfile, time, uuid

import config

STATE = {
    "target": "", "guid": "", "started": "",
    "surface":   {},   # name -> {status, kind, why}
    "verdicts":  [],   # confirmed/rejected records
    "candidates": [],  # {id,target,claim,state,klass,reason,anchors}
    "disasm":    set(),
    "controls":  {},
    "graveyard": [],
    "hedges":    0,
    "refutes":   {"run": 0, "killed": 0, "survived": 0, "failed": 0},
    # Pressure on the rejection side. broke = how many rejections collapsed and went back to ASK.
    "interrogs": {"run": 0, "broke": 0, "sustained": 0, "failed": 0, "skipped": 0},
}

STATUS = ("unanalysed", "auditing", "confirmed", "rejected", "refuted", "boundary-held")
# boundary-held = **the defect stands, but the boundary is out of scope** (currently admin→kernel).
#   It is not a confirmation (it cannot be graded). Nor is it a rejection (the defect in the code is real).
#   ★ The remaining question has narrowed to exactly one: **"is there a lower privilege that reaches this sink?"**
#   So this row goes to the escalator. It does not go to the graveyard.
# ★ Putting disassemble and measured both at 3 **puts a static-reading clean in the same slot as a measured clean.**
# The three refutations from the afd.sys session (every one a disassemble verdict overturned or voided by measured):
#   · TDI transport-name validation: "level 2 = rejects unregistered" -> measured, even names that do not exist all returned SUCCESS
#   · the free-then-no-NULL scanner: 86 candidates -> measured sample 9/9 false positives
#   · AfdGetConnectData: static clean -> measured, all 8 cases returned early; it never ran once
BASIS_RANK = {"decompile": 1, "doc": 2, "disassemble": 3, "measured": 4}

# ★ 2026-09-07 — **`basis` was a free string, so the vocabulary collapsed and the gate was bypassed.**
#   Measured (the whole ledger): the basis of ahcache's 157 rejections was `disassemble` 83 · `disassembly` 30 ·
#   `static` 22 · `disasm` 3 — **four names for the same thing**. 50 bases were longer than 30 chars,
#   the longest **3,116 chars** (the full argument had been put in the basis slot).
#   So `BASIS_RANK` mostly fell to 0, and above all
#   `GATE_CONTROL_BEFORE_REJECT` only fired on an **exact match** `basis == "measured"`, so
#   a measured rejection starting with `"measured on the live kernel, not inferred…"`
#   **skipped the positive-control check entirely** (the very gate the verifier_guard incident created).
#   => canonicalise by the **leading token**. The prose is not thrown away; it moves to `basis_note`.
#     ("disassembly of the measured build" leads with the disassemble family, so it is static —
#      had this been a substring match, these 5 would have been falsely treated as measured.)
_BASIS_ALIAS = {
    "measured": "measured", "measure": "measured", "measurement": "measured",
    "live": "measured", "kd": "measured", "ioctl": "measured", "runtime": "measured",
    "disassemble": "disassemble", "disassembly": "disassemble", "disasm": "disassemble",
    "disassembled": "disassemble", "static": "disassemble", "bytes": "disassemble",
    "decompile": "decompile", "decompiler": "decompile", "decompiled": "decompile",
    "hexrays": "decompile", "hex-rays": "decompile",
    "doc": "doc", "docs": "doc", "documentation": "doc", "msdn": "doc",
}


def normalize_basis(b):
    """Fold the **leading token** of `basis` into the canonical vocabulary. Returns: (canonical or None, the original).

    None means an unregistered word — the caller denies it. Once folded, `BASIS_RANK` works again.
    """
    raw = str(b or "").strip()
    if not raw:
        return None, raw
    tok = re.split(r'[^A-Za-z-]+', raw.lower(), 1)[0]
    return _BASIS_ALIAS.get(tok), raw
_PATH = [None]

# The handoff box that carries what the PreToolUse gate computed over to the verdict tool.
# Modifying tool_input in a hook does not reach the tool (measured).
PENDING = {"anchors": None, "refute": None, "key": None}
# ★ One slot that carries what backed `basis=measured` all the way to the verdict record.
#   `classify` (graded) and `trace` (executed, ungraded) carry different evidential weight, and consumers must tell them apart.
_pending_meas = [None]


def stage(target, claim, anchors, refute=None):
    PENDING.update({"anchors": anchors, "refute": refute,
                    "key": (str(target), (claim or "")[:120])})


def _take(target, claim):
    if PENDING["key"] == (str(target), (claim or "")[:120]):
        a, r = PENDING["anchors"], PENDING["refute"]
        PENDING.update({"anchors": None, "refute": None, "key": None})
        return a or [], r
    return [], None


# ── persistence ────────────────────────────────────────────────────
def _key(target):
    return re.sub(r'[^A-Za-z0-9._-]', '_', os.path.basename(target or "corpus"))[:60]


# ★ The test/prod boundary. A bench run mixed into the production ledger and polluted `pcw.sys` (2026-08-24).
#   Ending it with a deletion lets the same accident happen again — stamp the provenance into the ledger and split the namespace.
PROVENANCE = os.environ.get("LEDGER_NS", "prod")     # prod | bench | scratch


def _ns_dir():
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "state")
    if PROVENANCE != "prod":
        d = os.path.join(d, "_" + PROVENANCE)
    os.makedirs(d, exist_ok=True)
    return d


# The default skeleton to restore when the target changes. `attach` needs it to **empty** and then fill.
_SKELETON = {k: (v.copy() if hasattr(v, "copy") else v) for k, v in STATE.items()}


# A round-(process-)scoped counter — not saved in the ledger. Every round starts from 0.
_RUN = {"adds": 0, "verdicts0": 0}

# Registration budget: 12 by default + **8 per verdict** filed this round.
#   "If you want to register more, adjudicate first." It does not block completeness, it enforces **order.**
SURFACE_BASE = int(os.environ.get("SURFACE_BASE", "12"))
SURFACE_PER_VERDICT = int(os.environ.get("SURFACE_PER_VERDICT", "8"))


def surface_budget():
    """(registrations left, budget, verdicts this round)."""
    made = max(0, len(STATE.get("verdicts") or []) - int(_RUN.get("verdicts0") or 0))
    cap = SURFACE_BASE + SURFACE_PER_VERDICT * made
    return cap - int(_RUN.get("adds") or 0), cap, made


# ── ledger key lock ────────────────────────────────────────────────
# ★ Why: when two processes open the same target, `save()` wipes verdicts wholesale with
#   last-writer-wins. No trace in the log — exactly the shape this repository has lost again and again.
#   `nightrun.acquire_lock()` does the same job, but **it existed only there.** Calling `agent_sdk.py`
#   directly, or a script attaching, was unprotected. What the lock guards is the ledger, so it lives
#   **next to the ledger**, not at an entry point — the same rule applies whichever path comes in.
#   (Several terminals on non-overlapping targets still work. A different key means a different lock.)
_LOCK = {"path": None}
_LOCK_HOOKED = [False]


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                      # alive, but someone else's
    except OSError:
        return False
    return True


def _lock_release():
    p = _LOCK.get("path")
    if not p:
        return
    try:
        if open(p).read().strip() == str(os.getpid()):
            os.unlink(p)
    except OSError:
        pass
    _LOCK["path"] = None


def detach():
    """Let go of the ledger. Releases the lock and disarms `save()` (back to the not-attached exception)."""
    _lock_release()
    _PATH[0] = ""


def _lock_acquire(path):
    if os.environ.get("LEDGER_NOLOCK", "") in ("1", "true", "yes"):
        return
    lp = os.path.join(os.path.dirname(path), "." + os.path.basename(path) + ".lock")
    if _LOCK.get("path") == lp:
        return                           # the same process re-attaching to the same ledger
    _lock_release()                      # switching targets — release the previous lock
    if os.path.exists(lp):
        try:
            old = int(open(lp).read().strip())
        except (ValueError, OSError):
            old = None
        if old is not None and old != os.getpid() and _pid_alive(old):
            raise RuntimeError(
                "this ledger is already being written by another process: %s (pid %d).\n"
                "  Opening the same target in two places makes save() overwrite each other and verdicts vanish silently.\n"
                "  · parallel runs on different targets are not blocked — launch on a different target\n"
                "  · if that process looks dead:  kill %d ; rm %s\n"
                "  · if you only mean to read:  LEDGER_NOLOCK=1 (do not write)"
                % (os.path.basename(path), old, old, lp))
        if old is not None and old != os.getpid():
            sys.stderr.write("\033[93m[ledger] removing a stale lock (dead pid %s)\033[0m\n" % old)
    try:
        with open(lp, "w") as f:
            f.write(str(os.getpid()))
    except OSError as e:
        sys.stderr.write("\033[93m[ledger] could not create the lock file: %s\033[0m\n" % e)
        return
    _LOCK["path"] = lp
    if not _LOCK_HOOKED[0]:
        atexit.register(_lock_release)
        _LOCK_HOOKED[0] = True


def attach(target, guid=""):
    d = _ns_dir()
    _p = os.path.join(d, _key(target) + ".json")
    # ★ Take the lock **before touching STATE.** If it fails, the ledger held right now is untouched.
    _lock_acquire(_p)
    _PATH[0] = _p
    # ★ 2026-09-02 bug: this used to do only `STATE.update(d)`. That **leaves the previous target's keys behind** —
    #   attaching two targets in one process leaked ahcache's `tracks` straight into the wcifs ledger
    #   and saved them (a track-reset script exposed it). Mixing ledgers is silent pollution, and
    #   it ruins verdict lineage at the root. Every attach **empties** and then fills.
    STATE.clear()
    STATE.update({k: (v.copy() if hasattr(v, "copy") else v) for k, v in _SKELETON.items()})
    if os.path.exists(_PATH[0]) and os.environ.get("FRESH", "") not in ("1", "true"):
        try:
            with open(_PATH[0], encoding="utf-8") as f:
                d = json.load(f)
            d["disasm"] = set(d.get("disasm", []))
            STATE.update(d)
            loaded = True
        except Exception:
            loaded = False
    else:
        loaded = False
    STATE["target"], STATE["guid"] = target or "", guid or STATE.get("guid", "")
    # ★ 2026-09-08 — **the backfill that adds `kind`/`by` to old questions runs at attach time.**
    #   Both are derived from slots that already exist (derived fields, idempotent). Fixing only new rows
    #   leaves the old 356 rows without a ranking axis forever — and then the single queue cannot be sorted.
    if loaded:
        try:
            backfill_ask_fields()
        except Exception:
            pass                     # a backfill failure must not block the attach itself
        # ★ 2026-09-08 self-correction — **materialise** the resisted questions **into the ledger.**
        #   `resisted_to_asks` used to be called only from the seed render (a file copy, save_now=False), so
        #   the XQ questions **were in the SEED and not in the ledger**. An analyst could not find an id seen
        #   in the seed with `verdict(action='asks')` (in the 09-08 run the leads took the whole top so it
        #   simply was not hit — a latent defect).
        #   ★ It is idempotent: the id comes deterministically from the target, and regeneration bumps
        #     `attempts` only when resistance really grew. Otherwise the second ranking axis becomes "how many times it ran".
        try:
            resisted_to_asks(STATE.get("target"))
        except Exception:
            pass
    # ★ The baseline for the round budget. Registering surfaces is cheap and verdicts are expensive — left alone, only the denominator grows.
    #   Measured (2026-09-02, 3 hours): surface +69 / verdicts +4, blocked 476/518 (92%).
    #   ahcache R3 spent 25 of its 108 tool calls on registration.
    _RUN["adds"] = 0
    _RUN["verdicts0"] = len(STATE.get("verdicts") or [])
    # ★ The baseline for the handoff gate. Counting inherited handles as this round's kills the gate —
    #   measured: the cumulative ledger's 450 BLOCKED rows covered almost every anchor, so armA simply passed.
    _RUN["asks0"] = {str(a.get("id")) for a in (STATE.get("asks") or [])}
    _RUN["surface0"] = set(STATE.get("surface") or {})
    # ★ 2026-09-07 — **the baseline for the debt cap (WIP cap).** It measures **flow**, not stock.
    #   Capping on stock locks from the first turn because of the cumulative 546 blocked · 160 open ASKs.
    #   Capping on flow looks only at "what this round opened − what it closed", so exactly things like
    #   09-06's net +90 / 09-07's +34 become impossible.
    try:
        _RUN["leads0"] = {str(x.get("id")) for x in open_leads(STATE.get("target"))}
    except Exception:
        _RUN["leads0"] = set()
    _RUN["blocked0"] = _blocked_rows()
    STATE["provenance"] = PROVENANCE
    if PROVENANCE != "prod":
        STATE.setdefault("_warn", "This ledger is in the %s namespace. Do NOT use its verdicts as "
                                  "evidence."
                         % PROVENANCE)
    STATE.setdefault("started", time.strftime("%Y-%m-%d %H:%M"))
    status_reset("attach")       # the target changed, so a delta cannot be trusted — the next block is in full
    save()
    return loaded


def save():
    if not _PATH[0]:
        raise RuntimeError(
            "ledger.save(): attach() was never called. This record was about to be discarded "
            "silently. Call ledger.attach(target) first.")
    # ★ Atomic write. `open(path,"w")` used to **truncate the file to 0 bytes first** and write over it.
    #   Dying mid-write, or two processes overlapping, left **truncated JSON**, and the next `attach()`
    #   swallowed it with `except Exception: loaded=False` and restarted the ledger from zero.
    #   Verdicts could vanish wholesale with no trace in the log. Writing to tmp and swapping it in with
    #   `os.replace` removes that window — same directory means same filesystem, and replace is atomic.
    d = dict(STATE)
    d["disasm"] = sorted(STATE["disasm"])
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(_PATH[0]) or ".",
                                   prefix=".ledger-", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, _PATH[0])
        tmp = None
    except OSError as e:
        # ★ Not passed over silently. A save failure is lost verdicts, and the old `except OSError: pass`
        #   made it indistinguishable from a normal exit.
        sys.stderr.write("\033[91m[ledger] save failed — this round's records are not on disk: "
                         "%s (%s)\033[0m\n" % (e, _PATH[0]))
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


# ── 1) the census table ────────────────────────────────────────────────
# ★ Reachability is **a property of the row.** It used to not be, so the denominator was heterogeneous:
#   in the WUDFRd round, **20 PnP/power handlers** of `RdFdoDevice` were filed as `kind="ingress"` and
#   became part of a 114-entry attack surface. An unprivileged process cannot send `IRP_MJ_PNP`.
#   The agent honestly wrote *"neither reachable nor unreachable"*, but
#   **there was no field** to hold that sentence, so `kind` stayed `ingress`.
#
# ★★ And `kernel-only` must not simply be discarded — the killer in the SCPVBUS-01 UAF was
#    **the PnP thread.** When the user provokes a re-enumeration through an IOCTL, PnP fires REMOVE asynchronously.
#    So it is **4-valued**, not 3-valued: the middle slot is **the pool of race counterparties.**
REACH = ("user-direct",            # directly, via DeviceIoControl and the like
         "user-triggerable-async",  # indirectly provoked by a user request (PnP · completion · cancel · DPC · work item · timer)
         "kernel-only",             # genuinely unrelated to the user
         "unknown")                 # ★ the default. Do not write down as known what is not known.
# ★ The set minus unknown. It is the criterion `reach_unknown()` uses to pick "rows not yet decided".
REACH_KNOWN = tuple(x for x in REACH if x != "unknown")


_CODE_RE = re.compile(r'0x8[0-9a-fA-F]{7}')


def _ctl_code(name):
    """Pull the control code out of a surface row's name. None if there is none."""
    m = _CODE_RE.search(name or "")
    return m.group(0).lower() if m else None


def code_index():
    """Control code -> the registered names. For detecting duplicate registrations."""
    idx = {}
    for k in (STATE.get("surface") or {}):
        c = _ctl_code(k)
        if c:
            idx.setdefault(c, []).append(k)
    return idx


# ── the anchor reverse index ──────────────────────────────────────────────────
# ★ 2026-09-03. A direct answer to the most expensive loss in this project.
#   "What is this feature gate's default?" came back up across **five rounds.**
#   All along the answer sat as prose inside `verdicts[].evidence` — a sentence the analyst wrote
#   themselves said that descriptor address "evaluates to ENABLED".
#   The ledger sees verdicts only **row by row**, and the grounds are free text, so nobody queried them.
#
#   And all six stores (verdicts/asks/graveyard/gate_blocks/candidates/surface) use
#   **expression-based keys**: a name string · a SHA1 of the claim's bag of words · an exact target match · no key.
#   Reword a sentence and it slips through; one differing prefix makes it a different scenario.
#   => the only thing that does not change when the wording changes is **the anchor (VA).** It becomes a first-class key.
# ★ Requiring the `0x` prefix **misses the very answer.** The grounds of the confirmed row in question
#   were written **without 0x**, as in "descriptor VAs 14000f818, 14000f540, 14000f690".
#   Free text cannot enforce a notation, so both are caught and **normalised.**
#   A bare hex number is only taken in kernel-VA shape (9 digits starting with 1, i.e. 0x1_0000_0000~0x1_FFFF_FFFF) —
#   long tokens like a build GUID do not match in fragments, because of the word boundaries.
_ANCHOR_RE = re.compile(r'0x([0-9a-fA-F]{6,16})\b|\b(1[0-9a-fA-F]{8})\b')


def _vas(text):
    """The notation-normalised anchor set. 0x14003625d · 14003625D · 0x014003625d count as the same thing."""
    out = set()
    for m in _ANCHOR_RE.finditer(str(text or "")):
        h = (m.group(1) or m.group(2)).lower().lstrip("0") or "0"
        out.add(h)
    return out


def anchor_index():
    """VA -> [(store, id, one line)] . Rebuilt every time (the ledger is small, and a stale index is more dangerous)."""
    idx = {}

    def add(blob, store, ident, brief):
        for va in _vas(blob):
            idx.setdefault(va, []).append((store, str(ident or "-"), str(brief)[:74]))

    for v in STATE.get("verdicts") or []:
        add(" ".join(str(v.get(k) or "") for k in ("claim", "evidence", "reason")),
            v.get("status") or "verdict", v.get("id"), v.get("target"))
    for a in STATE.get("asks") or []:
        n = len(a.get("attempts") or [])
        add(" ".join(str(a.get(k) or "") for k in ("claim", "why", "guard", "sink", "method")),
            "question%s" % ("·%dx" % n if n else ""), a.get("id"), a.get("target"))
    for g in STATE.get("graveyard") or []:
        add(" ".join(str(g.get(k) or "") for k in ("claim", "reason")),
            "graveyard[%s]" % (g.get("klass") or "-"), g.get("id"), g.get("target"))
    for b in STATE.get("gate_blocks") or []:
        add(" ".join(str(b.get(k) or "") for k in ("why", "would_be", "evidence", "gate")),
            "no-slot", b.get("gate"), b.get("target"))
    for c in STATE.get("candidates") or []:
        add(" ".join(str(c.get(k) or "") for k in ("claim", "reason")),
            "candidate[%s]" % (c.get("state") or "-"), c.get("id"), c.get("target"))
    for k, r in (STATE.get("surface") or {}).items():
        add("%s %s" % (k, r.get("why") or ""), "surface[%s]" % (r.get("status") or "-"), "", k)
    for n, t in (STATE.get("tracks") or {}).items():
        add(t.get("note") or "", "track·stage%s" % t.get("stage"), n, n)
    for m in (STATE.get("measures") or []):
        add(json.dumps(m, ensure_ascii=False), "measured", m.get("id") if isinstance(m, dict) else "", "")
    return idx


def anchor_hits(text, exclude_id=None, limit=10):
    """Where in the ledger are this text's anchors already. An empty string if nowhere."""
    want = _vas(text)
    if not want:
        return ""
    idx = anchor_index()
    grouped = {}
    for va in want:
        for store, ident, brief in idx.get(va, []):
            if exclude_id and ident == str(exclude_id):
                continue
            grouped.setdefault((store, ident, brief), set()).add(va)
    if not grouped:
        return ""
    # Risk is highest for a verdict whose grounds already exist → a question → the graveyard, in that order
    def rank(k):
        st = k[0]
        return (0 if st.startswith(("confirmed", "rejected")) else
                1 if st.startswith("question") else
                2 if st.startswith("graveyard") else 3, -len(grouped[k]))
    # A per-kind cap so one store does not eat the whole screen (surfaces have many duplicate registrations).
    per, rows = {}, []
    for k in sorted(grouped, key=rank):
        st = k[0].split("[")[0]
        per[st] = per.get(st, 0) + 1
        if per[st] > 3:
            continue
        rows.append(k)
        if len(rows) >= limit:
            break
    L = ["", "─" * 66,
         "THIS ANCHOR IS ALREADY IN THE LEDGER. Read it before re-deriving anything -",
         "   Re-deriving the same fact in different words has burned five sessions of "
         "this project.",
         "─" * 66]
    for (store, ident, brief) in rows:
        vs = ", ".join(sorted(grouped[(store, ident, brief)])[:4])
        L.append("   [%-14s %-16s] %s" % (store, ident[:16], vs))
        if brief:
            L.append("        %s" % brief)
    more = len(grouped) - len(rows)
    if more > 0:
        L.append("   … and %d more" % more)
    L.append("   => To read the full basis, open that row with note(action='read') or status().")
    L.append("─" * 66)
    return "\n".join(L)


def surface_add(items, kind="ingress", reach="unknown"):
    # ★ 2026-09-03: registration had no cap. The seed demands completeness (do not drop unanalysed rows),
    #   registration is cheap, and every registered row demands a verdict => only the denominator grows and
    #   coverage falsely worsens. It does not block, it enforces **order**: filing verdicts grows the registration budget.
    left, cap, made = surface_budget()
    if left <= 0:
        return ("YOU HAVE SPENT THIS SESSION'S REGISTRATION BUDGET (%d/%d, %d verdicts this "
                "session).\nSurfaces are cheap and verdicts are expensive - the table is %d rows "
                "and %d of them are blocked.\nEACH VERDICT YOU FILE OPENS %d MORE REGISTRATIONS. "
                "Use worklist() and close the highest-scoring rows first.\nIf something really "
                "must be registered now, put it in note() and add it next session - written down "
                "is not lost." % (_RUN.get("adds"), cap, made, len(STATE.get("surface") or {}),
                   sum(1 for r in (STATE.get("surface") or {}).values() if r.get("blocked")),
                   SURFACE_PER_VERDICT))
    _asked = len(list(items))
    items = list(items)[:left]
    _clipped = _asked - len(items)
    n = 0
    dup = []
    idx = code_index()
    for it in items:
        name = it if isinstance(it, str) else it.get("name", "")
        if not name or name in STATE["surface"]:
            continue
        # ★ Re-registering the same control code **under a different prefix** inflates the denominator
        #   and adjudicates the same code twice. It really happened in the WUDFRd 08-31 night run:
        #   20 USB codes were double-registered as `USB.*` / `CTRL.IRP.*`, 21 of the 115 surfaces were duplicates,
        #   and 4 of 22 rejections were re-adjudications of the same code.
        c = _ctl_code(name)
        if c and idx.get(c):
            dup.append((name, idx[c][0]))
            continue
        r = reach if isinstance(it, str) else (it.get("reach") or reach)
        if r not in REACH:
            return f"reach is one of {REACH}. If you do not know, 'unknown' — do not write a guess."
        # ★ 2026-09-05: `entry` was **only read, never written** — 0 of 1144 rows, measured.
        #   So `code_coverage()` always fell back to the `Dispatch|Callback|Unload` name heuristic, and
        #   the reachable set started not from the real ingress but from functions with plausible names.
        #   Yet **381 rows already carry `@0xVA` in their name.**
        #   (The agent pointed out exactly this in a gate report — the report was right.)
        #   => use the address embedded in the name as-is. No guessing: if there is none, nothing is set.
        _rec = {"status": "unanalysed", "kind": kind, "reach": r,
                "why": "" if isinstance(it, str) else it.get("why", "")}
        _ent = None if isinstance(it, str) else it.get("entry")
        if not _ent:
            # ★ 2026-09-07 — **requiring `@` splits arming by target.**
            #   Measured: wcifs follows the `WcProcessGetUnions@0x140020d48` convention so 354/583 rows have an entry,
            #   while ahcache follows `IOCTL f6 -> 0x140038850` and had **0/620**.
            #   This slot seeds `code_coverage()`, so ahcache kept running on the name-heuristic
            #   fallback. The trigger **must not depend on the agent's naming convention.**
            #   => `@` is optional. Without it, the **first address** in the name is used (a citation, not a guess).
            _me = (re.search(r'@\s*(0x[0-9a-fA-F]{6,16})', name)
                   or re.search(r'(0x[0-9a-fA-F]{6,16})', name))
            if _me:
                _ent = _me.group(1)
        if _ent:
            try:
                _rec["entry"] = int(str(_ent), 16) if isinstance(_ent, str) else int(_ent)
            except (TypeError, ValueError):
                pass
        STATE["surface"][name] = _rec
        n += 1
    _RUN["adds"] = int(_RUN.get("adds") or 0) + n
    save()
    if dup:
        return ("DUPLICATE REGISTRATION BLOCKED - the same control code is already in the table "
                "under a different name:\n"
                + "\n".join("  · %s (already registered as %s)" % d for d in dup[:10])
                + (f"\n  … and {len(dup)-10} more" if len(dup) > 10 else "")
                + "\nKeeping the same code under two names INFLATES THE DENOMINATOR AND "
                  "ADJUDICATES THE SAME CODE TWICE. Adjudicate under the existing name, or - if "
                  "it really is a different surface - put the distinguishing axis (handler / "
                  "transfer method) in the name, not the code.")
    #   ★ Keep kind / reach in the return — the model must be able to check what it was registered as.
    #     And when the budget let **only part** of it in, that is not passed over silently.
    _clip = (" Registered only %d of the %d requested (registration budget)." %
             (n, _asked)) if _clipped else ""
    return ("Registered %d items (kind=%s, reach=%s).%s Total table: %d items. Nothing ever "
            "disappears from this table - if you cannot analyse it, file "
            "verdict(action='blocked').\n"
            "reach='unknown' MAKES THE DENOMINATOR FALSE. Settle reachability, or update it "
            "with surface(action='reach', name=..., reach=...)."
            % (n, kind, reach, _clip, len(STATE["surface"])))


def count_via(bucket, v):
    """Count **which medium** an adversary verdict arrived through: tool submission / text fallback / fault.

    ★ 2026-09-03. Attaching the submission tool without counting this **leaves its effect unknowable.** This
      repository has already lost tools that were built and never wired several times (measure · sink_gates · claimaudit).
      If `via_text` keeps rising, the model is not calling the tool, and then what needs fixing is
      **the tool description**, not the prompt.
    """
    if not isinstance(v, dict):
        return
    st = STATE.setdefault(bucket, {})
    key = "via_fault" if v.get("fault") else ("via_%s" % (v.get("via") or "text"))
    st[key] = st.get(key, 0) + 1
    save()


def measure_vas(text):
    """Pull **the addresses a measurement touched** out of a string. Both absolute VAs and `<mod>+0xOFF`.

    ★ Why it is needed (measured 2026-09-08): `measured()` was an **exact string match**
      `m["target"] == target`. target is free prose (the problem of 11 rows hanging off one site), so
      a measurement `ioctl` recorded under `device` (`\\.\ahcache`) could never meet a verdict's target
      (`0x14004188c K2 call site in AhcQuirksInit …`).
      The same disease that was fixed on 09-06 by moving `mark_interrogated` from the target string to `vid=` was left here.
    ★ `<mod>+0xOFF` is folded into an absolute VA **by adding the ImageBase** only when it is this ledger's target module.
      Other modules like `nt!…` are not folded — folding without knowing the base produces fake matches.
    """
    t = str(text or "")
    out = {int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{6,16})', t)}
    try:
        _mod = os.path.basename(str(STATE.get("target") or "")).lower()
        _mod = re.sub(r'\.(sys|exe|dll)$', '', _mod)
        if _mod:
            _p = _img()
            _base = getattr(_p, "base", None) if _p is not None else None
            if _base:
                for off in re.findall(r'\b%s\s*\+\s*0x([0-9a-fA-F]{1,8})\b'
                                      % re.escape(_mod), t, re.I):
                    out.add(_base + int(off, 16))
    except Exception:
        pass
    return out


# ─── principal canonicalisation (2026-09-10) ────────────────────────────────────────────
#   ★ This was a spot where the wiring was cut. `probe.py` puts `principal={user,il_sid,elevated}`
#     in its result, and `vmprobe.assert_low_principal()` **really reads** the token and throws if it is
#     not non-elevated (type-D grounding). But `measure_record()` had no such argument, so
#     that fact was discarded at the ledger boundary — all 212 measurements had no principal field.
#   => the next session, reading only the ledger, **cannot tell "it did not work at low privilege" from
#     "it was never re-measured at low privilege".** That distinction is the whole of a privilege-boundary claim.
#   Related: memory `vm-guest-channel-runs-elevated` (the vmrun token is High+Administrators),
#         `controls-assume-a-context` (the principal field is now the only thing that separates elevation),
#         `built-but-never-wired` · `prose-cannot-carry-a-predicate`.
PRINCIPAL_SRC = ("probe", "kd", "declared", "unknown")
# Integrity SIDs accepted as non-elevated (Low / Medium). The same set as vmprobe._IL_OK.
_IL_LOW = ("S-1-16-4096", "S-1-16-8192")


def normalize_principal(p, req=None, src=None):
    """Fold whatever comes in into a canonical dict carrying **only what was observed.**

    Returned keys:
      src      probe | kd | declared | unknown  — where this fact came from
      req      low | default | None             — what was requested (probe only)
      il_sid / elevated / user                  — **observed values.** None if unknown (do not fill with 0/False)
      verified only when True can one claim "this measurement came from this principal"

    ★ `verified` is the reason this function exists. The rest are reference values; consumers look at this one slot only.
      `src='declared'` (transcribed by the agent) is **never verified** — it is type B.
    """
    out = {"src": "unknown", "req": (req or None), "il_sid": None,
           "elevated": None, "user": None, "verified": False}
    if isinstance(p, dict):
        # The principal field of a probe result. If err is set the credentials could not be read = unverified.
        out["src"] = src or "probe"
        if not p.get("err"):
            out["il_sid"] = str(p.get("il_sid") or "") or None
            out["user"] = str(p.get("user") or "") or None
            if p.get("elevated") is not None:
                out["elevated"] = bool(p.get("elevated"))
            out["verified"] = bool(out["il_sid"])
    elif isinstance(p, str) and p.strip():
        tok = p.strip().lower()
        out["src"] = tok if tok in PRINCIPAL_SRC else (src or "declared")
        if out["src"] == "declared":
            out["user"] = p.strip()[:120]
        # kd is a kernel debugger, not a user token. It is an observation, but it cannot be used for a principal claim.
    elif src:
        out["src"] = src if src in PRINCIPAL_SRC else "unknown"
    return out


def principal_grade(p):
    """Canonical dict → one word. For queries and aggregation."""
    if not isinstance(p, dict):
        return "unknown"
    if p.get("src") == "kd":
        return "kernel-debugger"
    if not p.get("verified"):
        return "declared" if p.get("src") == "declared" else "unknown"
    sid = str(p.get("il_sid") or "")
    if p.get("elevated"):
        return "verified_elevated"
    return "verified_low" if sid in _IL_LOW else "verified_default"


def measure_record(target, grade, why="", kind="classify", vas=None, principal=None):
    """A measurement record. `verdict(basis='measured')` stands only if this exists —
    without it, 'I measured it' stays a **self-report.**

    ★ 2026-09-08 — `kind` splits them. The two carry different evidential weight, and mixing them makes the grade false:
        `classify` — an observation **graded** by dual fill (measure.py produced the grade)
        `trace`    — an observation the harness **executed** but that was not graded (a kd chain, etc.)
      A trace is **not a self-report** either — it is a record of what the harness fired.

    ★ 2026-09-10 — takes `principal`. **Pass only what the caller observed.**
      The probe path passes `principal=r.get("principal")` (a dict that really read the guest token),
      the kd path `principal="kd"`, and hex the agent transcribed `principal="declared"`.
      If nothing is passed it stays `unknown` — and **that is the honest value.** Filling in `default`
      as a default turns "measured elevated" into a fact (read-shaped-call-writes). So the gate is let through, but
      **a stamp** goes on the verdict saying what backed it. And a `basis=measured` rejection still has
      `GATE_CONTROL_BEFORE_REJECT` **demand a positive control separately**, so
      allowing this does not open the hole of being unable to tell "a broken harness from an absent defect".
    """
    _pr = principal if isinstance(principal, dict) and "verified" in principal \
        else normalize_principal(principal)
    STATE.setdefault("measures", []).append(
        {"target": target, "grade": str(grade), "why": why[:300], "kind": kind,
         "vas": sorted(vas)[:24] if vas else [],
         "principal": _pr, "principal_grade": principal_grade(_pr),
         "t": time.strftime("%m-%d %H:%M")})
    save()
    return True


def measured(target, state=None):
    """The measurement records backing this verdict. **Exact match + address overlap.**

    ★ Looking only at exact matches dropped a genuinely valuable verdict in the 09-08 run:
      the analyst ran baseline→treatment→after in three stages with 3/3 controls and filed `basis=measured`, but
      that target string was not in `measures`, so it was refused, and it ended up sinking to `basis=disassemble`.
    """
    _S = state if state is not None else STATE
    M = _S.get("measures") or []
    tgt = str(target or "")
    hit = [m for m in M if m.get("target") == target]
    _va = measure_vas(tgt)
    if _va:
        for m in M:
            if m in hit:
                continue
            mv = set(m.get("vas") or []) | measure_vas(m.get("target"))
            if mv & _va:
                hit.append(m)
    return hit


def measured_principal(target, state=None):
    """**Which principal** this target's measurements came from. Returns (best grade, supporting records).

    Best = the strongest for a privilege-boundary claim. `verified_low` > `verified_default`
    > `verified_elevated` > `kernel-debugger` > `declared` > `unknown`.

    ★ The point of this function is to **return `unknown` distinctly from `denied`.**
      "It failed at low privilege" (measured, and refused) and "it was never re-measured at low
      privilege" (unmeasured) are opposites for a privilege-boundary claim, yet while there was
      no principal field they looked the same in the ledger.
    """
    _rank = {"verified_low": 5, "verified_default": 4, "verified_elevated": 3,
             "kernel-debugger": 2, "declared": 1, "unknown": 0}
    recs = measured(target, state=state)
    if not recs:
        return ("none", [])
    best, who = "unknown", []
    for m in recs:
        g = m.get("principal_grade") or principal_grade(m.get("principal"))
        if _rank.get(g, 0) > _rank.get(best, 0):
            best, who = g, [m]
        elif g == best:
            who.append(m)
    return (best, who)


def arm_record(name, precondition, why=""):
    """A measurement **arming self-report**. The back end of `measure(action='armed')`.

    ★ This is not a verification. A string cannot carry a predicate (memory
    `prose-cannot-carry-a-predicate`) — the harness does not evaluate `precondition`.
    Why record it anyway: `classify` attaches **whether this record exists** to its verdict.
    Without it, "nobody reported actually taking that path" stays attached to the verdict.

    Real case (from the original docstring): to measure the `id < table_count` bounds check in
    `AfdRioInvalidateBuffer`, 10 extreme ids were fed in and all returned SUCCESS — but the
    table was empty, count=0, so **the bounds-check path was never taken at all.** "We measured it" was an illusion.
    """
    STATE.setdefault("armings", []).append(
        {"name": name, "precondition": str(precondition)[:300],
         "why": str(why)[:300], "t": time.strftime("%m-%d %H:%M")})
    save()
    return True


def armings(name):
    return [x for x in (STATE.get("armings") or []) if x["name"] == name]


def race_add(a, b, shared, why="", reach="user-triggerable-async"):
    """★ **A two-sided surface entry.** A race is not a property of a location but of (T_A, T_B) + a shared object.

    Of the 604 surface rows across all ledgers, **1** had the shape of a race hypothesis, and this
    project's only confirmed memory-safety bug (SCPVBUS-01 UAF) came out of that 1. With no row to
    hold it, it is not filed, and if it is not filed **it does not even remain as unanalysed** — it
    drops out of the denominator entirely.
    """
    if not (a and b and shared):
        return "race needs all three of a=, b=, shared= (the shared object/field)."
    if reach not in REACH:
        return f"reach is one of {REACH}."
    name = f"RACE({a} , {b} @ {shared})"
    STATE["surface"][name] = {"status": "unanalysed", "kind": "race", "reach": reach,
                              "pair": [a, b], "shared": shared, "why": why[:400]}
    save()
    return ("\nTo adjudicate you must show that BOTH sides touch the SAME SHARED STATE and that "
            "their order is not enforced.\nABSENCE OF A LOCK IS ONLY ONE FORM OF RACE. These hold "
            "even when locking is correct:\n  - double fetch - the value checked and the value "
            "used are DIFFERENT READS (user buffer / METHOD_NEITHER). Locks are irrelevant. With "
            "a kernel copy (METHOD_BUFFERED) this axis dies - state the transfer method first.\n  "
            "- state-transition window (dirty-COW shaped) - the premise validated changes between "
            "dropping and re-taking the lock. Look for RE-VALIDATION after re-acquisition; "
            "without it, a lock still leaves a window.\n  - handle / object reuse - the lock "
            "protects the slot while the IDENTITY inside the slot changes.\n  - refcount "
            "asymmetry - acquire and release sit under different locks.\n=> To reject, you must "
            "rule out EACH of those four. 'There is a common lock' alone does not sustain a "
            "rejection.")


def races():
    return {k: v for k, v in (STATE.get("surface") or {}).items()
            if v.get("kind") == "race"}


def surface_reach(name, reach, why=""):
    """Update reachability. `kernel-only` drops out of the attack-surface denominator but **stays in the table** —
    because it is a candidate race counterparty (`user-triggerable-async`)."""
    if reach not in REACH:
        return f"reach is one of {REACH}."
    if name not in STATE["surface"]:
        return f"'{name}' is not in the census table. surface(action='add') comes first."
    STATE["surface"][name]["reach"] = reach
    if why:
        STATE["surface"][name]["reach_why"] = why[:300]
    save()
    return f"{name} → reach={reach}"


def reach_unknown(limit=40):
    """★ **Returns the names** of the rows with `reach='unknown'`.

    The 2026-09-05 incident: the completion gate blocks while `reach=unknown` rows remain, yet
    **there was no way to point at those rows by name.** The agent could see only the count.
    S42 set 16 rows and still could not reach 0, filing gate_blocked; S45 **probed by name about
    140 times** without finding them and filed gate_blocked twice. Close to 150 wasted probes over the two rounds.
    S45's note title is the evidence as it stands: `STOP-PROBING-read-before-touching`.
    => make what the gate demands **enumerable.** This was a wiring problem, not a judgement problem.
    """
    out = [k for k, v in (STATE.get("surface") or {}).items()
           if isinstance(v, dict) and (v.get("reach") or "unknown") not in REACH_KNOWN]
    return out[:limit], len(out)


def dead_claim_open(limit=40, surface=None):
    """★ Returns, by name and split into two buckets, **the rows whose claims died but whose surface did not close.**

    Returns: (no_scope, open_cand, n_no_scope, n_open)
      · no_scope  — no denominator was ever declared. A single `verdict(action='scope', target=, items=, method=)`
                    opens the path to closing it.
      · open_cand — there is a denominator but candidates remain. Deciding the remaining candidates closes the surface.

    Measured 2026-09-06: **83** of 560 surface rows are in this state (`rejected_claims` present, yet unanalysed).
    For a rejection to close a surface there must first be a denominator (`_settle_reject`'s no_scope/open),
    and the guidance goes out on every successful rejection — **it went out 104 times.** Yet across the whole
    ledger only **1 row** is `closed_by_scope`. Not because the guidance went unseen, but **because the backlog was
    invisible**: there was no way to enumerate those rows by name.
    => the same remedy as `reach_unknown`. Make what the gate demands **enumerable.**
      A wiring problem, not a judgement problem. It does not prescribe what to do first.
    """
    # ★ `surface=` accepts a **snapshot.** Measured 2026-09-06: `nightrun.build_carryover`
    #   builds the carry-over from a file snapshot, `json.load(_state_path(name))`, and does
    #   not use `ledger.STATE`. Written to read only STATE, it **silently returned 0** in the
    #   parent process and the whole block was dropped (with no exception, it did not even look
    #   like a failure). The logic is kept as one copy and **only the data source** is an
    #   argument — duplicate it and only one side gets fixed.
    ns, oc = [], []
    _src = surface if surface is not None else (STATE.get("surface") or {})
    for k, v in _src.items():
        if not isinstance(v, dict) or v.get("status") != "unanalysed":
            continue
        if not (v.get("rejected_claims") or v.get("claims_rejected")):
            continue
        (oc if v.get("cand") else ns).append(k)
    return ns[:limit], oc[:limit], len(ns), len(oc)


def reach_breakdown():
    """(attack-surface denominator, kernel-only, unknown). Denominator = user-direct + user-triggerable-async."""
    c = {k: 0 for k in REACH}
    for v in (STATE.get("surface") or {}).values():
        c[v.get("reach", "unknown") if v.get("reach") in REACH else "unknown"] += 1
    return (c["user-direct"] + c["user-triggerable-async"], c["kernel-only"], c["unknown"], c)


def mark_incidental(name, found_while):
    """Mark that **B was found while looking at A.**

    ★ Why it is needed: this session's best defect (`S13-UAF-AVLNODE-V2`) came out exactly that way —
      the seed said 'look at the information-leak gate' and an AVL node UAF turned up.
      Yet after that every seed hammered in "do not add new surface", and the carry-over even
      got an automatic "this round only grew the denominator" warning. **It was punishing the best discovery path.**
      Widening (filing rows indiscriminately) and something hit while digging are different — the latter is a product of real work.
    """
    r = STATE.get("surface", {}).get(name)
    if r is None:
        return None
    r["incidental"] = (found_while or "")[:160]
    r["t_found"] = time.strftime("%m-%d %H:%M")
    save()
    return r


def incidental_count():
    return sum(1 for v in (STATE.get("surface") or {}).values() if v.get("incidental"))


def surface_set(name, status, why=""):
    if status not in STATUS:
        return f"status is one of {STATUS}."
    STATE["surface"].setdefault(name, {"status": "unanalysed", "kind": "ad-hoc",
                                      "reach": "unknown", "why": ""})
    STATE["surface"][name]["status"] = status
    if status != "unanalysed":
        STATE["surface"][name].pop("blocked", None)
        # A decided row's 'next step' is meaningless — left in place, the next round picks up a dead step.
        STATE["surface"][name].pop("next", None)
    if why:
        STATE["surface"][name]["why"] = why
    save()
    return f"{name} → {status}"



def _settle(vid, tgt, status, why=""):
    """Reflect a verdict into the **census table under the right key.**

    ★ This used to be a single `surface_set(tgt, ...)`. The census table's key is the **id** the agent
      filed (e.g. `MJ_CREATE_0x18001b864`), but `tgt` is an **address** (`0x18001B864`).
      `surface_set` is a setdefault, so the address key **created a new row** and the original row stayed
      unanalysed forever — the denominator inflates and the numerator never rises.
      A cng.sys round decided 25 items and was still printed at coverage **13/42 (31%)** (really 25/27).
      With MIN_COVERAGE turned on it becomes an unsatisfiable gate.

    Rule: if the id is in the table use it, and if tgt is also already in the table mark it too.
          **A verdict does not create new rows in the census table.** Only when neither exists is one created
          (so that nothing is silently dropped).
    """
    keys = [k for k in (vid, tgt) if k and k in STATE["surface"]]
    if not keys:
        keys = [vid or tgt]
    for k in keys:
        surface_set(k, status, why)
    return keys


def _va(x):
    try:
        return int(str(x), 16) if str(x).lower().startswith("0x") else int(str(x))
    except Exception:
        return None


def _scope_of(k):
    return (STATE.get("surface", {}).get(k) or {}).get("cand")


def _scope_open(k):
    """Return the candidates not yet decided. None if there is no scope declaration (= declare it first)."""
    sc = _scope_of(k)
    if not sc:
        return None
    return [it for it in sc["items"] if not it.get("done")]


def _scope_mark(k, item_label, sink_va, vid):
    """One rejection closes **one** candidate. Only an explicit match (item=) or a matching sink VA counts.

    ★ It does not guess matches by string similarity. A wrong match passes off an unseen candidate as
      decided, and that is exactly the trap this harness has stepped in repeatedly (a quiet wrong answer).
    """
    sc = _scope_of(k)
    if not sc:
        return None
    want = (item_label or "").strip().lower()
    sv = _va(sink_va)
    for it in sc["items"]:
        if it.get("done"):
            continue
        if (want and want == it["label"].strip().lower()) or \
           (sv is not None and it.get("va") is not None and sv == it["va"]):
            it["done"] = vid
            return it
    return None


def _settle_reject(vid, tgt, claim, item_label, sink_va):
    """★ R-A: **a rejection does not close a surface row.**

    Measured (2026-08-31): of 73 rejected surfaces, **73 were closed by a single claim.** Not one surface
    was closed after two or more competing claims were raised. A real case, `FDO.MAJOR.READ@0x14000d2d0` —
    it rebutted **one** sink of a shared classifier and rejected the **entire** major handler, while the
    same round's own note said "CopyIoBuffer/MapIoBuffer/MakeSafeMdl not looked at yet".

    So the conditions for a surface to become `rejected` are pinned to three:
      ① a **candidate set was declared first** with `verdict(action='scope', ...)`, and
      ② **every** one of those candidates has been decided, or
      ③ `action='exhaust'` (that is not a rejection but an exhausted method)
    If the conditions are not met the surface stays **unanalysed (blocked)** — the claim died but the surface did not.
    """
    keys = [k for k in (vid, tgt) if k and k in STATE["surface"]] or [tgt or vid]
    out = []
    for k in keys:
        row = STATE["surface"].setdefault(
            k, {"status": "unanalysed", "kind": "ad-hoc", "reach": "unknown", "why": ""})
        row["claims_rejected"] = int(row.get("claims_rejected") or 0) + 1
        row.setdefault("rejected_claims", []).append({"vid": vid, "claim": (claim or "")[:120]})
        hit = _scope_mark(k, item_label, sink_va, vid)
        rest = _scope_open(k)
        if rest is None:
            row["status"] = "unanalysed"
            row["blocked"] = True
            row["why"] = ("%d claims were rejected but NO CANDIDATE SET WAS DECLARED - the "
                          "surface does not close. Declare this surface's denominator first with "
                          "verdict(action='scope', target=%r, items=[...], method=...)."
                          % (row["claims_rejected"], k))
            out.append((k, "no_scope", None))
        elif rest:
            row["status"] = "unanalysed"
            row["blocked"] = True
            row["why"] = ("%d claims rejected · %d/%d candidates decided — **remaining candidates: %s**"
                          % (row["claims_rejected"],
                             len(_scope_of(k)["items"]) - len(rest),
                             len(_scope_of(k)["items"]),
                             ", ".join(it["label"] for it in rest[:6])))
            out.append((k, "partial", rest))
        else:
            surface_set(k, "rejected", (claim or "")[:120])
            row["closed_by_scope"] = True
            out.append((k, "closed", hit))
    return out


def coverage():
    """**Decision rate** — counts only confirmed/rejected/refuted. blocked is not an achievement, so it is not counted."""
    tot = len(STATE["surface"])
    if not tot:
        return 0.0, 0, 0
    done = sum(1 for v in STATE["surface"].values()
               if v["status"] in ("confirmed", "rejected", "refuted", "boundary-held"))
    return done / tot, done, tot


def code_coverage():
    """★ **Actual code coverage.** It measures something different from `coverage()`.

    `coverage()` = verdicts / surface, but **the agent fills the surface itself.**
    So it is a ratio over a denominator it picked itself, measuring not "how much was audited" but
    "did it tidy up what it wrote down". Write 16 entry points and decide 17 items and it reads 57%,
    but if 394 functions are reachable behind them, what was actually seen is 8% (measured on ahcache).

    Returns (rate, functions seen, reachable functions). (None,0,0) if there is no index.
    ※ It uses only the direct-call graph, so the reachable count is a **lower bound** (jump tables and guard_dispatch_icall are missed).
    """
    try:
        import tools as _T, pe as _PE
        ix = _T._ix()
        if not ix:
            return (None, 0, 0)
        nm = {cva: n for cva, n in ix.byva}
        # ★ 2026-09-05 — **the key spaces were mixed.** `ix.out` and `touched` below are keyed by
        #   **symbol name (str)**, but `surface[].entry` is a **VA (int)**. Fed in as seeds as-is,
        #   `ix.out.get(<int>)` is always None so the closure never grows once, and the final
        #   intersection `touched(names) & seen(ints)` is **empty forever** => always 0%.
        #
        #   ★★ This is a regression I (the observer) introduced. At 02:31, while adding the wiring that
        #   fills `entry`, I **did not fix the consumer.** Before that `entry` was always empty, so the
        #   name-heuristic fallback below ran, and there was no symptom. In other words **filling the
        #   field correctly is what armed the gate.**
        #   (The msquic round reproduced `(0.0, 0, 20)` exactly and diagnosed it. That diagnosis is right.)
        #   => normalise the seeds **into the graph's key space.** If it is not a function start, fold it to the bounds.
        _t0 = STATE.get("target") or ""
        _pe0 = None
        if _t0 and os.path.exists(_t0):
            try:
                _pe0 = _PE.PE(_t0)
            except Exception:
                _pe0 = None
        ents, _unres = [], 0
        for v in (STATE.get("surface") or {}).values():
            if not isinstance(v, dict) or not v.get("entry"):
                continue
            try:
                _va = int(v["entry"], 16) if isinstance(v["entry"], str) else int(v["entry"])
            except (TypeError, ValueError):
                continue
            _n = nm.get(_va)
            if _n is None and _pe0 is not None:
                try:
                    _b, _ = _pe0.func_bounds_merged(_va)
                    _n = nm.get(_b)
                except Exception:
                    _n = None
            if _n is None:
                _unres += 1
            else:
                ents.append(_n)
        if not ents:
            ents = [n for n in nm.values()
                    if "Dispatch" in n or "Callback" in n or "Unload" in n]
        seen, stack = set(), list(ents)
        while stack:
            a = stack.pop()
            if a in seen:
                continue
            seen.add(a)
            stack += list(ix.out.get(a, ()) or ())
        t = STATE.get("target") or ""
        if not (t and os.path.exists(t)):
            return (None, 0, len(seen))
        p_ = _PE.PE(t)
        touched = set()
        for x in (STATE.get("disasm") or []):
            try:
                a = int(x, 16) if isinstance(x, str) else int(x)
                b, _e = p_.func_bounds_merged(a)
                if b in nm:
                    touched.add(nm[b])
            except Exception:
                pass
        hit = len(touched & seen)
        return ((hit / len(seen)) if seen else None, hit, len(seen))
    except Exception:
        return (None, 0, 0)


def mark_interrogated(tgt, v, broke=None, note="", vid=None):
    """Stamp an interrogation result onto a rejection entry. **A rejection that was never interrogated is not a verified negative** —
    lowering the sample rate and inflating coverage are different things, so it is kept per entry.

    ★ Measured 2026-09-06 — **this function found rows by target string and was overwriting other rows.**
      Interrogation is always a pre-gate that runs **before** the rejection is recorded. But the loop
      below first looked for "a rejection with the same target" and patched it, so **from the second
      rejection that shares a target onward** (candidate sets, sibling rows)
        ① it did not get its own mark (= stayed uninterrogated), and
        ② its own interrogation result was **stamped onto the earlier row** (= quiet contamination).
      Measured: rejections sharing a target — ahcache 18 groups / 59 rows · wcifs 12 groups / 33 rows;
      42% (ahcache) of the rejections carrying an interrogation record were rows later followed by another rejection of the same target.
      => **carry it by row id.** Given an id, stamp only that row; without one, stash it under the id key.
      (Same family as memory `hook-local-dict-is-not-a-transport` — the transport could not identify the row.)
    """
    key = str(vid).strip() if vid else None
    for rec in reversed(STATE.get("verdicts") or []):
        # ★ Given an id, fix **only that row.** Without one, fix no row at all —
        #   this is a pre-gate, so the matching row normally does not exist yet.
        if key and str(rec.get("id")) == key and rec.get("status") == "rejected":
            rec["interrogated"] = bool(v)
            if v:
                rec["interrogation"] = {"klass": v.get("klass"),
                                        "reason": (v.get("reason") or "")[:400],
                                        # ★ 2026-09-05: without `broke`, `session_products()`
                                        #   cannot tell "a broken rejection" from "passed interrogation".
                                        "broke": bool(broke) if broke is not None
                                                 else (not v.get("sustained", True))}
            save()
            return True
    # ★ Interrogation is a pre-gate that runs **before the rejection is recorded** => there is no verdict to find here yet.
    #   It used to store only a bool that nobody ever read back, so **the interrogation result evaporated entirely**:
    #   the 08-31 12:57 round ran two interrogations and was still printed in the ledger as `rejects_interrogated=0`.
    #   = the dashboard reports "were the rejections verified" as 0 forever.
    STATE.setdefault("pending_interrog", {})[key or tgt] = {
        "ok": bool(v),
        # ★ When the consumer cannot find it by id and falls back to target, the provenance is kept
        #   alongside so it can tell whether the result really belongs to this row.
        "for_id": key,
        "for_target": str(tgt)[:160],
        # ★ 2026-09-05: `ok` means "did the interrogation run", not "did the rejection stand".
        #   Without separating the two, `session_products()` **counts a broken rejection as output.**
        "broke": (bool(broke) if broke is not None
                  else (bool(v) and not (v or {}).get("sustained", True))),
        "klass": (v or {}).get("klass"),
        "reason": ((v or {}).get("reason") or "")[:400],
        "note": (note or "")[:1200]}
    save()
    return False


def verified_negatives():
    """★ **The verified-negative rate.** `coverage()` counts every rejection as a verdict, but a rejection the
    gate let through as 'undecidable' is not a negative but unanalysed (`ledger.py` itself wrote
    "for coverage this is not a confirmed negative" and kept counting it anyway).

    Returns: (rate, verified, total_rejections). With a sample of 0, rate=None — it claims no ratio.
    """
    try:
        import rejaudit as RA
    except Exception:
        return (None, 0, 0)
    tot = ver = 0
    for v in STATE.get("verdicts") or []:
        if (v.get("status") or "") != "rejected":
            continue
        tot += 1
        if RA.classify(v)[0] == "T0":
            ver += 1
    return ((ver / tot) if tot else None, ver, tot)


def settled():
    """**Settled rate** — verdicts + 'blocked with a reason attached'. The finish gate looks at this.

    ★ Without this split the gate was issuing an unsatisfiable instruction:
      can_finish() says "at least attach a reason with blocked", but coverage() does not count
      blocked, so with MIN_COVERAGE>0 turned on you could follow that instruction and never finish.
      MIN_COVERAGE defaults to 0.0 and was never turned on, so it never surfaced.
    Unanalysed with a reason attached is **honest unanalysed** — it lets you finish, but does not count as an achievement.
    """
    tot = len(STATE["surface"])
    if not tot:
        return 0.0, 0, 0
    # ★ Rows the R-A migration reverted are **not settled.** Their `why` is not analysis but
    #   migration wording. Counting them puts the settled rate at 89% from the start and the finish
    #   gate is satisfied immediately — the 08-31 15:50 round really did end itself that way after
    #   31 minutes of a 60-minute cap (0 verdicts). Once the agent writes **its own reason** on such
    #   a row, `why` is overwritten and this exclusion lifts automatically.
    def _migrated(v):
        return v.get("reopened_by") and str(v.get("why", "")).startswith("R-A reopen")
    n = sum(1 for v in STATE["surface"].values()
            if v["status"] in ("confirmed", "rejected", "refuted", "boundary-held")
            or (v.get("blocked") and not _migrated(v)))
    return n / tot, n, tot


# ★ Measured 2026-09-04: the old implementation was `[:limit]` = **dict insertion order 0-7.**
#   Of wcifs's 560 unanalysed rows only filing positions 0-7 appeared and **552 rows were never seen.**
#   ahcache was the same (fixed at fn0-fn7) — yet all 3 confirmations came from around fn8 and fn10.
#   This list rides in `status_block` and is injected **every 4 tools + after every verdict**, about 45
#   times per round, and it was the same 8 rows across rounds too. The extreme form of cold-start bias —
#   a newly filed row **never even gets a chance to be picked up.** (Only the worklist picks by score,
#   and it is shown once per round. At 45:1 the bias wins.)
#
# The replacement: ① show the **composition** of what is left first (more information than 8 rows),
#         and ② **slide the window** on every call so the sample sweeps the whole set within a round.
#   Why not use the score axis (worklist) — that axis picks "the rows that move the grade", while
#   the question here is "what has not been looked at yet", a different purpose. Layering priority
#   twice would itself become a new bias.
_UN_CURSOR = [0]


def unaudited(limit=8, rotate=True):
    rows = [k for k, v in STATE["surface"].items() if v["status"] == "unanalysed"]
    if not rows:
        return []
    if not rotate or len(rows) <= limit:
        return rows[:limit]
    i = _UN_CURSOR[0] % len(rows)
    _UN_CURSOR[0] = (i + limit) % len(rows)
    out = rows[i:i + limit]
    if len(out) < limit:                     # past the end, wrap around to the front
        out += rows[:limit - len(out)]
    return out


def unaudited_shape():
    """The **composition** of the remaining unanalysed rows. This says more than 8 names do."""
    import collections as _c
    c = _c.Counter()
    for _k, v in STATE["surface"].items():
        if v.get("status") != "unanalysed":
            continue
        c[(v.get("reach") or "unknown")] += 1
    return c


# ── 2) grounds ───────────────────────────────────────────────────
def note_disasm(target):
    STATE["disasm"].add(str(target))
    save()


def has_disasm(target):
    t = str(target)
    return any(t in d or d in t for d in STATE["disasm"])


# ── 3) scenario duplication ───────────────────────────────────────
def _scen(target, claim):
    """A (location, hypothesis) pair. A claim to the same effect arriving again for the same function is the same scenario."""
    words = sorted(set(re.findall(r'[^\W\d_]{3,}', (claim or "").lower())))[:12]
    return hashlib.sha1((str(target) + "|" + " ".join(words)).encode()).hexdigest()[:12]


REOPEN_GROUND = {
    "new_evidence": "A NEW ANCHOR that breaks the refutation exists - the evidence must contain "
                    "a VA absent from the dead record",
    "category_error": "The rejection klass DOES NOT ADDRESS WHAT THE CLAIM IS ABOUT - write both "
                      "what the klass asserts and what the claim asserts",
    "precondition_resolved": "The precondition the rejection rested on HAS SINCE BEEN MEASURED - "
                             "give that measurement / question id",
}


def reopen(gid, ground, why, evidence=""):
    """Graveyard re-examination. **It does not resurrect; it grants the standing to argue again.**

    ★ Why it was built on 2026-09-03. `S23-GATE3-DEFAULT-V2` is the real incident:
      the claim was "this feature gate is DISABLED by default" (what the value is), the rejection klass
      was `not_controlled` ("the value is a constant"). Being a constant **does not rebut that claim, it
      supports it.** Yet it went into the graveyard locked as 'do not reopen', and an OOB report built on
      top of it came back up over five rounds. In other words **a question one observation would settle was locked away.**

    ★ At the same time the graveyard **was also leaky**: `_scen` is a bag-of-words hash, so changing the
      wording makes a different scenario. The agent really did burn rounds hunting for "a third phrasing".
      => open legitimate re-examinations, block rewordings. The two are defects in opposite directions.
    """
    gid = str(gid or "").strip()
    g = next((x for x in STATE.get("graveyard") or [] if str(x.get("id")) == gid), None)
    if g is None:
        ids = [str(x.get("id")) for x in (STATE.get("graveyard") or [])][-8:]
        return ("no id=%r in the graveyard. Recent ids: %s\nPick one from the 'graveyard' line of status()." % (gid, ids))
    ground = str(ground or "").strip().lower()
    if ground not in REOPEN_GROUND:
        return ("`reopen` requires ground=. It must be one of these three:\n"
                + "\n".join("  %-22s %s" % (k, v) for k, v in REOPEN_GROUND.items())
                + "\n\n'I WILL PHRASE IT DIFFERENTLY' IS NOT A GROUND. That is a move that "
                  "has already failed twice.")
    why = str(why or "").strip()
    if len(why) < 40:
        return ("why= must be AT LEAST 40 CHARACTERS. If you cannot write in one sentence what "
                "changed, it is not yet time to reopen.\nDead rejection: [%s] %s - %s"
                % (g.get("klass"), str(g.get("claim"))[:100], str(g.get("reason"))[:150]))

    if ground == "new_evidence":
        old = set(x.lower() for x in re.findall(r'0x[0-9a-fA-F]{6,16}',
                                                json.dumps(g, ensure_ascii=False)))
        new = set(x.lower() for x in re.findall(r'0x[0-9a-fA-F]{6,16}', str(evidence)))
        if not (new - old):
            return ("ground='new_evidence' but the evidence CONTAINS NO ANCHOR THAT THE DEAD "
                    "RECORD LACKED.\nAnchors in the dead record: %s\nRe-submitting the same "
                    "basis is not new evidence." % (", ".join(sorted(old)[:8]) or "(none)"))
    if ground == "category_error":
        kl = str(g.get("klass") or "")
        if kl and kl.lower() not in why.lower():
            return ("With ground='category_error' you must NAME THAT KLASS (%r) INSIDE why=, and "
                    "write side by side what that klass asserts and what the claim asserts. That "
                    "is the proof of a category error." % kl)

    g.setdefault("reopens", []).append(
        {"ground": ground, "why": why[:500], "t": time.strftime("%m-%d %H:%M"),
         "evidence": str(evidence)[:400]})
    g["reopened"] = True
    # ★ 2026-09-05 — **a reopen spoils a track's "it is finished" claim.** (memory `raw-material-goes-stale`)
    #   Measured: the `searchpath-head-injection` track note says *"S48 FINAL v4 — GOAL MET AND THE TRACK IS
    #   ANSWERED END TO END … closes NEGATIVE"*, yet S46 on that axis was reopened for a scope error and
    #   the ablation arm hung 3 new open questions on the same axis. The note still tells every following
    #   round "finished, and negative". It is not erased, only **marked** — judgement belongs to the human/analyst.
    _CLOSED = ("ANSWERED", "GOAL MET", "CLOSED AS", "closes NEGATIVE", "END TO END", "FINAL")
    for _tn, _t in (STATE.get("tracks") or {}).items():
        _note = str(_t.get("note") or "")
        if any(c in _note for c in _CLOSED):
            _t.setdefault("stale_closure", []).append(
                {"by": gid, "ground": ground, "t": time.strftime("%m-%d %H:%M")})
    save()
    n = len(g["reopens"])
    warn = ""
    if n >= 3:
        warn = ("\nTHIS IS REOPEN ATTEMPT %d. If three rounds of argument have not closed it, "
                "the problem is not the argument but the METHOD. Filing "
                "gate_blocked(kind='tool'/'taxonomy') is the better move." % n)
    return ("[REOPENED] %s - ground=%s (attempt %d)\nDead rejection: [%s] %s\n  its stated "
            "reason: %s\n\nYou may now attempt this scenario ONCE more. The refuter still "
            "runs.\nThe reopen is recorded on the graveyard entry - it is not erased.%s"
            % (gid, ground, n, g.get("klass"), str(g.get("claim"))[:120],
               str(g.get("reason"))[:200], warn))


def gy_origin(entry):
    """Where a graveyard entry came from. Old entries have no `origin`, so it is **inferred backwards** from the candidate list.

    ★ The two carry different evidential weight:
      refuted — an **independent adversary** with a kill mandate killed it. Demanding new grounds for a resurrection is right.
      self    — **the analyst's own rejection.** The next round looking at it again is a normal re-examination,
                not "a resurrection from the graveyard".
    """
    o = entry.get("origin")
    if o:
        return o
    cid = str(entry.get("id"))
    for c in (STATE.get("candidates") or []):
        if str(c.get("id")) == cid and c.get("state") == "refuted":
            return "refuted"
    return "self"


def graveyard_priming(n=12):
    """★ The graveyard summary carried into the opening prompt and the status block. **The wording is split by origin.**

    The old wording stamped "CLAIMS ALREADY KILLED (do not resurrect)" on all 394 rows.
    Of those, 94 percent were the analyst's own rejections, so its own verdicts came back in the same language as an adversary's.

    Selection is also **stratified by klass** instead of `[-12:]` (recency) — what has to get across is not
    "what was killed recently" but "for which reasons things die", so the next round checks those reasons up front.
    """
    import collections as _c
    gy = STATE.get("graveyard") or []
    if not gy:
        return ""
    # ★ 2026-09-10 — **take negatives that do not stand out of the 'killed claims' slot.**
    #   On 09-06 the grades were counted and the rows were even named, yet the last `reaudit`
    #   calls were the 3 on 09-07 (zero in every session on 09-08, 09 and 10). Meanwhile ahcache's `broke` went 17 → 43.
    #   The cause is that **the same row was carried in two slots at once**: the "KILLED / YOUR OWN
    #   EARLIER REJECTIONS" list above (long, comes first) and the "rejections that do not stand" below (short, comes
    #   after). The first slot wins, and the row reads as a closed axis.
    #   It is exactly the rule of memory `graveyard-is-not-ground-truth` — *do not put "rejected" and "a rejection that
    #   survived an adversary" in the same slot.* Now they are carried only in the re-examination slot below.
    try:
        _sc, _srows, _sn = graveyard_trust(limit=10 ** 6)
        _suspect = {str(r["id"]) for r in _srows}
    except Exception:
        _sc, _srows, _sn, _suspect = None, [], 0, set()
    ref = [g for g in gy if gy_origin(g) == "refuted" and str(g.get("id")) not in _suspect]
    own = [g for g in gy if gy_origin(g) != "refuted" and str(g.get("id")) not in _suspect]
    L = []
    if ref:
        L.append("=== KILLED BY AN INDEPENDENT REFUTER (%d) — do not resurrect without new "
                 "evidence that breaks the refutation ===" % len(ref))
        for g in ref[-min(n, 6):]:
            L.append("  [%s] %s — %s: %s" % (g.get("id"), str(g.get("target"))[:44],
                                             g.get("klass"), str(g.get("claim"))[:90]))
    if own:
        by = _c.Counter(g.get("klass") or "-" for g in own)
        L.append("")
        L.append("=== YOUR OWN EARLIER REJECTIONS (%d) — these are VERDICTS, NOT REFUTATIONS. "
                 "Re-examining one is normal re-audit, not resurrection. The interrogator breaks "
                 "%s of rejections it sees, so treat these as provisional ===" % (len(own), "67%"))
        L.append("  reason distribution: " + " · ".join("%s %d" % kv for kv in by.most_common(8)))
        # stratified by klass — one per reason
        seen = set()
        for g in reversed(own):
            k = g.get("klass") or "-"
            if k in seen:
                continue
            seen.add(k)
            L.append("  [%s] %s — %s: %s" % (g.get("id"), str(g.get("target"))[:44], k,
                                             str(g.get("claim"))[:80]))
            if len(seen) >= n - min(len(ref), 6):
                break
    # ★ 2026-09-06 — **carry the graveyard's trust grades as well.**
    #   Measured: this table's `verified` rows (negatives the interrogator could not break) were only 54 of
    #   ahcache's 167 (32%), yet the wording above went out without telling the grades apart. In particular the
    #   `broke`/`reopened` rows are **negatives that were withdrawn or do not stand**, yet the next round saw them as closed axes —
    #   that is how the 09-06 run left `S77-REDIR-GUARD-ASYM` (a row the interrogator broke as door_only and the analyst
    #   accepted) sitting as a rejection when it was cut off by budget expiry. They are called out by name.
    _c2, _rows, _n = _sc, _srows, _sn      # ★ already measured above — counting twice makes the two values diverge
    if _c2:
        L.append("")
        L.append("=== this graveyard's trust grades — verified negatives %d / total %d ==="
                 % (_c2.get("verified", 0), sum(_c2.values())))
        L.append("  " + " · ".join("%s %d" % kv for kv in _c2.items() if kv[1]))
        L.append("  Only `verified` rows are negatives that survived an adversary. `unexamined` means nobody has tried to break it,")
        L.append("  and `broke`/`reopened` are **rows that already collapsed but were never withdrawn** — first in line for re-examination.")
    if _rows:
        L.append("")
        L.append("=== %d rejections that do not stand — this is **cleanup**, not resurrection ===" % _n)
        L.append("  ★ These %d rows were **taken out of the 'killed claims' list above.** The interrogator broke them"
                 " (broke) or their author withdrew them (reopened), so they must not be read as closed axes." % _n)
        for r in _rows[:6]:
            L.append("  [%s] %s (%s) %s — %s"
                     % (r["grade"], r["id"], r.get("klass"), r.get("target", "")[:40],
                        str(r.get("why") or "")[:90]))
    return "\n".join(L)


def seen_scenario(target, claim):
    s = _scen(target, claim)
    # ★ A scenario with a re-examination open is not blocked. Graveyard entries and candidates are linked by id.
    reopened = {str(g.get("id")) for g in (STATE.get("graveyard") or [])
                if g.get("reopened") and not g.get("rekilled")}
    # ★ 2026-09-10 — **a rejection the interrogator broke (broke) is not blocked either.**
    #   The priming sends these rows out as "negatives that do not stand, clean them up", yet when someone
    #   actually tried to reopen one this gate refused it as "an already dead scenario". A refusal that offers no
    #   way forward produces spinning (memory `predicate-cannot-ask`). The grade comes from `graveyard_trust` alone —
    #   writing the same predicate twice makes the two values diverge.
    #   ★ This is not unlimited resubmission: repeated non-closure is closed by the adjudicator (`ADJUDICATE_AFTER`).
    try:
        _, _srows, _ = graveyard_trust(limit=10 ** 6)
        reopened |= {str(r["id"]) for r in _srows if r.get("grade") == "broke"}
    except Exception:
        pass
    for c in STATE["candidates"]:
        if c.get("scen") == s and c["state"] in ("refuted", "promoted"):
            if str(c.get("id")) in reopened:
                return None
            return c
    return None


# ── 4) verdicts ───────────────────────────────────────────────────
def open_candidate(target, claim, basis, evidence, anchors=None):
    cid = f"C{len(STATE['candidates']) + 1}"
    rec = {"id": cid, "target": target, "claim": claim, "basis": basis,
           "evidence": (evidence or "")[:4000], "anchors": anchors or [],
           "state": "proposed", "klass": None, "reason": "",
           "scen": _scen(target, claim), "t": time.strftime("%m-%d %H:%M")}
    STATE["candidates"].append(rec)
    save()
    return rec


def close_candidate(rec, state, klass=None, reason="", impact=None):
    """★ Two additions on 2026-09-04:
      ① keep `impact` — a dead confirmation produces no verdict record, so the three impact items **vanished entirely.**
         Tonight, trying to audit two `impact_unproven` kills after the fact, there were no grounds to look at.
      ② a `t` on the graveyard record — without it, filtering by date yields **zero rows every time.**
         I really did misread it as "zero refuter kills tonight" (there were 5 kills).
    """
    rec["state"] = state
    rec["klass"] = klass
    rec["reason"] = reason
    if impact:
        rec["impact"] = impact
    if state == "refuted":
        # ★ When an item opened for re-examination dies again, **close the re-examination mark** (rekilled).
        #   Otherwise a single re-examination becomes a permanent pass.
        _prev = next((g for g in (STATE.get("graveyard") or [])
                      if str(g.get("id")) == str(rec.get("id"))), None)
        if _prev is not None and _prev.get("reopened"):
            _prev["rekilled"] = True
            _prev["rekill_reason"] = ("%s: %s" % (klass, reason))[:300]
        STATE["graveyard"].append({"id": rec["id"], "target": rec["target"],
                                   "claim": rec["claim"][:120], "klass": klass,
                                   "reason": reason[:300],
                                   "impact": rec.get("impact"),
                                   "origin": "refuted",     # killed by an independent adversary
                                   "t": time.strftime("%m-%d %H:%M")})
        _settle(rec.get("id"), rec["target"], "refuted", f"{klass}: {reason[:70]}")
    save()




def _pe_for_gates():
    try:
        import tools as _T
        return _T.TARGET.get("_pe")
    except Exception:
        return None


def _sink_va(rec):
    """Pull the sink VA out of a confirmation's target/evidence. None (= unanalysed) if there is none."""
    import re as _re
    for fld in (rec.get("target"), rec.get("evidence")):
        if not fld:
            continue
        m = _re.search(r"0x([0-9a-fA-F]{6,16})", str(fld))
        if m:
            return int(m.group(1), 16)
    return None


# ── ASK — when a gate cannot decide, it **asks** ─────────────────────────
#   2026-08-29. Until then a gate was a predicate: `(ok, note)`. When it could not decide, the only
#   choices were **pass or refuse**, both wrong, so it **leaked out as a warning line**:
#   `⚠ recording as an unverified rejection`. 186 of 262 leaked that way.
#   A third choice is needed — **ask.** A predicate cannot ask. So the question is carried in the return value.
#
#   The gate already knows **why** it could not decide => the question is specific, and the next method comes with it.
#   (The sentences used so far as warnings become the questions as they are.)
ASK_METHOD = {
    # ── verdicts produced by the cut generalisation (2026-09-04). Without guidance they fall through to
    #    the default wording, and the agent re-submits the same pair not knowing "what next moves there are".
    "not_a_cut":
        "The declared guards are NOT a cut: removing all of them still leaves a path from the "
        "function entry to the sink, i.e. there is a way in that crosses none of your guards. "
        "Find that path (it is usually a SECOND ingress with its own check) and add its guard to "
        "`guards=`, or the rejection does not hold.",
    "no_escape":
        "Your guards form a cut, but NO edge out of any of them avoids the sink — so nothing is "
        "actually being filtered. Point at the failure path (the drop / return / assert arm). If "
        "there is none, the 'guard' does not guard anything.",
    "cut_needs_judgement":
        "Your guards cut the sink, but the graph's MINIMAL cut is a strict subset of what you "
        "declared. The extra members may be a refinement chain on the same value (legitimate) or "
        "padding (not). That distinction needs the comparison instructions read, so it is not "
        "decided mechanically - an adversary reviews it. Make sure `evidence=` contains the "
        "disassembly of EVERY declared guard, showing what each one compares.",
    "both_edges":
        "The branch you named reaches the sink on BOTH edges - it separates nothing. Either name "
        "the branch whose failure arm actually leaves (usually the LAST comparison of a chain), "
        "or declare the whole set with `guards=` if the invariant is established by several "
        "blocks together.",
    # ★ 2026-09-04, fixed after reading the ledger's 33 (answered) rows. This wall is **85%** of the answered questions.
    #   And the outcomes split into **two opposites** — the old wording only showed the road to one of them:
    #     (1)(2) both assume "there is a guard somewhere". Yet nearly half of what was actually
    #     answered was **"no guard, hence a defect"** (S11-P3b probe range mismatch,
    #     S15-AM1c AccessMode=KernelMode, S15-C2 RemoveEntryList arbitrary write, S20 feature-off …).
    #   The exhaustion records show the price: "tried both paths the gate offered …
    #   only one branch constrains this sink" — **they died looking for a guard that was not there.**
    "dominates_only":
        "The value the guard reads never reaches the sink operand. The gate cannot tell WHICH "
        "of two opposite things this is, so answer that first:\n"
        "  (A) THE SINK OPERAND IS NOT ATTACKER-DERIVED at all -> no guard is needed and the "
        "rejection stands. Show it the way this ledger's own settled rows did: name every "
        "operand's origin (driver-planted constant, compile-time offset, read-only .rdata "
        "table decoded exhaustively, width fixed by the instruction pair itself).\n"
        "  (B) IT IS ATTACKER-DERIVED AND NOTHING CONSTRAINS IT -> then this is not a "
        "rejection, IT IS THE DEFECT. File it as a confirmation. Half of the answered "
        "questions on this exact wall ended here: a probe covering a shorter range than the "
        "sink reads, AccessMode=KernelMode skipping the access check, a length checked "
        "against one value and used against another, a feature gate that is OFF by default.\n"
        "  (C) only if neither holds: name the OTHER guard that constrains this sink, or show "
        "the path that value takes ONE MORE HOP (`sink_gates` enumerates the cmp/call that "
        "dominate the sink; give it `sink=`, not `target=`).\n"
        "KNOWN GATE LIMITS - if your guard has this shape, the gate is wrong and (A)/(B) is "
        "still the answer: the tracked value is a MEMORY operand (`cmp rax, [rbp-1]` - only "
        "the register term is followed), or it round-trips through another register "
        "(`mov rbx, rcx` ... `mov rcx, rbx` reads as a different value).",
    "no_branch":
        "The guard block does not have two successors — it is an indirect branch. DECODE THE "
        "DISPATCHER, recover the (code/major -> slot) mapping, and re-submit the pair that "
        "actually lies on that path. If it goes through guard-CF "
        "(`_guard_dispatch_icall`), the real target is one hop further.",
    "indirect_only":
        "Nothing calls the sink function directly (function pointer / vtable / callback). The "
        "call graph cannot settle this. What you CAN do: (1) recover the selector->handler "
        "mapping with `dispatch_table`; (2) use `find_bytes` to find where that function's "
        "address is referenced AS DATA (vtable / dispatch array) and trace that array's "
        "consumers back with `import_xref` / `callers`; (3) use `disassemble` to read the slot "
        "offset at the indirect call site and match it to the array index.",
    "sink_unreachable":
        "The sink block is not reachable from the guard block. The pair may lie on different "
        "paths — pick the entry point again and show that both points sit in the SAME "
        "execution.",
    "unbounded":
        "No successor reaches the sink — the CFG is incomplete (indirect branch). Recover the "
        "edges with `dispatch_table`; if it is a jump table, decode the table directly with "
        "`find_bytes`, enumerate the arms, and ask again. Do NOT do a cumulative subtraction "
        "ladder (`sub r,1`) in your head — expand it with `disassemble`.",
    "cross_function":
        "The pair crosses a function boundary. Compute dominance over the call graph with "
        "`authz.gates_inter` — the 'checked once at the door' shape lives here.",
    "no_pdata":
        "The function is not in .pdata. Do NOT guess the bounds — check whether adjacent "
        "chunks were merged via `pe.merged_functions` (chunk splitting trips here) and ask "
        "again.",
    "no_image":
        "The target image could not be opened. Settle the binary path and re-run — a verdict "
        "reached without the image is not a negative.",
    "double_fetch_unchecked":
        "This is a METHOD_NEITHER target and YOU HAVE NOT RULED OUT THE DOUBLE-FETCH AXIS. The "
        "user pointer arrives without a kernel copy, so 'guarded' only holds if you show the "
        "value CHECKED and the value USED come from the SAME READ. Either (1) cite the "
        "instruction that takes a kernel copy (ProbeForRead / capture), or (2) show that the "
        "check and the use come from the same register / stack slot. If there is a re-read, "
        "THAT is the defect.\n"
        "Tool: `double_fetch` (CFG dataflow, control-enforced). NOTE: that tool seeds its "
        "lineage from `entry rdx = IRP`, so FAST-IO IS OUT OF ITS RANGE — for a fast-io "
        "handler, follow the argument registers by hand from the entry with `disassemble`. "
        "A zero result from that tool must NOT be written down as clean.",

}


def asks(status="open"):
    """The ASK queue. `status=None` means all of it."""
    return [q for q in (STATE.get("asks") or [])
            if status is None or q.get("status") == status]


def _ask_open(tgt):
    for q in (STATE.get("asks") or []):
        if q.get("target") == tgt and q.get("status") == "open":
            return q
    return None


def _ask_close(tgt, vid, how="answered", note=""):
    """Close a question. **A verdict closes it automatically** — otherwise the queue grows forever."""
    n = 0
    for q in (STATE.get("asks") or []):
        if q.get("target") == tgt and q.get("status") == "open":
            q["status"] = how
            q["resolved_by"] = vid
            q["resolved_t"] = time.strftime("%m-%d %H:%M")
            if note:
                q["resolution"] = note[:300]
            n += 1
    return n


# ── the broken-rejection register (**outside** the ledger) ────────────────────────────
# ★ Why outside the ledger: the conductor reads all of `state/*.json`. Putting broken rejections there
#   would add dozens per round and explode what the conductor has to read. But the consumer of this
#   record is not the conductor, it is **the next round's analyst** — so the medium is split.
#
# ★ Why it is needed (measured 2026-09-04): the interrogator broke **213** rejections, yet
#   only 11 left a reason in the ledger, and even those had an empty klass.
#   Because `mark_interrogated()` is called **only on the sustained branch** —
#   a broken rejection is not recorded as a verdict, so there is no row to attach it to.
#   The reasons went to `work/transcript.*.log`, and that file is **truncated every round.**
#   => 213 answers to "why does this rejection not stand" vanished without a trace. Some were new leads
#     (even the one surviving line carried an unprobed 0x1B8 memcpy in `AhcDispatch`).
def _break_dir():
    """★ Follows the namespace. Otherwise **bench/scratch learns from production records** —
    `_lesson_ledgers` had already been fixed that way, and only this place was missed (T39 blew up on it).
    The same accident already happened on 08-24 as bench→pcw.sys ledger contamination."""
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports", "breaks")
    if PROVENANCE != "prod":
        d = os.path.join(d, "_" + PROVENANCE)
    return d


def _break_path(image=None):
    """★ The file key is the **image** (not the target function). Splitting by function creates hundreds of
    one-line files per target and defeats the whole point of accumulation. The function name goes inside the row."""
    _d = _break_dir()
    os.makedirs(_d, exist_ok=True)
    return os.path.join(_d, _key(image or STATE.get("target") or "unknown") + ".jsonl")


# ★ 2026-09-07 — the lead queue and the refile queue **must be split.**
#   Measured (71 cumulative): wrong_pair 28 (39%) · other_constructor 11 · bound_wrong 11 ·
#   indirect_entry 7 · door_only 5 · window_too_short 5 · not_measured 4.
#   By `break_digest`'s own interpretation, `wrong_pair` is a paperwork problem — **the analyst submitted the wrong
#   pair** — not a lead. Mixed together, 20 real leads look like 71,
#   and then "draining the queue" looks like an impossible goal, so nobody touches it.
_REFILE_KLASS = {"wrong_pair"}


def break_kind(klass):
    """Is one break a **lead** or a **refile**? A single klass decides it."""
    return "refile" if (klass or "") in _REFILE_KLASS else "lead"


_BREAK_ESCALATE_AT = 3          # escalate at this many breaks on the same target


def _break_key(target, claim=""):
    """The key that groups breaks by **target identity.** A renamed row is still caught as the same row.

    Returns: {normalised function name} | {VAs pulled from the strings}. Any intersection means the same row.
    """
    t = str(target or "").lower()
    out = set()
    for v in measure_vas(t + " " + str(claim or "")):
        out.add(("0x%x" % v) if isinstance(v, int) else str(v).lower())
    nm = re.sub(r'^[a-z0-9_]+!', '', t.split('@')[0].split('(')[0].strip())
    nm = re.sub(r'[^a-z0-9_]', '', nm)[:48]
    if len(nm) >= 6:
        out.add(nm)
    return out


def record_break(target, v, args=None, kind="interrogator"):
    """Append one broken rejection. **Does not touch STATE** — zero load on the conductor.

    It accumulates (it is not wiped each round). That is the reason this file exists.

    ★ 2026-09-07 — `id` and `status` are stamped with it. Without them the queue **never shrinks**:
      answered and unanswered cannot be told apart, so either every round shows the same rows again,
      or they get pushed out of `B[-n:]` and are never seen again (both really happened).
    """
    a = args or {}
    bid = "%s-%s" % (time.strftime("%m%d%H%M%S"), uuid.uuid4().hex[:4])
    row = {"id": bid, "t": time.strftime("%Y-%m-%d %H:%M"), "kind": kind,
           "queue": break_kind((v or {}).get("klass")),
           "status": "open",
           "target": str(target)[:120],
           "klass": (v or {}).get("klass"),
           "reason": str((v or {}).get("reason") or "")[:1200],
           "next_method": str((v or {}).get("next_method") or "")[:800],
           "claim": str(a.get("claim") or "")[:300],
           "rejected_as": a.get("klass"),
           "vid": a.get("id"),
           "guard": a.get("guard"), "sink": a.get("sink")}
    # ★ 2026-09-23 — **a per-target repeat counter.**
    #   ★ It first counted by verdict id (vid), and **it never fired once**: the real loop runs while
    #     changing ids — that row from the mrxsmb night of 09-22 changed its name as `QUIC-RECV-SEED-001 → -R2 → -R3 → -R4 → -R5`.
    #     So the key is **target identity**: the function name with the module prefix and the address
    #     stripped + the set of VAs pulled from the strings. If either overlaps, it is treated as the same row.
    #     (Measured that night: **10 of 20 breaks were one function** — 4 by name had no VA, and
    #      6 were `mrxsmb!SmbQuicReceiveEx@0x140052860`. Without the name axis, 4 are missed.)
    #   ★ The queue value stays {lead, refile} — inventing a new queue value would make `open_leads(queue="lead")`
    #     **unable to see those rows in any queue** (the very disease of a queue that mixes two kinds).
    #     Instead a repeat row is taken out of the paperwork queue, **sent back to lead**, and stamped.
    _key = _break_key(target, a.get("claim"))
    _n = 0
    if _key:
        try:
            with open(_break_path(), encoding="utf-8") as _bf:
                for _l in _bf:
                    if not _l.strip():
                        continue
                    try:
                        _o = json.loads(_l)
                    except ValueError:
                        continue
                    if _break_key(_o.get("target"), _o.get("claim")) & _key:
                        _n += 1
        except OSError:
            _n = 0
    row["attempt"] = _n + 1
    if _n + 1 >= _BREAK_ESCALATE_AT:
        # ★ 2026-09-23 (2nd edition) — **do not tamper with `queue`.**
        #   The first edition overwrote refile→lead, but `break_digest` counts "awaiting refile N" from that
        #   field, so the tally broke (test_breaks caught it). Instead of overwriting the label,
        #   **stamp separately** and have `open_leads` look at the stamp — no information is thrown away.
        row["escalated"] = True
        row["escalate_hint"] = (
            "This is break number %d on this target. Do not rewrite the label a fifth time — "
            "what is missing is most likely **an observation.** Seal it with `verdict(action='gate_blocked', "
            "gate='needs-measurement', …)` and demand that observation." % (_n + 1))
    try:
        with open(_break_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except OSError as e:
        sys.stderr.write("\033[93m[breaks] write failed: %s\033[0m\n" % e)
        return None
    return row


# ★ There are **only three** ways a lead closes. `exhausted` is not one of them —
#   ASK leaked out through exactly that exit (395 created · 41 answered (10%) · **194 exhausted (49%)**;
#   on 09-04 alone 81 were closed as exhausted, while 2 were answered that day).
#   This ledger's measurement is that pressure to exhaust produces giving up, not answers.
CLOSE_HOWS = {
    "refuted":        "the refuter killed the confirmation on this axis (an adversary judged it)",
    "measured":       "a measurement split it (there is an observation that passed its controls)",
    "reinterrogated": "the rejection was filed again and this time the interrogator **could not break it**",
}


def close_break(bid, how, why="", image=None):
    """Close one lead. **Append-only** — a closure is stacked as one more line too.

    ★ Why the file is not rewritten: parallel rounds append to the same image.
      Rewriting it would wipe out every append made in between.
    """
    how = (how or "").strip().lower()
    if how not in CLOSE_HOWS:
        return ("[CLOSE REFUSED] how=%r is not a way to close a lead. There are only three:\n"
                % how + "\n".join("  · %s — %s" % kv for kv in CLOSE_HOWS.items())
                + "\nThere is no exhausted. If you cannot close it, leaving it open is the honest thing.")
    rec = {"op": "close", "ref": str(bid), "how": how,
           "why": str(why or "")[:600], "t": time.strftime("%Y-%m-%d %H:%M")}
    try:
        with open(_break_path(image), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError as e:
        return "[CLOSE FAILED] %s" % e
    return "closed lead %s as `%s` — %s" % (bid, how, CLOSE_HOWS[how])


# ── the question queue — **split by recipient** ─────────────────────────────
# ★ Built from a 2026-09-07 measurement. The breakdown of 160 open questions:
#     filed by the analyst  102 → answered 34 (33%) · exhausted 64 · **open 4**
#     filed by the conductor 293 → answered  7 ( 2%) · exhausted 130 · **open 156**
#   156 of the 160 that piled up belong to the conductor. And at least 85 of those are not target analysis but
#   ledger/gate audit questions (their target starts with `harness / …` outright. CQ87 nails down in its body:
#   "do not act, report in numbers").
#   => questions the analyst cannot answer were being piled up, and the answered ratio was being counted.
#     Many of the 130 exhausted were not giving up but **returns to sender for misdelivery.**
_ASK_OPERATOR = re.compile(r'^\s*[\[\(]?\s*harness\b', re.I)


# ★ 2026-09-08 — **a question's origin is not a label but a ranking axis.**
#   Measured (all ledgers): `by=conductor` questions — **0 answered of 185** for ahcache, 2 of 87 for wcifs.
#   Gate/refuter questions in the same ledgers were answered at **32.6% / 18.4%.** Yet 113/115 of the
#   open questions were the conductor's, so even with the rotating window **what was visible was effectively only conductor questions.**
#   And the question most likely to pay off — the interrogator's `next_method` — has **not a single row** in `asks`
#   (73 sit in `reports/breaks/`, all carrying a next_method, and 1 has been closed).
_ASK_BY = ("gate", "refuter", "interrogator", "resisted", "conductor")
_ASK_BY_ALIAS = {"gate": "gate", "r3": "gate", "reject_gate": "gate",
                 "refuter": "refuter", "refute": "refuter", "rq": "refuter",
                 "interrogator": "interrogator", "interrog": "interrogator",
                 "break": "interrogator", "lead": "interrogator",
                 "resisted": "resisted", "resist": "resisted", "xq": "resisted",
                 "conductor": "conductor", "cq": "conductor"}


def normalize_ask_by(b, aid=""):
    """Normalise a question's origin to the canonical vocabulary. If empty, **infer it back from the id prefix** (to backfill old rows).

    ★ Nothing is made up — a prefix outside the vocabulary falls to `gate`. That is the old default
      (originally the only producer of this queue was the gate, when it could not decide).
    """
    tok = str(b or "").strip().lower()
    if tok in _ASK_BY_ALIAS:
        return _ASK_BY_ALIAS[tok]
    pre = str(aid or "")[:2].lower()
    return _ASK_BY_ALIAS.get(pre, "gate")


def ask_yield(state=None):
    """The **answered ratio** per origin. Ranking weights are measured from the ledger, not hard-coded as constants.

    ★ Hard-coded constants go stale when the target changes. And this figure is itself something to observe —
      if the yield of conductor questions rises, the ranking should follow on its own.
    ★ With a small sample (<8) it returns `None` — zero and unmeasured are not mixed.
    """
    S = state if state is not None else STATE
    agg = {}
    for a in (S.get("asks") or []):
        o = normalize_ask_by(a.get("by"), a.get("id"))
        d = agg.setdefault(o, {"n": 0, "answered": 0, "closed": 0})
        d["n"] += 1
        if a.get("status") == "answered":
            d["answered"] += 1
            d["closed"] += 1
        elif a.get("status") == "exhausted":
            d["closed"] += 1
    out = {}
    for o, d in agg.items():
        # ★ The denominator is **the closed ones**, not the total. An open question has not failed yet, it just
        #   has not been answered. Using the total as the denominator **pins a new origin that was created in one
        #   batch to the floor at 0% before it gets a chance** — the first edition did exactly that
        #   (`resisted` created 26 at once and got 0/26 = 0.0).
        # ★ With a small sample (<8), `None`. Zero and unmeasured are not mixed.
        out[o] = {"n": d["n"], "answered": d["answered"], "closed": d["closed"],
                  "rate": (d["answered"] / d["closed"]) if d["closed"] >= 8 else None}
    return out


def _ask_t_key(a):
    """Sort key by time. **The stored value is not changed** — there are two stores with different owners.

    ★ Measured 2026-09-08: the lead store uses `2026-09-04 23:11` (with the year), ledger questions use
      `08-30 01:06` (no year). It is a string comparison, so `"2026-…"` was **always pushed behind** `"09-…"`,
      and so within a tie **interrogator questions were permanently last.**
      The question most likely to pay off was invisible because of one format mismatch.
    """
    t = str((a or {}).get("t") or "")
    m = re.match(r'^\d{4}-(\d{2}-\d{2}.*)$', t)
    return m.group(1) if m else t


def ask_rank_key(a, yields=None):
    """The sort key of the single queue. **yield > attempt count > oldest first**.

    ★ Why attempt count (`attempts`) is second: it means the gate was repeatedly undecided on the same row,
      which is the same signal `resisted` counts. With a single queue, that signal lives here.
    """
    o = normalize_ask_by(a.get("by"), a.get("id"))
    y = (yields or {}).get(o) or {}
    r = y.get("rate")
    # Unmeasured yield (None) goes **in the middle** — treated as 0, a new origin would sit on the floor forever.
    r = 0.5 if r is None else r
    return (-r, -len(a.get("attempts") or []), _ask_t_key(a))


def ask_audience(a):
    """A question's **recipient.** The conductor already uses a `harness /` prefix, so it splits mechanically."""
    return "operator" if _ASK_OPERATOR.match(str((a or {}).get("target") or "")) else "analyst"


def open_asks(state=None, audience=None, rank=False, include_leads=False):
    """Open questions as **one queue.** Ranked by yield by default; `rank=False` gives the old behaviour (oldest first).

    ★ 2026-09-08 — the default is **the old contract unchanged** (oldest first · ledger questions only). Merging and ranking are
      **explicit opt-ins**: `ask_window` is a renderer that counts rotation and totals, so mixing in leads that
      `_ask_close` cannot close would break the contract (`test_askqueue` caught that).
      What looks at the single queue is `ask_queue()` and `verdict(action='asks')`.

    ★ Interrogator leads are **merged in, but their store does not move**
      (the reason `reports/breaks/` lives outside the ledger still holds — the conductor's reading would explode).
      **One queue means one view, not one store.**
      The way to close them differs, so `_close_via` is sent along.
    """
    S = state if state is not None else STATE
    out = [a for a in (S.get("asks") or []) if (a.get("status") or "open") == "open"]
    if include_leads:
        # ★ 2026-09-11 — **if the target cannot be pinned down, carry no leads at all.**
        #   `breaks(None)` means "every target" (right for the operator queue). But if `None` flows
        #   in here, **another target's queue gets carried into this target's handoff.**
        #   Measured (bfs.sys first round 00:18): the SEED of a new target with 0 ledger rows carried **52**
        #   open questions, all of them msquic's and ahcache's. The first-contact session read someone else's questions first.
        #   => do not read an absence as "everything". When the target is unknown, **zero is the right answer.**
        #   ★ And the ledger's `target` is **the full staging path** (`work/night/x.sys/x.sys`),
        #     while `reports/breaks/` lives by basename. Without normalisation the filter
        #     quietly yields zero (the safe direction), and an empty target yields everything (the dangerous direction).
        _tgt = os.path.basename(str(S.get("target") or "").strip()) or None
        try:
            for b in (breaks(_tgt, open_only=True, queue="lead") if _tgt else []):
                out.append({"id": b.get("id"), "target": b.get("target"),
                            "why": "the interrogator broke this rejection [%s] %s"
                                   % (b.get("klass") or "-", str(b.get("reason") or "")[:160]),
                            "method": b.get("next_method") or b.get("reason") or "",
                            "klass": b.get("klass"), "cfg": None, "status": "open",
                            "by": "interrogator", "kind": "need_observation",
                            "attempts": [], "t": b.get("t") or "",
                            "_close_via": "verdict(action='lead', id=%s, how=…, why=…)"
                                          % b.get("id")})
        except Exception:
            pass                        # a lead-store failure must not kill the ledger questions
    if audience:
        out = [a for a in out if ask_audience(a) == audience]
    if not rank:
        return sorted(out, key=_ask_t_key)
    _y = ask_yield(S)
    return sorted(out, key=lambda a: ask_rank_key(a, _y))


def ask_window(state=None, n=6, audience="analyst"):
    """The **rotating window** carried into the handoff. (window, total, start offset)

    ★ The old behaviour was `asks[:4]` — **fixed**, oldest first. Measured: ahcache had 115 open
      questions, yet every round showed the same 4 (CQ65~68, created 09-05 16:02), and
      the other 111 **were never exposed once.** 3~5 were created per round while exposure was
      fixed at 4, so the bandwidth did not match — the answered ratio was not low, they were never reached.
      The evidence: on 09-07 the conductor newly created CQ182 `harness / CQ66` and CQ184 `harness / CQ66 klass
      vocabulary`. It reissued the same topic while CQ66 sat trapped in the window.

    ★ The rotation key is **the round count.** No new state is created — a `shown` counter would require the handoff
      to write the ledger, but the handoff is a rendering that runs on a copy read from a file, so it cannot write
      (it is the place where `save()` was neutralised via a temporary path).
    """
    S = state if state is not None else STATE
    A = open_asks(S, audience=audience)
    if not A:
        return [], 0, 0
    r = len(S.get("rounds") or [])
    off = (r * n) % len(A)
    win = (A + A)[off:off + n] if len(A) > n else A
    return win, len(A), off


def backfill_graveyard_trust(state=None):
    """**Stamp interrogation results back onto graveyard rows.** Idempotent, and it only moves what the verdict side recorded.

    ★ Why (measured 2026-09-07): of 616 graveyard rows only **12** carried a `broke` mark.
      Stamping started on 09-06, so earlier rows do not have the field at all. Yet on the
      `verdicts` side 43 remain with `interrogation.broke=True` —
      **the same fact existed in only one store.** To the consumers that read the graveyard (priming, `lessons`,
      the `_resolve_row` fallback), those rows all look like equal negatives.

    ★ It creates no new facts. It only copies `verdicts[i].interrogation` onto the graveyard row with the same **id**.
      On a conflict (the two stores disagree) it **leaves it alone and counts it** — overwriting quietly would make it
      forever impossible to tell which side is right.
    """
    S = state if state is not None else STATE
    src = {}
    for v in (S.get("verdicts") or []):
        if v.get("status") != "rejected" or v.get("id") is None:
            continue
        ig = v.get("interrogation") if isinstance(v.get("interrogation"), dict) else {}
        if ig.get("broke") is not None or v.get("interrogated") is not None:
            src[str(v.get("id"))] = (bool(ig.get("broke")), v.get("interrogated"),
                                     ig.get("klass"))
    stamped = same = conflict = 0
    for g in (S.get("graveyard") or []):
        r = src.get(str(g.get("id")))
        if not r:
            continue
        broke, interrogated, klass = r
        if g.get("broke") is None:
            g["broke"] = broke
            if g.get("interrogated") is None:
                g["interrogated"] = interrogated
            if broke and klass and not g.get("break_klass"):
                g["break_klass"] = klass
            stamped += 1
        elif bool(g.get("broke")) != broke:
            conflict += 1
        else:
            same += 1
    return {"stamped": stamped, "already": same, "conflict": conflict}


def breaks(target=None, limit=0, open_only=False, queue=None):
    """Read the record files and **fold in the close records.** With no target, every target.

    ★ 2026-09-07 — old rows have no `id`/`status`/`queue` (all 71 accumulated so far).
      They are backfilled on read: the id is derived deterministically from the **ordinal**
      within the file (close records are excluded from the ordinal — otherwise every close
      would shift the ids), and the queue is derived from the klass.
    """
    import glob as _g
    _d = _break_dir()
    os.makedirs(_d, exist_ok=True)
    files = ([_break_path(target)] if target      # target here is an **image**
             else sorted(_g.glob(os.path.join(_d, "*.jsonl"))))
    out = []
    for fp in files:
        rows, closes = [], {}
        key = os.path.basename(fp)[:-6]
        try:
            with open(fp, encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln:
                        continue
                    try:
                        r = json.loads(ln)
                    except ValueError:
                        continue
                    if r.get("op") == "close":
                        closes[str(r.get("ref"))] = r
                    else:
                        rows.append(r)
        except OSError:
            continue
        for i, r in enumerate(rows):
            r.setdefault("image", key)
            if not r.get("id"):
                r["id"] = "%s#%03d" % (key.split(".")[0][:12], i)
            if not r.get("queue"):
                r["queue"] = break_kind(r.get("klass"))
            c = closes.get(str(r["id"]))
            if c:
                r["status"], r["closed_how"] = "closed", c.get("how")
                r["closed_t"], r["closed_why"] = c.get("t"), c.get("why")
            else:
                r.setdefault("status", "open")
            out.append(r)
    if queue:
        out = [r for r in out if r.get("queue") == queue]
    if open_only:
        out = [r for r in out if r.get("status") != "closed"]
    return out[-limit:] if limit else out


def open_leads(target=None):
    """Only the open **leads**, oldest first. The WIP cap and the carry-over read the same function.

    ★ 2026-09-23 — **an escalated refile counts as a lead too.** A row broken %d times on the
      same target is work, not paperwork (mrxsmb 09-22: 10 times on one function). The `queue`
      field is left alone, though — `break_digest` counts refiles from that field.
    """ % _BREAK_ESCALATE_AT
    L = breaks(target, open_only=True, queue="lead")
    _esc = [r for r in breaks(target, open_only=True)
            if r.get("escalated") and r.get("queue") != "lead"]
    return sorted(L + _esc, key=lambda r: str(r.get("t") or ""))


def break_digest(target=None, n=None, width=260):
    """★ The **lead queue** handed to the next round's analyst. A work list, not a summary.

    ★ Redesigned 2026-09-07 — the old behaviour was `B[-n:]` with n=3, i.e. **the newest 3, LIFO.**
      With 71 accumulated, 3 new breaks made everything before them **invisible forever** —
      it built a queue and then threw away the front of it. Now the oldest unresolved come first.

    ★ It splits two queues (`break_kind`): `wrong_pair` is **paperwork** fixed by re-declaring
      the pair, and in the lead queue it makes 20 real rows look like 71. Only its count is given.
    """
    n = int(n if n is not None else getattr(_cfgmod(), "LEAD_DIGEST_N", 8))
    B = breaks(target)
    if not B:
        return ""
    import collections as _c
    L = [x for x in B if x.get("queue") == "lead"]
    R = [x for x in B if x.get("queue") == "refile"]
    Lo = sorted([x for x in L if x.get("status") != "closed"],
                key=lambda r: str(r.get("t") or ""))
    Rc = sum(1 for x in R if x.get("status") != "closed")
    done = sum(1 for x in B if x.get("status") == "closed")
    c = _c.Counter(b.get("klass") or "(not stated)" for b in Lo)
    out = ["## ⟂ Lead queue — rejections the interrogator broke (reports/breaks/)", "",
           "  open leads **%d** · awaiting refile %d · closed %d  (cumulative %d)"
           % (len(Lo), Rc, done, len(B)), ""]
    if c:
        out += ["  " + " · ".join("%s %d" % kv for kv in c.most_common(8)), ""]
    _hint = {"wrong_pair": "the guard/sink pair you declared points at something other than your claim",
             "other_constructor": "a **different constructor** of the same object sets that field differently — half the population is exempt",
             "door_only": "the check runs **only once**, at open/create — see whether it is re-applied on every operation",
             "indirect_entry": "function pointers, vtables or dispatch bypass the guard. `callers()` sees only direct calls",
             "bound_wrong": "dominance is proven, but the **bound constant** is wrong",
             "window_too_short": "'present/absent' was judged inside a fixed-size window — look one hop over",
             "not_measured": "this is a static rejection. **Does the handler even run?** — one measurement settles it"}
    if c:
        top = c.most_common(1)[0][0]
        if top in _hint:
            out += ["★ top klass `%s` — %s" % (top, _hint[top]), ""]
    if Rc:
        out += ["  (the %d `wrong_pair` rows are the **refile queue** — a pair-declaration problem, not a defect, so "
                "they are not counted as leads)" % Rc, ""]
    out.append("**%d oldest unresolved first.** There are only three ways to close one — "
               "`verdict(action='lead', id=<lead id>, how=refuted|measured|reinterrogated, why=…)`"
               % min(n, len(Lo)))
    for b in Lo[:n]:
        out.append("- `%s` [%s] %s  (%s)"
                   % (b.get("id"), b.get("klass") or "-", str(b.get("target"))[:56],
                      str(b.get("t") or "")[:10]))
        nm = (b.get("next_method") or b.get("reason") or "").replace("\n", " ")
        if nm:
            out.append("    next move: %s" % nm[:width])
    if len(Lo) > n:
        out.append("  … and %d more (all of them: `verdict(action='leads')`)" % (len(Lo) - n))
    return "\n".join(out)


# ── L1 · unifying the raw material ──────────────────────────────────────────
# ★ Reads the failure/breakthrough records that were scattered across three places in one shape.
#   answered  — records that **actually broke through** that wall. The most valuable, and until now carried nowhere
#   exhausted — records closed without breaking through. "This method is already dead"
#   break     — records of the interrogator breaking a rejection (reports/breaks/, added 2026-09-04)
#
# ★ Raw material **goes stale.** Measured: complaints that `sink_gates` was broken remain in 3
#   exhausted records, but that bug was fixed on 09-02 (the post-mortem note in `tools.py`). Feeding
#   stale negative knowledge as-is causes what the literature calls "propagation of a wrong procedure"
#   — **in the negative direction.**
#   => the date is carried along, and old entries are marked as such.
_LESSON_SKIP = ("dbg", "dbg2", "e2e", "demo", "rt", "bench", "bench_gate", "niede",
                "GOALTEST.sys", "GOALBY.sys", "XIMG.sys", "KslD.sys")


def _lesson_ledgers():
    # ★ Follows the namespace. Hard-coding `state/` makes **the bench learn from production** —
    #   this repository has already had the incident in the opposite direction (the bench polluted the pcw.sys ledger, 08-24).
    import glob as _g
    d = _ns_dir()
    out = []
    for fp in sorted(_g.glob(os.path.join(d, "*.json"))):
        nm = os.path.basename(fp)[:-5]
        if nm in _LESSON_SKIP or nm.startswith(("scratch", "_", "test")):
            continue
        out.append((nm, fp))
    return out


def lessons(cfg_verdict=None, srcs=("answered", "exhausted", "break", "graveyard"),
            min_len=60):
    """Raw material in one shape. Given `cfg_verdict`, only that wall's records.

    `min_len` — short ones are dropped. A test ledger's `resolution` was a single character like "c".
    """
    out = []
    for nm, fp in _lesson_ledgers():
        try:
            d = json.load(open(fp, encoding="utf-8"))
        except Exception:
            continue
        # ★ ① How did that target end up — because the same wall has **two opposite outcomes.**
        #   Reading the 25 dominates_only breakthroughs, half are "the rejection stood" (the operand
        #   was not the attacker's) and half are "that was the defect" (there was no constraint at all).
        #   Showing only one side is not bias, it is **teaching the wrong answer.**
        # ★ The link is made through **`resolved_by` → verdict id.** Matching on the target string is wrong —
        #   measured: `WcPortMessage@0x140035dd0` alone had 2 verdicts attached, so a stack-leak question
        #   got labelled with the status of an **unrelated rejection.** That is not bias, it is a wrong answer.
        #   The `resolved_by` that `_ask_close()` leaves is an exact link (holds for answered 33/33).
        _vst = {str(v.get("id")): v.get("status") for v in (d.get("verdicts") or [])}
        for q in (d.get("asks") or []):
            st = (q.get("status") or "").lower()
            if st not in srcs:
                continue
            if cfg_verdict and q.get("cfg") != cfg_verdict:
                continue
            txt = str(q.get("resolution") or "").strip()
            if len(txt) < min_len:
                continue
            out.append({"src": st, "image": nm, "cfg": q.get("cfg"), "klass": q.get("klass"),
                        "target": q.get("target"), "text": txt,
                        "outcome": {"rejected": "clean", "confirmed": "defect",
                                    "boundary-held": "defect"}.get(
                                        _vst.get(str(q.get("resolved_by") or ""))),
                        "t": q.get("resolved_t") or q.get("t") or "",
                        "attempts": len(q.get("attempts") or [])})
        # ★ ⑥ The klass axis — the graveyard is "precedents that died for this reason". The refuter-kill (24)
        #   and interrogator-break (213) paths key on klass, not cfg, and until now that axis had no retrieval.
        if "graveyard" in srcs:
            for gy in (d.get("graveyard") or []):
                if cfg_verdict and gy.get("klass") != cfg_verdict:
                    continue
                txt = str(gy.get("reason") or "").strip()
                if len(txt) < min_len:
                    continue
                out.append({"src": "graveyard", "image": nm, "cfg": gy.get("klass"),
                            "klass": gy.get("klass"), "target": gy.get("target"),
                            "text": txt, "outcome": "killed", "t": "", "attempts": 0})
    if "break" in srcs:
        for b in breaks():
            if cfg_verdict and b.get("klass") != cfg_verdict:
                continue
            txt = str(b.get("next_method") or b.get("reason") or "").strip()
            if len(txt) < min_len:
                continue
            out.append({"src": "break", "image": "", "cfg": b.get("klass"),
                        "klass": b.get("rejected_as"), "target": b.get("target"),
                        "text": txt, "t": b.get("t") or "", "attempts": 0})
    return out


def rules_for(key, n=2, width=300, image=None):
    """★ Retrieve the precedents that actually came out of this wall / this reason.

    The moment of retrieval is **the moment a deterministic gate settles the kind of failure.** The
    literature (ProactAgent) calls for "retrieval as a learned policy action"; we do not need that —
    `cfg`/`klass` is already the name of the failure, so an exact match gives zero false retrievals (and zero overhead).

    Three selection rules (all of them made by measurement):
      ① **Outcome balance** — the same wall has two opposite outcomes. Picking only one side teaches the wrong answer.
         One `clean` (the rejection stood) and one `defect` (that was the defect) are placed side by side.
      ② **Image stratification** — measured: `won[-2:]` were both wcifs. Auditing ahcache, not one of
         ahcache's own 11 breakthroughs was visible. The current target's records are picked first.
      ⑤ **It must be switchable off** — `GATE_LESSONS=0`. Unmeasured, you never learn whether it helps or is noise.
    """
    if not key:
        return ""
    try:
        import config as _cf
        if not getattr(_cf, "GATE_LESSONS", True):
            return ""
    except Exception:
        pass
    L = lessons(key)
    if not L:
        return ""
    img = _key(image or STATE.get("target") or "")
    won = [x for x in L if x["src"] == "answered"]
    dead = [x for x in L if x["src"] != "answered"]

    def _pick(pool):
        """② The current target's first → then other images. The same image never appears twice."""
        seen, out = set(), []
        for want_mine in (True, False):
            for x in sorted(pool, key=lambda y: y.get("t") or "", reverse=True):
                mine = x["image"] == img
                if mine != want_mine or x["image"] in seen:
                    continue
                seen.add(x["image"])
                out.append(x)
        return out

    # ① Outcome balance — fill clean 1 + defect 1 first, then top up from the rest if short
    chosen = []
    for oc in ("clean", "defect"):
        c = _pick([x for x in won if x.get("outcome") == oc])
        if c:
            chosen.append(c[0])
    if len(chosen) < n:
        for x in _pick(won):
            if x not in chosen:
                chosen.append(x)
            if len(chosen) >= n:
                break
    chosen = chosen[:n]

    _LBL = {"clean": "the rejection stood", "defect": "★ it was a defect", None: "outcome unknown"}
    out = []
    if chosen:
        out.append("\n\n── %d records that actually reached an outcome at this wall, %d shown ──" % (len(won), len(chosen)))
        for x in chosen:
            out.append("  · [%s %s · %s] %s"
                       % (x["image"], x["t"][:11] or "-",
                          _LBL.get(x.get("outcome"), "outcome unknown"), x["text"][:width]))
        if len({x.get("outcome") for x in chosen}) > 1:
            out.append("  ↑ **Two cases where the same wall ended in opposite ways.** Which one this is, is the question of this verdict.")
    elif dead:
        # The klass axis (graveyard, breaks) has no breakthrough records — use them only as cautionary precedents
        d2 = _pick(dead)[:n]
        out.append("\n\n── %d precedents that died for the same reason, %d shown ──" % (len(dead), len(d2)))
        for x in d2:
            out.append("  · [%s] %s" % (x["image"] or "-", x["text"][:width]))
    if won and dead:
        out.append("  ⚠ %d at this same wall were exhausted/broken — do not use the same method again." % len(dead))
    if not out:
        return ""
    out.append("  (Precedents are as of their time. Tools may have been fixed since, so re-check — "
               "complaints about a broken `sink_gates` really did stay in the records after it was fixed.)")
    return "\n".join(out)


def ask_refuted(target, claim, klass, reason, would_change):
    """★ **Turn a confirmation the refuter killed back into an open question.**

    Until now `would_change_my_mind` ("what would let it survive") appeared once in the agent's
    context and vanished. The result: of **11 confirmations killed by the refuter, 0 refile attempts** —
    the refuter was effectively the court of last resort. The stage-gated design in the literature
    ([[refs/01]]) has a judge/adjudicator; we had none. Put in the queue, **the next round can at least see that condition and pick it up.**
    """
    if not would_change and not reason:
        return None
    q = {"id": "RQ%d" % (len(STATE.get("asks") or []) + 1), "target": target,
         "why": "confirmation killed by the refuter [%s] %s" % (klass or "-", (reason or "")[:200]),
         "method": (would_change or "(the refuter gave no revival condition - change the axis of "
                                    "your evidence)")[:300],
         "cfg": "refuted", "status": "open", "attempts": [],
         "kind": "need_observation", "by": "refuter",
         "claim": (claim or "")[:300], "t": time.strftime("%m-%d %H:%M")}
    STATE.setdefault("asks", []).append(q)
    save()
    return q


# ★ ASK used to mix two things, and the two have **completely different next moves.**
#   - need_observation : an observation is missing (no image, no .pdata, CFG construction failed).
#                        A human/tool has to go and measure one more thing. Calling an LLM yields nothing.
#   - inexpressible    : **the analysis is done but the gate's model cannot express the shape.**
#                        (the guard is a clamp, not a branch / the value does not syntactically reach the
#                         sink operand / several blocks establish the invariant together)
#   Measured 2026-09-04: among open questions across all targets, `dominates_only` is by far the top
#   cfg reason with **62.** And `_gate_verdict` **skipped the interrogator on those 62**, saying "an ASK is
#   not a rejection yet, so it is not interrogated." So rows stuck on inexpressibility **had never been seen
#   by any LLM**, and the next round's analyst hit the same rule again, in a loop. The conductor reported
#   this 14 times from 09-02 on.
#   => split the kinds and hand `inexpressible` **to the adversarial layer once** (no new role — the
#     interrogator's mandate is already "when in doubt, the rejection does not stand", which points the right way).
#   ★ `not_a_cut` / `no_escape` are not put here. Those two are **not limits of the model but
#     definite refutations by the graph** — "a path that passes no guard at all really exists",
#     "no edge avoids the sink". Letting the adversarial layer overturn them would let an LLM beat a
#     computable fact. Like `both_edges`/`not_dominated`, they go to a **hard refusal.**
_ASK_INEXPRESSIBLE = ("dominates_only", "cut_needs_judgement", "no_branch")


def history_for(target, ask=None):
    """★ The **full history** for the adjudicator. In this panel only the adjudicator sees this.

    The refuter, interrogator and escalator deliberately cannot see each other (to prevent collusion).
    That independence is the value, but the price is that **nobody can synthesise** — so the same
    question ran 4–5 times. This is where that price is recovered.
    """
    L = []
    tgt = str(target or "")
    a = ask or _ask_for(tgt)
    if a:
        L.append("## Open question [%s] — %d attempts, still unresolved" % (a.get("id"), len(a.get("attempts") or [])))
        if a.get("why"):
            L.append("gate reason: %s" % str(a["why"])[:400])
        if a.get("method"):
            L.append("method the queue prescribed: %s" % str(a["method"])[:400])
        for i, at in enumerate(a.get("attempts") or [], 1):
            L.append("  attempt %d (%s): cfg=%s guard=%s sink=%s"
                     % (i, at.get("t"), at.get("cfg"), at.get("guard"), at.get("sink")))
    # Every verdict attached to this row — rejected/confirmed/refuted
    # ★ 2026-09-04: this **must not be truncated.** The adjudicator's reason to exist is "the only one
    #   in this panel that sees the whole history", yet it was cut at `[-6:]`/`[-4:]`/`[-3:]`. It comes
    #   to close a row that hit the same question 4–5 times; if the early attempts are invisible the role does not hold.
    #   Length is controlled by **folding the old ones to one line each** — nothing is dropped.
    def _fold(items, keep, render, brief):
        old_n = max(0, len(items) - keep)
        if old_n:
            L.append("  (the %d older ones are folded to one line each — none are dropped)" % old_n)
            for x in items[:old_n]:
                L.append("  · " + brief(x))
        for x in items[old_n:]:
            render(x)

    vs = [v for v in (STATE.get("verdicts") or []) if str(v.get("target")) == tgt]
    if vs:
        L.append("\n## All %d verdicts recorded on this row" % len(vs))
        for v in vs[:max(0, len(vs) - 6)]:
            L.append("  · [%s] %s — %s" % (v.get("status"), v.get("id"),
                                           str(v.get("claim"))[:110].replace("\n", " ")))
        for v in vs[max(0, len(vs) - 6):]:
            g = v.get("gate") if isinstance(v.get("gate"), dict) else {}
            L.append("- [%s] klass=%s cfg=%s (%s)"
                     % (v.get("status"), v.get("klass"), (g.get("cfg") or {}).get("verdict"),
                        v.get("t")))
            L.append("  claim/reason: %s" % str(v.get("reason") or v.get("claim"))[:400])
            it = v.get("interrogation")
            if isinstance(it, dict):
                L.append("  ↳ interrogator: sustained=%s klass=%s — %s"
                         % (it.get("sustained"), it.get("klass"), str(it.get("reason"))[:300]))
                if it.get("next_method"):
                    L.append("     next observation the interrogator named: %s" % str(it["next_method"])[:250])
    # what the refuter killed (the graveyard)
    gy = [x for x in (STATE.get("graveyard") or []) if str(x.get("target")) == tgt]
    if gy:
        L.append("\n## All %d confirmations the refuter killed" % len(gy))
        for x in gy[:max(0, len(gy) - 4)]:
            L.append("  · [%s] %s" % (x.get("klass"), str(x.get("reason"))[:110].replace("\n", " ")))
        for x in gy[max(0, len(gy) - 4):]:
            L.append("- [%s] %s" % (x.get("klass"), str(x.get("reason"))[:350]))
            if x.get("would_change_my_mind"):
                L.append("  ↳ condition for surviving: %s" % str(x["would_change_my_mind"])[:250])
    # reports that the gate could not express it
    gb = [x for x in (STATE.get("gate_blocks") or []) if str(x.get("target")) == tgt]
    if gb:
        L.append("\n## All %d reports that the gate blocked it (a tool limit, not evidence about the code)"
                 % len(gb))
        for x in gb[:max(0, len(gb) - 3)]:
            L.append("  · %s — %s" % (x.get("gate"), str(x.get("why"))[:100].replace("\n", " ")))
        for x in gb[max(0, len(gb) - 3):]:
            L.append("- %s — %s" % (x.get("gate"), str(x.get("why"))[:300]))
    return "\n".join(L)


def record_adjudication(target, v, n_attempts, raw=""):
    """Record an adjudication **separately.** Put only in the verdict list, tomorrow's scoring could not pick it out."""
    rec = {"target": str(target)[:160], "verdict": v.get("verdict"),
           "reason": str(v.get("reason") or "")[:800],
           "decisive": str(v.get("decisive") or "")[:400],
           "residual_risk": str(v.get("residual_risk") or "")[:400],
           "downgraded_from": v.get("downgraded_from"),
           "fault": v.get("fault"), "via": v.get("via"),
           "attempts": n_attempts, "raw_tail": str(raw or "")[:600],
           "t": time.strftime("%m-%d %H:%M")}
    STATE.setdefault("adjudications", []).append(rec)
    save()
    return rec


def stash_adjudication(target, rec):
    """The adjudicator is a pre-gate that runs **before the verdict is recorded** => there is no verdict to attach to yet.
    Stash it and let `verdict()` stamp it in at recording time. (The same pattern as interrogation/escalation —
    there is no guarantee that editing `inp` in a hook reaches the tool.)"""
    STATE.setdefault("pending_adjudication", {})[str(target)] = rec
    save()


def adjudicated_confirms():
    """Only the confirmations the adjudicator issued. Scoring must count them **separately.**"""
    return [v for v in (STATE.get("verdicts") or [])
            if v.get("status") == "confirmed" and v.get("decided_by") == "adjudicator"]


def adjudication_audit():
    """★ For tomorrow's scoring. One table of what the adjudicator overturned, and on what authority."""
    A = STATE.get("adjudications") or []
    if not A:
        return "no adjudication records."
    import collections
    c = collections.Counter(x.get("verdict") for x in A)
    L = ["%d adjudications — %s" % (len(A), dict(c)),
         "★ Many confirms is a signal in itself: giving the adjudicator confirm authority was a "
         "**one-day operator decision** on 2026-09-04. To roll it back, decide from this table.", ""]
    for x in A:
        L.append("[%s] %s  (%s attempts, %s)" % (x.get("verdict"), str(x.get("target"))[:60],
                                              x.get("attempts"), x.get("t")))
        L.append("   decisive anchor: %s" % (x.get("decisive") or "(none)")[:160])
        L.append("   reason         : %s" % str(x.get("reason"))[:200])
        L.append("   residual risk  : %s" % (x.get("residual_risk") or "(not stated)")[:160])
        if x.get("downgraded_from"):
            L.append("   ※ downgraded from %s (no decisive anchor)" % x["downgraded_from"])
    return "\n".join(L)


# ── a store for the fact that the interrogator **could not break** an inexpressible rejection ────────
# ★ Why it is needed (measured 2026-09-04): `inexpressible` is wired to run the interrogator, and it
#   really ran 19 times with 10 coming back `sustained` (= could not break it). But the hook wrote that
#   fact **into the local variable `_rec`**, and the tool-side `verdict()` recomputes `_reject_gate`
#   from scratch, so the mark vanished. Confirmed by two fingerprints:
#     · zero `passed_by` markers in the entire ledger
#     · 13 leftovers in `pending_interrog` (the ASK branch comes before the consumption point, so they are never read)
#   => hand it over with the `stash_*` pattern the adjudicator and escalator already use. That editing a
#     dict in a hook is not guaranteed to reach the tool is something this repository already knows.
#
# ★ It does **not cancel the ASK**, though. The interrogator's mandate is "when in doubt, the rejection does
#   not stand", so `sustained` is closer to "could not break it" than to "it is right". Automatic promotion
#   would be a change that opens the precision axis, and that is a separate decision. Here it only **passes the fact to the analyst** — the analyst judges.
def stash_inexpr_pass(target, rec):
    STATE.setdefault("pending_inexpr_pass", {})[str(target)] = {
        "cfg": rec.get("cfg"), "klass": rec.get("klass"),
        "reason": str(rec.get("reason") or "")[:400],
        "t": time.strftime("%m-%d %H:%M")}
    save()


def _take_inexpr_pass(target, cfg_verdict):
    """Take it out only when it concerns the same wall (cfg) — attached to a different question it becomes a false assurance."""
    box = STATE.get("pending_inexpr_pass") or {}
    got = box.get(str(target))
    if not got:
        return None
    if cfg_verdict and got.get("cfg") and got["cfg"] != cfg_verdict:
        return None
    return box.pop(str(target), None)


def render_ask(target, a, extra=""):
    """★ Assemble the ASK text **at render time**: the static guidance + accumulated precedents + the interrogator-pass fact.

    Only the static guidance is stored, so the ledger does not grow and the precedents attached are always current.
    """
    m = str((a or {}).get("method") or "")
    try:
        m += rules_for((a or {}).get("cfg"))
    except Exception:
        pass                                   # a failed precedent lookup must not kill the guidance itself
    ip = _take_inexpr_pass(target, (a or {}).get("cfg"))
    if ip:
        m += ("\n\n★ Note — **an independent interrogator could not break this rejection** [%s] %s\n"
              "   The interrogator sees only the claim and the evidence, and runs with 'when in doubt, the rejection does not stand' as its default. "
              "Getting past that is not a weak signal.\n"
              "   What the gate could not decide may be undecided **because it cannot express the shape**, not because your argument is wrong. "
              "Pin down in one sentence which of (A)/(B) above it is, and reject the same target again — "
              "if you judge it still insufficient, write down what is missing."
              % (ip.get("klass") or "-", str(ip.get("reason") or "")[:300]))
    return m + (extra or "")


def ask_kind(cfg_verdict):
    """Is this ASK a missing observation, or a shape the gate cannot express?"""
    return "inexpressible" if cfg_verdict in _ASK_INEXPRESSIBLE else "need_observation"


def ask(rec, why, cfg_verdict=None):
    """When the gate cannot decide, **leave a question** (not a pass)."""
    rec = rec if isinstance(rec, dict) else {}
    # ★ Only **the static guidance** is stored. `render_ask()` attaches the precedents at render time.
    #   Appending them at creation time would (1) freeze stale precedents into the ledger permanently (contrary
    #   to the disposal principle), and (2) grow the ledger by ~700 chars per ASK, **adding to what the conductor
    #   reads** — breaking, inside the same file, the very reason `reports/breaks/` is kept outside the ledger.
    rec["ask"] = {"why": why, "cfg": cfg_verdict, "kind": ask_kind(cfg_verdict),
                  "method": ASK_METHOD.get(cfg_verdict or "",
                                           "Obtain one more observation that the verdict needs."),
                  "t": time.strftime("%m-%d %H:%M")}
    return rec


# ── the reject gate (R1~R3) ───────────────────────────────────────
# Why: until now the gate applied **only to confirmations.** Rejection was free, so false negatives just passed.
# In the pcw.sys run, all 98 anchors of the 18 rejections were genuine, but that was luck, not enforcement.
# And even with genuine anchors **the argument can leak** — the decisive instruction holding up fn0x9's rejection
# (`0x14000C262 jmp` = the failure path does not go to the sink) was **not in the citations at all.**
# => do not rely on citations; **compute.**
_REJECT_KLASS = {
    "guarded":        "a guard blocks the sink — guard=/sink= required; CFG dominance is computed",
    "unreachable":    "unreachable — needs reachability grounds (callpath/xref)",
    "not_controlled": "the value is a constant — needs an anchor at the point where that constant is defined",
    "no_sink":        "there is no dangerous consumer — needs grounds from an exhaustive scan",
    "by_design":      "intended by design — needs a documentation/shipped-tool source",
    "delta_zero":     "the normal path gives the same result — needs a control() measurement record",
    "decompiler_artifact": "a decompiler artifact — needs a disassembly anchor",
    # ★ Added 2026-09-05. Grounds: the conductor's 76 `unrecordable` re-reports **fold into four shapes**
    #   (ahcache 8·7·6·5 times / wcifs 7·6·3 times). With no slot to hold them, eight rounds' worth of verdicts evaporated.
    #   => the two added here are **only ones whose obligation a machine can check.** A klass carrying an
    #   obligation that cannot be checked becomes a free pass — because a klass is by definition "the observation it demands".
    "second_site": "a **different site** of a defect already judged — name the original verdict with origin_id= and put "
                   "this site's anchor in evidence. The grade follows the original",
    "bounded_absence": "absent, exhaustively, **within this range** — state the range with scope= "
                       "(function/section/image) and run an enumeration that actually covers it",
    # ★ Added 2026-09-05 ②. Grounds: wcifs's 12 unrecorded rows **fold into three requests, and 6 of them say
    #   the same thing** — that `guarded` has only one soundness rule ("the value the guard reads must flow
    #   into the sink operand"). **Two structurally different shapes** that do not fit that rule came back
    #   8 and 2 times, and meanwhile wcifs went five rounds in a row with +0 verdicts.
    #   Both klasses have machine-checked obligations — judged from the cited mnemonics.
    # ★ Both readings go into **one slot** (rather than growing the vocabulary), because the obligation is the
    #   same — both end in "enumerate every branch that can produce that state".
    #     (a) the guard constrains a **state**, not an operand
    #     (b) the dangerous **edge itself is impossible** (every predecessor establishes the invariant)
    #   (b) is the shape wcifs `ABORT-ASYM:WcSetUnionContext@0x140023a2c` asked for under the name
    #   `klass=control-flow-exclusion`, and that row stayed `unanalysed` for **six rounds** with
    #   "the analysis is done but there is no slot to write it in".
    "state_precondition": "the guard does not constrain the sink **operand**; it makes the **state in which "
                          "the sink becomes dangerous impossible** — or the dangerous **edge is impossible** "
                          "(every predecessor establishes the invariant). Together with sink=, put **every** branch "
                          "that can produce that state in evidence as conditional-branch anchors (2 or more)",
    "callsite_guarded": "a shared helper, so **global dominance does not hold**, but at this callsite "
                        "the guard dominates — give the anchor of that `call` instruction with callsite= "
                        "and give guard= as well. It makes no claim at all about other callers",
    # ★ Added 2026-09-05 ③. The grounds are **usage**: in a round with the reject gate switched off, of the
    #   klasses the agent actually used, `impact_unproven` (8) and `gated_off` (2) were **values not in
    #   the vocabulary** (with the gate on, all would have been refused). And of 39 gate reports, three
    #   asked for exactly these two. A slot in use that did not exist.
    "gated_off": "the vulnerable arm is **behind a feature/configuration gate whose default is the safe side** — "
                 "name that gate with gate=, and put **both** the **accessor `call` anchor** and "
                 "**the conditional-branch anchor that selects the safe arm** in evidence",
    "impact_unproven": "the sink executes but **no consumer reads its result** — together with sink=, "
                       "state with scope= **over what range you enumerated consumers.** This is a claim "
                       "of absence, so it does not hold without a range",
    # ★ Added 2026-09-06. The grounds are a **tally**: counting the 47 "slot needed" proposals in
    #   `reports/unrecordable/ahcache.sys.md`, one concept is scattered over five names —
    #   bounded_by_saturation 10 · loop_bounded 4 · bounded_nonconstant 3 ·
    #   partially_controlled 2 · range_bounded 2 = **21 proposals**. That row (n=18) tried
    #   `not_controlled` and was **rightly** refused by the CFG check (the caller does influence the
    #   value). There was simply no slot for "influenced, but clamped".
    #   And the 4 privileged_principal proposals (n=8) are "reaches it, but crosses no boundary".
    #   ★ Both have machine-checked obligations. Adding vocabulary without a check turns a klass into a free pass.
    #   ★ immutable_global (3) · intra_function_edge_enumeration (2) were **not added** —
    #     those are not terminal klasses but **kinds of grounds** for existing klasses. Promoting a kind of
    #     grounds to a destination closes rows with no conclusion. Those are a matter of widening the grounds
    #     the checker accepts, a structural change left to the operator (they remain in unrecordable as-is).
    "bounded_by_saturation": "the attacker **influences** the value, but it increases monotonically / saturates "
                             "so the range is clamped — neither `not_controlled` (a constant) nor `guarded` "
                             "(a dominating branch). Together with sink=, put **both** the **accumulation point** "
                             "(an add/inc/sub/imul anchor) and **the conditional-branch anchor that produces "
                             "the clamp** in evidence, and write in scope= **what the upper bound is** "
                             "(monotonicity + the clamp value). Without a clamp anchor this claim is "
                             "just 'not_controlled with words attached'",
    "privileged_principal": "it is reached, but **the minimum principal that reaches the sink already holds "
                            "the privilege the sink grants** — no boundary is crossed. Together with sink=, "
                            "put the **access-check `call` anchor** in evidence, and write in scope= "
                            "**how you established** that minimum principal (device SD / the IOCTL's "
                            "RequiredAccess / AC ACE, etc.). ★ 'because it is Everyone' is not "
                            "grounds — there is a case where a static verdict covered over an AppContainer",
}

# ★ 2026-09-23 — **a state-dependent klass requires binding to a measurement.**
#   Grounds (measured on the mrxsmb night of 09-22): a rejection filed as `gated_off` was broken **4 times**,
#   and all 4 break reasons said the same thing — "the rejection never observed the value that selects the arm …
#   'shipped default 1' is seed metadata, not a measurement of eax". Those 4 round trips took
#   23:48~02:09, i.e. **2 hours 21 minutes** (55% of a 4h16m run).
#   Because the klass's obligation checked only "there is a gate" and let "the default is the safe
#   side" through unchecked. That term is a runtime value and cannot be established by an anchor — **it must be measured.**
#   => it does not look at sentences (no vocabulary dependence). It looks only at the **existence and kind**
#      of the measurement rows `measured(target)` returns. A `trace` is not an observation (closed-axis-trapped-in-notes).
#   ★ The rule is not a kind blacklist — a `trace` is also an observation the harness fired (comment at line 655).
#     Instead it checks **whether that measurement touched the gate you claim**: the `gate_anchors` that
#     gated_off already records (accessor call + safe-arm branch) must overlap the measurement's addresses.
#     On the mrxsmb night this target had 29 measurements, but **zero touched the gate's addresses** —
#     this is where "measured something" is told apart from "measured this value".
#   ★ delta_zero is not included, because `GATE_CONTROL_BEFORE_REJECT` separately demands a positive control
#     (two gates demanding the same thing twice creates a bypass).
_REQUIRES_MEASURE = {"gated_off"}


# ★ 2026-09-06. **What to cite**, per klass. This does not loosen the gate —
#   the "at least 1 citation" requirement stays. But a generic refusal message does not lead to a successful retry.
#   Measured: in case 3 the same row (`fn1_AhcApiRemove … AhcpCacheEntryFilter`, klass=impact_unproven) was
#   blocked with "0 citations" **three times in a row at 01:24·01:25·01:26.** 3 of that round's 5 denials were this.
#   `impact_unproven` is a claim of **absence** ("nobody reads it"), so the agent could not find an instruction to cite —
#   the answer was "the sink instruction itself", and the message never said so.
_CITE_HINT = {
    "guarded":            "the conditional branch you call the guard, AND the sink instruction it dominates",
    "unreachable":        "the call/xref sites you enumerated (the ones that do NOT reach it)",
    "not_controlled":     "the instruction that DEFINES the constant (where the value is written)",
    "no_sink":            "the candidate sites your sweep visited and rejected as non-dangerous",
    "by_design":          "the instructions implementing the documented behaviour",
    "delta_zero":         "the sink instruction whose output you compared across the two arms",
    "decompiler_artifact": "the DISASSEMBLY that contradicts the decompiler output",
    "second_site":        "the instruction at THIS site (the origin verdict covers the other one)",
    "bounded_absence":    "the boundary instructions of the range you enumerated (first/last)",
    "state_precondition": "every conditional branch that could produce the dangerous state (2+)",
    "callsite_guarded":   "the `call` instruction at this callsite, AND the guard branch",
    "gated_off":          "the gate accessor `call`, AND the branch that selects the safe arm",
    "impact_unproven":    "the SINK INSTRUCTION ITSELF — your claim is that nothing reads its "
                          "effect, but the sink is still a real instruction and it is what the "
                          "claim is about. Cite it, plus any consumer-shaped site your sweep "
                          "visited and ruled out",
    "bounded_by_saturation": "the accumulating instruction AND the clamp branch",
    "privileged_principal":  "the access-check `call` that fixes the minimum principal",
}


def _img():
    try:
        import pe as PE
        t = STATE.get("target") or ""
        return PE.PE(t) if t and os.path.exists(t) else None
    except Exception:
        return None


_DF_RE = re.compile(r'double[ _-]?fetch|read twice|re-?read|same read|single[ -]read|'
                    r'ProbeFor|captur|MmProbe|__try', re.I)
_RACE_RE = re.compile(r'race|async|cancel|work ?item|DPC|timer|'
                      r'completion|revalidat|Interlocked|reference ?count|refcount', re.I)


def _is_neither(tgt):
    """Is this a METHOD_NEITHER target? Decided from the name or the surface record."""
    t = (tgt or "").upper()
    if "NEITHER" in t:
        return True
    for k, v in (STATE.get("surface") or {}).items():
        if k == tgt or v.get("target") == tgt:
            blob = (k + " " + json.dumps(v, ensure_ascii=False)).upper()
            if "NEITHER" in blob:
                return True
    return False


def _cites(text):
    """The `0xADDR mnem ops` citations in an evidence text. An empty list when the evidence module is missing."""
    try:
        import evidence as EV
        return EV.parse(text or "")
    except Exception:
        return []


def _reject_open_lead(tgt, args):
    """Check whether this rejection's anchors overlap an **open lead that was already broken (broke)**. If they
    do, return that lead — to stop a dead axis from being rejected again by re-derivation.

    ★ 2026-09-25 — the real incident: the interrogator broke TDIDRAIN 4 times, leaving a reason and
      next_method on every break, yet a later session (and the model itself) **re-derived without reading**
      those grounds and filed it again as a "negative". The reject gate looked only at the klass's form, never at 'was this axis already broken'.
      (memory: broke-rejections-are-open-not-negative · analysis-outran-measurement)
    Grounding: `open_leads(STATE.target)` — scoped to the current image (no cross-contamination), re-derived on every call.
    """
    try:
        blob = " ".join(str(args.get(k) or "")
                        for k in ("evidence", "sink", "item", "target", "reason", "claim"))
        mine = set(re.findall(r'0x[0-9a-fA-F]{6,16}', (blob + " " + str(tgt)).lower()))
        if not mine:
            return None
        for L in open_leads(STATE.get("target")):
            lb = " ".join(str(L.get(k) or "")
                          for k in ("target", "claim", "reason", "next_method", "sink", "guard", "vid"))
            if mine & set(re.findall(r'0x[0-9a-fA-F]{6,16}', lb.lower())):
                return L
    except Exception:
        return None
    return None


def _reject_gate(tgt, args):
    """A rejection must pass measurement too. Returns (ok, message, verification record)."""
    klass = (args.get("klass") or "").strip().lower()
    ev = args.get("evidence", "") or ""
    rec = {"klass": klass}
    img = _img()

    # ★ Block re-derive-and-re-reject: if this axis is an open lead that has already been
    #   broken, show the break's grounds and send the caller to the designed exit
    #   (action='lead'). An explicit rebuttal via contest_lead= is let through
    #   (a refusal with no way forward produces spinning — predicate-cannot-ask).
    _lead = _reject_open_lead(tgt, args)
    if _lead is not None and str(args.get("contest_lead") or "").strip() != str(_lead.get("id")):
        return (False,
                "⚠ The interrogator has already broken this axis — open lead %s (klass=%s, attempt=%s).\n"
                "Do not reject it again by re-deriving it. Rebut the grounds that break left behind first:\n"
                "  reason: %s\n"
                "  next_method: %s\n"
                "The designed exit is `verdict(action='lead', id='%s', how='refuted'|'measured'|"
                "'reinterrogated', why=...)` — it must be closed by a refutation, a measurement or a re-interrogation.\n"
                "If this rejection really does rebut the grounds of that break, attach `contest_lead='%s'` and "
                "write in why **which term of the break you disproved, and how** (then it passes)."
                % (_lead.get("id"), _lead.get("klass"), _lead.get("attempt"),
                   str(_lead.get("reason"))[:400] or "(none)",
                   str(_lead.get("next_method"))[:250] or "(none)",
                   _lead.get("id"), _lead.get("id")),
                rec)

    # ★ second_site — the origin verdict must exist (A/D shape: id lookup + machine-verified anchors)
    if klass == "second_site":
        _oid = str(args.get("origin_id") or "").strip()
        _ids = {str(v.get("id")) for v in (STATE.get("verdicts") or [])}
        if not _oid or _oid not in _ids:
            return (False, "klass='second_site' REQUIRES `origin_id=` naming an EXISTING verdict "
                           "on this ledger (the site whose defect this repeats).\n"
                           "Known ids: %s" % ", ".join(sorted(_ids)[:12]), rec)
        rec["origin_id"] = _oid
    # ★ bounded_absence — a scope declaration is required. The point is that it is not a global absence
    if klass == "bounded_absence" and img is not None:
        # ★ 2026-09-23 — when an absence-form rejection was sent here (R4 (a) above), **make it match the count.**
        #   Narrowing the scope is not the same as pretending not to have seen the counterexamples. It is checked by a number, not by a sentence.
        try:
            import icall as _ic2
            _sc2 = _ic2.scan(img)
            _un2 = [x for x in _sc2["stores"]
                    if not any(c["kind"] == "slot" and c.get("off") == x.get("off")
                               for c in _sc2["icalls"])]
        except Exception:
            _un2 = []
        if _un2:
            try:
                _dec = int(str(args.get("excludes_indirect") or "").strip() or -1)
            except ValueError:
                _dec = -1
            if _dec != len(_un2):
                return (False,
                        "This image has **%d** unresolved function pointers. To file a bounded "
                        "absence, write that count yourself: `excludes_indirect=%d`.\n"
                        "(value given: %s) — matching the count is the minimum proof of 'I saw the counterexamples'. "
                        "Narrowing the scope is not the same as pretending not to have seen the counterexamples."
                        % (len(_un2), len(_un2),
                           args.get("excludes_indirect") if args.get("excludes_indirect") is not None else "none"),
                        rec)
            rec["excludes_indirect"] = len(_un2)
    if klass == "bounded_absence":
        _sc = str(args.get("scope") or "").strip()
        if len(_sc) < 12:
            return (False, "klass='bounded_absence' REQUIRES `scope=` — WHAT RANGE did you "
                           "enumerate exhaustively (a function's .pdata range / a section / the "
                           "whole image)? An absence claim without its range is a global absence "
                           "claim, and that is a different (much stronger) statement.", rec)
        rec["scope_decl"] = _sc[:200]
    # ★ state_precondition — the branches that produce the state must be given **exhaustively.**
    #   Machine check: are there 2+ **conditional branches** among the citations, and is there a sink=?
    #   (Whether the addresses themselves exist is verified separately against the image by R1 below.)
    if klass == "state_precondition":
        _sk = str(args.get("sink") or "").strip()
        _br = [c for c in _cites(ev)
               if (c["mnem"] or "").startswith("j") and c["mnem"] != "jmp"]
        if not _sk or len(_br) < 2:
            return (False, "klass='state_precondition' says the guard constrains STATE, not the "
                           "sink operand. That is a legitimate shape — and it carries its own "
                           "obligation, because 'no state can make this dangerous' is an "
                           "EXHAUSTIVE claim over the branches that produce that state.\n"
                           "REQUIRED: `sink=` plus at least TWO conditional-branch anchors in "
                           "evidence (`0xADDR je ...`) — the branches you enumerated.\n"
                           "Found: sink=%s, conditional branches=%d.\n"
                           "If there is genuinely only one branch, the ordinary `guarded` rule "
                           "applies and you should be able to satisfy it."
                    % ("yes" if _sk else "MISSING", len(_br)), rec)
        rec["precondition_branches"] = ["0x%x" % c["va"] for c in _br][:8]
    # ★ callsite_guarded — that callsite must actually be a `call`.
    #   The point is **narrowing the scope of the claim**: the other callers stay unanalysed.
    if klass == "callsite_guarded":
        _cs = str(args.get("callsite") or "").strip()
        _gd = str(args.get("guard") or "").strip()
        # ★ Joined with a newline, not a space — CITE's ops is `[^\n;/]*`, so putting two
        #   citations on one line makes the second one swallowed as the first one's operands (just measured).
        _calls = [c for c in _cites(ev + "\n" + _cs) if (c["mnem"] or "") == "call"]
        if not _gd or not _calls:
            return (False, "klass='callsite_guarded' scopes the dominance claim to ONE callsite "
                           "of a shared helper — which is exactly right when no per-caller guard "
                           "can dominate globally. Then name the callsite.\n"
                           "REQUIRED: `guard=` plus a `call` anchor (`0xADDR call 0x...`) in "
                           "`callsite=` or in evidence.\n"
                           "Found: guard=%s, call anchors=%d.\n"
                           "NOTE this rejection covers THIS callsite only — the helper's other "
                           "callers stay unaudited and must not be counted as covered."
                    % ("yes" if _gd else "MISSING", len(_calls)), rec)
        rec["callsite"] = ["0x%x" % c["va"] for c in _calls][:4]
        rec["callsite_scoped"] = True
    # ★ gated_off — "the default is the safe side" is proven by **two anchors**: the call that reads
    #   the gate, and the branch that picks the safe arm. One alone only gets as far as "a gate exists".
    #   (Measured grounds: ahcache `Feature_EnsureVerBlockCanHoldFixedInfo` has exactly this shape,
    #    the two anchors `0x1400558cf call` + `0x1400558d6 je`.)
    if klass == "gated_off":
        _gt = str(args.get("gate") or "").strip()
        _cs = _cites(ev)
        _ca = [c for c in _cs if (c["mnem"] or "") == "call"]
        _br = [c for c in _cs if (c["mnem"] or "").startswith("j") and c["mnem"] != "jmp"]
        if not _gt or not _ca or not _br:
            return (False, "klass='gated_off' claims the dangerous arm is behind a gate whose "
                           "DEFAULT selects the safe arm. Two different facts, two anchors:\n"
                           "  (1) the gate is READ here — a `call` anchor (the accessor), and\n"
                           "  (2) the SAFE arm is chosen — the conditional branch anchor.\n"
                           "Plus `gate=` naming it. Found: gate=%s, call=%d, branch=%d.\n"
                           "One anchor only proves 'a gate exists', which is not the claim.\n"
                           "AND: the gate's DEFAULT STATE is itself a claim. If it is a WIL "
                           "feature, the compiled default is a byte in its descriptor and the "
                           "override is a registry key — both are readable. Do not assert it."
                    % ("yes" if _gt else "MISSING", len(_ca), len(_br)), rec)
        rec["gate_name"] = _gt[:120]
        rec["gate_anchors"] = ["0x%x" % c["va"] for c in (_ca + _br)][:6]
    # ★ impact_unproven — "there is no consumer" is an **absence claim.** It does not hold without a scope.
    #   Measured grounds: msquic V-I8-C1-CIBIR was closed as "no consumer" while consumers existed
    #   (`0x14002ac68`/`0x14002ac8a`). Worse, it got there by **xref'ing a different offset.**
    #   Requiring the scope puts in writing which offset was swept, and that misreading becomes visible.
    if klass == "impact_unproven":
        _sk = str(args.get("sink") or "").strip()
        _sc = str(args.get("scope") or "").strip()
        if not _sk or len(_sc) < 12:
            return (False, "klass='impact_unproven' says the sink runs but NOTHING READS its "
                           "effect. That is an ABSENCE claim wearing an impact field's clothes, "
                           "and absence needs its range.\n"
                           "REQUIRED: `sink=` plus `scope=` — WHAT did you enumerate, over WHAT "
                           "range, to conclude there is no consumer? (e.g. 'every read of "
                           "conn+0x6E0/+0x6E8 across the whole image').\n"
                           "Found: sink=%s, scope=%d chars.\n"
                           "This exact klass was filed once with 'no consumer reads it' — and a "
                           "consumer existed; the sweep had been run on the WRONG OFFSET. "
                           "Naming the range is what makes that visible."
                    % ("yes" if _sk else "MISSING", len(_sc)), rec)
        rec["consumer_scope"] = _sc[:200]
    # ★ bounded_by_saturation — "it has influence but gets clamped" is **two facts.**
    #   (1) where the value grows (accumulation)  (2) where it is stopped (the clamp branch)
    #   Without (2) there is no upper bound, and then it is not this klass but undecided.
    #   Measured grounds: the row (n=18) that asked for this shape cited exactly two arithmetic anchors
    #   (`0x1400277b9 add dword ptr [rbx+0xb0], esi; 0x1400277c6 add ...`) — there was no clamp.
    if klass == "bounded_by_saturation":
        _sk = str(args.get("sink") or "").strip()
        _sc = str(args.get("scope") or "").strip()
        _cs = _cites(ev)
        _ar = [c for c in _cs
               if (c["mnem"] or "") in ("add", "inc", "adc", "sub", "dec", "imul", "shl")]
        _br = [c for c in _cs
               if (c["mnem"] or "").startswith("j") and c["mnem"] != "jmp"]
        if not _sk or len(_sc) < 12 or not _ar or not _br:
            return (False, "klass='bounded_by_saturation' says the caller INFLUENCES the value "
                           "but a monotonic/saturating step clamps its range. That is a real "
                           "shape — and it is two facts, so it needs two anchors:\n"
                           "  (1) the ACCUMULATING site — an `add`/`inc`/`sub`/`imul` anchor\n"
                           "  (2) the CLAMP — the conditional branch that stops it\n"
                           "Plus `sink=` (where the bounded value is consumed) and `scope=` "
                           "stating WHAT the bound is (monotonicity + the clamp value).\n"
                           "Found: sink=%s, scope=%d chars, arithmetic=%d, branch=%d.\n"
                           "Without the clamp anchor there is no upper bound in evidence, and "
                           "the claim is `not_controlled` with extra words — which the CFG "
                           "check already refused, correctly, because the caller DOES influence it."
                    % ("yes" if _sk else "MISSING", len(_sc), len(_ar), len(_br)), rec)
        rec["saturation_sites"] = ["0x%x" % c["va"] for c in _ar][:4]
        rec["clamp_branches"] = ["0x%x" % c["va"] for c in _br][:4]
        rec["bound_scope"] = _sc[:200]
    # ★ privileged_principal — this klass is **the easiest to misuse.** If "it is admin anyway"
    #   passes as-is, AppContainer/low-privilege callers vanish wholesale.
    #   So it requires, with an anchor, **what fixed** the minimum principal.
    #   (memory `appcontainer-axis-ace-rule`: an Everyone ACE is not grounds.
    #    `wudfrd-boundary-is-umdf-host`: in reality a PID gate was blocking first.)
    if klass == "privileged_principal":
        _sk = str(args.get("sink") or "").strip()
        _sc = str(args.get("scope") or "").strip()
        _ca = [c for c in _cites(ev) if (c["mnem"] or "") == "call"]
        if not _sk or len(_sc) < 12 or not _ca:
            return (False, "klass='privileged_principal' says the sink is REACHABLE but the "
                           "minimum principal that reaches it ALREADY holds what the sink "
                           "grants — no boundary is crossed. That is a legitimate negative, "
                           "and it stands or falls on ONE question: how do you know that is "
                           "the MINIMUM principal?\n"
                           "REQUIRED: `sink=` plus an access-check `call` anchor in evidence, "
                           "plus `scope=` naming what fixed the minimum principal — the device "
                           "SD, the IOCTL's RequiredAccess, an AppContainer ACE, a PID/token "
                           "test.\n"
                           "Found: sink=%s, scope=%d chars, call anchors=%d.\n"
                           "'Everyone has access so it must be admin-only' is NOT evidence: a "
                           "static read of an ACL has already hidden an AppContainer caller in "
                           "this project, and a PID gate has already turned out to be the real "
                           "boundary where the ACE said otherwise."
                    % ("yes" if _sk else "MISSING", len(_sc), len(_ca)), rec)
        rec["principal_check"] = ["0x%x" % c["va"] for c in _ca][:4]
        rec["principal_scope"] = _sc[:200]
    # R2 — a reason class is mandatory. Each reason carries a different obligation.
    if klass not in _REJECT_KLASS:
        return (False, "A rejection REQUIRES a klass — each reason carries a DIFFERENT measurement obligation.\n"
                + "\n".join("  %-20s %s" % (k, v) for k, v in _REJECT_KLASS.items())
                + "\n\nWithout choosing one, the harness cannot decide what measurement to demand of you.", rec)

    # R2b — a state-dependent klass does not hold without a **binding to a measurement** (_REQUIRES_MEASURE).
    if klass in _REQUIRES_MEASURE:
        _want = {str(x).lower() for x in (rec.get("gate_anchors") or [])}
        _mm = []
        for _m in measured(tgt):
            _mv = {("0x%x" % v) if isinstance(v, int) else str(v).lower()
                   for v in (_m.get("vas") or [])}
            _mv |= {("0x%x" % v) if isinstance(v, int) else str(v).lower()
                    for v in measure_vas(str(_m.get("target") or "") + " " + str(_m.get("why") or ""))}
            if (not _want) or (_mv & _want):
                _mm.append(_m)
        if not _mm:
            return (False,
                    "The truth value of klass=%r depends on **runtime state** — anchors cannot establish it.\n"
                    "**None of this target's measurements touched the gate address you named.**\n"
                    "  · gated_off → actually read the gate's state (kd: featureState / "
                    "registry override / probe). The compiled default byte is metadata, not an observation.\n"
                    "  · delta_zero → actually run the normal path with control().\n"
                    "**Until it is measured it is not a rejection, it is unanalysed** — seal it with `verdict(action='gate_blocked', "
                    "gate='needs-measurement', why=…, would_be=…)` and demand that observation in the next "
                    "round. (Grounds: without this check the same row bounced back and forth 4 times and ate 2h21m.)"
                    % klass, rec)
        rec["measure_binding"] = [
            "%s/%s" % (str(m.get("kind"))[:12], str(m.get("principal_grade") or "?")[:14])
            for m in _mm[:4]]

    # R7 — METHOD_NEITHER is a **double-fetch surface.** The user pointer arrives with no kernel copy.
    #   Measured (WUDFRd, 08-31 overnight): the table had 2 NEITHER entries, yet across the whole corpus
    #   `double fetch` appeared 0 times. The axis itself never ran once.
    if klass in ("guarded", "not_controlled", "no_sink") and _is_neither(tgt):
        if not _DF_RE.search(ev + " " + (args.get("claim") or "")):
            return (True, "", ask(rec,
                    "You are rejecting a METHOD_NEITHER target on a single-read assumption.",
                    "double_fetch_unchecked"))

    # R8 — is this rejecting one side of a registered race pair **having looked only at a single request**?
    if klass in ("guarded", "not_controlled", "no_sink", "unreachable"):
        _partners = [k for k, v in (STATE.get("surface") or {}).items()
                     if v.get("kind") == "race" and tgt in (v.get("pair") or [])]
        if _partners and not _RACE_RE.search(ev + " " + (args.get("claim") or "")):
            rec["race_partners"] = _partners[:3]
            return (True, "", ask(rec,
                    "This target is one side of a registered race pair: " + _partners[0][:120],
                    "race_axis_unchecked"))

    # R1 — machine-verify the anchors (the same G1 as for a confirmation, applied to a rejection)
    if img is not None:
        import evidence as EV
        res, summ = EV.check(img, ev, images=_images_for_anchor())
        rec["anchors"] = summ
        if summ["cites"] == 0 and klass not in ("by_design", "delta_zero"):
            _hint = _CITE_HINT.get(klass)
            return (False, "The rejection basis contains ZERO `0xADDR mnem ops` citations. "
                           "In this domain every basis is re-derivable — if you did not write "
                           "it that way it cannot be verified, and an unverified rejection "
                           "makes coverage a lie.\n"
                           "FORMAT: `0x140042a58 cmp dword ptr [rbx+0xb0], 3` — address, "
                           "mnemonic, operands, one per line.\n"
                           + ("WHAT TO CITE for klass='%s': %s\n" % (klass, _hint) if _hint else
                              "Pick a klass first — what you must cite depends on it.\n")
                           + "This is NOT a request for more evidence: it is a request for the "
                             "evidence you already have, written so the harness can re-derive it "
                             "against this build.", rec)
        if summ["failed"]:
            return (False, "The rejection's anchors do not verify against this build:\n"
                    + EV.render(res, summ)
                    + "\n\nThis is a hallucinated address, a typo, or a STALE-BUILD ANCHOR. Re-derive it.", rec)

    # R5 — `delta_zero` ("the normal path yields the same result") requires a **positive-control measurement.**
    # A measured rejection with no control is indistinguishable from a broken harness.
    if klass == "delta_zero" and not has_control("positive"):
        return (False, "klass='delta_zero' is a MEASURED claim: 'the normal path yields the "
                       "same result'. But there is no positive control in the ledger. Record "
                       "'under conditions that should work, it IS observed' first via "
                       "control(kind='positive') — a broken harness and a zero delta produce "
                       "the same output.", rec)
    # ★ A control **exists, but did it measure the same thing?** C-029: `has_control` is ledger-wide,
    #   so the first control exempted every remaining `delta_zero` on that target. Here it **does not block**;
    #   it computes the overlap and attaches it (refs/05 — the deterministic layer is given no suppression authority).
    #   The promoter takes `delta_zero` as blocking anyway, so the judgement is made there.
    if klass == "delta_zero":
        try:
            rec["control_overlap"] = control_overlap(
                " ".join(str(args.get(k) or "") for k in ("evidence", "claim", "guard", "sink")))
        except Exception as _e:
            rec["control_overlap"] = {"verdict": "error", "why": str(_e)[:120]}

    # R6 — `not_controlled` ("the value is a constant") requires, as an anchor, **the instruction that plants** that constant.
    # Anything not of the form `mov reg, imm` / `mov [mem], imm` is not grounds for a constant.
    if klass == "not_controlled" and img is not None:
        import evidence as EV
        cites = EV.parse(ev)
        ok_const = False
        for c in cites:
            if c["mnem"] in ("mov", "movs", "or", "and", "xor", "lea") and \
                    re.search(r'(?:^|,)\s*(?:0x[0-9a-fA-F]+|\d+)\s*$', c["ops"] or ""):
                ok_const = True
            if c["mnem"] == "xor" and c["ops"] and "," in c["ops"]:
                a1, a2 = [x.strip() for x in c["ops"].split(",")[:2]]
                if a1 == a2:
                    ok_const = True
        if not ok_const:
            return (False, "klass='not_controlled' claims 'the caller cannot change this "
                           "value'. Then you must cite, as an anchor, THE INSTRUCTION THAT "
                           "WRITES THAT CONSTANT (`mov reg, imm` / `xor reg, reg` and "
                           "friends). Your basis does not have one — 'it looks constant' and "
                           "'the constant is written HERE' are different claims.", rec)

    # R4 — an absence-form rejection (no_sink / unreachable) requires an **xref over every executable section.**
    # A failure that looked only at `.text` and wrote "there is no call" really happened (ipt.sys / PAGE).
    if klass in ("no_sink", "unreachable") and img is not None:
        # ★ xref sees **direct references only.** A WDM/KMDF dispatch table is itself an array of function
        #   pointers, so if unresolved function-pointer stores exist, an absence proof does not hold.
        #   As it stands R4 only guarantees "the rejection is documented", not "it is right".
        try:
            import icall as _ic
            _sc = _ic.scan(img)
            _unres = [x for x in _sc["stores"]
                      if not any(c["kind"] == "slot" and c.get("off") == x.get("off")
                                 for c in _sc["icalls"])]
            if _unres:
                rec["indirect_unresolved"] = len(_unres)
                # ★ 2026-09-10 — **saying only "26" lets nobody resolve it.** Measured (ahcache 9168):
                #   most of the 26 are `base='rsp'`, i.e. `mov [rsp+0x20/0x28/0x30/0x38], rax` —
                #   the Windows x64 **argument slots from the 5th argument on** — code that **passes a
                #   callback as an argument**, not a dispatch table. But the matching compares `off` as if it
                #   were a struct offset, so an rsp-relative offset never matches.
                #   ★ They are still not excluded: a passed callback **can be called by the callee**, so it
                #     remains a valid counterexample to an absence claim. The gate stays as it is and **only shows the shape** —
                #     "26" is an opaque wall; a broken-down list is a work order.
                _byb = {}
                for _u in _unres:
                    _byb.setdefault("stack argument (rsp)" if str(_u.get("base")) == "rsp"
                                    else "struct slot (%s)" % _u.get("base"), []).append(_u)
                def _hx(v):
                    """A VA **in hex.** Decimal 5368730976 means nothing to an analyst."""
                    try:
                        return "0x%X" % int(str(v), 0)
                    except (TypeError, ValueError):
                        return str(v)
                _tf = sorted({_hx(_u.get("func")) for _u in _unres})
                rec["indirect_shapes"] = {k: len(v) for k, v in _byb.items()}
                _shape = ("\nbreakdown: " + " · ".join("%s %d" % (k, len(v))
                                                 for k, v in sorted(_byb.items()))
                          + "\n%d functions involved: %s"
                          % (len(_tf), ", ".join(_tf[:8]) + (" …" if len(_tf) > 8 else ""))
                          + "\n★ An `rsp` store is **argument passing, not a dispatch table** (an argument "
                            "slot from the 5th on). The callee can still call that callback, so it remains a "
                            "valid counterexample to the absence claim — the way out is to **point at the callee "
                            "that receives the callback and resolve it there**, or to narrow the claim to a "
                            "range those functions cannot reach.")
                # ★ Format in one go. Written as `A + _shape + B % args`, `%` binds tighter than `+`,
                #   attaches only to the last literal and raises a TypeError — which the `except`
                #   below then swallows, and **the gate passes** (a silent loosening).
                #   The first version of this fix really had that shape. [[refactor-loosens-guards]]
                _head = ("There are %d UNRESOLVED FUNCTION POINTERS and you are filing "
                         "an absence-form rejection (klass='%s')."
                         % (len(_unres), klass))
                _eg = ("\ne.g. %s  %s  -> function %s"
                       % (_hx(_unres[0].get("take")), _unres[0].get("insn", "?"),
                          _hx(_unres[0].get("func"))))
                # ★ 2026-09-23 — the old wording pointed **only at a dead end** ("File it as blocked").
                #   As a result, on mrxsmb 09-23 five siblings whose census was effectively finished
                #   went entirely unrecorded with "only the verdict FORM is refused".
                #   The escape hatch is already in the vocabulary — `bounded_absence` (a scope-bounded absence).
                #   But sending it there **makes the number match**: it passes only when the count of
                #   unresolved pointers is written directly as `excludes_indirect=` (a number, not a sentence).
                _tail = ("\nxref only sees direct references — if those functions can be "
                         "called indirectly, 'there is none' does not hold.\n"
                         "TWO legitimate ways forward — do NOT reword this klass a second time:\n"
                         "  (a) NARROW IT: klass='bounded_absence' with scope= naming the range "
                         "you actually enumerated, plus `excludes_indirect=%d` (the exact count "
                         "above). That files the substance instead of losing it.\n"
                         "  (b) RESOLVE the pointers: point at the callee that receives each "
                         "callback and close it there.\n"
                         "`gate_blocked` is the LAST resort, not the first." % len(_unres))
                return (False, _head + _shape + _eg + _tail, rec)
        except Exception as _e:
            rec["indirect_unresolved"] = "check_failed:%s" % _e
    if klass in ("no_sink", "unreachable") and not has_xref():
        return (False, "klass='%s' is an ABSENCE claim, but the ledger holds no "
                       "all-executable-section xref record.\n"
                       "Run import_xref() first — driver code is scattered across "
                       ".text / PAGE / INIT / fothk. In ipt.sys, .text was 12KB and PAGE 32KB, "
                       "and ALL FIVE authorization calls sat in PAGE. Looking only at .text "
                       "makes authorization appear to be zero." % klass, rec)

    # R3 — `guarded` computes CFG dominance. The pair must be **declared** (no inference).
    if klass == "guarded":
        # ★ 2026-09-04: accepts `guards=` (plural). A shape where **several blocks together** establish
        #   the invariant (a chain / a branch per ingress) cannot be expressed as a single dominance, so the
        #   conductor reported the same thing 14 times from 09-02 on. With n=1 it is identical to `gates()`
        #   **down to the verdict string**, so re-running old verdicts is itself the regression test (test_cutgate.py).
        _gs = args.get("guards")
        if isinstance(_gs, str):
            _gs = [x.strip() for x in re.split(r'[,\s]+', _gs) if x.strip()]
        gset = []
        for _x in (_gs or []):
            try:
                gset.append(int(str(_x), 0))
            except (TypeError, ValueError):
                # ★ 2026-09-10 — **`image!VA` is not a typo, it is a different claim.**
                #   Measured: from 03:17 to 03:19 one row (`class1-mask-delta impact rung`) was refused
                #   4 times in a row, and one of them was `guards=['apphelp!0…']`. The old message said only
                #   "must be VAs (0x…)", so the analyst read it as a format problem, spun for 2 minutes and
                #   closed the row as BLOCKED. It is not a format problem —
                #   **CFG dominance cannot cross images, so `guarded` was the wrong klass to begin with.**
                #   It is not changed to an allowance (that would record having computed something uncomputable).
                #   Instead it **gives the ways forward.**
                _m = re.match(r"^\s*([A-Za-z_][\w.-]*)\s*!\s*(0x[0-9A-Fa-f]+|\d+)\s*$", str(_x))
                if _m:
                    _im, _iva = _m.group(1), _m.group(2)
                    _reg = (STATE.get("images") or {}).get(_im)
                    rec["cross_image_guard"] = {"image": _im, "va": _iva,
                                                "registered": bool(_reg)}
                    _known = ("registered (build %s)" % str(_reg.get("guid"))[:8]
                              if _reg else "**not registered** in this ledger")
                    return (False,
                            "klass='guarded' was given **a guard in a different image**: %r\n"
                            "  · `%s` is %s.\n"
                            "This is not a format problem. `guarded` is a klass that **computes dominance** "
                            "with this image's CFG, and a CFG does not cross the image boundary — "
                            "whether a branch inside another module dominates this module's sink cannot be computed. "
                            "Rewriting it as a VA would still make the computation false.\n"
                            "There are three ways forward:\n"
                            "  ① If the claim is really about something **inside** `%s`, it is a claim about that image — "
                            "make that image the measured build and decide it there.\n"
                            "  ② If a dominating branch really exists inside this image, give **that VA** "
                            "(a check this module makes on its own before the call).\n"
                            "  ③ If neither, file it as `blocked`, but **keep this cross-image anchor as-is** "
                            "— then the next round will not mistake it for a format problem.\n"
                            "(what is registered: `images(action='list')` · to register: "
                            "`images(action='add', name=…, path=…)`)"
                            % (_x, _im, _known, _im), rec)
                return (False, "klass='guarded': `guards=` must be VAs (0x…): could not read %r."
                        % _x, rec)
        g, sk = args.get("guard"), args.get("sink")
        try:
            g = int(str(g), 0) if g is not None else None
            sk = int(str(sk), 0) if sk is not None else None
        except (TypeError, ValueError):
            g = sk = None
        if g is not None and g not in gset:
            gset.insert(0, g)
        if not gset:
            g = None
        elif g is None:
            g = gset[0]
        if g is None or sk is None:
            return (False, "klass='guarded' REQUIRES you to declare guard=<VA of the "
                           "conditional branch> and sink=<VA of the dangerous operation>.\n"
                           "'A guard exists' and 'the guard blocks every path' are different "
                           "claims, and the second one is COMPUTABLE from the CFG — so it is "
                           "not yours to assert.\n"
                           "Why the pair is not inferred from your prose: in practice a wrong "
                           "pair produced a false alarm (fn0xD).", rec)
        # ★ **Store** the pair. Until 2026-08-29 R3 demanded guard/sink and computed with them but
        #   never recorded them. So it was impossible to ask later "was that pair the claim's pair",
        #   and when the policy changed (e.g. revoking bound_compare's authority) **old verdicts could not be re-run.**
        #   In practice WUDFRd `IOCTL_0x80018483` had no pair and could only be approximated with sink_block,
        #   and that approximation produced 39 fake `dominates_only` results.
        rec["guard"], rec["sink"] = g, sk
        if len(gset) > 1:
            rec["guards"] = [hex(x) for x in gset]
        if img is None:
            rec["cfg"] = {"verdict": "no_image"}
            return (True, "UNDECIDABLE - no image", ask(rec, "Could not open the target image, so CFG dominance was not computed", "no_image"))
        # ── R7 — is the declared sink **actually a dangerous operation?**
        #   R3 verifies the pair the analyst picked. Nobody checked whether that pair was the claim's pair.
        #   WUDFRd `IOCTL_0x80018483`: the claim was "dereferences a user pointer without a probe", but
        #   the declared sink was `mov rdx, r13` (a register move). The gate granted `gated` to **an unrelated
        #   pair**, and the real rebuttal (the probe helper, MmUserProbeAddress) was free text nobody
        #   looked at.
        try:
            import cfg as _CFG
            sc = _CFG.sink_class(img, sk)
        except Exception as _e:
            sc = {"class": "unknown", "why": str(_e)}
        rec["sink_class"] = sc
        if sc.get("class") == "reg_only":
            return (False, "R7: the declared sink 0x%X is not a dangerous operation — "
                           "`%s`.\n   %s\n"
                           "Computing that a guard dominates THAT location is IRRELEVANT TO "
                           "THE CLAIM. Give the VA of the actual operation your claim is about "
                           "(dereference / call / write) as the sink."
                           % (sk, sc.get("insn", "?"), sc.get("why", "")), rec)
        try:
            import cfg as CFG
            # A single guard goes to gates(), a set to gates_cut(). At n=1 the two are equivalent —
            # the old path is kept anyway: only if **the function called** is also the same on a re-run
            # can one say "equivalent, not a regression".
            r = (CFG.gates(img, g, sk) if len(gset) <= 1
                 else CFG.gates_cut(img, gset, sk))
            # If it is inter-procedural, hand off to the call graph — the "checked once at the door" shape lives here.
            if r.get("verdict") == "cross_function":
                import authz as AZ
                r2 = AZ.gates_inter(img, g, sk)
                r2["intra"] = "cross_function"
                r = r2
        except Exception as e:
            rec["cfg"] = {"verdict": "error", "why": str(e)}
            return (True, "UNDECIDABLE - CFG computation failed", ask(rec, "CFG computation failed: %s" % e, None))
        rec["cfg"] = r
        if r["verdict"] == "gated_no_authority":
            return (False, "R3 HAS NO AUTHORITY TO REJECT at this location.\n   %s\n"
                           "File it with `verdict(action='blocked', reason=...)` and give "
                           "separate evidence for why the constant / sign is safe."
                           % r["why"], rec)
        if r["verdict"] in ("both_edges", "not_dominated", "other_callers",
                            "not_a_cut", "no_escape", "padded_cut"):
            # ★ 2026-09-05, measured — **the downgrade had only been half done.** These six are hard refusals
            #   `(False, …)`, not `ask`, so GATE_COMPUTE_ONLY never reached them.
            #   In a lunchtime measurement msquic **retried 4 times** with the same id, then filed `gate_blocked` and
            #   folded the axis. That report pinpoints exactly this gate's limit:
            #     *"the guard is enforced ONCE AT THE DOOR and carried forward in a FLAG BIT,
            #       so no intra-procedural dominance relation exists for the second arm."*
            #   => `not_dominated` is a **sound refutation** (more edges, more bypasses), but being unable to
            #     express an **inter-procedural invariant** such as "checked once at the door and carried in a
            #     flag" is still an encoding limit. The adversary does the judging.
            if getattr(_cfgmod(), "GATE_COMPUTE_ONLY", True):
                rec["cfg_refutes"] = {"verdict": r["verdict"], "why": r.get("why", "")[:400]}
                return (True, "CFG REFUTES THE PAIR (attached as evidence): %s"
                        % r.get("why", "")[:200], rec)
            return (False, "THE CFG MEASUREMENT REFUTES THIS REJECTION.\n   %s\n"
                           "A guard existing and a guard dominating the sink are different "
                           "things. Name a different guard, or this is not a rejection."
                           % r["why"], rec)
        if r["verdict"] not in ("gated", "gated_inter", "gated_cut"):
            return (True, "UNDECIDABLE - %s" % r["verdict"],
                    ask(rec, r.get("why", "")[:300], r["verdict"]))
        return (True, "CFG measured: %s" % r["why"], rec)
    return (True, "", rec)


# ★ Catch **exhaustiveness claims** inside the impact fields. "the only consumer is user mode" is an
#   absence claim, and until now no gate caught it: the G2 absence gate looks only at `claim`, and
#   the escalator runs only on `delta=0`/`owner=none`. **"delta is non-zero, but the only consumer is X"**
#   slips straight through the gap between them, and that one sentence sets the grade ceiling on its own.
#   Kept narrow: only when **an exhaustiveness word and a subject word** appear together (widening the detector disarms the gate).
_SOLE_WORD = r"(?:only|sole|solely|nothing\s+else|" \
             r"no\s+other|exclusively|none\s+other)"
_SOLE_SUBJ = r"(?:consumer|reader|caller|mapper|" \
             r"parser|path|kernel)"
_SOLE = re.compile(r"(?:%s[^.\n]{0,60}%s|%s[^.\n]{0,60}%s)" %
                   (_SOLE_WORD, _SOLE_SUBJ, _SOLE_SUBJ, _SOLE_WORD), re.I)

_NONE_OWNER = ("none", "nothing", "no one", "nobody", "n/a", "-")
_NA_DELTA = ("n/a", "na", "not-applicable", "not applicable", "n\\a")


_DEAD_STATUS = ("rejected", "refuted")


def _resolve_row(rid, state=None):
    """Find one id across the whole ledger → (kind, status, klass, reason) or None.

    It looks in three places: verdicts / graveyard / surface. **Exact matches only** —
    allowing partial matches turns this check into prose matching, and that was killed twice by measurement tonight.
    """
    _S = state if state is not None else STATE
    # ★ 2026-09-06 — rejections **have a trust grade.** A row the interrogator broke, or one carrying a
    #   reopen mark, is not a "dead claim" but "a rejection that does not stand". The status string is
    #   left as-is (the consumers' dead-premise verdict must not change); only a marker is prefixed to the reason.
    _gy = {str(g.get("id")): g for g in (_S.get("graveyard") or [])}

    def _doubt(rid_, v_=None):
        g_ = _gy.get(rid_) or {}
        ig = v_.get("interrogation") if isinstance((v_ or {}).get("interrogation"), dict) else {}
        if g_.get("reopened") and not g_.get("rekilled"):
            return "[reopened — this negative was withdrawn] "
        if (ig or {}).get("broke") or g_.get("broke"):
            return "[the interrogator broke it — this negative does not stand] "
        return ""

    for v in (_S.get("verdicts") or []):
        if str(v.get("id")) == rid:
            _d = _doubt(rid, v) if v.get("status") == "rejected" else ""
            return ("verdict", v.get("status"), (v.get("gate") or {}).get("klass"),
                    _d + str(v.get("claim") or "")[:200])
    for g in (_S.get("graveyard") or []):
        if str(g.get("id")) == rid:
            return ("graveyard", "rejected", g.get("klass"),
                    _doubt(rid) + str(g.get("reason") or "")[:200])
    row = (_S.get("surface") or {}).get(rid)
    if isinstance(row, dict):
        return ("surface", row.get("status"), None, str(row.get("why") or "")[:200])
    return None


def _reach_gate(args):
    """★ **Consistency across claims.** Checks whether a premise a confirmation depends on is already dead. (ok, note, ask_why)

    Why (2026-09-06, a harness defect named in §1 of the graded wcifs write-up):
      Every gate is **claim-local** — it looks only at *this* claim's grounds. So two wcifs
      confirmations stood on premises the same ledger had already rejected:
        · the trigger of `S13-OP12-FLAGS3` is port opcode 12, but `PORT-REACH` (AppContainer reach) was
          rejected as `by_design` ⇒ triggering it already requires privilege ⇒ no boundary is crossed
        · the free arm of `S13-UAF-AVLNODE-V2` is `WcRemoveUnionContext`, which is exactly the path
          `S13-R5-PORT8b` (an unprivileged caller can call it) was rejected on
      None of G0~G4 sees this. Filing a confirmation never asked **whether the premises it leans on are alive.**

    ★ **No automatic detection was built. It was measured twice and discarded twice** (measured 2026-09-06):
      · symbol/VA token overlap (thresholds 1/2/3): catches only 1 of the 2 in wcifs, and ahcache raises
        **19~22 per confirmation** (141 rejections crowd into the same code region and share tokens). Over-detection.
      · directional (a rejection's *target* symbol appears in a confirmation's *claim text*): **0 of 2** in wcifs —
        the symbol was not in `S13-R5-PORT8b`'s target but in its claim text. ahcache gives 7~13.
      ⇒ when the reader cannot pick them out, **the writer declares them** (the same conclusion as C-037).

    Obligation: `depends_on=` names the **ids of the rows/verdicts this confirmation borrows reachability/availability from.**
    If it borrows nothing, state `depends_on='none'` **explicitly** (the same escape hatch as the impact gate's `owner='none'`
    — an unsatisfiable gate makes the agent run off to blocked).
    """
    raw = str(args.get("depends_on") or "").strip()
    if not raw:
        # ★ **It does not block.** This is a lesson the impact gate already recorded — "make a gate
        #   unsatisfiable and the agent runs off to blocked, which is worse". Confirmations are a rare slot
        #   (3 of 587 rows), so a hard brake there costs more than it saves.
        #   Instead, **confirmations that declared nothing are made countable** (the second bucket of `dependency_audit`).
        return (True, "",
                "THIS CONFIRMATION DID NOT DECLARE WHAT IT BORROWS REACHABILITY FROM.\n"
                "  depends_on=<id>[,<id>...]  the rows/verdicts whose reachability or "
                "availability this claim rests on (the trigger path, the caller population, "
                "the principal that can drive it).\n"
                "  depends_on='none'          if the claim is self-contained — say it "
                "EXPLICITLY, the same way owner='none' is said.\n"
                "WHY: every other gate here is claim-local. Two wcifs confirmations were "
                "filed on premises this same ledger had already rejected, and nothing noticed. "
                "Naming the dependency is what makes that checkable, and it is what lets "
                "`dependency_audit()` re-flag this row if the premise dies LATER. "
                "Undeclared confirmations are counted separately and stay visible.")
    if raw.lower() in ("none", "-", "nothing"):
        return (True, "", "")

    ids = [x.strip() for x in raw.replace(";", ",").split(",") if x.strip()]
    missing, dead, alive = [], [], []
    for rid in ids:
        r = _resolve_row(rid)
        if r is None:
            missing.append(rid)
        elif r[1] in _DEAD_STATUS or r[0] == "graveyard":
            dead.append((rid, r))
        else:
            alive.append((rid, r[1]))
    if missing:
        known = [str(v.get("id")) for v in (STATE.get("verdicts") or [])][-14:]
        return (False,
                "depends_on names ids that do not exist on this ledger: %s\n"
                "Use an EXACT id from verdicts / graveyard / the surface table — no partial "
                "matches (a fuzzy dependency is not checkable).\nRecent verdict ids: %s"
                % (", ".join(missing), ", ".join(known)), "")
    if dead:
        lines = "\n".join(
            "  · %s  [%s%s]  %s" % (rid, r[1], ("/" + str(r[2])) if r[2] else "", r[3][:150])
            for rid, r in dead)
        return (True, "", 
                "THIS CONFIRMATION RESTS ON A PREMISE THIS LEDGER HAS ALREADY KILLED:\n"
                + lines +
                "\nA rejection can NARROW a claim instead of contradicting it — that is common "
                "and legitimate (a sibling caller ruled out, a wider variant killed). So this "
                "is a QUESTION, not a refusal. Answer one of:\n"
                "  (a) the rejection kills a DIFFERENT claim than the one I depend on — say "
                "which, and why the part I need survives;\n"
                "  (b) the rejection is wrong and should be reopened — "
                "`verdict(action='reopen', ...)` with the new observation;\n"
                "  (c) it does undercut me — then this is not a confirmation. Lower it.\n"
                "★ If the dependency dies LATER, `dependency_audit()` will surface this row "
                "again. That is the point of declaring it.")
    return (True, "", "")


def surface_sites(state=None):
    """★ **Count by site, not by row.** Returns: (site count, row count, duplicate row count, top duplicates)

    ★ Measured 2026-09-07 — surface keys are free strings, so several rows bite the same address:
      ahcache 620 rows / 309 unique addresses / 267 rows biting a duplicate, wcifs 583 rows / 333 / 377.
      A single `0x140038850` is bitten separately by several rows
      (`IOCTL f6 -> 0x140038850`, `0x140038850`, `S14-AZ-f6_…_ungated`).
      The result is twofold: ① **the denominator is structurally inflated** — the 620 in "607 of 620 rows
      unanalysed" is not the number of unique things to investigate ② **one site's history is scattered** — the same
      address is a verdict in one row and unanalysed in another.
    ★ It does not merge. Merging the ledger automatically cannot be undone, and which row's verdict represents
      the whole site is not for the machine to decide. **Only the counting is fixed.**
    """
    _S = (state if state is not None else STATE).get("surface") or {}
    import collections as _c
    own = _c.defaultdict(list)
    noaddr = 0
    for k, v in _S.items():
        va = set(x.lower() for x in re.findall(r'0x[0-9a-fA-F]{6,16}', k))
        if not va:
            noaddr += 1
            continue
        for a in va:
            own[a].append(k)
    dup_rows = {k for ks in own.values() if len(ks) > 1 for k in ks}
    top = sorted(((a, ks) for a, ks in own.items() if len(ks) > 1),
                 key=lambda x: -len(x[1]))[:5]
    # site count = unique addresses + rows with no address (each counted as its own site)
    return len(own) + noaddr, len(_S), len(dup_rows), top


def site_history(va, state=None):
    """Collect **the states of the rows biting one address into one line.** Makes the scattered history visible."""
    _S = (state if state is not None else STATE).get("surface") or {}
    a = str(va).lower()
    out = []
    for k, v in _S.items():
        if a in k.lower():
            out.append((k[:70], v.get("status"), bool(v.get("blocked"))))
    return out


def graveyard_trust(state=None, limit=40):
    """★ **Count the graveyard by grade.** The agent reads the graveyard as fact — so the next round is wrong
    exactly as much as the graveyard is. Returns: (counts, suspect_rows, n_suspect)

    Grades (exclusive, top first):
      · `orphan`      there is no verdict record at all — the reason and interrogation history cannot be cross-checked
      · `reopened`    carries a reopen mark yet is still in the graveyard (= a withdrawn negative)
      · `broke`       the interrogator broke it yet it is still there (= a negative that does not stand)
      · `unexamined`  **never once went through an adversary**
      · `verified`    the interrogator could not break it — only this is a verified negative

    ★ Why this is needed (measured 2026-09-06): of ahcache's 167 graveyard rows only **54 (32%)** were `verified`,
      and of wcifs's 76 only **25 (33%)**. The rest were loaded into the priming with the same weight and went out as
      "CLAIMS ALREADY KILLED (do not resurrect)".
    """
    _S = state if state is not None else STATE
    V = {str(v.get("id")): v for v in (_S.get("verdicts") or [])}
    # ★ Self-correction 2026-09-07 — in the first version `orphan` **swallowed rows closed from the candidate set.**
    #   `close_candidate` puts them in the graveyard under the candidate id (`C<n>`). That row's grounds live in
    #   `candidates`, not `verdicts` (claim/basis/evidence/anchors are all there). Measured: ahcache 10 · wcifs 14 were
    #   all that case, and **real orphans were 0**. Counting "no verdict" without looking at the other store
    #   is the same error as [[queue-mixes-two-kinds]].
    CAND = {str(c.get("id")): c for c in (_S.get("candidates") or [])}
    counts = {"orphan": 0, "candidate": 0, "reopened": 0, "broke": 0,
              "unexamined": 0, "verified": 0}
    rows = []
    for g in (_S.get("graveyard") or []):
        gid = str(g.get("id"))
        v = V.get(gid)
        ig = v.get("interrogation") if isinstance((v or {}).get("interrogation"), dict) else {}
        if v is None and gid in CAND:
            # A row closed as a candidate. Whether it went through an adversary is told by origin.
            k = "verified" if g.get("origin") == "refuted" else "candidate"
        elif v is None:
            k = "orphan"
        elif g.get("reopened") and not g.get("rekilled"):
            k = "reopened"
        elif (ig or {}).get("broke") or g.get("broke"):
            k = "broke"
        elif v.get("interrogated") is True or g.get("interrogated") is True:
            k = "verified"
        else:
            k = "unexamined"
        counts[k] += 1
        if k in ("reopened", "broke"):
            rows.append({"id": gid, "grade": k, "klass": g.get("klass"),
                         "target": str(g.get("target"))[:90],
                         "why": str((ig or {}).get("reason")
                                    or ((g.get("reopens") or [{}])[-1].get("why")))[:160]})
    return counts, rows[:limit], len(rows)


def untouched_regions(image_path, state=None, page=0x1000, limit=12):
    """Executable regions that **no verdict or surface row has ever mentioned by address.** (ranges, function count, total bytes)

    ★ Why (measured in the 2026-09-09 night run): the conductor's pick schema is *"lead id or track name **that
      exists in the digest**"*, yet the digest had **no hunting ground at all.** So even when the operator's goal
      was "find variants of the root cause population-wide", the conductor **had no means** to route outside
      leads/tracks — cases 1·2·3 picked a lead/track in a row, and round 3 read the goal and **diagnosed it itself**
      as *"drift: five rounds closed only negatives on adjacent axes"* while still picking a lead.
      Not disobedience but a structural inability.

    ★ **It is not filed as surface rows.** This is a view, not a denominator — filing it would have the harness
      itself commit the "denominator inflation" the seed forbids. It is only **shown** to the conductor.

    ★ The instrument's limit is stated alongside: "mentioned" means **the address appeared in a verdict/surface
      string**, not that the code was analysed. Both under- and over-counting are possible.
    """
    import struct
    _S = state if state is not None else STATE
    try:
        raw = open(image_path, "rb").read()
        off = struct.unpack_from("<I", raw, 0x3c)[0]
        nsec = struct.unpack_from("<H", raw, off + 6)[0]
        optsz = struct.unpack_from("<H", raw, off + 20)[0]
        base = struct.unpack_from("<Q", raw, off + 24 + 24)[0]
        sbase = off + 24 + optsz
    except Exception as e:
        return [], 0, 0
    buckets, execranges = {}, []
    for i in range(nsec):
        e = sbase + i * 40
        nm = raw[e:e + 8].rstrip(b"\0").decode("ascii", "replace")
        vs, va = struct.unpack_from("<II", raw, e + 8)[0:2]
        ch = struct.unpack_from("<I", raw, e + 36)[0]
        if ch & 0x20000000:                       # MEM_EXECUTE
            execranges.append((base + va, base + va + vs, nm))
            for b in range((base + va) // page, (base + va + vs + page - 1) // page):
                buckets[b] = nm
    if not buckets:
        return [], 0, 0
    seen = set()
    _re = re.compile(r'0x([0-9a-fA-F]{6,16})')
    for blob in ([" ".join(str(v.get(k) or "") for k in ("target", "id", "claim"))
                  for v in (_S.get("verdicts") or [])]
                 + list((_S.get("surface") or {}).keys())
                 + [str(a.get("target") or "") for a in (_S.get("asks") or [])]):
        for h in _re.findall(blob):
            seen.add(int(h, 16) // page)
    un = sorted(b for b in buckets if b not in seen)
    runs = []
    for b in un:
        if runs and b == runs[-1][-1] + 1:
            runs[-1].append(b)
        else:
            runs.append([b])
    # Count the functions in each range from .pdata — "how many functions" is a unit you can choose by, "how many KB left" is not
    fns = []
    try:
        import pe as _PE
        fns = [f[0] for f in _PE.PE(image_path).runtime_functions()]
    except Exception:
        pass
    rows, tot_f, tot_b = [], 0, 0
    for r in runs:
        lo, hi = r[0] * page, (r[-1] + 1) * page - 1
        nf = sum(1 for a in fns if lo <= a <= hi)
        sec = buckets[r[0]]
        rows.append({"lo": lo, "hi": hi, "sec": sec, "funcs": nf, "bytes": hi - lo + 1})
        tot_f += nf
        tot_b += hi - lo + 1
    rows.sort(key=lambda x: -x["funcs"])
    return rows[:limit], tot_f, tot_b


def untouched_digest(image_path, state=None, n=6):
    """`untouched_regions` as a string to carry in the conductor digest. An empty string when there is nothing."""
    try:
        rows, tf, tb = untouched_regions(image_path, state)
    except Exception as e:
        return "\n[untouched executable regions: computation failed %s]" % type(e).__name__
    if not rows:
        return ""
    L = ["", "[★ executable regions no row has mentioned by address yet — %d ranges · %d functions · %dKB]"
         % (len(rows), tf, tb // 1024),
         "  These are **not surface rows** (not a denominator). Under a hunting goal, `pick.what='row'`",
         "  can name one of these ranges — the only way out of leads/tracks.",
         "  ※ 'mentioned' means the address appeared in a string, not that it was analysed."]
    for r in rows[:n]:
        L.append("  0x%x–0x%x [%s] %d functions · %dKB"
                 % (r["lo"], r["hi"], r["sec"], r["funcs"], r["bytes"] // 1024))
    return "\n".join(L)


def resisted(target=None, state=None, min_n=2, limit=40):
    """★ **Rows somebody tried to kill and failed.** (rows, counts) — a queue in a direction this harness did not have.

    Why (measured 2026-09-08, the whole ledger):
      All the pressure in this harness is "killing". The refuter comes for confirmations, the interrogator for rejections.
      But **a failed kill goes nowhere.** When a rejection attempt is denied by a gate it piles up only per rule
      in the flat `denials` log (`denial_report` answers "which rule caught it", not "which row held out"),
      and when the CFG refutes a pair, `GATE_COMPUTE_ONLY` just attaches it as evidence and moves on.
      Measured: 30 targets with a rejection attempt denied **2+ times** (12 at most), 27 `cfg_refutes`.
      And some rows **overlap** on axes — `dispatcher 0x140038360` held 4 denials +
      cfg_refutes(no_escape) + an interrogator break + reopened all at once.

    ★ There is **no** automatic promotion. Changing state here would use "quantity as a proxy for quality"
      (`threshold-triggers-audit-not-rollback`). This function only builds the queue — re-analysis is for a human /
      the next round.

    ★ Denied 5 times under the same klass and denied under **3 different klasses** are different events.
      The former is a paperwork problem (pair declaration, citation format); the latter means **several death
      hypotheses all failed.** So `klasses` is counted separately and used as the top ranking key.

    ★ The `broke` axis is **only counted.** The `reports/breaks/` lead queue already owns that queue, so
      closing it here again would have two queues ask for the same work twice (`queue-mixes-two-kinds`).
      Instead the row's lead id is carried along **to prevent duplicate work.**

    ★ Rows with zero resistance **do not appear** in the queue — that is not 0 but "never attempted", and it
      belongs to `worklist`/`unfinished`. Two values are not mixed in one slot.
    """
    _S = state if state is not None else STATE
    K = lambda t: str(t or "")[:100]
    rows = {}

    def _row(t):
        return rows.setdefault(K(t), {"target": K(t), "denied": 0, "klasses": set(),
                                      "cfg": [], "broke": 0, "lead_ids": [],
                                      "verdicts": [], "last_t": ""})

    # axis B — a rejection attempt was denied by a gate
    for d in (_S.get("denials") or []):
        if str(d.get("act")) != "reject":
            continue
        r = _row(d.get("target"))
        r["denied"] += 1
        if d.get("klass"):
            r["klasses"].add(str(d["klass"]))
        if str(d.get("t") or "") > r["last_t"]:
            r["last_t"] = str(d.get("t") or "")

    # axis C — the CFG refuted the pair, yet the rejection was filed
    # axis A — the interrogator broke that rejection (only counted)
    _gy = {str(g.get("id")): g for g in (_S.get("graveyard") or [])}
    for v in (_S.get("verdicts") or []):
        if str(v.get("status")) != "rejected":
            continue
        g = v.get("gate") or {}
        cr = g.get("cfg_refutes")
        ig = v.get("interrogation") if isinstance(v.get("interrogation"), dict) else {}
        broke = bool((ig or {}).get("broke")) or bool(_gy.get(str(v.get("id")), {}).get("broke"))
        if not cr and not broke:
            continue
        r = _row(v.get("target"))
        r["verdicts"].append(str(v.get("id")))
        if cr:
            r["cfg"].append(str(cr.get("verdict") or "?"))
        if broke:
            r["broke"] += 1
        if str(v.get("t") or "") > r["last_t"]:
            r["last_t"] = str(v.get("t") or "")

    # carry the lead id along (prevents duplicate work)
    try:
        for b in breaks(_S.get("target"), open_only=True, queue="lead"):
            k = K(b.get("target"))
            if k in rows:
                rows[k]["lead_ids"].append(str(b.get("id")))
    except Exception:
        pass

    out = []
    for r in rows.values():
        r["klasses"] = sorted(r["klasses"])
        r["axes"] = ((1 if r["denied"] else 0) + (1 if r["cfg"] else 0)
                     + (1 if r["broke"] else 0))
        r["score"] = (r["axes"], len(r["klasses"]), r["denied"] + len(r["cfg"]) + r["broke"])
        # ★ Each axis has a different threshold — because the signals differ in strength.
        #   · `cfg` **gets in with 1.** The machine computed "the declared pair does not dominate", yet
        #     the rejection was filed, and right now **no consumer at all** looks at that.
        #   · `denied` gets in only **at min_n or more.** Once can be a paperwork problem (pair declaration, citation
        #     format). It has to repeat to be a property of the row.
        #   · `broke` **alone** does not get in — the `reports/breaks/` lead queue already asks for that work.
        #     Here it only means something **when it overlaps** another axis (the overlap is why this queue exists).
        if r["cfg"] or r["axes"] >= 2 or r["denied"] >= min_n:
            out.append(r)
    out.sort(key=lambda r: r["score"], reverse=True)
    counts = {"rows": len(out), "multi_axis": sum(1 for r in out if r["axes"] >= 2),
              "denied_only": sum(1 for r in out if r["axes"] == 1 and r["denied"]),
              "cfg_refuted": sum(1 for r in out if r["cfg"]),
              "attempts_total": sum(r["denied"] + len(r["cfg"]) + r["broke"] for r in out)}
    return out[:limit], counts


def backfill_ask_fields(state=None):
    """**Backfill** `kind`/`by` onto old asks. (kind filled, by filled)

    ★ Nothing is invented — both are **derived from fields already present**:
        kind ← `ask_kind(cfg)`   (left alone when cfg is missing; 0 and unmeasured are not mixed)
        by   ← the existing `by`, otherwise the id prefix (CQ/RQ/XQ) — `gate` (the old default) if not in the vocabulary
    ★ Why it is needed: all 231/231 · 125/125 were `kind=None`, so **there was no axis to sort a single queue
      by.** Fixing only new rows would leave the old 356 rows stuck at the bottom/middle of the ranking forever.
    """
    S = state if state is not None else STATE
    nk = nb = 0
    for a in (S.get("asks") or []):
        if not a.get("kind") and a.get("cfg"):
            a["kind"] = ask_kind(a.get("cfg"))
            nk += 1
        _b = normalize_ask_by(a.get("by"), a.get("id"))
        if a.get("by") != _b:
            a["by"] = _b
            nb += 1
    return nk, nb


def ask_queue(state=None, n=10, audience="analyst"):
    """★ **One queue.** Rendered sorted by the measured yield per source.

    ★ What this function answers: "of the asks open now, **which is most likely to get answered.**"
      The grounds for source as the ranking axis are measured on the ledger — `by=conductor` had **0**
      answered of 185 in ahcache, while gate·refuter had 15 of 46 (32.6%). Yet 113/115 of the open asks
      were the conductor's, so however the rotating window turned, practically only conductor asks were visible.
    """
    S = state if state is not None else STATE
    Q = open_asks(S, audience=audience, rank=True, include_leads=True)
    if not Q:
        return ""
    y = ask_yield(S)
    import collections as _c
    byo = _c.Counter(normalize_ask_by(a.get("by"), a.get("id")) for a in Q)
    byk = _c.Counter(str(a.get("kind") or "(unclassified)") for a in Q)
    L = ["## ⟂ Ask queue — %d open asks (it is one queue: gate·refuter·interrogator·resisted·conductor)" % len(Q), ""]
    L.append("  sources: " + " · ".join("%s %d" % kv for kv in byo.most_common()))
    L.append("  kinds: " + " · ".join("%s %d" % kv for kv in byk.most_common()))
    _yl = [("%s %d/%d closed (total %d)" % (o, d["answered"], d["closed"], d["n"]) +
            ("" if d["rate"] is None else " (%.0f%%)" % (d["rate"] * 100)))
           for o, d in sorted(y.items(), key=lambda kv: -(kv[1]["rate"] or 0))]
    L.append("  this ledger's **answered rate** per source: " + " · ".join(_yl))
    L += ["  ★ Sort order is yield > attempts > oldest. `inexpressible` is not a lack of observation,",
          "    it is **the gate being unable to express that shape** — the answer is `gate_blocked`, not a verdict.", ""]
    for a in Q[:n]:
        o = normalize_ask_by(a.get("by"), a.get("id"))
        L.append("- `%s` [%s/%s] %s%s"
                 % (a.get("id"), o, a.get("kind") or "?", str(a.get("target"))[:62],
                    ("  (%d attempts)" % len(a.get("attempts") or []))
                    if (a.get("attempts") or []) else ""))
        if a.get("why"):
            L.append("    why: %s" % str(a["why"]).replace("\n", " ")[:200])
        if a.get("method"):
            L.append("    next move: %s" % str(a["method"]).replace("\n", " ")[:260])
        if a.get("_close_via"):
            L.append("    close: %s" % a["_close_via"])
    return "\n".join(L)


def resisted_to_asks(target=None, state=None, save_now=True):
    """★ **Emit the resisted rows as asks.** No separate queue. (created, attempts bumped)

    ★ Why asks and not a queue (pointed out by the operator, 2026-09-08):
      With a queue per kind, which queue each round looks at becomes arbitrary and the queues compete.
      Measurement showed exactly that — ahcache had resisted 31 · re-audit 34 · leads 23 standing with
      overlaps of 4/12/8, and a 45-minute case cannot look at all three.
      And **a single ask queue already existed** (`asks`). The fields (target/claim/klass/guard/sink/
      cfg/why/method/status/**attempts**) and the mechanism (re-asking the same row bumps attempts instead of
      adding a row, `render_ask` assembles precedents at render time) fit. What was missing was only **a sort axis**,
      and that is `kind` (computed but never stored) and `by` (the source).

    ★ That resisted rows **do not overlap** `asks` is why this function exists: the measured intersection is
      ahcache 0/31 · wcifs 1/8. `asks` creates an ask only when a gate is UNDECIDABLE, and
      DENIED (requirement not met) and CFG refutations created none. The same "failed to kill",
      yet only one side had a queue.

    ★ Nothing is invented: with only one axis and only one klass it is most likely **a paperwork problem**, so
      no ask is emitted (needs `axes>=2`, or 2+ klasses, or a CFG refutation).
    """
    S = state if state is not None else STATE
    rows, _ = resisted(target, S)
    made = bumped = 0
    for r in rows:
        multi_klass = len(r["klasses"]) >= 2
        if not (r["axes"] >= 2 or multi_klass or r["cfg"]):
            continue
        tgt = r["target"]
        # The CFG refuted it = the gate **cannot express** this invariant (inter-function / one check at the door).
        kind = "inexpressible" if r["cfg"] else "need_observation"
        if multi_klass:
            why = ("failed to kill it — %d different death hypotheses (%s) all failed"
                   % (len(r["klasses"]), ", ".join(r["klasses"][:4])))
            method = ("If the denial reason **was different every time**, it is not a paperwork problem. Ask whether "
                      "this row will not die because it is a defect — trying to write the three impact fields of "
                      "`confirm` is the fastest test (not being able to write them is an answer too). "
                      "If you can write them, that is the answer; if not, close it honestly with `exhaust`.")
        elif r["cfg"]:
            why = ("the machine refuted your pair, yet the rejection was filed (%s)" % ",".join(sorted(set(r["cfg"]))[:3]))
            method = ("Re-declare the pair (the whole cut with `guards=`), or if the invariant is **inter-function** "
                      "(checked once at the door and carried in a flag), that is something this gate "
                      "cannot express — record what could not be written with `gate_blocked`.")
        else:
            why = "failed to kill it %d times (denied %d · broke %d)" % (
                r["denied"] + r["broke"], r["denied"], r["broke"])
            method = "If it was denied repeatedly under the same klass, meet the requirement and file it again. That closes it too."
        if r["lead_ids"]:
            method += ("  ★ This row also stands as lead %s — close it **there** (two queues do not ask for the same "
                       "work twice)." % ",".join(r["lead_ids"][:2]))
        # ★ Self-correction 2026-09-08 — the id was **position-based** (`XQ%d`). This function runs **both** on the
        #   seed render (a file copy) and on the live ledger, so with position-based ids the same row gets
        #   **different ids** in the two places: the `XQ3` the analyst saw in the SEED cannot be found
        #   with `verdict(action='asks')`. ⇒ build it **deterministically from the target.**
        qid = "XQ-" + hashlib.sha1(tgt.encode("utf-8", "replace")).hexdigest()[:8]
        cur = r["denied"] + len(r["cfg"]) + r["broke"]      # this row's total resistance
        # ★ Match **open rows only.** Matching by id alone would bump attempts on a closed XQ,
        #   and the "closed ones are not revived" branch below would never be reached (a test caught it).
        prev = None
        for q in (S.get("asks") or []):
            if (q.get("status") or "open") != "open":
                continue
            if str(q.get("id")) == qid or q.get("target") == tgt:
                prev = q
                break
        if prev is not None:
            # ★ **Do not inflate attempts by regeneration.** This function runs every round (and on every seed
            #   render) — bumping attempts unconditionally would turn the second ranking axis into "how many times it ran".
            #   Bump only when the resistance **actually grew.**
            if cur > int(prev.get("resist_n") or 0):
                prev.setdefault("attempts", []).append(
                    {"t": time.strftime("%m-%d %H:%M"), "cfg": "resisted", "kind": kind})
                prev["resist_n"] = cur
                if kind == "inexpressible":
                    prev["kind"] = "inexpressible"
                elif not prev.get("kind"):
                    prev["kind"] = kind
                bumped += 1
            continue
        # ★ A closed XQ is **not revived.** If resistance grew after that, it is a new observation made after
        #   closing, so it is **a new ask** (`-2`). Reviving it would interlock with `_ask_close`'s bulk closing
        #   and flip between open↔closed forever.
        _closed = [q for q in (S.get("asks") or []) if str(q.get("id")).startswith(qid)]
        if _closed:
            if cur <= max(int(q.get("resist_n") or 0) for q in _closed):
                continue
            qid = "%s-%d" % (qid, len(_closed) + 1)
        S.setdefault("asks", []).append(
            {"id": qid, "target": tgt,
             "why": why, "method": method, "kind": kind, "by": "resisted",
             "cfg": (sorted(set(r["cfg"]))[0] if r["cfg"] else None),
             "klass": (r["klasses"][0] if r["klasses"] else None),
             "resist_n": cur,
             "status": "open", "attempts": [], "t": time.strftime("%m-%d %H:%M")})
        made += 1
    if save_now and state is None and (made or bumped):
        save()
    return made, bumped


def resisted_digest(target=None, state=None, n=8):
    """`resisted()` as a string to carry in the seed/status block. An empty string when there is nothing."""
    try:
        rows, c = resisted(target, state)
    except Exception as _e:
        return "(⛔ resisted failed: %s)" % _e
    if not rows:
        return ""
    L = ["## ⟂ Resisted queue — %d **rows somebody tried to kill and failed** (2+ axes: %d)"
         % (c["rows"], c["multi_axis"]), "",
         "  Someone already tried to kill these rows and **failed.** A denial may be a paperwork problem, but",
         "  **a row denied repeatedly under different klasses** means several death hypotheses failed.",
         "  `cfg` means the machine refuted the pair yet the rejection was filed; `broke` means the interrogator broke it.",
         "  ★ There is no automatic promotion — this is **a re-analysis list**, not a list of confirmation candidates.", ""]
    for r in rows[:n]:
        bits = []
        if r["denied"]:
            bits.append("denied %d times%s" % (r["denied"],
                        (" [klass %s]" % ",".join(r["klasses"][:4])) if r["klasses"] else ""))
        if r["cfg"]:
            bits.append("CFG refuted %s" % ",".join(sorted(set(r["cfg"]))[:3]))
        if r["broke"]:
            bits.append("interrogator broke %d" % r["broke"])
        L.append("- %s" % r["target"][:78])
        L.append("    %s%s" % (" · ".join(bits),
                               ("  (lead %s — close it there)" % ",".join(r["lead_ids"][:2]))
                               if r["lead_ids"] else ""))
    L += ["", "The full list: `verdict(action='resisted')`."]
    return "\n".join(L)


def dependency_audit(limit=40, state=None):
    """Return, by name, the confirmations whose **declared premise is dead.** (rows, n)

    ★ The gate looks only at the **moment** of filing. Premises die later — and then nobody looks again.
      This function is that look back. The same family as `reach_unknown` / `dead_claim_open`:
      **make what the gate requires enumerable.**
    """
    # ★ It takes a **snapshot** via `state=`. `nightrun.build_carryover` builds the carry-over from a dict
    #   read from a file and does not use `ledger.STATE` — written to read STATE only, it would **quietly
    #   return 0** in the parent process. This trap was stepped on twice today
    #   (`verify-through-the-production-path`). One copy of the logic, only the source is an argument.
    _S = state if state is not None else STATE
    out, undeclared = [], []
    for v in (_S.get("verdicts") or []):
        if v.get("status") != "confirmed":
            continue
        dep = str(v.get("depends_on") or "").strip()
        if not dep:
            # ★ Second bucket: **confirmations that made no declaration at all.** Since it was decided not to block,
            #   this is the only visibility there is. Not counting them would reproduce "optional mechanisms go unused"
            #   as-is (scope: used once in 560 rows, while the hint went out 104 times).
            undeclared.append({"verdict": str(v.get("id")), "target": str(v.get("target"))[:80]})
            continue
        if dep.lower() in ("none", "-", "nothing"):
            continue
        for rid in [x.strip() for x in dep.replace(";", ",").split(",") if x.strip()]:
            r = _resolve_row(rid, _S)
            if r is not None and (r[1] in _DEAD_STATUS or r[0] == "graveyard"):
                out.append({"verdict": str(v.get("id")), "target": str(v.get("target"))[:80],
                            "depends_on": rid, "now": r[1], "klass": r[2]})
    return out[:limit], len(out), undeclared[:limit], len(undeclared)


def dead_premise_rejections(limit=20, state=None):
    """The **rejections** whose declared premise is dead. (rows, n)

    ★ 2026-09-10 — `dependency_audit` looks only at `status == "confirmed"`. But in this domain
      **a single rejection is a decision that loses a bug for good** (CLAUDE.md), and premises die later.
      Measured: 6 of ahcache's 195 rejections declared a premise, and **nobody ever looks at those 6 again.**
      `rejaudit` only grades by gate quality and does not look at premise death — a different axis.

      It uses **the same rule** as the confirmation side. The return shape is kept separate so as not to break
      the existing callers' 4-tuple unpacking (avoiding `built-but-never-wired` must not cause a regression).
    """
    _S = state if state is not None else STATE
    out = []
    for v in (_S.get("verdicts") or []):
        if v.get("status") != "rejected":
            continue
        dep = str(v.get("depends_on") or "").strip()
        if not dep or dep.lower() in ("none", "-", "nothing"):
            continue
        for rid in [x.strip() for x in dep.replace(";", ",").split(",") if x.strip()]:
            r = _resolve_row(rid, _S)
            if r is not None and (r[1] in _DEAD_STATUS or r[0] == "graveyard"):
                out.append({"verdict": str(v.get("id")), "target": str(v.get("target"))[:80],
                            "depends_on": rid, "now": r[1], "klass": r[2]})
    return out[:limit], len(out)


def _impact_gate(args):
    """★ L2 — **a confirmation must bring the three impact fields.** (ok, note, impact)

    Why: all the pressure in this harness pointed down (preventing false positives). So it simply
    stopped at "confirmed a check bypass", and the findings that actually paid off were the result of
    **turning the question once** at that point. The three fields carry over §1~§3 of `methodology/references/escalation.md` as-is.

      owner    the **owner** of these bytes/this resource. With none, there is no boundary to violate either
      delta    what the attacker gains **compared with the normal path.** If 0, the security impact is 0 even for a code defect
      boundary the **boundary** violated, in one sentence, in the vendor documentation's language

    Two cases are handled as a **cap** rather than a refusal — make the gate unsatisfiable and the
    agent runs off to blocked, which is worse:
      · owner='none'  → passes, but stamps `grade_cap='no boundary (unowned data)'`
      · delta='n/a'   → **a stronger finding** (a class where the normal-path comparison does not hold). Passes
    The only forced bounce-back is **delta=0 without having looked for a principal.** That is §3.
    """
    ow = (args.get("owner") or "").strip()
    dl = str(args.get("delta") or "").strip()
    bd = (args.get("boundary") or "").strip()
    pr = (args.get("principal") or "").strip()
    if not (ow and dl and bd):
        return (False,
                "A confirmation REQUIRES ALL THREE IMPACT FIELDS (`escalation.md` 1-3):\n"
                "  owner=    who owns these bytes / this resource. If nobody, owner='none'\n"
                "  delta=    what the attacker gets BEYOND what the legitimate path already\n"
                "            gives them. If nothing, delta='0'. If the comparison does not\n"
                "            apply, delta='n/a: <why>'\n"
                "  boundary= the boundary crossed, in ONE sentence, IN THE VENDOR'S OWN LANGUAGE\n"
                "STRONGLY RECOMMENDED — declare the crossing as TWO TOKENS, not prose. Prose is\n"
                "parsed by regex and in this ledger that caught 1 of 6 confirmations:\n"
                "  from_principal= / to_principal=  one of: remote-anonymous | "
                "remote-authenticated | appcontainer | low-il | standard-user | container-admin "
                "| admin | system | kernel | hypervisor\n"
                "  If you cannot establish the MINIMUM principal that reaches the sink, write\n"
                "  from_principal='unproven' — the row is then recorded as `boundary-held`, not `confirmed`,\n"
                "  and the escalator takes exactly that one question.\n"
                "Missing: %s\n"
                "'I found a path that skips a check' is not yet a vulnerability. If you cannot "
                "write these three, it is not a defect but UNAUDITED work — file it as `blocked`."
                % ", ".join(k for k, v in (("owner", ow), ("delta", dl), ("boundary", bd)) if not v),
                None)
    imp = {"owner": ow[:300], "delta": dl[:400], "boundary": bd[:300]}
    if pr:
        imp["principal"] = pr[:300]

    # ★ Exhaustiveness-claim checkpoint — "the only consumer is user mode" and the like are **absence claims.**
    #   This one sentence sets the grade ceiling by itself, and until now no gate looked at it.
    _blob = " / ".join((ow, dl, bd))
    _m = _SOLE.search(_blob)
    if _m:
        _en = (args.get("enumerated") or "").strip()
        if len(_en) < 30 and not has_xref():
            return (False,
                    "The impact contains an EXHAUSTIVENESS CLAIM: %r\n"
                    "That is an absence claim (\"there is nothing else\"), and this single "
                    "sentence sets the grade ceiling by itself.\n"
                    "But the ledger holds no basis for it. Do one of these:\n"
                    "  (1) Run a BEHAVIOUR-BASED sweep over ALL executable sections (e.g. via\n"
                    "      `import_xref`) and leave the record. Name-based xref misses wrappers;\n"
                    "      looking only at `.text` misses every call sitting in PAGE.\n"
                    "  (2) Pass `enumerated='<what you swept and by what method>'` with the "
                    "verdict.\n"
                    "This gate exists to stop premature certainty. IF YOU DO NOT KNOW, "
                    "WRITING 'the rest is unaudited' PASSES FREELY — writing 'only X' and "
                    "writing 'X is all I verified' are different claims."
                    % _m.group(0)[:80], None)
        imp["sole_claim"] = _m.group(0)[:120]
        if _en:
            imp["enumerated"] = _en[:400]
    low_o, low_d = ow.lower(), dl.lower()
    if low_o in _NONE_OWNER:
        imp["grade_cap"] = "no boundary (unowned data)"
    if low_d in _NA_DELTA or low_d.startswith("n/a"):
        imp["delta_kind"] = "not_applicable"      # the stronger class
    elif re.fullmatch(r'0+(\.0+)?|zero|none', low_d):
        imp["delta_kind"] = "zero"
        if not pr:
            return (False,
                    "delta=0. DO NOT THROW IT AWAY HERE — you may be looking in the wrong "
                    "place.\n"
                    "Turn the question around:  ~~is there a delta~~ -> WHICH PRINCIPAL HAS A "
                    "NONZERO DELTA?\n"
                    "  (1) PARSE the object's security descriptor and read EVERY ACE "
                    "(free text is not accepted)\n"
                    "  (2) Read the ACEs not as 'who can write this' but as 'WHICH SANDBOX CAN "
                    "GET OUT THROUGH THIS DOOR'\n"
                    "  (3) Look for a principal that is GRANTED ACCESS HERE yet BLOCKED on the "
                    "path it would otherwise use\n"
                    "If you find one, put it in `principal=` and confirm again. If you "
                    "enumerated and found nothing, write "
                    "`principal='none: <what you enumerated>'` — that is an honest negative "
                    "and it passes.\n"
                    "(This single pivot really did revive a dead finding: a sandbox SID "
                    "explicitly allowed in the SD was blocked on another axis, so "
                    "unreachability and granted-access held in the same process.)",
                    None)
    else:
        imp["delta_kind"] = "nonzero"
    # ── boundary: when the fields are present they are canonical, otherwise fall back to prose ──
    #   It does not block (compute + attach). But it records **what the judgement was made from** in `boundary_src`
    #   so that "what the regex read" and "what the analyst declared" can be told apart in the ledger.
    _fp = (args.get("from_principal") or "").strip().lower()
    _tp = (args.get("to_principal") or "").strip().lower()
    if _fp and _tp:
        _isb, _bwhy = boundary_typed(_fp, _tp)
        imp.update({"boundary_from": _fp, "boundary_to": _tp,
                    "is_security_boundary": _isb, "boundary_why": _bwhy[:240],
                    "boundary_src": "typed"})
        if _isb in ("no", "unknown"):
            imp["out_of_scope"] = ("%s→%s" % (_fp, _tp)) if _isb == "no" else "principal-unproven"
            imp["grade_cap"] = (imp.get("grade_cap") or "") + \
                (" · " if imp.get("grade_cap") else "") + "boundary %s: %s" % (_isb, _bwhy[:160])
    else:
        imp["boundary_src"] = "prose"
        _lab, _why = scope_verdict(imp)
        if _lab:
            imp["out_of_scope"] = _lab
            imp["grade_cap"] = (imp.get("grade_cap") or "") + (" · " if imp.get("grade_cap") else "") + \
                "out-of-scope boundary (%s): %s" % (_lab, _why)

    # ── does a measurement back the declared starting principal (the consumer side of top-priority T46) ──
    _pv, _pnote = principal_evidence(args.get("target") or STATE.get("target"), _fp)
    if _pv != "n/a":
        imp["principal_evidence"] = _pv
        if _pnote:
            imp["principal_evidence_why"] = _pnote[:300]
        if _pv in ("mismatch", "unmeasured"):
            imp["grade_cap"] = (imp.get("grade_cap") or "") + \
                (" · " if imp.get("grade_cap") else "") + "principal %s" % _pv
    return (True, "", imp)


def _cfgmod():
    import config as _c
    return _c


def _bump(key):
    """★ Put tool-side refusals on the instrument panel. Only the hook's `deny()` was counting `gate_denials`, so
    `[REJECTION REFUSED]` / `[REJECTION HELD - QUESTION]` / `[CONFIRMATION HELD - IMPACT]` /
    `[VERDICT REFUSED]` **had never once been counted** (one runlog call site in the whole ledger).
    On the night of 2026-09-04, five finished analyses vanished in the msquic round and **there was no way to tell why** —
    the return value goes only to the model and is left nowhere in stdout or runs.jsonl."""
    try:
        import runlog as _rl
        _rl.bump(key)
    except Exception:
        pass


def _blocked_rows():
    """Surface rows left as `BLOCKED:`. One axis of the debt."""
    n = 0
    for r in (STATE.get("surface") or {}).values():
        if isinstance(r, dict) and str(r.get("why") or "").lstrip().upper().startswith("BLOCKED"):
            n += 1
    return n


def open_debt():
    """What this round **opened − closed**. All three axes are counted.

    ★ Count only one axis and the volume leaks sideways. Measured grounds: this ledger already has 546
      `BLOCKED:` rows, and the ledger itself measured that "**blocked rows matching some prose predicate
      meaning 'there is a next step' are 56%**" — i.e. blocked is a cheap exit the machine cannot tell apart.
      Put a cap on leads alone and the whole volume leaks there.
    """
    _l0 = _RUN.get("leads0") or set()
    try:
        now = {str(x.get("id")) for x in open_leads(STATE.get("target"))}
    except Exception:
        now = set(_l0)
    lead_up, lead_dn = len(now - _l0), len(_l0 - now)
    _a0 = _RUN.get("asks0") or set()
    A = STATE.get("asks") or []
    ask_up = sum(1 for a in A if str(a.get("id")) not in _a0
                 and (a.get("status") or "open") == "open")
    ask_dn = sum(1 for a in A if str(a.get("id")) in _a0
                 and (a.get("status") or "") == "answered")
    blk_up = max(0, _blocked_rows() - int(_RUN.get("blocked0") or 0))
    opened, closed = lead_up + ask_up + blk_up, lead_dn + ask_dn
    return {"lead_up": lead_up, "lead_dn": lead_dn, "ask_up": ask_up, "ask_dn": ask_dn,
            "blocked_up": blk_up, "opened": opened, "closed": closed,
            "net": opened - closed}


def _wip_note():
    """The text to emit when the cap is hit. **It is not an instruction unless it names a row** —
    measured: block only the action, like the klass gate does, and the agent looks for a way around (the same id resubmitted 7 times in a row).
    The only rounds where the exit gate produced depth were those where the interrogator left **a named next move.**
    """
    d = open_debt()
    cap = int(getattr(_cfgmod(), "WIP_CAP", 12))
    L = ["[DEBT CAP] this round opened %d − closed %d = **net increase %d** (cap %d).\n"
         "  opened: leads +%d · asks +%d · blocked +%d   |   closed: leads %d · asks %d"
         % (d["opened"], d["closed"], d["net"], cap,
            d["lead_up"], d["ask_up"], d["blocked_up"], d["lead_dn"], d["ask_dn"]),
         "",
         "New rejections and blocked rows are not accepted. **Close to open.** Confirmation (`confirm`), measurement "
         "(`measure`), scope declaration (`scope`) and tracks (`track`) remain open as they are.", ""]
    try:
        ol = open_leads(STATE.get("target"))
    except Exception:
        ol = []
    if ol:
        L.append("The longest-open leads — the interrogator's next move is already attached:")
        for b in ol[:2]:
            L.append("  · `%s` [%s] %s" % (b.get("id"), b.get("klass") or "-",
                                           str(b.get("target"))[:70]))
            nm = (b.get("next_method") or b.get("reason") or "").replace("\n", " ")
            if nm:
                L.append("      %s" % nm[:420])
        L.append("")
        L.append("There are only three ways to close — `verdict(action='lead', id=<the id above>, "
                 "how=refuted|measured|reinterrogated, why=…)`. There is no exhausted.")
    else:
        L.append("No open leads ⇒ the net increase came from asks and blocked rows. "
                 "Answer an ask you opened, or drag one blocked row all the way to a verdict.")
    return "\n".join(L)


SURFACE_SCHEMA = 1      # surface artifact schema. Bump it when the shape changes → old files become invalid automatically


def _env_stamp():
    """The **measurement channel state at the time** a gate_block was raised. If it differs later, it is due for re-checking."""
    c = _cfgmod()
    return {k: int(bool(getattr(c, k, False)))
            for k in ("ALLOW_PROBE", "ALLOW_VM_PROBE", "ALLOW_KDNET")}


def export_surface(state=None, img_path=None, out_dir=None):
    """Export the ledger's **surface** as a fingerprinted artifact.

    ★ Taken from RAPTOR (the `/understand` → scan → `/validate` bridge): export the attack surface to a
      file so the next stage **picks it up automatically**, while the artifact carries the fingerprint of its
      input and the consumer recomputes it and refuses reuse on a mismatch.
      Our fingerprint is the CodeView GUID (closer to the build identity than a file md5).

    Why: until now the surface lived **only inside the ledger.** It could not get out, so ① cross-build diffs
      were impossible ② other tools could not read it ③ nobody asked "which build is this table from".
    """
    S = state if state is not None else STATE
    name = str(S.get("target") or "unknown")
    out_dir = out_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "out", "surface")
    os.makedirs(out_dir, exist_ok=True)
    guid = None
    if img_path:
        try:
            import pe as _pe
            cv = _pe.PE(img_path).codeview()
            guid = cv[0] if cv else None
        except Exception:
            guid = None
    surf = S.get("surface") or {}
    rows = [{"name": k, "status": (v or {}).get("status"), "why": (v or {}).get("why")}
            for k, v in (surf.items() if isinstance(surf, dict) else [])]
    doc = {"schema": SURFACE_SCHEMA, "target": name,
           "build": {"cv_guid": guid, "source": img_path},
           "generated": time.strftime("%Y-%m-%d %H:%M"),
           "counts": {"surface": len(rows),
                      "verdicts": len(S.get("verdicts") or []),
                      "measures": len(S.get("measures") or []),
                      "populations": len(S.get("populations") or [])},
           "surface": rows,
           "populations": S.get("populations") or []}
    path = os.path.join(out_dir, _key(name) + ".json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    return path


def load_surface(path, img_path=None):
    """Return an exported surface **only when it is fresh.** Returns: (doc, fresh, why).

    ★ Three-point contract (RAPTOR): refuse reuse on a fingerprint mismatch. If the fingerprint cannot be obtained,
      **do not reuse** (silent reuse is the most dangerous). A different schema is refused too.
    """
    try:
        doc = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as e:
        return (None, False, "read failed: %s" % e)
    if doc.get("schema") != SURFACE_SCHEMA:
        return (doc, False, "schema %s ≠ %s — not reusing"
                % (doc.get("schema"), SURFACE_SCHEMA))
    want = ((doc.get("build") or {}).get("cv_guid") or "")
    if not img_path:
        return (doc, False, "no binary to cross-check against — not reusing")
    got = None
    try:
        import pe as _pe
        cv = _pe.PE(img_path).codeview()
        got = cv[0] if cv else None
    except Exception as e:
        return (doc, False, "could not read the binary's fingerprint (%s) — not reusing" % e)
    if not want or not got:
        return (doc, False, "the fingerprint is empty — not reusing")
    if want.lower() != got.lower():
        return (doc, False, "different build: surface %s… / binary %s…" % (want[:8], got[:8]))
    return (doc, True, "")


def gate_block_digest(state=None, n=8):
    """The gate_block list the conductor sees. **Oldest unresolved first** + the repeat count of the same wall.

    ★ Why (2026-09-23): the old output was `tax[-4:]` / `oth[-5:]`, i.e. **newest-first LIFO.**
      ahcache had 47 but only 5 were visible — the very disease `break_digest` fixed on 09-07 was
      still in this output. Of 123 accumulated, nobody saw the old ones.
    Returns: (rows, summary) — rows oldest first, summary is {family label: count}.
    """
    S = state if state is not None else STATE
    gb = [x for x in (S.get("gate_blocks") or []) if isinstance(x, dict)]
    now = _env_stamp()
    cnt = {}
    for x in gb:
        cnt[str(x.get("gate"))[:40]] = cnt.get(str(x.get("gate"))[:40], 0) + 1
    rows = sorted(gb, key=lambda r: str(r.get("t") or ""))
    out = []
    for x in rows:
        if x.get("resolved"):
            continue
        e = x.get("env")
        x = dict(x)
        x["repeat"] = cnt.get(str(x.get("gate"))[:40], 1)
        x["stale_env"] = bool(e) and e != now
        out.append(x)
    # taxonomy first (the most dangerous), oldest first within it
    out.sort(key=lambda r: (r.get("kind") != "taxonomy", str(r.get("t") or "")))
    return out[:n], cnt


def verdict(args):
    act = (args.get("action") or "").lower()
    tgt = args.get("target", "?")
    # ★ 2026-09-07 — **The debt cap.** It blocks only `reject`/`blocked`.
    #   Confirmations are not blocked: a confirmation closes a row rather than opening one, and
    #   this harness's bottleneck is the refuter's input rate (41 on the 17th), not false positives.
    if act in ("reject", "blocked") and getattr(_cfgmod(), "GATE_WIP", True):
        _cap = int(getattr(_cfgmod(), "WIP_CAP", 12))
        _d = open_debt()
        if _d["net"] >= _cap:
            _bump("wip_blocked")
            record_denial(tgt, "[DEBT CAP] net increase %d ≥ cap %d" % (_d["net"], _cap),
                          act=act, rule="debt cap: opened-closed >= WIP_CAP")
            return _wip_note()
    # ★ 2026-09-24 — **The patch-anchored census completion gate** (Move 2).
    #   When a population that censuses the siblings of a vendor-fixed bug is marked with
    #   `population(invariant=...)`, any verdict closing that census as "fully fixed / no siblings"
    #   must carry `completes=<population name>`, and here enumeration completeness (0 unanalysed)
    #   and an interrogator SUSTAINED are enforced.
    #   Last night's mrxsmb over-closure (the interrogator BROKE it, but being non-blocking the
    #   rejection was counted first) becomes structurally unfileable. With no RI-tagged population
    #   this whole block passes through (no effect on a run).
    _completes = args.get("completes")
    if _completes:
        try:
            _cok, _creason = population_closure_status(str(_completes))
        except Exception as _e:      # the gate itself never crashes a verdict
            _cok, _creason = True, "closure gate error: %s" % type(_e).__name__
        if not _cok:
            _bump("held_closure")
            record_denial(tgt, "[CLOSURE HELD] completes=%s: %s" % (_completes, _creason[:150]),
                          act=act, rule="patch-anchored census not closable")
            return ("[CLOSURE HELD - PATCH-ANCHORED CENSUS] `%s`\n%s\n\n"
                    "This census is the sibling population of an invariant the vendor restored. To close it as complete: "
                    "① unanalysed=0 (every known member) ② run the interrogator on the closing statement and get SUSTAINED. "
                    "If the interrogator breaks it, the enumeration is incomplete — put the missed members in set_b and count again."
                    % (_completes, _creason))
    if act in ("confirm", "reject"):
        vid = args.get("id") or f"V{len(STATE['verdicts']) + 1}"
        # ★ The basis check is unrelated to the reject gate — it must apply to confirm too, so it is looked at **first**.
        # ★ 2026-09-08 — **Refusal is only for 'no record at all'.**
        #   Measured in the 09-08 run: the analyst ran a three-step baseline → treatment → after on a
        #   live guest **with controls 3/3** (`latch=1 → class-8 request → latch=1`, section handle
        #   bytes identical) and filed it as `basis=measured`, and was refused. The reason: it had not
        #   called `measure(action='classify')` — the observation was made with `kd`+`ioctl`, and
        #   **`kd` left nothing in the ledger** (the tool description promises `target=` is there
        #   "so the ledger can bind it", but the wiring did not exist).
        #   That round's only filed verdict fell back to `basis=disassemble`.
        #   => ① `kd` leaves a `trace`, ② `measured()` finds it by address overlap, and
        #     ③ here it **only stamps what backed the verdict.**
        #   ★ Why this is not a loosening: a `trace` is also a record of something the harness ran, not
        #     a self-report, and a `basis=measured` rejection still has `GATE_CONTROL_BEFORE_REJECT`
        #     demanding **a separate positive control** (agent_sdk:764). That check stays as it is.
        # ★ 2026-09-08 — **Compare after canonicalising.** This used to be an exact `== "measured"`
        #   match, so prose such as `basis="live kd read of the governing feature cache dword…"`
        #   **skipped this check entirely** (measured in the 09-08 second round: 2 verdicts passed that way).
        #   **The very bug** fixed on 09-07 in `agent_sdk`'s `GATE_CONTROL_BEFORE_REJECT` was still
        #   sitting in its ledger-side twin — the fix back then had been applied only halfway.
        if normalize_basis(args.get("basis"))[0] == "measured":
            _mrec = measured(tgt)
            if not _mrec:
                _bump("held_basis"); record_denial(tgt, "[VERDICT REFUSED] basis=measured without a measurement record",
                                                    act=act, klass=args.get("klass") or "", rule="basis=measured but no measurement record")
                return ("[VERDICT REFUSED] basis='measured' but THERE IS NO MEASUREMENT RECORD "
                        "bound to this target — not by name and not by address.\n"
                        "Two ways to bind one:\n"
                        "  · `measure(action='classify', target=..., a=<fill A hex>, "
                        "b=<fill B hex>, status=..., info=...)` — a GRADED measurement.\n"
                        "  · `kd(cmds=..., target=...)` / `ioctl(...)` — the harness records a "
                        "TRACE of what it actually executed, and binds it by the addresses in "
                        "your command chain. Put the VA this verdict is about IN the chain "
                        "(`dd <mod>+0x…`), or name it in `target=`.\n"
                        "Without either, 'I measured it' is SELF-REPORTED, and the reason "
                        "measured outranks disassemble in BASIS_RANK disappears.")
            _kinds = {str(m.get("kind") or "classify") for m in _mrec}
            # ★ 2026-09-10 — **Stamp the backing credentials onto the verdict.** Without it, whoever
            #   reads this verdict three weeks later cannot tell "measured at low privilege" from
            #   "nobody wrote down which token". It does not block — it only carries the fact (computed + attached).
            _pg = "unknown"
            _rank = {"verified_low": 5, "verified_default": 4, "verified_elevated": 3,
                     "kernel-debugger": 2, "declared": 1, "unknown": 0}
            for _m in _mrec:
                _c = _m.get("principal_grade") or principal_grade(_m.get("principal"))
                if _rank.get(_c, 0) > _rank.get(_pg, 0):
                    _pg = _c
            _pending_meas[0] = {"n": len(_mrec), "kinds": sorted(_kinds),
                                # ★ 2026-09-13 — three ranks. `before_after` is a graded
                                #   observation, so putting it in the same slot as `trace`
                                #   (the fact of execution only) would falsify the weight of the evidence.
                                "by": ("classify" if "classify" in _kinds
                                       else "before_after" if "before_after" in _kinds
                                       else "trace"),
                                "principal": _pg}
        gate_note, gate_rec = "", None
        impact = None
        if act == "confirm":
            _ok, _note, impact = _impact_gate(args)
            if not _ok:
                _bump("held_impact"); return "[CONFIRMATION HELD - IMPACT] %s\n\n%s" % (tgt, _note)
            # ★ 2026-09-06 — **Consistency between claims.** Every other gate is claim-local.
            #   Nobody checked whether a premise this confirmation borrows had already died (wcifs graded copy §1).
            _rok, _rnote, _rask = _reach_gate(args)
            if not _rok:
                _bump("held_reach")
                record_denial(tgt, "[CONFIRMATION HELD - DEPENDENCY] " + _rnote[:150],
                              act=act, rule="depends_on: missing or unresolvable")
                return "[CONFIRMATION HELD - DEPENDENCY] %s\n\n%s" % (tgt, _rnote)
        if act == "reject":
            # ★ Measured 2026-09-05: `GATE_REJECT=0` switched off **only the hook side** (agent_sdk:614).
            #   This tool-side call ran unconditionally, so rejections were blocked even with it off.
            #   The first trust-arm round showed `gate_denials=0` yet `refused_reject=1` — the
            #   instrument built that day found a switch leak on its first round.
            if not getattr(_cfgmod(), "GATE_REJECT", True):
                ok, gate_note, gate_rec = True, "", {"klass": (args.get("klass") or "")}
            else:
                ok, gate_note, gate_rec = _reject_gate(tgt, args)
            if not ok:
                _bump("refused_reject"); return "[REJECTION REFUSED] %s\n\n%s" % (tgt, gate_note)
            # ★ Redesigned 2026-09-05 — the gate is **demoted to a calculator.**
            #   Old behaviour: anything it could not decide was not counted as a verdict and was sent to
            #   the question queue. The result was a pair-hunting loop (of 208 open questions, 72 were gate
            #   verdicts, 66 had a pair attached, and 8 of 17 retries were hunting).
            #   What the gate denied was **the encoding, not the conclusion** — when the real reason a
            #   thing is safe is not shaped as "one branch + one sink", no satisfying pair exists.
            #   New behaviour: the verdict is **filed as-is**, and what the gate computed and **what it
            #   could not** are carried on the verdict and handed to the adversary as evidence. The interrogator judges.
            # ★ One exception: **if the image cannot be opened**, nothing can be verified. That is a
            #   matter of fact, not of encoding, and the interrogator cannot see the binary either, so handing it over decides nothing.
            #   What gets demoted is "a shape the gate model cannot express", not "unmeasurable".
            _ask_kind = ((gate_rec or {}).get("ask") or {}).get("cfg") if isinstance(gate_rec, dict) else None
            if (isinstance(gate_rec, dict) and gate_rec.get("ask")
                    and _ask_kind != "no_image"
                    and getattr(_cfgmod(), "GATE_COMPUTE_ONLY", True)):
                _a = gate_rec["ask"]
                gate_rec["computed_but_unexpressed"] = {
                    "cfg": _a.get("cfg"), "why": _a.get("why"),
                    "guard": gate_rec.get("guard"), "sink": gate_rec.get("sink")}
                gate_rec.pop("ask", None)          # not demoted to a question
            if isinstance(gate_rec, dict) and gate_rec.get("ask"):
                a = gate_rec["ask"]
                prev = _ask_open(tgt)
                if prev is not None:
                    # The same target already has an open question — count an **attempt** instead of stacking a new one.
                    prev.setdefault("attempts", []).append(
                        {"t": a.get("t"), "cfg": a.get("cfg"), "kind": a.get("kind"),
                         "guard": gate_rec.get("guard"), "sink": gate_rec.get("sink")})
                    # ★ `inexpressible` is **harness debt** (the gate cannot express this shape).
                    #   Even arriving late it must not be masked by an earlier `need_observation` — it is promoted.
                    #   It is never lowered the other way: something once inexpressible does not turn into an observation.
                    if a.get("kind") == "inexpressible":
                        prev["kind"] = "inexpressible"
                    elif not prev.get("kind"):
                        prev["kind"] = a.get("kind")
                    q = prev
                else:
                    # ★ 2026-09-08 — **Store `kind`/`by`.** `ask()` computes it with
                    #   `ask_kind()` and puts it in `rec["ask"]["kind"]`, but this dict did not copy
                    #   it and it was being thrown away: across the whole ledger 231/231 · 125/125 were `None`.
                    #   As a result need_observation (measuring more will do) and inexpressible (the gate
                    #   cannot express it) were not separated, and **the single queue had no axis to sort by.**
                    q = {"id": vid, "target": tgt, "claim": (args.get("claim") or "")[:300],
                         "klass": args.get("klass"), "guard": gate_rec.get("guard"),
                         "sink": gate_rec.get("sink"), "cfg": a.get("cfg"),
                         "why": a.get("why"), "method": a.get("method"),
                         "kind": a.get("kind"), "by": "gate",
                         "status": "open", "attempts": [], "t": a.get("t")}
                    STATE.setdefault("asks", []).append(q)
                _k = _surface_key(tgt) if "_surface_key" in globals() else tgt
                if tgt in STATE.get("surface", {}):
                    STATE["surface"][tgt]["status"] = "unanalysed"
                    STATE["surface"][tgt]["blocked"] = True
                    STATE["surface"][tgt]["why"] = "ASK: " + (a.get("why") or "")[:220]
                save()
                try:
                    _ah = anchor_hits(" ".join(str(args.get(k) or "")
                                               for k in ("claim", "evidence", "guard", "sink")),
                                      exclude_id=vid)
                except Exception:
                    _ah = ""
                _bump("held_ask")
                # ★ This ASK is the path that muted the interrogator and the promoter at once on 2026-09-05 (→ R-05 ②d).
                #   Even now that the gate is demoted, **what it could not decide** must be kept, or there are no per-rule results.
                record_denial(tgt, "[REJECTION HELD] cfg=%s %s"
                              % (a.get("cfg") or "undecidable", str(a.get("why") or "")[:120]),
                              act=act, klass=args.get("klass") or "",
                              rule="[ASK] cfg=%s" % (a.get("cfg") or "undecidable"))
                return ("[REJECTION HELD - QUESTION] %s\n\nThe gate could not adjudicate "
                        "(%s). THIS IS NOT A NEGATIVE, IT IS UNAUDITED.\n\n"
                        "Why: %s\n\nDo this next: %s\n\n"
                        "The question stays in the queue (check with "
                        "`verdict(action='asks')`). Once you have the answer, reject the same "
                        "target again.%s"
                        % (tgt, a.get("cfg") or "undecidable", a.get("why"),
                           render_ask(tgt, a),
                           ("\n" + _ah) if _ah else ""))
        # ★ Checking that cited constants actually exist (`claimaudit.constants_cited`).
        #   Measured 2026-08-30: the harness cited `0xFFFF00FF` as the cornerstone of a by-design argument,
        #   and that immediate occurs **zero times in this binary** (the real masks are 0xFFFF109F / 0xFFFF013F).
        #   When the constant turned out wrong, the conclusion flipped. The tool already existed and **was simply
        #   not connected** (the same state as `measure.py`). It does not block — the value may be computed — it warns in the tail.
        _const_note = ""
        try:
            import claimaudit as _CA
            _t = STATE.get("target") or ""
            if _t and os.path.exists(_t):
                _cc = _CA.constants_cited(args.get("claim", "") + " " + args.get("evidence", ""),
                                          pe_path=_t)
                # `nc == -1` means "corpus not checked", not "zero hits" — the old
                # filter was `not c[1] and not c[2]`, and since no corpus is passed
                # here nc is always -1, so **this warning could never fire.**
                # Treat "not checked" as no vote and let the binary byte count
                # decide. (Same defect upstream; confirmed by porting claimaudit.)
                _ghosts = [c for c in (_cc or []) if c[1] <= 0 and not c[2]]
                if _ghosts:
                    _const_note = ("\nWARNING: the constant %s cited by the claim occurs "
                                   "ZERO times in this binary. If it is a computed value, say "
                                   "how you derived it; otherwise re-derive it — one wrong "
                                   "constant flips the conclusion." %
                                   ", ".join("0x%X" % c[0] for c in _ghosts[:4]))
        except Exception:
            pass
        # ★ Claim ↔ anchor link (`refs/00-gate-gaming.md`). Extensional verification alone cannot stop the
        #   grounds being rebuilt to fit the gate's shape. Applied to confirmations only — rejections have per-klass duties of their own.
        _link_note = ""
        _scope_warn = ""
        if act == "confirm" and impact and impact.get("out_of_scope"):
            _scope_warn = ("\nRECORDED AS `boundary-held`, NOT AS A CONFIRMATION "
                           "— out-of-scope boundary (%s): %s\n"
                           "THIS IS NOT A REJECTION. The code defect stands and its basis is "
                           "kept. It cannot be promoted because the grade is zero across THIS "
                           "boundary.\n"
                           "The remaining question has narrowed to one: IS THERE A "
                           "LOWER-PRIVILEGED PRINCIPAL THAT REACHES THE SAME SINK? A non-admin "
                           "inside a container, AppContainer / sandbox, a lower-privileged "
                           "service, a bypass path via another port or device. Find ONE and "
                           "this row becomes a confirmation immediately.\n"
                           "   `escalation.md` section 3 (principal pivot) + escalator axis "
                           "`principal_sd_ace`."
                           % (impact["out_of_scope"],
                              impact.get("grade_cap", "").split(": ", 1)[-1][:120]))
        if act == "confirm":
            _ul, _ln = claim_anchor_link(args.get("claim", ""), args.get("_anchors") or [])
            if _ul:
                _link_note = "\n⚠ " + _ln
                rec_link = _ul

        staged_a, staged_r = _take(tgt, args.get("claim", ""))
        # ★ 2026-09-07 — basis is folded into the canonical vocabulary, and an unregistered leading token is **denied.**
        #   The prose is not thrown away; it moves to `basis_note` (the argument is carried by claim/reason).
        _bcanon, _braw = normalize_basis(args.get("basis"))
        # ★ **Leaving it blank is not writing it wrong.** The old default is kept —
        #   otherwise even the promise of a switch like `GATE_REJECT=0` breaks (caught as a regression).
        if not _braw:
            _bcanon = "decompile"
        if _bcanon is None:
            return ("`basis` MUST LEAD WITH ONE OF: measured | disassemble | decompile | doc.\n"
                    "You wrote: %r\n"
                    "This field is not prose — `BASIS_RANK` reads it, and "
                    "`GATE_CONTROL_BEFORE_REJECT` fires on `measured`. When it is a sentence, "
                    "both silently degrade: in this ledger the same thing carried four names "
                    "(disassemble 83 / disassembly 30 / static 22 / disasm 3) and a rejection "
                    "reading `measured on the live kernel…` skipped the positive-control check "
                    "entirely.\n"
                    "Keep your sentence — just LEAD with the token: "
                    "`basis='measured on the live kernel, kd against the running guest'` or "
                    "`basis='disassemble of the whole function body'`. The rest is preserved "
                    "in `basis_note`." % _braw[:120])
        rec = {"id": vid, "target": tgt, "claim": args.get("claim", "?"),
               "basis": _bcanon,
               "basis_note": (_braw[:600] if _braw.lower() != _bcanon else None),
               "evidence": (args.get("evidence", ""))[:4000],
               "anchors": args.get("_anchors") or staged_a,
               "refute": args.get("_refute") or staged_r,
               "measured_by": (_pending_meas[0] or {}).get("by"),
               "measured_n": (_pending_meas[0] or {}).get("n"),
               "measured_principal": (_pending_meas[0] or {}).get("principal"),
               "status": ("boundary-held" if (act == "confirm" and (impact or {}).get("out_of_scope"))
                          else "confirmed" if act == "confirm" else "rejected"),
               "gate": gate_rec, "impact": impact,
               # ★ The declared premise is stamped onto the verdict. The gate looks only at **filing time**,
               #   and premises die later — `dependency_audit()` comes back through this field then.
               "depends_on": (str(args.get("depends_on") or "").strip() or None),
               "unlinked_addrs": ["0x%X" % u for u in (locals().get("rec_link") or [])],
               "t": time.strftime("%m-%d %H:%M")}
        # ★ **Stamp onto this verdict** the interrogation result the pre-gate left behind. Without it,
        #   `verified_negatives()` and `rejects_interrogated` cannot see the interrogation.
        _pe = (STATE.get("pending_escalation") or {}).pop(tgt, None)
        if _pe is not None:
            rec["escalation"] = _pe
        # ★ 2026-09-04 — a confirmation issued by the adjudicator is **a different kind of confirmation.**
        #   It did not pass the refuter; the closer issued it after reading the history. Without a mark it
        #   is counted at face value in tomorrow's grading, and a one-day permission experiment quietly becomes policy.
        _adj = (STATE.get("pending_adjudication") or {}).pop(tgt, None) \
            or args.get("_adjudicated")
        if isinstance(_adj, dict):
            rec["decided_by"] = "adjudicator"
            rec["adjudication"] = _adj
        _interrog_note = ""
        # ★ 2026-09-06: look up by id first. The target fallback is used **only when the result does not
        #   claim to belong to another row** (if `for_id` points at a different row, it is someone else's interrogation).
        _pq = STATE.get("pending_interrog") or {}
        _pi = _pq.pop(vid, None) if vid else None
        if _pi is None:
            _cand = _pq.get(tgt)
            if isinstance(_cand, dict) and not _cand.get("for_id"):
                _pi = _pq.pop(tgt, None)
        if _pi is not None and act == "reject":
            rec["interrogated"] = bool(_pi.get("ok"))
            if _pi.get("ok"):
                rec["interrogation"] = {"klass": _pi.get("klass"),
                                        "reason": _pi.get("reason"),
                                        # ★ The criterion for judging the output. Without it a broken rejection leaks out as output.
                                        "broke": bool(_pi.get("broke"))}
            # ★ Even though it does not block, **the reason reaches the analyst.** Otherwise it becomes silence instead of a loop.
            if _pi.get("broke") and _pi.get("note"):
                _interrog_note = "\n\n" + str(_pi.get("note"))
        STATE["verdicts"].append(rec)
        _scope_note = ""
        if act == "reject":
            _res = _settle_reject(vid, tgt, rec["claim"], args.get("item"), args.get("sink"))
            _st = _res[0][1] if _res else "no_scope"
            if _st == "no_scope":
                _scope_note = ("\nTHE CLAIM DIED BUT THE SURFACE IS NOT CLOSED. No candidate set "
                               "has been declared for this surface - refuting one sink and "
                               "closing an entire handler is the wrong answer this ledger has "
                               "produced again and again.\n   Declare the denominator with "
                               "`verdict(action='scope', target=..., items=['0xVA name', ...], "
                               "method='how you enumerated')`, then adjudicate each candidate.")
            elif _st == "open":
                _rest = _res[0][2] or []
                _scope_note = ("\nThe surface is still UNAUDITED — %d candidates remain: %s"
                               % (len(_rest), ", ".join(i["label"] for i in _rest[:6])))
            else:
                _scope_note = "\nAll candidates are adjudicated => the surface CLOSES AS A REJECTION."
        else:
            _settle(vid, tgt, rec["status"], rec["claim"][:80])
        _closed = _ask_close(tgt, vid, "answered", rec["claim"][:200])
        if act == "reject":
            # ★ Measured 2026-09-04: of 394 graveyard rows only **24 (6%)** were refuter kills, and
            #   370 came through this path — **the analyst's own rejections.** Yet the priming text
            #   says "CLAIMS ALREADY KILLED (do not resurrect)" identically for both.
            #   One's own verdict blocks one's self in the next round with the same weight as an adversary's.
            #   (Given the interrogator's 67% break rate, many of those 370 are rejections that would not have stood.)
            #   => stamp the origin. And `t` — it was only put in close_candidate, so 394/394 had
            #     no date. Only the 6% path had effectively been fixed.
            # ★ 2026-09-06 — **Stamp the interrogation state onto the graveyard row as well.**
            #   `broke` used to live only on the verdicts record. So to the consumers that read the graveyard
            #   (carry-over, the `_resolve_row` fallback, priming) **a broken rejection also looked like a clean negative.**
            #   Measured: of 167 graveyard rows only 54 (32%) passed interrogation, but with no mark the
            #   other 113 were blocking the next round with the same weight.
            _ig = rec.get("interrogation") if isinstance(rec.get("interrogation"), dict) else {}
            STATE["graveyard"].append({"id": vid, "target": tgt,
                                       "claim": rec["claim"][:120],
                                       "klass": (args.get("klass") or "self-reject"),
                                       "reason": args.get("reason", "")[:300],
                                       "origin": "self",
                                       "interrogated": rec.get("interrogated"),
                                       "broke": bool(_ig.get("broke")) if _ig else None,
                                       "t": time.strftime("%m-%d %H:%M")})
        save()
        tail = ""
        # ★ 2026-09-07 — **The measurement axis was not attached to the verdict ladder.**
        #   Measured: ahcache was measured **97 times** with kd, ioctl and vmprobe, yet only 2 verdicts
        #   rose on that basis, and of 7 confirmations **zero** were measurement-based (all disassemble).
        #   Measuring and adjudicating just piled up side by side, with no promotion path.
        #   => it does not block (the writer judges). But it **counts and shows the measurements on the same target.**
        try:
            _va = set(re.findall(r'0x[0-9a-fA-F]{6,16}', str(tgt).lower()))
            _mine_m = []
            for m in (STATE.get("measures") or []):
                _mt = str(m.get("target") or "").lower()
                if not _mt:
                    continue
                # Address overlap (exact), or names containing each other, counts as the same target.
                if (_va & set(re.findall(r'0x[0-9a-fA-F]{6,16}', _mt))) or \
                        (len(_mt) > 8 and (_mt[:40] in str(tgt).lower()
                                           or str(tgt).lower()[:40] in _mt)):
                    _mine_m.append(m)
        except Exception:
            _mine_m = []
        if _mine_m and rec["basis"] != "measured":
            tail += ("\n\n★ This target has %d measurements, but this verdict's basis is `%s`.\n"
                     "   If you are using a measurement as grounds, raise it to `basis='measured …'` — it then "
                     "goes through the positive-control check (GATE_CONTROL_BEFORE_REJECT).\n"
                     "   If adjudicating statically is right, leave it. But this is how the gap in this ledger "
                     "of 97 measurements against 2 measured verdicts opened up.\n"
                     "   recent measurements: %s"
                     % (len(_mine_m), rec["basis"],
                        " · ".join("%s(%s)" % (str(m.get("target"))[:38], m.get("grade"))
                                   for m in _mine_m[-2:])))
        # ★ A confirmation standing on a dead premise is **asked about, not blocked.** A rejection often narrows a
        #   claim rather than rebutting it (excluding a sibling caller, a broader variant dying). The writer judges.
        if act == "confirm" and locals().get("_rask"):
            tail += "\n\n★ " + _rask
            rec_dead = True
        # ★ Anchor reverse index. Shows **automatically** where the anchors of the verdict just filed already appear in the ledger.
        #   If the agent has to ask before it sees them, it does not look — five rounds went that way.
        try:
            _ah = anchor_hits(" ".join(str(args.get(k) or "")
                                       for k in ("claim", "evidence", "reason")), exclude_id=vid)
        except Exception:
            _ah = ""
        if _ah:
            tail += "\n" + _ah
            # ★ Tool **results** do not stay in the transcript ([tool ] records only the call). There was no way
            #   to confirm afterwards whether this device actually fired, so it leaves one line. Silence is not evidence.
            try:
                import runlog as _rl
                _rl.transcript("[anchoridx] %s — showed %d earlier rows"
                               % (str(tgt)[:60], _ah.count("\n   [")))
            except Exception:
                pass
        if BASIS_RANK.get(rec["basis"], 0) < 3:
            tail = ("\nWARNING: weak basis (decompile/doc). This confirmation may only be used as INFERRED.")
        if act == "reject" and BASIS_RANK.get(rec["basis"], 0) < 4:
            # Under a recall-maximising objective **a false rejection = a lost bug.** That costs more here than a confirmation does.
            tail += ("\nWARNING: this is a STATIC rejection (basis=%s). Do not put this row in "
                     "the same column as 'measured clean' - that makes coverage a lie. Three "
                     "steps to promote it: (1) did the handler actually execute "
                     "(INVALID_PARAMETER / NOT_SUPPORTED / TOOSMALL + zero bytes written = "
                     "UNMEASURED); (2) was it observed with a DUAL FILL; (3) did that run pass "
                     "the scanner's positive AND negative controls. Using dual_fill / classify / "
                     "kernel_ptrs in `measure.py` enforces all three."% rec["basis"])
        tail += _const_note
        if rec["anchors"]:
            tail += f"\n{len(rec['anchors'])} anchors were machine-verified against this build and stored with it."
        if gate_note:
            tail += "\n" + gate_note
        # ★ The sink-downstream gate — the confirm gates (G0–G5) are all on the anchor/refutation axes, so nobody looked at this one.
        #   **Both** of the 2 measured failures happened here (globmerger underflow: the allocation call came after it /
        #   cng QUERY_VOLUME: ntoskrnl enforced a per-class minimum length).
        #   It does not block — under a recall-maximising objective there is no reason to block confirmations further. **It only shows.**
        if act == "confirm":
            try:
                import cfg as _cfg
                _p = _pe_for_gates()
                _sv = _sink_va(rec)
                if _p is not None and _sv is not None:
                    _r = _cfg.sink_gates(_p, _sv)
                    if _r and (_r["gates"] or _r.get("nearby")):
                        tail += "\n" + _cfg.render_sink_gates(_r)
            except Exception as _e:
                tail += "\n(sink-gate analysis failed: %s - that is UNAUDITED, not 'no gate')" % _e
        return (f"[{vid}] {tgt} → {rec['status']}. claim={rec['claim']!r} "
                f"basis={rec['basis']}{tail}{_link_note}{_scope_warn}{_scope_note}"
                f"{_interrog_note}")

    if act == "blocked":
        # In a smoke test the model retried three times without a reason. claim is accepted as a fallback.
        why = args.get("reason") or args.get("claim") or ""
        if not why:
            return ("`blocked` REQUIRES why you could not adjudicate (reason=). Write in one line "
                    "WHAT YOU WOULD HAVE TO LOOK AT to move this to confirm or reject - that line "
                    "becomes the next session's work list.")
        # ★ 2026-09-04: `id` and `tgt` used to **both, unconditionally,** become surface rows.
        #   So `blocked(id='V-I5-REAL', target='I-5 QuicConnRecvRetry@0x…')` created a new
        #   **fake row** called `V-I5-REAL`. In msquic r1, V-I3 / V-I5-REAL / V-I5-TOKEN /
        #   V-UNOPENED were born that way and inflated the denominator, and the next round
        #   inherited a table with more rows to close — **the substance of verdicts not carrying into the next round.**
        #   The `scope` handler just below was already doing it right at the same spot (`and k in STATE`).
        _bk = [k for k in (args.get("id"), tgt) if k and k in STATE["surface"]] \
            or [k for k in (tgt,) if k]
        # ★ 2026-09-05 (C-037): take the next step **as a field**, because it cannot be extracted from prose.
        #   Measured: applying (verb|question mark)+anchor to the 498 blocked rows catches 278 (56%),
        #   and anchor grounding (holding a VA no verdict covers) catches 245, but **3 of the 4 rows C-034 pointed at drop out.**
        #   => the measured result is that classifying prose is impossible. The writer is made to put it in a field.
        # ★ `next_step` is not in the schema — on purpose. The model is shown only `next`,
        #   keeping a single name, but a slip where the model emits a synonym is accepted.
        #   `agent_sdk._mk` **does not filter** arguments, so undeclared keys reach this point too.
        #   This tolerance is listed with its reason in test_argschema's TOLERATED_ALIASES.
        _nx = str(args.get("next") or args.get("next_step") or "").strip()
        _ok, _miss = _next_step_ok(_nx)
        for _k in _bk:
            surface_set(_k, "unanalysed", "BLOCKED: " + why)
            if _k in STATE["surface"]:
                STATE["surface"][_k]["blocked"] = True
                if _ok:
                    STATE["surface"][_k]["next"] = {"step": _nx[:400],
                                                    "t": time.strftime("%m-%d %H:%M")}
        save()
        _tail = ("\n★ RETURNABLE: the next step is in its field — this row shows up at the top of the worklist and "
                 "in the `verdict(action='unfinished')` list.\n   next: " + _nx[:200]) if _ok else (
                "\n★ This row's **next-step field is empty** (next=). The next round cannot pick reason prose "
                "by machine — that is a measured fact (on a 498-row sample, every predicate asking 'does the "
                "reason contain a next step' either caught 56%% or dropped the rows that needed recovering). "
                "Fill the field and it becomes a **work list** instead of a reservoir:\n"
                "   verdict(action='blocked', target=..., reason=..., next='<one step>')\n"
                "   requirements: %s. e.g. 'disassemble 0x14004efc0 and check whether "
                "SdbpInitializeSearchDBContext admits a caller-chosen absolute directory into "
                "v15[12*i+2]'" % (_miss or "-"))
        return (str(tgt) + " -> UNAUDITED (BLOCKED). It is NOT removed from the table. "
                "Reason: " + why[:200] +
                "\nIt does not count toward coverage - unaudited work with a reason is HONEST "
                "UNAUDITED WORK, not an achievement." + _tail)

    if act == "scope":
        #   A rejection kills only one candidate; the surface closes only when every candidate is dead.
        items = args.get("items") or []
        method = (args.get("method") or "").strip()
        if isinstance(items, str):
            items = [x.strip() for x in items.split(",") if x.strip()]
        if not items:
            record_denial(tgt, "[SCOPE REFUSED] items= missing — no candidate set",
                          act="scope", rule="scope: items= missing")
            return ("`scope` REQUIRES the CANDIDATE SET for this surface (items=['0x14000e4b3 "
                    "ProbeForWrite call site', ...]). If the denominator is sinks, list the "
                    "sinks; if it is the authorization axis, list the gates; if it is races, list "
                    "the shared-object access points.")
        # ★ A 30-char minimum. In the 2026-09-03 translation `len(method) < 30` shrank to `not method`,
        #   and `method="looked"` passed as a denominator. Under R-A rejections stand on scope, so
        #   loosening this one line weakens every rejection built on top of it.
        if len(method) < 30:
            record_denial(tgt, "[SCOPE REFUSED] method= %d chars (30-char minimum)" % len(method),
                          act="scope", rule="scope: method< 30 chars")
            return ("`scope` REQUIRES HOW you enumerated (method=, AT LEAST 30 CHARS). "
                    "Name-based xref misses wrappers - say what you swept, behaviourally. "
                    "Without an enumeration method it is not a denominator, just a list, and no "
                    "rejection built on it holds.")
        norm = []
        for it in items:
            lab = it if isinstance(it, str) else (it.get("label") or str(it))
            m = re.search(r'0x[0-9a-fA-F]+', lab)
            norm.append({"label": lab[:120], "va": int(m.group(0), 16) if m else None,
                         "done": None})
        keys = [k for k in (args.get("id"), tgt) if k and k in STATE["surface"]] or [tgt]
        for k in keys:
            row = STATE["surface"].setdefault(
                k, {"status": "unanalysed", "kind": "ad-hoc", "reach": "unknown", "why": ""})
            prev = (row.get("cand") or {}).get("items") or []
            done = {i["label"]: i.get("done") for i in prev}
            for i in norm:
                i["done"] = done.get(i["label"])
            row["cand"] = {"items": norm, "method": method[:500],
                           "t": time.strftime("%m-%d %H:%M")}
        save()
        return ("%s candidate set registered (%d items). Now adjudicate EACH CANDIDATE - a "
                "rejection must name which candidate it kills via `item='<label>'` or `sink=<VA>` "
                "before that candidate closes. When all of them close, the surface becomes a "
                "rejection.\n%s"
                % (tgt, len(norm), "\n".join("  - " + i["label"] for i in norm[:12])))
    if act == "track":
        # ★ `tgt` defaults to "?", so using it as-is **creates an unnamed track.**
        #   A track created silently pollutes the stage table — refused.
        nm = (args.get("name") or "").strip() or (tgt if tgt not in ("?", "", None) else "")
        nm = (nm or "").strip()
        if not nm or nm == "?":
            return ("`track` REQUIRES name= (the investigation track's name). An unnamed track "
                    "pollutes the stage table.")
        # ★ A bug measured 2026-09-05: `of` **was doing two jobs.**
        #   In `ledger.track()`, `of` is **the array of stage names** (static-confirm/trigger/measure/…),
        #   but here `evidence_ids` was being put in that slot. When the agent passed a value like `of='0'`,
        #   **the stage table was overwritten wholesale with ["0"]** and the 5-rung ladder showed as 1/1 complete.
        #   Measured: 6 tracks were in that state (quirks-rw · versionblock-parse ·
        #   telemetry-doublefree-gate · uaf-avlnode · lockfree-cacheref · AhcpCacheBuild…),
        #   and the `stage_sum` metric was false by the same amount.
        #   => the stage table changes only through `stages=`. `of`/`evidence_ids` are used **only as evidence.**
        _stages = args.get("stages")
        if isinstance(_stages, str):
            _stages = [x.strip() for x in _stages.split(",") if x.strip()]
        # ★ 2026-09-05 — **4 of 31 tracks had their stage table broken by a sentence in `stages=`.**
        #   A measured example: stages=['static-confirm -> trigger(CQ57 answered', 'key is name-only',
        #                    'hit does not re-match) -> measure -> impact -']
        #   The agent wrote its progress as prose (commas mixed into `a -> b -> c`), and that was split
        #   on the commas and **became the ladder itself.** Then `stage N/M` loses its meaning, and
        #   "what is the next rung" comes out as a sentence fragment (that is how it showed on the dashboard).
        #   => **a ladder is labels, not narration.** Filter by form: a rung that is too long or that
        #     mixes in arrows/parentheses is prose and is not accepted (keeping the existing table is the safe side).
        if _stages:
            _bad = [x for x in _stages
                    if len(str(x)) > 24 or "->" in str(x) or "(" in str(x)]
            if _bad:
                _stages = None      # keep the existing stage table
        of = _stages if (_stages and len(_stages) >= 2) else None
        _more = args.get("evidence_ids") or args.get("of")
        if isinstance(_more, str):
            _more = [x.strip() for x in _more.split(",") if x.strip()]
        _ev = args.get("evidence_ids") or ([args["id"]] if args.get("id") else None)
        _ev = list(_ev or []) + list(_more or [])
        # ★ Measured 2026-09-06 (overnight run, case 5): **a single read-shaped call wiped a track from 4 to 0.**
        #   When the model sends every schema field filled with blanks, an int field becomes **0** —
        #   `stage: int` cannot carry "do not change it" (the same disease as memory `predicate-cannot-ask`:
        #   the medium cannot carry unknown). The tool then returns "stage 0/5", and the agent reads that
        #   **as the ledger's state** — the measured sentence:
        #   *"The state demoted per-class-authz to 0/5"* (misreading what it had erased itself as state).
        #   A record built up to rung 4 by the previous round vanished in front of it, and that round set its
        #   goal on the premise of the loss. => **a demotion passes only with a reason attached.**
        #   The conductor's demotions always carry a why (conductor.apply), and this tool's own guidance
        #   ("lowering one after a refutation is the honest thing to do") already presumes a reason exists.
        #   Raising or keeping is unaffected — a read-shaped call is now simply a read.
        _note = args.get("note") or args.get("why") or ""
        _st = args.get("stage")
        _cur = int(((STATE.get("tracks") or {}).get(nm) or {}).get("stage", 0))
        _kept = ""
        if isinstance(_st, int) and not isinstance(_st, bool) and _st < _cur and not str(_note).strip():
            _kept = ("\n\n[STAGE KEPT AT %d] You passed stage=%d, which would MOVE THIS TRACK "
                     "BACK %d rung(s), but gave no reason. A demotion is a refutation, so it has "
                     "to say what refuted the rung: re-send with note='<what knocked it down>'. "
                     "(If you meant to READ the track, you already have - stage is unchanged. "
                     "An int field cannot say 'leave it alone', so a blank-filled call used to "
                     "erase depth silently. That is what this refusal exists to stop.)"
                     % (_cur, _st, _cur - _st))
            _st = None
        t = track(nm, _st, of, _note, _ev,
                  target=args.get("target"))
        return ("Track `%s` - stage %d/%d (%s)\n%s\nStages CAN MOVE BACK - lowering one after a "
                "refutation is the honest thing to do.\nThis table rides in the next session's "
                "carry-over. FOR SIX SESSIONS TO CLIMB SIX RUNGS, YOU HAVE TO MOVE IT."
                % (nm, t["stage"], len(t["stages"]),
                   t["stages"][t["stage"]] if t["stage"] < len(t["stages"]) else "complete",
                   track_render()) + _kept)
    if act == "anchors":
        # A manual lookup. Even with automatic attachment, it must be possible to ask **before** filing a verdict.
        _q = " ".join(str(args.get(k) or "") for k in ("evidence", "claim", "target", "text"))
        r = anchor_hits(_q)
        if not r:
            n = len(_vas(_q))
            return ("None of the %d anchors already appear in the ledger. This is new "
                    "ground.\n(Only 0x-form addresses of 6+ digits are considered. If you gave "
                    "none, put anchors in evidence=.)" % n)
        return r
    if act == "reopen":
        return reopen(args.get("id") or args.get("gid"), args.get("ground"),
                      args.get("why") or args.get("reason"), args.get("evidence") or "")
    if act == "gate_blocked":
        # ★ The reporting channel for when a gate **structurally** blocks a verdict.
        #   2026-09-02: when the function-pointer counter blocked absence-type rejections outright, the agent
        #   spent two rounds going around on other axes. If the only way is around, it goes around — so give it somewhere to report.
        g = (args.get("gate") or "").strip()
        w = (args.get("why") or args.get("reason") or "").strip()
        wo = (args.get("would_be") or args.get("claim") or "").strip()
        # kind: gate (a gate blocked it) · taxonomy (**the ledger has no slot to write it in**) · tool (a tool cannot do it)
        kd = (args.get("kind") or "gate").strip().lower()
        if kd not in ("gate", "taxonomy", "tool"):
            kd = "gate"
        if not g or len(w) < 20:
            return ("`gate_blocked` REQUIRES WHICH gate (gate=) and WHAT it blocked you on (why=, "
                    "at least 20 chars).\nOptional: would_be= 'what you would have filed had it "
                    "not blocked' - kind='taxonomy' WHEN THE LEDGER HAS NO SLOT AT ALL - "
                    "kind='tool' when a tool cannot do it.")
        STATE.setdefault("gate_blocks", []).append(
            {"gate": g[:80], "why": w[:500], "would_be": wo[:400], "target": tgt,
             "kind": kd, "evidence": (args.get("evidence") or "")[:1500],
             # ★ 2026-09-23 — **an environment stamp.** 39 measurement-channel reports said "the channel
             #   was closed at the time", yet they piled up forever even after the channel opened. Stamping the
             #   current state alongside lets a machine sort out **the ones that differ, for rechecking** (without reading sentences).
             "env": _env_stamp(),
             "t": time.strftime("%m-%d %H:%M")})
        save()
        # ★ 2026-09-23 — left as **a row**, not a receipt.
        #   Measured: gate_blocks had piled up to 123 across 8 targets (since 09-02), and the only consumers
        #   were the last 4 printed in the BRIEF and the conductor's screen. Nothing in census, coverage or
        #   grading picked them up, and would_be was cut at 400 chars, so the next session **rebuilt that row from scratch.**
        #   The oldest report (09-02 wcifs) was **the same sentence** as last night's —
        #   "no value expresses 'real defect, gated off'". It means nobody looked for three weeks.
        #   => loaded as an unanalysed verdict. The third slot of the three-way split (confirmed/rejected/unanalysed) is now filled.
        STATE.setdefault("verdicts", []).append(
            {"id": "GB-%s" % time.strftime("%m%d%H%M%S"), "target": tgt,
             "status": "unanalysed", "basis": "blocked", "blocked_by": g[:80],
             "blocked_kind": kd, "claim": (wo or w)[:400],
             "evidence": (args.get("evidence") or "")[:1500], "why": w[:500],
             "t": time.strftime("%m-%d %H:%M")})
        save()
        if kd == "taxonomy":
            save()
            return ("Accepted as a report that THE LEDGER HAS NO SLOT for this: `%s`\nThis is not "
                    "a gate problem, it is a SCHEMA problem - a measured truth the ledger cannot "
                    "hold, and left alone that finding disappears silently.\nBetween sessions the "
                    "conductor reads this and writes it OUTSIDE the schema to "
                    "`reports/unrecordable/<target>.md`, proposing the slot that should exist. If "
                    "you passed `evidence=`, that is carried too.\nSO DO NOT ABANDON THIS AXIS. "
                    "'There is no slot to write it in' and 'there is no defect' are different "
                    "things." % (w[:200]))
        return ("Gate-blocked report accepted: `%s`\nTHIS IS NOT A VERDICT - it does not count "
                "toward coverage. But it stays in the ledger and rides into the next session's "
                "carry-over and the report.\nAnd do not drop the axis just because you filed "
                "this. If another basis can route around it, take that; if not, leave a `blocked` "
                "with the reason - QUIETLY MOVING TO A DIFFERENT AXIS IS THE WORST OUTCOME."
                % (g[:80]))
    if act == "goal":
        return set_goal(args.get("text") or args.get("claim") or "",
                        (args.get("kind") or "judge").lower())
    if act == "worklist":
        return worklist(int(args.get("n") or 12))
    if act == "unfinished":
        return unfinished(int(args.get("n") or 12), int(args.get("offset") or 0))
    if act == "status":
        return status_block(None, None)
    if act == "exhaust":
        # ★ The third slot of the 3-way settle. **It is not a rejection.**
        #   Laundering "there is no method left to use" into a rejection makes the whole re-examination meaningless.
        why = (args.get("reason") or "").strip()
        tried = args.get("tried") or ""
        if len(why) < 20:
            return ("`exhaust` REQUIRES what you tried and why it blocked you (reason=). State "
                    "whether you actually ran the question's `method` - if you did not, it is not "
                    "exhaustion.")
        if not _ask_open(tgt):
            return "That target has no open question. (check with `verdict(action='asks')`)"
        n = _ask_close(tgt, args.get("id") or "-", "exhausted", why)
        for _k in [k for k in (tgt,) if k in STATE.get("surface", {})]:
            STATE["surface"][_k]["status"] = "unanalysed"
            STATE["surface"][_k]["blocked"] = True
            STATE["surface"][_k]["exhausted"] = True
            STATE["surface"][_k]["why"] = "METHOD EXHAUSTED: " + why[:220]
        save()
        return (str(tgt) + " -> METHOD EXHAUSTED (%d " % n +
                "questions closed). This is NOT a rejection - the row stays UNAUDITED in the "
                "table and does not become part of coverage's numerator.\nTried: " + str(tried)[:300])
    if act in ("lead", "leads"):
        # ★ 2026-09-07 — make the lead queue **actionable.** The record (reports/breaks/) existed
        #   since 09-04, but its only consumption path was the latest 3 in `break_digest`, and there was
        #   no way at all to close one. A queue without state never shrinks.
        if act == "leads" or not args.get("id"):
            _ol = open_leads(STATE.get("target"))
            if not _ol:
                return ("0 open leads. (`reports/breaks/` holds %d in total, all closed or "
                        "in the resubmission queue.)" % len(breaks(STATE.get("target"))))
            L = ["=== lead queue — %d open, oldest first ===" % len(_ol)]
            for b in _ol:
                L.append("· `%s` [%s] %s  (%s)"
                         % (b.get("id"), b.get("klass") or "-",
                            str(b.get("target"))[:70], str(b.get("t") or "")[:10]))
                nm = (b.get("next_method") or b.get("reason") or "").replace("\n", " ")
                if nm:
                    L.append("    next move: %s" % nm[:300])
            L += ["", "There are only three ways to close one — `verdict(action='lead', id=…, how=…, why=…)`"]
            L += ["  · %s — %s" % kv for kv in CLOSE_HOWS.items()]
            L += ["There is **no** exhausted. If you cannot close it, leaving it open is the honest thing."]
            return "\n".join(L)
        _r = close_break(args["id"], args.get("how") or args.get("klass") or "",
                         args.get("why") or args.get("reason") or "")
        if not str(_r).startswith("[CLOSE"):
            _bump("leads_closed")
        return _r

    if act == "reaudit":
        # ★ 2026-09-07 — **the defence against false rejections ran only once, at filing time.**
        #   The design intent is "a false rejection is a permanent loss, so guard against it expensively",
        #   but in practice once something passes it is never looked at again: `reopen()` runs only when
        #   the agent calls it itself with grounds in hand, and `rejaudit.audit()`/`regrade()` are
        #   **never called once** on the live path (only `RA.classify` is used — a grade calculation, not a re-examination).
        #   Measured: `verified` in the graveyard is only 34% for ahcache and 37% for wcifs, and
        #   even with `INTERROGATE_RATE=1.0` half are uninterrogated.
        #   => give an **actionable queue.** Counting grades (`graveyard_trust`) already existed, but
        #     that alone moved nobody.
        _c, _rows, _n = graveyard_trust()
        # ★ Even when the queue is empty **the contract must keep the same shape** — without printing 0 the consumer
        #   cannot tell "there is no such grade" from "there is no such slot".
        L = ["=== graveyard re-audit queue — verified negatives %d / total %d ==="
             % (_c.get("verified", 0), sum(_c.values())),
             "  " + " · ".join("%s %d" % (k, _c.get(k, 0)) for k in
                               ("verified", "unexamined", "broke", "reopened",
                                "candidate", "orphan")), ""]
        L.append("① %d rejections that do not stand — this is not a resurrection but **bookkeeping.** "
                 "`verdict(action='reopen', gid=<id>, ground='new_evidence', why=…)`" % _n)
        if _rows:
            for r in _rows[:8]:
                L.append("   [%s] %s (%s) — %s"
                         % (r["grade"], r["id"], r.get("klass"), str(r.get("why") or "")[:90]))
        else:
            L.append("   (none — no broken rejection or withdrawal mark remains)")
        _un = [g for g in (STATE.get("graveyard") or [])
               if not g.get("reopened")
               and not any(str(v.get("id")) == str(g.get("id"))
                           and (v.get("interrogated") is True
                                or ((v.get("interrogation") or {}) if isinstance(
                                    v.get("interrogation"), dict) else {}).get("broke"))
                           for v in (STATE.get("verdicts") or []))]
        if _un:
            import collections as _c2
            _byk = _c2.Counter(g.get("klass") for g in _un)
            L += ["", "② %d rejections that never went through an adversary — reason distribution: %s"
                  % (len(_un), " · ".join("%s %d" % kv for kv in _byk.most_common(6))),
                  "   ★ 'unverified' does not mean 'wrong'. Checked on a sample, this bucket was",
                  "     a **procedural defect**, not an accuracy defect — use it as a list of candidates to",
                  "     revisit when a new measurement, a new build or a counterexample in a sibling function appears.",
                  "   one representative per reason:"]
            _seen = set()
            for g in reversed(_un):
                if g.get("klass") in _seen:
                    continue
                _seen.add(g.get("klass"))
                L.append("     [%s] %s — %s" % (g.get("klass"), str(g.get("id"))[:44],
                                                str(g.get("target"))[:50]))
                if len(_seen) >= 6:
                    break
        return "\n".join(L)

    if act == "resisted":
        # ★ 2026-09-08 — **rows that someone tried to kill and failed.** All of this harness's pressure is
        #   "killing", yet an attempt that failed had no consumption path. `denial_report()` aggregates
        #   per rule, so it does not answer "which row held out".
        _rw, _c = resisted(STATE.get("target"))
        if not _rw:
            return ("resisted queue: 0 — on this target no rejection attempt was ever denied, no CFG "
                    "refuted a pair, and no interrogator broke a rejection. (This is 0, not unmeasured: "
                    "%d denial records · %d verdicts were examined.)"
                    % (len(STATE.get("denials") or []), len(STATE.get("verdicts") or [])))
        L = [resisted_digest(STATE.get("target"), n=12), "",
             "%d or more axes overlap on %d rows — overlap is the top signal. A single axis (denials only) can "
             "be a paperwork problem, but **a row denied again and again under changing klasses** means several "
             "death hypotheses did not take." % (2, _c["multi_axis"]),
             "",
             "★ The only way to close this queue is **re-analysis**, and it ends in one of three ways:",
             "  · file a rejection again that meets the requirement (if the denial was a paperwork problem, that is the right answer)",
             "  · `verdict(action='confirm', …)` — if the reason it will not die is that it is a defect",
             "  · `verdict(action='exhaust', …)` — there is no method left to use. This is not a rejection",
             "Close rows carrying a lead id **there** — two queues do not ask for the same work."]
        return "\n".join(L)

    if act == "asks":
        # ★ 2026-09-07 — **split by recipient.** The old behaviour dumped everything into one bucket, and 40% of
        #   that bucket were ledger/gate audit questions starting with `harness /…`. They were not questions
        #   the analyst could answer, so they were closed as exhausted, and that showed on the dashboard as a "49% give-up rate".
        mine = open_asks(audience="analyst", rank=True, include_leads=True)
        ops = open_asks(audience="operator")
        if not mine and not ops:
            return "No open questions."
        L = ["open questions — %d yours · %d the operator's. "
             "THESE ARE NOT NEGATIVES, THEY ARE UNAUDITED." % (len(mine), len(ops))]
        for q in mine:
            # ★ 2026-09-08 — **show the source and kind alongside.** This queue is sorted by measured yield
            #   per source (conductor 0/72 against gate 15/40), and interrogator leads close via
            #   `verdict(action='lead')`, not `_ask_close` — when the way to close differs, it has to be said.
            L.append("\n[%s] (%s/%s) %s  (cfg=%s, %d attempts)\n  why   : %s\n  method: %s%s"
                     % (q["id"], normalize_ask_by(q.get("by"), q.get("id")),
                        q.get("kind") or "?", q["target"], q.get("cfg"),
                        len(q.get("attempts") or []),
                        (q.get("why") or "")[:200], (q.get("method") or "")[:260],
                        ("\n  close : " + q["_close_via"]) if q.get("_close_via") else ""))
        if ops:
            L.append("\n— %d for the operator (harness/ledger audits. **Not your job** — do not answer them "
                     "or exhaust them. If you hit the same wall again, file it fresh with `gate_blocked`):"
                     % len(ops))
            for q in ops[:8]:
                L.append("  · [%s] %s" % (q["id"], str(q["target"])[:70]))
            if len(ops) > 8:
                L.append("  · … and %d more" % (len(ops) - 8))
        return "\n".join(L)
    return ("action must be one of: confirm | reject | blocked | scope | goal | track | "
            "gate_blocked | reopen | reaudit | asks | exhaust | lead | leads | "
            "worklist | unfinished | status.")


def stash_escalation(tgt, v):
    """The escalator is a pre-gate that runs **before** the verdict is recorded => there is no verdict to attach to yet.
    Keep it here and `verdict()` stamps it in at record time. (The same spot where interrogation results used to evaporate wholesale.)"""
    STATE.setdefault("pending_escalation", {})[tgt] = {
        "escalated": bool(v.get("escalated")), "axis": v.get("axis"),
        "principal": (v.get("principal") or "")[:300],
        "reason": (v.get("reason") or "")[:400],
        "enumerated": (v.get("enumerated") or "")[:400]}
    save()



_NEXT_ANCHOR = re.compile(r"0x[0-9a-fA-F]{6,16}|\b[A-Z][a-z]+[A-Z][A-Za-z]{5,}\b")


def _next_step_ok(s):
    """Does `next=` count as 'the next single step'? **A format check, not a prose classification.**

    Prose classification was tried and failed (measured 2026-09-05, C-037): over 498 blocked rows,
    (method verb|question mark)+anchor → 278 rows (56%), grounding in an unjudged anchor → 245 rows, and
    even that drops 3 of the 4 rows C-034 pointed at. The median reason is 882 chars, so nearly every row
    contains a verb and an address. => **if the reader cannot pick, the writer declares.**

    Two requirements (the same family as scope's 30-char minimum for method):
      · at least 40 chars — a one-liner like "needs re-check" cannot be picked up by the next round
      · one anchor — a VA (0x…) or a CamelCase symbol. **With nothing to do it against, it is not a step**
    """
    t = (s or "").strip()
    if not t:
        return (False, "next= itself is empty")
    if len(t) < 40:
        return (False, "at least 40 chars (now %d)" % len(t))
    if not _NEXT_ANCHOR.search(t):
        return (False, "one anchor — a VA (0x14004efc0) or a symbol (SdbpInitializeSearchDBContext)")
    return (True, "")


_ALIAS_MARK = re.compile(r"\bALIAS\b|ALREADY ADJUDICATED", re.I)


def _is_alias_row(why):
    """Is this BLOCKED row a **bookkeeping alias** (its verdict lives on another row)?

    ★ A false exclusion caught in the 2026-09-05 final check: at first `lives on|canonical row` was also
      matched, but that catches **prose about code** — 3 of 55 rows were falsely excluded, and those three
      were exactly the rows that had to be recovered ("NEXT STEP for…", "the constraint genuinely lives only
      in the caller"). I had reproduced, in the exclusion rule, the very pathology I had just written up in C-037.
    ★ It also **requires a position** (the first 120 chars). An alias row's first sentence is bookkeeping
      ("DUPLICATE ALIAS from a FRESH=1 restore. Judgement lives on fn2_AhcApiUpdate…").
      The one row matched only further back was in fact the **canonical** row — it said it had 9 aliases
      under it, so ignoring position would delete the canonical row and keep the aliases.
    Measured: restricted to the first 120 chars, all 51 sampled rows are real aliases · 0 false exclusions.
    """
    w = re.sub(r"^BLOCKED[:\s—-]*", "", str(why or "")).strip()
    return bool(_ALIAS_MARK.search(w[:120]))


def unfinished(n=12, offset=0):
    """★ **Enumerate the blocked reservoir.** A list, not a ranking — that is the honest form.

    C-034 said "move BLOCKED rows whose reason states a next step to the top of the worklist".
    Three predicates were built to implement it and measured, and all of them failed (C-037):
      current keywords 61/498 · (verb|?)+anchor 278/498 (56%) · unjudged-anchor grounding 245/498
      and the grounded one **drops 3 of the very 4 rows C-034 pointed at.**
    => the machine cannot pick. So **instead of picking, it counts and shows** — it states the
      reservoir's real size first (hundreds of rows) and pages through it. Picking is the analyst's / goal's job.
      (The lesson of C-021: rows that cannot be enumerated come back as ~150 name probes.)

    Excluded: aliases / already-judged rows (the verdict lives on another row) / exhausted rows.
    Order: rows with a `next=` field → unprivileged reach → never picked → longer reason.
    """
    surf = STATE.get("surface") or {}
    V = STATE.get("verdicts") or []
    judged = set()
    for v in V:
        judged |= {a.lower() for a in re.findall(r'0x[0-9a-fA-F]{6,16}',
                                                 json.dumps(v, ensure_ascii=False))}
    rows, alias, exh = [], 0, 0
    for k, r in surf.items():
        if not r.get("blocked"):
            continue
        w = str(r.get("why") or "")
        if r.get("exhausted"):
            exh += 1; continue
        if _is_alias_row(w):
            alias += 1; continue
        nx = (r.get("next") or {}).get("step") if isinstance(r.get("next"), dict) else None
        rch = (r.get("reach") or "").lower()
        up = any(t in rch for t in ("user-direct", "user-trigger", "unprivileged"))
        fresh = len({a.lower() for a in re.findall(r'0x[0-9a-fA-F]{6,16}', k + " " + w)} - judged)
        rows.append((bool(nx), up, int(r.get("picks") or 0) == 0, len(w), k, r, nx, rch, fresh))
    rows.sort(key=lambda x: (not x[0], not x[1], not x[2], -x[3]))
    withnext = sum(1 for x in rows if x[0])
    tot = len(rows)
    if not tot:
        return "the blocked reservoir is empty."
    off = max(0, int(offset or 0))
    if off >= tot:
        return ("blocked reservoir: %d rows — offset=%d is past the end. The last page is offset=%d."
                % (tot, off, max(0, tot - 12)))
    page = rows[off:off + max(1, int(n or 12))]
    L = ["blocked reservoir: **%d rows** (excluding %d aliases · %d exhausted) — showing %d~%d. For more, offset=%d"
         % (tot, alias, exh, off + 1, off + len(page), off + len(page)),
         "★ Of those, **%d rows declare** their next step in the field. The rest have only reason prose, and "
         "**the machine cannot pick** which of them states a next move (measured) — read and pick." % withnext]
    for hasnx, up, fresh_pick, _wl, k, r, nx, rch, fresh in page:
        w = re.sub(r"^BLOCKED[:\s—-]*", "", str(r.get("why") or "")).strip()
        head = re.split(r"(?<=[.?!])\s", w)[0] if w else "(no reason)"
        L.append("\n· %s%s\n    reach=%s · unjudged anchors %d · picks=%s"
                 % (k[:72], "  [next field set]" if hasnx else "", rch[:20] or "-", fresh,
                    r.get("picks") or 0))
        L.append("    %s: %s" % ("NEXT" if hasnx else "WHY", (nx or head)[:220]))
    L.append("\nThese rows remain in the coverage denominator. Pick one and close it to the end, or "
             "fill the field with `verdict(action='blocked', ..., next='<one step>')` so the next round can pick it up.")
    return "\n".join(L)


def _ask_for(target):
    """The open question attached to a surface key. None if there is none. Used by the worklist's scoring axis."""
    t = str(target)
    best = None
    for a in (STATE.get("asks") or []):
        at = str(a.get("target") or "")
        if at == t or (len(at) > 12 and (at in t or t in at)):
            # prefer the one with more attempts — that is what is blocking right now
            if best is None or len(a.get("attempts") or []) > len(best.get("attempts") or []):
                best = a
    return best


def worklist(n=12):
    """★ **What should be dug up again.** The opposite of an exhaustive sweep.

    When the table is large (hundreds of rows), "look at everything again" is infeasible, and even done it yields nothing.
    Rows have to be picked, and if the discipline for picking is not in code, every round improvises it.
    The score here is not a single axis but **"does this row move the grade of a defect already in hand"**.

    Positive axes — rows that move it:
      +4 sits **on the chain of a live confirmation** (the confirmation's target/claim/impact points at this row)
      +3 a confirmation holding an **ungrounded exhaustive claim** (that one sentence alone sets the grade cap)
      +3 a **weak rejection** — has a klass but neither a CFG verdict nor an interrogation (not a verified negative)
      +2 **unprivileged reach** (user-direct / user-triggerable)
      +2 a blocked row with a next move written (the cost of moving it is already written down)
      +1 `scope` declared but candidates remain (half-closed — cheap to finish)
    Negative axes — rows that yield nothing when touched:
      -4 method exhausted (exhaust)  -3 already confirmed  -2 kernel-only reach
    """
    surf = STATE.get("surface") or {}
    V = STATE.get("verdicts") or []
    conf = [v for v in V if v.get("status") == "confirmed"]
    conftext = " ".join(json.dumps(v, ensure_ascii=False) for v in conf).lower()
    byt = {}
    for v in V:
        byt.setdefault(str(v.get("target")), []).append(v)

    def addrs(k):
        return set(re.findall(r'0x[0-9a-fA-F]{6,16}', k))

    rows = []
    for k, r in surf.items():
        st = r.get("status") or ""
        sc, why = 0, []
        kl = k.lower()
        if kl[:60] in conftext or (addrs(k) and any(a.lower() in conftext for a in addrs(k))):
            sc += 4; why.append("on a confirmation's chain")
        if st == "confirmed":
            sc -= 3
            for v in byt.get(k, []):
                imp = v.get("impact") or {}
                if imp.get("sole_claim") and not imp.get("enumerated"):
                    sc += 3; why.append("ungrounded exhaustive claim")
        for v in byt.get(k, []):
            if v.get("status") != "rejected":
                continue
            g = v.get("gate") or {}
            if (g.get("klass") in ("not_controlled", "by_design", "delta_zero", "no_sink")
                    and not ((g.get("cfg") or {}).get("verdict"))
                    and not v.get("interrogated")):
                sc += 3; why.append("weak rejection (%s, no CFG/interrogation)" % g.get("klass")); break
        rch = (r.get("reach") or "").lower()
        if any(w in rch for w in ("user-direct", "user-triggerable", "unprivileged")):
            sc += 2; why.append("unprivileged reach")
        elif "kernel-only" in rch:
            sc -= 2
        # ★ 2026-09-03: `asks` was **not on the scoring axes at all.** The ledger counts retries
        #   (`asks[].attempts`) but the scoring did not read them, so the same question was picked up to 5 times
        #   (ahcache VARIANT-AXIS-S22 5 times / D_axis_quirks_section 4 times, all eventually exhausted).
        #   => use the question as a **two-way axis**: raise questions not yet tried, lower repeated failures.
        _aq = _ask_for(k)
        if _aq is not None:
            _at = len(_aq.get("attempts") or [])
            _ast = (_aq.get("status") or "open").lower()
            if _ast == "answered":
                sc += 3; why.append("★ the open question **has been answered** — a verdict is now possible")
            elif _ast == "exhausted":
                sc -= 4; why.append("question exhausted (%d attempts)" % _at)
            elif _at == 0:
                sc += 2; why.append("the question is open WITH A METHOD and has never been "
                                    "attempted")
            else:
                sc -= min(6, 2 * _at)
                why.append("the same question failed %d times — do not use the same method again (%s)"
                           % (_at, str(_aq.get("method"))[:40]))

        w = str(r.get("why") or "")
        # ★ It used to be an unconditional +2 for `blocked` + 'next move'. That is, **being blocked was itself
        #   a bonus**, so in a table with 476/518 (92%) blocked, the same rows kept coming to the top.
        #   => even with a next move written, lower the row if **it was picked and did not move.**
        _picks = int(r.get("picks") or 0)
        # ★ 2026-09-05 (C-037): split into two grades. **Declared in the field** (next=) vs a prose match.
        #   The regex is not widened — widen it and 56% of blocked rows match, so the axis loses its information (measured).
        _nxs = r.get("next") if isinstance(r.get("next"), dict) else None
        _nxs = (_nxs or {}).get("step")
        _prose = bool(re.search(r"TO MOVE|next move|next step", w, re.I))
        if r.get("blocked") and (_nxs or _prose):
            if _picks == 0:
                sc += 3 if _nxs else 2
                why.append(("★ the next single step is **declared in the field**: " + str(_nxs)[:90]) if _nxs
                           else "a next move is written in the reason prose (not in the field)")
            else:
                sc -= min(4, _picks)
                why.append("picked %d times with the next move already written down, and it never "
                           "moved - change the method" % _picks)
        cand = (r.get("cand") or {}).get("items") or []
        if cand and any(not i.get("done") for i in cand):
            sc += 1; why.append("scope candidates %d/%d left"
                                % (sum(1 for i in cand if not i.get("done")), len(cand)))
        # ★ The differential axis (refs/03): all 7 confirmations came from **setting up a population and the one that sticks out**.
        #   When a family has siblings and some of them are judged, the rest become comparison targets —
        #   the hunting ground is not "code that looks dangerous" but **code that differs from its siblings**.
        fam = re.match(r'^([A-Za-z_][A-Za-z0-9_]{2,}?)[._:@\-]', k)
        if fam:
            sib = [kk for kk in surf if kk != k and kk.startswith(fam.group(1))]
            done_sib = [kk for kk in sib if surf[kk].get("status") in ("confirmed", "rejected", "boundary-held")]
            if len(sib) >= 2 and done_sib:
                sc += 2
                why.append("differential possible (%d siblings, %d judged)" % (len(sib), len(done_sib)))
        for _v in byt.get(k, []):
            if (_v.get("impact") or {}).get("out_of_scope"):
                # Not lowered. This row has its remaining question narrowed to **one**, and filling it
                # makes it a confirmation at once — the cheapest confirmation candidate in the ledger.
                sc += 3
                why.append("boundary-held (%s) — one lower-privilege principal and it is confirmed"
                           % _v["impact"]["out_of_scope"])
                break
        if r.get("incidental"):
            sc += 3; why.append("incidental find (%s)" % str(r["incidental"])[:40])
        if r.get("exhausted"):
            sc -= 4; why.append("method exhausted")
        if sc > 0:
            rows.append((sc, k, st, "; ".join(why)))
    rows.sort(key=lambda x: -x[0])
    if not rows:
        return ("worklist: no row has a positive score. Either the table is empty or everything "
                "is exhausted or confirmed. If you need a new denominator, that is a different "
                "session's job.")
    surf = STATE.get("surface") or {}
    L = ["%d ROWS STILL WORTH DIGGING (this is not an exhaustive sweep - it is the order that "
         "MOVES THE GRADE of a finding you already hold)" % min(n, len(rows))]
    for sc, k, st, why in rows[:n]:
        # ★ **Count** the rows handed out. Without this counter "a next move is written" is
        #   a bonus forever — having it written is not the same as having tried it.
        _r = surf.get(k)
        if isinstance(_r, dict):
            _r["picks"] = int(_r.get("picks") or 0) + 1
        L.append("  [%+d] %-58s %s" % (sc, k[:58], st))
        L.append("       %s" % why)
    save()
    L += ["", "Work top down, one at a time. Close a row to the end before moving on - do not "
              "touch several shallowly.",
          "The score is not 'importance' - it is MOVABILITY x EFFECT ON THE GRADE."]
    return "\n".join(L)


def record_image(meta):
    """★ Record the build identity of **every** image used cross-image.

    Why it is mandatory: a record that `nt!0x14098f670` was verified cannot be reproduced unless
    **which ntoskrnl** is recorded with it. An anchor verified against another build is a coincidence, not a verification.
    """
    imgs = STATE.setdefault("images", {})
    imgs[meta["name"]] = dict(meta, t=time.strftime("%m-%d %H:%M"))
    save()
    return imgs[meta["name"]]


def record_xref(desc, sections, names, nhits):
    """Record the fact that an xref over every executable section was run. The absence-claim gate requires it.

    A failure where only `.text` was looked at and 'there is no API call' was written (ipt.sys / SeSinglePrivilegeCheck @PAGE)
    really happened. What was swept, and in which sections, is part of the grounds.
    """
    STATE.setdefault("xrefs", []).append(
        {"desc": desc, "sections": list(sections), "names": list(names)[:40],
         "hits": nhits, "t": time.strftime("%m-%d %H:%M")})
    save()


PRIORART_AXES = ("device", "ioctl", "symbol")

# Patterns that derive, from the target/claim, **the strings that should have been searched for as prior art**.
_DEV_RE = re.compile(r'\\{1,2}(?:Device|GLOBAL\?\?|DosDevices|\?\?)\\{1,2}[A-Za-z0-9_.\-]{2,48}')
# CTL codes: `_CODE_RE` (0x8xxxxxxx) is narrow — real confirmations in this ledger include 0x2A400C, 0x22C00C and
# 0x39006F, and none of them match. Also take 5~8 digits in an IOCTL/CTRL/FASTIO context.
_IOCTL_CTX = re.compile(r'(?:IOCTL|CTL_CODE|CTRL|FASTIO)[^\n]{0,16}?(0x[0-9a-fA-F]{4,8})', re.I)
# Handler/struct name candidates: identifiers of 6+ chars containing at least 2 capitals
_SYMB_RE = re.compile(r'\b(?=[A-Za-z_]*[A-Z][A-Za-z_]*[A-Z])[A-Za-z_][A-Za-z0-9_:]{5,60}\b')
_SYMB_STOP = {"IOCTL", "METHOD_NEITHER", "METHOD_BUFFERED", "METHOD_IN_DIRECT",
              "METHOD_OUT_DIRECT", "PAGE_READWRITE", "PAGE_WRITECOPY", "FILE_ANY_ACCESS",
              "FILE_READ_ACCESS", "FILE_WRITE_ACCESS", "CONFIRMED", "INFERRED", "TODO"}


def priorart_tokens(target="", text=""):
    """Derive, from the ledger and the claim, **the strings that should have been searched for as prior art** for this confirmation.

    ★ An axis that derives nothing is not required. An unsatisfiable gate makes the agent escape
      into `blocked`, which is worse — the same reason `_impact_gate` handles owner='none' as a
      grade cap rather than a refusal.
    """
    blob = " ".join([str(target or ""), str(text or ""),
                     " ".join(STATE.get("surface") or {})])
    out = {}
    dev = _DEV_RE.findall(blob)
    if dev:
        out["device"] = sorted(set(dev))[:4]
    codes = set(_IOCTL_CTX.findall(blob)) | set(_CODE_RE.findall(blob)) | set(code_index())
    # if the target itself points at one code, require only that one (not every code of every target)
    own = set(_IOCTL_CTX.findall(str(target or ""))) | set(_CODE_RE.findall(str(target or "")))
    if own:
        codes = own
    if codes:
        out["ioctl"] = sorted(codes)[:4]
    syms = [s for s in _SYMB_RE.findall(blob)
            if s not in _SYMB_STOP and not s.startswith("0x")]
    if syms:
        # the few longest — more search value than short abbreviations
        out["symbol"] = sorted(set(syms), key=len, reverse=True)[:4]
    return out


def priorart_gaps(target="", text=""):
    """A list of (axis, expected tokens, reason). Empty means confirming is allowed.

    ★ Why axes — the old gate only checked whether `has_priorart()` was **non-empty**.
      That means one line, `priorart(what='x', where='y', result='none')`, opened it.
      The prompt said "search at least (1) the device name (2) the IOCTL code (3) the handler/struct name,
      all three" and **the code did not count them.**
      ksecdd passed 32 machine-verified anchors + survived the refuter and was still a 2024 public writeup,
      and that IOCTL even had a published name, `IOCTL_KSEC_IPC_SET_FUNCTION_RETURN`.
      => it checks not "did you write that you searched" but **"did you search with this string"**.
    """
    recs = STATE.get("priorart") or []
    want = priorart_tokens(target, text)
    gaps = []
    for ax in PRIORART_AXES:
        toks = want.get(ax) or []
        if not toks:
            continue
        mine = [r for r in recs if (r.get("axis") or "").lower() == ax]
        if not mine:
            gaps.append((ax, toks, "no search recorded on this axis"))
            continue
        blob = " ".join(" ".join(str(r.get(k) or "") for k in ("what", "where", "result"))
                        for r in mine).lower()
        if not any(t.lower() in blob for t in toks):
            gaps.append((ax, toks, "there are records, but that string does not appear in them"))
    return gaps


def render_priorart_gaps(gaps):
    L = ["You have NOT SEARCHED FOR PRIOR ART on every axis this claim needs. "
         "Anchors and the refuter cannot catch a published finding — ksecdd passed both and was "
         "a 2024 public writeup with a documented IOCTL name."]
    for ax, toks, why in gaps:
        L.append("  · axis=%-6s %s — strings that should have been searched: %s"
                 % (ax, why, ", ".join(str(t) for t in toks[:4])))
    L.append("Record each with priorart(axis='device'|'ioctl'|'symbol', what=<the exact string "
             "you searched>, where=<source>, result=<what you found>). If an axis genuinely does "
             "not apply, file it with result='n/a: <why>' — that is an honest negative and it is "
             "recorded; silence is not.")
    return "\n".join(L)


def record_priorart(what, where, result, axis=""):
    """Prior-art search record. The confirm gate requires it.

    Why: a ksecdd.sys confirmation passed 32 machine-verified anchors + survived the refuter, and
    **had already been published in 2024** (KExecDD / SCRT). IOCTL 0x39006F even carried the name
    `IOCTL_KSEC_IPC_SET_FUNCTION_RETURN`.
    A gate that looks only at code can never catch this — hence a separate record is required.

    ★ `axis` must be one of three. The gate does not count a record with no axis —
      stopping a single line from claiming to cover all three axes is why this field exists.
    """
    ax = (axis or "").strip().lower()
    if ax and ax not in PRIORART_AXES:
        return ("axis must be one of %s (got: %r)." % (" / ".join(PRIORART_AXES), axis))
    STATE.setdefault("priorart", []).append(
        {"what": what, "where": where, "result": result[:600], "axis": ax,
         "t": time.strftime("%m-%d %H:%M")})
    save()
    tail = ""
    if not ax:
        tail = ("\n⚠ no axis given — this record **is not counted by the confirm gate.** "
                "Record it again with axis='device'|'ioctl'|'symbol'.")
    return ("prior art recorded: %s (%s)%s\n%s" % (what, where, "" if not ax else " [axis=%s]" % ax,
                                            result[:200]) + tail)


def has_priorart():
    return list(STATE.get("priorart") or [])


# ── scope policy (set by the operator) ─────────────────────────────────
# ★ User decision 2026-09-02: **"admin → kernel is all meaningless, so reject it."**
#   MSRC does not service admin→kernel as a security boundary either. Yet all 4 wcifs confirmations
#   hung on exactly that, and the harness, not knowing it, kept spending time on that axis.
#   => **it does not reject outright** — a path by which a lower privilege reaches the same sink may remain,
#     and finding that path is this axis's only value (operator decision 2026-09-02).
#   => **it just does not promote it to a confirmation.** It keeps it alive as status=boundary-held and hands it to the escalator.
# ★ The rule looks **only at the boundary field.** And the admin token must be on the **left** of the arrow (the source).
#   The first implementation also concatenated owner/principal and swept them, and **immediately produced 2 false positives** in our ledger:
#     · S13-OP12-FLAGS3 — the boundary was "container (server silo) → host kernel", but
#       the principal sentence said "…BUILTIN\\Administrators or SYSTEM per the fltMgr default SD —
#       **including a container-local administrator, which is a different principal**".
#       That is, **a mention of admin inside the argument** was misread as the boundary.
#     · S13-UAF-AVLNODE-V2 — the boundary headline was "**Unprivileged** file I/O → host kernel
#       memory corruption", and admin appeared in a **self-declared limit** sentence: "but the free
#       side I proved is privileged".
#   => the more careful the argument, the more it mentions the opposing principal. A broad seed kills **the best-written rows first**.
#     (the same family as `detector-seed-too-broad`)
_ARROW = re.compile(r'(→|->|=>|➜|\bto\b)')
_ADMIN = re.compile(r'BUILTIN\\Administrators|S-1-5-32-544|Administrators?\b|'
                    r'\bSYSTEM\b|elevated', re.I)
# If any of these is on the left, **the source is not admin** — not subject to the policy.
_LOWER = re.compile(r'unprivileged|non-?admin|standard user|low(-| )?priv|AppContainer|sandbox|'
                    r'container|silo|anonymous|unauthenticated|remote|guest', re.I)


# ─── the boundary as a field (2026-09-10, priority 2) ──────────────────────────────────
#   ★ Why: `scope_verdict()` reads the `boundary` **prose** with a regex. Measured — of 16 confirmations
#     across all targets, 6 have a boundary field at all, and of those 6 the policy fired on
#     **1** (a row where the analyst happened to write "Administrators/SYSTEM -> kernel").
#     And even that 1 sits in the ledger as `confirmed` — `boundary-held` used 0 times.
#     => prose cannot carry a predicate (memory `prose-cannot-carry-a-predicate`).
#
#   The lattice is the **privilege order as seen from the host.** A container admin sharing a slot with
#   standard-user is not a mistake — from the host kernel's point of view both are unprivileged, and one wcifs
#   confirmation is exactly that claim (Windows Server Container → host kernel).
PRINCIPAL_LATTICE = {
    "remote-anonymous": 0, "remote-authenticated": 1,
    "appcontainer": 2, "low-il": 3,
    "standard-user": 4, "container-admin": 4,
    "admin": 5, "system": 6, "kernel": 7, "hypervisor": 8,
}
# A value by which the analyst declares it cannot confirm. It passes, but goes to **boundary-held, not confirmed**.
PRINCIPAL_UNPROVEN = "unproven"


def boundary_typed(frm, to):
    """Two declared principals → (is_boundary, why). `is_boundary` is yes | no | unknown.

    Policy source: MSRC servicing criteria + operator decision (2026-09-02, admin→kernel is not a
    boundary). **This is not a fact the graph answers but the vendor's policy** — hence a table.
    """
    f, t = str(frm or "").strip().lower(), str(to or "").strip().lower()
    if f == PRINCIPAL_UNPROVEN or t == PRINCIPAL_UNPROVEN:
        return ("unknown", "one of source/destination is unproven — the minimum principal is not established yet")
    if f not in PRINCIPAL_LATTICE or t not in PRINCIPAL_LATTICE:
        return ("unknown", "principal not in the lattice (%s → %s)" % (frm, to))
    lf, lt = PRINCIPAL_LATTICE[f], PRINCIPAL_LATTICE[t]
    if lt <= lf:
        return ("no", "privilege does not go up (%s ≥ %s) — not an escalation" % (f, t))
    if lf >= PRINCIPAL_LATTICE["admin"]:
        # admin→kernel · admin→system · system→kernel …
        return ("no", "starts at admin or above — not a security boundary under the MSRC "
                      "servicing criteria (operator decision 2026-09-02). If a path by which a lower "
                      "principal reaches the same sink remains, that is this row's value")
    return ("yes", "%s → %s is a boundary the vendor recognises" % (f, t))


def principal_evidence(target, frm, state=None):
    """Does **a measurement back** the declared source principal? (verdict, note)

    ★ This is the first place that consumes the `principal_grade` planted by priority 1 (T46). It is where those
      two steps join — without knowing which token a measurement came from, "a low privilege reaches it" cannot be confirmed.
      A real case: ahcache `S9-D4`/`S10-VA1` are confirmed as `boundary=standard-user → machine-wide integrity`,
      yet all a low privilege actually gets is `PAGE_WRITECOPY`
      (memory `ahcache-authz-population-half`: "no grounds — due for a grade review").
    """
    f = str(frm or "").strip().lower()
    if f not in PRINCIPAL_LATTICE:
        return ("n/a", "")
    grade, recs = measured_principal(target, state=state)
    if PRINCIPAL_LATTICE[f] >= PRINCIPAL_LATTICE["admin"]:
        return ("n/a", "the source is admin or above, so no low-privilege measurement is needed")
    if grade == "none":
        return ("unmeasured", "this target has no measurement record — the source principal rests on static argument alone")
    if grade == "verified_low":
        return ("verified", "backed by a measurement from a non-elevated token")
    if grade in ("verified_elevated", "verified_default"):
        return ("mismatch",
                "the source was declared as %s but the backing measurement came from an **elevated token** (%s). "
                "Whether a low privilege gets the same result has not been measured yet — a grade cap applies." % (f, grade))
    return ("unmeasured",
            "the backing measurement's credentials are %s. The ledger does not say which token it came from, so "
            "the measurement cannot back '%s reaches it'. "
            "Fire it again with ioctl(where='guest', principal='low') and the harness verifies the token."
            % (grade, f))


def scope_verdict(impact):
    """**Is the boundary out of scope?** Returns (label, why) or (None, '').

    ★ Operator decision 2026-09-02, part 2: "just do not **promote** admin→kernel to a confirmation."
      Not an outright rejection — a path by which a lower privilege reaches the same sink may remain,
      and finding that path is this axis's only value.
    """
    b = str((impact or {}).get("boundary") or "")
    if not b:
        return None, ""
    m = _ARROW.search(b)
    left = b[:m.start()] if m else b          # with no arrow, the whole sentence is taken as the source
    if not _ADMIN.search(left):
        return None, ""
    if _LOWER.search(left):
        # a lower principal is written in the source too = this row does not claim admin as its headline.
        return None, ""
    return ("admin→kernel",
            "admin->kernel is not a security boundary (MSRC servicing criteria; operator decision "
            "2026-09-02)")


_ADDRLIKE = re.compile(r'0x[0-9a-fA-F]{5,16}')


def claim_anchor_link(claim, anchors):
    """★ **Are the addresses the claim names among the anchors?** (unlinked_addrs, note)

    Why: our gates are all **extensional** — they only ask "is that instruction at the cited VA".
    *Nobody checks whether that instruction supports the claim.* So rebuilding the grounds to fit the
    gate's shape works (round of 2026-09-02: "the gate wants machine-verified anchors. Bring them back as-is").
    The literature's prescription is **isomorphic verification** — check that the answer holds when the problem is transformed (`refs/00-gate-gaming.md`).
    Its counterpart in binary verdicts is this: **are the addresses carrying the claim's weight actually
    in the set of verified anchors?** If not, the claim was not verified by those anchors.

    Only address-shaped values (≥5 hex digits) are considered. Requiring small constants too widens the detector and disarms the gate.
    """
    have = set()
    for a in anchors or []:
        va = a.get("va")
        if isinstance(va, int):
            have.add(va)
        for m in _ADDRLIKE.finditer(str(a.get("insn") or "") + " " + str(a.get("actual") or "")):
            try:
                have.add(int(m.group(0), 16))
            except ValueError:
                pass
    want = set()
    for m in _ADDRLIKE.finditer(claim or ""):
        try:
            want.add(int(m.group(0), 16))
        except ValueError:
            pass
    unlinked = sorted(w for w in want if w not in have)
    if not unlinked:
        return [], ""
    return unlinked, (
        "The address %s named in the claim IS NOT AMONG THE VERIFIED ANCHORS.\nAnchor "
        "verification only asks 'does the cited instruction exist' - whether that instruction "
        "SUPPORTS THIS CLAIM is a separate question. Cite the address the claim's weight rests on "
        "so it gets machine-checked.\n(If an address appears only in the claim and not in the "
        "evidence, that is narration, not evidence.)")


def _images_for_anchor():
    """Auxiliary images for anchor verification. **Imported lazily to avoid a circular import.**

    ★ Bug of 2026-09-02: during the cross-image wiring, `images=` was passed on the confirm path
      (`agent_sdk._anchor_gate`) and to the `anchor` tool, but **only the reject path (`_reject_gate`) was missed.**
      So the same `nt!0x…` citation passed 9/9 in the `anchor` tool and failed every time in
      `verdict(action='reject')` — the agent reported it verbatim in the round log. Wiring must go **into every path together**.
    """
    try:
        import tools as _T
        return _T.images_all()
    except Exception:
        return {}


def has_xref(kind=None):
    for x in STATE.get("xrefs") or []:
        if kind is None or kind.lower() in (x.get("desc") or "").lower():
            return x
    return None


def control(kind, what, result):
    kind = (kind or "").lower()
    if kind not in ("positive", "negative", "swap"):
        return "kind is positive | negative | swap."
    STATE["controls"].setdefault(kind, []).append({"what": what, "result": result})
    save()
    return f"control recorded: {kind} — {what} → {result}"


# ── gate denial records (D-type grounding: behaviour the harness observed) ────────
# ★ Why (2026-09-05, operator question "are the gates actually helping?"):
#   Measured: **692 of 3,506 verdict tool calls (20%) were denied by a gate, and what they blocked was
#   recorded nowhere.** There are 49 denial points (`_reject_gate` 21 · `_gate_verdict` 11 · `verdict()` 17),
#   yet all that remains is a single `gate_denials` counter. The incident log stamps only `[tool ]`/`[think]` and
#   not tool results, so grepping the whole log for the gates' own wording ("STALE-BUILD ANCHOR" etc.) finds 0
#   — not because nothing was caught but **because nothing was recorded.**
#
#   The result was an asymmetry: the adversarial layer is auditable (escalations 6/8 · interrogations 93/152 ·
#   refutations 8/13) while the deterministic layer is not, which is why every diagnosis of the last few days came from the adversaries' side.
#
# ★ This function **blocks nothing.** It only observes. One round later `denial_report()` produces a table
#   of "which rule caught what, how many times", and gates that catch nothing are then removed on the data.
#   This is the hole memory `grounding-decides-gate` noted as "D-type is barely used".
DENIAL_CAP = 400


def _rule_key(reason):
    """Use the head of the denial wording as the rule id. Gate messages are fixed strings, so they cluster well."""
    r = " ".join(str(reason or "").split())
    return r[:56] or "(no reason)"


def record_denial(target, reason, act="", klass="", rule=""):
    D = STATE.setdefault("denials", [])
    D.append({"t": time.strftime("%m-%d %H:%M"), "rule": (rule or _rule_key(reason))[:64],
              "target": str(target or "")[:100], "act": str(act or "")[:12],
              "klass": str(klass or "")[:24], "reason": " ".join(str(reason or "").split())[:200]})
    if len(D) > DENIAL_CAP:
        del D[:len(D) - DENIAL_CAP]
    return len(D)


def denial_report(limit=25):
    """Denials per rule — the only primary source for "what does this gate actually catch"."""
    D = STATE.get("denials") or []
    if not D:
        return "no denial records (nothing has been blocked yet, or this is before the wiring)"
    agg = {}
    for d in D:
        k = d.get("rule") or "(no reason)"
        a = agg.setdefault(k, {"n": 0, "acts": set(), "klasses": set(), "targets": set()})
        a["n"] += 1
        a["acts"].add(d.get("act") or "?")
        if d.get("klass"):
            a["klasses"].add(d["klass"])
        a["targets"].add(str(d.get("target"))[:40])
    out = ["%d denials · %d rules (by target)" % (len(D), len(agg))]
    for k, a in sorted(agg.items(), key=lambda x: -x[1]["n"])[:limit]:
        out.append("  %3d× [%s] %d targets %s  %s"
                   % (a["n"], "/".join(sorted(a["acts"])), len(a["targets"]),
                      ("klass=" + ",".join(sorted(a["klasses"]))) if a["klasses"] else "", k))
    return "\n".join(out)


def control_overlap(text, kind="positive"):
    """Do the claim's anchor addresses overlap the control records' anchor addresses? **A-type grounding** — both sides are address sets.

    ★ Why (2026-09-05, C-029): R5 requires a positive control for `klass='delta_zero'`, but
      `has_control()` is **ledger-global**, so once a target had any control at all, every later
      `delta_zero` rejection passed for free. All 15 positives on `ahcache.sys` were controls measuring something
      else (gate-tool validation · sink_gates detection · a registry probe), and 0 measured the channel S46 claimed.
      5 of the 6 `delta_zero` rejections since 08-30 passed that way.

    ★ **It does not block.** Today's conclusion is "do not give the deterministic layer suppression authority" (refs/05),
      so it is not reversed here. It **computes the overlap, attaches it** and hands it to the escalator —
      the escalator takes `delta_zero` as blocking anyway.
    """
    want = set(x.lower() for x in re.findall(r'0x[0-9a-fA-F]{6,16}', str(text or "")))
    pool = STATE.get("controls", {}).get(kind) or []
    if not want:
        return {"verdict": "no_anchor_in_claim", "n_controls": len(pool), "shared": []}
    best, bestov = None, set()
    for c in pool:
        have = set(x.lower() for x in re.findall(r'0x[0-9a-fA-F]{6,16}',
                                                 json.dumps(c, ensure_ascii=False)))
        ov = want & have
        if len(ov) > len(bestov):
            best, bestov = c, ov
    return {"verdict": ("overlaps" if bestov else "no_overlap"),
            "n_controls": len(pool), "shared": sorted(bestov)[:8],
            "control": (str(best.get("what"))[:120] if best else "")}


def has_control(kind="positive"):
    return bool(STATE["controls"].get(kind))


# ── 5) task verification ─────────────────────────────────────
# ── investigation tracks ─────────────────────────────────────
# ★ Why: the 3 confirmations (`S7-D4`/`S9-D4`/`S10-VA1`) are **not three defects but three stages of one defect.**
#   Yet the ledger counted them separately, and nowhere said "how many stages is this investigation at". So every round
#   looked at "461 unanalysed of 479 table rows" and **decided again where to dig** — 6 rounds did not go 6 stages,
#   each did "stage-1-level work" six times over. Humans already do this by hand
#   (`poc/*.criteria.md`, `RESUME.md`). The harness just could not read it.
DEFAULT_STAGES = ["static-confirm", "trigger", "measure", "impact", "boundary/submission"]


def track(name, stage=None, of=None, note="", evidence=None, target=None):
    """Read or advance an investigation track's stage. A stage **can also go back** — lowering it when refuted is the honest thing."""
    T = STATE.setdefault("tracks", {})
    t = T.get(name)
    if t is None:
        t = {"stages": list(of or DEFAULT_STAGES), "stage": 0, "evidence": {},
             "note": "", "t": time.strftime("%m-%d %H:%M")}
        T[name] = t
    # ★ 2026-09-05: a track record had **no `target` at all** (fields in full: stages/stage/
    #   evidence/note/t). So "does this track's target have an anchor-verified confirmation" could not be
    #   computed, and the X in `GOAL(track:X)` was a free string with no referent.
    if target:
        t["target"] = str(target)[:160]
    if of:
        t["stages"] = list(of)
    if stage is not None:
        t["stage"] = max(0, min(int(stage), len(t["stages"])))
    if note:
        t["note"] = note[:400]
    for e in (evidence or []):
        t["evidence"].setdefault(str(t["stage"]), []).append(str(e)[:60])
    t["t"] = time.strftime("%m-%d %H:%M")
    save()
    return t


def track_render(compact=False):
    T = STATE.get("tracks") or {}
    if not T:
        return ""
    L = []
    for n, t in T.items():
        st, names = t.get("stage", 0), t.get("stages") or DEFAULT_STAGES
        bar = " ".join(("[x]" if i < st else ("**[ ]←now**" if i == st else "[ ]")) + nm
                       for i, nm in enumerate(names))
        L.append("- `%s`  %s" % (n, bar))
        if t.get("note") and not compact:
            L.append("    %s" % str(t["note"])[:160])
    return "\n".join(L)



# ── three shapes the ledger could not hold (2026-09-14) ─────────────────────────────────────
# ★ Why they were added. The 09-14 overnight run piled up **five items** in `reports/unrecordable/`, and the conductor
#   asked three times, concretely, for "the fields it needs". One of them was that night's **strongest finding**:
#     "of 13 FltCreateFileEx* call sites / 11 functions, only 1 has an authorization guard in its own body"
#   The ledger has only two row shapes — "one defect claim about one target" and "one graded observation".
#   So ① a **measured property** that is not a defect claim ② an **OS path fact** not bound to the target image
#   ③ a **population** carrying members and queries together — had nowhere to go.
#   Yet this repository's discipline says *"real defects are not absences but **under-applications**, and those
#   show up only as populations"*. The tool could not express the methodology's core output.
#
# ★ None of the three fields **is a verdict.** They cannot hold a confirmation/rejection — promotion still goes through
#   `verdict()` and takes the gates attached there (basis · controls · debt cap) as they are. These fields keep **the
#   material of verdicts from being lost**; they are not a back door around the gates.

POP_MEMBER_STATES = ("unanalysed", "safe", "suspect", "promoted", "void")


def population(name, query_a=None, set_a=None, query_b=None, set_b=None,
               differentiator=None, note="", member_state=None, target=None,
               invariant=None):
    """**Population record.** Set A, set B, and **the harness computes their intersection.**

    ★ Letting the caller declare the intersection would make it a self-report. Here A and B come in and the code does the counting.
    ★ The default member state is `unanalysed`, and the rendering **always reports the unanalysed count** —
      a partial census read as a complete one is the most expensive lie in this methodology.
    ★ This record is **not a verdict.** Changing a member to `promoted` means something only after a
      `verdict()` has actually been filed, and that gate stays in place.

    member_state: {"0x140057D00": "safe", ...} — a partial update. Values outside the vocabulary are rejected.
    """
    P = STATE.setdefault("populations", {})
    r = P.get(name)
    if r is None:
        r = {"name": name, "query_a": "", "set_a": [], "query_b": "", "set_b": [],
             "differentiator": "", "note": "", "members": {}, "target": "",
             "invariant": "", "t": time.strftime("%m-%d %H:%M")}
        P[name] = r
    if target:
        r["target"] = str(target)[:160]
    if invariant:
        # ★ 2026-09-24 — the patch-anchored census marker. When this field is present the population is
        #   "the population that must enforce the invariant I the vendor restored", and a completion
        #   claim (verdict completes=) must pass the `population_closure_status()` gate (Move 2).
        r["invariant"] = str(invariant)[:400]
    if query_a:
        r["query_a"] = str(query_a)[:300]
    if query_b:
        r["query_b"] = str(query_b)[:300]
    if differentiator:
        r["differentiator"] = str(differentiator)[:400]
    if note:
        r["note"] = str(note)[:400]
    if set_a is not None:
        r["set_a"] = sorted({str(x).strip() for x in set_a if str(x).strip()})
    if set_b is not None:
        r["set_b"] = sorted({str(x).strip() for x in set_b if str(x).strip()})
    # ★ The intersection and the difference are **counted by the code.**
    A, B = set(r["set_a"]), set(r["set_b"])
    r["inter"] = sorted(A & B)
    r["only_a"] = sorted(A - B)
    for m in r["only_a"]:
        r["members"].setdefault(m, "unanalysed")
    bad = []
    for k, v in (member_state or {}).items():
        v = str(v)
        if v not in POP_MEMBER_STATES:
            bad.append("%s=%s" % (k, v)); continue
        r["members"][str(k).strip()] = v
    r["t"] = time.strftime("%m-%d %H:%M")
    save()
    if bad:
        r = dict(r); r["_rejected"] = bad
    return r


def population_render(name=None, compact=False):
    P = STATE.get("populations") or {}
    if not P:
        return ""
    L = []
    for n, r in P.items():
        if name and n != name:
            continue
        todo = sum(1 for v in r["members"].values() if v == "unanalysed")
        L.append("- population `%s`  A=%d B=%d  **A∩B=%d**  A only=%d  (**unanalysed %d**)"
                 % (n, len(r["set_a"]), len(r["set_b"]), len(r["inter"]),
                    len(r["only_a"]), todo))
        if r.get("differentiator") and not compact:
            L.append("    discriminator: %s" % r["differentiator"][:200])
        if todo and not compact:
            L.append("    unanalysed members: %s"
                     % ", ".join([m for m, v in r["members"].items() if v == "unanalysed"][:10]))
        if todo:
            L.append("    ★ **%d are unanalysed, so this census is not closed yet.**" % todo)
        if r.get("invariant"):
            L.append("    ⚑ patch-anchored (RI: %s) — a completion claim must pass the gate"
                     % r["invariant"][:120])
    return "\n".join(L)


def population_closure_status(name):
    """**May a patch-anchored census be closed as 'fully fixed'?** (the Move 2 gate).

    Returns (ok, reason).
    · not patch-anchored → (True, "") — not this gate's business.
    · unanalysed members remain → (False, ...): not even the known members have all been looked at.
    · closure_interrog has not **SUSTAINED** this census name → (False, ...):
      the real cause of last night's mrxsmb failure was not unanalysed members but **the set_b enumeration
      itself missing members**, and the only tool that catches that is the re-sweep interrogator. So completion
      requires an interrogator SUSTAINED — if the interrogator BROKE it (= incomplete enumeration) or never ran, it cannot close.
    · otherwise → (True, "").
    """
    P = STATE.get("populations") or {}
    r = P.get(name)
    if not r:
        return (False, "no such population: %s" % name)
    if not r.get("invariant"):
        return (True, "")  # not patch-anchored — outside this gate's remit
    todo = [m for m, v in r.get("members", {}).items() if v == "unanalysed"]
    if todo:
        return (False, "%d unanalysed members remain: %s" % (len(todo), ", ".join(todo[:12])))
    ci = (STATE.get("closure_interrogs") or {}).get("by_name") or {}
    res = ci.get(name)
    if res != "SUSTAINED":
        return (False, "closure_interrog state=%s — a patch-anchored census closes as complete only when "
                       "the interrogator has SUSTAINED it (an incomplete set enumeration is not caught by the unanalysed count). "
                       "Run the interrogator with the closing statement (name='%s'), and if it breaks, put the missed members into set_b."
                       % (res or "not run", name))
    return (True, "")


def posture(subject, prop, value, derivation, body_read=False, anchors=None,
            note="", target=None):
    """**A measured property.** Not a defect claim — which is why the `verdict()` vocabulary could not hold it.

    ★ The 09-14 incident: the access masks of two IOCTL arms were **fully measured**, but with no slot for
      them they were pushed into `blocked` ("could not decide"). A true measurement recorded as a failure falsifies the denominator.
    ★ `body_read=False` is **preserved** — "the posture was measured but the body was not read" is the content
      of this record, and erasing it would inflate the grounds later when this row is promoted to a reachability claim.
    """
    R = STATE.setdefault("postures", [])
    rec = {"target": str(target or STATE.get("target") or "?")[:160],
           "subject": str(subject)[:200], "prop": str(prop)[:120],
           "value": str(value)[:200], "derivation": str(derivation)[:300],
           "body_read": bool(body_read), "anchors": sorted(set(_vas(
               "%s %s %s" % (subject, value, " ".join(anchors or [])))))[:12],
           "note": str(note)[:300], "t": time.strftime("%m-%d %H:%M")}
    R.append(rec)
    save()
    return rec


_OSFACT_PATH = [None]


def _osfact_file():
    if _OSFACT_PATH[0]:
        return _OSFACT_PATH[0]
    base = os.path.dirname(_PATH[0]) if _PATH[0] else "state"
    _OSFACT_PATH[0] = os.path.join(base or "state", "_osfacts.json")
    return _OSFACT_PATH[0]


def os_fact(routine=None, arm=None, validated=None, omitted=None, anchors=None,
            applies_to=None, image="", build="", note=""):
    """**An OS path fact not bound to the target image.** Call with no arguments to just read.

    ★ The 09-14 incident: the BUFFERED/DIRECT arm asymmetry of `nt!NtSetEaFile` was measured, but every row
      in the ledger is bound to the single `target` image, so it had nowhere to go. Filed under cldflt it is off-target;
      filed under ntoskrnl nobody sees it while working on cldflt => **it gets re-derived on every target.**
      (That was measured: the same night, a fltmgr fact was re-derived twice across the bfs and cldflt rounds.)
    => so it lives in a **shared file.** Whichever target you attach, you see the same thing.
    """
    f = _osfact_file()
    try:
        with open(f, encoding="utf-8") as fh:
            D = json.load(fh)
    except (OSError, ValueError):
        D = {"facts": []}
    if routine:
        # ★ The same routine is **replaced.** Measured 09-14: the overnight run wrote "two arms" and
        #   the watcher re-derived "three"; with append alone **the stale version is read alongside it** —
        #   a shared fact asserting two values at once defeats the point of forbidding re-derivation.
        D["facts"] = [x for x in D["facts"] if x.get("routine") != str(routine)[:200]]
        D["facts"].append({
            "routine": str(routine)[:200], "arm": str(arm or "")[:200],
            "validated": str(validated or "")[:300], "omitted": str(omitted or "")[:300],
            "anchors": sorted(set(_vas("%s %s %s %s" % (routine, arm, validated,
                                                        " ".join(anchors or [])))))[:12],
            "applies_to": str(applies_to or "")[:300],
            "image": str(image)[:80], "build": str(build)[:80],
            "note": str(note)[:300], "t": time.strftime("%m-%d %H:%M")})
        try:
            tmp = f + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(D, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, f)
        except OSError:
            pass
    return D["facts"]


def osfact_render(n=6, compact=False):
    try:
        facts = os_fact()
    except Exception:
        return ""
    if not facts:
        return ""
    L = ["**OS path facts (target-independent · shared)** — do not re-derive:"]
    for r in facts[-int(n):]:
        _ib = (" [%s %s]" % (r.get("image"), r.get("build"))).replace(" ]", "]") \
            if r.get("image") else ""
        L.append("- `%s` %s%s" % (r.get("routine"), r.get("arm") or "", _ib))
        if not compact:
            if r.get("validated"):
                L.append("    validated: %s" % str(r["validated"])[:180])
            if r.get("omitted"):
                L.append("    **omitted: %s**" % str(r["omitted"])[:180])
            if r.get("applies_to"):
                L.append("    applies to: %s" % str(r["applies_to"])[:180])
    return "\n".join(L)

def seed_goal(text, kind="judge", by="operator"):
    """**A goal the operator sets.** The agent cannot overwrite it.

    ★ The 2026-09-02 incident: when the agent was allowed to declare the goal, it registered a `kind='measure'` goal and then,
      in the same round, **overwrote** it with `kind='judge'` and satisfied the finish condition with a single verdict.
      Measurements: zero — when that was exactly the job. It was setting its own exam questions.
    => the operator sets the goal. **Autonomous hunting after the goal is met is not blocked** — the gate only fires while it is unmet.
    """
    STATE["goal"] = {"text": (text or "")[:400], "kind": kind, "by": by,
                     "at": {"verdicts": len(STATE.get("verdicts") or []),
                            "measures": len(STATE.get("measures") or []),
                            "tracks": {n: t.get("stage", 0)
                                       for n, t in (STATE.get("tracks") or {}).items()}},
                     "t": time.strftime("%m-%d %H:%M")}
    # ★ 2026-09-05 — **an unenforceable goal is not let through silently.**
    #   The axis check of a `judge`/`both` goal works only when a VA can be pulled out of the goal text (_goal_unmet).
    #   Measured: a goal text I wrote held only `+0x56`/`+0x57` (field offsets) and **no complete VA**,
    #   so the check became a no-op and the round passed with 13 verdicts without touching that axis once.
    #   Worse than a gate not running is **not knowing it is not running.** It speaks up at install time.
    STATE["goal"]["enforceable"] = bool(
        kind.startswith("track:") or re.search(r'0x1[0-9a-fA-F]{6,15}', text or ""))
    # ★ 2026-09-05 — **does the goal prescribe a conclusion?** (C-030 cause 2)
    #   Measured: a goal I wrote said "there is **only one thing** blocking it … otherwise close it as `delta_zero`",
    #   and the analyst carried it out to the letter ("I could not name it. Closed delta_zero.").
    #   That **directly contradicts** the promoter's mandate ("a zero delta is not accepted as a destination"),
    #   but the promoter was off that day, so nothing was there to arbitrate. At the same spot, an **open question**
    #   a human asked ("is it really zero?") forced re-derivation and produced new candidates.
    #
    #   ★ It does not refuse — the goal belongs to the operator, who must be able to write one knowingly. But
    #     **the goal is the one input on this board that no adversary checks** (a gate's refusal is
    #     logged, while a goal silently cuts the search space), so it makes a noise at install time.
    _t = text or ""
    _bad = []
    for _k in _REJECT_KLASS:
        if _k in _t:
            _bad.append("the goal names the terminal klass `%s` — that hands the analyst an exit" % _k)
            break
    if re.search(r'only one blocker|the only thing blocking', _t, re.I):
        _bad.append("asserts a single blocker ('only one') — it stops the other channels being looked at. "
                    "S46 died exactly this way")
    if re.search(r'or close|otherwise close', _t, re.I):
        _bad.append("the 'if you can't, close it as …' shape — it licenses finishing. Write only questions")
    STATE["goal"]["prescriptive"] = _bad
    save()
    if _bad:
        return dict(STATE["goal"], _warn=(
            "⚠ This goal **prescribes a conclusion.** The analyst leaves through that exit (measured 2026-09-05: S46).\n"
            + "\n".join("  · " + b for b in _bad)
            + "\n  To fix it: write **only questions** in a goal. An open question forces re-derivation, "
              "a closed prescription licenses finishing."))
    if not STATE["goal"]["enforceable"]:
        return dict(STATE["goal"], _warn=(
            "⚠ This goal **is not enforced.** The axis check for kind='%s' works only when the goal text holds a **complete VA**"
            " (0x1........), and it holds none. As it stands it only checks 'did the verdict count go up at all' — "
            "a verdict on an entirely different axis closes it too (measured 2026-09-05).\n"
            "  To fix it: put one anchor of that axis in the goal text, or use kind='track:<name>'." % kind))
    return STATE["goal"]


def set_goal(text, kind="judge"):
    """This round's **one-line goal.** The finish gate looks at it.

    ★ The 2026-09-02 incident: a round capped at 120 minutes **finished normally at 19 minutes.** It was neither a limit nor an error —
      the processed rate was already 100% (nearly all 467 table rows were 'blocked with a reason'), so the finish gate let it through.
      The task the seed gave (measuring the RW view) **was checked by no gate**, so it was optional for the
      agent, and tidying the table was the shortest path to finishing. The verdict rate was 1%.
      => the gate has to know the round's goal.
    kind: judge (at least 1 verdict) · measure (at least 1 measurement) · both
    """
    cur = STATE.get("goal") or {}
    if cur.get("by") == "operator":
        _u = _goal_unmet()
        return ("This session's goal was SET BY THE OPERATOR and cannot be changed.\n  goal[%s]: "
                "%s\n%s\nPursuing another axis AFTER you have met the goal is not blocked - it is "
                "encouraged. But you cannot REPLACE the goal. Mark anything you stumble into with "
                "`surface(action='incidental', found_while=...)`."
                % (cur.get("kind"), str(cur.get("text"))[:200],
                   ("  now: " + _u.splitlines()[0]) if _u
                   else "  now: MET — you are free from here"))
    if not (text or "").strip():
        return "`goal` requires text=. An empty goal makes the finish gate meaningless."
    # ★ The night of 2026-09-04: the agent **overwrote the conductor's goal with "a summary of what it did."**
    #   (`SESSION GOAL, restated to what was actually achieved…`)
    #   The finish gate held — `at` was reset to the current counts, so the delta requirement stayed alive.
    #   But **the conductor's instruction vanishes from the record.** The next round's digest reads a completion
    #   report where the instruction should be. The policy is not changed (a conductor goal is replaceable by design) —
    #   instead **the overwritten goal is preserved**, so what changed into what can be audited.
    _old = STATE.get("goal")
    if _old and (_old.get("text") or "") != (text or ""):
        STATE.setdefault("goal_history", []).append(
            {"replaced_at": time.strftime("%m-%d %H:%M"), "by_new": "agent",
             "was_by": _old.get("by"), "was_kind": _old.get("kind"),
             "was_text": str(_old.get("text"))[:400], "now_text": (text or "")[:400]})
        STATE["goal_history"] = STATE["goal_history"][-10:]
    STATE["goal"] = {"text": (text or "")[:400], "kind": kind, "by": "agent",
                     "at": {"verdicts": len(STATE.get("verdicts") or []),
                            "measures": len(STATE.get("measures") or [])},
                     "t": time.strftime("%m-%d %H:%M")}
    save()
    return ("Session goal registered (kind=%s): %s\nThe finish gate checks this - tidying the "
            "table alone will not end the session." % (kind, text[:200]))


def _goal_unmet():
    g = STATE.get("goal")
    if not g:
        return None
    at = g.get("at") or {}
    dv = len(STATE.get("verdicts") or []) - (at.get("verdicts") or 0)
    dm = len(STATE.get("measures") or []) - (at.get("measures") or 0)
    kind = g.get("kind") or "judge"
    need = []
    if kind.startswith("track:"):
        # ★ When the goal is "move track X up one stage". It looks at **progress**, not the verdict count.
        nm = kind.split(":", 1)[1].strip()
        tr = (STATE.get("tracks") or {}).get(nm) or {}
        cur = tr.get("stage", 0)
        was = (at.get("tracks") or {}).get(nm, 0)
        if cur <= was:
            names = tr.get("stages") or DEFAULT_STAGES
            need.append("track `%s` stage unchanged (%d/%d — next is %s)"
                        % (nm, was, len(names), names[was] if was < len(names) else "done"))
    if kind in ("judge", "both") and dv <= 0:
        need.append("zero verdicts")
    # ★ 2026-09-05 — **a `judge` goal does not look at the axis.** A `track:` goal requires that track's
    #   stage to move, but `judge` only looks at `dv > 0` (did the verdict count go up at all). So a judge goal
    #   naming a specific axis can be satisfied by **10 verdicts on an entirely different axis.**
    #   Measured 2026-09-05: the ahcache (kind=track:) round had the gate block it 4 times until it answered the goal
    #   (`gate_denials: 4`), while the msquic (kind=judge) round the same night passed with 10 verdicts on other
    #   axes without touching the CidLen cap axis **even once** (`gate_denials: 0`).
    #   => when the goal text **names an address**, check whether that address is cited in this round's verdicts.
    #     The grounding is type A (an anchor is the only key that survives rephrasing — this repository's existing principle).
    #     A goal text with no address requires nothing (no forced gate is invented).
    if kind in ("judge", "both", "measure") and dv > 0:
        _gvas = set(re.findall(r'0x1[0-9a-fA-F]{6,15}', str(g.get("text") or "")))
        if _gvas:
            _new = (STATE.get("verdicts") or [])[(at.get("verdicts") or 0):]
            _blob = json.dumps(_new, ensure_ascii=False).lower()
            if not any(v.lower() in _blob for v in _gvas):
                need.append(
                    "the goal names %d address(es) and NONE of them appears in this session's "
                    "%d verdict(s): %s" % (len(_gvas), dv, ", ".join(sorted(_gvas)[:6]))
                    + "\n  Filing verdicts on a DIFFERENT axis does not close this goal. If the "
                      "goal's axis is wrong or already settled, say so with "
                      "verdict(action='gate_blocked', gate='goal', why=...) or close it with an "
                      "explicit reject/exhaust that CITES one of those addresses - either is "
                      "accepted. Silently working elsewhere is not.")
    if kind in ("measure", "both") and dm <= 0:
        need.append("zero measurements")
    if not need:
        return None
    return ("This session's goal is not closed: %s\n  goal: %s\n  this session's delta - verdicts "
            "%+d, measurements %+d (%s)\nTidying the table and closing the goal are different "
            "things. A high processed rate may be WHAT EARLIER SESSIONS LEFT BEHIND, not this "
            "session's work." % ("; ".join(need), str(g.get("text"))[:200],
                                 dv, dm, ", ".join(need)))


def session_products():
    """★ **What this round produced.** This is the definition of the finish condition.

    A product = **a verdict an adversary conceded.** There are only two shapes, and they are equal:
      · a confirmation the refuter **could not kill**            → a defect candidate
      · a rejection the interrogator **could not break**         → a verified negative

    Why this is the finish condition (redesigned 2026-09-05):
      All eight requirements of the old `can_finish` were tidying (coverage, processed rate, reach, race, open questions).
      That is, it asked "did you tidy the table", not "what did you produce". So confirming became
      the expensive option and rejecting the cheap duty — measured over 9 hours: reject 170 : distinct confirm 1.
      Tying finishing to **products** makes confirmation the normal finishing path, and rejection becomes an
      intermediate state rather than a destination. On a clean target, **a rejection the interrogator conceded** is the normal finish.

    ★ Exhaustion (exhaust) does not count here. What could not be decided is not finished —
      in that case the round gets cut off by its budget limit and is recorded as unfinished. There is no reason
      for the gate to offer **an elegant cheap exit** (that was the old 'finish early after tidying the table').

    Returns: (list of products, number of verdicts this round)
    """
    V = STATE.get("verdicts") or []
    base = int(_RUN.get("verdicts0") or 0)
    mine = V[base:]
    out = []
    for v in mine:
        st = v.get("status")
        if st == "confirmed" and not (v.get("refute") or {}).get("refuted", False):
            out.append(("confirmed", v.get("id"), "passed the refuter"))
        elif st == "rejected" and v.get("interrogated") is True:
            _ig = v.get("interrogation") or {}
            if not _ig.get("broke"):
                out.append(("verified-negative", v.get("id"), "the interrogator could not break it"))
    return out, len(mine)


def unsettled_axes():
    """The axes this round **opened and did not close** that have no open question at all.

    ★ Why (2026-09-05, measured by ablation):
      Two arms under the same conditions diverged. `armC` could not close the goal axis but left **3 open questions**
      (the whole chain, `SdbpResolveMatchingFile → AslPathToNetworkPathNt → …` and so on, addresses included),
      while `armA` left the same axis as `impact_unproven` and finished with **0 notes · 0 questions.**
      So armA did not "hand it to the next session" — **it never made a handle to hand over.**

    ★ This is **not** a prescription to "dig the goal axis." Which axis you dig does not matter —
      it only requires **writing down what you opened, as still open.** Forcing the goal axis is exactly the
      prescription `reports/corrections.md` C-030/C-032 recorded as a defect, so it is not used.

    ★ Grounding: the verdict's anchor addresses ∩ the open questions' anchor addresses (type A). But **the requirement itself is procedural**
      — writing a question does not prove the axis is actually open (memory `grounding-decides-gate`).

    Returns: [(verdict id, a sample of that axis's anchors)] — empty means pass.
    """
    V = STATE.get("verdicts") or []
    base = int(_RUN.get("verdicts0") or 0)
    try:
        prod = {p[1] for p in (session_products()[0] or [])}
    except Exception:
        prod = set()
    # ★ Two things count as a handle (grounds from measurement):
    #   (a) an open question — armC's RQ120~122 were exactly that, and **the harness generated them automatically**
    #       ("confirmation killed by the refuter …" + `method`). So they come free when a confirmation is tried and dies.
    #   (b) a BLOCKED surface row with a reason — as C-034 showed, the next step sits in that reason field.
    #   What the analyst can make directly is (b) (`verdict(action='blocked', reason=…)`), and
    #   (a) follows from pushing a confirmation and losing. Both are "what the next round picks up", so they count equally.
    _a0 = _RUN.get("asks0") or set()
    _s0 = _RUN.get("surface0") or set()
    ask_va = set()
    for a in STATE.get("asks") or []:
        if a.get("status") == "open" and str(a.get("id")) not in _a0:
            ask_va |= set(x.lower() for x in re.findall(
                r'0x[0-9a-fA-F]{6,16}', json.dumps(a, ensure_ascii=False)))
    for k, sv in (STATE.get("surface") or {}).items():
        if k in _s0:
            continue
        if str(sv.get("why", "")).startswith("BLOCKED"):
            ask_va |= set(x.lower() for x in re.findall(
                r'0x[0-9a-fA-F]{6,16}', k + " " + str(sv.get("why", "")) + " " + str(sv.get("reach_why", ""))))
    out = []
    for v in V[base:]:
        if v.get("id") in prod:
            continue                      # a product = an adversary conceded = closed
        blob = " ".join(str(v.get(k) or "") for k in ("evidence", "target", "claim"))
        va = set(x.lower() for x in re.findall(r'0x[0-9a-fA-F]{6,16}', blob))
        if not va:
            continue                      # with no anchor the axis cannot be pinned down — another gate's job
        if not (va & ask_va):
            out.append((v.get("id"), sorted(va)[:6]))
    return out


def can_finish():
    """May it finish? If not, a list of reasons. The gate that prevents 'quiet success'."""
    bad = []
    # ★ 2026-09-05 — the finish condition moved **from tidying to products.** The full grounds are in session_products().
    if getattr(config, "FINISH_ON_PRODUCT", True):
        _prod, _n = session_products()
        if not _prod:
            _conf = sum(1 for v in (STATE.get("verdicts") or [])[int(_RUN.get("verdicts0") or 0):]
                        if v.get("status") == "confirmed")
            _rej = sum(1 for v in (STATE.get("verdicts") or [])[int(_RUN.get("verdicts0") or 0):]
                       if v.get("status") == "rejected")
            bad.append(
                "NOTHING SURVIVED AN ADVERSARY THIS SESSION. The session ends on a PRODUCT, "
                "not on a tidy table.\n"
                "  A product is one of exactly two things, and they count equally:\n"
                "    · a CONFIRMATION the refuter could not kill\n"
                "    · a REJECTION the interrogator could not break  (a verified negative)\n"
                "  This session: %d verdicts (%d confirm / %d reject), 0 of them adversary-tested "
                "and surviving.\n"
                "  Filing more rejections does not end the session. Take ONE thing all the way: "
                "either confirm it and let the refuter try to kill it, or reject it and let the "
                "interrogator try to break it. Bring the evidence that beats them.\n"
                "  METHOD EXHAUSTED IS NOT AN ENDING — an unsettled row is not a product." 
                % (_n, _conf, _rej))
    # ★ 2026-09-05 — **write down what you opened, as still open.** If an axis not closed by a product has
    #   no open question at all, that axis is silently abandoned (measured: armA — left the goal axis as impact_unproven
    #   and finished with 0 notes · 0 questions). It does not direct which axis to dig — it only makes the next
    #   round get a handle to pick up. → the unsettled_axes() docstring
    if getattr(config, "FINISH_ON_PRODUCT", True):
        _un = unsettled_axes()
        if _un:
            bad.append(
                "YOU OPENED AXES AND LEFT NO HANDLE ON THEM. %d verdict(s) this session were not "
                "settled by an adversary, and NO OPEN QUESTION cites their anchors — so the next "
                "session inherits a dead end, not a next step.\n"
                % len(_un)
                + "\n".join("  · %s  (anchors %s)" % (i, ", ".join(a)) for i, a in _un[:6])
                + "\n  Two ways to leave a handle, both cheap:\n"
                  "    · `verdict(action='blocked', target='<the row>', reason='<why you could "
                  "not settle it>', next='<the ONE next step, >=40 chars, naming a VA or symbol>')` "
                  "— the row stays UNAUDITED, not a fake negative, and `next=` is the field the NEXT "
                  "session's work list reads. Prose in reason= is NOT machine-selectable: measured, "
                  "56%% of blocked rows match any prose predicate for 'has a next step'.\n"
                  "    · push it to `confirm`: if the refuter kills it, the harness files the open "
                  "question FOR you, with the method that would settle it.\n"
                  "  This is NOT a request to work the axis, and NOT a request to work any "
                  "particular axis — only to write down what is left.")
    _gu = _goal_unmet()
    if _gu:
        bad.append(_gu)
    # ★ 2026-09-05 — the housekeeping items below are issued **as advice, not as blocks.**
    #   Grounds: all eight old requirements were tidying, asking only "did you tidy the table", and so confirming became optional.
    #   The values are still computed and reported — their consumer is not the analyst but **the conductor** (it sets the next goal).
    #   With FINISH_ON_PRODUCT off, the old behaviour (block on all of them) stays as it was.
    _adv = [] if getattr(config, "FINISH_ON_PRODUCT", True) else bad
    pct, done, tot = coverage()
    spct, sdone, _ = settled()
    if not tot:
        bad.append("The enumeration table is EMPTY — register the ingress first with "
                   "surface(action='add'). A conclusion drawn without the table has false "
                   "coverage.")
    elif spct < config.MIN_COVERAGE:
        _adv.append(f"Processed rate {spct*100:.0f}% < floor {config.MIN_COVERAGE*100:.0f}% "
                   f"(adjudicated {done} + blocked-with-reason {sdone-done} / {tot} total). "
                   f"Adjudicate the remaining {tot-sdone}, or use "
                   f"verdict(action='blocked', reason=...) to state WHY YOU CANNOT. "
                   f"Unaudited rows with no reason make coverage a lie.")
    elif config.MIN_ADJUDICATED and pct < config.MIN_ADJUDICATED:
        _adv.append(f"Adjudication rate {pct*100:.0f}% < floor "
                   f"{config.MIN_ADJUDICATED*100:.0f}%. "
                   f"[verified negatives {verified_negatives()[1]}/{verified_negatives()[2]}] "
                   f"Those {sdone-done} blocked rows are HONEST UNAUDITED WORK, NOT AN "
                   f"ACHIEVEMENT — adjudicate more of the ones your tools can actually settle.")
    _cc = code_coverage()
    if _cc[0] is not None and _cc[0] < 0.25:
        _adv.append("ACTUAL CODE COVERAGE is %d/%d = %.0f%%. `coverage()` is a ratio over the "
                   "surfaces YOU wrote down, so it measures 'did you tidy your list', not 'how "
                   "much did you audit'. Enumerate entry points and never look past them and "
                   "you get a high adjudication rate on rock-bottom coverage."
                   % (_cc[1], _cc[2], _cc[0] * 100))
    _den, _ko, _unk, _c = reach_breakdown()
    if _unk:
        _adv.append("%d surfaces still have reach=`unknown` — THE DENOMINATOR IS FALSE. "
                   "Settle each as user-direct / user-triggerable-async / kernel-only. "
                   "(kernel-only drops out of the denominator but STAYS IN THE TABLE — it is a "
                   "candidate race partner.)" % _unk)
    if not races():
        _adv.append("There are ZERO race entries. If your surface unit is a single request, "
                   "races never even get registered — `coverage()` at 100%% still says nothing "
                   "about concurrency. Enumerate asynchronous entry points with `async_entry` "
                   "(cancel, completion, work item, DPC, timer, PnP), then register the pairs "
                   "that touch shared state via `surface(action='race', ...)` — or state "
                   "explicitly that RACES WERE NOT INVESTIGATED.")
    _open = asks("open")
    if _open:
        _adv.append("%d open questions remain — THESE ARE NOT NEGATIVES, THEY ARE UNAUDITED. "
                   "Run each one's `method` and answer it, or if there is genuinely no method "
                   "left, declare METHOD EXHAUSTED with "
                   "`verdict(action='exhaust', target=..., reason=...)` (do NOT file it as a "
                   "rejection). Targets: %s"
                   % (len(_open), ", ".join(q["target"] for q in _open[:6])))
    if not STATE["verdicts"] and not STATE["candidates"]:
        bad.append("Zero verdicts. Even with no confirmations, YOU MUST LEAVE REJECTIONS AND "
                   "BLOCKED ROWS for coverage to mean anything.")
    weak = [v["id"] for v in STATE["verdicts"]
            if v["status"] in ("confirmed", "boundary-held") and not v.get("anchors")]
    if weak:
        bad.append(f"Confirmations whose anchors were never machine-verified: "
                   f"{', '.join(weak)}. A confirmation without citations is INFERRED.")
    # ★ 2026-09-05 — the advice items **do not block the analyst; they go to the conductor.**
    #   Driving the analyst into tidying labour was the bottleneck of the old structure. The values are still computed,
    #   but the consumer changes: coverage, reach, race and open questions are **material for setting the next goal.**
    if getattr(config, "FINISH_ON_PRODUCT", True):
        STATE["housekeeping"] = _adv
        save()
    return bad


# ── 6) the status block ──────────────────────────────────────────────
# ── status_block delta ────────────────────────────────────────
# ★ Why: this block is injected as `additionalContext` every 4 tool calls + after every verdict.
#   The API is stateless, so whatever goes in once **is carried again in the request of every later turn.**
#   Measured (09-04 wcifs, 165 turns): a 1332-char block × about 45 injections × 82 remaining turns on average
#   ≈ 2.2M tokens of re-reading. About 8% of that round's 28.4M cache_read.
#   Yet most of those 1332 chars (the unanalysed list, the graveyard) **barely change over the whole round.**
#
# ★★ But one thing must never be folded: **"what has already been tried."**
#   Without it the next turn's analyst uses the same method again — the whole reason the ledger
#   counts `attempts` becomes meaningless. Measured: hitting the same question 4–5 times happened
#   6 times in ahcache · 8 times in wcifs, and that loop is why the adjudicator was built.
#   => unchanged big chunks are folded, and **the attempt history is always carried.** Not a net increase but a trade.
_SB = {"digest": None}


def status_reset(why=""):
    """Empty the delta cache — the next block goes out **in full.**

    ★ It must be called right after compaction (PreCompact). If the model has lost the previous block
      and gets only a one-line 'unchanged', that round never sees the state again.
    """
    _SB["digest"] = None
    return why


def _tried_line():
    """★ The part that is never folded — what has already been tried and what has been closed."""
    out = []
    qs = [q for q in (STATE.get("asks") or []) if (q.get("attempts") or [])
          or (q.get("status") or "open").lower() in ("exhausted", "answered")]
    qs.sort(key=lambda q: -len(q.get("attempts") or []))
    if qs:
        mark = {"exhausted": "exhausted", "answered": "★answered"}
        bits = ["[%s]%s×%d%s" % (str(q.get("id"))[:16],
                                 (":" + str(q.get("cfg") or q.get("klass"))[:18])
                                 if (q.get("cfg") or q.get("klass")) else "",
                                 len(q.get("attempts") or []),
                                 "·" + mark[(q.get("status") or "").lower()]
                                 if (q.get("status") or "").lower() in mark else "")
                for q in qs[:6]]
        out.append("  ★ already tried (do not use the same method again): " + " · ".join(bits)
                   + (" …and %d more" % (len(qs) - 6) if len(qs) > 6 else ""))
    adj = STATE.get("adjudications") or []
    if adj:
        out.append("  ⚖ %d rows closed by the adjudicator — do not argue them again (%s)"
                   % (len(adj), ", ".join(str(a.get("target"))[:22] for a in adj[-3:])))
    return out


def status_block(i, total):
    parts = []
    if i and total:
        parts.append(f"[state] tool {i}/{total} · budget left {total - i}")
    pct, done, tot = coverage()
    if tot:
        parts.append(f"  coverage {done}/{tot} ({pct*100:.0f}%)")
        un = unaudited()
        if un:
            _shape = unaudited_shape()
            _n = sum(_shape.values())
            parts.append("  %d rows unanalysed — reachability mix: %s"
                         % (_n, " · ".join("%s %d" % (k, v)
                                           for k, v in _shape.most_common(4))))
            parts.append("  this sample (rotating; it walks all %d rows): " % _n + " / ".join(un))
    else:
        parts.append("WARNING: the enumeration table is empty. Register the ingress first with "
                     "surface(action='add').")

    # Spending more than 40% of the budget with zero verdicts is a deviation in itself.
    # (A real case: clfs, 61 turns · $9.87 · zero verdicts in the ledger — findings left only in note, coverage 0%)
    if i and total and not STATE["verdicts"] and i >= total * 0.4:
        parts.append(
            "  BUDGET: %d/%d of budget spent with ZERO verdicts. note() is not a verdict.\n"
            "     Register what you have read so far as verdicts RIGHT NOW (rejections and "
            "unaudited rows count).\n"
            "     A rejection IS a verdict - record 'the guard is real, the candidate died' "
            "with basis='decompile'." % (i, total))

    conf = [v for v in STATE["verdicts"] if v["status"] == "confirmed"]
    if conf:
        weak = [v["id"] for v in conf if BASIS_RANK.get(v["basis"], 0) < 3]
        parts.append(f"  {len(conf)} confirmed" + (f" (weak grounds: {', '.join(weak)})" if weak else ""))
    # ★ 2026-09-05 — **the dashboard showed only "what has not been done."**
    #   Measured (a 9-hour overnight run): this block, injected every 4 tool calls, showed 2% coverage · 544 unanalysed rows ·
    #   8 rotating sample rows · 6 graveyard entries · 101 failure-history entries, and **not one line of "nearly done."**
    #   Result: of 134 verdicts, `reject` 170 : `confirm` 4 (and even those were retries of the same candidate, so **1 distinct**).
    #   Meanwhile wcifs had three tracks at 4/5, and ahcache had one, **left untouched.**
    #   => tracks with 1–2 rungs left on the ladder are **shown every turn.** Not a quota but **visibility.**
    _near = []
    for _n, _t in (STATE.get("tracks") or {}).items():
        _st = _t.get("stage", 0); _names = _t.get("stages") or DEFAULT_STAGES
        _left = len(_names) - _st
        if 0 < _left <= 2:
            _near.append((_left, _n, _names[_st] if _st < len(_names) else "?"))
    if _near:
        _near.sort()
        parts.append("  ★ %d tracks near the top of the ladder — **climb the next rung**: %s"
                     % (len(_near), " / ".join("`%s` %d rungs left (next: %s)" % (n, l, nx)
                                               for l, n, nx in _near[:4])))
    # ★ Show every turn the tracks whose **closure claim went stale** through a reopen. If the note says
    #   "done, negative" but that axis has been reopened, the next round that starts by trusting that note spins in vain entirely.
    _stale = [(n, t) for n, t in (STATE.get("tracks") or {}).items() if t.get("stale_closure")]
    if _stale:
        parts.append("  ⚠ %d tracks whose closure claim **went stale** — the note says 'done' but the axis was reopened: %s"
                     % (len(_stale),
                        " / ".join("`%s`(reopened %d times: %s)"
                                   % (n, len(t["stale_closure"]),
                                      ", ".join(str(x.get("by"))[:28] for x in t["stale_closure"][:2]))
                                   for n, t in _stale[:3])))
    # ★ 2026-09-05 (C-037) — **make the reservoir visible every turn.** This is where the gap C-034 measured sits:
    #   four rows the harness had stopped at, correctly by the discipline, one question short of a defect sat as `BLOCKED`,
    #   and since BLOCKED rightly drops out of coverage and also sinks in the worklist, **nobody went back to them.**
    #   No ranking (whether prose 'has a next step' cannot be decided — that was measured). **It states only the size.**
    _bl = [r for r in (STATE.get("surface") or {}).values()
           if r.get("blocked") and not r.get("exhausted")
           and not _is_alias_row(r.get("why"))]
    if _bl:
        _wn = sum(1 for r in _bl if isinstance(r.get("next"), dict))
        parts.append("  ★ blocked reservoir: %d rows — **%d of them declare** the next step in the field. "
                     "List them with `verdict(action='unfinished')`. These are rows where the analysis already "
                     "happened and stopped one step short." % (len(_bl), _wn))
    _prop = [c for c in (STATE.get("candidates") or []) if c.get("state") == "proposed"]
    if _prop:
        parts.append("  ★ %d candidates not yet through the refuter: %s"
                     % (len(_prop), ", ".join(str(c.get("id")) for c in _prop[:6])))
    r = STATE["refutes"]
    if r["run"]:
        parts.append(f"  refutations {r['run']} — killed {r['killed']} / survived {r['survived']}"
                     + (f" / run failures {r['failed']}" if r["failed"] else ""))
    if STATE["graveyard"]:
        parts.append("  graveyard (do not reopen): " + " / ".join(
            f"{g['id']}:{g['target']}[{g.get('klass') or '-'}]" for g in STATE["graveyard"][-6:]))
    miss = [k for k in ("positive", "negative", "swap") if not STATE["controls"].get(k)]
    if STATE["controls"] or miss != ["positive", "negative", "swap"]:
        parts.append("  controls missing: " + (", ".join(miss) if miss else "none (all 3 in place)"))

    # ── delta ──────────────────────────────────────────────────
    # The first line (the budget) changes on every call, so it is left out of the fingerprint — otherwise the delta never triggers.
    # ★ The rotating sample is left out for the same reason. Otherwise the body differs on every call and **the delta never triggers**
    #   (that really happened as soon as the unaudited rotation went in). The sample is still carried in the folded block —
    #   the point of that line is to sweep the whole table within a round, so folding it would defeat the point.
    body = [x for x in (parts[1:] if (i and total) else parts)
            if not x.startswith("  this sample")]
    sample = [x for x in parts if x.startswith("  this sample")]
    dig = hashlib.sha1("\n".join(body).encode("utf-8")).hexdigest()
    tried = _tried_line()
    if body and _SB["digest"] == dig:
        # unchanged → fold the big chunks. The attempt history is **not folded.**
        head = parts[0] if (i and total) else ""
        return "\n".join(([head] if head else [])
                         + ["  (table · confirmations · graveyard · controls unchanged)"] + sample + tried)
    _SB["digest"] = dig
    return "\n".join(parts + tried)
