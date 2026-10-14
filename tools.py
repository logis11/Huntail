# tools.py — the analysis tools.
#
# Two design principles:
#  (1) **Anything the model rewrites every time becomes a tool.** The first run
#      transcripts show the model hand-reimplementing PE parsing, VA conversion,
#      capstone and cross-build diffing through run_python. All of it is
#      deterministic. (A classification whose precision matters belongs to a
#      deterministic node, not an LLM.)
#  (2) **Navigation is the bottleneck.** In the COTS-binary agent work, just
#      attaching a toolset lifted Claude Code's F1 by +0.214. You cannot get
#      around a 3,884-function corpus with a single grep over names.
import hashlib
import json, os, re, struct, subprocess, sys, tempfile, time

import config, ledger, nav, evidence, xref, authz
import pe as PEmod

TARGET = {"binary": None, "alt": None, "corpus": None,
          "_pe": None, "_alt": None, "_ix": None,
          # Cross-image. With only the target loaded, a claim stops at the image boundary:
          #   a question like "in which mode does `nt!MmCreateSection` reference the
          #   handle?" cannot be answered by reading 100% of our own driver. This is where
          #   that wall opens.
          "_images": {}, "_imeta": {}}

_BANNER = nav.BANNER


def set_target(binary=None, corpus=None, alt=None):
    TARGET.update({"binary": os.path.abspath(binary) if binary else None,
                   "alt": os.path.abspath(alt) if alt else None,
                   "corpus": os.path.abspath(corpus) if corpus else None,
                   "_pe": None, "_alt": None, "_ix": None})
    if TARGET["binary"]:
        TARGET["_pe"] = PEmod.PE(TARGET["binary"])       # NotPE is caught by the caller
    if TARGET["alt"]:
        TARGET["_alt"] = PEmod.PE(TARGET["alt"])
    if TARGET["corpus"]:
        TARGET["_ix"] = nav.Index(TARGET["corpus"], cache_dir=config.WORK_DIR)
    TARGET["_iix"] = None          # reset the IDA index cache
    TARGET["_images"] = {}         # a target change unloads every auxiliary image too
    TARGET["_imeta"] = {}


def _ix():
    """The corpus index when there is one, otherwise the **IDA index.**
    This used to return None with no corpus, which killed six navigation
    tools outright."""
    if TARGET["_ix"] is not None:
        return TARGET["_ix"]
    return _ida_index()


def _pe():
    return TARGET["_pe"]


MAIN_ALIASES = ("", "main", "target", "self", "none")


def add_image(name, path):
    """Register an auxiliary image. The name becomes the citation tag
    (`nt!0x14098f670 mov ...`).

    Build identity is recorded **alongside it.** An anchor verified against a
    different build of the kernel is a coincidence, not a verification — and
    without telling those apart, cross-image only moves the hallucination one
    hop along.
    """
    nm = str(name).strip().lower()
    if nm in MAIN_ALIASES:
        raise ValueError("%r cannot be used as an auxiliary image name (main is reserved)" % name)
    if not re.fullmatch(r'[a-z_][a-z0-9_]{0,15}', nm):
        raise ValueError("an image name must match [a-z_][a-z0-9_]{0,15}: %r" % name)
    ap = os.path.abspath(os.path.expanduser(path))
    img = PEmod.PE(ap)                       # NotPE is caught by the caller
    guid = age = pdb = ""
    try:
        guid, age, pdb = img.codeview()          # a (guid, age, pdb) tuple
    except Exception:
        pass
    TARGET["_images"][nm] = img
    TARGET["_imeta"][nm] = {
        "name": nm, "path": ap, "size": os.path.getsize(ap),
        "base": "0x%x" % img.base, "timestamp": "0x%x" % img.timestamp,
        "guid": guid or "", "age": age or "", "pdb": os.path.basename(pdb or ""),
        "exports": len(img.exports()),
    }
    return TARGET["_imeta"][nm]


def image_of(name):
    """name -> PE. `main` or empty means the measured target. An unknown name
    gives None."""
    nm = str(name or "").strip().lower()
    if nm in MAIN_ALIASES:
        return _pe()
    return TARGET["_images"].get(nm)


def images_all():
    """{name: PE}, including main. The per-image anchor verification in
    `evidence` takes this."""
    d = {"main": _pe()} if _pe() is not None else {}
    d.update(TARGET["_images"])
    return d


def _img_resolve(img, target):
    """Resolve `0xVA` or **an export name** to a VA in an auxiliary image.
    Returns (va, note)."""
    t = str(target).strip()
    if re.fullmatch(r'0x[0-9a-fA-F]+', t):
        return int(t, 16), ""
    va = img.export_va(t)
    if va:
        return va, "export %s -> 0x%x" % (t, va)
    if t in img.exports():
        return None, ("`%s` is a **forwarder** in this image — its body lives in "
        "another file. Register that file as an image to follow "
        "it." % t)
    near = [k for k in img.exports() if t.lower() in k.lower()][:8]
    return None, ("in an auxiliary image **only an export name or a 0xVA** "
    "resolves (corpus symbols belong to the measured target). "
    "`%s` is not an export.%s"
    % (t, ("  Similar names: " + ", ".join(near)) if near else ""))


def _cap(s, n=None):
    n = n or config.TOOL_OUT_CAP
    s = s if isinstance(s, str) else str(s)
    if len(s) <= n:
        return s
    return s[: n // 2] + f"\n... [{len(s)-n} chars elided] ...\n" + s[-n // 2:]


# ── address resolution: name / 0xVA -> (corpus VA, measured-build VA, note) ──
def resolve(target, from_corpus=False):
    """The corpus build and the measured build may differ, so the two are
    **always** returned separately.

    The rule (this is the reference when in doubt):
    · **A symbol name** only comes from the corpus => the corpus coordinate is
    re-derived into the measured build.
    · **An address** is read as a measured-build coordinate => used as-is,
    because an address `find_bytes` / `disassemble` just handed over must not
    be relocated again.
    To relocate an old-build address, pass from_corpus=1 or
    anchor(relocate=...).
    """
    ix, p, a = _ix(), _pe(), TARGET["_alt"]
    cva = lva = None
    name = None
    if isinstance(target, str) and target.lower().startswith("0x"):
        va = int(target, 16)
        if not from_corpus:
            return (ix.func_at(va) if ix else None), None, va, ""
        cva = va
        name = ix.func_at(cva) if ix else None
    elif ix:
        name = ix.resolve(target)
        if name:
            cva = ix.fn[name][0]
    if cva is None:
        return None, None, None, f"cannot resolve '{target}' as a corpus symbol or an address"
    if a is None or p is None:
        return name, cva, cva, ""
    ext = 0x400
    if ix:
        nxt = [v for v, _ in ix.byva if v > cva]
        ext = min(nxt[0] - cva, 0x800) if nxt else 0x400
    nva, how = PEmod.relocate_function(a, p, cva, ext)
    if nva is None:
        return name, cva, None, (
            f"WARNING: corpus-build VA 0x{cva:x} was not found in the measured build — {how}.\n"
            "This does NOT by itself mean it was patched. A recompile alone changes "
            "every byte (register allocation, stack slots). The next move is to "
            "**search again by an invariant constant**: "
            "find_bytes(hex='<struct offset + immediate>') — e.g. "
            "cmp [r+0x2d4], 0x0FFFFFFF is 'd4020000ffffff0f'. Then disassemble at "
            "the address you find.")
    note = "" if how == "same" else \
    f"anchor moved: corpus 0x{cva:x} -> measured build 0x{nva:x} ({how}). Cite the measured-build address."
    return name, cva, nva, note


# ── binary_info ──────────────────────────────────────────────
def _t_binary_info(_):
    p = _pe()
    if not p:
        return "no binary (corpus-only mode). A verdict cannot be grounded in disassembly."
    guid, age, pdb = p.codeview()
    L = [f"path      : {p.path}", f"size      : {len(p.d)}",
         f"ImageBase : 0x{p.base:X}   TimeStamp: 0x{p.timestamp:X}",
         f"CodeView  : GUID={guid} age={age} pdb={pdb}",
         f"mitigations: {', '.join(p.mitigations()) or 'none'}", "",
         "sections (name / RVA / VSize / RawPtr / RawSize / X):"]
    for s in p.secs:
        L.append(f"  {s['name']:<10} 0x{s['va']:08X} 0x{s['vsize']:08X} "
                 f"0x{s['raw']:08X} 0x{s['rsize']:08X} {'X' if s['chars'] & 0x20000000 else '-'}")
    L += ["", f"FileAlignment=0x{p.fa:X} SectionAlignment=0x{p.sa:X}" +
          ("  → file offset == RVA" if p.fa == p.sa else
           "  -> file offset != RVA. Do not infer a VA from base+fileoff")]
    a = TARGET["_alt"]
    if a:
        g2 = a.codeview()[0]
        L += ["", f"alt build  : {os.path.basename(a.path)}  GUID={g2}",
        ("  => same GUID — corpus anchors can be used as they are." if g2 == guid else
        "  => **different GUID.** The corpus came from the alt build. Every address "
        "is re-derived automatically by resolve/anchor. Always cite the "
        "measured-build address.")]
    elif TARGET["corpus"]:
        L += ["", "WARNING: no alt build. The harness does not know which build the "
        "corpus came from, so it cannot re-derive anchors automatically. "
        "Supply ALT=<a PE of the same build as the corpus>."]
    if _ix():
        L += ["", f"corpus     : {len(_ix().fn)} functions, "
        f"{sum(len(v) for v in _ix().out.values())} call-graph edges"]
    return "\n".join(L)



def _noix(extra=""):
    """A **diagnosable** message for when there is no navigation index.
    ★ This used to be just "no corpus." — the same wording even when the IDA bridge
      was broken, so the cause was invisible (it really was always dead from a missing WSLENV)."""
    why = []
    if not TARGET["corpus"]:
        why.append("no corpus")
    if not TARGET["binary"]:
        why.append("no binary")
    elif not config.USE_IDA:
        why.append("USE_IDA=0")
    elif not os.path.exists(config.IDAT):
        why.append("IDAT missing (%s)" % config.IDAT)
    else:
        why.append("building the IDA index failed — reproduce it directly with `python3 -c \"import tools;tools.set_target(binary=...);print(tools._ida_index())\"`")
    return "no navigation index: " + " / ".join(why) + (("  (%s)" % extra) if extra else "")


# ── navigation ───────────────────────────────────────────────────────────
def _t_find_funcs(a):
    ix = _ix()
    if not ix:
        return _noix()
    hits, tot = ix.search(a["pattern"], int(a.get("limit") or 60))
    body = "\n".join(f"  {n:<58} 0x{va:x}" for n, va in hits)
    return f"'{a['pattern']}' name matches: {tot} (showing {len(hits)})\n{body}"


def _t_func_at(a):
    """The function containing a VA, plus its **bounds**.

    Why the bounds come with it: sweeping with a fixed window (0x1200 or the like) and
    **scraping someone else's function** has already happened twice in this project (the
    early scanner's fixed 0x6000 span, and a recent immediate sweep). The `.pdata`
    RUNTIME_FUNCTION table holds the right answer, so there is no reason to guess.
    => when sweeping this function, stay strictly inside this range."""
    va = int(a["va"], 16) if isinstance(a["va"], str) else int(a["va"])
    p = _pe()
    lo = hi = None
    if p is not None:
        try:
            lo, hi = p.func_bounds(va)
        except Exception:
            lo = hi = None
    ix = _ix()
    n = ix.func_at(va) if ix else None
    if not n and lo is None:
        return _noix() if not ix else f"no function contains 0x{va:x}"
    L = []
    if n:
        fva = ix.fn[n][0]
        L.append(f"0x{va:x} \u2208 {n} @ 0x{fva:x}  (+0x{va-fva:x})")
    if lo is not None and hi is not None:
        L.append(f"bounds (.pdata): [0x{lo:x}, 0x{hi:x})  size 0x{hi-lo:x}")
        L.append("★ Sweep **only inside this range.** A fixed window scrapes someone else's function.")
    else:
        L.append("bounds (.pdata): none — this is **unanalysed**, not 'not a function'")
    return "\n".join(L)


def _t_callers(a):
    ix = _ix()
    if not ix:
        return _noix()
    n, cs = ix.callers(a["target"])
    if not n:
        return f"'{a['target']}' unresolved"
    return (f"{len(cs)} callers of {n}:\n" + "\n".join(f"  {c}" for c in cs) +
            "\n\n★ This graph sees only **direct calls** in the decompiled bodies. Calls through "
            "function pointers, vtables or dispatch tables are invisible — before claiming an "
            "absence, check the indirect paths separately with dispatch_table and corpus_grep.")


def _t_callees(a):
    ix = _ix()
    if not ix:
        return _noix()
    n, cs = ix.callees(a["target"])
    if not n:
        return f"'{a['target']}' unresolved"
    # **An absence from this list is not evidence.** `callers` already carried this
    #   warning and `callees` did not — an asymmetry that was paid for the same night:
    #   one case used *"MEASURED FROM callees(): <handler> does NOT call
    #   ExAcquireRundownProtection"* as the **load-bearing ground** of a UAF lead. A
    #   second case disproved it from the bytes, and the operator resolved the IAT
    #   slot by hand to confirm:
    #     0x14000390e lea rcx,[rip+0x1aa7b]     ; gBfsRundownProtection 0x14001E390
    #     0x140003915 call qword ptr [rip+0x1cd24]  ; IAT 0x140020640 = ExAcquireRundownProtection
    #   So **an indirect call through an import does not enter this graph.** A lead
    #   stood on that absence and died.
    return (f"{len(cs)} callees of {n}:\n" + "\n".join(f"  {c}" for c in cs) +
            "\n\n★ **Do not write 'does not call' because something is missing from this list.** "
            "Indirect calls through imports (`call qword ptr [rip+…]` → IAT), dispatch tables and "
            "function pointers are not caught here. "
            "Measured (2026-09-11 bfs.sys): `ExAcquireRundownProtection` was absent from this list "
            "while `0x140003915` called it through the IAT, and a UAF lead built on that absence was "
            "disproved the next round. To claim an absence, resolve every "
            "`call qword ptr [rip+…]` slot across the whole function with `disassemble`, or check with `import_xref`.")


def _t_callpath(a):
    ix = _ix()
    if not ix:
        return _noix()
    p, how = ix.callpath(a["src"], a["dst"], int(a.get("maxdepth") or 8))
    if not p:
        return (f"{a['src']} → {a['dst']}: no path ({how}).\n"
                "★ Do not settle 'unreachable' on this alone — indirect calls are not in this graph. "
                "Unreachability is the number-one rejection reason, so if the grounds are weak leave it blocked.")
    return (f"{a['src']} → {a['dst']}  ({len(p)-1} hops)\n" +
            "\n".join(f"  {i}. {n}" for i, n in enumerate(p)))


def _t_census(a):
    ix = _ix()
    if not ix:
        return _noix()
    ment = set()
    for k, v in ledger.STATE["surface"].items():
        ment.add(k)
    rows = ix.census(ment)
    L = ["family      total  unlisted  unaudited", "-" * 40]
    for k, tot, un, r in rows[:24]:
        L.append(f"  {k:<8} {tot:>5} {un:>7}   {r*100:>3.0f}%")
    L.append("\n★ 'not in the census table = certainly unaudited'. Being mentioned is not being audited.")
    return "\n".join(L)


# ── code ─────────────────────────────────────────────────────────────────
def _t_decompile(a):
    ix = _ix()
    if ix:
        hit = ix.body(a["target"])
        if hit:
            n, va, body = hit
            _nm, _c, lva, note = resolve(n)
            return (f"[corpus] {n} @ 0x{va:x}" + (f"\n{note}" if note else "") + "\n" +
                    _cap(body) + "\n\n⚠ This is decompiler output. Confirm any code that would change a verdict with disassemble — "
                    "a decompiler both drops checks and invents defects that are not there.")
    r = _ida_call("decompile", a["target"])
    if r and not r.get("error"):
        return _cap(r.get("code") or str(r)) + "\n\n⚠ This is decompiler output."
    return f"decompile failed: {a['target']} is not in the corpus, and IDA cannot do it either. ({r})"


def _t_disassemble(a):
    """Takes a name or an address. Decodes the **measured build**, and says so if the anchor moved.

    `image='nt'` decodes an **auxiliary image** instead (cross-image). Citations must then
    take the form `nt!0xVA mnem ops` — an untagged citation is verified against the measured
    target, where an address from another file either passes (by coincidence) or fails (correctly). The tag is what gets verified.
    """
    t = a["target"]
    cnt = int(a.get("count") or 80)
    imgname = str(a.get("image") or "").strip().lower()
    if imgname not in MAIN_ALIASES:
        img = image_of(imgname)
        if img is None:
            return ("auxiliary image %r is not registered. Check with `images(action='list')` and, "
                    "if needed, register it with `images(action='add', name=..., path=...)`." % imgname)
        va, note = _img_resolve(img, t)
        if va is None:
            return note
        ins = img.disasm(va, cnt)
        if not ins:
            return "decoding 0x%x failed — not mapped in image %s?" % (va, imgname)
        meta = TARGET["_imeta"].get(imgname, {})
        head = ("[%s / image=%s] @ 0x%x  (%d insn)\nbuild: %s ts=%s"
                % (os.path.basename(img.path), imgname, va, len(ins),
                   meta.get("guid", "?")[:16] or "?", meta.get("timestamp", "?")))
        if note:
            head += "\n" + note
        ledger.note_disasm("%s!%s" % (imgname, t))
        body = "\n".join("0x%x  %-20s %s %s" % (v, b.hex(), m, o) for v, b, m, o in ins)
        return _cap(head + "\n" + body +
                    "\n\n★ Tag citations from this image as **`%s!0x…`**. Untagged, they are "
                    "verified against the measured target and fail." % imgname)
    p = _pe()
    name, cva, lva, note = resolve(t, from_corpus=bool(a.get("from_corpus")))
    if p is None:
        return "no binary — the grounds for a verdict (disassembly) cannot be produced. Nothing can be confirmed in corpus mode."
    if lva is None:
        # Re-derivation failed. Decoding a corpus coordinate straight against the
        # measured build produces **garbage**, so it stops here rather than handing
        # garbage over quietly.
        return (note or f"failed to resolve '{t}'") + (
            "\n\n(It does not just decode at this address — the coordinate belongs to another build, so "
            "the instructions that come out are meaningless. Find this build's address with find_bytes first.)")
    ins = p.disasm(lva, cnt)
    if not ins:
        return f"decoding 0x{lva:x} failed (not mapped?)"
    head = f"[{os.path.basename(p.path)}] {name or ''} @ 0x{lva:x}  ({len(ins)} insn)"
    if note:
        head += "\n" + note
    ledger.note_disasm(name or t)
    ledger.note_disasm(f"0x{lva:x}")
    body = "\n".join("0x%x  %-20s %s %s" % (v, b.hex(), m, o) for v, b, m, o in ins)
    return _cap(head + "\n" + body +
                "\n\n★ Cite the addresses above exactly as shown. A verdict's evidence is machine-verified.")


def _t_grep(a):
    # `_t_grep` scans the decompiled bodies (.c) with a regex. The IDA index holds no
    #   bodies (`_IdaIndex.text == ""`), so using `_ix()` directly **sweeps an empty
    #   string and always returns zero** — which really happened in one round: a
    #   symbol with 18 occurrences in the binary came back as 0. The agent caught it
    #   with a positive control and did not use the result, but that was luck. It is
    #   blocked here.
    ix = TARGET["_ix"]
    if ix is None or not getattr(ix, "text", ""):
        return _noix("corpus_grep needs **decompiled bodies (.c)**. "
                     "The IDA index holds no bodies — do not use zero hits as grounds for an absence. "
                     "Use find_bytes for binary strings/constants and callers/callees for call relations")
    try:
        rx = re.compile(a["pattern"], re.M)
    except re.error as e:
        return f"regex error: {e}"
    txt = ix.text
    out, seen = [], 0
    lim = int(a.get("limit") or 60)
    for m in rx.finditer(txt):
        seen += 1
        if len(out) >= lim:
            continue
        fn = ix.func_at_offset(m.start()) if hasattr(ix, "func_at_offset") else None
        if fn is None:
            fn = "?"
            for va, n in ix.byva:
                if ix.fn[n][1] <= m.start():
                    fn = n
                else:
                    break
        line = txt[txt.rfind("\n", 0, m.start()) + 1: txt.find("\n", m.end())]
        out.append(f"  {fn}: {line.strip()[:150]}")
    grouped = {}
    for o in out:
        k = o.split(":")[0].strip()
        grouped[k] = grouped.get(k, 0) + 1
    return (f"'{a['pattern']}' matches: {seen} (showing {len(out)}, {len(grouped)} functions)\n" +
            "\n".join(out) +
            ("\n\n★ Zero hits does not mean 'there is none', it means 'this expression does not catch it'. Ask again by behaviour."
             if seen == 0 else ""))


# ── dispatch table (the IOCTL census technique) ──────────────────────────
_METHOD = {0: "BUFFERED", 1: "IN_DIRECT", 2: "OUT_DIRECT", 3: "NEITHER"}
_ACCESS = {0: "ANY", 1: "READ", 2: "WRITE", 3: "READ|WRITE"}


def _locate_table(p, probe_code, stride, code_off):
    """Find the start of a dispatch table, using one known IOCTL code as the anchor.

    The criteria (all deterministic):
      ① those 4 bytes sit in a data/read-only section
      ② the neighbours at stride intervals on either side are also **CTL_CODE-shaped** (driver.plausible_ctl)
      ③ at least 3 such neighbours in a row
    If any one condition fails it offers no candidate — giving no answer beats guessing.
    """
    import driver as DRV
    need = struct.pack("<I", probe_code & 0xFFFFFFFF)
    out = []
    for s_ in p.secs:
        beg, o = p.base + s_["va"], s_["raw"]
        n = min(s_["rsize"], max(0, len(p.d) - o))
        start = 0
        while True:
            j = p.d.find(need, o + start, o + n)
            if j < 0:
                break
            start = (j - o) + 1
            hit_va = beg + (j - o) - code_off
            # neighbour check
            run, first = 0, hit_va
            for k in range(1, 40):
                d = p.read(hit_va - k * stride + code_off, 4)
                if not d:
                    break
                v = int.from_bytes(d, "little")
                if not DRV.plausible_ctl(v):
                    break
                run += 1
                first = hit_va - k * stride
            fwd = 0
            for k in range(1, 256):
                d = p.read(hit_va + k * stride + code_off, 4)
                if not d:
                    break
                v = int.from_bytes(d, "little")
                if not DRV.plausible_ctl(v):
                    break
                fwd += 1
            if run + fwd >= 3:
                out.append((first, "[%s] anchor 0x%X → table start 0x%X (%d entries back, %d forward, contiguous)"
                            % (s_["name"], hit_va, first, run, fwd)))
    out.sort(key=lambda t: -len(t[1]))
    return out


def _t_dispatch_table(a):
    """Decode a dispatch table deterministically. Splitting CTL_CODE fields is exact by
    definition — it is not something for an LLM to count by hand. (A Windows IOCTL census used
    this method on 27k drivers and matched independent disassembly 272/272.)"""
    p = _pe()
    ix = _ix()
    if not p:
        return "no binary."
    stride = int(a.get("stride") or 24)
    # probe= : **locates the table** from a single known control code. Until now the
    # table VA had to be supplied by hand (the attack-surface module's comments record
    # that limit), and on one target a separate script did this job. It is
    # deterministic, so the harness should do it.
    if a.get("va") in (None, "", 0) and a.get("probe") not in (None, ""):
        pr = a["probe"]
        pr = int(pr, 16) if isinstance(pr, str) and not pr.startswith("0x") else int(str(pr), 0)
        found = _locate_table(p, pr, stride, int(a.get("code_off") or 0))
        if not found:
            return ("found no table from probe=0x%X at stride=%d. Try a different stride or "
                    "supply code_off. (A table repeats its code field at stride intervals and "
                    "its neighbours must be CTL_CODE-shaped too)" % (pr, stride))
        va, why = found[0]
        if len(found) > 1:
            why += "  ⚠ the first of %d candidates — the rest: %s" % (
                len(found), ", ".join("0x%X" % v for v, _w in found[1:4]))
        a = dict(a); a["va"] = va
    va = int(a["va"], 16) if isinstance(a["va"], str) else int(a["va"])
    count = int(a.get("count") or 64)
    code_off = int(a.get("code_off") or 0)
    hoffs = a.get("handler_offs") or [8, 16]
    if isinstance(hoffs, str):
        hoffs = [int(x, 0) for x in re.split(r'[,\s]+', hoffs) if x]
    name_of = {}
    if ix:
        # measured-build VA -> name. A different corpus build needs reverse relocation.
        for cva, n in ix.byva:
            name_of[cva] = n
    def nm(x):
        if not x:
            return "-"
        if x in name_of:
            return name_of[x]
        if TARGET["_alt"] is not None:
            back, how = PEmod.relocate_escalating(p, TARGET["_alt"], x)
            if back in name_of:
                return name_of[back] + ("" if how == "same" else f" (←0x{back:x})")
        return "0x%x" % x
    L = [f"dispatch table @ 0x{va:x}  stride={stride} count={count}",
         "idx  code        devtype func  method     access  " + "  ".join(f"h@+{h}" for h in hoffs),
         "-" * 130]
    live = 0
    for i in range(count):
        d = p.read(va + i * stride, stride)
        if d is None or len(d) < stride:
            L.append(f"{i:<4} (outside the mapping)"); continue
        code = int.from_bytes(d[code_off:code_off + 4], "little")
        hs = [int.from_bytes(d[h:h + 8], "little") for h in hoffs]
        if not code and not any(hs):
            L.append(f"{i:<4} (empty)"); continue
        live += 1
        L.append("%-4d 0x%08X  0x%04X  %-5d %-10s %-7s %s" %
                 (i, code, (code >> 16) & 0xFFFF, (code >> 2) & 0xFFF,
                  _METHOD.get(code & 3, "?"), _ACCESS.get((code >> 14) & 3, "?"),
                  "  ".join(nm(h) for h in hs)))
    L += ["-" * 130, f"live {live} / {count}",
          "★ This table IS the census. File it as-is with surface(action='add') — "
          "leave anything you could not analyse as unanalysed, do not drop it."]
    return _cap("\n".join(L))



# ── import xrefs over every executable section ───────────────────────────
def _t_import_xref(a):
    """Census of import references across **every executable section.** The tool removes the habit of looking only at `.text`.

    A real failure: on ipt.sys the model wrote "SeSinglePrivilegeCheck is not among the 23
    .text import calls" and could not close the kill condition. **The call was in PAGE** (0x14000CC59).
    That image is 12KB of .text against 32KB of PAGE, and **all 5 authorization calls are in PAGE** —
    looking only at .text makes authorization look like zero.
    """
    p = _pe()
    if not p:
        return "no binary."
    want = a.get("names")
    if want in (None, "", "authz"):
        want, desc = xref.AUTHZ, "AUTHZ preset (privilege/token/SD related)"
    elif want == "probe":
        want, desc = xref.PROBE, "PROBE preset (user-pointer validation)"
    elif want == "all":
        want, desc = None, "all imports"
    else:
        want = [x.strip() for x in str(want).split(",") if x.strip()]
        desc = "filter=" + ",".join(want)
    try:
        hits, cov, names = xref.sweep(p, want)
    except Exception as e:
        return "xref failed: %s" % e
    ledger.record_xref(desc, [c["name"] for c in cov], sorted(set(names.values())), len(hits))
    return xref.render(hits, cov, names, desc) + (
        "\n\n★ This result sees **direct references only.** Calls via function pointers, vtables or DPC callbacks are invisible — "
        "before settling an absence, also check the places in that image that take a function address with `lea reg, [rip+X]`.")


def _t_authz_reach(a):
    """Does the handler **reach an authorization API** — a call-graph BFS over every executable section.

    This was the core measurement of A-13 (http.sys ClientSession): all 20 client IOCTLs had
    zero authorization APIs, while the server-side control did detect them. That tool existed
    only as a window_kernel-specific script — it has been moved into the harness and generalised.

    ★ A 'zero' produced without controls= is not grounds. Include a handler known to
    perform authorization alongside. If the control comes back zero too, the analyser is broken.
    """
    p = _pe()
    if not p:
        return "no binary."
    def _vas(x):
        if not x:
            return []
        return [int(v, 0) for v in re.split(r'[,\s]+', str(x)) if v]
    tg, ct = _vas(a.get("targets") or a.get("va")), _vas(a.get("controls"))
    if not tg:
        return "give handler VAs (comma-separated) in targets=. dispatch_table provides that list."
    apis = a.get("apis")
    apis = tuple(x.strip() for x in str(apis).split(",")) if apis else authz.AUTHZ
    try:
        res = authz.audit(p, tg, ct, apis=apis, depth=int(a.get("depth") or 6))
    except Exception as e:
        return "authz failed: %s" % e
    if res.get("valid"):
        ledger.record_xref("authz_reach positive control passed", ["<callgraph>"], list(apis)[:20],
                           sum(len(v.get("found", {})) for v in res["targets"].values()))
    return authz.render(res) + (
        "\n\nLimits: tracks **direct calls only** (indirect, vtable and DPC callbacks are not tracked). Depth %d. "
        "Based on import names. Write these three in the report as well." % int(a.get("depth") or 6))


# ── byte / instruction search ────────────────────────────────────────────
def _t_find_bytes(a):
    """Find a byte pattern in the measured build's .text. `??` is a wildcard.

    **This is the right path when relocation fails.** Code-signature relocation cannot follow a
    recompile — changing nothing but register allocation and stack slots changes every byte (this
    really happened from 8875 to live with UlPrepareParsedHeaderRangeResponse: the same instruction
    order, but r13→rax, [rbp-0x21]→[rbp-0x31]). What a human does then is search again by **a
    constant that does not change** — a struct offset + immediate pair survives a recompile.
    e.g. cmp dword [r+0x2d4], 0x0FFFFFFF → hex='d4020000ffffff0f'
    """
    _imgn = str(a.get("image") or "").strip().lower()
    if _imgn not in MAIN_ALIASES:
        p = image_of(_imgn)
        if p is None:
            return "auxiliary image %r is not registered. images(action='list')." % _imgn
    else:
        p = _pe()
    if not p:
        return "no binary."
    pat = re.sub(r'[\s_]', '', a.get("hex", ""))
    if not pat or len(pat) % 2 or not re.fullmatch(r'[0-9a-fA-F?]+', pat):
        return "give a byte pattern in hex= (even length, `??` is a wildcard)."
    pairs = [pat[i:i + 2] for i in range(0, len(pat), 2)]
    fixed = [(i, int(b, 16)) for i, b in enumerate(pairs) if b != "??"]
    if not fixed:
        return "it is all wildcards."
    secs = [s for s in p.secs if s["chars"] & 0x20000000] if a.get("code_only", 1) else p.secs
    out, total = [], 0
    lim = int(a.get("limit") or 40)
    ix = _ix()
    for s in secs:
        blob = p.d[s["raw"]:s["raw"] + s["rsize"]]
        base = p.base + s["va"]
        anchor_i, anchor_b = fixed[0]
        needle = bytes(b for _i, b in fixed[:1])
        i = 0
        while True:
            i = blob.find(needle, i)
            if i < 0:
                break
            st = i - anchor_i
            if st >= 0 and all(st + k < len(blob) and blob[st + k] == v for k, v in fixed):
                total += 1
                if len(out) < lim:
                    va = base + st
                    # A match usually lands **inside** an instruction (a displacement or an
                    # immediate). Walk back to the start of the instruction containing that byte —
                    # otherwise the answer is always "decode failed".
                    mlen = len(pairs)
                    ins, iva = p.disasm(va, 1), va
                    best = None
                    for back in range(0, 16):
                        cand = p.disasm(va - back, 1)
                        if not cand:
                            continue
                        s0, e0 = cand[0][0], cand[0][0] + len(cand[0][1])
                        if s0 <= va and e0 >= va + mlen:      # the instruction covering the whole match
                            best = (cand, va - back)
                            break
                    if best:
                        ins, iva = best
                    fn = ""
                    if ix and TARGET["_alt"] is not None:
                        b2, _ = PEmod.relocate_escalating(p, TARGET["_alt"], iva)
                        if b2:
                            fn = ix.func_at(b2) or ""
                    elif ix:
                        fn = ix.func_at(iva) or ""
                    out.append("  0x%x%s  %-40s %s" % (
                        iva, ("(+%d)" % (va - iva)) if iva != va else "    ",
                        (ins[0][2] + " " + ins[0][3])[:39] if ins else "(decode failed)", fn))
            i += 1
    return (f"'{pat}' hits: {total} (showing {len(out)}, sections {[s['name'] for s in secs]})\n" +
            "\n".join(out) +
            ("\n\n★ Zero hits means this build does not have that shape. Shrink the constant and search again "
             "(the struct offset alone, or the immediate alone)." if total == 0 else
             "\n\n★ Function names are traced back through the reference build, so they can be empty for recompiled functions."))


# ── anchors ──────────────────────────────────────────────────────────────
def _t_anchor(a):
    p = _pe()
    if not p:
        return "no binary — anchors cannot be verified."
    txt = a.get("cites") or ""
    if a.get("relocate"):
        alt = TARGET["_alt"]
        if not alt:
            return "relocate needs a reference build (ALT)."
        out = []
        for m in re.finditer(r'0x[0-9a-fA-F]{6,16}', a["relocate"]):
            v = int(m.group(0), 16)
            nv, how = PEmod.relocate_escalating(alt, p, v)
            out.append(f"  0x{v:x} → " + (f"0x{nv:x} ({how})" if nv else f"not found ({how})"))
        return "reference build → measured build relocation:\n" + "\n".join(out)
    res, summ = evidence.check(p, txt, alt=TARGET["_alt"], images=images_all())
    return evidence.render(res, summ)


# ── notes (a checkpoint outside the context) ─────────────────────────────
def _t_priorart(a):
    """Record a prior-art search in the ledger. The confirm gate requires this record.

    This harness has no network — search with **what you know and the material the user
    supplied**, and write down here what you based a 'new / already known' judgement on. If
    you do not know, say so. 'not searched' and 'searched, found nothing' are completely different values.
    """
    what = a.get("what") or ""
    if not what:
        return ("write **what you searched for** in what= (device name / IOCTL code / handler name). "
                "where= is where you looked, result= is what came up.\n"
                "axis= is one of three: device | ioctl | symbol. "
                "The confirm gate does not count a record with no axis.")
    return ledger.record_priorart(what, a.get("where") or "(not stated)",
                                  a.get("result") or "(no result stated — this is not a search)",
                                  axis=a.get("axis") or "")


# **The notes lived only under `work/notes/`, and that directory is documented as
#   "safe to delete"** (`runlog.py`'s opening comment: *"work/ ... `rm -rf work/*`
#   to clear it"*). Measured one morning: **562 notes, 3.1MB.** They hold all the
#   grounds a track note points at with "full detail in note X", and the reopen
#   shortlist references them too.
#   => following the instructions turns **the entire shortlist into dead
#   pointers.** The transcript already got this treatment
#   (`runlog.ARCHIVE_DIR`); the notes are preserved alongside it.
NOTES_ARCHIVE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports", "notes")


def _note_archive(key, body):
    """Keep a copy under `reports/notes/`. A failure here never blocks the
    original write."""
    try:
        os.makedirs(NOTES_ARCHIVE, exist_ok=True)
        with open(os.path.join(NOTES_ARCHIVE, key + ".md"), "w", encoding="utf-8") as f:
            f.write(body)
    except OSError:
        pass


# **Close the hole where a prose handoff overrides the adversaries.**
#   A real incident: the interrogator broke all four rejections in one family
#   (broke:true) and escalated with "do not rewrite the label a fifth time — what
#   is missing is an observation, seal it as needs-measurement". Two minutes later
#   a hand-written handoff note reversed that verdict outright with
#   "THE <FAMILY> IS CLOSED. Do NOT reopen.", and the next session believed the
#   prose and reported a negative. The gates audit verdicts; nobody audits a prose
#   note. A note is in the same family as the GOAL — a surface no adversary looks
#   at.
#   => it does not block (blocking produces spinning), it attaches **a live
#     banner.** The grounding re-derives `graveyard_trust()` on every call, so it
#     cannot go stale, it also catches notes already written, and it never touches
#     the original text.
_CLOSURE_RX = re.compile(
    r'\bCLOSED\b|do\s*not\s*re\s*open|is\s+closed|clean\s+negative'
    r'|no\s+(surviving\s+)?variant|true\s+negative|real\s+negative|clean\b.*negative',
    re.I)


def _broke_doubt_banner(text):
    """Build a warning banner when a note's body claims a 'negative that does not stand' (broke/reopened) is CLOSED.
    Only when both hold: (1) closure wording is present and (2) the note references that broke/reopened
    rejection by an id token or an anchor VA. Grounded in ledger.graveyard_trust() — re-derived from current state on every call."""
    if not text or not _CLOSURE_RX.search(text):
        return ""
    try:
        _, rows, _ = ledger.graveyard_trust(limit=10 ** 6)   # return only the broke + reopened rows
    except Exception:
        return ""
    # Pull anchors out of the full, untruncated graveyard entry
    # (target/claim/reason): a row's target[:90] loses the anchor. Also match on the
    # family prefix (the first token of the id) — a handoff names a family rather
    # than individual ids, as in "THE <FAMILY> IS CLOSED".
    try:
        _gy = {str(g.get("id")): g for g in (ledger.STATE.get("graveyard") or [])}
    except Exception:
        _gy = {}
    low = text.lower()
    hits = []
    for r in rows or []:
        gid = str(r.get("id") or "")
        if not gid:
            continue
        g = _gy.get(gid) or {}
        blob = " ".join(str(g.get(k) or "") for k in ("target", "claim", "reason")) or str(r.get("target") or "")
        anchors = set(re.findall(r'0x[0-9a-fA-F]{6,16}', blob.lower()))
        fam = re.split(r'[-_]', gid)[0]                       # family prefix
        ref = (gid.lower() in low
               or (len(fam) >= 4 and not fam.isdigit() and fam.lower() in low)
               or any(a in low for a in anchors))
        if ref:
            hits.append((gid, r.get("grade"), r.get("klass")))
    if not hits:
        return ""
    L = ["⚠️ HARNESS — this note's CLOSED/negative claim does not stand (re-derived on every read):"]
    for gid, grade, klass in hits[:8]:
        tag = "the interrogator broke it (broke)" if grade == "broke" else "reopened — a withdrawn negative"
        L.append("   · %s [%s] %s — this is due for needs-measurement/re-examination, not 'closed'."
                 % (gid, klass or "?", tag))
    L.append("   A broke:true rejection has already been rebutted by an adversary. Handle it with "
             "verdict(action='lead'|'reaudit'), and do not write it as CLOSED in a handoff until a measurement resolves it.")
    L.append("   (memory: broke-rejections-are-open-not-negative)")
    return "\n".join(L) + "\n\n"


def _t_note(a):
    """A record that survives context compaction. Keeps findings from quietly vanishing in a long session."""
    d = os.path.join(config.WORK_DIR, "notes")
    os.makedirs(d, exist_ok=True)
    key = re.sub(r'[^A-Za-z0-9._-]', '_', a.get("key", "misc"))[:60]
    p = os.path.join(d, key + ".md")
    if a.get("action") == "read":
        if not os.path.exists(p):
            avail = sorted(x[:-3] for x in os.listdir(d)) if os.path.isdir(d) else []
            return f"'{key}' not found. Available: {', '.join(avail) or '(none)'}"
        _body = open(p, encoding="utf-8").read()
        return _cap(_broke_doubt_banner(_body) + _body)      # first, so the banner cannot be truncated away
    with open(p, "a", encoding="utf-8") as f:
        f.write(a.get("text", "") + "\n")
    # an archived copy - work/ is documented as safe to delete (see NOTES_ARCHIVE above)
    try:
        _note_archive(key, open(p, encoding="utf-8").read())
    except OSError:
        pass
    _warn = _broke_doubt_banner(a.get("text", ""))            # warn the author immediately (without blocking)
    tail = ("\n\n" + _warn) if _warn else ""
    return f"appended {len(a.get('text',''))} chars to note[{key}]. It persists outside the context." + tail


# ── IDA, when available ──────────────────────────────────────────────────
def _winpath(p):
    if p.startswith("/mnt/"):
        return p[5].upper() + ":" + p[6:].replace("/", "\\")
    try:
        return subprocess.run(["wslpath", "-w", p], capture_output=True,
                              text=True, timeout=10).stdout.strip() or p
    except Exception:
        return p


def _ida_call(op, target):
    if not (config.USE_IDA and TARGET["binary"] and os.path.exists(config.IDAT)):
        return None
    with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False) as f:
        outp = f.name
    env = dict(os.environ, IDA_CMD=json.dumps({"op": op, "args": {"target": target}}),
               IDA_OUT=_winpath(outp))
    # Environment variables **do not cross automatically** from WSL into a Windows
    #   process — only the names listed in WSLENV do. Without this the worker never
    #   receives IDA_CMD, falls back to overview, dies with a KeyError on
    #   os.environ["IDA_OUT"], writes no output file, and `_ida_call` returns
    #   "IDA failed: Expecting value" — i.e. **a silent negative that looks like "IDA
    #   is unavailable" even when IDA is installed.**
    #   (The path is already in Windows form via `_winpath`, so the /p flag must not
    #   be added.)
    env["WSLENV"] = ":".join(x for x in (env.get("WSLENV", ""), "IDA_CMD", "IDA_OUT") if x)
    cmd = ([config.WINE] if config.WINE else []) + [
        config.IDAT, "-A", "-S" + _winpath(config.IDA_WORKER), _winpath(TARGET["binary"])]
    # With a stale unpacked database left behind, IDA exits immediately with rc=4 and
    #   produces no output. That used to be reported only as "IDA failed: Expecting
    #   value", which hid the cause. It cleans up and retries once; if the retry fails
    #   too, the rc is reported as-is.
    # Make the startup **visible.** A first analysis takes tens of seconds up to
    #   IDA_TIMEOUT (900s by default), and stdout/stderr used to be completely silent
    #   for all of it — so a hang was indistinguishable from progress. (A bench run
    #   against a large image with no corpus really did hang this way.)
    #   Same failure class as elsewhere in this file: silence hiding a cause.
    def _run():
        sys.stderr.write("[ida] %s ← %s (up to %ds)\n"
                         % (op, os.path.basename(TARGET["binary"]), config.IDA_TIMEOUT))
        sys.stderr.flush()
        t0 = time.time()
        pr = subprocess.run(cmd, capture_output=True, timeout=config.IDA_TIMEOUT, env=env)
        sys.stderr.write("[ida] %s rc=%d %.1fs\n" % (op, pr.returncode, time.time() - t0))
        sys.stderr.flush()
        try:
            with open(outp, encoding="utf-8", errors="replace") as f:
                return pr.returncode, json.load(f)
        except Exception as e:
            return pr.returncode, None if pr.returncode == 0 else e

    try:
        rc, res = _run()
        if isinstance(res, dict):
            return res
        stale = [TARGET["binary"] + e for e in (".id0", ".id1", ".id2", ".nam", ".til")
                 if os.path.exists(TARGET["binary"] + e)]
        if stale:
            for f in stale:
                try:
                    os.unlink(f)
                except OSError:
                    pass
            rc, res = _run()
            if isinstance(res, dict):
                return res
        return {"error": "IDA rc=%d, no output (%s). If it still fails after the stale DB is cleaned up, "
                         "run `%s -A -S%s %s` directly to see why."
                         % (rc, res, config.IDAT, config.IDA_WORKER, TARGET["binary"])}
    except Exception as e:
        return {"error": f"IDA failed: {e}"}
    finally:
        try:
            os.unlink(outp)
        except OSError:
            pass


# ── the IDA index: keeps the navigation tools alive with no .c corpus ────
# Why it is needed: with no corpus, find_funcs / func_at / callers / callees /
# callpath / census all died with "no corpus". That is the orchestrator's default
# path — the agent was groping around with nothing but addresses. One `index` op
# through the IDA worker (about 30s, then roughly 3s reusing the IDB) yields the
# function table plus the direct-call graph. Names come out real when a PDB is
# present.
class _IdaIndex(nav.Index):
    """The **same interface** as nav.Index. Every method is inherited; only the data comes from IDA.
    => the tool functions all work unchanged, without touching a single one."""

    def __init__(self, data):
        # nav.Index.__init__ parses a .c file; it is not called here.
        self.path = "(IDA)"
        self.text = ""
        self.fn, self.byva = {}, []
        for f in data.get("functions") or []:
            n = f["name"]
            va = int(f["start"], 16)
            if n in self.fn:                      # same name twice -> disambiguate by VA (the same rule as nav)
                n = "%s@%x" % (n, va)
            self.fn[n] = (va, 0, 0)               # the body offsets are unused (body() returns None)
            self.byva.append((va, n))
        self.byva.sort()
        _byva = {va: n for va, n in self.byva}
        self.out, self.inn = {}, {}
        for sva, dsts in (data.get("calls") or {}).items():
            a = _byva.get(int(sva, 16))
            if not a:
                continue
            for d in dsts:
                b = _byva.get(int(d, 16))
                if not b:
                    continue
                self.out.setdefault(a, []).append(b)
                self.inn.setdefault(b, []).append(a)

    def body(self, name):
        # Decompiled bodies are not cached — `_t_decompile` goes through
        # `_ida_call('decompile')`.
        return None


def _ida_index():
    """The IDA function table + call graph. Built once per process, and cached on disk too."""
    if TARGET.get("_iix") is not None:
        return TARGET["_iix"] or None
    b = TARGET["binary"]
    if not (b and config.USE_IDA and os.path.exists(config.IDAT)):
        TARGET["_iix"] = False
        return None
    try:
        st = os.stat(b)
        key = hashlib.sha1(("%s|%d|%d" % (b, st.st_size, int(st.st_mtime))).encode()).hexdigest()[:16]
        cp = os.path.join(config.WORK_DIR, "idaidx-%s.json" % key)
    except OSError:
        cp = None
    data = None
    if cp and os.path.exists(cp):
        try:
            data = json.load(open(cp, encoding="utf-8"))
        except Exception:
            data = None
    if data is None:
        r = _ida_call("index", None)
        if not r or r.get("error") or not r.get("functions"):
            TARGET["_iix"] = False
            return None
        data = r
        if cp:
            try:
                json.dump(data, open(cp, "w", encoding="utf-8"))
            except OSError:
                pass
    try:
        TARGET["_iix"] = _IdaIndex(data)
    except Exception:
        TARGET["_iix"] = False
        return None
    return TARGET["_iix"]



# ── the rest ─────────────────────────────────────────────────────────────
def _t_surface(a):
    act = a.get("action")
    if act == "add":
        return ledger.surface_add(a.get("items") or [], a.get("kind", "ingress"),
                                  a.get("reach", "unknown"))
    if act == "incidental":
        # For when **B was found while looking at A.** This channel exists to tell that
        #   apart from widening (filing rows indiscriminately). The best defect of one
        #   session came out exactly that way, while the seed was punishing the path with
        #   "do not add new surface". Marked as incidental it is exempt from the
        #   denominator-inflation warning and the worklist promotes it.
        nm, fw = a.get("name"), a.get("found_while") or a.get("why") or ""
        if not nm:
            return "incidental needs name= (the surface name already filed with add)."
        if len(fw) < 10:
            return ("write one line in `found_while=` saying **what you were doing when you found it.** "
                    "That is the ground for this mark — the sentence is what separates a row merely filed from one hit while digging.")
        r = ledger.mark_incidental(nm, fw)
        if r is None:
            return "no such surface: %r — file it with surface(action='add') first." % nm
        return ("marked `%s` as an **incidental finding** (while: %s)\n"
                "★ This is not denominator inflation. It is a product of real work, so the worklist moves it up."
                % (nm, fw[:120]))
    if act == "race":
        return ledger.race_add(a.get("a", ""), a.get("b", ""), a.get("shared", ""),
                               a.get("why", ""), a.get("reach", "user-triggerable-async"))
    if act == "async":
        # Exhaustive asynchronous entry points — the pool of race counterparties. Do
        # not read an absence here as "there is none"; this is a candidate generator.
        try:
            import async_entry as AE
            p_ = _pe()
            if p_ is None:
                return "no binary."
            rs = AE.enumerate_async(p_)
            got = [r for r in rs if r.get("callback")]
            ix = _ix()
            nm = {cva: n for cva, n in ix.byva} if ix else {}
            L = ["%d registration call sites / %d callbacks recovered (unrecovered ones may go through a register or a global)"
                 % (len(rs), len(got)), "These are reach='user-triggerable-async' — "
                 "async counterparties the user **triggers** (do not discard them as kernel-only)."]
            seen = set()
            for r in got:
                if r["callback"] in seen:
                    continue
                seen.add(r["callback"])
                L.append("  0x%X  %-46s ← %s" % (r["callback"],
                         nm.get(r["callback"], "(unnamed)")[:46], r["registrar"]))
            return _cap("\n".join(L))
        except Exception as e:
            return "async enumeration failed: %s" % e
    if act == "reach":
        # Called without a name it **enumerates the rows not yet decided.** The
        #   completion gate demands the unknown rows, and with no way to point at them
        #   two rounds spent roughly 150 name probes guessing.
        _nm = (a.get("name") or "").strip()
        if not _nm or _nm == "?":
            _rows, _n = ledger.reach_unknown(40)
            if not _n:
                return "no rows have reach='unknown'. This item of the completion gate is already satisfied."
            return ("%d rows have no reach decided yet (up to 40 shown) — **copy the names exactly**:\n"
                    % _n + "\n".join("  · " + r for r in _rows)
                    + "\n\nsurface(action='reach', name='<the name above, verbatim>', reach=..., why=...)")
        _r = ledger.surface_reach(_nm, a.get("reach", "unknown"), a.get("why", ""))
        if isinstance(_r, str) and "is not in the census table" in _r:
            _rows, _n = ledger.reach_unknown(20)
            if _n:
                _r += ("\n\nThe %d rows still undecided are these (do not guess names — copy them):\n"
                       % _n + "\n".join("  · " + x for x in _rows))
        return _r
    if act == "set":
        return ledger.surface_set(a.get("name", "?"), a.get("status", "auditing"), a.get("why", ""))
    return ledger.status_block(None, None)


def _t_sink_gates(a):
    """Census of the cmp/test/call instructions that **dominate** a sink — **one hop** of ASK (`dominates_only`).
    The direction is the opposite of `dispatch`/`gates`: not 'does the guard I named block it' but
    '**what else** blocks this sink'."""
    p = _pe()
    if p is None:
        return "no binary."
    import cfg as CFG
    # A confirmed bug: this used to be `a.get("target") or a.get("sink")`, so a
    #   present `target` **discarded the sink entirely.** The agent's standard call is
    #     sink_gates(target='<handler name>', sink='0x...31b')
    #   and the tool analysed the function's **entry point** instead and answered
    #   about that. Measured: the answer to a target+sink call equalled the answer to
    #   a target-only call (the sink ignored), and **differed** from the sink-only
    #   answer. Nothing dominates a function entry point, of course, so the result was
    #   always "no guard" — it was **quietly answering a different question.**
    #   => the sink **takes precedence.** When the two differ, the output states which
    #   one was used.
    _sk = (str(a.get("sink") or "")).strip()
    _tg = (str(a.get("target") or "")).strip()
    name, cva, lva, note = resolve(_sk or _tg)
    if lva is None:
        return note or "could not resolve the sink address."
    _amb = ""
    if _sk and _tg:
        _n2, _c2, _l2, _ = resolve(_tg)
        if _l2 is not None and _l2 != lva:
            _amb = ("\n\n※ `target=%s` (→0x%X) and `sink=%s` (→0x%X) differ. "
                    "**sink was used.** target is read only as a name for the containing function — "
                    "to ask about instruction-level dominance, sink= is the right argument."
                    % (_tg, _l2, _sk, lva))
    try:
        r = CFG.sink_gates(p, lva, int(a.get("max_span") or 0x20000))
    except Exception as e:
        return "sink_gates failed: %s" % e
    if not r:
        return ("found no cmp/test/call dominating sink 0x%X. **This is not 'no guard'** — "
                "it can be validated outside the function (in a caller). Go one hop up with callers()." % lva) + _amb
    return _cap("\n".join(str(x) for x in (r if isinstance(r, list) else [r]))) + _amb


# The last probe result the harness observed itself. `_t_measure` treats this
# as canonical.
_LAST_PROBE = {}
# A store for kd output. It exists for the same reason as `_LAST_PROBE`: so the
#   scorer grades from **output the harness saw itself** rather than **a value the
#   agent transcribed.** `measure(action='before_after')` cross-checks the
#   provenance of the before/after values here — found means kd-grounded, not
#   found means `declared`. The point is to stop laundering.
_LAST_KD = {"v": []}
_LAST_KD_MAX = 8


_IL_SID = {
    "S-1-16-4096":  "Low",
    "S-1-16-8192":  "Medium",
    "S-1-16-12288": "High",
    "S-1-16-16384": "System",
}


def _principal_lines(r):
    """Write the **credentials** that produced this measurement into the result. If there are none, say so.

    ★ 2026-09-06. Why: the guest ioctl channel runs on the vmrun token (High+Administrators).
      That fact appeared nowhere in the result, so "a low-privilege principal reaches this sink"
      was written **with no measurement behind it**, and the conductor was re-reporting the same
      item as a harness problem for the 22nd, 19th and 15th time. Not left to memory — a measurement carries its own credentials.
    ★ It prescribes no conclusion. It only states **what this result can say and what it cannot.**
    """
    pc = (r or {}).get("principal") or {}
    if pc.get("err"):
        return ["  ⚠ failed to read the principal: %s — the credentials behind this measurement are unknown. "
                "Do not use it for a privilege-boundary claim." % str(pc["err"])[:120]]
    if not pc:
        return ["  ⚠ no principal field (an old probe). Which token this measurement came from is "
                "unknown — do not use it for a privilege-boundary claim."]
    sid = str(pc.get("il_sid") or "")
    out = ["  principal: %s · IL=%s · elevated=%s"
           % (pc.get("user"), _IL_SID.get(sid, sid or "unknown"), pc.get("elevated"))]
    if pc.get("elevated") or sid in ("S-1-16-12288", "S-1-16-16384"):
        out.append("  ★ **This measurement came from an elevated token.** It can speak to reachability "
                   "itself, but **it cannot speak to a privilege boundary** — the claim "
                   "'a low-privilege principal reaches it' needs a separate non-elevated context"
                   "(`schtasks /ru \"NT AUTHORITY\\LOCAL SERVICE\"`).")
    return out


def _t_ioctl(a):
    """**Actually sends an IOCTL.** The piece the harness lacked — `measure` is a scorer, not an executor.

    Sends twice with different fill values (0xCC / 0x55 by default), producing exactly the shape
    `measure(action='classify')` expects. Every run also produces **three controls** (NUL opens /
    PhysicalDrive0 err=5 / nonexistent device err=2), and if any one is off **it returns no result** —
    because a broken probe and a blocked driver produce the same result.

    ★ `where=` (wired 2026-09-05)
      `host` (default) — fires at this analyst machine. **A BSOD takes the harness and the ledger down with it.**
      `guest`          — fires at an isolated VMware guest (`vmprobe.py`). A crash is recovered from a snapshot.
                         The same code and the same three controls run inside the guest — only the transport differs.
      **When testing something that can crash, use `guest`.** Hesitating on the host and not measuring
      lets a static estimate harden into a conclusion with no measurement.
    """
    _where = str(a.get("where") or "host").lower()
    _prin = str(a.get("principal") or "default").lower()
    if _prin not in ("default", "low"):
        return "principal is one of default | low (got: %r)" % _prin
    if _prin == "low" and _where not in ("guest", "vm"):
        return ("principal='low' works only on the guest — the host probe has no non-elevated "
                "transport. Specify where='guest' along with it.")
    if _where in ("guest", "vm"):
        import vmprobe as P
        _st = P.status()
        if _st != "ok":
            return ("guest measurement unavailable: %s\n"
                    "**This is not 'no defect', it is unmeasured.** Bring up the VM power/Tools/credentials first."
                    % _st)
    else:
        import probe as P
    try:
        _kw = {"principal": _prin} if _where in ("guest", "vm") else {}
        # **Pass `aux` / `fh` through.** The probe accepted both and the PowerShell side
        #   really did allocate the buffer and plant the address, but they were **missing
        #   from this relay and from the tool schema**, so the analyst could not use them.
        #   Three tracks sat for days on "the harness cannot place an interior pointer in
        #   the request". Three layers were in place and the top two were not — the
        #   classic unwired shape.
        _aux, _fh = a.get("aux") or None, a.get("fh") or None
        for _nm, _v, _req in (("aux", _aux, ("at", "hex")), ("fh", _fh, ("at", "path"))):
            if _v is None:
                continue
            if not isinstance(_v, (list, tuple)):
                return "%s must be a list (got: %r)" % (_nm, type(_v).__name__)
            for _e in _v:
                if not isinstance(_e, dict) or any(k not in _e for k in _req):
                    return ("each entry of %s must be a dict with the keys %s. Got: %r\n"
                            "  aux=[{'at': <offset in the input buffer to plant the pointer at>, "
                            "'hex': '<the contents of that buffer>', 'lenat': <optional: offset to write a "
                            "UNICODE_STRING Length/MaximumLength at>}]\n"
                            "  fh =[{'at': <offset to plant the handle at>, 'path': '<file to open>', "
                            "'acc': <DesiredAccess>}]" % (_nm, "/".join(_req), _e))
        if _aux:
            _kw["aux"] = _aux
        if _fh:
            _kw["fh"] = _fh
        r = P.ioctl(a.get("device", ""), int(str(a.get("code")), 0),
                    a.get("input", ""), **_kw,
                    inlen=int(str(a["inlen"]), 0) if a.get("inlen") else None,
                    outlen=int(str(a.get("outlen") or 0), 0),
                    access=int(str(a.get("access") or 0xC0000000), 0),
                    fills=tuple(int(x) for x in (a.get("fills") or (0xCC, 0x55))))
    except P.ProbeRefused as e:
        return "probe refused: %s" % e
    except Exception as e:
        return "probe failed: %s: %s" % (type(e).__name__, e)
    L = ["[ran on %s] three controls passed. open_err=%s" % (_where, r.get("open_err"))]
    L += _principal_lines(r)
    for run in r.get("runs") or []:
        if run.get("exc"):
            L.append("  fill=0x%02X  exception: %s" % (run.get("fill", 0), run["exc"]))
            continue
        L.append("  fill=0x%02X  ok=%s err=%s info=%s outhex=%s"
                 % (run.get("fill", 0), run.get("ok"), run.get("err"), run.get("info"),
                    (run.get("outhex") or "")[:160]))
    # Store **the value the harness actually sent.** Until now `measure` received hex
    #   the agent had transcribed — the harness fired and the scorer took hearsay, so
    #   the measurement grade was never grounded. It is stored here and `_t_measure`
    #   cross-checks it.
    try:
        _runs = [x for x in (r.get("runs") or []) if not x.get("exc")]
        if len(_runs) >= 2:
            _LAST_PROBE["v"] = {
                "a": _runs[0].get("outhex") or "", "b": _runs[1].get("outhex") or "",
                "status": _runs[0].get("err"), "info": _runs[0].get("info"),
                "device": a.get("device"), "code": str(a.get("code")),
                # The store carries the principal along. Without it,
                #   `measure(action='classify')` records the principal as 'unknown' **while
                #   grading bytes the harness itself sent** — discarding a fact it has.
                "principal": r.get("principal"), "principal_req": _prin,
                "t": __import__("time").strftime("%m-%d %H:%M")}
            # Grade right where it was fired, so an observation is never discarded
            # ungraded.
            try:
                import measure as M, ledger as _L
                _ha = bytes.fromhex((_runs[0].get("outhex") or "").replace(" ", ""))
                _hb = bytes.fromhex((_runs[1].get("outhex") or "").replace(" ", ""))
                _df = M.DualFill(_ha, _hb, status=_runs[0].get("err") or 0,
                                 info=_runs[0].get("info") or 0)
                _kh = M.kernel_ptrs(_ha)
                # This path passes `DeviceIoControl`'s **Win32 GetLastError.** Declare it rather
                #   than leaving it to inference: 5 (ACCESS_DENIED) does not match 0xC0000022 in
                #   the NTSTATUS table, so an authorization-layer refusal was leaking out as
                #   `unmeasured`.
                _g, _w = M.classify(_df, kernel_hits=_kh, space="win32",
                                    neither=(int(str(a.get("code")), 0) & 3) == 3)
                # **Carry the principal.** `r["principal"]` is a value actually read from the
                #   guest token, and if `principal='low'` was requested then
                #   `vmprobe.assert_low_principal()` has already verified it. Not passing it here
                #   loses that fact at the ledger boundary.
                _L.measure_record(a.get("target") or a.get("device") or "?", _g, _w,
                                  principal=_L.normalize_principal(
                                      r.get("principal"), req=_prin, src="probe"))
                L.append("\n★ The harness **graded it directly**: grade=%s — %s" % (_g, _w))
                L.append("   This grade came from bytes the harness observed, not from values you transcribed. "
                         "It is recorded in the ledger as a measurement, so you can cite it with basis='measured'.")
            except Exception as _me:
                L.append("\n[automatic grading failed: %s: %s] — a failure is not clean."
                         % (type(_me).__name__, _me))
            L.append("\n[the values the harness observed are stored] Calling measure(action='classify') with no arguments "
                     "grades from them. If you pass a=/b= yourself they are **cross-checked** against the stored values and a mismatch is reported.")
        else:
            # With only one fill, **the fact that it ran is still recorded even when nothing
            #   could be graded.** This used to leave nothing in the ledger, so a round that
            #   really did fire looked like "zero measurements" (the log said `ioctl 0` while
            #   the transcript showed four).
            #   It is a `trace`, not a grade — adjudicating from a single fill stays
            #   forbidden.
            import ledger as _Li
            _blob2 = "%s %s %s" % (a.get("target") or "", a.get("device") or "",
                                   a.get("code") or "")
            _Li.measure_record(a.get("target") or a.get("device") or "?", "trace",
                               "ioctl %s %s (single run — not graded)"
                               % (a.get("device"), a.get("code")),
                               kind="trace", vas=_Li.measure_vas(_blob2),
                               principal=_Li.normalize_principal(
                                   r.get("principal"), req=_prin, src="probe"))
    except Exception:
        pass
    L.append("\nPut the outhex of both fills into measure(action='classify', a=..., b=..., status=, info=). "
             "**A single-fill verdict is forbidden** — if the kernel writes bytes equal to that fill value, it is misread as unwritten.")
    return _cap("\n".join(L))


def _t_kd(a):
    """**Bring up the guest kernel with symbols and ask it** (KDNET / WinDbg kd).

    `ioctl` fires and looks at the **result**. This asks **why that result came out** —
    it looks directly inside the kernel with `x nt!<sym>` / `dt` / `!object` / `bp`. The debugStub (gdb)
    axis had no symbols and had to derive the base by scanning pages. Here the names come out as they are.

    ★ Every run also produces **two controls** — a symbol that exists (`nt!NtCreateFile`) must resolve
      and a nonexistent symbol must not. If either is off **it returns no result**: a broken debugger
      and "there is no such thing" produce the same result.
    ★ Afterwards it checks that the guest **really resumed** (putting in `qd` does not mean it resumed).
    """
    import kdnet as K
    st = K.status()
    if not st.startswith("ok"):
        return ("KDNET measurement unavailable: %s\n"
                "**This is not 'no defect', it is unmeasured.**" % st)
    try:
        r = K.run(a.get("cmds", ""), timeout=(int(str(a["timeout"]), 0)
                                              if a.get("timeout") else None),
                  target=a.get("target"))
    except K.ProbeRefused as e:
        return "KDNET refused: %s" % e
    except Exception as e:
        return "KDNET failed: %s: %s" % (type(e).__name__, e)
    # **Bind it to the ledger.** This tool's description promises `target=` is there
    #   "so the ledger can bind it" and **the wiring did not exist**
    #   (built-but-never-wired). Measured: an analyst ran baseline -> treatment ->
    #   after through kd with 3/3 controls, filed it as `basis=measured`, and was
    #   refused with "no measurement record" — and that round's only filed verdict
    #   fell back to `basis=disassemble`.
    #   No grade is assigned — kd is not a dual-fill scorer. It is recorded as
    #     `kind='trace'`: the content of this record is only "the harness really ran
    #     this".
    try:
        import ledger as _Lk
        _blob = "%s %s" % (a.get("cmds", ""), a.get("target") or "")
        _Lk.measure_record(a.get("target") or _Lk.STATE.get("target") or "?",
                           "trace", "kd: %s" % str(a.get("cmds", ""))[:200],
                           kind="trace", vas=_Lk.measure_vas(_blob),
                           # kd is a kernel debugger, not a user token. It is an observation, but it cannot
                           #   support a claim about which principal reaches something.
                           principal="kd")
    except Exception:
        pass                       # a recording failure must not withhold the observation
    # Store the output **the harness saw itself.** `measure(action='before_after')`
    #   cross-checks the provenance of the before/after values against this.
    try:
        _LAST_KD["v"].append({"cmds": str(a.get("cmds", ""))[:400],
                              "output": str(r.get("output") or ""),
                              "target": a.get("target") or "",
                              "t": __import__("time").strftime("%m-%d %H:%M")})
        del _LAST_KD["v"][:-_LAST_KD_MAX]
    except Exception:
        pass
    # **State the route to grading right here.** One analyst wrote *"I will turn this
    #   into a graded before/after"* and then did not: it had **never loaded the
    #   `measure` tool**, so it had no schema for it. Building a scorer with no route
    #   to it leaves every observation as a `trace` — the same reason this target sat
    #   at `measures=0` for three months.
    #   The prompt is delivered once at the start of a round, which is too late; **a
    #   tool response is always read.**
    _grade_hint = (
        "\n★ Turn this observation into a **grade.** As it stands it stays in the ledger only as a `trace` (the fact that it ran) "
        "and supports no verdict.\n"
        "   If you read the same spot **before/after** a treatment:\n"
        "     ToolSearch(query='select:mcp__vuln__measure')  ← the schema must be loaded first before it can be called\n"
        "     measure(action='before_after', target=…, before=…, after=…,\n"
        "             control_before=…, control_after=…)\n"
        "   **Without a control (an untreated arm) the grade is `uncontrolled`** — because a value drifting "
        "by itself cannot be told apart from the treatment changing it. The harness judges the provenance by "
        "cross-checking the values against its own kd output (transcribed values become `declared`).")
    return _cap("[ran in the guest kernel] two controls passed · kernel_base=%s · resume confirmed=%s\n%s%s"
                % (r.get("kernel_base"), r.get("resumed"),
                   r.get("output") or "(no output)", _grade_hint))



def _t_kdscan(a):
    """**Keep the breakpoint alive until one sample matching the condition is found.**

    `kd` sets up once, asks and leaves. This sets a bp, **lets the guest run again** and
    waits for the moment the condition hits. **Questions about a distribution**, such as "does
    this underflow actually happen", get no answer in any other shape.

    ★ 2026-09-13 — `kd(cmds="bp …; g")` **never works.** `kd` appends `qd`, so it detaches
      the moment it resumes and the bp disappears. It is **complete silence** with no error and no
      output, so it looks like "measured, zero hits". Three ~10-minute rounds vanished that way that day.
      So `kd` now **refuses** a top-level `g` and sends you here.

    ★★ Do not use the returned `verdict` as a verdict as-is — it is one of three:
        hit         found a sample matching the condition (the dump can be cited)
        no-match    saw samples outside the condition and the condition never hit → **only this is a negative**
        UNMEASURED  zero samples even outside the condition → the stimulus did not run that code. Not a negative.
    """
    import kdbp as B
    import kdnet as K
    st = K.status()
    if not st.startswith("ok"):
        return ("KDNET measurement unavailable: %s\n**This is not 'no defect', it is unmeasured.**" % st)
    bp = (a.get("bp") or "").strip()
    dump = _kdq(a.get("dump"))
    if not bp or not dump:
        return "both bp= and dump= are required. dump is the kd command to print when the condition hits."

    act = None
    stim = (a.get("stim_ps1") or "").strip()
    if stim:
        def act():
            _kdscan_stim(stim, int(str(a.get("stim_timeout") or "240"), 0))

    try:
        r = B.scan(bp, dump, cond=(a.get("cond") or None), action=act,
                   ctrl_dump=(_kdq(a.get("ctrl_dump")) or None),
                   ctrl_n=int(str(a.get("ctrl_n") or "6"), 0),
                   wait_s=int(str(a.get("wait_s") or "240"), 0),
                   target=a.get("target"))
    except B.ProbeRefused as e:
        return "kdscan refused: %s" % e
    except Exception as e:
        return "kdscan failed: %s: %s" % (type(e).__name__, e)

    try:
        import ledger as _Lk
        _Lk.measure_record(a.get("target") or _Lk.STATE.get("target") or "?",
                           "trace", "kdscan[%s]: %s" % (r.get("verdict"), bp[:160]),
                           kind="trace", vas=_Lk.measure_vas("%s %s" % (bp, dump)),
                           principal="kd")
    except Exception:
        pass

    v = r.get("verdict")
    head = {"hit": "★ Found a sample matching the condition — cite the dump as-is.",
            "no-match": "Saw samples outside the condition and the condition did not hit. **This is a negative.**",
            "UNMEASURED": "★★ **This is unmeasured. Do not write it as a negative.**"}.get(v, v)
    return _cap(
        "[kdscan] verdict=%s  armed=%s  hit=%s  control samples=%d  trigger=%s  cleanup=%s\n%s\n%s\n"
        "--- condition sample ---\n%s\n--- control samples (outside the condition) ---\n%s\n"
        "★ Check by eye that the control samples carry non-trivial values **in the fields the discriminator tests.** "
        "If they are all trivial values (0 and the like), the target was not in the sample space, and that is unmeasured."
        % (v, r.get("armed"), r.get("hit"), r.get("controls"), r.get("trigger_used"),
           r.get("clear_why") or r.get("cleared"), head, r.get("why") or "",
           r.get("hit_text") or "(none)", r.get("control_text") or "(none)"))



def _kdq(cmds):
    """Escape the quotes in a string that goes **inside** a kd bp command.

    ★ 2026-09-14 — leaving this out killed the `kdscan` I built on its first real use.
      The form is `bp ADDR "…dump…"`, so a `"` inside the dump must be `\"`, but when
      a caller passes `.printf "X=%x\n", …` as-is, kd answers
      `Malformed string in '.reload; x nt'` and **throws away the whole chain.**
      Then no bp is set and no `qd` runs, so **the guest is left halted** (that really happened).
    ★ The same principle as encoding and line endings: **the harness owns the quoting.** Left to the
      analyst's head, sound rounds vanish quietly.
    Anything already escaped as `\"` is left alone (no double escaping).
    """
    t = (cmds or "").strip()
    if not t:
        return t
    out, i = [], 0
    while i < len(t):
        c = t[i]
        if c == "\\" and i + 1 < len(t) and t[i + 1] == '"':
            out.append('\\"'); i += 2; continue
        if c == '"':
            out.append('\\"'); i += 1; continue
        out.append(c); i += 1
    return "".join(out)

def _kdscan_stim(ps1_body, timeout):
    """Deliver the stimulus script to the guest **as ASCII+CRLF** and run it with `-File`.

    ★ The harness owns the encoding, line endings and transport. On 09-13 this was left to the
      analyst's head, and it died silently three times — a UTF-8 BOM, LF, and `-Command` string escaping.
    """
    import config as C
    import vmprobe as V
    body = ps1_body.replace("\r\n", "\n").replace("\n", "\r\n")
    body.encode("ascii")                       # anything non-ASCII raises loudly right here
    host = os.path.join(C.PROBE_DIR, "kdscan_stim.ps1")
    with open(host, "wb") as f:
        f.write(body.encode("ascii"))
    g = C.VM_PROBE_DIR_GUEST
    V._vmrun("createDirectoryInGuest", g, guest=True, timeout=60)
    rc, out = V._vmrun("CopyFileFromHostToGuest", C.PROBE_DIR_WIN + r"\kdscan_stim.ps1",
                       g + r"\kdscan_stim.ps1", guest=True, timeout=120)
    if rc != 0:
        raise RuntimeError("stimulus delivery failed: %s" % str(out)[:160])
    V._vmrun("runProgramInGuest",
             r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
             g + r"\kdscan_stim.ps1", guest=True, timeout=timeout)


def _t_record(a):
    """**Put what is not a verdict into the ledger.** On 09-14 five of them leaked into `reports/unrecordable/`.

    `kind='population'` — set A / set B / **the intersection is counted by the harness** / per-member state.
        The exact shape of what this methodology calls "under-applied", and until now there was no slot to hold it.
        ★ The member default is `unanalysed`, and the rendering **always reports the unanalysed count** —
          a partial census read as a complete one is the most expensive lie there is.
    `kind='posture'`    — a **measured property** with no defect claim (an authorization constant, a transfer method, a flag).
        Preserves `body_read=0`: "measured, but the body was not read" is the content of this record.
    `kind='os_fact'`    — an OS path fact **not bound to the target image.** It goes to a shared file.

    ★ None of the three **can hold a confirmation or a rejection.** Promotion still goes through `verdict()` and takes
      the gates attached there (basis, controls, the debt cap) as they are. Not a back door but **material preservation.**
    """
    import ledger as L
    k = (a.get("kind") or "").strip().lower()

    def _list(v):
        if v is None:
            return None
        if isinstance(v, (list, tuple)):
            return [str(x) for x in v]
        return [x.strip() for x in str(v).replace(",", " ").split() if x.strip()]

    if k == "population":
        nm = (a.get("name") or "").strip()
        if not nm:
            return "name= is required. Name which question this population is the denominator of."
        ms = a.get("member_state")
        if isinstance(ms, str) and ms.strip():
            d = {}
            for tok in ms.replace(",", " ").split():
                if "=" in tok:
                    kk, vv = tok.split("=", 1); d[kk.strip()] = vv.strip()
            ms = d
        r = L.population(nm, query_a=a.get("query_a"), set_a=_list(a.get("set_a")),
                         query_b=a.get("query_b"), set_b=_list(a.get("set_b")),
                         differentiator=a.get("differentiator"), note=a.get("note") or "",
                         member_state=ms if isinstance(ms, dict) else None,
                         target=a.get("target"), invariant=a.get("invariant"))
        bad = r.get("_rejected")
        todo = sum(1 for v in r["members"].values() if v == "unanalysed")
        return _cap(
            "[population record] `%s`\n%s\n%s"
            "\n★ The intersection was **counted by the harness** (%d). It is not a value you declared.\n"
            "★ %d unanalysed remain. Until that reaches 0, do not write that this census is \"closed\".\n"
            "★ To promote a member to a verdict, call `verdict()` separately — this record is not a verdict."
            % (nm, L.population_render(nm),
               ("★ rejected as states outside the vocabulary: %s (allowed: %s)" % (", ".join(bad), "/".join(L.POP_MEMBER_STATES)))
               if bad else "",
               len(r["inter"]), todo))

    if k == "posture":
        if not a.get("subject") or not a.get("prop"):
            return "subject= and prop= are required (which property of what did you measure)."
        r = L.posture(a.get("subject"), a.get("prop"), a.get("value") or "",
                      a.get("derivation") or "", body_read=str(a.get("body_read") or "0") in ("1", "true", "True"),
                      anchors=_list(a.get("anchors")), note=a.get("note") or "",
                      target=a.get("target"))
        return _cap("[property record] %s · %s = %s  (body read=%s)\nsource: %s\n"
                    "★ This is not a verdict. To promote it to a reachability/impact claim go through `verdict()` — "
                    "`body_read=%s` is then read alongside as a limit on the grounds."
                    % (r["subject"], r["prop"], r["value"], r["body_read"], r["derivation"], r["body_read"]))

    if k == "os_fact":
        if not a.get("routine"):
            facts = L.os_fact()
            return _cap("[%d OS path facts]\n%s" % (len(facts), L.osfact_render(n=12)))
        L.os_fact(routine=a.get("routine"), arm=a.get("arm"), validated=a.get("validated"),
                  omitted=a.get("omitted"), anchors=_list(a.get("anchors")),
                  applies_to=a.get("applies_to"), image=a.get("image") or "",
                  build=a.get("build") or "", note=a.get("note") or "")
        return _cap("[OS path fact filed]\n%s\n"
                    "★ This went to a **shared file** — it is visible whichever target you attach. "
                    "Do not re-derive it on the next target." % L.osfact_render(n=6))

    return ("kind= is required: 'population' | 'posture' | 'os_fact'.\n"
            "These three are slots for **what is not a verdict** — verdicts go to `verdict()`.")

def _t_measure(a):
    """The four measurement gates. **Put a result in and a grade comes out** — clean comes out only when every condition holds.

    ★ `measure.py` was built on 2026-08-26 and **was never once connected to the loop.**
      The tool that answers 'did you measure it?' was sitting on the shelf.
    """
    import measure as M
    act = (a.get("action") or "classify").lower()
    # Grounding: with no arguments it grades **the value the harness observed
    #   itself.** Until now `measure` received hex the agent had transcribed — the
    #   harness fired through `ioctl` while the scorer took hearsay.
    #   Supplying arguments is **cross-checked, not forbidden** — a mismatch is
    #   reported.
    _obs = _LAST_PROBE.get("v")
    _mismatch = ""
    # Whether this grade came from **bytes the harness sent** or from **hex the agent
    #   transcribed** decides whether the principal is grounded. That fact is settled
    #   here.
    _from_probe = False
    if act == "classify" and _obs:
        if not a.get("a") and not a.get("b"):
            a = dict(a, a=_obs["a"], b=_obs["b"],
                     status=a.get("status") if a.get("status") is not None else _obs.get("status"),
                     info=a.get("info") if a.get("info") is not None else _obs.get("info"))
            _mismatch = "\n[graded from values the harness observed directly — not hearsay]"
            _from_probe = True
        else:
            _same = all(re.sub(r"\s+", "", str(a.get(_k) or "")).lower()
                        == re.sub(r"\s+", "", str(_obs.get(_k) or "")).lower()
                        for _k in ("a", "b"))
            _from_probe = bool(_same and a.get("a") and a.get("b"))
            for _k in ("a", "b"):
                _typed = re.sub(r"\s+", "", str(a.get(_k) or "")).lower()
                _seen = re.sub(r"\s+", "", str(_obs.get(_k) or "")).lower()
                if _typed and _seen and _typed != _seen:
                    _mismatch += ("\n⚠ the %s you wrote differs from the harness's observed value "
                                  "(observed %d bytes / input %d bytes). **The observed value is canonical.**"
                                  % (_k, len(_seen)//2, len(_typed)//2))
    if act == "kernel_ptrs":
        try:
            buf = bytes.fromhex((a.get("buf") or "").replace(" ", ""))
        except ValueError:
            return "buf must be a hex string."
        hits = M.kernel_ptrs(buf)
        return "%d kernel pointer candidates: %s" % (len(hits), [hex(x) for x in hits][:12])
    if act == "armed":
        # The previous code returned `str(M.armed(...))`, i.e. **the repr of a decorator
        #   object** — a no-op that left nothing in the ledger and looked like success.
        #   `M.armed` is a decorator factory and cannot cross a string boundary. This goes
        #   no further than **recording the self-report.** It does not evaluate it, and it
        #   does not pretend to.
        nm = str(a.get("name") or "").strip()
        pc = str(a.get("precondition") or "").strip()
        wy = str(a.get("why") or "").strip()
        if not nm or not pc:
            return ("armed needs **both** name= and precondition=.\n"
                    "  name=        what you mean to measure (use the same string as classify's target=)\n"
                    "  precondition= the condition that must be true for that guard **to be evaluated**\n"
                    "  why=         **how you made** that condition hold")
        ledger.arm_record(nm, pc, wy)
        return ("arming report recorded: %s\n  precondition: %s\n  how it holds: %s\n"
                "★ This is **a self-report, not a verification** — the harness does not evaluate this precondition"
                " (a string cannot carry a predicate). classify(target='%s') attaches whether this record exists "
                "to its verdict." % (nm, pc, wy or "(not stated)", nm))
    if act == "before_after":
        # A third evidence shape: **a controlled before/after observation.** It is the
        #   shape that actually broke a defect, and because it could not be graded nobody
        #   was pushed to do it (the ledger held zero measurements).
        _bef, _aft = a.get("before"), a.get("after")
        if not _bef or not _aft:
            return ("before_after needs **both** before= and after=.\n"
                    "  before=/after=         values read at **the same observation point** before and after the treatment\n"
                    "  control_before=/_after= values read at the same interval **without** the treatment\n"
                    "★ Without a control the grade comes out as `uncontrolled` — because a value drifting "
                    "by itself cannot be told apart from the treatment changing it.")
        grade, why = M.before_after(_bef, _aft, a.get("control_before"),
                                    a.get("control_after"))
        # **The harness asserts the provenance.** It cross-checks whether the string the
        #   agent wrote really appears in the kd output: present means kd-grounded, absent
        #   means declared. Mixing the two launders hearsay into a grounded result.
        _blob = "\n".join(x.get("output") or "" for x in _LAST_KD.get("v") or [])
        _flat = re.sub(r"\s+", "", _blob).lower()
        def _seen(v):
            v = re.sub(r"\s+", "", str(v or "")).lower()
            return bool(v) and v in _flat
        _grounded = _seen(_bef) and _seen(_aft)
        _tgt = a.get("target", "?")
        ledger.measure_record(_tgt, grade, why, kind="before_after",
                              vas=ledger.measure_vas("%s %s" % (_tgt, a.get("why") or "")),
                              principal=("kd" if _grounded else "declared"))
        _src = ("[source: found **both** the before and after values in the kd output the harness saw — grounded]"
                if _grounded else
                "[source: these are **values you transcribed.** They were not found in the stored kd output — "
                "recorded as `declared`. To ground them, read with `kd(cmds=...)` in the same session and "
                "put in the values from that output verbatim.]")
        _ctl = ("" if (a.get("control_before") and a.get("control_after")) else
                "\n★ **There is no negative control.** Read the same observation point at the same interval in "
                "the untreated arm and put it in control_before=/control_after=. Until then, do not claim "
                "'the treatment changed it' from this delta.")
        return ("before/after observation grade: **%s**\n  %s\n%s%s" % (grade, why, _src, _ctl))
    if act == "classify":
        try:
            A_ = bytes.fromhex((a.get("a") or "").replace(" ", ""))
            B_ = bytes.fromhex((a.get("b") or "").replace(" ", ""))
        except ValueError:
            return "a=/b= must be the hex of the output buffer from two runs with **different fill values.**"
        if not A_ or not B_:
            return ("both a= and b= are required. **A single-fill verdict is forbidden** — if the kernel writes bytes equal "
                    "to that fill value it is misread as 'unwritten' (0xCC really produced that false positive).")
        df = M.DualFill(A_, B_, status=int(str(a.get("status") or 0), 0),
                        info=int(str(a.get("info") or 0), 0))
        kh = M.kernel_ptrs(A_)
        grade, why = M.classify(df, kernel_hits=kh, neither=bool(a.get("neither")))
        _tgt = a.get("target", "?")
        # Bytes the harness sent carry the store's verified principal; hex the agent
        #   transcribed is `declared` — **not verified.** Mixing the two launders hearsay
        #   into a grounded result.
        _pr = (ledger.normalize_principal(_obs.get("principal"),
                                          req=(_obs or {}).get("principal_req"), src="probe")
               if (_from_probe and _obs) else ledger.normalize_principal("declared"))
        ledger.measure_record(_tgt, grade, why, principal=_pr)
        _prline = ("\nprincipal: %s (%s)" % (ledger.principal_grade(_pr), _pr.get("src"))
                   + ("" if _pr.get("verified") else
                      " — **not verified.** This measurement cannot support a claim about 'which principal "
                      "reaches it'. Fire it with ioctl(where='guest', principal='low') and "
                      "the harness reads the token and verifies it."))
        _arm = ledger.armings(_tgt)
        _armline = ("\narming report: present — precondition «%s»" % _arm[-1]["precondition"][:140]) if _arm else (
            "\narming report: **none** — nobody reported that this measurement actually took that path. "
            "If this measurement measures a guard, write `measure(action='armed', name='%s', precondition=…, why=…)` "
            "first." % _tgt)
        return _mismatch + ("grade=%s\n%s\nwritten %d bytes / reported %d / nondeterministic %d / kernel pointers %d%s%s\n%s"
                % (grade, why, len(df.written), df.info, len(df.nondet), len(kh),
                   _prline, _armline,
                   "★ UNMEASURED is not clean — the handler did not even run."
                   if grade == M.UNMEASURED else ""))
    return "action is one of classify | kernel_ptrs | armed."


def _t_images(a):
    """Register/list auxiliary images. **The management window for the cross-image wiring.**

    action='list'  — shows the registered images and their **build identity**
    action='add'   — register with name=, path= (opened read-only)
    """
    act = (a.get("action") or "list").lower()
    if act == "add":
        nm, path = a.get("name"), a.get("path")
        if not nm or not path:
            return "images(action='add') needs name= and path=."
        if not os.path.exists(os.path.expanduser(str(path))):
            return "no file at that path: %s" % path
        try:
            meta = add_image(nm, path)
        except Exception as e:
            return "registration failed: %s: %s" % (type(e).__name__, e)
        ledger.record_image(meta)
        return ("image registered: %s ← %s\n  base=%s ts=%s guid=%s exports=%d\n"
                "★ When citing from this image, tag it as **`%s!0xVA mnem ops`**."
                % (meta["name"], meta["path"], meta["base"], meta["timestamp"],
                   (meta["guid"] or "?")[:16], meta["exports"], meta["name"]))
    L = ["registered images:"]
    pm = _pe()
    if pm is not None:
        L.append("  main  %-42s base=0x%x  (cite untagged)" % (os.path.basename(pm.path), pm.base))
    if not TARGET["_imeta"]:
        L.append("  (no auxiliary images — a claim that bottoms out in an nt! contract gets stuck here.")
        L.append("   start with IMAGES=nt=/mnt/c/Windows/System32/ntoskrnl.exe or use action='add')")
    for m in TARGET["_imeta"].values():
        L.append("  %-5s %-42s base=%s ts=%s guid=%s exports=%d"
                 % (m["name"], os.path.basename(m["path"]), m["base"], m["timestamp"],
                    (m["guid"] or "?")[:16], m["exports"]))
    return "\n".join(L)


def _t_crossref(a):
    """**Crosses the image boundary.** An import name the measured target calls → the body of that function.

    This is the shape that was stuck until now:
      `0x140001bb6 call qword ptr [rip+0x2058b]`  ← what we see (an IAT slot, a name only)
      how that function uses its arguments          ← the answer is in another file
    Give name= and it finds the export in the registered auxiliary images and **disassembles it there.**
    """
    name = (a.get("name") or "").strip()
    if not name:
        return "crossref needs name=<an import/export name>. e.g. name='MmCreateSection'"
    cnt = int(a.get("count") or 60)
    want = str(a.get("image") or "").strip().lower()
    cands = [(k, v) for k, v in TARGET["_images"].items() if not want or k == want]
    if not cands:
        return ("there are no auxiliary images%s. Start with `images(action='add', name='nt', "
                "path='/mnt/c/Windows/System32/ntoskrnl.exe')`."
                % (" (filtered by image=%r)" % want if want else ""))
    hits, fwd = [], []
    for nm, img in cands:
        va = img.export_va(name)
        if va:
            hits.append((nm, img, va))
        elif name in img.exports():
            fwd.append(nm)
    if not hits:
        if fwd:
            return ("`%s` is a **forwarder** in %s — its body is in yet another file. "
                    "That file must be registered to follow it." % (name, ", ".join(fwd)))
        return ("none of the registered images %s has a `%s` export. Check the name, or "
                "register the image containing that function." % (", ".join(k for k, _ in cands), name))
    if len(hits) > 1:
        return ("`%s` is in several images: %s. Pick one with image= — "
                "**which image's contract it is, is part of the claim.**"
                % (name, ", ".join("%s(0x%x)" % (n, v) for n, _, v in hits)))
    nm, img, va = hits[0]
    ins = img.disasm(va, cnt)
    if not ins:
        return "decoding 0x%x failed (%s)" % (va, nm)
    meta = TARGET["_imeta"].get(nm, {})
    ledger.note_disasm("%s!%s" % (nm, name))
    head = ("[%s / image=%s] %s @ 0x%x  (%d insn)\nbuild: guid=%s ts=%s"
            % (os.path.basename(img.path), nm, name, va, len(ins),
               (meta.get("guid") or "?")[:16], meta.get("timestamp", "?")))
    body = "\n".join("0x%x  %-20s %s %s" % (v, b.hex(), m, o) for v, b, m, o in ins)
    return _cap(head + "\n" + body +
                "\n\n★ Tag citations as **`%s!0x…`** (untagged, they are verified against the measured target).\n"
                "★ And if you are going to claim this function's **contract**, type where the argument registers "
                "come from as well — do not assert a contract from the export entry point alone." % nm)


def _t_verdict(a):
    return ledger.verdict(a)


def _t_control(a):
    return ledger.control(a.get("kind", ""), a.get("what", ""), a.get("result", ""))


def _scratch_dir():
    """A per-target scratch directory. **It was the only accuracy risk in parallel runs.**

    ★ 2026-09-02: two agents used to **share `work/` as-is**, and the agent picked the
      filename (the default `m.py`, **the same for both**). When the timing overlapped,
      B overwrote the file A had written and **A ran B's code and took its output as its own measurement**
      — a measurement with the target swapped, leaving no trace in any log.
      That night they happened not to overlap (ahcache `s27_*` 7 files / wcifs `s28_*` 11 files, intersection 0).
      But in R1 **both called themselves 'S26'**, and only one of them happened to use run_python.
      Target-agnostic names like `chk_cs.py` / `r8_defs.py` really were used too.
    => split by target key. The next round on the same target sees the previous round's files as-is (continuity kept).

    ★ **cwd stays `work/`.** What is isolated is the *file location*, not the working directory.
      Some old scratch files open paths relative to cwd (`ahc_bytes2.py`, `an3.py` …), so moving
      cwd too would make that idiom quietly read a different file — the same shape as the failure being fixed.
    """
    b = TARGET.get("binary")
    key = re.sub(r'[^A-Za-z0-9._-]', '_', os.path.basename(str(b)))[:50] if b else "_no_target"
    d = os.path.join(config.WORK_DIR, "scratch", key)
    os.makedirs(d, exist_ok=True)
    return d


def _t_run_python(a):
    code = a.get("code", "")
    fn = a.get("filename") or "m.py"
    # No path escape: `fn` is chosen by the agent, and `../` used to let it write
    # anywhere.
    fn = os.path.basename(str(fn)).strip() or "m.py"
    if not fn.endswith(".py"):
        fn += ".py"
    d = _scratch_dir()
    p = os.path.join(d, fn)
    with open(p, "w", encoding="utf-8") as f:
        f.write(code)
    try:
        r = subprocess.run(["python3", "-u", p], cwd=config.WORK_DIR,
                           capture_output=True, text=True,
                           timeout=int(a.get("timeout") or 180))
        # Return the path: the next round needs to know where to look.
        _rel = os.path.relpath(p, config.WORK_DIR)
        return _cap(f"[{_rel}] exit={r.returncode}\n"
                    f"--- stdout ---\n{r.stdout}\n--- stderr ---\n{r.stderr}")
    except subprocess.TimeoutExpired:
        return "timeout — not even an exit code came back. Do not read it as a negative result."


def _t_double_fetch(a):
    """Double-fetch (TOCTOU) candidates — CFG dataflow. **Results come out only after the controls pass.**

    ★ **Read the limits first.** Lineage starts from `entry rdx = IRP` (the WDM dispatch convention).
      So **fast-io paths are structurally invisible** — `FastIoDeviceControl` has no IRP and the
      user buffer arrives directly as an argument. Zero hits on a fast-io/METHOD_NEITHER target is
      **'out of this tool's range', not 'no double fetch'.** Then follow the argument registers
      by hand (with `disassemble`, from the handler's entry).
    """
    p = _pe()
    if not p:
        return "no binary."
    try:
        import dblfetch as DF
        lim = a.get("limit")
        rs = DF.detect(p, int(lim) if lim else None)
    except Exception as e:
        return ("dblfetch failed: %s: %s\n**A failure is not zero hits.**" % (type(e).__name__, e))
    hot = [r for r in rs if r.get("validated") and r.get("used")]
    trunc = [r for r in rs if r.get("slot") == "(TRUNCATED)"]
    out = ["%d double-fetch candidates (of which %d are **both checked once and used once**)"
           % (len(rs) - len(trunc), len(hot))]
    if trunc:
        out.append("⚠ " + trunc[0].get("note", ""))
    for r in hot[:12]:
        out.append("\n  fn 0x%X  slot %s" % (r["func"], r["slot"]))
        for x in r["reads"][:8]:
            out.append("     0x%X  %-34s %s" % (x["va"], x["insn"],
                                                "check" if x["is_cmp"] else "use"))
    out.append("\n" + DF.control_status())
    out.append("Limits: seeded from entry rdx=IRP — **fast-io is out of range.**")
    return "\n".join(out)


def _t_guards(a):
    """Deterministically scan for places where a guard is **"under-applied"** (`guards.py`).

    ★ Wired 2026-09-04. Until then this module had **zero callers** for 4 weeks —
      the agent had no tool to judge deterministically the doctrine SYSTEM hammers hardest
      ("a defect is not an absence but an under-application"). `test_wiring.py` caught it.

    A candidate generator. **Not a judge.** Anchor each place it reports with disassemble.
    """
    p = _pe()
    if p is None or not TARGET.get("binary"):
        return "no binary."
    import guards as G
    try:
        _pe2, hits, nprobe = G.scan(TARGET["binary"])
    except Exception as e:
        return "guards failed: %s: %s" % (type(e).__name__, e)
    name = os.path.basename(TARGET["binary"])
    body = G.render(name, hits, nprobe)
    n = sum(len(v) for v in hits.values())

    # A negative needs its control attached. Zero Probe calls does not mean "the
    #   guard is under-applied", it means **this axis is absent from this driver.**
    #   Mixing the two makes a zero read as clean.
    if nprobe == 0 and n == 0:
        return (body + "\n\n★ **Zero** Probe* calls. This does not mean 'every guard is in place', it means "
                "**this axis does not apply to this image** (it is not a driver that takes user buffers "
                "through Probe, or validation takes a different form). "
                "Do not write zero as clean — establish this image's real trust boundary first.")
    if n == 0:
        return (body + "\n\n★ Caught %d Probe* calls and **zero asymmetry candidates.** "
                "The scanner ran (the positive control holds) — on this axis you may write clean. "
                "But what this scanner sees is only the four shapes probe-skip / KernelMode / METHOD_NEITHER-no-probe. "
                "Any other shape of 'under-applied' is still manual." % nprobe)
    return (body + "\n\n★ These are all **candidates.** Confirm each place with disassemble and "
            "ask whether a guard dominates it with `sink_gates`. Appearing here is not grounds in itself.")


TOOLS = {
    "binary_info": _t_binary_info, "surface": _t_surface,
    "decompile": _t_decompile, "disassemble": _t_disassemble,
    "sink_gates": _t_sink_gates, "measure": _t_measure, "ioctl": _t_ioctl,
    "find_funcs": _t_find_funcs, "func_at": _t_func_at,
    "callers": _t_callers, "callees": _t_callees, "callpath": _t_callpath,
    "census": _t_census, "corpus_grep": _t_grep,
    "dispatch_table": _t_dispatch_table, "anchor": _t_anchor,
    "find_bytes": _t_find_bytes, "note": _t_note, "priorart": _t_priorart, "import_xref": _t_import_xref, "authz_reach": _t_authz_reach,
    "verdict": _t_verdict, "control": _t_control, "run_python": _t_run_python,
    "images": _t_images, "crossref": _t_crossref,
    "double_fetch": _t_double_fetch, "guards": _t_guards,
    "kd": _t_kd, "kdscan": _t_kdscan, "record": _t_record,
}

READONLY = ("binary_info", "decompile", "disassemble", "sink_gates", "find_funcs", "func_at",
            "callers", "callees", "callpath", "census", "corpus_grep",
            "dispatch_table", "anchor", "find_bytes", "import_xref", "authz_reach",
            "double_fetch", "images", "crossref", "guards")


# ── the wind-down window ─────────────────────────────────────────────────
# A case timeout is **SIGKILL** (`subprocess.run(timeout=...)`), so `finish()`
#   never runs and **everything produced at exit time is lost.** Measured over one
#   overnight run: 8 of 11 rounds timed out, all 8 recorded
#   `total_cost_usd=None`, and the cleanup that only runs at exit never ran once —
#   leaving 20 broken rejections sitting in the graveyard.
#   => tell **the agent directly** before the hard kill. A tool result is always
#     read, which makes this the only reliable channel (the prompt is delivered
#     once at the start of a round, far too early).
#   Say it loudly once and count in one line afterwards — a repeated paragraph
#   stops being read.
_WD_FIRED = [False]


def _winddown(now=None):
    """The text to attach once the time left has entered the wind-down window. Otherwise ''."""
    ts = os.environ.get("CASE_DEADLINE_TS")
    if not ts:
        return ""                      # with no deadline known, say nothing
    try:
        left = float(ts) - (now if now is not None else time.time())
    except ValueError:
        return ""
    cap = getattr(config, "WINDDOWN_SEC", 300)
    if left > cap:
        return ""
    mins = max(0, int(left // 60))
    if _WD_FIRED[0]:
        return "\n\n[wind-down window · ~%d min left]" % mins
    _WD_FIRED[0] = True
    return (
        "\n\n" + "=" * 66 +
        "\n★★ **The wind-down window has started — in ~%d min this round dies without warning (SIGKILL).**\n"
        "`finish()` will not run then, and **everything not in the ledger now is lost.** From here on, do not\n"
        "start new analysis — **file what you have.** In order:\n"
        "  1. Submit what stands as verdicts. If incomplete, submit them **saying they are incomplete**\n"
        "     (`verdict(action='reject'|'confirm', …)`; if a population could not be closed,\n"
        "      `action='blocked', next='<the next single step + anchor>'`).\n"
        "  2. `verdict(action='reaudit')` — clear any rejections the interrogator broke that remain in the graveyard.\n"
        "     **This is exactly the output that has been lost on every timeout.**\n"
        "  3. Move track stages **only when there are grounds.** Do not raise them because the deadline is near —\n"
        "     an inflated stage makes the next round skip two rungs.\n"
        "  4. One handoff note (`note`) — **the single step** the next round is to pick up, plus its anchor.\n"
        % mins + "=" * 66)


def execute_tool(name, ti):
    fn = TOOLS.get(name)
    if not fn:
        out = f"unknown tool {name}"
    else:
        try:
            out = fn(ti or {})
        except Exception as e:
            out = f"{name} exception: {type(e).__name__}: {e}"
    # The wind-down banner is attached on **every return path.** Miss a single early
    #   return and that call goes by without knowing the deadline — a regression
    #   caught exactly that, on the unknown-tool path.
    try:
        return (out or "") + _winddown()
    except Exception:
        return out                     # the wind-down banner must never kill the tool
