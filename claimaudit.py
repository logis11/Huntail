#!/usr/bin/env python3
"""claimaudit.py — **machine-audit the anchors, offsets and constants inside a claim.**

Why it exists. A 60-turn run was re-verified end to end by hand, and three
defects came out of it:

  1) **The anchors were not verified.** The agent made claims with a VA attached,
     like "there is a `[0x70, cbBlock-8]` check at 0x140069f1b". Disassembling
     eight of them by hand, all eight were right — but the ledger only looked at
     whether the anchors field **existed**, never at its content. Being right was
     luck.

  2) **An offset query silently returns zero.** Grepping a decompilation corpus
     for `this+0x70` as `+ 112` finds **nothing**, because Hex-Rays writes it as
     `*((_QWORD *)this + 14)`. That trap produced a **false negative** ("zero
     accesses to the third table"), and only re-asking by QWORD index found the
     real access. => an offset query has to ask for **every width's spelling at
     once.** And without a **class scope**, unrelated classes' `this+14` floods
     in (27 of them, measured).

  3) **A cited constant does not exist.** The agent asserted a magic value as
     fact; it occurs **zero times** in the whole corpus (it had been filled in
     from public documentation). Two neighbouring values do exist. => every
     constant appearing in a claim has to be checked exhaustively.

None of the three is something discipline fixes — all three were breached in a
single day.
"""

import re

from verifier_guard import guarded

# ── 1) anchor verification ──────────────────────────────────────────────────


def disasm_at(pe_path, va, before=0, after=64):
    """Return a VA window as a list of (addr, mnemonic, op_str)."""
    import capstone
    import pefile
    pe = pefile.PE(pe_path)
    base = pe.OPTIONAL_HEADER.ImageBase
    data = b""
    start = va - before
    for s in pe.sections:
        lo = base + s.VirtualAddress
        hi = lo + max(s.Misc_VirtualSize, len(s.get_data()))
        if lo <= start < hi:
            d = s.get_data()
            data = d[start - lo: start - lo + before + after]
            break
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    return [(i.address, i.mnemonic, i.op_str) for i in md.disasm(data, start)]


def check_anchor(pe_path, va, expect, window=64):
    """Is there an instruction matching `expect` (a regex) within `window` bytes
    of `va`?

    Returns (ok, the matching line or the head of the actual disassembly).
    **A claim has to pass this before it can be promoted to a confirmation.**
    """
    ins = disasm_at(pe_path, va, 0, window)
    rx = re.compile(expect, re.I)
    for a, m, o in ins:
        if rx.search(f"{m} {o}".strip()):
            return True, f"{a:016x}  {m} {o}"
    head = "; ".join(f"{m} {o}" for _, m, o in ins[:6])
    return False, f"no match — actual: {head}"


# ── 2) offset query (spelling expansion + class scope) ──────────────────────


def offset_forms(byte_off):
    """Expand one byte offset into **every spelling** Hex-Rays might use.

    Hex-Rays divides by the cast width and writes an element index:
      +0x70 -> `+ 112` (BYTE) / `+ 56` (WORD) / `+ 28` (DWORD) / `+ 14` (QWORD)
    Ask for only one of them and you silently get zero hits.
    """
    forms = []
    for width, cast in ((1, "_BYTE"), (2, "_WORD"), (4, "_DWORD"), (8, "_QWORD")):
        if byte_off % width == 0:
            forms.append((byte_off // width, cast))
    return forms


def parse_corpus(path):
    src = open(path, encoding="utf-8", errors="replace").read()
    return re.findall(
        r"/\* ==+ (\S+) @ (0x[0-9a-f]+) ==+ \*/\n(.*?)(?=\n/\* ==+ |\Z)", src, re.S)


def offset_query(blocks, byte_off, class_prefix=None, var="this", writers_only=False):
    """Find every function inside `<class>` that touches `var+byte_off`, in all
    spellings.

    Called without `class_prefix`, unrelated classes mix in — 27 of them, in the
    run this was written for.
    """
    pats = []
    for idx, cast in offset_forms(byte_off):
        w = r"\s*=(?!=)" if writers_only else ""
        pats.append(re.compile(
            r"\(\s*%s\s*\*\s*\)\s*%s\s*\+\s*%d\s*\)%s" % (cast, var, idx, w)))
        pats.append(re.compile(r"%s\s*\+\s*%d\b" % (var, idx)) if cast == "_BYTE" else None)
    pats = [p for p in pats if p]
    out = []
    for n, va, b in blocks:
        if class_prefix and class_prefix not in n:
            continue
        hits = [m.group(0) for p in pats for m in p.finditer(b)]
        if hits:
            out.append((n, va, sorted(set(hits))))
    return out


# ── 3) cited-constant check ─────────────────────────────────────────────────


def _image_range(pe_path):
    """(lowest VA, highest VA) of the mapped image, or None."""
    try:
        from pe import PE
        P = PE(pe_path)
    except Exception:
        return None
    if not P.secs:
        return None
    lo = P.base + min(s["va"] for s in P.secs)
    hi = P.base + max(s["va"] + max(s["vsize"], s["rsize"]) for s in P.secs)
    return (lo, hi)


def constants_cited(claim_text, corpus_path=None, pe_path=None, minbits=16,
                    skip_image_vas=True):
    """Check exhaustively whether the hex constants in a claim **actually occur**
    in the corpus / the binary.

    Returns [(constant, corpus_count, binary_count)] — 0/0 means that claim is
    INFERRED, not confirmed.

    `skip_image_vas` (default on, a deliberate change from upstream): a hex value
    that lands inside this image's mapped range is **an address, not a
    constant.** Its little-endian bytes are naturally absent from the file, so
    every anchor VA cited in the evidence would otherwise be reported as a
    phantom constant. Upstream never saw this because its only consumer's filter
    could not fire; once that filter was fixed, the anchor VAs were the first
    thing it flagged.
    """
    consts = {int(h, 16) for h in re.findall(r"0x([0-9A-Fa-f]{4,16})", claim_text)}
    consts = {c for c in consts if c.bit_length() >= minbits}
    if skip_image_vas and pe_path:
        rng = _image_range(pe_path)
        if rng:
            consts = {c for c in consts if not (rng[0] <= c < rng[1])}
    src = open(corpus_path, encoding="utf-8", errors="replace").read() if corpus_path else ""
    raw = open(pe_path, "rb").read() if pe_path else b""
    rows = []
    for c in sorted(consts):
        forms = {str(c), hex(c), hex(c).upper().replace("0X", "0x"), "%X" % c, "%x" % c}
        # Hex-Rays writes a value with the top bit set as a **signed integer**
        #   (0xC1FDF00D becomes `-1040322547`). Ask only for the unsigned
        #   spelling and the corpus count comes back zero, which yields the
        #   **false verdict** "that constant does not exist, so the claim is
        #   inferred". That trap nearly demoted a confirmed defect to a guess.
        for w in (4, 8):
            if c.bit_length() <= w * 8 and c >> (w * 8 - 1):
                forms.add(str(c - (1 << (w * 8))))
        nc = sum(src.count(f) for f in forms) if src else -1
        nb = 0
        if raw:
            for w in (4, 8):
                if c.bit_length() <= w * 8:
                    nb += raw.count(c.to_bytes(w, "little"))
        rows.append((c, nc, nb))
    return rows


# ── Controls ────────────────────────────────────────────────────────────────

_CTL = {
    # The derived prologue anchor must be found
    "anchor-hit":  True,
    # A pattern that is not there must fail (negative control)
    "anchor-miss": False,
    # +0x70 must expand to QWORD index 14
    "offset-forms": True,
    # Without the signed spelling the constant auditor returns a false "inferred"
    "signed-const": True,
}


# ── The control anchors are **derived from the target PE** ──────────────────
# They used to be a hard-coded VA from one specific driver. That VA does not
#   exist in any other binary — a smaller image does not even reach it.
#   => `audit()` was closed by ControlFailed **on every target but that one.**
#   Failure closed rather than opened, so nothing false got through, but the tool
#   was unusable.
#
# How this avoids circularity: letting the disassembler produce the expectation
#   is not a control (it fits the tool to its own output). Instead the
#   **byte -> mnemonic mapping comes from x86 encoding knowledge** (a fact outside
#   the tool) and the **instruction boundary comes from `.pdata`** (PE structure,
#   not the disassembler). Both are independent of the thing under test.

# Hand-checked MSVC x64 prologue encodings. Left is the file bytes; right is what
# those bytes mean.
_PROLOGUE_ORACLE = [
    (b"\x48\x89\x5c\x24", r"mov\s+qword ptr \[rsp \+ 0x[0-9a-f]+\],\s*rbx"),
    (b"\x48\x8b\xc4",     r"mov\s+rax,\s*rsp"),
    (b"\x48\x83\xec",     r"sub\s+rsp,"),
    (b"\x40\x53",         r"push\s+rbx"),
    (b"\x48\x89\x4c\x24", r"mov\s+qword ptr \[rsp \+ 0x[0-9a-f]+\],\s*rcx"),
]

# A synthetic vector for the signed-spelling trap. Any value with the top bit of
# a DWORD set will do — the lesson is the spelling, not the value, so pinning a
# real target's magic number here would make the control target material.
_SIGNED_PROBE_CONST = 0xC0DEF00D


def _control_anchor(pe_path):
    """Derive (va, expected_regex) from the target PE. None if there is none."""
    from pe import PE
    try:
        P = PE(pe_path)
        _fns = P.merged_functions()[:400]
    except Exception:
        # Not a PE, or unreadable => **no anchor.** The control closes there.
        return None
    for beg, _end in _fns:
        try:
            head = P.read(beg, 8)
        except Exception:
            continue
        if not head:
            continue
        for sig, expect in _PROLOGUE_ORACLE:
            if head.startswith(sig):
                return beg, expect
    return None


def _probe(label, _pe=None, _corpus=None):
    pe = _pe or _CFG.get("pe")
    if label in ("anchor-hit", "anchor-miss"):
        ca = _control_anchor(pe)
        if ca is None:
            # With no anchor, **do not pass.** Passing without a control is the
            # thing this tool exists to prevent.
            return (label != "anchor-hit")
        va, expect = ca
        if label == "anchor-hit":
            return check_anchor(pe, va, expect, 16)[0]
        return check_anchor(pe, va, r"vzeroupper", 16)[0]
    if label == "offset-forms":
        return (14, "_QWORD") in offset_forms(0x70)
    if label == "signed-const":
        # Synthetic and self-contained: write a corpus that contains ONLY the
        # signed spelling, then require the auditor to find it. Upstream pinned
        # this to a real target's magic value and to whatever corpus happened to
        # be configured, so the control silently did not run when there was no
        # corpus.
        import os
        import tempfile
        c = _SIGNED_PROBE_CONST
        signed = str(c - (1 << 32))
        d = tempfile.mkdtemp(prefix="claimaudit_ctl_")
        p = os.path.join(d, "corpus.c")
        with open(p, "w", encoding="utf-8") as f:
            f.write("if (magic == %s) { return 1; }\n" % signed)
        r = {k: nc for k, nc, _ in constants_cited("0x%X" % c, p, None)}
        return r.get(c, 0) > 0
    raise KeyError(label)


_CFG = {}


def configure(pe_path, corpus_path=None):
    _CFG["pe"] = pe_path
    _CFG["corpus"] = corpus_path


@guarded("claimaudit", _CTL, probe=_probe)
def audit(claims, corpus_path=None, pe_path=None):
    """claims: [{'id','va','expect','claim'}] -> an audited table."""
    pe = pe_path or _CFG.get("pe")
    corpus = corpus_path or _CFG.get("corpus")
    rows = []
    for c in claims:
        ok, ev = (check_anchor(pe, c["va"], c["expect"]) if c.get("va")
                  else (None, "no anchor"))
        # Zero hits in the corpus (the decompiled code) means **no function uses
        # that constant as an immediate** — even if the bytes happen to appear in
        # the image by alignment coincidence, that is no basis for a claim about
        # code behaviour. `nb` is kept for context only. The earlier filter
        # `nc == 0 and nb == 0` was defeated by a coincidental nb=1.
        bad = [(hex(k), nc, nb) for k, nc, nb
               in constants_cited(c.get("claim", ""), corpus, pe) if nc == 0]
        rows.append({"id": c["id"], "anchor_ok": ok, "evidence": ev, "phantom_consts": bad})
    return rows
