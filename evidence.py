# evidence.py — machine-verify a cited anchor against the binary.
#
# One of Naptime's principles is "perfect verification": structure the task so
# the answer can be checked automatically and with certainty. On a source target
# a sanitizer plays that role. **Static binary adjudication has an equivalent:
# is the instruction really at the address you cited?**
#
# Until this file existed, `evidence` was free text. Whatever the model wrote,
# the gate only asked "is it empty?". But every piece of evidence in this domain
# has the shape `0xADDR  mnem ops`, and that shape is **re-derivable**:
#
#   - address outside the image / outside code  -> UNMAPPED / NONCODE
#   - mnemonic differs                          -> MISMATCH (a hallucination, or
#                                                  **an anchor from another build**)
#   - mnemonic and constants match              -> VERIFIED
#
# If it is a MISMATCH here but matches in the older build, that is precisely the
# "re-derive every anchor when the version changes" rule being broken — so the
# diagnosis is returned along with the failure.
import re

import pe as PE

# 0x140099e53  cmp dword [rbx+0x2d4], 0xfffffff   ; comment
# 0x140099e53: cmp     [rbx+2D4h], 0FFFFFFFh
#
# Image tag: a citation can name **which file the address belongs to**, as in
#   `nt!0x14098f670 mov ...`
# With no tag, the citation is verified against the measured target (main).
# The tag is optional but there is **no guessing fallback** — "if it fails
# against main, look in the other images too" manufactures accidental passes.
# The tag IS the declaration of what is being verified against.
#
# Markdown separators are allowed. This was a measured defect: the harness
# itself speaks in `**bold**` and backticks, yet the parser did not read those
# forms as citations. The result was that a well-evidenced rejection was scored
# as "ZERO citations" — one row was blocked **four times in a row** by that rule
# alone. The forms that were failing:
#     `0x…` mov  /  **0x…** mov  /  - **0x…** cmp  /  | 0x… | cmp |
# The requirement did not loosen (the address + mnemonic still have to verify
# against this build; `check()` still compares the anchor). What stopped is
# **throwing away valid citations over formatting.**
#
# Prose must still be rejected: reading the `the` of `**0x…** — the guard` as a
# mnemonic produces "anchor mismatch", which is **a different lie**. So dashes
# and em-dashes are not separators, and mnemonics stay **lower-case only** (the
# convention of disassembler output).
#
# At least ONE separator is mandatory. Allowing zero splits the address itself —
# `**0x140038c5c** — the guard` parsed as address `0x140038` + mnemonic `c5c`
# (measured). The old regex's `\s+` was the thing preventing that. Widen the
# tolerance, **keep the floor.**
_SEP = r'[*`_|,:\-\s]+'              # whitespace + markdown emphasis/table/list marks (1+)
CITE = re.compile(
    r'(?:^|[\s`(\[*_|])(?:([A-Za-z_][A-Za-z0-9_]{0,15})!)?(0x[0-9a-fA-F]{6,16})'
    + _SEP +
    # `|` belongs in the operand terminator set: **pipe-joined citations were
    # parsed as one.** Measured: a run scored 10 rejection attempts as 0 rows
    # recorded, and the analyst's own transcript named the cause exactly —
    # *"the verifier expects one `0xVA mnem ops` per line, not a pipe-joined
    # string"*. `|` had already been added to the leading separator class but
    # **the trailing operand capture did not stop at `|`**, so the first
    # citation swallowed every citation after it. The earlier fix had only been
    # applied to half the pattern.
    # `|` cannot appear in an x86 operand, so terminating on it loses nothing.
    # A comma **must not** be a terminator — `cmp eax, 4` is legal.
    #
    # Parentheses are terminators too: **an x86 Intel-syntax operand never
    # contains parentheses** (addressing uses `[]`), so once `(` or `)` appears
    # the rest is always prose. Measured on one night run: 6 of 18 denials were
    # "anchors do not verify", and the instructions themselves were exactly
    # right —
    #   x 0x140028e54 cited=`mov dword ptr [rsp + 0x20], 4) with a kernel han`
    #                 actual=`mov dword ptr [rsp + 0x20], 4`  [CONST_MISMATCH]
    # The analyst continued an explanation on the same line and a number in that
    # prose broke the constant comparison. Again: stop discarding valid
    # citations over formatting; the requirement is unchanged.
    r'([a-z][a-z0-9]{1,9})\b([^\n;/|()]*)', re.M)

_SIZEWORD = re.compile(r'\b(byte|word|dword|qword|xmmword|ymmword|tbyte|short|near|far|ptr|offset)\b')
_IDAHEX   = re.compile(r'\b([0-9][0-9A-Fa-f]*)h\b')
_NUM      = re.compile(r'0x([0-9a-fA-F]+)|\b(\d+)\b')


def _norm_ops(s):
    s = s.strip().lower()
    s = _IDAHEX.sub(lambda m: "0x" + m.group(1).lstrip("0").lower() or "0x0", s)
    s = _SIZEWORD.sub("", s)
    return re.sub(r'[\s,+]+', '', s)


def _consts(s):
    """Pull only the constants (displacements, immediates) out of the operands.
    Those numbers are what the claim actually leans on."""
    s = _IDAHEX.sub(lambda m: "0x" + m.group(1), s.lower())
    out = set()
    for m in _NUM.finditer(s):
        v = int(m.group(1), 16) if m.group(1) else int(m.group(2))
        if v > 3:                      # drop register-index / scale noise
            out.add(v)
    return out


def parse(text):
    """Extract (va, mnem, ops, raw) citations from evidence text."""
    out, seen = [], set()
    for m in CITE.finditer(text or ""):
        img = (m.group(1) or "").lower()
        va = int(m.group(2), 16)
        mnem = m.group(3).lower()
        ops = m.group(4).strip()
        if (img, va, mnem) in seen:
            continue
        seen.add((img, va, mnem))
        out.append({"va": va, "mnem": mnem, "ops": ops, "img": img,
                    "raw": m.group(0).strip()[:120]})
    return out


# Pairs where a decompiler / IDA spells the same thing differently. Killing a
# citation on a mnemonic mismatch for one of these would be unfair.
_ALIAS = {("jz", "je"), ("jnz", "jne"), ("jb", "jc"), ("jnb", "jae"), ("jnae", "jb"),
          ("setz", "sete"), ("setnz", "setne"), ("cmovz", "cmove"),
          ("retn", "ret"), ("repe", "rep"), ("jnbe", "ja"), ("jna", "jbe"),
          ("jnl", "jge"), ("jnge", "jl"), ("jng", "jle"), ("jnle", "jg")}


def _mnem_ok(a, b):
    a, b = a.lower(), b.lower()
    if a == b:
        return True
    if (a, b) in _ALIAS or (b, a) in _ALIAS:
        return True
    return a.rstrip("q").startswith(b[:4]) and len(b) >= 4 and a[:3] == b[:3]


def _in_image_range(img, va):
    """Is `va` inside this image's VA space? None when it cannot be determined."""
    try:
        base = int(img.base)
    except Exception:
        return None
    try:
        size = max(s["va"] + max(s.get("vsize") or 0, s.get("rsize") or 0)
                   for s in (img.secs or [])) or 0
    except Exception:
        size = 0
    if not size:
        return None
    return base <= int(va) < base + size + 0x1000


_MNEMS = [None]


def mnemonics():
    """The full set of x86 mnemonics. **capstone is the authority** — a
    hand-written list drifts.

    Used for one thing: deciding whether an out-of-image citation is **a
    constant or an anchor**.
      `0x220003 inlen=0x188, …`  -> mnem='inlen' -> not a mnemonic -> constant
      `0xdeadbeef00 mov rax, rbx` -> mnem='mov'  -> a mnemonic -> anchor
                                                    (hallucinated / cross-image)
    """
    if _MNEMS[0] is None:
        try:
            import capstone
            from capstone import x86 as _X
            _md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            got = {_md.insn_name(getattr(_X, n)) for n in dir(_X) if n.startswith("X86_INS_")}
            got.discard(None)
            _MNEMS[0] = got
        except Exception:
            # If the dictionary cannot be built, **do not claim nothing is an
            # anchor.** An empty set folds every out-of-range citation into
            # "constant", which is quieter than having no check at all. So leave
            # None here and let the caller count it conservatively as
            # "cannot decide".
            _MNEMS[0] = None
            return None
    return _MNEMS[0]


def check_one(img, c, alt=None):
    va = c["va"]
    sec = img.sec_of(va)
    if sec is None:
        # **A number that was never an image VA and a wrong VA are different
        # things.** Measured: a confirmation attempt died on
        # `anchor check: 7/8 verified, 1 failed`, and the 1 was `0x220003` — an
        # **IOCTL control code**. The analyst had written the request parameters
        # into the evidence (`0x220003 inlen=0x188, outlen=0, …`) and the parser
        # read a 6-digit hex number as an image VA, counting it as an UNMAPPED
        # failure. The other 7 all verified. **A harness false positive killed a
        # confirmation.**
        # The discriminator is the **image VA range**. Typos and stale-build
        # anchors are almost always **inside** the range (builds share a base),
        # so the gate keeps its teeth. Out-of-range values are not dropped
        # silently: they stay **visible** as `NOTANCHOR`.
        #
        # That first fix then **inverted the error**: folding everything
        # out-of-range into "constant" made **hallucinated and cross-image
        # anchors invisible to the gate** (`0x<out of range> mov rax, rbx`).
        # Measured: 5 real anchors + 1 out-of-range -> `failed=0, cites=5`, no
        # trace left in the counts, so the gate never fired.
        # The answer is to **separate** the two cases, not to fold either way,
        # and the discriminator is the mnemonic: a constant is not followed by an
        # instruction (`inlen=…` is not an x86 mnemonic).
        if _in_image_range(img, va) is False:
            _mn = mnemonics()
            if _mn is not None and c.get("mnem", "").lower() not in _mn:
                return dict(c, status="NOTANCHOR", actual="",
                            note=("Outside this image's VA range, and the following token %r is "
                                  "not an x86 mnemonic — read as a constant rather than an anchor "
                                  "(control code, status value, size, ...). Excluded from "
                                  "verification." % c.get("mnem", "")))
            return dict(c, status="OUT_OF_IMAGE", actual="",
                        note=("Outside this image's VA range, yet an x86 instruction (%s) was "
                              "cited — this is not an anchor in this image. Three ways forward: "
                              "(1) if it is an address in another file, register it with "
                              "`images(action='add')` and cite it as `module!0x…`; "
                              "(2) give a VA re-derived in THIS image (addresses die across "
                              "builds); (3) if it really is a constant, write it without a "
                              "mnemonic — then it drops out of verification."
                              % (c.get("mnem", "") + " " + str(c.get("ops", ""))[:32]).strip()))
        return dict(c, status="UNMAPPED", actual="", note="VA is not mapped in the image")
    if not (sec["chars"] & 0x20000000):
        return dict(c, status="NONCODE", actual="",
                    note=f"{sec['name']} is not an executable section")
    ins = img.disasm(va, 1)
    if not ins:
        return dict(c, status="UNDECODABLE", actual="", note="does not decode")
    _a, b, mn, op = ins[0]
    actual = f"{mn} {op}".strip()
    if not _mnem_ok(mn, c["mnem"]):
        note = f"mnemonic mismatch: cited {c['mnem']!r} vs actual {mn!r}"
        if alt is not None:
            ai = alt.disasm(va, 1)
            if ai and _mnem_ok(ai[0][2], c["mnem"]):
                note += ("  ** it DOES match in the reference build -> **this anchor is from "
                         "another build.** Re-derive the VA in this build with relocate() and "
                         "restate the claim.")
        return dict(c, status="MISMATCH", actual=actual, bytes=b.hex(), note=note)
    want, got = _consts(c["ops"]), _consts(op)
    if c["ops"] and want and not want <= got:
        return dict(c, status="CONST_MISMATCH", actual=actual, bytes=b.hex(),
                    note=f"constant mismatch: cited {sorted(hex(v) for v in want)} "
                         f"vs actual {sorted(hex(v) for v in got)}")
    exact = _norm_ops(c["ops"]) == _norm_ops(op) if c["ops"] else True
    return dict(c, status="VERIFIED" if exact else "VERIFIED_CONST",
                actual=actual, bytes=b.hex(), note="" if exact else "notation differs only")


MAIN_TAGS = ("", "main", "target", "self")


def check(img, text, alt=None, images=None):
    """(results, summary_dict). img = the measured build, alt = the reference
    (older) build.

    Pass `images` to verify **tagged citations** (`nt!0x…`) against that image.
    If a citation is tagged but the image is not registered, it does **not**
    pass (UNKNOWN_IMAGE) — accepting an address in an unknown file as evidence
    is the most expensive failure available here.
    """
    images = images or {}
    cites = parse(text)
    res = []
    for c in cites:
        tag = c.get("img") or ""
        if tag in MAIN_TAGS:
            res.append(check_one(img, c, alt))
            continue
        tgt = images.get(tag)
        if tgt is None:
            res.append(dict(c, status="UNKNOWN_IMAGE", actual="",
                            note=("Image %r is not registered — this citation cannot be "
                                  "verified. Register it with images(action='add') and cite "
                                  "again." % tag)))
        else:
            res.append(check_one(tgt, c, None))
    n = {}
    for r in res:
        n[r["status"]] = n.get(r["status"], 0) + 1
    ok = n.get("VERIFIED", 0) + n.get("VERIFIED_CONST", 0)
    # `NOTANCHOR` is not a failure — it was never an anchor. **Take it out of
    # the denominator too.** Leaving it in reads as "7/8 verified", which a
    # human reads as one anchor being wrong.
    skipped = n.get("NOTANCHOR", 0)
    bad = sum(n.get(k, 0) for k in
              ("MISMATCH", "CONST_MISMATCH", "UNMAPPED", "NONCODE", "UNDECODABLE",
               "UNKNOWN_IMAGE", "OUT_OF_IMAGE"))
    return res, {"cites": len(res) - skipped, "verified": ok, "failed": bad,
                 "skipped": skipped, "by": n}


def render(res, summ):
    if not res:
        return ("0 anchor citations. The evidence contains nothing of the form "
                "`0xADDR  mnem ops` — every piece of evidence in this domain is "
                "re-derivable, and if you did not write it that way it cannot be verified.")
    L = [f"anchor check: {summ['verified']}/{summ['cites']} verified, {summ['failed']} failed"
         + (f" ({summ['skipped']} not anchors, excluded)" if summ.get("skipped") else "")]
    for r in res:
        # `NOTANCHOR` is not a failure — printing it as x reads as a bad anchor
        mark = {"VERIFIED": "OK", "VERIFIED_CONST": "OK~", "NOTANCHOR": "-"}.get(r["status"], "x")
        tag = (r.get("img") or "")
        tag = (tag + "!") if tag and tag not in MAIN_TAGS else ""
        L.append(f"  {mark} {tag}0x{r['va']:x}  cited={r['mnem']} {r['ops'][:44]}")
        if r["status"] not in ("VERIFIED",):
            L.append(f"      actual={r['actual'][:60]}   [{r['status']}] {r['note']}")
    return "\n".join(L)
