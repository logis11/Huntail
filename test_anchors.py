#!/usr/bin/env python3
# test_anchors.py — the anchor gate. **Does a citation parse, and does it verify
# against a real image?**
#
# Two things are being protected here, and they pull in opposite directions.
#
# A. **Do not throw away valid citations over formatting.** The harness itself
#    speaks in `**bold**`, backticks, table cells and bullets, and the parser used
#    to be blind to all of them. One well-evidenced rejection was blocked **four
#    times in a row** for "ZERO `0xADDR mnem ops` citations" while the citations
#    were right there in markdown.
#
# B. **Do not read prose as a citation.** The first attempt at (A) allowed zero
#    separators, and `**0x140038c5c** — the guard` parsed as address `0x140038`
#    plus mnemonic `c5c`. The old regex's `\s+` was the only thing preventing
#    that. Widen the tolerance, keep the floor: **at least one separator.**
#
# And the part a parser test cannot reach: `check()` against **an actual image.**
# The image is built by `mkpe.py`, so every expected answer is known by
# construction — no target binary is required and the test never degrades into a
# skip.
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
        print("  FAIL  %s  %s" % (name, str(extra)[:260]))


def main():
    import evidence as EV
    import mkpe
    import pe as PE

    VA = 0x140038C5C

    def one(t):
        r = EV.parse(t)
        return (len(r), r[0]["va"] if r else None, r[0]["mnem"] if r else None)

    # ── A. markdown forms read as citations ───────────────────────────
    for lbl, t, mn in [
        ("backticked address", "`0x140038c5c` mov eax, 1", "mov"),
        ("bold",               "**0x140038c5c** mov eax, 1", "mov"),
        ("bullet + bold",      "- **0x140038c5c** cmp eax, 3", "cmp"),
        ("table cell",         "| 0x140038c5c | cmp | eax, 3 |", "cmp"),
        ("comma",              "0x140038c5c, cmp eax, 3", "cmp"),
        ("underscore",         "_0x140038c5c_ je 0x140038d00", "je"),
    ]:
        n, va, m = one(t)
        ck("A: %s parses as a citation" % lbl, n == 1 and va == VA and m == mn,
           (n, hex(va or 0), m))

    # ── B. the forms that already worked still work, unchanged ────────
    for lbl, t, mn in [
        ("plain",       "0x140038c5c mov eax, dword ptr [rbx+0x10]", "mov"),
        ("colon",       "0x140038c5c: mov eax, 1", "mov"),
        ("all in code", "`0x140038c5c mov eax, 1`", "mov"),
        ("bullet",      "- 0x140038c5c mov eax, 1", "mov"),
        ("IDA syntax",  "0x140038c5c: cmp     [rbx+2D4h], 0FFFFFFFh", "cmp"),
        ("mid-sentence", "the guard at 0x140038c5c je 0x140038d00 dominates", "je"),
        ("parenthesised", "(0x140038c5c je 0x140038d00)", "je"),
    ]:
        n, va, m = one(t)
        ck("B: %s unchanged" % lbl, n >= 1 and va == VA and m == mn, (n, hex(va or 0), m))

    # ── C. the address is never split — one separator is mandatory ────
    ck("C1: no separator is not a citation (the address must not split)",
       one("**0x140038c5c**")[0] == 0, one("**0x140038c5c**"))
    ck("C2: prose after an em-dash is not a citation",
       one("**0x140038c5c** — the guard dominates")[0] == 0,
       one("**0x140038c5c** — the guard dominates"))
    ck("C3: the address is never truncated, in any form",
       all(one(t)[1] in (None, VA) for t in
           ("**0x140038c5c** — x", "`0x140038c5c`", "0x140038c5c**mov eax,1",
            "**0x140038c5c**mov", "0x140038c5c")),
       [(t, one(t)) for t in ("**0x140038c5c**mov",)])

    # The floor is asserted on the source too, so a future edit cannot lower it
    # without this test noticing.
    src = open(os.path.join(HERE, "evidence.py"), encoding="utf-8").read()
    ck("C4: the separator class is `+` (one or more)", "_SEP = r'[*`_|,:\\-\\s]+'" in src,
       "with `*` (zero or more) the address splits")
    ck("C5: no em-dash in the separator class",
       "—" not in src.split("_SEP =")[1].split("\n")[0])

    # ── D. pipe-joined citations are separate citations ───────────────
    # Measured: a run scored 10 rejection attempts as 0 rows recorded. `|` had
    # been added to the leading separator class but the trailing operand capture
    # did not stop at `|`, so the first citation swallowed all the rest.
    # `|` cannot appear in an x86 operand. A comma **can** (`cmp eax, 4`), so a
    # comma must never be a terminator.
    p2 = "0x140001000 cmp eax, 4 | 0x140001010 call 0x140002000"
    p3 = p2 + " | 0x140001020 jne 0x140001040"
    ck("D1: two pipe-joined citations parse as two", len(EV.CITE.findall(p2)) == 2,
       EV.CITE.findall(p2))
    ck("D2: three parse as three", len(EV.CITE.findall(p3)) == 3, len(EV.CITE.findall(p3)))
    m = EV.CITE.findall(p2)
    ck("D3: operands stop at the pipe", m[0][3].strip() == "eax, 4", m[0][3])
    ck("D4: the second citation is intact",
       (m[1][1], m[1][2], m[1][3].strip()) == ("0x140001010", "call", "0x140002000"), m[1])
    c = EV.CITE.findall("0x140001000 mov eax, dword ptr [rbx + 0x10]")
    ck("D5: a comma stays inside the operands (it must not be a terminator)",
       len(c) == 1 and "dword ptr" in c[0][3], c)
    for nm, tx, n in (("newline", "0x140001000 cmp eax, 4\n0x140001010 call 0x140002000", 2),
                      ("semicolon", "0x140001000 cmp eax, 4; 0x140001010 call 0x140002000", 2)):
        ck("D6: %s separation still gives %d" % (nm, n), len(EV.CITE.findall(tx)) == n)

    # ── E. trailing prose does not contaminate the operands ───────────
    # Measured: 6 of 18 denials on one night run were "anchors do not verify",
    # and the instructions were exactly right — the analyst had continued an
    # explanation on the same line and a number in that prose broke the constant
    # comparison. An x86 Intel-syntax operand never contains parentheses.
    for lbl, t, mn, ops in [
        ("prose after `)`",
         "0x140038c5c mov dword ptr [rsp + 0x20], 4) with a kernel handle",
         "mov", "dword ptr [rsp + 0x20], 4"),
        ("prose after `(`",
         "0x140038c5c syscall (SomeSyscallName)", "syscall", ""),
        ("a number inside parens does not leak in as a constant",
         "0x140038c5c cmp eax, 3 (the 0x99 case)", "cmp", "eax, 3"),
    ]:
        r = EV.parse(t)
        ck("E: %s" % lbl,
           len(r) == 1 and r[0]["mnem"] == mn and r[0]["ops"].strip() == ops,
           [(x["mnem"], x["ops"]) for x in r])

    # citations without parentheses are **unchanged** (the fix did not narrow the seed)
    for lbl, t, mn, ops in [
        ("memory operand", "0x140038c5c call qword ptr [rip - 0x1234]",
         "call", "qword ptr [rip - 0x1234]"),
        ("branch", "0x140038c5c jns 0x14002948c", "jns", "0x14002948c"),
        ("immediate", "0x140038c5c mov dword ptr [rsp + 0x20], 4",
         "mov", "dword ptr [rsp + 0x20], 4"),
    ]:
        r = EV.parse(t)
        ck("E: normal citation preserved — %s" % lbl,
           len(r) == 1 and r[0]["mnem"] == mn and r[0]["ops"].strip() == ops,
           [(x["mnem"], x["ops"]) for x in r])

    # ── F. check() against a real image ──────────────────────────────
    path = os.path.join(tempfile.mkdtemp(prefix="otter-anchor-"), "synthetic.bin")
    mkpe.write(path)
    img = PE.PE(path)

    def status(text, images=None):
        r, s = EV.check(img, text, images=images)
        return r[0]["status"], s

    st, _ = status("0x140001000 mov eax, 1")
    ck("F1: a correct citation is VERIFIED", st == "VERIFIED", st)
    st, _ = status("0x140001008 mov rax, qword ptr [rcx + 0x18]")
    ck("F2: a memory operand verifies", st == "VERIFIED", st)
    st, _ = status("0x14000100c jz 0x140001013")
    ck("F3: jz/je is accepted as an alias", st == "VERIFIED", st)
    st, _ = status("0x140001000 zzz eax, 1")
    ck("F4: a wrong mnemonic is MISMATCH", st == "MISMATCH", st)
    st, _ = status("0x140001005 cmp eax, 0x1234")
    ck("F5: a wrong constant is CONST_MISMATCH", st == "CONST_MISMATCH", st)
    st, _ = status("0x140002000 mov eax, 1")
    ck("F6: an address in a non-executable section is NONCODE", st == "NONCODE", st)
    st, _ = status("0x140000500 mov eax, 1")
    ck("F7: in range but unmapped is UNMAPPED", st == "UNMAPPED", st)
    st, _ = status("nt!0x140001000 mov eax, 1")
    ck("F8: a tagged citation for an unregistered image does not pass",
       st == "UNKNOWN_IMAGE", st)
    st, _ = status("nt!0x140001000 mov eax, 1", images={"nt": img})
    ck("F9: once the image is registered, the tagged citation verifies",
       st == "VERIFIED", st)

    # ── G. a value that was never an anchor is not counted as a failure ──
    # Measured: a confirmation attempt died on `anchor check: 7/8 verified,
    # 1 failed`, and the 1 was an IOCTL control code the analyst had written into
    # the evidence as a request parameter. The other 7 verified.
    # **A harness false positive killed a confirmation.**
    r, s = EV.check(img, "0x220003 inlen =0x188, outlen=0, access=0xC0000000\n"
                         "0x140001000 mov eax, 1\n")
    ck("G1: an out-of-range constant is NOTANCHOR",
       any(x["status"] == "NOTANCHOR" and x["va"] == 0x220003 for x in r), s)
    ck("G2: it is not counted as a failure", s["failed"] == 0, s)
    ck("G3: **it leaves the denominator too** (it must not read as 1/2)",
       s["cites"] == 1, s)
    ck("G4: it stays visible", s.get("skipped") == 1, s)
    ck("G5: it is not printed as a failure mark", "- 0x220003" in EV.render(r, s))

    # The gate keeps its teeth: an out-of-range citation that carries a **real
    # mnemonic** is a hallucinated or cross-image anchor, and must stay visible.
    r, s = EV.check(img, "0x990001000 mov rax, rbx\n")
    ck("G6: out of range + a real mnemonic is OUT_OF_IMAGE",
       r[0]["status"] == "OUT_OF_IMAGE", r[0]["status"])
    ck("G7: and it IS counted as a failure", s["failed"] == 1 and s["cites"] == 1, s)

    # ── H. evidence with no citation at all ──────────────────────────
    r, s = EV.check(img, "The handler validates nothing and the sink is reachable.")
    ck("H1: zero citations", s["cites"] == 0 and s["verified"] == 0, s)
    ck("H2: render() says what shape was expected", "0xADDR" in EV.render(r, s))

    print("%d/%d passed" % (TOTAL[0] - len(FAIL), TOTAL[0]))
    if FAIL:
        print("FAILED: %s" % ", ".join(FAIL))
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
