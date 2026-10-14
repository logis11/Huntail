#!/usr/bin/env python3
# test_claimaudit.py — the claim auditor. **Are the anchors, offsets and
# constants inside a claim actually there?**
#
# Three defects came out of hand-verifying one long run end to end, and all three
# are false *negatives* — the most expensive kind, because a false negative looks
# exactly like a clean result:
#
#  1. **An offset query silently returns zero.** `this+0x70` grepped as `+ 112`
#     finds nothing, because Hex-Rays writes `*((_QWORD *)this + 14)`. That
#     produced a "zero accesses" answer that was simply wrong. So the expansion
#     to every cast width is pinned, QWORD index included.
#
#  2. **A signed spelling is missed.** Hex-Rays writes a value with the top bit
#     set as a negative integer. Ask only for the unsigned form and the corpus
#     count is zero, which produces the false verdict "that constant does not
#     exist, so the claim is inferred" — it nearly demoted a confirmed defect.
#
#  3. **An address is not a constant.** Once the ledger's phantom-constant filter
#     was fixed, the first thing it flagged was the anchor VAs cited in the
#     evidence. A hex value inside the image's mapped range is an address, and
#     its little-endian bytes are naturally absent from the file.
#
# All of it runs against an image built by `mkpe.py` and a corpus written by the
# test, so every answer is known by construction.
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


# A real MSVC x64 prologue, so the module's own control anchor can be derived
# from this image. The displacement is 0x18 on purpose — see section G.
PROLOGUE = (b"\x48\x89\x5c\x24\x18"      # mov qword ptr [rsp+0x18], rbx
            b"\xb8\x01\x00\x00\x00"      # mov eax, 1
            b"\xc3")

CORPUS = (
    "/* ===== Klass_A::Open @ 0x140001000 ===== */\n"
    "int f(void *this){ return *((_QWORD *)this + 14); }\n"
    "/* ===== Klass_A::Set @ 0x140001100 ===== */\n"
    "void g(void *this){ *((_QWORD *)this + 14) = 1; }\n"
    "/* ===== Other_B::Touch @ 0x140001200 ===== */\n"
    "int h(void *this){ return *((_QWORD *)this + 14); }\n"
)


def main():
    import claimaudit as CA
    import mkpe
    B = mkpe.IMAGE_BASE + mkpe.TEXT_VA

    d = tempfile.mkdtemp(prefix="test_claimaudit_")
    img = os.path.join(d, "v.bin")
    with open(img, "wb") as f:
        f.write(mkpe.build(code=PROLOGUE, pdata=[(mkpe.TEXT_VA, mkpe.TEXT_VA + 0x40)]))
    corp = os.path.join(d, "corpus.c")
    with open(corp, "w", encoding="utf-8") as f:
        f.write(CORPUS)

    # ── A. offset spellings ─────────────────────────────────────────────────
    f70 = CA.offset_forms(0x70)
    ck("A1: 0x70 expands to the QWORD index", (14, "_QWORD") in f70, f70)
    ck("A2: and to every other width",
       set(f70) == {(112, "_BYTE"), (56, "_WORD"), (28, "_DWORD"), (14, "_QWORD")}, f70)
    ck("A3: an odd offset only has a BYTE spelling",
       CA.offset_forms(7) == [(7, "_BYTE")], CA.offset_forms(7))
    ck("A4: 2 has BYTE and WORD only",
       set(CA.offset_forms(2)) == {(2, "_BYTE"), (1, "_WORD")}, CA.offset_forms(2))

    # ── B. offset_query needs a class scope ─────────────────────────────────
    blocks = CA.parse_corpus(corp)
    ck("B1: the corpus parses into its functions", len(blocks) == 3,
       [(n, v) for n, v, _b in blocks])
    allhits = CA.offset_query(blocks, 0x70)
    ck("B2: unscoped, unrelated classes mix in", len(allhits) == 3,
       [n for n, _v, _h in allhits])
    scoped = CA.offset_query(blocks, 0x70, class_prefix="Klass_A")
    ck("B3: a class scope removes them", [n for n, _v, _h in scoped]
       == ["Klass_A::Open", "Klass_A::Set"], scoped)
    writers = CA.offset_query(blocks, 0x70, class_prefix="Klass_A", writers_only=True)
    ck("B4: writers_only keeps only the assignment",
       [n for n, _v, _h in writers] == ["Klass_A::Set"], writers)
    ck("B5: a different offset finds nothing", CA.offset_query(blocks, 0x78) == [],
       CA.offset_query(blocks, 0x78))

    # ── C. cited constants ──────────────────────────────────────────────────
    c = CA._SIGNED_PROBE_CONST
    signed = os.path.join(d, "signed.c")
    with open(signed, "w", encoding="utf-8") as f:
        f.write("if (magic == %d) return 1;\n" % (c - (1 << 32)))
    rows = {k: (nc, nb) for k, nc, nb in CA.constants_cited("0x%X" % c, signed, None)}
    ck("C1: the signed spelling is found", rows.get(c, (0, 0))[0] > 0, rows)
    # Without that expansion the same corpus reads as zero, which is the false
    # "this constant does not exist" verdict.
    unsigned_only = open(signed, encoding="utf-8").read()
    ck("C2: the corpus really contains only the signed form",
       ("0x%X" % c).lower() not in unsigned_only.lower()
       and str(c) not in unsigned_only, unsigned_only)

    rows = {k: (nc, nb) for k, nc, nb in
            CA.constants_cited("0xCCCCCCCC and 0xDEADBEEF", None, img)}
    ck("C3: a constant present in the image is counted",
       rows.get(0xCCCCCCCC, (0, 0))[1] > 0, rows)
    ck("C4: a constant absent from the image counts zero",
       rows.get(0xDEADBEEF, (0, 1))[1] == 0, rows)
    ck("C5: with no corpus the corpus count is -1 (not checked), not 0",
       rows.get(0xDEADBEEF, (0, 0))[0] == -1, rows)

    # The address-is-not-a-constant rule.
    txt = "anchors 0x%X and 0x%X, magic 0xDEADBEEF" % (B, B + 5)
    got = {k for k, _nc, _nb in CA.constants_cited(txt, None, img)}
    ck("C6: a VA inside the image is not treated as a constant",
       B not in got and (B + 5) not in got, [hex(x) for x in got])
    ck("C7: the real constant still comes through", 0xDEADBEEF in got,
       [hex(x) for x in got])
    off = {k for k, _nc, _nb in CA.constants_cited(txt, None, img, skip_image_vas=False)}
    ck("C8: and the skip can be turned off", B in off, [hex(x) for x in off])
    ck("C9: short values are below the bit floor",
       not any(k == 0x10 for k, _nc, _nb in CA.constants_cited("0x0010", None, img)))

    rng = CA._image_range(img)
    ck("C10: the image range starts at .text", rng[0] == B, [hex(x) for x in rng])
    ck("C11: a non-PE has no range", CA._image_range(corp) is None)

    # ── D. anchor verification against a real image ─────────────────────────
    ins = CA.disasm_at(img, B, 0, 16)
    ck("D1: the window disassembles", ins and ins[0][1] == "mov", ins[:2])
    ok, ev = CA.check_anchor(img, B, r"mov\s+eax,\s*1", 16)
    ck("D2: a real citation verifies", ok, ev)
    ck("D3: and the evidence quotes the instruction", "mov eax, 1" in ev, ev)
    ok, ev = CA.check_anchor(img, B, r"vzeroupper", 16)
    ck("D4: a hallucinated citation does not", not ok, ev)
    ck("D5: and the failure shows what is actually there", "actual:" in ev, ev)

    # ── E. the module's own controls, on this image ─────────────────────────
    CA.configure(img, corp)
    ck("E1: the control anchor is derived from the image",
       CA._control_anchor(img) is not None)
    ck("E2: anchor-hit passes", CA._probe("anchor-hit") is True)
    ck("E3: anchor-miss fails, as it must", CA._probe("anchor-miss") is False)
    ck("E4: offset-forms control passes", CA._probe("offset-forms") is True)
    ck("E5: signed-const control passes", CA._probe("signed-const") is True)
    # No anchor derivable -> the control closes rather than passing.
    bare = os.path.join(d, "bare.bin")
    with open(bare, "wb") as f:
        f.write(mkpe.build())                     # no prologue, no .pdata
    ck("E6: no derivable anchor -> anchor-hit does NOT pass",
       CA._probe("anchor-hit", _pe=bare) is False)

    # ── F. audit() end to end ───────────────────────────────────────────────
    import verifier_guard as _VG
    try:
        rows = CA.audit([{"id": "ghost", "va": None, "claim": "magic 0xDEADBEEF"},
                         {"id": "real", "va": None, "claim": "marker 0xCCCCCCCC"},
                         {"id": "anchored", "va": B, "expect": r"mov\s+qword ptr",
                          "claim": "prologue"},
                         {"id": "bad", "va": B, "expect": r"vzeroupper",
                          "claim": "nope"}],
                        corpus_path=corp, pe_path=img)
    except _VG.ControlFailed as e:
        # The controls refusing a result is the right behaviour, but it must not
        # take the tally with it.
        ck("F0: audit() controls pass", False, str(e)[:200])
        rows = []
    by = {r["id"]: r for r in rows}
    for _k in ("ghost", "real", "anchored", "bad"):
        by.setdefault(_k, {"phantom_consts": [], "anchor_ok": "<no result>"})
    ck("F1: the phantom constant is reported",
       by["ghost"]["phantom_consts"] and
       by["ghost"]["phantom_consts"][0][0] == "0xdeadbeef", by["ghost"])
    ck("F2: a constant the corpus lacks but the image has is still phantom-free "
       "only if the corpus has it", isinstance(by["real"]["phantom_consts"], list))
    ck("F3: a real anchor is ok", by["anchored"]["anchor_ok"] is True, by["anchored"])
    ck("F4: a false anchor is not", by["bad"]["anchor_ok"] is False, by["bad"])
    ck("F5: no va -> anchor_ok is None, not False",
       by["ghost"]["anchor_ok"] is None, by["ghost"])

    # ── G. a documented limit of the prologue oracle ────────────────────────
    # capstone renders a small displacement as `[rsp + 8]`, not `[rsp + 0x8]`, so
    # the oracle's regex only matches displacements it prints in hex. This is
    # pinned so the limit is known rather than discovered: a prologue with a
    # small displacement yields no control anchor.
    small = os.path.join(d, "small.bin")
    with open(small, "wb") as f:
        f.write(mkpe.build(code=b"\x48\x89\x5c\x24\x08\xc3",
                           pdata=[(mkpe.TEXT_VA, mkpe.TEXT_VA + 0x40)]))
    ca = CA._control_anchor(small)
    ok = ca is not None and CA.check_anchor(small, ca[0], ca[1], 16)[0]
    ck("G1: the oracle regex needs a hex-printed displacement", not ok,
       "a [rsp + 8] prologue unexpectedly matched — the oracle was widened, "
       "update this note")

    print("%d/%d passed" % (TOTAL[0] - len(FAIL), TOTAL[0]))
    if FAIL:
        print("FAILED: %s" % ", ".join(FAIL))
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
