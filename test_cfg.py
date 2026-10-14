#!/usr/bin/env python3
# test_cfg.py — the dominance gate. **Does a guard actually block a sink, and
# does R3 give up its authority where it is known to be blind?**
#
# This is the gate the whole rejection path rests on. With `cfg.py` absent, every
# rejection came back "CFG dominance undecidable" and the ledger recorded it as
# an unverified rejection anyway — so a regression here does not break loudly, it
# **quietly turns every rejection into a pass.** That is the failure this file
# exists to catch.
#
# Every vector is a hand-assembled function in an image built by `mkpe.py`, so
# the answers are known by construction: no target binary, and no path where the
# test degrades into a skip. The byte comments are the contract — if capstone
# ever decodes them differently the disassembly is printed on failure.
#
# What is pinned, and why each one matters:
#   gated               the guard separates and the value flows -> R3 may reject
#   both_edges          the sink is on both edges -> "there is a guard" is not grounds
#   not_dominated       a path bypasses the guard -> the rejection does not stand
#   dominates_only      it dominates but constrains nothing (taint does not reach)
#   signed_compare      a negative input passes the bound -> authority withdrawn
#   bound_compare       dominance cannot tell whether the constant is right
#   double_fetch        the checked slot is re-read from a user pointer
#   no_pdata            bounds unknown -> undecidable, never guessed
#   cross_function      inter-procedural is not adjudicated here
#   sink_class          a register move is not a sink (R7)
#   gates_cut n=1       must agree with gates(), label for label
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


# ── vectors ─────────────────────────────────────────────────────────────────
# Addresses below are offsets from the start of .text (0x140001000).
#
#   GATED            00 test rcx,rcx | 03 je +4 | 05 mov eax,[rcx] | 07 jmp | 09 ret | 0A ret
#   BOTH_EDGES       00 test rcx,rcx | 03 je 07  | 05 jmp 07        | 07 mov eax,[rcx]
#   NOT_DOMINATED    00 test rdx,rdx | 03 je 0A  | 05 test rcx,rcx  | 08 je 0C | 0A mov eax,[rcx]
#   SIGNED           GATED with `jl` instead of `je`
#   BOUND            00 cmp ecx,8    | 03 jbe 09 | 05 mov eax,[rcx] | ...
#   NO_FLOW          guard reads rdx, sink reads [rcx] -> nothing flows
#   DOUBLE_FETCH     IRP -> CurrentStackLocation -> Type3InputBuffer, slot read twice
GATED = b"\x48\x85\xc9\x74\x04\x8b\x01\xeb\x01\xc3\xc3"
BOTH_EDGES = b"\x48\x85\xc9\x74\x02\xeb\x00\x8b\x01\xc3"
NOT_DOMINATED = b"\x48\x85\xd2\x74\x05\x48\x85\xc9\x74\x02\x8b\x01\xc3"
SIGNED = b"\x48\x85\xc9\x7c\x04\x8b\x01\xeb\x01\xc3\xc3"
BOUND = b"\x83\xf9\x08\x76\x04\x8b\x01\xeb\x01\xc3\xc3"
NO_FLOW = b"\x48\x85\xd2\x74\x04\x8b\x01\xeb\x01\xc3\xc3"
DOUBLE_FETCH = (b"\x48\x8b\x82\xb8\x00\x00\x00"   # 00 mov rax,[rdx+0xb8]  CurrentStackLocation
                b"\x48\x8b\x70\x20"               # 07 mov rsi,[rax+0x20]  Type3InputBuffer
                b"\x8b\x4e\x10"                   # 0B mov ecx,[rsi+0x10]  first fetch
                b"\x83\xf9\x08"                   # 0E cmp ecx,8           the guard
                b"\x76\x07"                       # 11 jbe 1A
                b"\x8b\x56\x10"                   # 13 mov edx,[rsi+0x10]  SECOND fetch
                b"\x8b\x01"                       # 16 mov eax,[rcx]       sink consumes rcx
                b"\xc3\xc3\xc3")

# (name, code, guard offset, sink offset, expected verdict, expected class)
VECTORS = [
    ("gated",         GATED,         0x00, 0x05, "gated",              None),
    ("both_edges",    BOTH_EDGES,    0x00, 0x07, "both_edges",         None),
    ("not_dominated", NOT_DOMINATED, 0x05, 0x0A, "not_dominated",      None),
    ("dominates_only", NO_FLOW,      0x00, 0x05, "dominates_only",     None),
    ("signed_compare", SIGNED,       0x00, 0x05, "gated_no_authority", "signed_compare"),
    ("bound_compare",  BOUND,        0x00, 0x05, "gated_no_authority", "bound_compare"),
    ("double_fetch",   DOUBLE_FETCH, 0x0E, 0x16, "gated_no_authority", "double_fetch"),
]

SINK_CLASSES = [
    ("mem_read",  b"\x8b\x01\xc3"),                  # mov eax,[rcx]
    ("mem_write", b"\x89\x01\xc3"),                  # mov [rcx],eax
    ("reg_only",  b"\x48\x89\xca\xc3"),              # mov rdx,rcx
    ("call",      b"\xe8\x00\x00\x00\x00\xc3"),      # call rel32
    ("string_op", b"\xf3\xa4\xc3"),                  # rep movsb
]


def _img(code, pdata=((0x1000, 0x1040),)):
    import mkpe
    import pe as PEM
    d = tempfile.mkdtemp(prefix="test_cfg_")
    p = os.path.join(d, "v.bin")
    with open(p, "wb") as f:
        f.write(mkpe.build(code=code, pdata=list(pdata) or None))
    return PEM.PE(p)


def _disasm(code, base):
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    return "; ".join("0x%X %s %s" % (i.address, i.mnemonic, i.op_str)
                     for i in md.disasm(code, base))


def main():
    import cfg as CFG
    import mkpe
    B = mkpe.IMAGE_BASE + mkpe.TEXT_VA

    # ── A. the verdict matrix ───────────────────────────────────────────────
    for name, code, g, s, want, wclass in VECTORS:
        P = _img(code)
        r = CFG.gates(P, B + g, B + s)
        ck("A/%s verdict" % name, r["verdict"] == want,
           "got %s (%s) :: %s" % (r["verdict"], r.get("why", "")[:90], _disasm(code, B)))
        if wclass:
            ck("A/%s class" % name, r.get("class") == wclass, "got %r" % r.get("class"))
        # A gated verdict has to carry a taint result; without one, "it dominates"
        # was asserted with nothing behind it.
        if want in ("gated", "gated_no_authority"):
            ck("A/%s taint flows" % name,
               (r.get("taint") or {}).get("taint") == "flows", r.get("taint"))

    # The one that silently breaks everything: `gated` must NOT be the answer
    # where a bypass exists. Checked positively above, and again as a negation
    # so a detector that answers `gated` for everything cannot pass this file.
    gated_count = 0
    for name, code, g, s, want, _c in VECTORS:
        if CFG.gates(_img(code), B + g, B + s)["verdict"] == "gated":
            gated_count += 1
    ck("A/only one vector is `gated`", gated_count == 1,
       "%d vectors answered gated — the gate may be stuck" % gated_count)

    # ── B. taint-lite: dominance is not constraint ──────────────────────────
    r = CFG.gates(_img(NO_FLOW), B + 0x00, B + 0x05)
    ck("B1: no_flow is reported as such",
       (r.get("taint") or {}).get("taint") == "no_flow", r.get("taint"))
    ck("B2: the why says it dominates without constraining",
       "does not constrain" in (r.get("why") or ""), r.get("why"))

    # ── C. bounds are never guessed ─────────────────────────────────────────
    P = _img(GATED, pdata=())
    ck("C1: no .pdata -> no_pdata", CFG.gates(P, B, B + 5)["verdict"] == "no_pdata")
    ck("C2: no .pdata -> no runtime functions", P.runtime_functions() == [])
    ck("C3: no .pdata -> build() refuses", CFG.build(P, B) is None)

    # Two non-adjacent chunks must stay two functions (merging would hide the
    # cross-function case, which is exactly what `merged=True` must not do).
    code = GATED + b"\x90" * (0x20 - len(GATED)) + b"\x48\x85\xd2\x8b\x02\xc3"
    P = _img(code, pdata=((0x1000, 0x1010), (0x1020, 0x1030)))
    ck("C4: two chunks stay two functions", len(P.runtime_functions()) == 2,
       P.runtime_functions())
    ck("C5: guard and sink in different functions -> cross_function",
       CFG.gates(P, B, B + 0x23)["verdict"] == "cross_function")

    # ── D. sink_class (R7 material) ─────────────────────────────────────────
    for want, code in SINK_CLASSES:
        got = CFG.sink_class(_img(code), B)
        ck("D/%s" % want, got["class"] == want, "got %s (%s)" % (got["class"], got.get("insn")))
    ck("D/reg_only explains itself",
       "not a dangerous operation" in CFG.sink_class(_img(b"\x48\x89\xca\xc3"), B)["why"])

    # ── E. gates_cut must agree with gates at n=1 ───────────────────────────
    # The failure labels are deliberately matched so that replaying an old
    # verdict produces the same string. Only the success label differs.
    SUCCESS = {"gated": "gated_cut"}
    for name, code, g, s, want, wclass in VECTORS:
        P = _img(code)
        a = CFG.gates(P, B + g, B + s)
        c = CFG.gates_cut(P, [B + g], B + s)
        ck("E/%s n=1 agreement" % name,
           c["verdict"] == SUCCESS.get(a["verdict"], a["verdict"]),
           "gates=%s gates_cut=%s" % (a["verdict"], c["verdict"]))
        if wclass:
            ck("E/%s n=1 class" % name, c.get("class") == wclass, c.get("class"))

    # ── F. a cut cannot be padded into existence ────────────────────────────
    P = _img(GATED)
    ck("F1: two VAs in one block -> padded_cut",
       CFG.gates_cut(P, [B + 0, B + 3], B + 5)["verdict"] == "padded_cut")
    ck("F2: no guard declared -> no_guard",
       CFG.gates_cut(P, [], B + 5)["verdict"] == "no_guard")

    # ── G. sink_gates asks the opposite question ────────────────────────────
    r = CFG.sink_gates(_img(GATED), B + 5)
    ck("G1: the dominating test is enumerated",
       any(a == B and m == "test" for a, m, _o, _k in r["gates"]), r["gates"])
    ck("G2: nothing past the sink is a gate",
       all(a < B + 5 for a, _m, _o, _k in r["gates"]), r["gates"])
    ck("G3: render names the dominating count", "dominates" in CFG.render_sink_gates(r))
    ck("G4: no result is unanalysed, not 'no gates'",
       "unanalysed" in CFG.render_sink_gates(None))

    # ── H. adjacent .pdata chunks must be merged ────────────────────────────
    # MSVC splits a large function across several `.pdata` chunks (chained
    # unwind). Cutting at a chunk boundary breaks the graph mid-function, and the
    # measured cost of that was severe: eight injected double fetches all missed,
    # because the bounds spanned 0x59 bytes and every injected site was outside
    # them. Here guard and sink sit in chunk 1 while the branch's other successor
    # lands in chunk 2 — so without the merge the taken edge falls off the end of
    # the graph and the guard block is misread as an indirect branch.
    #
    #   00 test rcx,rcx | 03 je 0x0A | 05 mov eax,[rcx] | 07 ret | [chunk 2] 0A ret
    SPLIT = b"\x48\x85\xc9\x74\x05\x8b\x01\xc3\x90\x90\xc3"
    P = _img(SPLIT, pdata=((0x1000, 0x1008), (0x1008, 0x1040)))
    ck("H1: the chunks really are two", len(P.runtime_functions()) == 2,
       P.runtime_functions())
    ck("H2: and merge into one", len(P.merged_functions()) == 1, P.merged_functions())
    gm = CFG.build(P, B, merged=True)
    gc = CFG.build(P, B, merged=False)
    ck("H3: the merged graph spans both chunks", gm["end"] == B + 0x40, hex(gm["end"]))
    ck("H4: the chunk graph stops at the boundary", gc["end"] == B + 0x08, hex(gc["end"]))
    ck("H5: the branch target is a block only in the merged graph",
       (B + 0x0A) in gm["leaders"] and (B + 0x0A) not in gc["leaders"],
       (gm["leaders"], gc["leaders"]))
    ck("H6: the chunk graph misreads the guard as indirect",
       B in gc["indirect"] and B not in gm["indirect"],
       (gc["indirect"], gm["indirect"]))
    # The one that matters: the verdict itself has to come out right.
    ck("H7: gates() across a chunk boundary is still `gated`",
       CFG.gates(P, B, B + 5)["verdict"] == "gated",
       CFG.gates(P, B, B + 5))

    print("%d/%d passed" % (TOTAL[0] - len(FAIL), TOTAL[0]))
    if FAIL:
        print("FAILED: %s" % ", ".join(FAIL))
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
