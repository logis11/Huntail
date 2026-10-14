#!/usr/bin/env python3
# test_guards.py — the under-applied-guard sweep. **Does it find the bypass, and
# does it still reject the idiom that is not one?**
#
# This detector's whole value is in the second half. Its first run reported 17
# hits in one driver and **all 17 were the same correct idiom**:
#     if (Irp->RequestorMode != KernelMode) ProbeForWrite(...)
# A candidate generator that fires on the correct idiom is worse than nothing —
# it spends the analyst's turns and teaches them to ignore the tool. So the
# RequestorMode layer is pinned here as a **negative** control, right next to the
# positive one, and a regression that reinstates it fails this file.
#
# Every image is built by `mkpe.py` with a real import directory and real
# `.pdata`, so the import names resolve and the function bounds exist without any
# target binary.
#
# What is pinned:
#   strong      a length branch that jumps past Probe*  -> reported, not weak
#   notskip     the same test, but the branch lands BEFORE the call -> NOT reported
#   requestmode `cmp byte ptr [reg+0x40], 0`             -> NOT reported
#   weak        an 8-bit flag self-test                  -> reported, downgraded
#   kernelmode  AccessMode zeroed before an Ob* open     -> reported
#   no-import   no Probe* imported at all                -> nothing at all
import os
import struct
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


# Prefixes: each ends in a conditional jump whose rel8 lands just past the
# `lea` + `call` that follow, i.e. the branch skips the Probe* call.
#   strong    mov ecx,[rdx+0x10] ; test ecx,ecx ; je +0x0d
#   notskip   the same, but `je +0` lands on the lea -- it does NOT skip the probe
#   reqmode   cmp byte ptr [rbx+0x40],0 ; je +0x0d    <- _IRP.RequestorMode
#   weak      test al,al ; je +0x0d                   <- an 8-bit BOOLEAN flag
PREFIX = {
    "strong":  b"\x8b\x4a\x10\x85\xc9\x74\x0d",
    "notskip": b"\x8b\x4a\x10\x85\xc9\x74\x00",
    "reqmode": b"\x80\x7b\x40\x00\x74\x0d",
    "weak":    b"\x84\xc0\x74\x0d",
}


def _probe_image(prefix, fn="ProbeForWrite"):
    """prefix, then `lea rcx,[rip+0]` + `call qword [rip+IAT(fn)]` + ret."""
    def code(slots):
        off_call = len(prefix) + 7
        after = off_call + 6
        d = slots[fn] - (BASE + after)
        return prefix + b"\x48\x8d\x0d\x00\x00\x00\x00" \
            + b"\xff\x15" + struct.pack("<i", d) + b"\xc3"
    return _write(code, {"ntoskrnl.exe": [fn]})


def _write(code, imports):
    import mkpe
    d = tempfile.mkdtemp(prefix="test_guards_")
    p = os.path.join(d, "v.bin")
    with open(p, "wb") as f:
        f.write(mkpe.build(code=code, imports=imports,
                           pdata=[(mkpe.TEXT_VA, mkpe.TEXT_VA + 0x40)]))
    return p


def _counts(hits):
    strong = [h for h in hits["probe_skip"] if not h.get("weak")]
    return {"strong": len(strong),
            "weak": len(hits["probe_skip"]) - len(strong),
            "kernelmode": len(hits["kernelmode"])}


BASE = None


def main():
    global BASE
    import guards
    import mkpe
    BASE = mkpe.IMAGE_BASE + mkpe.TEXT_VA

    # ── A. the positive: a branch that skips the probe ──────────────────────
    _pe, hits, nprobe = guards.scan(_probe_image(PREFIX["strong"]))
    c = _counts(hits)
    ck("A1: the Probe* import resolves", nprobe == 1, nprobe)
    ck("A2: the skip is reported", c["strong"] == 1, c)
    ck("A3: it is not downgraded to weak", c["weak"] == 0, c)
    h = hits["probe_skip"][0] if hits["probe_skip"] else {}
    ck("A4: it names the probe", h.get("probe") == "ProbeForWrite", h)
    ck("A5: the probe call is before the branch target", h.get("probe_va", 0) < BASE + 0x14, h)
    ck("A6: it cites the deciding test", "test ecx, ecx" in h.get("test", ""), h)

    # The same test and the same probe, but the branch lands ON the lea instead
    # of past the call — nothing is skipped, so nothing may be reported. Without
    # this vector, a detector that reports every nearby jcc still passes.
    _pe, hits, nprobe = guards.scan(_probe_image(PREFIX["notskip"]))
    c = _counts(hits)
    ck("A7: a branch that does not skip the probe is not reported",
       c["strong"] + c["weak"] == 0, c)
    ck("A8: the probe call is still seen there", nprobe == 1, nprobe)

    # ── B. the negative that matters most ───────────────────────────────────
    # `if (Irp->RequestorMode != KernelMode) Probe...` is the CORRECT idiom. The
    # first version of this detector reported 17 of these and nothing else.
    _pe, hits, nprobe = guards.scan(_probe_image(PREFIX["reqmode"]))
    c = _counts(hits)
    ck("B1: the probe call is still seen", nprobe == 1, nprobe)
    ck("B2: RequestorMode is NOT reported", c["strong"] == 0 and c["weak"] == 0, c)

    # ── C. an 8-bit flag is kept but downgraded ─────────────────────────────
    # It may be a RequestorMode copy, so it is not dropped — losing a candidate
    # is more expensive than ranking one low.
    _pe, hits, _n = guards.scan(_probe_image(PREFIX["weak"]))
    c = _counts(hits)
    ck("C1: the 8-bit flag branch is kept", c["strong"] + c["weak"] == 1, c)
    ck("C2: it is ranked weak, not strong", c["weak"] == 1 and c["strong"] == 0, c)

    # ── D. AccessMode == KernelMode skips the access check entirely ─────────
    def km(slots):
        pre = b"\x4d\x31\xc9"                      # xor r9, r9  (AccessMode = KernelMode)
        d = slots["ObReferenceObjectByHandle"] - (BASE + len(pre) + 6)
        return pre + b"\xff\x15" + struct.pack("<i", d) + b"\xc3"

    _pe, hits, _n = guards.scan(_write(km, {"ntoskrnl.exe": ["ObReferenceObjectByHandle"]}))
    ck("D1: the KernelMode open is reported", len(hits["kernelmode"]) == 1, hits["kernelmode"])
    if hits["kernelmode"]:
        k = hits["kernelmode"][0]
        ck("D2: it names the API", k["api"] == "ObReferenceObjectByHandle", k)
        ck("D3: it says how AccessMode was zeroed", k["how"] == "xor r9", k)

    # ── E. nothing imported, nothing reported ───────────────────────────────
    _pe, hits, nprobe = guards.scan(_write(lambda _s: b"\x8b\x01\xc3",
                                           {"ntoskrnl.exe": ["IoCreateDevice"]}))
    ck("E1: no Probe* import -> zero probe calls", nprobe == 0, nprobe)
    ck("E2: no Probe* import -> zero candidates",
       sum(len(v) for v in hits.values()) == 0, hits)

    # ── F. render says what it counted ──────────────────────────────────────
    _pe, hits, nprobe = guards.scan(_probe_image(PREFIX["strong"]))
    txt = guards.render("synthetic", hits, nprobe)
    ck("F1: render reports the probe count", "1 Probe call" in txt, txt)
    ck("F2: render marks the strong candidate", "PROBE-SKIP" in txt, txt)
    _pe, hits, nprobe = guards.scan(_probe_image(PREFIX["weak"]))
    txt = guards.render("synthetic", hits, nprobe)
    ck("F3: render explains the downgrade", "weak candidate" in txt, txt)

    print("%d/%d passed" % (TOTAL[0] - len(FAIL), TOTAL[0]))
    if FAIL:
        print("FAILED: %s" % ", ".join(FAIL))
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
