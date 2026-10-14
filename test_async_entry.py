#!/usr/bin/env python3
# test_async_entry.py — the asynchronous-registrar sweep. **Can a race even be
# filed, and is the recovered callback really code?**
#
# Why this module exists at all is a coverage hole, not a bug: across a whole
# ledger of 604 surface rows, **one** was shaped like a race hypothesis, and the
# only confirmed memory-safety bug in that ledger came out of that one row. The
# unit of the surface table was a single request, so a race had no row to live in
# — never filed, so never even counted as unanalysed.
#
# Two failure modes are pinned here, pulling opposite ways.
#
# A. **Report nothing and the hole comes back.** The registration APIs are the
#    enumerable part of a race: the third party is registered with the kernel, so
#    it can be recovered statically. The positive controls prove the recovery
#    path works.
#
# B. **Report `.rdata` as code and the output is noise.** Collapsing the
#    executable sections into one min/max span swallows `.rdata` and `.data`
#    whole (PAGE and INIT sit after them), and `.rdata` addresses were reported
#    as callbacks. That is pinned as a negative control, and it is the reason
#    `_exec_ranges` returns one range **per section**.
#
# Upstream pinned its positive control to a particular driver on disk, which made
# the control target material and the module dead wherever that file was absent.
# Everything here is synthetic — `mkpe.py` with a real import directory — so the
# answers are known by construction and nothing degrades into a skip.
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


def _image(callback_va, fn="IoSetCompletionRoutine", imports=None):
    """A driver that registers `fn` with a callback at `callback_va`:
         lea rcx, [rip+..]            <- the callback argument
         call qword ptr [rip+IAT(fn)] <- the registration call
    """
    import mkpe
    import pe as PEM

    def code(slots):
        base = mkpe.IMAGE_BASE + mkpe.TEXT_VA
        d1 = callback_va - (base + 7)
        d2 = slots[fn] - (base + 13)
        return (b"\x48\x8d\x0d" + struct.pack("<i", d1)
                + b"\xff\x15" + struct.pack("<i", d2) + b"\xc3")

    d = tempfile.mkdtemp(prefix="test_async_")
    p = os.path.join(d, "v.bin")
    with open(p, "wb") as f:
        f.write(mkpe.build(code=code, imports=imports or {"ntoskrnl.exe": [fn]}))
    return PEM.PE(p)


def main():
    import async_entry as AE
    import mkpe
    TEXT = mkpe.IMAGE_BASE + mkpe.TEXT_VA
    IN_TEXT = TEXT + 0x100                 # inside .text  (vsize 0x200)
    IN_RDATA = mkpe.IMAGE_BASE + mkpe.RDATA_VA   # inside .rdata — NOT code

    # ── A. the callback is recovered, at the address it was planted ──────────
    P = _image(IN_TEXT)
    rs = AE.scan(P)
    ck("A1: the registration site is found", len(rs) == 1, rs)
    if rs:
        r = rs[0]
        ck("A2: it names the registrar",
           r["registrar"] == "IoSetCompletionRoutine", r)
        ck("A3: the callback is the planted address", r["callback"] == IN_TEXT,
           hex(r["callback"] or 0))
        ck("A4: it records which lea carried it", r["lea_at"] == TEXT, r)
        ck("A5: it carries the context the callback runs in",
           "completion" in r["context"], r)

    # ── B. `.rdata` is not code ─────────────────────────────────────────────
    # The historical bug: one collapsed min/max executable range swallowed the
    # data sections, and `.rdata` targets were reported as callbacks.
    rs = AE.scan(_image(IN_RDATA))
    ck("B1: the registration site is still seen", len(rs) == 1, rs)
    ck("B2: but no callback is claimed", rs and rs[0]["callback"] is None, rs)

    # The mechanism, not just the symptom: one range per executable section.
    rngs = AE._exec_ranges(P)
    ck("B3: only executable sections get a range", len(rngs) == 1, rngs)
    ck("B4: .text is in range", AE._in_text(rngs, IN_TEXT), [hex(x) for r in rngs for x in r])
    ck("B5: .rdata is not", not AE._in_text(rngs, IN_RDATA), IN_RDATA)

    # The mechanism needs TWO executable sections to be testable at all: with one
    # section a min/max collapse is a no-op. Real drivers have PAGE and INIT
    # sitting AFTER the data sections, which is exactly how one collapsed range
    # swallowed `.rdata`. A fabricated section table pins it without needing an
    # image shaped that way.
    class _TwoExec(object):
        base = mkpe.IMAGE_BASE
        secs = [{"name": ".text", "va": 0x1000, "vsize": 0x1000, "rsize": 0x1000,
                 "chars": 0x60000020},
                {"name": ".rdata", "va": 0x2000, "vsize": 0x1000, "rsize": 0x1000,
                 "chars": 0x40000040},
                {"name": "PAGE", "va": 0x3000, "vsize": 0x1000, "rsize": 0x1000,
                 "chars": 0x60000020}]

    two = AE._exec_ranges(_TwoExec())
    ck("B6: two executable sections stay two ranges", len(two) == 2,
       [(hex(a), hex(b)) for a, b in two])
    ck("B7: a data section between them is NOT executable",
       not AE._in_text(two, mkpe.IMAGE_BASE + 0x2000),
       [(hex(a), hex(b)) for a, b in two])
    ck("B8: both executable sections still are",
       AE._in_text(two, mkpe.IMAGE_BASE + 0x1500)
       and AE._in_text(two, mkpe.IMAGE_BASE + 0x3500), two)

    # ── C. registrars that take no callback are counted, not guessed at ─────
    # `IoAllocateWorkItem(PDEVICE_OBJECT)` has no callback argument. The first
    # version still picked up the preceding `lea` and called it the callback.
    rs = AE.scan(_image(IN_TEXT, fn="IoAllocateWorkItem"))
    ck("C1: it is still enumerated", len(rs) == 1, rs)
    ck("C2: no callback is invented", rs and rs[0]["callback"] is None, rs)
    ck("C3: and it says why", rs and rs[0].get("no_callback_arg") is True, rs)
    ck("C4: IoAllocateWorkItem is excluded from callback recovery",
       "IoAllocateWorkItem" not in AE.HAS_CALLBACK)
    ck("C5: but IoSetCancelRoutine is not",
       "IoSetCancelRoutine" in AE.HAS_CALLBACK)

    # ── C'. only a rip-relative lea carries a callback ──────────────────────
    # `lea rcx, [rax+0x40]` is an offset into some object, not an address. Drop
    # the rip check and `addr + size + disp` is computed anyway, landing inside
    # .text and inventing a callback out of nothing.
    def _nonrip(slots):
        pre = b"\x48\x8d\x48\x40"              # lea rcx, [rax+0x40]
        d2 = slots["IoSetCompletionRoutine"] - (TEXT + len(pre) + 6)
        return pre + b"\xff\x15" + struct.pack("<i", d2) + b"\xc3"

    rs = AE.scan(_raw(_nonrip, {"ntoskrnl.exe": ["IoSetCompletionRoutine"]}))
    ck("C6: the site is enumerated", len(rs) == 1, rs)
    ck("C7: a non-rip lea is not a callback", rs and rs[0]["callback"] is None, rs)

    # ── C''. the lookback window is bounded ─────────────────────────────────
    # The window exists because a lea far upstream is not the argument to THIS
    # call. Pinned on both sides so the bound cannot drift unnoticed.
    def _gap(n):
        def code(slots):
            lea = b"\x48\x8d\x0d" + struct.pack("<i", IN_TEXT - (TEXT + 7))
            d2 = slots["IoSetCompletionRoutine"] - (TEXT + 7 + n + 6)
            return lea + b"\x90" * n + b"\xff\x15" + struct.pack("<i", d2) + b"\xc3"
        return code

    near = AE.scan(_raw(_gap(10), {"ntoskrnl.exe": ["IoSetCompletionRoutine"]}))
    far = AE.scan(_raw(_gap(13), {"ntoskrnl.exe": ["IoSetCompletionRoutine"]}))
    ck("C8: a lea inside the window is recovered",
       near and near[0]["callback"] == IN_TEXT, near)
    ck("C9: a lea outside it is not",
       far and far[0]["callback"] is None, far)
    ck("C10: the window is the documented size", AE.LOOKBACK == 12, AE.LOOKBACK)

    # ── D. nothing registered, nothing reported ─────────────────────────────
    d = tempfile.mkdtemp(prefix="test_async_")
    bare = os.path.join(d, "bare.bin")
    with open(bare, "wb") as f:
        f.write(mkpe.build())
    import pe as PEM
    ck("D1: an image with no imports yields nothing", AE.scan(PEM.PE(bare)) == [])
    unrelated = _image(IN_TEXT, fn="IoSetCompletionRoutine",
                       imports={"ntoskrnl.exe": ["IoSetCompletionRoutine",
                                                 "IoCreateDevice"]})
    ck("D2: an unrelated import does not add a row",
       len(AE.scan(unrelated)) == 1, AE.scan(unrelated))

    # ── E. several registrars in one image ──────────────────────────────────
    def multi(slots):
        base = mkpe.IMAGE_BASE + mkpe.TEXT_VA
        out = b""
        for i, fn in enumerate(("IoSetCompletionRoutine", "IoSetCancelRoutine")):
            at = len(out)
            d1 = IN_TEXT - (base + at + 7)
            d2 = slots[fn] - (base + at + 13)
            out += b"\x48\x8d\x0d" + struct.pack("<i", d1) \
                + b"\xff\x15" + struct.pack("<i", d2)
        return out + b"\xc3"

    p = os.path.join(d, "multi.bin")
    with open(p, "wb") as f:
        f.write(mkpe.build(code=multi,
                           imports={"ntoskrnl.exe": ["IoSetCompletionRoutine",
                                                     "IoSetCancelRoutine"]}))
    rs = AE.scan(PEM.PE(p))
    ck("E1: both registrars are enumerated", len(rs) == 2,
       [(r["registrar"], hex(r["callback"] or 0)) for r in rs])
    ck("E2: both callbacks are recovered",
       all(r["callback"] == IN_TEXT for r in rs), rs)
    ck("E3: the rows are sorted by registrar then site",
       [r["registrar"] for r in rs] == sorted(r["registrar"] for r in rs), rs)

    # ── F. the module's own controls ────────────────────────────────────────
    ck("F1: the synthetic positive fires",
       AE._control_probe("synthetic_callback_recovered") == 1)
    ck("F2: recovered callbacks are all in .text",
       AE._control_probe("callbacks_in_text") == 1)
    ck("F3: an .rdata target is rejected",
       AE._control_probe("rdata_callback_rejected") == 0)
    ck("F4: an image with no registration import yields zero",
       AE._control_probe("no_imports_zero") == 0)
    ck("F5: an unknown control label is an error, not a pass",
       _raises(AE._control_probe, "no_such_control"))

    import verifier_guard as _VG
    try:
        ck("F6: enumerate_async emits once the controls pass",
           len(AE.enumerate_async(P)) == 1)
    except _VG.ControlFailed as e:
        ck("F6: enumerate_async emits once the controls pass", False, str(e)[:200])

    # ── G. control status is honest about what ran ──────────────────────────
    import config as _C
    st = AE.control_status()
    avail = bool(getattr(_C, "ASYNC_CONTROL_IMAGE", "")
                 and os.path.exists(_C.ASYNC_CONTROL_IMAGE))
    ck("G1: availability follows the configured path",
       AE._real_control_available() == avail, (AE._real_control_available(), avail))
    ck("G2: the control set follows availability",
       ("real_image_has_async" in AE._controls()) == avail, sorted(AE._controls()))
    ck("G3: the synthetic set always runs", len(AE._CONTROLS) == 4, AE._CONTROLS)
    ck("G4: the wording follows availability",
       ("No real-image control is configured" in st) == (not avail), (st[:70], avail))

    print("%d/%d passed" % (TOTAL[0] - len(FAIL), TOTAL[0]))
    if FAIL:
        print("FAILED: %s" % ", ".join(FAIL))
        return 1
    print("ALL PASS")
    return 0


def _raw(codefn, imports):
    """An image with hand-written code and the given imports."""
    import mkpe
    import pe as PEM
    d = tempfile.mkdtemp(prefix="test_async_")
    p = os.path.join(d, "v.bin")
    with open(p, "wb") as f:
        f.write(mkpe.build(code=codefn, imports=imports))
    return PEM.PE(p)


def _raises(fn, *a):
    try:
        fn(*a)
    except Exception:
        return True
    return False


if __name__ == "__main__":
    sys.exit(main())
