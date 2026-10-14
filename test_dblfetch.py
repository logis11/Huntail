#!/usr/bin/env python3
# test_dblfetch.py — the double-fetch detector. **Does it find the re-read, and
# does it refuse to fire on the three things that look like one?**
#
# This detector sits downstream of a gate that buries its own bug class: once
# `cfg.py` grew taint-lite, a double fetch earns a `flows` verdict (the first
# fetched value really does reach the sink) and passes R3. So a regression here
# does not surface as a wrong answer — it surfaces as a rejection that looks
# well-founded.
#
# The history is almost entirely about false positives and one false negative,
# and each one is a vector below:
#
#  · **A linear scan cannot work.** Walking a function in address order lets one
#    branch's register state leak into another, and the first version could not
#    even catch its own positive control — so its zero findings meant the
#    detector was broken, not that the target was clean. Hence the basic-block
#    dataflow, and hence `no_lineage` below.
#  · **`+0x20` is a union member.** `IO_STACK_LOCATION.Parameters` is a union, so
#    `+0x20` is `Type3InputBuffer` **only under DEVICE_CONTROL/FSCTL**. Without
#    that gate the detector reported kernel struct bookkeeping as a user-buffer
#    double fetch. Hence `no_devctl`.
#  · **A re-read of any struct field is not a double fetch.** It only holds when
#    the slot is user-controlled. Hence `kernel_slot`.
#  · **A truncated scan looks exactly like zero findings.** The first version
#    silently cut 64% of a large image. Hence the truncation vector.
#
# Everything runs against `mkpe.py` images with real `.pdata`; nothing here needs
# a target binary.
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


# ── building blocks ─────────────────────────────────────────────────────────
#   HEAD_SP   mov rax,[rdx+0xb8]   IRP -> CurrentStackLocation (rdx = IRP at entry)
#   DEVCTL    mov ecx,[rax+0x18]   touches IoControlCode -> this IS a DEVICE_CONTROL
#   USER      mov rsi,[rax+0x20]   Type3InputBuffer  (only valid once DEVCTL is seen)
#   USERBUF   mov rsi,[rdx+0x70]   Irp->UserBuffer   (straight off the IRP)
#   KERNOFF   mov rsi,[rax+0x40]   some other parameter slot — not user-controlled
#   BODY      cmp [rsi+0x10],8 ; jbe ; mov ecx,[rsi+0x10] ; mov eax,[rcx] ; ret
#             i.e. the same slot read once for the CHECK and once for the USE
HEAD_SP = b"\x48\x8b\x82\xb8\x00\x00\x00"
DEVCTL = b"\x8b\x48\x18"
USER = b"\x48\x8b\x70\x20"
USERBUF = b"\x48\x8b\x72\x70"
KERNOFF = b"\x48\x8b\x70\x40"
BODY = b"\x83\x7e\x10\x08\x76\x05\x8b\x4e\x10\x8b\x01\xc3"

POSITIVE = HEAD_SP + DEVCTL + USER + BODY
NO_DEVCTL = HEAD_SP + USER + BODY
KERNEL_SLOT = HEAD_SP + DEVCTL + KERNOFF + BODY
NO_LINEAGE = b"\x48\x8b\x73\x20" + BODY          # [rbx+0x20] out of nowhere
USERBUFFER = USERBUF + BODY
SINGLE_READ = USERBUF + b"\x83\x7e\x10\x08\xc3"  # checked once, never used again

# Two paths seed the user pointer into DIFFERENT registers and join at the read
# block, so the join block has two predecessors carrying different taint. A
# may-analysis has to union them; overwriting at the join loses one slot.
#   00 mov rax,[rdx+0xb8] | 07 mov ecx,[rax+0x18] | 0A test rdx,rdx | 0D je 0x15
#   0F mov rsi,[rax+0x20] | 13 jmp 0x19
#   15 mov rdi,[rax+0x20]
#   19 cmp [rsi+0x10],8 | 1D cmp [rdi+0x10],8 | 21 mov ecx,[rsi+0x10] | 24 mov edx,[rdi+0x10]
MERGE_POINT = (HEAD_SP + DEVCTL
               + b"\x48\x85\xd2\x74\x06"
               + b"\x48\x8b\x70\x20\xeb\x04"
               + b"\x48\x8b\x78\x20"
               + b"\x83\x7e\x10\x08\x83\x7f\x10\x08"
               + b"\x8b\x4e\x10\x8b\x57\x10\xc3")


def _img(code, pdata=((0x1000, 0x1040),)):
    import mkpe
    import pe as PEM
    d = tempfile.mkdtemp(prefix="test_dblfetch_")
    p = os.path.join(d, "v.bin")
    with open(p, "wb") as f:
        f.write(mkpe.build(code=code, pdata=list(pdata)))
    return PEM.PE(p)


def main():
    import dblfetch as DF

    # ── A. the positives ────────────────────────────────────────────────────
    rs = DF.scan(_img(POSITIVE))
    ck("A1: the Type3InputBuffer re-read is found", len(rs) == 1, rs)
    if rs:
        r = rs[0]
        ck("A2: it names the slot", r["slot"] == "[rsi+0x10]", r["slot"])
        ck("A3: it counts both reads", len(r["reads"]) == 2, r["reads"])
        ck("A4: one read is the check", r["validated"] is True, r)
        ck("A5: the other is a use", r["used"] is True, r)
        ck("A6: it is not an over-approximation", not r.get("approx"), r)

    rs = DF.scan(_img(USERBUFFER))
    ck("A7: Irp->UserBuffer needs no DEVICE_CONTROL evidence", len(rs) == 1, rs)

    # ── B. the union gate (the big false-positive killer) ───────────────────
    # Same lineage shape, but nothing in the function says this is a
    # DEVICE_CONTROL/FSCTL, so `+0x20` is just the fourth parameter slot.
    ck("B1: without IoControlCode/InputBufferLength, +0x20 is not a user buffer",
       DF.scan(_img(NO_DEVCTL)) == [], DF.scan(_img(NO_DEVCTL)))
    # And the gate is what makes the difference, not something else in the bytes:
    ck("B2: adding the IoControlCode touch is what turns it on",
       len(DF.scan(_img(POSITIVE))) == 1 and DF.scan(_img(NO_DEVCTL)) == [])

    # ── C. the other two negatives ──────────────────────────────────────────
    ck("C1: a non-user parameter slot is not tracked",
       DF.scan(_img(KERNEL_SLOT)) == [], DF.scan(_img(KERNEL_SLOT)))
    ck("C2: a pointer with no IRP lineage is not seeded",
       DF.scan(_img(NO_LINEAGE)) == [], DF.scan(_img(NO_LINEAGE)))
    ck("C3: a slot read once is not a double fetch",
       DF.scan(_img(SINGLE_READ)) == [], DF.scan(_img(SINGLE_READ)))

    # ── D. a truncated scan has to say so ───────────────────────────────────
    # Two non-adjacent chunks stay two functions, so `limit=1` really truncates.
    code = POSITIVE + b"\x90" * (0x38 - len(POSITIVE)) + b"\xc3"
    P = _img(code, pdata=((0x1000, 0x1030), (0x1038, 0x1050)))
    ck("D1: the image really has two functions", len(P.merged_functions()) == 2,
       P.merged_functions())
    rs = DF.scan(P, limit=1)
    tr = [r for r in rs if r["slot"] == "(TRUNCATED)"]
    ck("D2: truncation is announced", len(tr) == 1, rs)
    ck("D3: and it says it is not exhaustive",
       tr and "not exhaustive" in tr[0]["note"], tr)
    ck("D4: no limit means no truncation row",
       not any(r["slot"] == "(TRUNCATED)" for r in DF.scan(P)))

    # ── E. the module's own controls ────────────────────────────────────────
    ck("E1: the synthetic positive fires", DF._probe("user_slot_refetch") == 1)
    ck("E2: a kernel slot is ignored", DF._probe("kernel_slot_ignored") == 0)
    ck("E3: no lineage is ignored", DF._probe("no_lineage_ignored") == 0)
    import verifier_guard as _VG
    try:
        ck("E4: detect() produces a result once they pass",
           len(DF.detect(_img(POSITIVE))) == 1)
    except _VG.ControlFailed as e:
        # Refusing is right when a control genuinely failed; losing the tally is
        # not, so it is reported instead of raised.
        ck("E4: detect() produces a result once they pass", False, str(e)[:200])

    # ── F. control status is never silently optimistic ──────────────────────
    # The real-image false-positive control is optional; what is NOT optional is
    # saying when it did not run. A zero result with that control missing is the
    # one case where the omission matters most.
    st = DF.control_status()
    if DF._fp_control_available():
        ck("F1: a configured control is named", "all passed" in st, st)
    else:
        ck("F1: an unconfigured control is announced, loudly",
           "DID NOT RUN" in st, st)
        ck("F2: and the result is called UNMEASURED", "UNMEASURED" in st, st)
    ck("F3: the status mentions the union misread it guards against",
       "union" in st, st)
    # The dangerous direction is a status that claims a control ran when it did
    # not, so availability, the control set and the wording all have to agree.
    import config as _C
    avail = bool(getattr(_C, "DBLFETCH_FP_CONTROL", "")
                 and os.path.exists(_C.DBLFETCH_FP_CONTROL))
    ck("F4: availability follows the configured path",
       DF._fp_control_available() == avail, (DF._fp_control_available(), avail))
    ck("F5: the control set follows availability",
       ("real_union_misread" in DF._controls()) == avail, sorted(DF._controls()))
    ck("F6: the wording follows availability",
       ("DID NOT RUN" in st) == (not avail), (st[:60], avail))

    # ── G. the dataflow joins at merge points ───────────────────────────────
    # A block-local analysis would lose the taint across the branch. The positive
    # vector's second read is in the fall-through block, not the guard block, so
    # finding it at all proves the join.
    rs = DF.scan(_img(POSITIVE))
    if rs:
        addrs = sorted(x["va"] for x in rs[0]["reads"])
        ck("G1: the two reads are in different blocks",
           len(addrs) == 2 and addrs[1] > addrs[0] + 2, [hex(a) for a in addrs])

    # Two predecessors, different taint. Union keeps both slots; overwriting at
    # the join keeps one, and the lost one looks exactly like "no double fetch".
    rs = DF.scan(_img(MERGE_POINT))
    slots = sorted(r["slot"] for r in rs)
    ck("G2: taint from both predecessors survives the join",
       slots == ["[rdi+0x10]", "[rsi+0x10]"], slots)
    ck("G3: and both are check-and-use",
       all(r["validated"] and r["used"] for r in rs), rs)

    print("%d/%d passed" % (TOTAL[0] - len(FAIL), TOTAL[0]))
    if FAIL:
        print("FAILED: %s" % ", ".join(FAIL))
        return 1
    print("ALL PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
