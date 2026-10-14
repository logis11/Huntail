#!/usr/bin/env python3
# async_entry.py — **enumerate every asynchronous entry point.**
#
# Why it is needed: across a whole ledger of 604 surface rows, **one** was shaped
# like a race hypothesis — and the only confirmed memory-safety bug in that
# ledger (a UAF) came out of that one row. The unit of the surface table was a
# **single request**, so there was no row a race could live in: never filed, so
# never even recorded as unanalysed, so missing from the denominator entirely.
#
# A race is a property of (T_A, T_B) plus an **asynchronous third party.** The
# third party does not have to be guessed — it is registered with the kernel
# through a **registration API**, so it can be enumerated statically. That is
# what this module does.
#
# These entries are `reach="user-triggerable-async"`. Do not discard them as
# `kernel-only`: in that UAF the killer was a **PnP thread**, and all the user
# did was trigger re-enumeration with an IOCTL.
#
# Ported note: upstream's positive controls were pinned to a specific driver on
# disk, which makes the control target material and makes the module dead
# wherever that file is absent. The controls here are **synthetic** — built with
# `mkpe`, answers known by construction — including a negative that pins the
# historical `.rdata`-reported-as-a-callback bug. An optional real-image control
# can be added through `config.ASYNC_CONTROL_IMAGE`.
import capstone
from capstone import x86 as X

import config
import verifier_guard as VG
import xref as XR

# registration API -> the context its callback runs in
REGISTRARS = {
    "IoSetCancelRoutine":            "cancel (IRP cancellation — arbitrary time, outside the lock)",
    "IoSetCompletionRoutine":        "completion (when a lower driver completes)",
    "IoSetCompletionRoutineEx":      "completion",
    "IoQueueWorkItem":               "work item (system worker thread)",
    "IoQueueWorkItemEx":             "work item",
    "IoAllocateWorkItem":            "work item allocation (takes no callback — queueing is separate)",
    "ExQueueWorkItem":               "work item (legacy)",
    "ExInitializeWorkItem":          "work item",
    "KeInitializeDpc":               "DPC (DISPATCH_LEVEL, arbitrary CPU)",
    "KeInsertQueueDpc":              "DPC",
    "KeInitializeTimer":             "timer",
    "KeSetTimer":                    "timer",
    "KeSetTimerEx":                  "timer",
    "IoRegisterPlugPlayNotification": "PnP notification",
    "IoRegisterDeviceInterface":     "PnP interface",
    "PsSetCreateProcessNotifyRoutine": "process notification",
    "PsSetCreateThreadNotifyRoutine":  "thread notification",
    "PsSetLoadImageNotifyRoutine":     "image-load notification",
    "IoRegisterShutdownNotification":  "shutdown",
    "KeRegisterBugCheckCallback":      "bugcheck",
}

LOOKBACK = 12          # how many instructions before the call to search for a lea


def _md():
    m = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    m.detail = True
    return m


# Only the registration APIs that **take a callback argument.** The rest are
#   counted for visibility but no callback recovery is attempted.
#   (`IoAllocateWorkItem(PDEVICE_OBJECT)` takes no callback. The first version
#    still picked up the preceding `lea` and reported an `.rdata` address as "the
#    callback" — which compounded with the `_in_text` bug below into a large
#    false-positive count.)
HAS_CALLBACK = {
    "IoSetCancelRoutine", "IoSetCompletionRoutine", "IoSetCompletionRoutineEx",
    "IoQueueWorkItem", "IoQueueWorkItemEx", "ExQueueWorkItem", "ExInitializeWorkItem",
    "KeInitializeDpc", "IoRegisterPlugPlayNotification",
    "PsSetCreateProcessNotifyRoutine", "PsSetCreateThreadNotifyRoutine",
    "PsSetLoadImageNotifyRoutine", "IoRegisterShutdownNotification",
    "KeRegisterBugCheckCallback",
}


def _exec_ranges(pe):
    """The range of **each** executable section, separately. Collapsing them into
    one min/max range is wrong — PAGE and INIT sections sit after the data
    sections, so one range swallows `.rdata` and `.data` whole, and `.rdata`
    addresses then get reported as callbacks."""
    return [(pe.base + s["va"], pe.base + s["va"] + max(s["vsize"], s["rsize"]))
            for s in pe.secs if s["chars"] & 0x20000000]


def _in_text(rngs, va):
    return any(a <= va < b for a, b in rngs)


def scan(pe):
    """Recover the **callback address** at each registration call site.

    Method: in the LOOKBACK instructions before the call, find a
    `lea reg, [rip+disp]` whose target lands in an executable section. On x64 a
    callback is almost always passed that way.

    Limits (always report them): (1) a callback stashed in a register far earlier
    is missed; (2) one loaded from a vtable or a global is invisible; (3) this is
    a linear sweep, so it can desync.
    => **This is a candidate generator.** Absence here is not "no asynchronous
    entry points".
    """
    md = _md()
    rngs = _exec_ranges(pe)
    lo = min(a for a, _b in rngs) if rngs else 0
    hits, _cov, names = XR.sweep(pe, list(REGISTRARS), kinds=("call", "jmp"))
    out = []
    for h in hits:
        nm = h.get("name") or ""
        base = next((k for k in REGISTRARS if k.lower() in nm.lower()), None)
        if not base:
            continue
        site = h["va"]
        if base not in HAS_CALLBACK:
            out.append({"registrar": base, "context": REGISTRARS[base], "site": site,
                        "callback": None, "lea_at": None, "no_callback_arg": True,
                        "section": h.get("section")})
            continue
        start = max(site - 96, lo)
        d = pe.read(start, site - start)
        if not d:
            continue
        cb = None
        for i in list(md.disasm(bytes(d), start))[-LOOKBACK:]:
            if i.mnemonic != "lea" or len(i.operands) != 2:
                continue
            op = i.operands[1]
            if op.type != X.X86_OP_MEM or op.mem.base == 0:
                continue
            if md.reg_name(op.mem.base) != "rip":
                continue
            tgt = i.address + i.size + op.mem.disp
            if _in_text(rngs, tgt):
                cb = (tgt, i.address)
        out.append({"registrar": base, "context": REGISTRARS[base], "site": site,
                    "callback": cb[0] if cb else None,
                    "lea_at": cb[1] if cb else None,
                    "section": h.get("section")})
    out.sort(key=lambda r: (r["registrar"], r["site"]))
    return out


# ── Controls ────────────────────────────────────────────────────────────────
#   A broken detector and "no asynchronous entry points" produce the same output,
#   so the detector does not get to speak until it has caught something it is
#   known to have planted itself.
_SYNTH_CB = 0x140001100            # inside .text of the synthetic image
_SYNTH_RDATA = 0x140002000         # inside .rdata — must NOT be reported


def _synthetic(callback_va):
    """A synthetic driver that registers one completion routine at
    `callback_va`. Returns the PE object."""
    import os
    import struct
    import tempfile

    import mkpe
    import pe as PEmod

    def code(slots):
        base = mkpe.IMAGE_BASE + mkpe.TEXT_VA
        d1 = callback_va - (base + 7)
        d2 = slots["IoSetCompletionRoutine"] - (base + 13)
        return (b"\x48\x8d\x0d" + struct.pack("<i", d1)       # lea rcx, [rip+d1]
                + b"\xff\x15" + struct.pack("<i", d2))        # call qword [rip+d2]

    blob = mkpe.build(code=code, imports={"ntoskrnl.exe": ["IoSetCompletionRoutine"]})
    p = os.path.join(tempfile.mkdtemp(prefix="async_ctl_"), "synth.bin")
    with open(p, "wb") as f:
        f.write(blob)
    return PEmod.PE(p)


def _control_probe(label):
    import os

    import mkpe
    import pe as PEmod
    if label == "synthetic_callback_recovered":
        # Positive: a callback planted in .text must come back, at that address.
        rs = scan(_synthetic(_SYNTH_CB))
        return len([r for r in rs if r["callback"] == _SYNTH_CB])
    if label == "rdata_callback_rejected":
        # Negative, and it pins a real regression: when the executable ranges
        # were collapsed into one min/max span, an `.rdata` target was reported
        # as the callback.
        rs = scan(_synthetic(_SYNTH_RDATA))
        return len([r for r in rs if r["callback"] is not None])
    if label == "callbacks_in_text":
        p = _synthetic(_SYNTH_CB)
        rngs = _exec_ranges(p)
        bad = [r for r in scan(p) if r["callback"] and not _in_text(rngs, r["callback"])]
        return 0 if bad else 1
    if label == "no_imports_zero":
        # Negative: an image importing no registration API yields nothing.
        import tempfile
        p = os.path.join(tempfile.mkdtemp(prefix="async_ctl_"), "bare.bin")
        with open(p, "wb") as f:
            f.write(mkpe.build())
        return len(scan(PEmod.PE(p)))
    if label == "real_image_has_async":
        path = config.ASYNC_CONTROL_IMAGE
        if not path or not os.path.exists(path):
            raise RuntimeError("control image not available: %r" % path)
        return len([r for r in scan(PEmod.PE(path)) if r["callback"]])
    raise RuntimeError("unknown control label: %r" % label)


_CONTROLS = {"synthetic_callback_recovered": 1,   # positive  (synthetic)
             "callbacks_in_text": 1,              # positive  (synthetic)
             "rdata_callback_rejected": 0,        # negative  (pins the .rdata bug)
             "no_imports_zero": 0}                # negative  (synthetic)
_REAL_CONTROL = {"real_image_has_async": 1}       # positive  (optional, real image)


def _real_control_available():
    import os
    return bool(getattr(config, "ASYNC_CONTROL_IMAGE", "")
                and os.path.exists(config.ASYNC_CONTROL_IMAGE))


def _controls():
    c = dict(_CONTROLS)
    if _real_control_available():
        c.update(_REAL_CONTROL)
    return c


def control_status():
    """Which controls ran. The synthetic set always runs, so a zero result is a
    real zero rather than a silent malfunction."""
    n = len(_CONTROLS)
    if _real_control_available():
        return ("controls: %d synthetic (2 positive, 2 negative) + 1 real image (%s) — "
                "all passed." % (n, config.ASYNC_CONTROL_IMAGE))
    return ("controls: %d synthetic (2 positive, 2 negative) — all passed. No real-image "
            "control is configured (config.ASYNC_CONTROL_IMAGE); the synthetic positive "
            "proves the recovery path works, not that it matches any particular compiler's "
            "output." % n)


def enumerate_async(pe):
    """No result until the controls check out."""
    @VG.guarded("async_entry", _controls(), probe=_control_probe,
                expect=lambda want, got: (got >= want) if want else (got == 0))
    def _run():
        return scan(pe)

    return _run()


if __name__ == "__main__":
    import collections
    import sys

    import pe as PEmod
    p = PEmod.PE(sys.argv[1])
    rs = enumerate_async(p)
    got = [r for r in rs if r["callback"]]
    print("%d registration site(s), %d callback(s) recovered (%d not — may be passed via a "
          "register or read from a global)" % (len(rs), len(got), len(rs) - len(got)))
    for k, c in collections.Counter(r["registrar"] for r in rs).most_common():
        print("   %-34s %d  [%s]" % (k, c, REGISTRARS[k]))
    print("\nCallbacks (race-counterparty candidates — reach=user-triggerable-async):")
    for r in got:
        print("   0x%X  <- %s @0x%X" % (r["callback"], r["registrar"], r["site"]))
    print("\n" + control_status())
