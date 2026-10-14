#!/usr/bin/env python3
# mkpe.py — build a minimal, valid PE32+ in memory, for tests.
#
# Why this exists: the anchor gate is the load-bearing part of this harness, and a
# test for it has to run `evidence.check()` against **a real image** — the parser
# alone is only half of it. Shipping a binary to test against is not an option
# (it would be target material), and skipping the test when no binary is around
# is how a gate rots: the suite stays green because it stopped looking.
#
# So the test builds its own image with instruction bytes it chose itself. The
# expected answers are known by construction, which is the same property the
# positive controls in `verifier_guard` are after.
import struct

IMAGE_BASE = 0x140000000
TEXT_VA    = 0x1000          # -> 0x140001000
RDATA_VA   = 0x2000          # -> 0x140002000
IDATA_VA   = 0x3000          # -> 0x140003000, only when `imports` is given
PDATA_VA   = 0x4000          # -> 0x140004000, only when `pdata` is given
SEC_ALIGN  = 0x1000
FILE_ALIGN = 0x200

# x86-64 bytes placed at the start of .text. Chosen so the test can cite them.
CODE = (
    b"\xB8\x01\x00\x00\x00"          # 0x140001000  mov eax, 1
    b"\x83\xF8\x03"                  # 0x140001005  cmp eax, 3
    b"\x48\x8B\x41\x18"              # 0x140001008  mov rax, qword ptr [rcx + 0x18]
    b"\x74\x05"                      # 0x14000100c  je 0x140001013
)

_CHAR_CODE   = 0x60000020            # CODE | EXECUTE | READ
_CHAR_RDATA  = 0x40000040            # INITIALIZED_DATA | READ


def _align(n, to=FILE_ALIGN):
    return to * ((n + to - 1) // to)


def _section(name, va, vsize, raw, rsize, chars):
    return (name.encode().ljust(8, b"\0")
            + struct.pack("<IIII", vsize, va, rsize, raw)
            + struct.pack("<IIHHI", 0, 0, 0, 0, chars))


def plan_imports(imports, va=IDATA_VA):
    """Lay out an import directory at RVA `va`.

    Returns (blob, {func_name: iat_rva}). A detector that resolves imports (an
    async-registrar sweep, a guard scan, a BYOVD primitive scan) needs named
    imports to have a control at all, and pinning its control to a real driver
    makes the control target material. This gives it a synthetic one instead,
    with the answers known by construction.

    `imports` is {dll_name: [func, ...]}.
    """
    regions, cur = [], (len(imports) + 1) * 20
    for dll, funcs in imports.items():
        funcs = list(funcs)
        ilt = cur
        cur += 8 * (len(funcs) + 1)
        iat = cur
        cur += 8 * (len(funcs) + 1)
        regions.append((dll, funcs, ilt, iat))
    at = {}
    for dll, funcs, _ilt, _iat in regions:
        at[("dll", dll)] = cur
        cur += len(dll) + 1
        for f in funcs:
            at[("fn", f)] = cur
            cur += 2 + len(f) + 1                 # Hint word + name + NUL
    blob = bytearray(cur)
    for k, (dll, funcs, ilt, iat) in enumerate(regions):
        # IMAGE_IMPORT_DESCRIPTOR; the trailing all-zero one terminates the list.
        struct.pack_into("<IIIII", blob, k * 20,
                         va + ilt, 0, 0, va + at[("dll", dll)], va + iat)
        for j, f in enumerate(funcs):
            struct.pack_into("<Q", blob, ilt + 8 * j, va + at[("fn", f)])
            struct.pack_into("<Q", blob, iat + 8 * j, va + at[("fn", f)])
        o = at[("dll", dll)]
        blob[o:o + len(dll)] = dll.encode()
        for f in funcs:
            o = at[("fn", f)]
            struct.pack_into("<H", blob, o, 0)    # Hint
            blob[o + 2:o + 2 + len(f)] = f.encode()
    slots = {f: va + iat + 8 * j
             for _dll, funcs, _ilt, iat in regions
             for j, f in enumerate(funcs)}
    return bytes(blob), slots


def build(code=CODE, dllchar=0x4160, imports=None, pdata=None):
    """Return the bytes of a PE32+ with one .text and one .rdata section.

    dllchar defaults to HIGH_ENTROPY_VA | DYNAMIC_BASE | NX | GUARD_CF so that
    `PE.mitigations()` has something to report.

    With `imports` ({dll: [func, ...]}) a non-executable `.idata` section carries
    a real import directory, so `xref.iat` resolves the names. `code` may then be
    a callable taking {func_name: iat_va} and returning the bytes, which is how a
    test emits a real `call qword ptr [rip+disp]` at an import slot.

    With `pdata` ([(begin_va, end_va), ...]) a `.pdata` section carries a real
    RUNTIME_FUNCTION array, so `PE.runtime_functions()` / `func_bounds()` /
    `merged_functions()` work. Everything built on the CFG — dominance, taint,
    the double-fetch dataflow, the guard sweep — needs function bounds and
    refuses to guess them, so without this there is no way to test any of it
    against an image. Addresses may be given as VAs or as RVAs.

    Passing neither leaves the output byte-for-byte what it was before.
    """
    idata = b""
    if imports:
        idata, slots = plan_imports(imports)
        if callable(code):
            code = code({f: IMAGE_BASE + rva for f, rva in slots.items()})
    elif callable(code):
        raise TypeError("a callable `code` needs `imports` to resolve slots against")
    pblob = b""
    if pdata:
        rows = bytearray()
        for b_, e_ in pdata:
            b_ = b_ - IMAGE_BASE if b_ >= IMAGE_BASE else b_
            e_ = e_ - IMAGE_BASE if e_ >= IMAGE_BASE else e_
            # RUNTIME_FUNCTION {BeginAddress, EndAddress, UnwindInfoAddress}
            rows += struct.pack("<III", b_, e_, 0)
        pblob = bytes(rows)
    nsec = 2 + (1 if imports else 0) + (1 if pdata else 0)
    optsz = 240                                   # standard PE32+ optional header
    pe_off = 0x80
    hdr_end = pe_off + 24 + optsz + 40 * nsec
    text_raw = _align(hdr_end)
    text_rsize = _align(max(len(code), 0x200))
    rdata_raw = text_raw + text_rsize
    idata_raw = rdata_raw + FILE_ALIGN
    idata_rsize = _align(len(idata)) or FILE_ALIGN
    pdata_raw = (idata_raw + idata_rsize) if imports else (rdata_raw + FILE_ALIGN)
    pdata_rsize = _align(len(pblob)) or FILE_ALIGN

    dos = bytearray(pe_off)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, pe_off)

    coff = struct.pack("<HHIIIHH", 0x8664, nsec, 0x66000000, 0, 0, optsz, 0x2022)

    opt = bytearray(optsz)
    struct.pack_into("<H", opt, 0, 0x20B)                      # magic PE32+
    struct.pack_into("<I", opt, 16, TEXT_VA)                   # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 24, IMAGE_BASE)                # ImageBase
    struct.pack_into("<I", opt, 32, SEC_ALIGN)                 # SectionAlignment
    struct.pack_into("<I", opt, 36, FILE_ALIGN)                # FileAlignment
    last_va = PDATA_VA if pdata else (IDATA_VA if imports else RDATA_VA)
    struct.pack_into("<I", opt, 56, last_va + SEC_ALIGN)       # SizeOfImage
    struct.pack_into("<I", opt, 60, text_raw)                  # SizeOfHeaders
    struct.pack_into("<H", opt, 70, dllchar)                   # DllCharacteristics
    struct.pack_into("<I", opt, 108, 16)                       # NumberOfRvaAndSizes
    if imports:
        # DataDirectory[1] = IMPORT. Offset 112 is the directory array.
        struct.pack_into("<II", opt, 112 + 8, IDATA_VA, len(idata))
    if pdata:
        # DataDirectory[3] = EXCEPTION (.pdata)
        struct.pack_into("<II", opt, 112 + 24, PDATA_VA, len(pblob))

    secs = (_section(".text", TEXT_VA, max(len(code), 0x200), text_raw,
                     text_rsize, _CHAR_CODE)
            + _section(".rdata", RDATA_VA, 0x200, rdata_raw, FILE_ALIGN, _CHAR_RDATA))
    if imports:
        secs += _section(".idata", IDATA_VA, max(len(idata), 0x200),
                         idata_raw, idata_rsize, _CHAR_RDATA)
    if pdata:
        secs += _section(".pdata", PDATA_VA, max(len(pblob), 0x200),
                         pdata_raw, pdata_rsize, _CHAR_RDATA)

    out = bytearray(dos + b"PE\0\0" + coff + bytes(opt) + secs)
    out += b"\0" * (text_raw - len(out))
    out += code.ljust(text_rsize, b"\xCC")
    out += b"\xAA" * FILE_ALIGN                                # .rdata payload
    if imports:
        out += idata.ljust(idata_rsize, b"\0")
    if pdata:
        out += pblob.ljust(pdata_rsize, b"\0")
    return bytes(out)


def write(path, **kw):
    with open(path, "wb") as f:
        f.write(build(**kw))
    return path


if __name__ == "__main__":
    import sys
    print(write(sys.argv[1] if len(sys.argv) > 1 else "synthetic.bin"))
