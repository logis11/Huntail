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


def _section(name, va, vsize, raw, rsize, chars):
    return (name.encode().ljust(8, b"\0")
            + struct.pack("<IIII", vsize, va, rsize, raw)
            + struct.pack("<IIHHI", 0, 0, 0, 0, chars))


def build(code=CODE, dllchar=0x4160):
    """Return the bytes of a PE32+ with one .text and one .rdata section.

    dllchar defaults to HIGH_ENTROPY_VA | DYNAMIC_BASE | NX | GUARD_CF so that
    `PE.mitigations()` has something to report.
    """
    nsec = 2
    optsz = 240                                   # standard PE32+ optional header
    pe_off = 0x80
    hdr_end = pe_off + 24 + optsz + 40 * nsec
    text_raw = FILE_ALIGN * ((hdr_end + FILE_ALIGN - 1) // FILE_ALIGN)
    rdata_raw = text_raw + FILE_ALIGN

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
    struct.pack_into("<I", opt, 56, RDATA_VA + SEC_ALIGN)      # SizeOfImage
    struct.pack_into("<I", opt, 60, text_raw)                  # SizeOfHeaders
    struct.pack_into("<H", opt, 70, dllchar)                   # DllCharacteristics
    struct.pack_into("<I", opt, 108, 16)                       # NumberOfRvaAndSizes

    secs = (_section(".text", TEXT_VA, max(len(code), 0x200), text_raw, FILE_ALIGN, _CHAR_CODE)
            + _section(".rdata", RDATA_VA, 0x200, rdata_raw, FILE_ALIGN, _CHAR_RDATA))

    out = bytearray(dos + b"PE\0\0" + coff + bytes(opt) + secs)
    out += b"\0" * (text_raw - len(out))
    out += code.ljust(FILE_ALIGN, b"\xCC")
    out += b"\xAA" * FILE_ALIGN                                # .rdata payload
    return bytes(out)


def write(path, **kw):
    with open(path, "wb") as f:
        f.write(build(**kw))
    return path


if __name__ == "__main__":
    import sys
    print(write(sys.argv[1] if len(sys.argv) > 1 else "synthetic.bin"))
