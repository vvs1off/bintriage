"""Generators for tiny, harmless, deterministic binaries used in tests.

Everything here is built from struct packs: no real executables are committed to
the repository. Each generator produces the smallest file the matching parser
accepts, with one imported symbol and one section so the full pipeline exercises.
"""

from __future__ import annotations

import struct


def make_elf64() -> bytes:
    """A minimal 64-bit little-endian ELF importing ``connect`` from libc."""
    # String tables -------------------------------------------------------
    shstrtab = b"\x00.shstrtab\x00.dynstr\x00.dynsym\x00.dynamic\x00.text\x00"

    def shname(label: bytes) -> int:
        return shstrtab.index(label)

    dynstr = b"\x00libc.so.6\x00connect\x00"
    off_libc = dynstr.index(b"libc.so.6")
    off_connect = dynstr.index(b"connect")

    # .dynsym: null symbol + one undefined STT_FUNC named "connect".
    sym_null = struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)
    sym_connect = struct.pack("<IBBHQQ", off_connect, (1 << 4) | 2, 0, 0, 0, 0)
    dynsym = sym_null + sym_connect

    # .dynamic: DT_NEEDED(libc) then DT_NULL.
    dynamic = struct.pack("<qQ", 1, off_libc) + struct.pack("<qQ", 0, 0)

    text = b"\x90" * 16  # low-entropy NOP sled

    # Lay out section contents after the 64-byte header.
    cur = 64
    placements = {}
    for key, body in (
        ("shstrtab", shstrtab), ("dynstr", dynstr),
        ("dynsym", dynsym), ("dynamic", dynamic), ("text", text),
    ):
        placements[key] = (cur, len(body))
        cur += len(body)
    shoff = cur

    # Section header table ------------------------------------------------
    SHT_PROGBITS, SHT_STRTAB, SHT_DYNSYM, SHT_DYNAMIC = 1, 3, 11, 6
    idx = {"shstrtab": 1, "dynstr": 2, "dynsym": 3, "dynamic": 4, "text": 5}

    def shdr(name_off, stype, off, size, link):
        return struct.pack("<IIQQQQIIQQ", name_off, stype, 0, 0, off, size, link, 0, 1, 0)

    headers = [shdr(0, 0, 0, 0, 0)]  # SHT_NULL
    headers.append(shdr(shname(b".shstrtab"), SHT_STRTAB, *placements["shstrtab"], 0))
    headers.append(shdr(shname(b".dynstr"), SHT_STRTAB, *placements["dynstr"], 0))
    headers.append(shdr(shname(b".dynsym"), SHT_DYNSYM, *placements["dynsym"], idx["dynstr"]))
    headers.append(shdr(shname(b".dynamic"), SHT_DYNAMIC, *placements["dynamic"], idx["dynstr"]))
    headers.append(shdr(shname(b".text"), SHT_PROGBITS, *placements["text"], 0))

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7
    header = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2, 0x3E, 1, 0, 0, shoff, 0, 64, 0, 0, 64, len(headers), idx["shstrtab"],
    )

    body = bytearray(header)
    for key in ("shstrtab", "dynstr", "dynsym", "dynamic", "text"):
        off, size = placements[key]
        assert len(body) == off
        body += {"shstrtab": shstrtab, "dynstr": dynstr, "dynsym": dynsym,
                 "dynamic": dynamic, "text": text}[key]
    assert len(body) == shoff
    for h in headers:
        body += h
    return bytes(body)


def make_pe32() -> bytes:
    """A minimal 32-bit PE importing ``connect`` from ws2_32.dll."""
    vaddr = 0x1000
    sec = bytearray()
    off_descr = 0
    off_ilt = 40
    off_ibn = 48
    off_dll = 58

    ibn = struct.pack("<H", 0) + b"connect\x00"       # hint + name
    dll = b"ws2_32.dll\x00"

    descr = struct.pack(
        "<IIIII", vaddr + off_ilt, 0, 0, vaddr + off_dll, vaddr + off_ilt
    )
    null_descr = b"\x00" * 20
    ilt = struct.pack("<II", vaddr + off_ibn, 0)

    sec += descr                 # 0..20
    sec += null_descr            # 20..40
    sec += ilt                   # 40..48
    sec += ibn                   # 48..58
    sec += dll                   # 58..
    raw_size = (len(sec) + 0x1FF) & ~0x1FF
    sec += b"\x00" * (raw_size - len(sec))

    pe_off = 0x80
    opt_size = 0xE0
    raw_off = 0x200

    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, opt_size, 0x0102)

    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x10B)        # magic PE32
    struct.pack_into("<I", opt, 92, 16)          # NumberOfRvaAndSizes
    struct.pack_into("<II", opt, 96 + 8, vaddr + off_descr, len(descr) + 20)  # import dir

    section = struct.pack(
        "<8sIIIIIIHHI", b".idata\x00\x00", len(sec), vaddr, raw_size, raw_off,
        0, 0, 0, 0, 0xC0000040,
    )

    out = bytearray(b"\x00" * raw_off)
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, pe_off)
    body = b"PE\x00\x00" + coff + bytes(opt) + section
    out[pe_off:pe_off + len(body)] = body
    out += sec
    return bytes(out)


def make_macho64() -> bytes:
    """A minimal 64-bit little-endian Mach-O importing ``_connect``."""
    def align8(n: int) -> int:
        return (n + 7) & ~7

    # Build load commands first with placeholder file offsets, then patch.
    # Segment command (__TEXT) with one __text section.
    seg_cmdsize = 72 + 80

    dylib_name = b"/usr/lib/libSystem.B.dylib\x00"
    dylib_name += b"\x00" * (align8(24 + len(dylib_name)) - (24 + len(dylib_name)))
    dylib_cmdsize = 24 + len(dylib_name)

    symtab_cmdsize = 24

    header_size = 32
    cmds_size = seg_cmdsize + dylib_cmdsize + symtab_cmdsize
    data_start = header_size + cmds_size

    text_bytes = b"\x90" * 16
    text_off = data_start
    nlist_off = text_off + len(text_bytes)
    strtab = b"\x00_connect\x00"
    str_off = nlist_off + 16

    # Header (64-bit has a trailing reserved field -> 8 words, 32 bytes)
    header = struct.pack(
        "<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, 3, cmds_size, 0, 0
    )

    # Segment
    seg = struct.pack("<II", 0x19, seg_cmdsize)
    seg += b"__TEXT".ljust(16, b"\x00")
    seg += struct.pack("<QQQQiiII", 0, len(text_bytes), 0, len(text_bytes), 7, 5, 1, 0)
    section = b"__text".ljust(16, b"\x00") + b"__TEXT".ljust(16, b"\x00")
    section += struct.pack("<QQIIIIIIII", 0, len(text_bytes), text_off, 0, 0, 0, 0, 0, 0, 0)
    seg += section

    # Dylib
    dylib = struct.pack("<IIIIII", 0xC, dylib_cmdsize, 24, 0, 0x10000, 0x10000)
    dylib += dylib_name

    # Symtab
    symtab = struct.pack("<IIIIII", 0x2, symtab_cmdsize, nlist_off, 1, str_off, len(strtab))

    nlist = struct.pack("<IBBHQ", 1, 0x01, 0, 0, 0)  # n_strx=1 -> "_connect", N_EXT|N_UNDF

    out = bytearray()
    out += header + seg + dylib + symtab
    assert len(out) == data_start, (len(out), data_start)
    out += text_bytes
    out += nlist
    out += strtab
    return bytes(out)


def make_macho_fat() -> bytes:
    """A universal binary wrapping a single x86-64 Mach-O slice."""
    thin = make_macho64()
    slice_off = 4096
    header = struct.pack(">II", 0xCAFEBABE, 1)
    arch = struct.pack(">iiIII", 0x01000007, 3, slice_off, len(thin), 12)
    out = bytearray(header + arch)
    out += b"\x00" * (slice_off - len(out))
    out += thin
    return bytes(out)
