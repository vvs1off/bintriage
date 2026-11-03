"""Minimal Mach-O parser (thin and universal/fat)."""

from __future__ import annotations

import struct

from ..categories import categorize
from ..entropy import is_packed, shannon_entropy
from ..report import Import, ParseError, Report, Section

_CPU = {
    7: "x86", 0x01000007: "x86-64", 12: "arm", 0x0100000C: "arm64",
    18: "ppc", 0x01000012: "ppc64",
}
_FILETYPES = {
    1: "object", 2: "executable", 3: "fixed-vm-lib", 4: "core",
    5: "preload", 6: "dylib", 7: "dylinker", 8: "bundle",
}

_LC_SEGMENT = 0x1
_LC_SEGMENT_64 = 0x19
_LC_SYMTAB = 0x2
_LC_LOAD_DYLIB = 0xC
_LC_LOAD_WEAK_DYLIB = 0x80000018
_LC_REEXPORT_DYLIB = 0x8000001F
_DYLIB_CMDS = {_LC_LOAD_DYLIB, _LC_LOAD_WEAK_DYLIB, _LC_REEXPORT_DYLIB}

_N_TYPE = 0x0E
_N_EXT = 0x01
_N_UNDF = 0x00
_S_ZEROFILL = 0x1


def _magic_props(head: bytes) -> tuple[str, int]:
    table = {
        b"\xce\xfa\xed\xfe": ("little", 32),
        b"\xcf\xfa\xed\xfe": ("little", 64),
        b"\xfe\xed\xfa\xce": ("big", 32),
        b"\xfe\xed\xfa\xcf": ("big", 64),
    }
    return table[head[:4]]


def parse(data: bytes, path: str, fat: bool = False) -> Report:
    note = None
    if fat:
        data, note = _select_fat_slice(data)
    if len(data) < 28:
        raise ParseError("file too small to be Mach-O")
    endian, bits = _magic_props(data)
    pre = "<" if endian == "little" else ">"
    header_size = 32 if bits == 64 else 28
    _magic, cputype, _sub, filetype, ncmds, _sizeofcmds, _flags = struct.unpack_from(
        pre + "IiiIIII", data, 0
    )

    report = Report(
        path=path,
        size=len(data),
        fmt="Mach-O",
        arch=_CPU.get(cputype & 0xFFFFFFFF, f"unknown(0x{cputype & 0xFFFFFFFF:x})"),
        bits=bits,
        endian=endian,
        filetype=_FILETYPES.get(filetype, f"unknown({filetype})"),
    )
    if note:
        report.notes.append(note)

    off = header_size
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack_from(pre + "II", data, off)
        if cmdsize < 8 or off + cmdsize > len(data):
            break
        if cmd in (_LC_SEGMENT, _LC_SEGMENT_64):
            report.sections.extend(_read_segment(data, pre, off, cmd))
        elif cmd in _DYLIB_CMDS:
            name = _read_lc_str(data, off, cmdsize, pre)
            if name:
                report.libraries.append(name.rsplit("/", 1)[-1])
        elif cmd == _LC_SYMTAB:
            report.imports.extend(_read_symtab(data, pre, bits, off))
        off += cmdsize

    # Collapse duplicate imported symbols while preserving order.
    report.imports = _dedupe(report.imports)
    return report


def _select_fat_slice(data: bytes) -> tuple[bytes, str]:
    # Fat headers are always big-endian.
    magic, nfat = struct.unpack_from(">II", data, 0)
    is64 = magic == 0xCAFEBABF
    entry_size = 32 if is64 else 20
    archs = []
    first = None
    for i in range(nfat):
        base = 8 + i * entry_size
        if base + entry_size > len(data):
            break
        if is64:
            cputype, _sub, soff, ssize, _align, _res = struct.unpack_from(">iiQQII", data, base)
        else:
            cputype, _sub, soff, ssize, _align = struct.unpack_from(">iiIII", data, base)
        archs.append(_CPU.get(cputype & 0xFFFFFFFF, f"0x{cputype & 0xFFFFFFFF:x}"))
        if first is None:
            first = (soff, ssize)
    if first is None:
        raise ParseError("universal binary has no architecture slices")
    soff, ssize = first
    slice_bytes = data[soff:soff + ssize]
    note = f"universal binary: {nfat} slice(s) [{', '.join(archs)}]; showing first"
    return slice_bytes, note


def _read_segment(data, pre, off, cmd):
    sections = []
    if cmd == _LC_SEGMENT_64:
        nsects = struct.unpack_from(pre + "I", data, off + 64)[0]
        sec_start = off + 72
        sec_size = 80
    else:
        nsects = struct.unpack_from(pre + "I", data, off + 48)[0]
        sec_start = off + 56
        sec_size = 68
    for i in range(nsects):
        base = sec_start + i * sec_size
        if base + sec_size > len(data):
            break
        sectname = data[base:base + 16].split(b"\x00", 1)[0].decode("latin-1", "replace")
        segname = data[base + 16:base + 32].split(b"\x00", 1)[0].decode("latin-1", "replace")
        if cmd == _LC_SEGMENT_64:
            _addr, size, foff, _align, _rel, _nrel, flags = struct.unpack_from(
                pre + "QQIIIII", data, base + 32
            )
        else:
            _addr, size, foff, _align, _rel, _nrel, flags = struct.unpack_from(
                pre + "IIIIIII", data, base + 32
            )
        name = f"{segname},{sectname}"
        if (flags & 0xFF) == _S_ZEROFILL or size == 0 or foff == 0:
            sections.append(Section(name=name, size=size, entropy=0.0, packed=False))
            continue
        body = data[foff:foff + size]
        ent = shannon_entropy(body)
        sections.append(Section(name=name, size=size, entropy=ent, packed=is_packed(ent)))
    return sections


def _read_symtab(data, pre, bits, off):
    symoff, nsyms, stroff, strsize = struct.unpack_from(pre + "IIII", data, off + 8)
    strtab = data[stroff:stroff + strsize]
    nlist_size = 16 if bits == 64 else 12
    imports = []
    for i in range(nsyms):
        base = symoff + i * nlist_size
        if base + nlist_size > len(data):
            break
        if bits == 64:
            n_strx, n_type, _sect, _desc, _val = struct.unpack_from(pre + "IBBHQ", data, base)
        else:
            n_strx, n_type, _sect, _desc, _val = struct.unpack_from(pre + "IBBHI", data, base)
        if (n_type & _N_TYPE) != _N_UNDF or not (n_type & _N_EXT):
            continue
        name = _cstr(strtab, n_strx)
        if name:
            imports.append(Import(name=name, category=categorize(name)))
    return imports


def _read_lc_str(data, off, cmdsize, pre):
    str_off = struct.unpack_from(pre + "I", data, off + 8)[0]
    start = off + str_off
    end = off + cmdsize
    if start < off or start > len(data) or end > len(data):
        return ""
    chunk = data[start:end]
    return chunk.split(b"\x00", 1)[0].decode("latin-1", "replace")


def _cstr(table: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    if end == -1:
        end = len(table)
    return table[offset:end].decode("utf-8", "replace")


def _dedupe(imports: list[Import]) -> list[Import]:
    seen = set()
    out = []
    for imp in imports:
        if imp.name in seen:
            continue
        seen.add(imp.name)
        out.append(imp)
    return out
