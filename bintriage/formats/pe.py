"""Minimal PE/PE32+ parser (headers, sections, imports)."""

from __future__ import annotations

import struct

from ..categories import categorize
from ..entropy import is_packed, shannon_entropy
from ..report import Import, ParseError, Report, Section

_MACHINES = {
    0x014C: "x86", 0x8664: "x86-64", 0x01C0: "arm", 0xAA64: "arm64",
    0x01C4: "armnt", 0x0200: "ia64",
}
_PE32 = 0x10B
_PE32_PLUS = 0x20B


def _u(fmt: str, data: bytes, off: int):
    size = struct.calcsize("<" + fmt)
    if off < 0 or off + size > len(data):
        raise ParseError("PE structure extends past end of file")
    return struct.unpack_from("<" + fmt, data, off)


def parse(data: bytes, path: str) -> Report:
    if len(data) < 0x40:
        raise ParseError("file too small to be PE")
    (e_lfanew,) = _u("I", data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ParseError("missing PE signature")
    coff = e_lfanew + 4
    machine, num_sections, _ts, _psym, _nsym, opt_size, chars = _u("HHIIIHH", data, coff)
    optoff = coff + 20
    (magic,) = _u("H", data, optoff)
    if magic == _PE32:
        bits, dd_off, nrva_off = 32, optoff + 96, optoff + 92
    elif magic == _PE32_PLUS:
        bits, dd_off, nrva_off = 64, optoff + 112, optoff + 108
    else:
        raise ParseError(f"unknown optional header magic 0x{magic:x}")

    filetype = "dll" if chars & 0x2000 else ("executable" if chars & 0x0002 else "object")
    report = Report(
        path=path,
        size=len(data),
        fmt="PE",
        arch=_MACHINES.get(machine, f"unknown(0x{machine:x})"),
        bits=bits,
        endian="little",
        filetype=filetype,
    )

    sections = _read_sections(data, optoff + opt_size, num_sections)
    for sec in sections:
        body = data[sec["raw_off"]:sec["raw_off"] + sec["raw_size"]]
        ent = shannon_entropy(body)
        report.sections.append(
            Section(name=sec["name"], size=sec["raw_size"], entropy=ent, packed=is_packed(ent))
        )

    (nrva,) = _u("I", data, nrva_off)
    if nrva >= 2:
        imp_rva, _imp_size = _u("II", data, dd_off + 8)
        if imp_rva:
            report.imports, report.libraries = _read_imports(data, sections, imp_rva, bits)

    if not report.imports and not report.sections:
        report.notes.append("no sections or imports recovered; possibly packed or malformed")
    return report


def _read_sections(data, table_off, count):
    out = []
    for i in range(count):
        off = table_off + i * 40
        if off + 40 > len(data):
            break
        raw_name = data[off:off + 8]
        name = raw_name.split(b"\x00", 1)[0].decode("latin-1", "replace")
        _vsize, vaddr, raw_size, raw_off = _u("IIII", data, off + 8)
        out.append({"name": name, "vaddr": vaddr, "vsize": _vsize,
                    "raw_size": raw_size, "raw_off": raw_off})
    return out


def _rva_to_offset(sections, rva):
    for sec in sections:
        span = max(sec["vsize"], sec["raw_size"])
        if sec["vaddr"] <= rva < sec["vaddr"] + span:
            return sec["raw_off"] + (rva - sec["vaddr"])
    return None


def _read_imports(data, sections, imp_rva, bits):
    imports: list[Import] = []
    libraries: list[str] = []
    seen: set[tuple[str, str]] = set()
    descr = _rva_to_offset(sections, imp_rva)
    if descr is None:
        return imports, libraries
    thunk_size = 8 if bits == 64 else 4
    ordinal_flag = 1 << (63 if bits == 64 else 31)

    for i in range(1024):  # hard cap: avoids runaway loops on malformed tables
        base = descr + i * 20
        if base + 20 > len(data):
            break
        oft, _ts, _fwd, name_rva, ft = _u("IIIII", data, base)
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        dll_off = _rva_to_offset(sections, name_rva)
        dll = _cstr(data, dll_off) if dll_off is not None else "?"
        if dll and dll not in libraries:
            libraries.append(dll)
        thunk_rva = oft or ft
        thunk_off = _rva_to_offset(sections, thunk_rva)
        if thunk_off is None:
            continue
        for j in range(4096):
            toff = thunk_off + j * thunk_size
            fmt = "Q" if bits == 64 else "I"
            if toff + thunk_size > len(data):
                break
            (entry,) = _u(fmt, data, toff)
            if entry == 0:
                break
            if entry & ordinal_flag:
                continue  # imported by ordinal, no name
            hint_off = _rva_to_offset(sections, entry & 0x7FFFFFFF)
            if hint_off is None:
                continue
            fname = _cstr(data, hint_off + 2)
            key = (dll, fname)
            if not fname or key in seen:
                continue
            seen.add(key)
            imports.append(Import(name=fname, category=categorize(fname), library=dll))
    return imports, libraries


def _cstr(data: bytes, offset: int | None) -> str:
    if offset is None or offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("latin-1", "replace")
