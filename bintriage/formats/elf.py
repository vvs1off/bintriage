"""Minimal ELF parser (32- and 64-bit, both endiannesses)."""

from __future__ import annotations

import struct

from ..categories import categorize
from ..entropy import is_packed, shannon_entropy
from ..report import Import, ParseError, Report, Section

_MACHINES = {
    0x03: "x86", 0x3E: "x86-64", 0x28: "arm", 0xB7: "aarch64",
    0x08: "mips", 0xF3: "riscv", 0x14: "ppc", 0x15: "ppc64",
    0x16: "s390", 0x2B: "sparcv9",
}
_TYPES = {0: "none", 1: "relocatable", 2: "executable", 3: "shared-object", 4: "core"}

_SHT_NOBITS = 8
_SHT_DYNAMIC = 6
_SHN_UNDEF = 0
_STT_FUNC = 2
_DT_NEEDED = 1


def _u(endian: str, fmt: str, data: bytes, off: int):
    prefix = "<" if endian == "little" else ">"
    size = struct.calcsize(prefix + fmt)
    if off < 0 or off + size > len(data):
        raise ParseError("ELF structure extends past end of file")
    return struct.unpack_from(prefix + fmt, data, off)


def parse(data: bytes, path: str) -> Report:
    if len(data) < 24:
        raise ParseError("file too small to be ELF")
    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        raise ParseError(f"invalid ELF class {ei_class}")
    bits = 64 if ei_class == 2 else 32
    endian = "little" if ei_data == 1 else "big"

    if bits == 64:
        (e_type, e_machine, _ver, _entry, _phoff, e_shoff, _flags,
         _ehsize, _phentsize, _phnum, e_shentsize, e_shnum,
         e_shstrndx) = _u(endian, "HHIQQQIHHHHHH", data, 16)
    else:
        (e_type, e_machine, _ver, _entry, _phoff, e_shoff, _flags,
         _ehsize, _phentsize, _phnum, e_shentsize, e_shnum,
         e_shstrndx) = _u(endian, "HHIIIIIHHHHHH", data, 16)

    report = Report(
        path=path,
        size=len(data),
        fmt="ELF",
        arch=_MACHINES.get(e_machine, f"unknown(0x{e_machine:x})"),
        bits=bits,
        endian=endian,
        filetype=_TYPES.get(e_type, f"unknown({e_type})"),
    )

    sections = _read_section_headers(data, endian, bits, e_shoff, e_shentsize, e_shnum)
    shstr = b""
    if 0 <= e_shstrndx < len(sections):
        shstr = _section_bytes(data, sections[e_shstrndx])

    dynsym = dynstr = dyn_section = dyn_link_str = None
    for sh in sections:
        name = _cstr(shstr, sh["name_off"])
        sh["name"] = name
        if name == ".dynsym":
            dynsym = sh
        elif name == ".dynstr":
            dynstr = sh
        elif sh["type"] == _SHT_DYNAMIC:
            dyn_section = sh

        if sh["type"] != _SHT_NOBITS and sh["size"] > 0 and name:
            body = _section_bytes(data, sh)
            ent = shannon_entropy(body)
            report.sections.append(
                Section(name=name, size=sh["size"], entropy=ent, packed=is_packed(ent))
            )

    if dynsym is not None and dynstr is not None:
        report.imports = _read_imports(data, endian, bits, dynsym, dynstr)
    if dyn_section is not None:
        # .dynamic's sh_link points at the string table holding library names.
        link = dyn_section["link"]
        dyn_link_str = sections[link] if link < len(sections) else dynstr
        if dyn_link_str is not None:
            report.libraries = _read_needed(data, endian, bits, dyn_section, dyn_link_str)

    if not report.sections:
        report.notes.append("no section headers (stripped or corrupt); limited triage")
    return report


def _read_section_headers(data, endian, bits, shoff, shentsize, shnum):
    out = []
    if shoff == 0 or shnum == 0:
        return out
    entsize = 64 if bits == 64 else 40
    if shentsize and shentsize != entsize:
        entsize = shentsize
    for i in range(shnum):
        off = shoff + i * entsize
        if bits == 64:
            name, stype, _flags, _addr, soff, size, link, _info, _align, _es = _u(
                endian, "IIQQQQIIQQ", data, off
            )
        else:
            name, stype, _flags, _addr, soff, size, link, _info, _align, _es = _u(
                endian, "IIIIIIIIII", data, off
            )
        out.append({"name_off": name, "type": stype, "offset": soff,
                    "size": size, "link": link, "name": ""})
    return out


def _section_bytes(data: bytes, sh: dict) -> bytes:
    start = sh["offset"]
    end = start + sh["size"]
    if start < 0 or end > len(data):
        return b""
    return data[start:end]


def _read_imports(data, endian, bits, dynsym, dynstr):
    strtab = _section_bytes(data, dynstr)
    symbytes = _section_bytes(data, dynsym)
    entsize = 24 if bits == 64 else 16
    imports = []
    seen = set()
    for off in range(0, len(symbytes) - entsize + 1, entsize):
        if bits == 64:
            st_name, st_info, _oth, st_shndx, _val, _sz = _u(endian, "IBBHQQ", symbytes, off)
        else:
            st_name, _val, _sz, st_info, _oth, st_shndx = _u(endian, "IIIBBH", symbytes, off)
        if st_shndx != _SHN_UNDEF or (st_info & 0xF) != _STT_FUNC:
            continue
        name = _cstr(strtab, st_name)
        if not name or name in seen:
            continue
        seen.add(name)
        imports.append(Import(name=name, category=categorize(name)))
    return imports


def _read_needed(data, endian, bits, dyn, strsec):
    strtab = _section_bytes(data, strsec)
    body = _section_bytes(data, dyn)
    entsize = 16 if bits == 64 else 8
    libs = []
    for off in range(0, len(body) - entsize + 1, entsize):
        if bits == 64:
            tag, val = _u(endian, "qQ", body, off)
        else:
            tag, val = _u(endian, "iI", body, off)
        if tag == 0:  # DT_NULL terminates the array
            break
        if tag == _DT_NEEDED:
            lib = _cstr(strtab, val)
            if lib:
                libs.append(lib)
    return libs


def _cstr(table: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(table):
        return ""
    end = table.find(b"\x00", offset)
    if end == -1:
        end = len(table)
    try:
        return table[offset:end].decode("utf-8", "replace")
    except Exception:
        return ""
