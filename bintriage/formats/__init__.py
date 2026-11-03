"""Format detection and dispatch."""

from __future__ import annotations

from ..report import ParseError, Report

ELF_MAGIC = b"\x7fELF"
PE_MZ = b"MZ"
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",  # 32-bit big-endian
    b"\xfe\xed\xfa\xcf",  # 64-bit big-endian
    b"\xce\xfa\xed\xfe",  # 32-bit little-endian
    b"\xcf\xfa\xed\xfe",  # 64-bit little-endian
}
MACHO_FAT_MAGICS = {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}


def detect(data: bytes) -> str | None:
    """Return the format name for ``data`` or None if unrecognised."""
    if data[:4] == ELF_MAGIC:
        return "elf"
    if data[:4] in MACHO_MAGICS:
        return "macho"
    if data[:4] in MACHO_FAT_MAGICS:
        return "macho-fat"
    if data[:2] == PE_MZ:
        return "pe"
    return None


def parse(data: bytes, path: str) -> Report:
    """Detect the format of ``data`` and parse it into a Report."""
    fmt = detect(data)
    if fmt is None:
        raise ParseError("unrecognised file format (not PE, ELF or Mach-O)")
    # Imported lazily so a parser bug in one format never breaks the others.
    if fmt == "elf":
        from . import elf

        return elf.parse(data, path)
    if fmt == "pe":
        from . import pe

        return pe.parse(data, path)
    from . import macho

    return macho.parse(data, path, fat=fmt == "macho-fat")
