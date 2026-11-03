import _fixtures as F

from bintriage.formats import parse


def _imports(report):
    return {imp.name: imp for imp in report.imports}


def test_elf_fields():
    r = parse(F.make_elf64(), "sample")
    assert r.fmt == "ELF"
    assert r.arch == "x86-64"
    assert r.bits == 64
    assert r.endian == "little"
    assert r.filetype == "executable"
    assert "libc.so.6" in r.libraries
    imps = _imports(r)
    assert "connect" in imps
    assert imps["connect"].category == "network"
    assert any(s.name == ".text" for s in r.sections)


def test_pe_fields():
    r = parse(F.make_pe32(), "sample.exe")
    assert r.fmt == "PE"
    assert r.arch == "x86"
    assert r.bits == 32
    assert r.filetype == "executable"
    assert "ws2_32.dll" in r.libraries
    imps = _imports(r)
    assert "connect" in imps
    assert imps["connect"].library == "ws2_32.dll"
    assert imps["connect"].category == "network"


def test_macho_fields():
    r = parse(F.make_macho64(), "sample")
    assert r.fmt == "Mach-O"
    assert r.arch == "x86-64"
    assert r.bits == 64
    assert "libSystem.B.dylib" in r.libraries
    assert "_connect" in _imports(r)
    assert any(s.name == "__TEXT,__text" for s in r.sections)


def test_macho_fat_note():
    r = parse(F.make_macho_fat(), "sample")
    assert r.fmt == "Mach-O"
    assert any("universal binary" in n for n in r.notes)
    assert "_connect" in _imports(r)
