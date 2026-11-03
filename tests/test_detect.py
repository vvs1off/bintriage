import _fixtures as F
import pytest

from bintriage.formats import detect, parse
from bintriage.report import ParseError


def test_detect_each_format():
    assert detect(F.make_elf64()) == "elf"
    assert detect(F.make_pe32()) == "pe"
    assert detect(F.make_macho64()) == "macho"
    assert detect(F.make_macho_fat()) == "macho-fat"


def test_detect_unknown():
    assert detect(b"not a binary at all") is None
    assert detect(b"") is None


def test_parse_unknown_raises():
    with pytest.raises(ParseError):
        parse(b"\x00\x01\x02\x03nope", "junk")


def test_parse_truncated_elf_raises():
    with pytest.raises(ParseError):
        parse(F.make_elf64()[:10], "truncated")
