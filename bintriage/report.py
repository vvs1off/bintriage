"""Data model shared by the format parsers and the renderers."""

from __future__ import annotations

from dataclasses import dataclass, field

from .strings import FlaggedString


@dataclass
class Section:
    name: str
    size: int
    entropy: float
    packed: bool


@dataclass
class Import:
    name: str
    category: str
    library: str | None = None


@dataclass
class Report:
    path: str
    size: int
    fmt: str
    arch: str
    bits: int
    endian: str
    filetype: str
    hashes: dict[str, str] = field(default_factory=dict)
    libraries: list[str] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    imports: list[Import] = field(default_factory=list)
    strings: list[FlaggedString] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def notable_imports(self) -> list[Import]:
        from .categories import NOTABLE

        return [imp for imp in self.imports if imp.category in NOTABLE]


class ParseError(Exception):
    """Raised when a target cannot be parsed as the detected format."""
