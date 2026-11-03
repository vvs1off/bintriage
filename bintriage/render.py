"""Human-readable and JSON rendering of a Report."""

from __future__ import annotations

import json
from dataclasses import asdict

from .categories import NOTABLE
from .report import Report

_RESET = "\x1b[0m"
_COLORS = {
    "head": "\x1b[1;36m",
    "key": "\x1b[0;36m",
    "warn": "\x1b[1;33m",
    "bad": "\x1b[1;31m",
    "dim": "\x1b[2m",
}


class _Palette:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, kind: str, text: str) -> str:
        if not self.enabled or kind not in _COLORS:
            return text
        return f"{_COLORS[kind]}{text}{_RESET}"


def _entropy_bar(entropy: float, width: int = 16) -> str:
    filled = int(round((entropy / 8.0) * width))
    filled = max(0, min(width, filled))
    return "#" * filled + "-" * (width - filled)


def render_text(report: Report, color: bool = True) -> str:
    c = _Palette(color)
    lines: list[str] = []

    lines.append(c("head", f"bintriage: {report.path}"))
    lines.append(
        f"  {c('key', 'format')}   {report.fmt} / {report.arch} / {report.bits}-bit "
        f"{report.endian}-endian ({report.filetype})"
    )
    lines.append(f"  {c('key', 'size')}     {report.size} bytes")

    if report.hashes:
        lines.append(c("head", "hashes"))
        for algo, digest in report.hashes.items():
            lines.append(f"  {c('key', algo.ljust(7))} {digest}")

    if report.libraries:
        lines.append(c("head", "libraries"))
        lines.append("  " + ", ".join(report.libraries))

    if report.sections:
        lines.append(c("head", "sections"))
        name_w = max((len(s.name) for s in report.sections), default=4)
        for s in report.sections:
            flag = c("bad", " packed?") if s.packed else ""
            bar = _entropy_bar(s.entropy)
            lines.append(
                f"  {s.name.ljust(name_w)}  {s.size:>10}  "
                f"[{bar}] {s.entropy:4.2f}{flag}"
            )

    if report.imports:
        lines.append(c("head", "imports (by behaviour)"))
        grouped: dict[str, list[str]] = {}
        for imp in report.imports:
            grouped.setdefault(imp.category, []).append(imp.name)
        # Notable categories first, then the rest alphabetically.
        ordered = [cat for cat in NOTABLE if cat in grouped]
        ordered += sorted(cat for cat in grouped if cat not in NOTABLE)
        for cat in ordered:
            label = c("warn", cat) if cat in NOTABLE else cat
            names = ", ".join(sorted(set(grouped[cat])))
            lines.append(f"  {label}: {names}")

    if report.strings:
        lines.append(c("head", "interesting strings"))
        for fs in report.strings:
            lines.append(f"  {c('dim', f'[{fs.reason}]')} {fs.value}")

    if report.notes:
        lines.append(c("head", "notes"))
        for note in report.notes:
            lines.append(f"  {c('warn', '!')} {note}")

    return "\n".join(lines)


def render_json(report: Report) -> str:
    data = {
        "path": report.path,
        "size": report.size,
        "format": report.fmt,
        "arch": report.arch,
        "bits": report.bits,
        "endian": report.endian,
        "filetype": report.filetype,
        "hashes": report.hashes,
        "libraries": report.libraries,
        "sections": [asdict(s) for s in report.sections],
        "imports": [asdict(i) for i in report.imports],
        "strings": [asdict(s) for s in report.strings],
        "notes": report.notes,
    }
    return json.dumps(data, indent=2, sort_keys=False)
