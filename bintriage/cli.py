"""Command-line entry point for bintriage."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys

from . import __version__
from .formats import parse
from .render import render_json, render_text
from .report import ParseError
from .strings import DEFAULT_MIN_LEN, extract_strings, flag_interesting

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

# Guard against reading an enormous file fully into memory.
MAX_SIZE = 256 * 1024 * 1024
MAX_STRINGS = 40


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bintriage",
        description="Fast first-look triage for PE, ELF and Mach-O binaries.",
        epilog=(
            "examples:\n"
            "  bintriage sample.exe\n"
            "  bintriage --json /bin/ls | jq .imports\n"
            "  bintriage --no-color --strings-min 8 firmware.bin\n\n"
            "Static analysis only: bintriage never executes the target and makes "
            "no network connections. Use on files you are authorized to inspect."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("file", help="path to the binary to triage")
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    parser.add_argument(
        "--strings-min", type=int, default=DEFAULT_MIN_LEN, metavar="N",
        help=f"minimum printable-string length (default: {DEFAULT_MIN_LEN})",
    )
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="show all strings, not just a sample"
    )
    parser.add_argument("--version", action="version", version=f"bintriage {__version__}")
    return parser


def _use_color(explicit_no_color: bool) -> bool:
    if explicit_no_color or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.strings_min < 1:
        parser.error("--strings-min must be >= 1")

    try:
        size = os.path.getsize(args.file)
    except OSError as exc:
        print(f"bintriage: cannot access {args.file!r}: {exc.strerror}", file=sys.stderr)
        return EXIT_ERROR
    if size > MAX_SIZE:
        print(
            f"bintriage: {args.file!r} is larger than {MAX_SIZE} bytes; refusing",
            file=sys.stderr,
        )
        return EXIT_ERROR

    try:
        with open(args.file, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"bintriage: cannot read {args.file!r}: {exc.strerror}", file=sys.stderr)
        return EXIT_ERROR

    try:
        report = parse(data, args.file)
    except ParseError as exc:
        print(f"bintriage: {args.file!r}: {exc}", file=sys.stderr)
        return EXIT_ERROR

    report.hashes = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    flagged = flag_interesting(extract_strings(data, args.strings_min))
    report.strings = flagged if args.verbose else flagged[:MAX_STRINGS]
    if not args.verbose and len(flagged) > MAX_STRINGS:
        report.notes.append(
            f"{len(flagged)} interesting strings; showing {MAX_STRINGS} (use -v for all)"
        )

    if args.json:
        print(render_json(report))
    else:
        print(render_text(report, color=_use_color(args.no_color)))
    return EXIT_OK


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
