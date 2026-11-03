# bintriage

Fast first-look triage for **PE**, **ELF** and **Mach-O** binaries — one command, one readable report.

Opening an unknown binary usually starts with the same ten minutes of `file`,
`sha256sum`, `rabin2 -i`, `strings | grep`. `bintriage` collapses that into a
single pass: format and architecture, hashes, per-section entropy (with a
packed/encrypted flag), imports grouped by behaviour, and the strings worth
looking at — plus `--json` for pipelines.

```
$ bintriage sample.exe
bintriage: sample.exe
  format   PE / x86-64 / 64-bit little-endian (executable)
  size     94208 bytes
hashes
  md5     1a2b...
  sha256  9f86...
libraries
  KERNEL32.dll, WS2_32.dll, ADVAPI32.dll
sections
  .text      41984  [#############---] 6.41
  .rdata      8192  [##########------] 5.12
  .data       2048  [###-------------] 1.90
  UPX1       40960  [###############-] 7.81 packed?
imports (by behaviour)
  injection: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
  network: WSAStartup, connect, send
  persistence: RegSetValueExA
interesting strings
  [url] http://198.51.100.23/gate.php
  [suspicious] cmd.exe /c
```

> Example output is illustrative. A recorded demo GIF will live here.

## Why it's different

- **Three formats, one tool.** PE/PE32+, ELF (32/64, LE/BE) and Mach-O
  (thin + universal) in one consistent report.
- **Behaviour-grouped imports.** Imports are bucketed into `injection`,
  `anti-debug`, `persistence`, `network`, `process`, `crypto`, `filesystem`,
  so the interesting calls surface first.
- **Entropy at a glance.** Per-section Shannon entropy with a `packed?` flag
  for likely compressed or encrypted sections.
- **Zero dependencies.** Pure Python standard library. `pip install` and go —
  nothing to compile, no native parser to keep in sync.
- **Pipeline-friendly.** `--json` emits a stable schema for `jq` and scripts.

## Install

```sh
pip install bintriage        # once published to PyPI
# or, from a checkout:
pip install .
```

Requires Python 3.9+. No third-party runtime dependencies.

## Usage

```sh
bintriage <file>                     # human-readable report
bintriage --json <file> | jq .       # structured output
bintriage --no-color <file>          # plain text (also honours NO_COLOR)
bintriage --strings-min 8 <file>     # longer minimum string length
bintriage -v <file>                  # show every interesting string
```

| Flag | Meaning |
| --- | --- |
| `--json` | Emit a JSON report with a stable schema. |
| `--strings-min N` | Minimum printable-string length (default 6). |
| `--no-color` | Disable ANSI colour. |
| `-v`, `--verbose` | Show all interesting strings, not a sample. |
| `--version` | Print version and exit. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Report produced successfully. |
| `1` | Target could not be read or parsed. |
| `2` | Usage error (bad arguments). |

## What it looks at

- **Header**: format, architecture, bitness, endianness, object type.
- **Hashes**: MD5, SHA-1, SHA-256 of the whole file.
- **Libraries**: `DT_NEEDED` (ELF), import DLLs (PE), `LC_LOAD_DYLIB` (Mach-O).
- **Sections/segments**: size and Shannon entropy, with a packing flag.
- **Imports**: imported function names, grouped by behaviour.
- **Strings**: URLs, IPs, Windows/registry paths and suspicious tokens.

## Scope and authorized use

`bintriage` performs **static analysis only**. It never executes the target and
makes no network connections. It is intended for reverse engineers, malware
analysts and incident responders inspecting files **they are authorized to
analyze** (their own samples, lab artifacts, or engagement scope). Use it
responsibly and only on binaries you have permission to examine.

## Development

```sh
pip install -e ".[dev]"
python -m pytest
```

Tests build tiny, synthetic PE/ELF/Mach-O fixtures at runtime (see
`tests/_fixtures.py`) — no real executables are committed.

## License

MIT. See [LICENSE](LICENSE).
