# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of `bintriage`.
- PE/PE32+, ELF (32/64-bit, little/big-endian) and Mach-O (thin + universal)
  parsing using only the Python standard library.
- Header summary: format, architecture, bitness, endianness, object type.
- File hashes (MD5, SHA-1, SHA-256).
- Linked libraries (`DT_NEEDED`, PE import DLLs, `LC_LOAD_DYLIB`).
- Per-section Shannon entropy with a packing flag.
- Imported symbols grouped by behaviour (injection, anti-debug, persistence,
  network, process, crypto, filesystem).
- Interesting-string extraction (URLs, IPs, paths, suspicious tokens).
- Human-readable and `--json` output, with documented exit codes.
