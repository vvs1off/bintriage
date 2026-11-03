"""Printable-string extraction and interesting-string flagging."""

from __future__ import annotations

import re
from dataclasses import dataclass

DEFAULT_MIN_LEN = 6

_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s'\"<>]+", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_WIN_PATH = re.compile(r"\b[a-zA-Z]:\\[^\s'\"<>|]+")
_UNC_PATH = re.compile(r"\\\\[^\s'\"<>|]+")
_REGISTRY = re.compile(r"\b(?:HKEY_[A-Z_]+|SOFTWARE\\\\[^\s'\"<>]+)", re.IGNORECASE)

_SUSPICIOUS_TOKENS = (
    "cmd.exe", "powershell", "/bin/sh", "/bin/bash", "rundll32",
    "regsvr32", "schtasks", "base64", "-enc", "invoke-", "mimikatz",
    "backdoor", ".onion", "user-agent",
)


@dataclass(frozen=True)
class FlaggedString:
    value: str
    reason: str


def extract_strings(data: bytes, min_len: int = DEFAULT_MIN_LEN) -> list[str]:
    """Return ASCII printable runs of at least ``min_len`` characters."""
    if min_len < 1:
        raise ValueError("min_len must be >= 1")
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return [m.group().decode("ascii") for m in pattern.finditer(data)]


def flag_interesting(values: list[str]) -> list[FlaggedString]:
    """Pick out strings that are worth an analyst's attention.

    De-duplicates on value while keeping first-seen order.
    """
    seen: set[str] = set()
    flagged: list[FlaggedString] = []
    for value in values:
        reason = _classify(value)
        if reason is None or value in seen:
            continue
        seen.add(value)
        flagged.append(FlaggedString(value=value, reason=reason))
    return flagged


def _classify(value: str) -> str | None:
    if _URL.search(value):
        return "url"
    if _WIN_PATH.search(value) or _UNC_PATH.search(value):
        return "path"
    if _REGISTRY.search(value):
        return "registry"
    lowered = value.lower()
    for token in _SUSPICIOUS_TOKENS:
        if token in lowered:
            return "suspicious"
    if _IPV4.search(value) and _looks_like_ip(value):
        return "ip"
    return None


def _looks_like_ip(value: str) -> bool:
    for match in _IPV4.finditer(value):
        octets = match.group().split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            return True
    return False
