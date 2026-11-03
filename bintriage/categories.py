"""Behavioural grouping for imported symbols.

The goal is not perfect classification but a fast, readable grouping that points
an analyst at the interesting imports first. Matching is case-insensitive and
substring-based, so it works across the decorated names used by the three
formats (e.g. ``VirtualAllocEx``, ``ptrace``, ``__libc_connect``).
"""

from __future__ import annotations

# Ordered so the more specific / interesting categories win when a name could
# plausibly match more than one bucket.
_RULES: list[tuple[str, tuple[str, ...]]] = [
    (
        "injection",
        (
            "virtualalloc", "writeprocessmemory", "createremotethread",
            "ntunmapviewofsection", "queueuserapc", "setwindowshookex",
            "rtlcreateuserthread", "ptrace", "mmap", "mprotect",
            "task_for_pid", "mach_vm_write", "process_vm_writev",
        ),
    ),
    (
        "anti-debug",
        (
            "isdebuggerpresent", "checkremotedebuggerpresent",
            "ntqueryinformationprocess", "outputdebugstring", "gettickcount",
            "sysctl", "p_traced", "ptrace_deny",
        ),
    ),
    (
        "persistence",
        (
            "regsetvalue", "regcreatekey", "createservice", "startservice",
            "schedule", "taskschd", "launchd", "crontab", "autostart",
        ),
    ),
    (
        "process",
        (
            "createprocess", "shellexecute", "winexec", "openprocess",
            "fork", "execve", "execl", "posix_spawn", "system", "popen",
            "terminateprocess",
        ),
    ),
    (
        "network",
        (
            "socket", "connect", "send", "recv", "wsastartup", "internetopen",
            "httpopenrequest", "winhttp", "urldownload", "getaddrinfo",
            "gethostbyname", "bind", "listen", "accept", "inet_",
        ),
    ),
    (
        "crypto",
        (
            "crypt", "bcrypt", "aes", "rc4", "md5", "sha1", "sha256",
            "cc_crypt", "evp_", "rsa_",
        ),
    ),
    (
        "filesystem",
        (
            "createfile", "writefile", "readfile", "deletefile", "movefile",
            "copyfile", "fopen", "open", "unlink", "rename", "remove",
        ),
    ),
]

UNCATEGORIZED = "other"

# Categories listed here are the ones worth surfacing loudly in the summary.
NOTABLE = ("injection", "anti-debug", "persistence", "network")


def categorize(symbol: str) -> str:
    """Return the behavioural category for ``symbol`` (lowercased match)."""
    name = symbol.lower()
    for category, needles in _RULES:
        for needle in needles:
            if needle in name:
                return category
    return UNCATEGORIZED
