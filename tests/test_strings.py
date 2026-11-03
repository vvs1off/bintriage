from bintriage.categories import categorize
from bintriage.strings import extract_strings, flag_interesting


def test_extract_min_length():
    data = b"ab\x00longenough\x00\x01\x02short"
    out = extract_strings(data, min_len=6)
    assert "longenough" in out
    assert "ab" not in out


def test_flag_url_ip_path_suspicious():
    values = [
        "http://evil.example/beacon",
        "connect to 192.168.1.5 now",
        "C:\\Windows\\System32\\cmd.exe",
        "just some words",
        "powershell -enc ABCD",
    ]
    flagged = flag_interesting(values)
    reasons = {f.value: f.reason for f in flagged}
    assert reasons["http://evil.example/beacon"] == "url"
    assert reasons["connect to 192.168.1.5 now"] == "ip"
    # cmd.exe is a suspicious token and also a windows path; suspicious or path both acceptable.
    assert "C:\\Windows\\System32\\cmd.exe" in reasons
    assert reasons["powershell -enc ABCD"] == "suspicious"
    assert "just some words" not in reasons


def test_flag_dedupes():
    flagged = flag_interesting(["http://a/", "http://a/", "http://b/"])
    assert [f.value for f in flagged] == ["http://a/", "http://b/"]


def test_invalid_ip_not_flagged():
    flagged = flag_interesting(["999.999.999.999 version string"])
    assert flagged == []


def test_categorize():
    assert categorize("VirtualAllocEx") == "injection"
    assert categorize("IsDebuggerPresent") == "anti-debug"
    assert categorize("WSAStartup") == "network"
    assert categorize("some_unknown_symbol") == "other"
