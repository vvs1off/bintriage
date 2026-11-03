import json

import _fixtures as F
import pytest

from bintriage.cli import EXIT_ERROR, EXIT_OK, EXIT_USAGE, run


@pytest.fixture
def elf_file(tmp_path):
    p = tmp_path / "sample.elf"
    p.write_bytes(F.make_elf64())
    return str(p)


def test_run_text_output(elf_file, capsys):
    rc = run([elf_file, "--no-color"])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    assert "bintriage:" in out
    assert "x86-64" in out
    assert "connect" in out
    assert "sha256" in out


def test_run_json_output(elf_file, capsys):
    rc = run([elf_file, "--json"])
    out = capsys.readouterr().out
    assert rc == EXIT_OK
    doc = json.loads(out)
    assert doc["format"] == "ELF"
    assert doc["arch"] == "x86-64"
    assert "sha256" in doc["hashes"]
    assert any(i["name"] == "connect" for i in doc["imports"])
    assert "libc.so.6" in doc["libraries"]


def test_missing_file_returns_error(capsys):
    rc = run(["/no/such/file/here.bin", "--no-color"])
    err = capsys.readouterr().err
    assert rc == EXIT_ERROR
    assert "cannot access" in err


def test_unparseable_returns_error(tmp_path, capsys):
    p = tmp_path / "junk.bin"
    p.write_bytes(b"this is clearly not a binary executable file")
    rc = run([str(p), "--no-color"])
    assert rc == EXIT_ERROR
    assert "unrecognised" in capsys.readouterr().err


def test_bad_strings_min_is_usage_error(elf_file):
    with pytest.raises(SystemExit) as exc:
        run([elf_file, "--strings-min", "0"])
    assert exc.value.code == EXIT_USAGE
