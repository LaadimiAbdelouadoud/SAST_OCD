"""Tests for pysast.ingestion."""
from pathlib import Path

from pysast.ingestion import discover_files, read_source


def test_discover_files_finds_py_files(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1")
    (tmp_path / "b.txt").write_text("not python")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "c.py").write_text("y = 2")

    files = discover_files(tmp_path)
    names = {f.name for f in files}
    assert "a.py" in names
    assert "c.py" in names
    assert "b.txt" not in names


def test_discover_files_skips_pycache(tmp_path: Path) -> None:
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "cached.py").write_text("z = 3")
    (tmp_path / "real.py").write_text("w = 4")

    files = discover_files(tmp_path)
    assert all("__pycache__" not in str(f) for f in files)
    assert any(f.name == "real.py" for f in files)


def test_read_source_utf8(tmp_path: Path) -> None:
    p = tmp_path / "hello.py"
    p.write_text("# héllo\n", encoding="utf-8")
    assert "héllo" in read_source(p)


def test_read_source_latin1_fallback(tmp_path: Path) -> None:
    p = tmp_path / "latin.py"
    p.write_bytes(b"# caf\xe9\n")  # latin-1 encoded
    content = read_source(p)
    assert content.startswith("#")
