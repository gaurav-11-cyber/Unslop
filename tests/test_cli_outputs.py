"""The scan command's report files, including the case where one input file is broken (found by the end-to-end run)."""
import json

from click.testing import CliRunner

from unslop import scanner
from unslop.cli import main
from unslop.registry_client import PackageMetadata


def test_scan_markdown_works_when_another_input_is_broken(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "fetch_metadata", lambda n, e: PackageMetadata(name=n, ecosystem=e, exists=False))
    good = tmp_path / "requirements.txt"
    good.write_text("reqeusts\n")
    bad = tmp_path / "package.json"
    bad.write_text("{not json")
    md, js = tmp_path / "c.md", tmp_path / "r.json"
    r = CliRunner().invoke(main, ["scan", str(good), str(bad), "--markdown", str(md), "--json", str(js), "--no-cache"])
    assert r.exception is None or isinstance(r.exception, SystemExit), repr(r.exception)
    assert r.exit_code == 1                                           # a block outranks the broken-file error
    text = md.read_text(encoding="utf-8")
    assert "reqeusts" in text and "package.json" in text            # the broken file is reported, not silently dropped
    assert json.loads(js.read_text())["reports"]


def test_scan_markdown_without_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "fetch_metadata", lambda n, e: PackageMetadata(name=n, ecosystem=e, exists=False))
    f = tmp_path / "requirements.txt"
    f.write_text("reqeusts\n")
    md = tmp_path / "c.md"
    CliRunner().invoke(main, ["scan", str(f), "--markdown", str(md), "--no-cache"])
    assert "reqeusts" in md.read_text(encoding="utf-8")
