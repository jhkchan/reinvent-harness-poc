"""Tests for the local agent loop's file tools (no AWS calls)."""

from harness.agent import _impl_read_file, _impl_write_file


def test_file_tools_stay_inside_the_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("HARNESS_WORKSPACE", str(tmp_path))
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
    assert _impl_read_file({"path": "notes.txt"}) == "hello"
    (tmp_path / "link").symlink_to("/etc/hosts")  # a link that leads out
    for path in ("../outside.txt", "/etc/hosts", "link"):
        assert _impl_read_file({"path": path}).startswith("(refused")
    assert _impl_write_file({"path": "../x.txt", "content": "x"}).startswith("(refused")
    assert "wrote 2 bytes" in _impl_write_file({"path": "out/a.txt", "content": "ok"})
