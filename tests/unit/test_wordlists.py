from __future__ import annotations

import zipfile
from pathlib import Path

from nightfalllx.core import wordlists


def make_archive(path: Path, entries: dict[str, str]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)


def test_ensure_wordlists_downloads_and_extracts(tmp_path: Path, monkeypatch) -> None:
    archive = tmp_path / "seclists.zip"
    make_archive(
        archive,
        {
            "SecLists-master/Discovery/Web-Content/common.txt": "admin\n",
            "SecLists-master/README.md": "SecLists\n",
        },
    )

    calls = 0

    def fake_download(url: str, destination: Path, timeout: tuple[float, float]) -> None:
        nonlocal calls
        calls += 1
        destination.write_bytes(archive.read_bytes())

    monkeypatch.setattr(wordlists, "_download", fake_download)
    root = tmp_path / "wordlists"

    result = wordlists.ensure_wordlists(root, url="https://example.invalid/seclists.zip")

    assert result == root / "seclists"
    assert (result / "Discovery" / "Web-Content" / "common.txt").read_text() == "admin\n"
    assert calls == 1

    again = wordlists.ensure_wordlists(root, url="https://example.invalid/seclists.zip")
    assert again == result
    assert calls == 1


def test_safe_extract_blocks_path_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "evil.zip"
    make_archive(
        archive,
        {
            "../escape.txt": "escaped\n",
            "SecLists-master/ok.txt": "safe\n",
        },
    )
    destination = tmp_path / "extract"
    destination.mkdir()

    wordlists._safe_extract(archive, destination)

    assert (destination / "SecLists-master" / "ok.txt").read_text() == "safe\n"
    assert not (tmp_path / "escape.txt").exists()
