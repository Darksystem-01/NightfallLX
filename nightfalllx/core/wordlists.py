"""SecLists bootstrap helpers for NightfallLX."""

from __future__ import annotations

import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

import requests

SECLISTS_URL = "https://github.com/danielmiessler/SecLists/archive/refs/heads/master.zip"
DEFAULT_ROOT = Path.home() / ".nightfalllx" / "wordlists"


def ensure_wordlists(
    root: Path | None = None,
    *,
    url: str = SECLISTS_URL,
    force: bool = False,
    timeout: tuple[float, float] = (10.0, 120.0),
) -> Path:
    """Return the local SecLists directory, downloading it when absent."""
    base = (root or DEFAULT_ROOT).expanduser()
    target = base / "seclists"

    if target.is_dir() and any(target.iterdir()) and not force:
        print(f"[wordlists] SecLists already available: {target}")
        return target

    base.mkdir(parents=True, exist_ok=True)
    print("[wordlists] SecLists was not found locally.")
    print(f"[wordlists] Downloading {url}")

    with tempfile.TemporaryDirectory(prefix=".seclists-", dir=base) as temp:
        temp_path = Path(temp)
        archive_path = temp_path / "seclists.zip"
        extract_path = temp_path / "extracted"
        extract_path.mkdir()

        _download(url, archive_path, timeout)
        _safe_extract(archive_path, extract_path)
        source = _archive_root(extract_path)

        staging = base / ".seclists-staging"
        if staging.exists():
            shutil.rmtree(staging)
        try:
            shutil.copytree(source, staging)
            if target.exists():
                shutil.rmtree(target)
            staging.rename(target)
        finally:
            if staging.exists():
                shutil.rmtree(staging)

    print(f"[wordlists] SecLists ready: {target}")
    return target


def _download(url: str, destination: Path, timeout: tuple[float, float]) -> None:
    with requests.get(url, stream=True, timeout=timeout) as response:
        response.raise_for_status()
        written = 0
        with destination.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=256 * 1024):
                if not chunk:
                    continue
                handle.write(chunk)
                written += len(chunk)
    print(f"[wordlists] Downloaded {written / (1024 * 1024):.1f} MiB")


def _safe_extract(archive_path: Path, destination: Path) -> None:
    destination_root = destination.resolve()
    with zipfile.ZipFile(archive_path) as archive:
        for info in archive.infolist():
            name = info.filename
            if not name or name.endswith("/"):
                continue
            parts = PurePosixPath(name).parts
            if not parts or PurePosixPath(name).is_absolute() or ".." in parts:
                continue
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                continue
            target = destination.joinpath(*parts).resolve()
            if not target.is_relative_to(destination_root):
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as handle:
                shutil.copyfileobj(source, handle)


def _archive_root(extracted: Path) -> Path:
    entries = [entry for entry in extracted.iterdir() if entry.name != "__MACOSX"]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return extracted
