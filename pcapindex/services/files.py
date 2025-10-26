"""Utilities for validating and resolving access to pcap files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from django.conf import settings


class FileAccessError(Exception):
    """Raised when a path cannot be accessed under the configured policy."""


@dataclass(frozen=True)
class ResolvedPath:
    """Represents a validated filesystem path."""

    original: str
    absolute: Path

    def __str__(self) -> str:  # pragma: no cover - trivial formatting
        return str(self.absolute)


def _normalize_allowed_directories(allowed: Iterable[str]) -> list[Path]:
    normalized: list[Path] = []
    for entry in allowed:
        path = Path(entry).expanduser().resolve()
        normalized.append(path)
    return normalized


def _assert_within_allowed(path: Path, allowed_dirs: Iterable[Path]) -> None:
    for allowed in allowed_dirs:
        try:
            path.relative_to(allowed)
        except ValueError:
            continue
        else:
            return
    raise FileAccessError(
        f"Path '{path}' is outside of configured directories: "
        f"{', '.join(str(a) for a in allowed_dirs)}"
    )


def resolve_pcap_path(path: str | Path, *, must_exist: bool = True) -> ResolvedPath:
    """Resolve a user supplied path ensuring it is accessible.

    Parameters
    ----------
    path:
        The path to validate.
    must_exist:
        When ``True`` the path must be present on disk.
    """

    raw_path = Path(path)
    absolute = raw_path.expanduser().resolve()

    allowed_directories = _normalize_allowed_directories(settings.PCAP_ALLOWED_DIRECTORIES)
    if settings.PCAP_REQUIRE_WITHIN_ALLOWED:
        _assert_within_allowed(absolute, allowed_directories)

    exists = absolute.exists()

    if must_exist and not exists:
        raise FileAccessError(f"Path '{absolute}' does not exist")

    if exists:
        if absolute.is_dir():
            raise FileAccessError(
                f"Path '{absolute}' must reference a file, not a directory"
            )

        if not absolute.is_file():
            raise FileAccessError(f"Path '{absolute}' is not a regular file")

        if settings.PCAP_ENFORCE_READABLE and not os_access(absolute):
            raise FileAccessError(
                f"Path '{absolute}' is not readable under current permissions"
            )

    return ResolvedPath(original=str(path), absolute=absolute)


def os_access(path: Path) -> bool:
    """Wrapper around :func:`os.access` for easier testing/mocking."""

    import os

    return os.access(path, os.R_OK)


def ensure_upload_directory() -> Path:
    """Return the configured upload directory, creating it when required."""

    upload_root = Path(settings.PCAP_UPLOAD_ROOT).expanduser().resolve()
    upload_root.mkdir(parents=True, exist_ok=True)
    allowed_directories = _normalize_allowed_directories(settings.PCAP_ALLOWED_DIRECTORIES)
    if settings.PCAP_REQUIRE_WITHIN_ALLOWED:
        _assert_within_allowed(upload_root, allowed_directories)
    return upload_root


def store_uploaded_file(filename: str, content: bytes) -> ResolvedPath:
    """Persist an uploaded pcap file into the upload directory."""

    upload_root = ensure_upload_directory()
    destination = upload_root / filename
    destination.write_bytes(content)
    return resolve_pcap_path(destination)


def remove_path(path: str | Path) -> None:
    """Delete a cached/uploaded pcap file if present."""

    resolved = resolve_pcap_path(path, must_exist=False)
    if resolved.absolute.exists():
        resolved.absolute.unlink()


__all__ = [
    "FileAccessError",
    "ResolvedPath",
    "resolve_pcap_path",
    "store_uploaded_file",
    "ensure_upload_directory",
    "remove_path",
]
