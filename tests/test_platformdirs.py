#!/usr/bin/env python
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for SPSDK platform-specific cache directories."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from platformdirs import PlatformDirs

import spsdk
from spsdk import SPSDKPlatformDirs


@pytest.mark.parametrize("ensure_exists", [False, True])
def test_windows_cache_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, ensure_exists: bool
) -> None:
    """Preserve the Windows cache layout and optional, repeatable directory creation."""
    data_dir = tmp_path / "data" / "spsdk" / "version"
    monkeypatch.setattr(spsdk, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(PlatformDirs, "user_data_dir", property(lambda _: str(data_dir)))
    dirs = SPSDKPlatformDirs(ensure_exists=ensure_exists)
    expected = data_dir / "Cache"

    assert dirs.user_cache_dir == str(expected)
    assert expected.is_dir() == ensure_exists
    assert dirs.user_cache_dir == str(expected)


def test_windows_cache_directory_creation_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Propagate filesystem errors instead of returning an unusable cache directory."""
    (tmp_path / "Cache").write_text("not a directory", encoding="utf-8")
    monkeypatch.setattr(spsdk, "sys", SimpleNamespace(platform="win32"))
    monkeypatch.setattr(PlatformDirs, "user_data_dir", property(lambda _: str(tmp_path)))
    dirs = SPSDKPlatformDirs(ensure_exists=True)

    with pytest.raises(FileExistsError):
        _ = dirs.user_cache_dir


@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_non_windows_cache_directory(monkeypatch: pytest.MonkeyPatch, platform: str) -> None:
    """Continue delegating non-Windows cache paths to platformdirs."""
    monkeypatch.setattr(spsdk, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(PlatformDirs, "user_cache_dir", property(lambda _: "native-cache"))

    assert SPSDKPlatformDirs().user_cache_dir == "native-cache"
