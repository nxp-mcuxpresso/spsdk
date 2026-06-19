#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for el2go/database.py to improve coverage."""

from collections.abc import Generator
from pathlib import Path

import pytest

from spsdk.el2go.database import LocalSecureObjectsDB, ProdDBStats, SecureObjectsDB
from spsdk.exceptions import SPSDKError

# ── SecureObjectsDB.create() factory tests ────────────────────────────────────


def test_secure_objects_db_create_local(tmp_path: Path) -> None:
    """Test SecureObjectsDB.create with file_path (lines 171-177)."""
    db_path = str(tmp_path / "test.db")
    db = SecureObjectsDB.create(file_path=db_path)
    assert isinstance(db, LocalSecureObjectsDB)


def test_secure_objects_db_create_both_raises() -> None:
    """Test SecureObjectsDB.create with both file_path and host raises."""
    with pytest.raises(SPSDKError):
        SecureObjectsDB.create(file_path="/tmp/db.db", host="localhost")


def test_secure_objects_db_create_neither_raises() -> None:
    """Test SecureObjectsDB.create with neither file_path nor host raises."""
    with pytest.raises(SPSDKError):
        SecureObjectsDB.create()


# ── LocalSecureObjectsDB tests ────────────────────────────────────────────────


@pytest.fixture
def local_db(tmp_path: Path) -> Generator[LocalSecureObjectsDB, None, None]:
    """Create a LocalSecureObjectsDB fixture."""
    db_path = str(tmp_path / "test_so.db")
    db = LocalSecureObjectsDB(db_path)
    db.open()
    yield db
    db.close()


def test_local_db_add_uuid(local_db: LocalSecureObjectsDB) -> None:
    """Test add_uuid inserts UUID (lines 350-360)."""
    result = local_db.add_uuid("AABBCCDD1122334455667788AABBCCDD")
    assert result is True


def test_local_db_add_uuid_duplicate(local_db: LocalSecureObjectsDB) -> None:
    """Test add_uuid with duplicate UUID returns False (lines 357-359)."""
    uuid = "AABBCCDD1122334455667788AABBCCDD"
    local_db.add_uuid(uuid)
    result = local_db.add_uuid(uuid)
    assert result is False


def test_local_db_add_and_get_secure_object(local_db: LocalSecureObjectsDB) -> None:
    """Test add_secure_object and get_secure_object round-trip (lines 370-373, 385-396)."""
    uuid = "AABBCCDD1122334455667788AABBCCDD"
    so_data = b"\x01\x02\x03\x04" * 16
    local_db.add_uuid(uuid)
    local_db.add_secure_object(uuid, so_data)
    result = local_db.get_secure_object(uuid)
    assert result == so_data


def test_local_db_remove_secure_object_single(local_db: LocalSecureObjectsDB) -> None:
    """Test remove_secure_object for a single UUID (lines 408-416)."""
    uuid = "AABBCCDD1122334455667788AABBCCDD"
    local_db.add_uuid(uuid)
    local_db.add_secure_object(uuid, b"\xab" * 16)
    result = local_db.remove_secure_object(uuid)
    assert result is True


def test_local_db_remove_secure_object_list(local_db: LocalSecureObjectsDB) -> None:
    """Test remove_secure_object for a list of UUIDs (lines 428-434)."""
    uuids = ["AABBCCDD1122334455667788AABBCCDD", "11223344AABBCCDD11223344AABBCCDD"]
    for uuid in uuids:
        local_db.add_uuid(uuid)
        local_db.add_secure_object(uuid, b"\xff" * 16)
    result = local_db.remove_secure_object(uuids)
    assert result is True


def test_local_db_get_uuids_empty(local_db: LocalSecureObjectsDB) -> None:
    """Test get_uuids returns UUIDs without SOs (lines 446-455)."""
    uuid1 = "AABBCCDD1122334455667788AABBCCDD"
    uuid2 = "11223344AABBCCDD11223344AABBCCDD"
    local_db.add_uuid(uuid1)
    local_db.add_uuid(uuid2)
    local_db.add_secure_object(uuid2, b"\xab" * 16)
    empty_uuids = local_db.get_uuids(empty=True)
    assert uuid1 in empty_uuids
    assert uuid2 not in empty_uuids


def test_local_db_get_uuids_all(local_db: LocalSecureObjectsDB) -> None:
    """Test get_uuids with empty=False returns all UUIDs."""
    uuid = "AABBCCDD1122334455667788AABBCCDD"
    local_db.add_uuid(uuid)
    all_uuids = local_db.get_uuids(empty=False)
    assert uuid in all_uuids


def test_local_db_get_uuids_with_limit(local_db: LocalSecureObjectsDB) -> None:
    """Test get_uuids with limit parameter."""
    for i in range(5):
        local_db.add_uuid(f"UUID{i:028d}")
    limited = local_db.get_uuids(empty=False, limit=2)
    assert len(limited) == 2


def test_local_db_count_uuids(local_db: LocalSecureObjectsDB) -> None:
    """Test get_count method."""
    uuid = "AABBCCDD1122334455667788AABBCCDD"
    local_db.add_uuid(uuid)
    count = local_db.get_count(empty=True)
    assert count >= 1


def test_local_db_context_manager(tmp_path: Path) -> None:
    """Test LocalSecureObjectsDB as context manager (lines 125-155)."""
    db_path = str(tmp_path / "ctx_test.db")
    with LocalSecureObjectsDB(db_path) as db:
        result = db.add_uuid("AABBCCDD1122334455667788AABBCCDD")
        assert result is True


# ── ProdDBStats tests ─────────────────────────────────────────────────────────


def test_prod_db_stats_init() -> None:
    """Test ProdDBStats initialization (lines 578-605)."""
    stats = ProdDBStats(
        has_dynamic_records=10, used_dynamic_records=5, free_dynamic_records=3, reports=2
    )
    assert stats.has_dynamic_records == 10
    assert stats.used_dynamic_records == 5


def test_prod_db_stats_str() -> None:
    """Test ProdDBStats __str__ (lines 599-605)."""
    stats = ProdDBStats(has_dynamic_records=10, used_dynamic_records=5)
    s = str(stats)
    assert s is not None
