#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
import os
from typing import Optional
import pytest
from spsdk.utils import database
from spsdk.utils.database import Database, DevicesQuickInfo, QuickDatabase
from spsdk.utils import schema_validator


class TestDatabaseManager:
    """Main SPSDK database."""

    _instance = None
    _db: Optional[Database] = None
    _quick_info: Optional[DevicesQuickInfo] = None

    @property
    def db(self) -> Database:
        """Get Database."""
        db = type(self)._db
        assert isinstance(db, Database)
        return db

    @property
    def quick_info(self) -> QuickDatabase:
        """Get quick info Database."""
        quick_info = type(self)._quick_info
        assert isinstance(quick_info, QuickDatabase)
        return quick_info

    """List all SPSDK supported features"""
    FEATURE1 = "feature1"
    FEATURE2 = "feature2"
    FEATURE3 = "feature3"
    SHADOW_REGS = "shadow_regs"


@pytest.fixture
def mock_test_database(monkeypatch, data_dir):
    """Change the SPSDK Database"""
    monkeypatch.setattr(database, "DatabaseManager", TestDatabaseManager)
    TestDatabaseManager._db = Database(
        os.path.join(data_dir, "../../../utils/data/test_db"), complete_load=True
    )
    TestDatabaseManager._quick_info = QuickDatabase.create(TestDatabaseManager._db)
    monkeypatch.setattr(schema_validator, "DatabaseManager", TestDatabaseManager)
