#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK test configuration and fixtures for fuses testing.

This module provides pytest configuration and shared fixtures for testing
fuse-related functionality across the SPSDK project. It includes database
management utilities and mock objects for consistent test setup.
"""

import os
from typing import Any, Optional

import pytest

from spsdk.utils import database, family
from spsdk.utils.database import Database, QuickDatabase


class TestDatabaseManager:
    """SPSDK Test Database Manager for fuse operations.

    This class provides a singleton-style manager for accessing SPSDK database
    instances used in testing fuse configurations and operations. It maintains
    cached references to both full Database and QuickDatabase instances for
    efficient access during test execution.

    :cvar FEATURE1: Test feature identifier.
    :cvar FEATURE2: Test feature identifier.
    :cvar FEATURE3: Test feature identifier.
    :cvar SHADOW_REGS: Shadow registers feature identifier.
    """

    _instance = None
    _db: Optional[Database] = None
    _quick_info: Optional[QuickDatabase] = None

    @property
    def db(self) -> Database:
        """Get Database instance.

        Retrieves the cached Database instance from the class variable and validates
        that it is properly initialized.

        :raises AssertionError: If the database instance is not of type Database.
        :return: The Database instance used for fuse operations.
        """
        db = type(self)._db
        assert isinstance(db, Database)
        return db

    @property
    def quick_info(self) -> QuickDatabase:
        """Get quick info Database.

        Retrieves the cached QuickDatabase instance for this class.

        :return: The QuickDatabase instance containing quick access information.
        """
        quick_info = type(self)._quick_info
        assert isinstance(quick_info, QuickDatabase)
        return quick_info

    """List all SPSDK supported features"""
    FEATURE1 = "feature1"
    FEATURE2 = "feature2"
    FEATURE3 = "feature3"
    SHADOW_REGS = "shadow_regs"


@pytest.fixture
def mock_test_database(monkeypatch: Any, data_dir: str) -> None:
    """Mock the SPSDK Database for testing purposes.

    This function patches the DatabaseManager in both database and family modules
    to use a test database instance loaded from the test data directory.

    :param monkeypatch: Pytest monkeypatch fixture for patching objects.
    :param data_dir: Directory path containing test data files.
    """
    monkeypatch.setattr(database, "DatabaseManager", TestDatabaseManager)
    TestDatabaseManager._db = Database(
        os.path.join(data_dir, "../../../utils/data/test_db"), complete_load=True
    )
    TestDatabaseManager._quick_info = QuickDatabase.create(TestDatabaseManager._db)

    monkeypatch.setattr(family, "DatabaseManager", TestDatabaseManager)
