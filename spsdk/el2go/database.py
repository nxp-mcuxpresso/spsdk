#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for handling UUID-Secure Object database."""
import abc
import contextlib
import logging
import sqlite3
from typing import Iterator, Optional

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.utils.http_client import HTTPClientBase

logger = logging.getLogger(__name__)


@contextlib.contextmanager
def sqlite_cursor(file_path: str) -> Iterator[sqlite3.Cursor]:
    """Yield an cursor to SQLite database.

    :param file_path: Path to SQLite database file
    :raises SPSDKError: Error during SQL operation
    :yield: SQLite cursor
    """
    try:
        conn = sqlite3.connect(file_path)
        cursor = conn.cursor()
        yield cursor
    except sqlite3.Error as sql_error:
        raise SPSDKError(
            f"Error during sqlite operation using database '{file_path}': {sql_error}"
        ) from sql_error
    except SPSDKError:
        raise
    except Exception as e:
        raise SPSDKError(str(e)) from e
    finally:
        if "conn" in locals():
            conn.commit()
            conn.close()


CREATE_DATABASE_COMMAND = """
    CREATE TABLE IF NOT EXISTS settings (
        "name" varchar NOT NULL,
        "value" text NOT NULL
    );
    CREATE TABLE IF NOT EXISTS objects (
        "uuid" varchar(32) NOT NULL PRIMARY KEY,
        "so" blob NULL
    );
"""


class SecureObjectsDB(abc.ABC):
    """Base abstract class for UUID-Secure_Objects database."""

    @abc.abstractmethod
    def add_uuid(self, uuid: str) -> bool:
        """Add UUID into the database."""

    @abc.abstractmethod
    def add_secure_object(self, uuid: str, so: bytes) -> None:
        """Add Secure Objects for given UUID."""

    @abc.abstractmethod
    def get_uuids(self, empty: bool = True) -> Iterator[str]:
        """Get iterator to UUIDs."""

    @abc.abstractmethod
    def get_secure_object(self, uuid: str) -> bytes:
        """Get Secure Objects for given UUID."""

    @abc.abstractmethod
    def get_count(self, empty: bool = True) -> int:
        """Get number of records in the database."""

    @classmethod
    def create(
        cls, file_path: Optional[str] = None, host: Optional[str] = None, port: int = 8000
    ) -> Self:
        """Create Secure Objects database.

        :param file_path: Path to SQLite database file
        :param host: Remote server host
        :param port: Remote server port
        :return: Secure Objects database handler
        :raises SPSDKError: Only one of file_path or host can be specified
        """
        if file_path and host:
            raise SPSDKError("Only one of file_path or host can be specified")
        if host:
            return RemoteSecureObjectsDB(host, port)  # type: ignore[return-value]
        if file_path:
            return LocalSecureObjectsDB(file_path)  # type: ignore[return-value]
        raise SPSDKError("Either file_path or host must be specified")


class LocalSecureObjectsDB(SecureObjectsDB):
    """Handler for UUID-Secure_Objects database using a local sqlite file."""

    def __init__(self, file_path: str) -> None:
        """Initialize the database file."""
        self.db_file = file_path
        self._setup_db()

    def _setup_db(self) -> None:
        logger.debug("Setting up a database")
        with sqlite_cursor(self.db_file) as cursor:
            cursor.executescript(CREATE_DATABASE_COMMAND)

    def add_uuid(self, uuid: str) -> bool:
        """Add UUID into the database."""
        logger.info(f"Adding UUID: {uuid}")
        with sqlite_cursor(self.db_file) as cursor:
            try:
                cursor.execute("INSERT INTO objects (uuid) VALUES (?)", (uuid,))
            except sqlite3.Error as e:
                if "UNIQUE" in str(e):
                    logger.warning(f"UUID {uuid} is already in the database")
                    return False
                raise
        return True

    def add_secure_object(self, uuid: str, so: bytes) -> None:
        """Add Secure Objects for given UUID."""
        logger.info(f"Adding Secure Objects for UUID: {uuid}")
        with sqlite_cursor(self.db_file) as cursor:
            cursor.execute("UPDATE objects SET so = ? WHERE uuid = ?", (so, uuid))

    def get_uuids(self, empty: bool = True) -> Iterator[str]:
        """Get iterator to UUIDs.

        :param empty: Get only UUIDs without Secure Objects
        """
        logger.info(f"Getting UUIDs {'without associated Secure Objects' if empty else '(all)'}")
        with sqlite_cursor(self.db_file) as cursor:
            command = "SELECT uuid from objects"
            if empty:
                command += " WHERE so is NULL or so = ''"
            cursor.execute(command)
            for item in cursor:
                yield item[0]

    def get_secure_object(self, uuid: str) -> bytes:
        """Get Secure Objects for given UUID."""
        logger.info(f"Getting Secure Objects for UUID: {uuid}")
        with sqlite_cursor(self.db_file) as cursor:
            cursor.execute("SELECT so FROM objects WHERE uuid = ?", (uuid,))
            data = cursor.fetchone()
            if not data:
                raise SPSDKError(f"UUID {uuid} not found in database")
            return data[0]

    def get_count(self, empty: bool = True) -> int:
        """Get number of records in the database."""
        with sqlite_cursor(self.db_file) as cursor:
            cmd = "SELECT COUNT(*) from objects"
            if empty:
                cmd += " WHERE so is NULL or so = ''"
            cursor.execute(cmd)
            row = cursor.fetchone()
            return row[0]


class RemoteSecureObjectsDB(HTTPClientBase, SecureObjectsDB):
    """Handler for UUID-Secure_Objects database using a remote server."""

    api_version = "1.0.0"

    def __init__(self, host: str, port: int = 8000) -> None:
        """Initialize Remote Secure Objects database."""
        super().__init__(host=host, port=port, url_prefix="", use_ssl=False, raise_exceptions=True)

    def add_uuid(self, uuid: str) -> bool:
        """Add UUID into the database."""
        logger.info(f"Adding UUID: {uuid}")
        response = self._handle_request(self.Method.POST, "/items", json_data={"uuid": uuid})
        if response.status_code == self.Status.BAD_REQUEST:
            logger.warning(f"UUID {uuid} is already in the database")
        return response.status_code == self.Status.OK

    def add_secure_object(self, uuid: str, so: bytes) -> None:
        """Add Secure Objects for given UUID."""
        logger.info(f"Adding Secure Objects for UUID: {uuid}")
        response = self._handle_request(
            self.Method.POST, f"/items/{uuid}", json_data={"so": so.hex()}
        )
        if not response.ok:
            raise SPSDKError(f"Failed to add Secure Object for UUID {uuid}")

    def get_uuids(self, empty: bool = True) -> Iterator[str]:
        """Get iterator to UUIDs."""
        logger.info(f"Getting UUIDs {'without associated Secure Objects' if empty else '(all)'}")
        response = self._handle_request(self.Method.GET, f"/items?empty={empty}")
        for item in response.json():
            yield item["uuid"]

    def get_secure_object(self, uuid: str) -> bytes:
        """Get Secure Objects for given UUID."""
        logger.info(f"Getting Secure Objects for UUID: {uuid}")
        response = self._handle_request(self.Method.GET, f"/items/{uuid}")
        if not response.ok:
            raise SPSDKError(f"UUID {uuid} not found in database")
        data = response.json()["so"]
        if not data:
            raise SPSDKError(f"Secure Objects for UUID {uuid} not found in database")
        return bytes.fromhex(response.json()["so"])

    def get_count(self, empty: bool = True) -> int:
        """Get number of records in the database."""
        response = self._handle_request(self.Method.GET, f"/items/count?empty={empty}")
        return response.json()
