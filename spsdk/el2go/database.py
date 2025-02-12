#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for handling UUID-Secure Object database."""
import abc
import datetime
import logging
import sqlite3
from types import TracebackType
from typing import Optional, Type, Union

from typing_extensions import Self

from spsdk.exceptions import SPSDKError
from spsdk.utils.http_client import HTTPClientBase

logger = logging.getLogger(__name__)


sqlite3.register_adapter(bool, int)
sqlite3.register_converter("BOOLEAN", lambda v: bool(int(v)))

sqlite3.register_adapter(datetime.date, lambda v: v.isoformat())
sqlite3.register_converter("DATE", lambda v: datetime.date.fromisoformat(v.decode("utf-8")))

sqlite3.register_adapter(datetime.time, lambda v: v.isoformat())
sqlite3.register_converter("TIME", lambda v: datetime.time.fromisoformat(v.decode("utf-8")))

sqlite3.register_adapter(datetime.datetime, lambda v: v.isoformat())
sqlite3.register_converter("DATETIME", lambda v: datetime.datetime.fromisoformat(v.decode("utf-8")))


class SecureObjectsDB(abc.ABC):
    """Base abstract class for UUID-Secure_Objects database."""

    @abc.abstractmethod
    def add_uuid(self, uuid: str) -> bool:
        """Add UUID into the database."""

    @abc.abstractmethod
    def add_secure_object(self, uuid: str, so: bytes) -> None:
        """Add Secure Objects for given UUID."""

    @abc.abstractmethod
    def remove_secure_object(self, uuid: Union[str, list[str]]) -> bool:
        """Remove Secure Objects for given UUID(s)."""

    @abc.abstractmethod
    def get_uuids(self, empty: bool = True, limit: int = 0) -> list[str]:
        """Get iterator to UUIDs."""

    @abc.abstractmethod
    def get_secure_object(self, uuid: str) -> bytes:
        """Get Secure Objects for given UUID."""

    @abc.abstractmethod
    def get_count(self, empty: bool = True) -> int:
        """Get number of records in the database."""

    @abc.abstractmethod
    def open(self) -> None:
        """Open the database connection."""

    @abc.abstractmethod
    def close(self) -> None:
        """Close the database connection."""

    def __enter__(self) -> Self:
        """Enter the context manager."""
        self.open()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[Exception]] = None,
        exc_val: Optional[Exception] = None,
        exc_tb: Optional[TracebackType] = None,
    ) -> None:
        """Exit the context manager."""
        self.close()
        if exc_val:
            raise exc_val

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
        self.conn: Optional[sqlite3.Connection] = None
        self.cursor: Optional[sqlite3.Cursor] = None
        self._setup_db()

    def open(self) -> None:
        """Open the database connection."""
        try:
            self.conn = sqlite3.connect(self.db_file)
            self.cursor = self.conn.cursor()
        except sqlite3.Error as e:
            self.close()
            raise SPSDKError(f"Error during opening database '{self.db_file}': {e}") from e

    def close(self) -> None:
        """Close the database connection."""
        if self.conn:
            self.conn.commit()
            self.conn.close()
        self.conn = None
        self.cursor = None

    def __exit__(
        self,
        exc_type: Optional[Type[Exception]] = None,
        exc_val: Optional[Exception] = None,
        exc_tb: Optional[TracebackType] = None,
    ) -> None:
        self.close()
        if exc_type == sqlite3.Error and exc_val:
            raise SPSDKError(f"Error during database operation: {exc_val}") from exc_val
        if exc_val:
            raise SPSDKError(str(exc_val)) from exc_val

    def _setup_db(self) -> None:
        logger.debug("Setting up a database")
        with self:
            cursor = self._sanitize_cursor()
            cursor.executescript(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    "name" varchar NOT NULL,
                    "value" text NOT NULL
                );
                CREATE TABLE IF NOT EXISTS objects (
                    "uuid" varchar(32) NOT NULL PRIMARY KEY,
                    "so" blob NULL
                );
                """
            )

    def _sanitize_cursor(self) -> sqlite3.Cursor:
        if not self.cursor or not self.conn:
            raise SPSDKError("Database is closed. Use 'with' statement to open it.")
        return self.cursor

    def add_uuid(self, uuid: str) -> bool:
        """Add UUID into the database."""
        logger.info(f"Adding UUID: {uuid}")
        cursor = self._sanitize_cursor()
        try:
            cursor.execute("INSERT INTO objects (uuid) VALUES (?)", (uuid,))
        except sqlite3.Error as e:
            if "UNIQUE" in str(e):
                logger.warning(f"UUID {uuid} is already in the database")
                return False
            raise
        cursor.connection.commit()
        return True

    def add_secure_object(self, uuid: str, so: bytes) -> None:
        """Add Secure Objects for given UUID."""
        logger.info(f"Adding Secure Objects for UUID: {uuid}")
        cursor = self._sanitize_cursor()
        cursor.execute("UPDATE objects SET so = ? WHERE uuid = ?", (so, uuid))
        cursor.connection.commit()

    def remove_secure_object(self, uuid: Union[str, list[str]]) -> bool:
        """Remove Secure Objects for given UUID(s)."""
        is_single = isinstance(uuid, str)
        logger.info(
            f"Removing Secure Objects for {f'UUID {uuid}' if is_single else f'{len(uuid)} UUIDs.'}"
        )
        cursor = self._sanitize_cursor()
        if is_single:
            cursor.execute("UPDATE objects SET so = null WHERE uuid = ?", (uuid,))
        else:
            args = [(i,) for i in uuid]
            cursor.executemany("UPDATE objects SET so = null WHERE uuid = ?", args)
        cursor.connection.commit()
        return True

    def get_uuids(self, empty: bool = True, limit: int = 0) -> list[str]:
        """Get iterator to UUIDs.

        :param empty: Get only UUIDs without Secure Objects
        :param limit: Limit the number of returned UUIDs
        """
        logger.info(f"Getting UUIDs {'without associated Secure Objects' if empty else '(all)'}")
        command = "SELECT uuid from objects"
        if empty:
            command += " WHERE so is NULL or so = ''"
        if limit:
            command += f" LIMIT {limit}"
        cursor = self._sanitize_cursor()
        cursor.execute(command)
        return [item[0] for item in cursor]

    def get_secure_object(self, uuid: str) -> bytes:
        """Get Secure Objects for given UUID."""
        logger.info(f"Getting Secure Objects for UUID: {uuid}")
        cursor = self._sanitize_cursor()
        cursor.execute("SELECT so FROM objects WHERE uuid = ?", (uuid,))
        data = cursor.fetchone()
        if not data:
            raise SPSDKError(f"UUID {uuid} not found in database")
        return data[0]

    def get_count(self, empty: bool = True) -> int:
        """Get number of records in the database."""
        logger.info(
            f"Getting number of records {'without associated Secure Objects' if empty else '(all)'}"
        )
        cmd = "SELECT COUNT(*) from objects"
        if empty:
            cmd += " WHERE so is NULL or so = ''"
        cursor = self._sanitize_cursor()
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

    def remove_secure_object(self, uuid: Union[str, list[str]]) -> bool:
        """Remove Secure Objects for given UUID(s)."""
        raise NotImplementedError()

    def get_uuids(self, empty: bool = True, limit: int = 0) -> list[str]:
        """Get iterator to UUIDs."""
        logger.info(f"Getting UUIDs {'without associated Secure Objects' if empty else '(all)'}")
        response = self._handle_request(self.Method.GET, f"/items?empty={empty}")
        return [item["uuid"] for item in response.json()]

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

    def open(self) -> None:
        """Open the database connection."""

    def close(self) -> None:
        """Close the database connection."""
