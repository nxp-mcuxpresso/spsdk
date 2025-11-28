#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK EdgeLock 2GO database management utilities.

This module provides functionality for handling secure objects databases
in EdgeLock 2GO context, supporting both local and remote database operations
for UUID-based secure object storage and retrieval.
"""

import abc
import base64
import datetime
import logging
import sqlite3
from dataclasses import dataclass
from types import TracebackType
from typing import Optional, Type, Union

from filelock import FileLock, Timeout
from typing_extensions import Self

from spsdk.crypto.keys import PublicKey
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
    """SPSDK Secure Objects Database Interface.

    Abstract base class that defines the interface for managing UUID-indexed secure objects
    in EL2GO provisioning workflows. Provides standardized methods for storing, retrieving,
    and managing secure objects associated with unique device identifiers.
    Implementations of this interface handle the persistence layer for secure provisioning
    data and support context manager operations for proper resource management.
    """

    @abc.abstractmethod
    def add_uuid(self, uuid: str) -> bool:
        """Add UUID into the database.

        :param uuid: The UUID string to be added to the database.
        :return: True if UUID was successfully added, False otherwise.
        """

    @abc.abstractmethod
    def add_secure_object(self, uuid: str, so: bytes) -> None:
        """Add Secure Objects for given UUID.

        :param uuid: Unique identifier for the secure object.
        :param so: Secure object data in bytes format.
        """

    @abc.abstractmethod
    def remove_secure_object(self, uuid: Union[str, list[str]]) -> bool:
        """Remove Secure Objects for given UUID(s).

        :param uuid: Single UUID string or list of UUID strings identifying the secure objects to remove.
        :return: True if removal was successful, False otherwise.
        """

    @abc.abstractmethod
    def get_uuids(self, empty: bool = True, limit: int = 0) -> list[str]:
        """Get UUIDs from the database.

        Retrieves a list of UUIDs based on the specified criteria for empty status
        and result limit.

        :param empty: Include empty UUIDs in the result, defaults to True
        :param limit: Maximum number of UUIDs to return, 0 means no limit, defaults to 0
        :return: List of UUID strings
        """

    @abc.abstractmethod
    def get_secure_object(self, uuid: str) -> bytes:
        """Get Secure Objects for given UUID.

        :param uuid: The UUID string identifier for the secure object to retrieve.
        :return: The secure object data as bytes.
        """

    @abc.abstractmethod
    def get_count(self, empty: bool = True) -> int:
        """Get number of records in the database.

        :param empty: Whether to include empty records in the count.
        :return: Number of records in the database.
        """

    @abc.abstractmethod
    def open(self) -> None:
        """Open the database connection.

        Establishes a connection to the EL2GO database for subsequent operations.

        :raises SPSDKError: If database connection cannot be established.
        """

    @abc.abstractmethod
    def close(self) -> None:
        """Close the database connection.

        This method properly closes the database connection and releases any associated resources.
        """

    def __enter__(self) -> Self:
        """Enter the context manager.

        Opens the database connection and returns the instance for use in a with statement.

        :return: The database instance.
        """
        self.open()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[Exception]] = None,
        exc_val: Optional[Exception] = None,
        exc_tb: Optional[TracebackType] = None,
    ) -> None:
        """Exit the context manager and handle exceptions.

        Properly closes the database connection and re-raises any exception that occurred
        within the context manager block.

        :param exc_type: The exception type if an exception was raised.
        :param exc_val: The exception instance if an exception was raised.
        :param exc_tb: The traceback object if an exception was raised.
        :raises Exception: Re-raises any exception that occurred in the context block.
        """
        self.close()
        if exc_val:
            raise exc_val

    @classmethod
    def create(
        cls, file_path: Optional[str] = None, host: Optional[str] = None, port: int = 8000
    ) -> Self:
        """Create Secure Objects database.

        Factory method to create either a local SQLite database or remote database connection
        based on the provided parameters. Exactly one of file_path or host must be specified.

        :param file_path: Path to SQLite database file for local database.
        :param host: Remote server host for remote database connection.
        :param port: Remote server port number.
        :return: Secure Objects database handler instance.
        :raises SPSDKError: When both file_path and host are specified, or when neither is
            specified.
        """
        if file_path and host:
            raise SPSDKError("Only one of file_path or host can be specified")
        if host:
            return RemoteSecureObjectsDB(host, port)  # type: ignore[return-value]
        if file_path:
            return LocalSecureObjectsDB(file_path)  # type: ignore[return-value]
        raise SPSDKError("Either file_path or host must be specified")


class LocalDB(abc.ABC):
    """Base local database implementation for SPSDK operations.

    This abstract class provides a foundation for local SQLite database operations
    with file locking support and context manager functionality. It manages database
    connections, transactions, and ensures thread-safe access to local database files
    used in SPSDK workflows.
    """

    def __init__(self, file_path: str, lock_timeout: Optional[int] = 10) -> None:
        """Initialize local batch processing database.

        Sets up a SQLite database connection with optional file locking for concurrent access
        protection. Creates necessary database tables and prepares cursors for operations.

        :param file_path: Path to the SQLite database file.
        :param lock_timeout: Timeout in seconds for file lock acquisition, None disables locking.
        """
        self.file_path = file_path
        self.lock = FileLock(f"{file_path}.lock", timeout=lock_timeout) if lock_timeout else None
        self.connection: Optional[sqlite3.Connection] = None
        self.cursor: Optional[sqlite3.Cursor] = None
        self._setup_db()

    def open(self) -> None:
        """Open the database connection.

        Establishes a connection to the SQLite database file and creates a cursor for executing
        queries. If a file lock is configured, it will be acquired before opening the connection
        to ensure exclusive access.

        :raises SPSDKError: File lock timeout or database connection error.
        """
        try:
            if self.lock:
                self.lock.acquire()
            self.connection = sqlite3.connect(self.file_path)
            self.cursor = self.connection.cursor()
            logger.debug(f"Opened database connection to {self.file_path}")
        except Timeout as e:
            logger.error(f"Could not acquire file lock for {self.file_path}")
            raise SPSDKError(f"File lock timeout: {e}") from e
        except sqlite3.Error as e:
            if self.lock:
                self.lock.release()
            logger.error(f"Error opening database connection: {e}")
            raise SPSDKError(f"Could not open database connection: {e}") from e
        # unspecified error, release the lock if it was acquired
        except BaseException:
            if self.lock and self.lock.is_locked:
                self.lock.release()

    def close(self) -> None:
        """Close the database connection.

        Commits any pending transactions, closes the database connection, and releases
        the associated lock if present. Sets connection and cursor to None to prevent
        further database operations.

        :raises Exception: If an error occurs during connection closing or lock release.
        """
        try:
            if self.connection:
                self.connection.commit()
                self.connection.close()
            self.connection = None
            self.cursor = None
        finally:
            if self.lock:
                self.lock.release()
        logger.debug(f"Closed database connection to {self.file_path}")

    def __enter__(self) -> Self:
        """Context manager entry method to open database connection.

        :return: Self instance with opened database connection.
        """
        self.open()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[Exception]] = None,
        exc_val: Optional[Exception] = None,
        exc_tb: Optional[TracebackType] = None,
    ) -> None:
        """Exit the database context manager and handle exceptions.

        Closes the database connection and converts various exception types to SPSDKError
        for consistent error handling across the SPSDK library.

        :param exc_type: The exception type if an exception occurred, None otherwise.
        :param exc_val: The exception instance if an exception occurred, None otherwise.
        :param exc_tb: The traceback object if an exception occurred, None otherwise.
        :raises SPSDKError: When any exception occurs during context manager execution.
        """
        self.close()
        if isinstance(exc_val, sqlite3.Error):
            raise SPSDKError(f"Error during database operation: {exc_val}") from exc_val
        if isinstance(exc_val, SPSDKError):
            raise SPSDKError(exc_val.description) from exc_val
        if exc_val:
            raise SPSDKError(str(exc_val)) from exc_val

    def _sanitize_cursor(self) -> sqlite3.Cursor:
        """Ensure a valid database cursor is available.

        This method validates that both the database connection and cursor are properly
        initialized and ready for use.

        :raises SPSDKError: Database connection is not open or cursor is invalid.
        :return: Valid database cursor for executing SQL operations.
        """
        if not self.cursor or not self.connection:
            raise SPSDKError("Database connection is not open. Call open() or use `with`.")
        return self.cursor

    @abc.abstractmethod
    def _setup_db(self) -> None:
        """Set up database schema.

        Abstract method that must be implemented by subclasses to initialize
        the database schema and create necessary tables or structures.

        :raises NotImplementedError: If the method is not implemented by subclass.
        """


class LocalSecureObjectsDB(LocalDB, SecureObjectsDB):
    """Local database handler for UUID and Secure Objects management.

    This class provides SQLite-based storage and retrieval operations for managing
    UUIDs and their associated secure objects in the EL2GO provisioning system.
    It combines local database functionality with secure objects database operations
    to enable offline management of provisioning data.
    """

    def _setup_db(self) -> None:
        """Initialize and set up the database schema.

        Creates the necessary tables (settings and objects) if they don't already exist.
        The method uses a database transaction to ensure atomic execution of the schema
        creation commands.

        :raises SPSDKError: If database setup fails or connection issues occur.
        """
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

    def add_uuid(self, uuid: str) -> bool:
        """Add UUID into the database.

        Inserts a new UUID into the objects table. If the UUID already exists,
        the operation is skipped and a warning is logged.

        :param uuid: The UUID string to be added to the database.
        :raises sqlite3.Error: Database operation failed (excluding unique constraint violations).
        :return: True if UUID was successfully added, False if UUID already exists.
        """
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
        """Add Secure Objects for given UUID.

        Updates the database record with secure object data for the specified UUID.

        :param uuid: Unique identifier for the object to update.
        :param so: Secure object data in bytes format.
        """
        logger.info(f"Adding Secure Objects for UUID: {uuid}")
        cursor = self._sanitize_cursor()
        cursor.execute("UPDATE objects SET so = ? WHERE uuid = ?", (so, uuid))
        cursor.connection.commit()

    def remove_secure_object(self, uuid: Union[str, list[str]]) -> bool:
        """Remove Secure Objects for given UUID(s).

        This method removes secure objects from the database by setting the 'so' column to null
        for the specified UUID(s). The operation is performed using SQL UPDATE statements and
        the changes are committed to the database.

        :param uuid: Single UUID string or list of UUID strings to remove secure objects for.
        :return: Always returns True indicating successful operation.
        """
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
        """Get list of UUIDs from the database.

        Retrieves UUIDs from the objects table with optional filtering for empty
        secure objects and result limiting.

        :param empty: If True, return only UUIDs without associated Secure Objects.
        :param limit: Maximum number of UUIDs to return, 0 means no limit.
        :return: List of UUID strings from the database.
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
        """Get Secure Object data for given UUID.

        Retrieves the secure object binary data from the database based on the provided UUID.
        The method queries the database and returns the raw secure object data.

        :param uuid: Unique identifier of the secure object to retrieve.
        :raises SPSDKError: UUID not found in database.
        :return: Binary data of the secure object.
        """
        logger.info(f"Getting Secure Objects for UUID: {uuid}")
        cursor = self._sanitize_cursor()
        cursor.execute("SELECT so FROM objects WHERE uuid = ?", (uuid,))
        data = cursor.fetchone()
        if not data:
            raise SPSDKError(f"UUID {uuid} not found in database")
        return data[0]

    def get_count(self, empty: bool = True) -> int:
        """Get number of records in the database.

        The method can count all records or only records without associated Secure Objects
        based on the empty parameter.

        :param empty: If True, count only records without associated Secure Objects,
                      if False count all records.
        :return: Number of records matching the criteria.
        """
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
    """Remote Secure Objects Database client for EL2GO services.

    This class provides a client interface to interact with a remote UUID-Secure Objects
    database server over HTTP. It manages secure object storage and retrieval operations
    for device provisioning workflows in the EL2GO ecosystem.

    :cvar api_version: API version used for server communication.
    """

    api_version = "1.0.0"

    def __init__(self, host: str, port: int = 8000) -> None:
        """Initialize Remote Secure Objects database.

        :param host: Host address for the database connection.
        :param port: Port number for the database connection, defaults to 8000.
        """
        super().__init__(host=host, port=port, url_prefix="", use_ssl=False, raise_exceptions=True)

    def add_uuid(self, uuid: str) -> bool:
        """Add UUID into the database.

        Sends a POST request to add the specified UUID to the database. If the UUID
        already exists, a warning is logged but the operation continues.

        :param uuid: The UUID string to be added to the database.
        :return: True if UUID was successfully added, False otherwise.
        """
        logger.info(f"Adding UUID: {uuid}")
        response = self._handle_request(self.Method.POST, "/items", json_data={"uuid": uuid})
        if response.status_code == self.Status.BAD_REQUEST:
            logger.warning(f"UUID {uuid} is already in the database")
        return response.status_code == self.Status.OK

    def add_secure_object(self, uuid: str, so: bytes) -> None:
        """Add Secure Objects for given UUID.

        This method uploads secure object data to the EL2GO service for the specified UUID.

        :param uuid: The unique identifier for the secure object.
        :param so: The secure object data as bytes to be uploaded.
        :raises SPSDKError: Failed to add secure object to the service.
        """
        logger.info(f"Adding Secure Objects for UUID: {uuid}")
        response = self._handle_request(
            self.Method.POST, f"/items/{uuid}", json_data={"so": so.hex()}
        )
        if not response.ok:
            raise SPSDKError(f"Failed to add Secure Object for UUID {uuid}")

    def remove_secure_object(self, uuid: Union[str, list[str]]) -> bool:
        """Remove Secure Objects for given UUID(s).

        :param uuid: Single UUID string or list of UUID strings identifying the secure objects to remove.
        :raises NotImplementedError: Method is not yet implemented.
        :return: True if removal was successful, False otherwise.
        """
        raise NotImplementedError()

    def get_uuids(self, empty: bool = True, limit: int = 0) -> list[str]:
        """Get list of UUIDs from EL2GO database.

        Retrieves UUIDs of items from the EL2GO database, with option to filter by
        whether they have associated Secure Objects or not.

        :param empty: If True, return only UUIDs without associated Secure Objects.
                      If False, return all UUIDs.
        :param limit: Maximum number of UUIDs to return. If 0, return all available.
        :return: List of UUID strings.
        """
        logger.info(f"Getting UUIDs {'without associated Secure Objects' if empty else '(all)'}")
        response = self._handle_request(self.Method.GET, f"/items?empty={empty}")
        return [item["uuid"] for item in response.json()]

    def get_secure_object(self, uuid: str) -> bytes:
        """Get Secure Objects for given UUID.

        Retrieves secure object data from the database using the provided UUID identifier.
        The method makes a GET request to fetch the secure object and converts the
        hexadecimal string response to bytes.

        :param uuid: Unique identifier for the secure object to retrieve.
        :raises SPSDKError: When UUID is not found in database or secure object data is empty.
        :return: Secure object data as bytes.
        """
        logger.info(f"Getting Secure Objects for UUID: {uuid}")
        response = self._handle_request(self.Method.GET, f"/items/{uuid}")
        if not response.ok:
            raise SPSDKError(f"UUID {uuid} not found in database")
        data = response.json()["so"]
        if not data:
            raise SPSDKError(f"Secure Objects for UUID {uuid} not found in database")
        return bytes.fromhex(response.json()["so"])

    def get_count(self, empty: bool = True) -> int:
        """Get number of records in the database.

        :param empty: Whether to include empty records in the count.
        :return: Number of records in the database.
        """
        response = self._handle_request(self.Method.GET, f"/items/count?empty={empty}")
        return response.json()

    def open(self) -> None:
        """Open the database connection.

        Establishes a connection to the EL2GO database for subsequent operations.

        :raises SPSDKError: If database connection fails or database is already open.
        """

    def close(self) -> None:
        """Close the database connection.

        This method properly closes the database connection and releases any associated resources.
        """


@dataclass
class ProdDBStats:
    """Product database statistics container for EL2GO provisioning operations.

    This class holds statistical information about dynamic records and reports
    in the product-based provisioning database, providing a structured way to
    track database usage and capacity.
    """

    has_dynamic_records: int = 0
    used_dynamic_records: int = 0
    free_dynamic_records: int = 0
    reports: int = 0

    def __str__(self) -> str:
        """Get string representation of the database status.

        Provides a formatted multi-line string containing information about dynamic records
        availability, usage statistics, and total reports count.

        :return: Formatted string with database status information.
        """
        msgs = [
            f"Has Dynamic Records: {'Yes' if self.has_dynamic_records else 'No'}",
            f"Used Dynamic Records: {self.used_dynamic_records}",
            f"Free Dynamic Records: {self.free_dynamic_records}",
            f"Total Reports: {self.reports}",
        ]
        return "\n".join(msgs)


class LocalProductBasedBatchDB(LocalDB):
    """Local product-based batch database for EL2GO secure provisioning.

    This class manages a SQLite database for batch processing of secure objects, attestation keys,
    and device reports in EL2GO workflows. It maintains three main tables: static data for
    job-level information, dynamic data for device-specific secure objects, and reports for
    provisioning results.
    """

    def _setup_db(self) -> None:
        """Initialize and set up the local batch processing database schema.

        Creates the necessary tables (static, dynamic, report) with their respective schemas
        if they don't already exist. The method uses a sanitized cursor to execute the
        database setup script safely.

        :raises SPSDKError: Database connection or setup operation fails.
        """
        logger.debug("Setting up local batch processing database")
        with self:
            # Create table if not exists with appropriate schema
            cursor = self._sanitize_cursor()
            cursor.executescript(
                """
                CREATE TABLE IF NOT EXISTS static (
                    version INTEGER DEFAULT 1,
                    job_id TEXT,
                    secure_object BLOB,
                    attestation_key BLOB,
                    has_dynamic BOOLEAN,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS dynamic (
                    virtual_uuid TEXT PRIMARY KEY,
                    secure_object BLOB,
                    used BOOLEAN DEFAULT 0,
                    uuid TEXT,
                    FOREIGN KEY(uuid) REFERENCES report(uuid)
                );
                CREATE TABLE IF NOT EXISTS report (
                    uuid TEXT PRIMARY KEY,
                    report BLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )

    def __init__(self, file_path: str, lock_timeout: Optional[int] = 10):
        """Initialize local product-based database.

        :param file_path: Path to the database file.
        :param lock_timeout: Timeout in seconds for database lock acquisition, defaults to 10.
        """
        super().__init__(file_path, lock_timeout=lock_timeout)
        self._attestation_key: Optional[PublicKey] = None

    @property
    def attestation_key(self) -> PublicKey:
        """Retrieve or lazily load the attestation key.

        The method fetches the attestation key from the database if not already cached in memory.
        Uses lazy loading pattern to avoid unnecessary database queries.

        :raises SPSDKError: Attestation key data is not set in the database.
        :return: The parsed attestation public key from the database.
        """
        if not self._attestation_key:
            cursor = self._sanitize_cursor()
            cursor.execute("SELECT attestation_key FROM static LIMIT 1")
            row = cursor.fetchone()
            if not row:
                raise SPSDKError("Attestation key data is not set")
            attestation_key_data = row[0]
            self._attestation_key = PublicKey.parse(attestation_key_data)
        return self._attestation_key

    def _clear_all(self) -> None:
        """Clear all records from both static and dynamic tables.

        This method removes all data from the batch processing database by executing
        DELETE operations on both the static and dynamic tables. The operation is
        logged for audit purposes.

        :raises SPSDKError: If database cursor sanitization fails or SQL execution encounters an error.
        """
        logger.info("Clearing all records from batch processing database")
        cursor = self._sanitize_cursor()
        cursor.execute("DELETE FROM static")
        cursor.execute("DELETE FROM dynamic")

    def insert_static_record(
        self, job_id: str, secure_object: bytes, attestation_key: bytes, has_dynamic: bool
    ) -> None:
        """Insert a new record into the static table.

        This method adds a new entry to the static table with the provided job ID,
        secure object data, attestation key, and dynamic flag information.

        :param job_id: Unique identifier for the job.
        :param secure_object: Binary data containing the secure object.
        :param attestation_key: Binary data containing the attestation key.
        :param has_dynamic: Flag indicating whether the record has dynamic components.
        """
        cursor = self._sanitize_cursor()
        cursor.execute(
            "INSERT INTO static (job_id, secure_object, attestation_key, has_dynamic) VALUES (?, ?, ?, ?)",
            (job_id, secure_object, attestation_key, has_dynamic),
        )
        logger.info("Inserted static record with secure object")

    def insert_dynamic_record(self, virtual_uuid: str, secure_object: bytes) -> None:
        """Insert a new record into the dynamic table.

        This method adds a new entry to the dynamic table with the provided virtual UUID
        and secure object data.

        :param virtual_uuid: The virtual UUID identifier for the record.
        :param secure_object: The secure object data to be stored as bytes.
        """
        cursor = self._sanitize_cursor()
        cursor.execute(
            "INSERT INTO dynamic (virtual_uuid, secure_object) VALUES (?, ?)",
            (virtual_uuid, secure_object),
        )
        logger.info(f"Inserted dynamic record with virtual UUID: {virtual_uuid}")

    def insert_report(self, report: bytes) -> None:
        """Add a report to the dynamic record.

        This method extracts the UUID from the report, verifies the report signature
        using the attestation key, and stores the report in the database.

        :param report: Binary report data containing UUID and signature
        :raises SPSDKError: Invalid report signature
        """
        # TODO: add proper report parsing
        uuid = report[2:18].hex()
        if not self.attestation_key.verify_signature(report[-64:], report[:-64]):
            raise SPSDKError("Invalid report signature")
        cursor = self._sanitize_cursor()
        cursor.execute(
            "INSERT INTO report (uuid, report) VALUES (?, ?)",
            (uuid, report),
        )

    def get_next_secure_object(self) -> bytes:
        """Get the next available secure object by combining static and dynamic data.

        Retrieves a secure object from the database by first fetching static data and then
        combining it with dynamic data if required. Dynamic records are marked as used to
        prevent reuse.

        :raises SPSDKError: No valid static record found or no unused dynamic record available.
        :return: Combined secure object as bytes from static and dynamic data.
        """
        cursor = self._sanitize_cursor()

        # Get secure_object from static table
        cursor.execute("SELECT has_dynamic, secure_object FROM static LIMIT 1")
        static_record = cursor.fetchone()
        if not static_record or not static_record[1]:
            raise SPSDKError("No valid static record found")

        has_dynamic, static_so = static_record
        if not has_dynamic:
            logger.info("No dynamic data required, returning static secure object")
            return static_so

        # Get unused record from dynamic table
        cursor.execute("SELECT virtual_uuid, secure_object FROM dynamic WHERE used = 0 LIMIT 1")
        dynamic_record = cursor.fetchone()
        if not dynamic_record:
            raise SPSDKError("No unused dynamic record found")

        virtual_uuid, dynamic_so = dynamic_record

        cursor.execute("UPDATE dynamic SET used = 1 WHERE virtual_uuid = ?", (virtual_uuid,))
        # preemptively commit the update to mark the record as used
        cursor.connection.commit()

        combined_so = static_so + dynamic_so

        logger.info(f"Retrieved and marked as used: virtual_uuid={virtual_uuid}")
        return combined_so

    def get_stats(self) -> ProdDBStats:
        """Retrieve database statistics and usage information.

        The method queries the production database to collect comprehensive statistics
        including dynamic record availability, usage counts, and report totals.

        :return: Database statistics containing dynamic records status, usage counts, and reports.
        """
        cursor = self._sanitize_cursor()

        cursor.execute("SELECT has_dynamic FROM static")
        has_dynamic_records = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM dynamic WHERE used = 0")
        free_dynamic_records = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM dynamic WHERE used = 1")
        used_dynamic_records = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM report")
        reports = cursor.fetchone()[0]

        return ProdDBStats(
            has_dynamic_records=has_dynamic_records,
            used_dynamic_records=used_dynamic_records,
            free_dynamic_records=free_dynamic_records,
            reports=reports,
        )

    def process(self, data: dict) -> None:
        """Process EL2GO response data and populate database records.

        This method parses the EL2GO provisioning response, extracts static and dynamic
        provisioning data, decodes base64-encoded secure objects, and stores them in
        the database using appropriate record insertion methods.

        :param data: EL2GO response data containing metadata, static and optional dynamic provisioning records
        """
        self._clear_all()
        job_id = data["metadata"].get("jobId", "N/A")
        puk_data = data["metadata"]["provisioningReportAttestationKey"]["publicKey"]
        puk = base64.b64decode(puk_data)
        has_dynamic = "dynamicProvisionings" in data
        secure_object = bytes()
        for static_record in data["staticProvisionings"]:
            object_data = base64.b64decode(static_record["data"])
            secure_object += object_data
        self.insert_static_record(job_id, secure_object, puk, has_dynamic)

        if not has_dynamic:
            return

        for virtual_uuid, dynamic_records in data["dynamicProvisionings"].items():
            secure_object = bytes()
            for dynamic_record in dynamic_records:
                dynamic_object_data = base64.b64decode(dynamic_record["data"])
                secure_object += dynamic_object_data
            self.insert_dynamic_record(virtual_uuid, secure_object)


class RemoteProductBasedBatchDB(HTTPClientBase):
    """Remote product-based batch database client for EL2GO provisioning operations.

    This class provides HTTP-based communication with a remote database server for
    managing secure objects and provisioning reports in product-based batch scenarios.
    It handles retrieval of secure objects for device provisioning and submission
    of provisioning reports back to the server.

    :cvar api_version: API version used for communication with the remote server.
    """

    api_version = "1.0.0"

    def __init__(self, host: str = "localhost", port: int = 8000):
        """Initialize remote product-based batch database client.

        :param host: Hostname or IP address of the database server.
        :param port: Port number for the database connection.
        """
        super().__init__(host, port, url_prefix="", use_ssl=False, raise_exceptions=True)

    def insert_report(self, report: bytes) -> None:
        """Add a provisioning report to the remote database.

        The method sends the provisioning report data to the remote database endpoint
        via HTTP POST request with the report data encoded as hexadecimal string.

        :param report: Binary provisioning report data to be sent to database.
        :raises SPSDKError: Failed to send report to remote database.
        """
        logger.info("Sending report to remote database")
        payload = {"data": report.hex()}
        response = self._handle_request(self.Method.POST, "/report", json_data=payload)
        if not response.ok:
            raise SPSDKError(f"Failed to send report: {response.text}")

    def get_next_secure_object(self) -> bytes:
        """Get the next available secure object from remote database.

        Retrieves the next available secure object from the EL2GO remote database
        and converts it from hexadecimal format to bytes.

        :raises SPSDKError: Failed to retrieve secure object from database or no secure object
                           found in response.
        :return: Secure object data as bytes.
        """
        logger.info("Requesting next secure object from remote database")
        response = self._handle_request(self.Method.GET, "/secure-object")
        if not response.ok:
            raise SPSDKError(f"Failed to retrieve secure object: {response.text}")
        secure_object_hex = response.json().get("data")
        if not secure_object_hex:
            raise SPSDKError("No secure object found in response")
        return bytes.fromhex(secure_object_hex)

    def get_stats(self) -> ProdDBStats:
        """Retrieve remote database statistics.

        Fetches statistical information from the remote EL2GO database including
        dynamic records usage and report counts.

        :raises SPSDKError: Failed to retrieve database statistics from remote server.
        :return: Database statistics containing dynamic records and reports information.
        """
        logger.info("Requesting database statistics from remote database")
        response = self._handle_request(self.Method.GET, "/stats")
        if not response.ok:
            raise SPSDKError(f"Failed to retrieve database statistics: {response.text}")

        stats = response.json()
        return ProdDBStats(
            has_dynamic_records=stats.get("has_dynamic_records", 0),
            used_dynamic_records=stats.get("used_dynamic_records", 0),
            free_dynamic_records=stats.get("free_dynamic_records", 0),
            reports=stats.get("reports", 0),
        )
