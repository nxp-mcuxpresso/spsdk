#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2024-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for handling UUID-Secure Object database."""
import abc
import base64
import datetime
import logging
import sqlite3
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


class LocalDB(abc.ABC):
    """Base local database implementation."""

    def __init__(self, file_path: str, lock_timeout: Optional[int] = 10) -> None:
        """Initialize local batch processing."""
        self.file_path = file_path
        self.lock = FileLock(f"{file_path}.lock", timeout=lock_timeout) if lock_timeout else None
        self.connection: Optional[sqlite3.Connection] = None
        self.cursor: Optional[sqlite3.Cursor] = None
        self._setup_db()

    def open(self) -> None:
        """Open the database connection."""
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
        """Close the database connection."""
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
        """Context manager entry method to open database connection."""
        self.open()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[Exception]] = None,
        exc_val: Optional[Exception] = None,
        exc_tb: Optional[TracebackType] = None,
    ) -> None:
        self.close()
        if isinstance(exc_val, sqlite3.Error):
            raise SPSDKError(f"Error during database operation: {exc_val}") from exc_val
        if isinstance(exc_val, SPSDKError):
            raise SPSDKError(exc_val.description) from exc_val
        if exc_val:
            raise SPSDKError(str(exc_val)) from exc_val

    def _sanitize_cursor(self) -> sqlite3.Cursor:
        """Ensure a valid database cursor is available."""
        if not self.cursor or not self.connection:
            raise SPSDKError("Database connection is not open. Call open() or use `with`.")
        return self.cursor

    @abc.abstractmethod
    def _setup_db(self) -> None:
        """Abstract method to set up database schema."""


class LocalSecureObjectsDB(LocalDB, SecureObjectsDB):
    """Handler for UUID-Secure_Objects database using a local sqlite file."""

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


class LocalProductBasedBatchDB(LocalDB):
    """Batch processing for local database connection."""

    def _setup_db(self) -> None:
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
        """Initialize local product-based database."""
        super().__init__(file_path, lock_timeout=lock_timeout)
        self._attestation_key: Optional[PublicKey] = None

    @property
    def attestation_key(self) -> PublicKey:
        """Retrieve or lazily load the attestation key."""
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
        """Clear all records from both static and dynamic tables."""
        logger.info("Clearing all records from batch processing database")
        cursor = self._sanitize_cursor()
        cursor.execute("DELETE FROM static")
        cursor.execute("DELETE FROM dynamic")

    def insert_static_record(
        self, job_id: str, secure_object: bytes, attestation_key: bytes, has_dynamic: bool
    ) -> None:
        """Insert a new record into the static table."""
        cursor = self._sanitize_cursor()
        cursor.execute(
            "INSERT INTO static (job_id, secure_object, attestation_key, has_dynamic) VALUES (?, ?, ?, ?)",
            (job_id, secure_object, attestation_key, has_dynamic),
        )
        logger.info("Inserted static record with secure object")

    def insert_dynamic_record(self, virtual_uuid: str, secure_object: bytes) -> None:
        """Insert a new record into the dynamic table."""
        cursor = self._sanitize_cursor()
        cursor.execute(
            "INSERT INTO dynamic (virtual_uuid, secure_object) VALUES (?, ?)",
            (virtual_uuid, secure_object),
        )
        logger.info(f"Inserted dynamic record with virtual UUID: {virtual_uuid}")

    def insert_report(self, report: bytes) -> None:
        """Add a report to the dynamic record."""
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
        """Get the next available secure object by combining static and dynamic data."""
        cursor = self._sanitize_cursor()

        # Get secure_object from static table
        cursor.execute("SELECT has_dynamic, secure_object FROM static LIMIT 1")
        static_record = cursor.fetchone()
        if not static_record or not static_record[0]:
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

    def process(self, data: dict) -> None:
        """Process EL2GO response data."""
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
    """Handler for remote product-based batch database operations."""

    api_version = "1.0.0"

    def __init__(self, host: str = "localhost", port: int = 8000):
        """Initialize remote product-based batch database client."""
        super().__init__(host, port, url_prefix="", use_ssl=False, raise_exceptions=True)

    def insert_report(self, report: bytes) -> None:
        """Add a provisioning report."""
        logger.info("Sending report to remote database")
        payload = {"data": report.hex()}
        response = self._handle_request(self.Method.POST, "/report", json_data=payload)
        if not response.ok:
            raise SPSDKError(f"Failed to send report: {response.text}")

    def get_next_secure_object(self) -> bytes:
        """Get the next available secure object."""
        logger.info("Requesting next secure object from remote database")
        response = self._handle_request(self.Method.GET, "/secure-object")
        if not response.ok:
            raise SPSDKError(f"Failed to retrieve secure object: {response.text}")
        secure_object_hex = response.json().get("data")
        if not secure_object_hex:
            raise SPSDKError("No secure object found in response")
        return bytes.fromhex(secure_object_hex)
