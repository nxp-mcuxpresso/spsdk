#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for generating, processing and verifying TP Audit Log."""
import contextlib
import os
import sqlite3
from typing import Iterator, NamedTuple, Optional

from spsdk.crypto.hash import get_hash
from spsdk.crypto.keys import PublicKeyEcc
from spsdk.tp.data_container.data_container import Container
from spsdk.tp.data_container.payload_types import PayloadType
from spsdk.tp.exceptions import SPSDKTpError
from spsdk.utils.misc import Endianness

DB_VERSION = 2

CREATE_TABLE_COMMAND = """
    CREATE TABLE IF NOT EXISTS records (
        id integer PRIMARY KEY,
        nxp_cert blob,
        oem_cert_0 blob,
        oem_cert_1 blob,
        oem_cert_2 blob,
        oem_cert_3 blob,
        prod_counter blob,
        start_hash blob,
        signature blob
    );
    CREATE TABLE IF NOT EXISTS properties (
        id integer PRIMARY KEY,
        version integer,
        tp_device_id text
    );
"""

INSERT_COMMAND = """
    INSERT INTO records (
        nxp_cert, oem_cert_0, oem_cert_1, oem_cert_2, oem_cert_3,
        prod_counter, start_hash, signature
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
"""

SELECT_COMMAND = """
    SELECT * from records
"""

# Python is indexing from 0, while SQLite from 1
# Python slice does't include the last item, unlike SQLite's BETWEEN operator
SELECT_SLICE_COMMAND = """
    SELECT * FROM records WHERE id >= (? + 1) and id < (? + 1)
"""

RECORD_COUNT_COMMAND = """
    SELECT COUNT(*) FROM records
"""

INSERT_PROPERTIES_COMMAND = """
    INSERT INTO properties (
        version,  tp_device_id
    ) VALUES (?, ?)
"""

UPDATE_PROPERTIES_COMMAND = """
    UPDATE properties
    SET tp_device_id = ?
"""

SELECT_PROPERTIES_COMMAND = """
    SELECT * from properties
"""


@contextlib.contextmanager
def sqlite_cursor(file_path: str) -> Iterator[sqlite3.Cursor]:
    """Yield an cursor to SQLite database.

    :param file_path: Path to SQLite database file
    :raises SPSDKTpError: Error during SQL operation
    :yield: SQLite cursor
    """
    try:
        conn = sqlite3.connect(file_path)
        cursor = conn.cursor()
        yield cursor
    except sqlite3.Error as sql_error:
        raise SPSDKTpError(
            f"Error during sqlite operation using audit log file '{file_path}': {sql_error}"
        ) from sql_error
    except Exception as e:
        raise SPSDKTpError(str(e)) from e
    finally:
        if "conn" in locals():
            conn.commit()
            conn.close()


def _sqlite_setup(file_path: str, tp_device_id: str) -> None:
    """Setup an SQLite database file."""
    with sqlite_cursor(file_path) as cursor:
        cursor.executescript(CREATE_TABLE_COMMAND)
        cursor.execute(INSERT_PROPERTIES_COMMAND, (DB_VERSION, tp_device_id))


class AuditLogRecord(NamedTuple):
    """Single record in the Audit log."""

    nxp_id_cert: bytes
    oem_id_certs: list[bytes]
    prod_counter: bytes
    start_hash: bytes
    signature: bytes

    @classmethod
    def from_data(cls, container_data: bytes) -> "AuditLogRecord":
        """Create AuditLogRecord from TP Data Container."""
        container = Container.parse(container_data)
        nxp_id_cert = container.get_entry(PayloadType.NXP_DIE_ID_AUTH_CERT).payload
        oem_id_certs = [
            item.payload for item in container.get_entries(PayloadType.OEM_DIE_DEVATTEST_ID_CERT)
        ]
        prod_counter = container.get_entry(PayloadType.OEM_PROD_COUNTER).payload
        start_hash = container.get_entry(PayloadType.OEM_TP_LOG_HASH).payload
        signature = container.get_entry(PayloadType.OEM_TP_LOG_SIGN).payload

        return AuditLogRecord(
            nxp_id_cert=nxp_id_cert,
            oem_id_certs=oem_id_certs,
            prod_counter=prod_counter,
            start_hash=start_hash,
            signature=signature,
        )

    @classmethod
    def from_dict(cls, data: dict) -> "AuditLogRecord":
        """Create AuditLogRecord from a dictionary."""
        try:
            return AuditLogRecord(
                nxp_id_cert=data[PayloadType.name(PayloadType.NXP_DIE_ID_AUTH_CERT)],
                oem_id_certs=data[PayloadType.name(PayloadType.OEM_DIE_DEVATTEST_ID_CERT)],
                prod_counter=data[PayloadType.name(PayloadType.OEM_PROD_COUNTER)],
                start_hash=data[PayloadType.name(PayloadType.OEM_TP_LOG_HASH)],
                signature=data[PayloadType.name(PayloadType.OEM_TP_LOG_SIGN)],
            )
        except Exception as e:
            raise SPSDKTpError(f"Invalid AuditLog dictionary record: {e}") from e

    @property
    def prod_counter_int(self) -> int:
        """Return production counter as an integer."""
        return int.from_bytes(self.prod_counter, byteorder=Endianness.BIG.value)

    def as_dict(self) -> dict:
        """Return dictionary suitable for writing into log file."""
        record = {
            PayloadType.name(PayloadType.NXP_DIE_ID_AUTH_CERT): self.nxp_id_cert,
            PayloadType.name(PayloadType.OEM_DIE_DEVATTEST_ID_CERT): self.oem_id_certs,
            PayloadType.name(PayloadType.OEM_PROD_COUNTER): self.prod_counter,
            PayloadType.name(PayloadType.OEM_TP_LOG_HASH): self.start_hash,
            PayloadType.name(PayloadType.OEM_TP_LOG_SIGN): self.signature,
        }
        return record

    @classmethod
    def from_tuple(cls, data: tuple) -> "AuditLogRecord":
        """Create AuditLogRecord from a tuple."""
        # tuple of length more than 8 signifies using a row directly from table
        # in such case, ignore the first entry 'id'
        if len(data) > 8:
            data = data[1:]
        return AuditLogRecord(
            nxp_id_cert=data[0],
            oem_id_certs=list(filter(None, [data[1], data[2], data[3], data[4]])),
            prod_counter=data[5],
            start_hash=data[6],
            signature=data[7],
        )

    def as_tuple(self) -> tuple:
        """Return AuditLogRecord as tuple."""
        return (
            self.nxp_id_cert,
            *tuple(self.oem_id_certs[i] if i < len(self.oem_id_certs) else None for i in range(4)),
            self.prod_counter,
            self.start_hash,
            self.signature,
        )

    def new_hash(self) -> bytes:
        """Hash together the relevant pieces of the record."""
        data_to_hash = self.nxp_id_cert
        for oem_cert in self.oem_id_certs:
            data_to_hash += oem_cert or bytes()
        data_to_hash += self.prod_counter
        data_to_hash += self.start_hash
        return get_hash(data_to_hash)

    def is_valid(self, key: PublicKeyEcc) -> bool:
        """Check if record is valid.

        :param key: PEM-encoded public key or public key object
        :return: True if signature checks out
        """
        new_hash = self.new_hash()
        return key.verify_signature(
            signature=self.signature,
            data=new_hash,
        )

    def save(self, file_path: str, tp_device_id: str) -> None:
        """Store record in an sqlite database file."""
        if not os.path.isfile(file_path):
            _sqlite_setup(file_path, tp_device_id)
        with sqlite_cursor(file_path) as cursor:
            cursor.execute(INSERT_COMMAND, self.as_tuple())


class AuditLogProperties(NamedTuple):
    """Properties of the Audit log."""

    version: int
    tp_device_id: str

    @classmethod
    def from_tuple(cls, data: tuple) -> "AuditLogProperties":
        """Create AuditLogProperties from database tuple.

        :raises SPSDKTpError: Unexpected number of data members.
        """
        # first item in data is index; we can skip that
        if len(data) != 3:
            raise SPSDKTpError(f"AuditLogProperties record expects 3 items, got: {len(data)}")
        return AuditLogProperties(data[1], data[2])


class AuditLog(list[AuditLogRecord]):
    """Full Audit log, List of AuditLogRecords."""

    @staticmethod
    def load(file_path: str) -> "AuditLog":
        """Load AuditLog from a sqlite database file."""
        log = AuditLog()
        with sqlite_cursor(file_path) as cursor:
            cursor.execute(SELECT_COMMAND)
            rows = cursor.fetchall()
            for row in rows:
                # pylint: disable=no-member  # Pylint struggles to understand Audit log is a list
                log.append(AuditLogRecord.from_tuple(row[1:]))
        return log

    def save(self, file_path: str, tp_device_id: str) -> None:
        """Store AuditLog into a sqlite database file."""
        if os.path.isfile(file_path):
            os.remove(file_path)
        _sqlite_setup(file_path, tp_device_id)
        with sqlite_cursor(file_path) as cursor:
            for record in self:  # pylint: disable=not-an-iterable  # yes, it is iterable
                cursor.execute(INSERT_COMMAND, record.as_tuple())

    @staticmethod
    def records(
        file_path: str, id_slice: Optional[tuple[int, int]] = None
    ) -> Iterator[tuple[int, AuditLogRecord]]:
        """Read records from database file.

        :param file_path: Path to database file
        :param id_slice: Read records with id between (x, y), defaults to None
        :yield: Iterator yielding record ID and record itself
        """
        command = (SELECT_SLICE_COMMAND, id_slice) if id_slice else (SELECT_COMMAND,)
        with sqlite_cursor(file_path) as cursor:
            cursor.execute(*command)
            for item in cursor:
                yield item[0], AuditLogRecord.from_tuple(item)

    @staticmethod
    def record_count(file_path: str) -> int:
        """Return number of records in database file."""
        with sqlite_cursor(file_path) as cursor:
            cursor.execute(RECORD_COUNT_COMMAND)
            row = cursor.fetchone()
            return row[0]

    @staticmethod
    def properties(file_path: str) -> AuditLogProperties:
        """Return properties of database.

        :param file_path: Path to audit log file.
        :raises SPSDKTpError: Unable to read properties table
        """
        try:
            with sqlite_cursor(file_path) as cursor:
                cursor.execute(SELECT_PROPERTIES_COMMAND)
                row = cursor.fetchone()
                return AuditLogProperties.from_tuple(row)
        except SPSDKTpError as e:
            raise SPSDKTpError(
                "Couldn't read audit log properties. Perhaps you're using an old audit log file. "
                f"\nUnderlying issue: {e}"
            ) from e


class AuditLogCounter:
    """Counter for Audit Log stats (records verified, certificates exported)."""

    def __init__(self, check_count: int = 0, nxp_count: int = 0, oem_count: int = 0) -> None:
        """Initialize counters for Audit log verification."""
        self.check_count = check_count
        self.nxp_count = nxp_count
        self.oem_count = oem_count

    def __add__(self, other: "AuditLogCounter") -> "AuditLogCounter":
        if not isinstance(other, AuditLogCounter):
            return NotImplemented
        return AuditLogCounter(
            check_count=self.check_count + other.check_count,
            nxp_count=self.nxp_count + other.nxp_count,
            oem_count=self.oem_count + other.oem_count,
        )

    def __iadd__(self, other: "AuditLogCounter") -> "AuditLogCounter":
        if not isinstance(other, AuditLogCounter):
            return NotImplemented
        self.check_count += other.check_count
        self.oem_count += other.oem_count
        self.nxp_count += other.nxp_count
        return self

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({', '.join(f'{name}={value}' for name, value in vars(self).items())})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AuditLogCounter):
            return NotImplemented
        return vars(self) == vars(other)

    def __str__(self) -> str:
        return (
            f"Records verified:  {self.check_count:,}\n"
            f"NXP cert exported: {self.nxp_count:,}\n"
            f"OEM cert exported: {self.oem_count:,}"
        )
