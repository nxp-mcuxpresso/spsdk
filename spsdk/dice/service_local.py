#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2023-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Module for local DICE attestation."""

import contextlib
import logging
import secrets
import sqlite3
from datetime import date, datetime, time
from typing import Iterator, Optional

from spsdk.crypto.keys import PublicKeyEcc
from spsdk.dice.exceptions import SPSDKDICEError, SPSDKDICEVerificationError
from spsdk.dice.models import APIResponse, DICEResponse, DICEVerificationService
from spsdk.dice.utils import reconstruct_ecc_key, serialize_ecc_key

logger = logging.getLogger(__name__)


sqlite3.register_adapter(bool, int)
sqlite3.register_converter("BOOLEAN", lambda v: bool(int(v)))

sqlite3.register_adapter(date, lambda v: v.isoformat())
sqlite3.register_converter("DATE", lambda v: date.fromisoformat(v.decode("utf-8")))

sqlite3.register_adapter(time, lambda v: v.isoformat())
sqlite3.register_converter("TIME", lambda v: time.fromisoformat(v.decode("utf-8")))

sqlite3.register_adapter(datetime, lambda v: v.isoformat())
sqlite3.register_converter("DATETIME", lambda v: datetime.fromisoformat(v.decode("utf-8")))


CREATE_DATABASE_COMMAND = """
    CREATE TABLE IF NOT EXISTS settings (
        "name" varchar NOT NULL,
        "version" integer NOT NULL,
        "value" text NOT NULL
    );
    CREATE TABLE IF NOT EXISTS csrs (
        "uuid" varchar(32) NOT NULL PRIMARY KEY,
        "version" integer NOT NULL,
        "puk" text NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attestation_records (
        "challenge" varchar(64) NOT NULL PRIMARY KEY,
        "issued" datetime NOT NULL,
        "uuid" varchar(32) NULL,
        "version" integer NULL,
        "completed" datetime NULL,
        "status" varchar(20) NOT NULL
    );
"""


@contextlib.contextmanager
def sqlite_cursor(file_path: str) -> Iterator[sqlite3.Cursor]:
    """Yield an cursor to SQLite database.

    :param file_path: Path to SQLite database file
    :raises SPSDKDICEError: Error during SQL operation
    :yield: SQLite cursor
    """
    try:
        conn = sqlite3.connect(file_path)
        cursor = conn.cursor()
        yield cursor
    except sqlite3.Error as sql_error:
        raise SPSDKDICEError(
            f"Error during sqlite operation using database '{file_path}': {sql_error}"
        ) from sql_error
    except Exception as e:
        raise SPSDKDICEError(str(e)) from e
    finally:
        if "conn" in locals():
            conn.commit()
            conn.close()


class LocalDICEVerificationService(DICEVerificationService):
    """DICE Verification adapter using a local database."""

    def __init__(self, file_path: str) -> None:
        """Initialize the local verification service with given path to database file (sqlite3)."""
        self.db_file = file_path
        self._setup_db()

    def _setup_db(self) -> None:
        """Create database if not already exists."""
        logger.debug("Setting up a database")
        with sqlite_cursor(self.db_file) as cursor:
            cursor.executescript(CREATE_DATABASE_COMMAND)

    def register_dice_ca_puk(self, key_data: bytes) -> APIResponse:
        """Register NXP_CUST_DICE_CA_PUK in the service."""
        logger.info("Registering NXP_CUST_DICE_CA_PUK")
        ca_puk = reconstruct_ecc_key(puk_data=key_data)
        pem_data = serialize_ecc_key(key=ca_puk)
        with sqlite_cursor(self.db_file) as cursor:
            cursor.execute(
                "DELETE FROM settings where name = 'DICE_CA_PUK'",
            )
            cursor.execute(
                "INSERT INTO settings(name, version, value) VALUES(?, ?, ?)",
                ("DICE_CA_PUK", 0, pem_data),
            )
        return APIResponse(
            api="register-ca-puk",
            status="OK",
            message="NXP_CUST_DICE_CA_PUK set successfully.",
        )

    def register_version(self, data: bytes, allow_update: bool = True) -> APIResponse:
        """Register new FW version, RTF and HAD based on DICE response."""
        logger.info("Registering RTF and HAD for new version")
        response = DICEResponse.parse(data=data)
        with sqlite_cursor(self.db_file) as cursor:
            cursor.execute(
                "SELECT version FROM settings WHERE version = ?", (response.version_int,)
            )
            found = cursor.fetchone()
            if found and not allow_update:
                return APIResponse(
                    api="register-version",
                    status="VERSION_ALREADY_EXISTS",
                    message=f"FW Version {response.version_int} already exists in the system",
                )
            if found:
                cursor.executemany(
                    "UPDATE settings SET value = ? WHERE name = ? AND version = ?",
                    [
                        (response.rtf.hex(), "RTF", response.version_int),
                        (response.had.hex(), "HAD", response.version_int),
                    ],
                )
            else:
                cursor.executemany(
                    "INSERT INTO settings(name, version, value) VALUES(?, ?, ?)",
                    [
                        ("RTF", response.version_int, response.rtf.hex()),
                        ("HAD", response.version_int, response.had.hex()),
                    ],
                )
        return APIResponse(
            api="register-version",
            status="OK",
            message=f"FW Version, RTF, and HAD {'updated' if found else 'registered'} successfully.",
        )

    def get_challenge(self, pre_set: Optional[str] = None) -> bytes:
        """Get challenge vector from the service."""
        logger.info("Generating DICE challenge")
        timestamp = datetime.now()
        challenge = pre_set or secrets.token_hex(32)
        for _ in range(10):
            try:
                with sqlite_cursor(self.db_file) as cursor:
                    if pre_set:
                        cursor.execute(
                            "DELETE FROM attestation_records WHERE challenge = ?", (pre_set,)
                        )
                        cursor.connection.commit()
                    cursor.execute(
                        "INSERT INTO attestation_records(challenge, issued, status) VALUES(?, ?, ?)",
                        (challenge, timestamp, "INCOMPLETE"),
                    )
                    return bytes.fromhex(challenge)
            except SPSDKDICEError as e:
                # we expect UNIQUE constraint failure (thus the for loop)
                logger.debug(str(e))
        raise SPSDKDICEError(
            "Could not generate unique challenge. Consider pruning attestation_records data."
        )

    def _verify_challenge(
        self, response: DICEResponse, attestation_record: Optional[tuple]
    ) -> None:
        if not attestation_record:
            raise SPSDKDICEVerificationError(
                status="INVALID_CHALLENGE",
                message=f"Challenge {response.challenge.hex()} couldn't be found!",
            )
        if attestation_record[3] is not None:
            raise SPSDKDICEVerificationError(
                status="REPEATED_CHALLENGE",
                message=f"Challenge {response.challenge.hex()} has already been used!",
            )

    def _verify_rtf(self, response: DICEResponse, cursor: sqlite3.Cursor) -> None:
        cursor.execute(
            "SELECT value FROM settings WHERE name = 'RTF' AND version = ?",
            (response.version_int,),
        )
        rtf_record = cursor.fetchone()
        if not rtf_record:
            raise SPSDKDICEVerificationError(
                status="RTF_NOT_SET",
                message=f"RTF value is not set for version {response.version_int}!",
            )
        if rtf_record[0] != response.rtf.hex():
            raise SPSDKDICEVerificationError(
                status="INVALID_RTF",
                message="RTF value doesn't match expected value",
            )

    def _verify_ca_puk(self, cursor: sqlite3.Cursor) -> PublicKeyEcc:
        cursor.execute("SELECT value FROM settings WHERE name = 'DICE_CA_PUK'")
        ca_puk_record = cursor.fetchone()
        if not ca_puk_record:
            raise SPSDKDICEVerificationError(
                status="DICE_CA_PUK_NOT_FOUND",
                message="NXP_CUST_DICE_CA_PUK was not found",
            )
        ca_puk_data: str = ca_puk_record[0]
        ca_puk = PublicKeyEcc.parse(data=ca_puk_data.encode("utf8"))
        return ca_puk

    def _verify_signatures(self, response: DICEResponse, ca_puk: PublicKeyEcc) -> PublicKeyEcc:
        if not response.verify_ca_signature(ca_puk=ca_puk):
            raise SPSDKDICEVerificationError(
                status="INVALID_CA_SIGNATURE",
                message="CA signature verification failed!",
            )

        if not response.verify_die_signature():
            raise SPSDKDICEVerificationError(
                status="INVALID_DIE_SIGNATURE",
                message="DIE signature verification failed!",
            )
        die_puk = PublicKeyEcc(reconstruct_ecc_key(puk_data=response.die_puk))
        return die_puk

    def _verify_csr(
        self, response: DICEResponse, die_puk: PublicKeyEcc, cursor: sqlite3.Cursor
    ) -> None:
        die_puk_pem = serialize_ecc_key(key=die_puk.key)
        cursor.execute(
            "SELECT puk FROM csrs WHERE uuid = ? AND version = ?",
            (response.uuid.hex(), response.version_int),
        )
        csr_record = cursor.fetchone()
        if not csr_record:
            cursor.execute(
                "INSERT INTO csrs(uuid, version, puk) VALUES(?, ?, ?)",
                (response.uuid.hex(), response.version_int, die_puk_pem),
            )
        else:
            if csr_record[0] != die_puk_pem:
                raise SPSDKDICEVerificationError(
                    status="DIE_PUK_CHANGED",
                    message=(
                        f"CUST_DIE_DICE_CA_PUK for uuid={response.uuid.hex()}, "
                        f"version={response.version_int} has changed"
                    ),
                )

    def _verify_had(
        self, response: DICEResponse, cursor: sqlite3.Cursor
    ) -> Optional[tuple[str, str]]:
        cursor.execute(
            "SELECT value FROM settings WHERE name = 'HAD' AND version = ?",
            (response.version_int,),
        )
        had_record = cursor.fetchone()
        if not had_record:
            raise SPSDKDICEVerificationError(
                status="HAD_NOT_SET",
                message=f"HAD value is not set for version {response.version_int}!",
            )
        if had_record[0] != response.had.hex():
            return had_record[0], response.had.hex()
            # raise SPSDKDICEVerificationError(
            #     status="INVALID_HAD",
            #     message="HAD value doesn't match expected value",
            # )
        return None

    def verify(self, data: bytes, reset_challenge: bool = False) -> APIResponse:
        """Submit DICE response for verification."""
        logger.info("Verifying DICE Response")
        api = "verify"
        response = DICEResponse.parse(data=data)

        if reset_challenge:
            self.get_challenge(pre_set=response.challenge.hex())

        timestamp = datetime.now()
        with sqlite_cursor(self.db_file) as cursor:
            cursor.execute(
                "SELECT * FROM attestation_records WHERE challenge = ?",
                (response.challenge.hex(),),
            )
            attestation_record = cursor.fetchone()
            try:
                self._verify_challenge(response=response, attestation_record=attestation_record)

                ca_puk = self._verify_ca_puk(cursor=cursor)

                die_puk = self._verify_signatures(response=response, ca_puk=ca_puk)

                self._verify_csr(response=response, die_puk=die_puk, cursor=cursor)

                self._verify_rtf(response=response, cursor=cursor)

                had_diffs = self._verify_had(response=response, cursor=cursor)

                if attestation_record:
                    cursor.execute(
                        "UPDATE attestation_records "
                        "SET uuid = ?, completed = ?, status = ?, version = ? "
                        "WHERE challenge = ?",
                        (
                            response.uuid.hex(),
                            timestamp,
                            "HAD_DIFF" if had_diffs else "OK",
                            response.version_int,
                            response.challenge.hex(),
                        ),
                    )
                return APIResponse(
                    api=api,
                    status="HAD_DIFF" if had_diffs else "OK",
                    message="DICE response verified successfully.",
                    expected_had=had_diffs[0] if had_diffs else None,
                    actual_had=had_diffs[1] if had_diffs else None,
                )
            except SPSDKDICEVerificationError as e:
                if attestation_record:
                    cursor.execute(
                        "UPDATE attestation_records "
                        "SET uuid = ?, completed = ?, status = ?, version = ? "
                        "WHERE challenge = ?",
                        (
                            response.uuid.hex(),
                            timestamp,
                            e.status,
                            response.version_int,
                            response.challenge.hex(),
                        ),
                    )
                return APIResponse(
                    api=api,
                    status=e.status,
                    message=e.message,
                )
