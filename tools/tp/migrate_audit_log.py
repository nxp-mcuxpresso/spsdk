#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""Helper script for migrating the Audit Log."""

import argparse
import shutil
import sys
from typing import Optional, Sequence

from spsdk.tp.data_container import audit_log
from spsdk.tp.exceptions import SPSDKTpError


def find_audit_log_version(file_path: str) -> int:
    """Get audit log version.

    :param file_path:  Filename of audit log
    :return: Version number
    """
    try:
        with audit_log.sqlite_cursor(file_path) as cursor:
            cursor.execute(audit_log.SELECT_PROPERTIES_COMMAND)
            row = cursor.fetchone()
            prop = audit_log.AuditLogProperties.from_tuple(row)
            return prop.version
    except SPSDKTpError:
        return 1


def v1_v2(file_path: str) -> None:
    """Method to migrate from version 1 to version 2 of audit log.

    :param file_path: Filename of original audit log
    """
    print("Migrating from v1 to v2")
    tp_device_id = input("Enter TP Device ID: ")
    shutil.copy(file_path, f"{file_path}.v1.db")
    with audit_log.sqlite_cursor(file_path) as cursor:
        cursor.executescript(audit_log.CREATE_TABLE_COMMAND)
        cursor.execute(audit_log.INSERT_PROPERTIES_COMMAND, (2, tp_device_id))


def completed(file_path: str) -> None:
    """Help print method when all is done."""
    print(
        f"Nothing to do with audit log '{file_path}'.\n"
        f"It's already at latest version: {audit_log.DB_VERSION}"
    )


MIGRATION_HANDLERS = {
    1: v1_v2,
    audit_log.DB_VERSION: completed,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Migrate the Audit Log."""
    parser = argparse.ArgumentParser(description="Helper script for migrating TP Audit log.")
    parser.add_argument("-p", "--audit-log-path", required=True, help="Path to audit log")
    args = parser.parse_args(argv)

    current_version = find_audit_log_version(args.audit_log_path)
    handler = MIGRATION_HANDLERS.get(current_version)
    if not handler:
        print(f"Don't know how to migrate audit log version {current_version}")
    else:
        handler(args.audit_log_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
