#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
# Script for generation of table
import itertools
import os
from typing import Dict, List

from pytablewriter import RstGridTableWriter

from spsdk.apps.nxpimage import main as nxpimage_main
from spsdk.exceptions import SPSDKValueError
from spsdk.image.mbi.mbi import MAP_AUTHENTICATIONS, MAP_IMAGE_TARGETS, create_mbi_class
from spsdk.utils.database import DatabaseManager, get_db
from spsdk.utils.misc import get_key_by_val

TARGET = 0
AUTHENTICATION = 1

DOC_PATH = os.path.abspath(".")
TABLE_DIR = os.path.join(DOC_PATH, "_prebuild")
MBI_TABLE_FILE = os.path.join(TABLE_DIR, "mbi_table.inc")
NXPIMAGE_FEATURES_TABLE_FILE = os.path.join(TABLE_DIR, "features_table.inc")
OTHER_FEATURES_TABLE_FILE = os.path.join(TABLE_DIR, "other_features_table.inc")


ROT_TYPE_MAPPING = {
    "srk_table_ahab": "SRK",
    "cert_block_21": "v2.1",
    "cert_block_1": "v1.0",
    "cert_block_x": "vX",
    "srk_table_hab": "SRK",
}

IGNORED_FEATURES = ["comm_buffer", "sbx", "signing"]

NXPIMAGE_FEATURES_MAPPING = {"cert_block": "RoT", "bootable_image": "Bootable image"}
OTHER_FEATURES_MAPPING = {
    "dat": "nxpdebugmbox",
    "shadow_regs": "shadowregs",
    "devhsm": "nxpdevhsm",
    "tp": "tphost",
    "ele": "nxpele",
    "memcfg": "nxpmemcfg",
    "wpc": "nxpwpc",
}

SUPPORTED_CHAR = "\u2705"
UNSUPPORTED_CHAR = "\u274C"


def is_nxpimage_subcommand(subcommand: str) -> bool:
    """Return true if subcommand is nxpimage subcommand.

    :param subcommand: subcommand str
    :return: True if nxpimage subcommand
    """
    EXTRAS = ["fcb", "xmcd"]
    if subcommand in EXTRAS:
        return True
    subcommand = subcommand.replace("_", "-")
    for command in nxpimage_main.commands.values():
        if subcommand == command.name:
            return True
    return False


def get_targets() -> List[str]:
    """Get list of all targets from device database

    :return: list with all targets
    """
    targets = []
    for _, val in MAP_IMAGE_TARGETS["targets"].items():
        targets.append(val[0])
    return targets


def get_authentications() -> List[str]:
    """Get all authentication types from the device database

    :return: list of all authentication types
    """
    authentications = []
    for _, val in MAP_AUTHENTICATIONS.items():
        authentications.append(val[0])
    return authentications


def get_table_header(combinations: List[tuple]) -> List[str]:
    """Create header for the table

    :param combinations: combinations of targets x authentication type
    :return: list of header to be used with pytablewriter
    """
    header = [i[TARGET] for i in combinations]
    header.insert(0, "Targets")

    return header


def write_table(header: List[str], values: List[List[str]], title: str, file_name: str):
    """Write RST table to file using pytablewriter

    :param header: table header
    :param values: values to be writter
    :param title: table title
    :param file_name: file name of the file with table
    """
    writer = RstGridTableWriter(
        table_name=title,
        headers=header,
        value_matrix=values,
    )
    if not os.path.exists(os.path.dirname(file_name)):
        os.makedirs(os.path.dirname(file_name))

    with open(file_name, "w", encoding="utf-8") as f:
        writer.stream = f
        writer.write_table()

    print(f"Table {file_name} has been written")


def generate_mbi_table():
    """Create table with matrix of supported devices
    vs image target and authentication types for the
    purpose of documentation.
    """
    targets = get_targets()
    authentications = get_authentications()
    families = sorted(DatabaseManager().db.get_devices_with_feature(DatabaseManager().MBI))
    print("Processing MBI table")
    combinations = list(itertools.product(targets, authentications))
    value_matrix = []
    for family in families:
        submatrix = []
        submatrix.append(family)
        for c in combinations:
            try:
                target = get_key_by_val(c[TARGET], MAP_IMAGE_TARGETS["targets"])
                authentication = get_key_by_val(c[AUTHENTICATION], MAP_AUTHENTICATIONS)
                cls_name = (
                    DatabaseManager()
                    .db.get_device_features(family)
                    .get_value(DatabaseManager().MBI, ["images", target, authentication])
                )
                cls = create_mbi_class(cls_name, family)
                reference = f":ref:`{SUPPORTED_CHAR}<{cls.hash()}>`"
                submatrix.append(reference)
            except (KeyError, SPSDKValueError):
                submatrix.append(UNSUPPORTED_CHAR)
                continue
        value_matrix.append(submatrix)

    auth_list = [f"*{i[AUTHENTICATION]}*" for i in combinations]
    auth_list.insert(0, "*Authentication*")
    value_matrix.insert(0, auth_list)
    header = get_table_header(combinations)
    write_table(header, value_matrix, "Supported devices", MBI_TABLE_FILE)


def generate_features_table(
    features: List[str],
    heading: str,
    features_mapping: Dict[str, str],
    table_file: str,
    ignored_features: List[str] = [],
):
    """Generate table for features.

    :param features: list of features.
    :param heading: table heading.
    :param features_mapping: features mapping for translation
    :param table_file: table file string
    :param ignored_features: ignore list for features, defaults to []
    """
    print("Processing Features table")
    feature_list = [
        feature
        for feature in features
        if feature not in IGNORED_FEATURES and feature not in ignored_features
    ]
    value_matrix = []
    for device in DatabaseManager().db.devices:
        submatrix = []
        submatrix.append(device.name)
        for feature in feature_list:
            if feature in device.features_list:
                if feature == DatabaseManager.CERT_BLOCK:
                    db = get_db(device.name)
                    rot_type = db.get_str(DatabaseManager.CERT_BLOCK, "rot_type")
                    submatrix.append(ROT_TYPE_MAPPING.get(rot_type, rot_type))
                else:
                    submatrix.append(SUPPORTED_CHAR)
            else:
                submatrix.append(" ")
        value_matrix.append(submatrix)

    feature_list = [f":ref:`{features_mapping.get(feature, feature)}`" for feature in feature_list]
    feature_list.insert(0, "Device")

    write_table(feature_list, value_matrix, heading, table_file)


def main():
    generate_mbi_table()

    nxpimage_features = [
        feature
        for feature in DatabaseManager().db.get_feature_list()
        if is_nxpimage_subcommand(feature)
    ]
    generate_features_table(
        features=nxpimage_features,
        heading="NXPIMAGE Supported devices",
        features_mapping=NXPIMAGE_FEATURES_MAPPING,
        table_file=NXPIMAGE_FEATURES_TABLE_FILE,
    )
    generate_features_table(
        features=DatabaseManager().db.get_feature_list(),
        heading="Other apps supported devices",
        features_mapping=OTHER_FEATURES_MAPPING,
        table_file=OTHER_FEATURES_TABLE_FILE,
        ignored_features=nxpimage_features,
    )


def setup(app):
    main()


if __name__ == "__main__":
    main()
