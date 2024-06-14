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
from typing import Optional

from pytablewriter import RstGridTableWriter, MarkdownTableWriter

from spsdk.apps.nxpimage import main as nxpimage_main
from spsdk.exceptions import SPSDKValueError
from spsdk.image.mbi.mbi import MAP_AUTHENTICATIONS, MAP_IMAGE_TARGETS, create_mbi_class
from spsdk.utils.database import DatabaseManager, get_db, get_families, Device
from spsdk.utils.misc import get_key_by_val
import requests

TARGET = 0
AUTHENTICATION = 1

DOC_PATH = os.path.abspath(".")
TABLE_DIR = os.path.join(DOC_PATH, "_prebuild")
MBI_TABLE_FILE = os.path.join(TABLE_DIR, "mbi_table.inc")
NXPIMAGE_FEATURES_TABLE_FILE = os.path.join(TABLE_DIR, "features_table.inc")
OTHER_FEATURES_TABLE_FILE = os.path.join(TABLE_DIR, "other_features_table.inc")
DEVICES_TABLE_FILE = os.path.join(TABLE_DIR, "devices_table.inc")
DEVICES_TABLE_FILE_README = os.path.join(TABLE_DIR, "devices_table_readme.inc")
LIST_OF_SUPPORTED_DEVICES = os.path.join(DOC_PATH, "devices_list.rst")


ROT_TYPE_MAPPING = {
    "srk_table_ahab": "SRK AHAB",
    "cert_block_21": "v2.1",
    "cert_block_1": "v1.0",
    "cert_block_x": "vX",
    "srk_table_hab": "SRK HAB",
}

IGNORED_FEATURES = ["comm_buffer", "sbx", "fuses", "signing"]  # features to be ignored in the table.

NXPIMAGE_FEATURES_MAPPING = {
    "mbi": "Master Boot Image (MBI)",
    "cert_block": "RoT",
    "bootable_image": "Bootable image",
    "fcb": "FlexSPI Configuration Block (FCB)",
    "xmcd": "External Memory Configuration Data (XMCD)",
    "sb21": "Secure Binary 2.1",
    "sb31": "Secure Binary 3.1",
}
OTHER_FEATURES_MAPPING = {
    "dat": "nxpdebugmbox",
    "shadow_regs": "shadowregs",
    "devhsm": "nxpdevhsm",
    "tp": "tphost",
    "ele": "nxpele",
    "memcfg": "nxpmemcfg",
    "wpc": "nxpwpc",
    "el2go_tp": "el2go",
}
ALL_FEATURES_MAPPING = {**NXPIMAGE_FEATURES_MAPPING, **OTHER_FEATURES_MAPPING}
SUPPORTED_CHAR = "\u2705"
UNSUPPORTED_CHAR = "\u274C"


def get_link(name: str, url: str, use_markdown: bool = False) -> str:
    """Get link to the device."""
    if use_markdown:
        return f"[{name}]({url})"
    return f"`{name} <{url}>`_"


def is_link_accessible(url: str) -> bool:
    """Check if the link is accessible."""
    works = False
    try:
        response = requests.head(url, timeout=5)
        works = response.status_code in [200, 301, 302]
    except requests.exceptions.RequestException:
        pass

    if not works:
        print("\033[91mLink is not accessible", url, "\033[0m")
    return works


def create_internal_reference(reference_name: str, use_markdown: bool = False) -> str:
    """Create internal reference to the documentation."""
    if use_markdown:
        return f"[{reference_name}]({reference_name})"
    else:
        return f":ref:`{reference_name}`"


def create_internal_reference_link_text(
    reference_name: str, link_text: str, use_markdown: bool = False
) -> str:
    """Create internal reference to the documentation."""
    if use_markdown:
        return f"[{link_text}](#{reference_name})"
    else:
        return f":ref:`{link_text} <{reference_name}>`"


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


def generate_table(
    header: List[str],
    values: List[List[str]],
    title: str,
    use_markdown: bool = False,
) -> str:
    """Generate RST/MD table to file using pytablewriter

    :param header: table header
    :param values: values to be writter
    :param title: table title
    :param use_markdown: use markdown format
    """
    if use_markdown:
        writer = MarkdownTableWriter(
            table_name=title,
            headers=header,
            value_matrix=values,
        )
    else:
        writer = RstGridTableWriter(
            table_name=title,
            headers=header,
            value_matrix=values,
        )
    return writer.dumps()


def write_table(
    header: List[str],
    values: List[List[str]],
    title: str,
    file_name: str,
    use_markdown: bool = False,
):
    """Write RST table to file using pytablewriter

    :param header: table header
    :param values: values to be writter
    :param title: table title
    :param file_name: file name of the file with table
    :param use_markdown: use markdown format
    """
    table = generate_table(header, values, title, use_markdown)
    if not os.path.exists(os.path.dirname(file_name)):
        os.makedirs(os.path.dirname(file_name))

    with open(file_name, "w", encoding="utf-8") as f:
        f.write(table)

    print(f"Table {file_name} has been written")


def generate_mbi_table():
    """Create table with matrix of supported devices
    vs image target and authentication types for the
    purpose of documentation.
    """
    targets = get_targets()
    authentications = get_authentications()
    families = sorted(
        [
            family
            for family in get_families(DatabaseManager.MBI)
            if DatabaseManager().db.devices.get(family).info.use_in_doc
        ]
    )
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


def generate_feature_table(
    device: Device,
    features: List[str],
    heading: str,
    features_mapping: Dict[str, str],
    ignored_features: Optional[List[str]] = None,
    use_markdown: bool = False,
) -> str:
    """Generate table for features.

    :param device: device object to be used.
    :param features: list of features.
    :param heading: table heading.
    :param features_mapping: features mapping for translation
    :param ignored_features: list for features
    :param use_markdown: use MD
    """
    if not ignored_features:
        ignored_features = []

    feature_list = [
        feature
        for feature in features
        if feature not in IGNORED_FEATURES and feature not in ignored_features
    ]

    value_matrix = []

    for feature in feature_list:
        feature_reference = create_internal_reference(
            reference_name=features_mapping.get(feature, feature),
            use_markdown=use_markdown,
        )
        if feature in device.features_list:
            if feature == DatabaseManager.CERT_BLOCK:
                db = get_db(device.name)
                rot_type = db.get_str(DatabaseManager.CERT_BLOCK, "rot_type")
                value_matrix.append(
                    [
                        feature_reference,
                        ROT_TYPE_MAPPING.get(rot_type, rot_type),
                    ]
                )
            else:
                value_matrix.append([feature_reference, SUPPORTED_CHAR])

    header = ["Feature", "Support"]

    return generate_table(header, value_matrix, heading, use_markdown=use_markdown)


def generate_features_table(
    features: List[str],
    heading: str,
    features_mapping: Dict[str, str],
    table_file: str,
    ignored_features: Optional[List[str]] = None,
):
    """Generate table for features.

    :param features: list of features.
    :param heading: table heading.
    :param features_mapping: features mapping for translation
    :param table_file: table file string
    :param ignored_features: ignore list for features
    """
    print("Processing Features table")
    if not ignored_features:
        ignored_features = []
    feature_list = [
        feature
        for feature in features
        if feature not in IGNORED_FEATURES and feature not in ignored_features
    ]
    value_matrix = []
    families = sorted(
        [
            family
            for family in DatabaseManager().db.devices
            if DatabaseManager().db.devices.get(family.name).info.use_in_doc
        ],
        key=lambda x: x.name,
    )

    for device in families:
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

    feature_list = [
        create_internal_reference(features_mapping.get(feature, feature))
        for feature in feature_list
    ]
    feature_list.insert(0, "Device")

    write_table(feature_list, value_matrix, heading, table_file)


def generate_devices_table(
    heading: str,
    table_file: str,
    use_markdown: bool = False,
    add_internal_links: bool = True,
):
    """Generate table containing all supported devices and check the links.

    :param heading: table heading.
    :param table_file: table file string
    :param use_markdown: use markdown format
    :param add_internal_links: add internal links
    """
    print("Processing Devices table and checking links")
    header = ["SPSDK name", "Category", "Weblink", "Latest Revision"]
    value_matrix = []
    devices = sorted(
        [
            family
            for family in DatabaseManager().db.devices
            if DatabaseManager().db.devices.get(family.name).info.use_in_doc
        ],
        key=lambda x: x.name,
    )

    for device in devices:
        submatrix = []
        if add_internal_links:
            submatrix.append(device.name)
        else:
            submatrix.append(create_internal_reference(device.name, use_markdown))
        submatrix.append(device.info.purpose)
        if is_link_accessible(device.info.web):
            submatrix.append(get_link("Link to nxp.com", device.info.web, use_markdown))
        else:
            submatrix.append(device.name)
        submatrix.append(device.latest_rev)

        value_matrix.append(submatrix)

    write_table(header, value_matrix, heading, table_file, use_markdown=use_markdown)


def generate_devices_list(
    output_file: str,
):
    """Generate markdown containing all supported devices.

    :param output_file: output file string
    """

    print("Processing list of devices")

    devices = sorted(
        [
            family
            for family in DatabaseManager().db.devices
            if DatabaseManager().db.devices.get(family.name).info.use_in_doc
        ],
        key=lambda x: x.info.purpose,
    )

    lines = [
        "============================\n",
        "List of supported devices\n",
        "============================\n",
    ]

    for category, devices in itertools.groupby(devices, key=lambda x: x.info.purpose):
        lines.extend(
            [
                "========================================================\n",
                f"{category}\n",
                "========================================================\n",
            ]
        )
        devices = sorted(devices, key=lambda x: x.name)
        for device in devices:
            lines.append(f"\n{device.name}\n")
            lines.append("--------------------------\n")
            # lines.append(f"\nDevice category: {device.info.purpose}\n")
            lines.append(f"\nLatest revision: {device.latest_rev}\n")
            lines.append(
                f"\nAll supported chip revisions: {', '.join(device.revisions.revision_names())}\n"
            )
            lines.append(f"\nWeblink: {get_link(device.name, device.info.web, False)}\n\n")
            lines.append(
                generate_feature_table(
                    device,
                    DatabaseManager().db.get_feature_list(),
                    "",
                    ALL_FEATURES_MAPPING,
                    use_markdown=False,
                )
            )
            lines.append("\n")
            # lines.append(f"### Getting started with {device.name} \n")

    with open(output_file, "w", encoding="utf-8") as f:
        f.writelines(lines)


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

    generate_devices_table(heading="", table_file=DEVICES_TABLE_FILE, use_markdown=True)
    generate_devices_table(
        heading="",
        table_file=DEVICES_TABLE_FILE_README,
        use_markdown=True,
        add_internal_links=False,
    )

    generate_devices_list(LIST_OF_SUPPORTED_DEVICES)


def setup(app):
    main()


if __name__ == "__main__":
    main()
