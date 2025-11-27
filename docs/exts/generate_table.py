#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK documentation table generation utilities.

This module provides functionality for automatically generating various tables
and documentation content for SPSDK documentation. It creates tables for
device support, features, MBI configurations, and other documentation assets.
"""

# Script for generation of table
import itertools
import os
from functools import lru_cache
from typing import Any, Optional, Union

import nbformat
import requests
from pytablewriter import MarkdownTableWriter, RstGridTableWriter

from spsdk.apps.nxpele import main as nxpele_main
from spsdk.apps.nxpimage import main as nxpimage_main
from spsdk.exceptions import SPSDKValueError
from spsdk.image.mbi.mbi import MAP_AUTHENTICATIONS, MAP_IMAGE_TARGETS, MasterBootImage
from spsdk.mboot.error_codes import StatusCode
from spsdk.utils.database import DatabaseManager, Device
from spsdk.utils.family import FamilyRevision, get_db, get_families
from spsdk.utils.misc import get_key_by_val

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
MBOOT_ERROR_CODES = os.path.join(TABLE_DIR, "mboot_error_codes.inc")
NXPELE_COMMANDS_TABLE = os.path.join(TABLE_DIR, "nxpele_commands_table.inc")

ROT_TYPE_MAPPING = {
    "srk_table_ahab": "SRK AHAB",
    "cert_block_21": "v2.1",
    "cert_block_1": "v1.0",
    "cert_block_x": "vX",
    "srk_table_hab": "SRK HAB",
}

IGNORED_FEATURES = [
    "comm_buffer",
    "sbx",
    "fuses",
    "signing",
    "fastboot",
]  # features to be ignored in the table.

NXPIMAGE_FEATURES_MAPPING = {
    "mbi": "Master Boot Image (MBI)",
    "cert_block": "RoT",
    "bootable_image": "Bootable image",
    "fcb": "FlexSPI Configuration Block (FCB)",
    "xmcd": "External Memory Configuration Data (XMCD)",
    "sb21": "Secure Binary 2.1",
    "sb31": "Secure Binary 3.1",
    "sb40": "Secure Binary 4.0",
    "sbc": "Secure Binary C",
    "tlv_blob": "Type-Length-Value blobs",
}
OTHER_FEATURES_MAPPING = {
    "dat": "nxpdebugmbox",
    "shadow_regs": "shadowregs",
    "devhsm": "nxpdevhsm",
    "ele": "nxpele",
    "memcfg": "nxpmemcfg",
    "wpc": "nxpwpc",
    "el2go_tp": "el2go-host",
    "dice": "nxpdice",
    "fuse_tool": "nxpfuses",
    "she_scec": "nxpshe",
}
ALL_FEATURES_MAPPING = {**NXPIMAGE_FEATURES_MAPPING, **OTHER_FEATURES_MAPPING}
SUPPORTED_CHAR = "\u2705"
UNSUPPORTED_CHAR = "\u274c"


def get_link(name: str, url: str, use_markdown: bool = False) -> str:
    """Get link formatted for documentation.

    Creates a formatted link string that can be used in either Markdown or
    reStructuredText format depending on the specified format preference.

    :param name: Display text for the link.
    :param url: Target URL for the link.
    :param use_markdown: Whether to format as Markdown link, defaults to reStructuredText format.
    :return: Formatted link string in the requested format.
    """
    if use_markdown:
        return f"[{name}]({url})"
    return f"`{name} <{url}>`_"


@lru_cache
def is_link_accessible(url: str) -> bool:
    """Check if a URL is accessible by sending a HEAD request.

    This method verifies URL accessibility by sending a HEAD request and checking
    for successful HTTP status codes (200, 301, 302). If the link is not accessible,
    an error message is printed to the console.

    :param url: The URL to check for accessibility.
    :return: True if the URL is accessible (status codes 200, 301, or 302), False otherwise.
    """
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
    """Create internal reference to the documentation.

    Generates either a Markdown-style link or Sphinx reference syntax
    depending on the output format requirement.

    :param reference_name: Name of the reference target to link to.
    :param use_markdown: If True, creates Markdown link format; if False, creates Sphinx reference format.
    :return: Formatted reference string in either Markdown or Sphinx syntax.
    """
    if use_markdown:
        return f"[{reference_name}]({reference_name})"

    return f":ref:`{reference_name}`"


def create_internal_reference_link_text(
    reference_name: str, link_text: str, use_markdown: bool = False
) -> str:
    """Create internal reference link text for documentation.

    Generates either Markdown or reStructuredText format internal reference links
    depending on the specified format preference.

    :param reference_name: The internal reference identifier/anchor name.
    :param link_text: The display text for the link.
    :param use_markdown: Whether to use Markdown format instead of reStructuredText.
    :return: Formatted internal reference link string.
    """
    if use_markdown:
        return f"[{link_text}](#{reference_name})"

    return f":ref:`{link_text} <{reference_name}>`"


def is_nxpimage_subcommand(subcommand: str) -> bool:
    """Check if a subcommand belongs to nxpimage tool.

    This method verifies whether the given subcommand is a valid nxpimage command
    by checking against extra commands and registered nxpimage commands with
    underscore-to-hyphen normalization.

    :param subcommand: The subcommand string to validate.
    :return: True if the subcommand is a valid nxpimage command, False otherwise.
    """
    EXTRAS = ["fcb", "xmcd"]
    if subcommand in EXTRAS:
        return True
    subcommand = subcommand.replace("_", "-")
    for command in nxpimage_main.commands.values():
        if subcommand == command.name:
            return True
    return False


def get_targets() -> list[str]:
    """Get list of all targets from device database.

    :return: List of all available target names from the device database.
    """
    targets = []
    for _, val in MAP_IMAGE_TARGETS["targets"].items():
        targets.append(val[0])
    return targets


def get_authentications() -> list[str]:
    """Get all authentication types from the device database.

    :return: List of all authentication types available in the system.
    """
    authentications = []
    for _, val in MAP_AUTHENTICATIONS.items():
        authentications.append(val[0])
    return authentications


def get_table_header(combinations: list[tuple]) -> list[str]:
    """Create header for the table.

    Generates a table header by extracting target names from combinations
    and prepending "Targets" as the first column header.

    :param combinations: List of tuples containing combinations of targets and authentication types.
    :return: List of header strings to be used with pytablewriter, with "Targets" as first element.
    """
    header = [i[TARGET] for i in combinations]
    header.insert(0, "Targets")

    return header


def generate_table(
    header: list[str],
    values: list[list[str]],
    title: str,
    use_markdown: bool = False,
) -> str:
    """Generate RST/MD table using pytablewriter.

    Creates a formatted table in either reStructuredText or Markdown format
    based on the provided header, data values, and formatting preference.

    :param header: List of column headers for the table.
    :param values: Matrix of string values representing table rows and columns.
    :param title: Title to be displayed with the table.
    :param use_markdown: Whether to generate Markdown format instead of RST format.
    :return: Formatted table as a string in the specified format.
    """
    writer: Union[MarkdownTableWriter, RstGridTableWriter]
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
    header: list[str],
    values: list[list[str]],
    title: str,
    file_name: str,
    use_markdown: bool = False,
) -> None:
    """Write table to file using pytablewriter.

    The method generates a table from provided header and values, then writes it to the specified file.
    Creates the target directory if it doesn't exist.

    :param header: List of column headers for the table.
    :param values: List of rows, where each row is a list of string values.
    :param title: Title to be displayed above the table.
    :param file_name: Path to the output file where the table will be written.
    :param use_markdown: Whether to use Markdown format instead of RST format.
    """
    table = generate_table(header, values, title, use_markdown)
    if not os.path.exists(os.path.dirname(file_name)):
        os.makedirs(os.path.dirname(file_name))

    with open(file_name, "w", encoding="utf-8") as f:
        f.write(table)

    print(f"Table {file_name} has been written")


def generate_mbi_table() -> None:
    """Generate MBI table with matrix of supported devices vs image target and authentication types.

    Creates a comprehensive table showing which combinations of image targets and authentication
    types are supported for each device family in the MBI (Master Boot Image) context. The table
    is written to a file for documentation purposes.

    :raises KeyError: When device features or configuration keys are not found in database.
    :raises SPSDKValueError: When invalid values are encountered during processing.
    """
    targets = get_targets()
    authentications = get_authentications()
    families = sorted(
        [
            family
            for family in get_families(DatabaseManager.MBI)
            if DatabaseManager().db.devices.get(family.name).info.use_in_doc
        ]
    )
    print("Processing MBI table")
    combinations = list(itertools.product(targets, authentications))
    value_matrix = []
    for family in families:
        submatrix = []
        submatrix.append(family.name)
        for c in combinations:
            try:
                target = get_key_by_val(c[TARGET], MAP_IMAGE_TARGETS["targets"])
                authentication = get_key_by_val(c[AUTHENTICATION], MAP_AUTHENTICATIONS)
                cls_name = (
                    DatabaseManager()
                    .db.get_device_features(family.name, family.revision)
                    .get_value(DatabaseManager().MBI, ["images", target, authentication])
                )
                cls = MasterBootImage.create_mbi_class(cls_name, family)
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
    features: list[str],
    heading: str,
    features_mapping: dict[str, str],
    use_markdown: bool = False,
) -> str:
    """Generate table for features supported by a device.

    Creates a formatted table showing which features are supported by the specified device,
    with proper feature name mapping and filtering of ignored features.

    :param device: Device object containing feature information.
    :param features: List of feature names to include in the table.
    :param heading: Table heading text.
    :param features_mapping: Dictionary mapping feature names to display names for translation.
    :param use_markdown: Whether to generate table in Markdown format instead of reStructuredText.
    :return: Formatted table string showing feature support status.
    """
    feature_list = [feature for feature in features if feature not in IGNORED_FEATURES]

    value_matrix = []
    db = get_db(FamilyRevision(device.name))

    for feature in feature_list:
        feature_reference = create_internal_reference(
            reference_name=features_mapping.get(feature, feature),
            use_markdown=use_markdown,
        )
        if feature in device.get_features():
            if feature == DatabaseManager.CERT_BLOCK:
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
    features: list[str],
    heading: str,
    features_mapping: dict[str, str],
    table_file: str,
    ignored_features: Optional[list[str]] = None,
) -> None:
    """Generate table for features with device compatibility matrix.

    Creates a table showing which features are supported by different device families.
    The table includes all devices marked for documentation use and filters out ignored features.
    Special handling is provided for certificate block features to show ROT type information.

    :param features: List of feature names to include in the table.
    :param heading: Title text for the generated table.
    :param features_mapping: Dictionary mapping feature names to display names for translation.
    :param table_file: Output file path where the table will be written.
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
            for family in DatabaseManager().quick_info.devices.devices
            if DatabaseManager().quick_info.devices.devices.get(family) is not None
            and DatabaseManager().quick_info.devices.devices.get(family).info.use_in_doc  # type: ignore
        ]
    )

    for device in families:
        submatrix = []
        submatrix.append(device)
        for feature in feature_list:
            device_info = DatabaseManager().quick_info.devices.devices.get(device)
            if device_info is not None and feature in device_info.get_features():
                if feature == DatabaseManager.CERT_BLOCK:
                    db = get_db(FamilyRevision(device))
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
) -> None:
    """Generate table containing all supported devices and check the links.

    This method creates a formatted table (RST or Markdown) with information about
    all supported devices from the SPSDK database, including device names, categories,
    web links, and latest revisions. It also validates web link accessibility.

    :param heading: Table heading text to be displayed above the generated table.
    :param table_file: Output file path where the generated table will be written.
    :param use_markdown: Whether to generate table in Markdown format instead of RST format.
    :param add_internal_links: Whether to add internal documentation links for device names.
    """
    print("Processing Devices table and checking links")
    header = ["SPSDK name", "Category", "Weblink", "Latest Revision"]
    value_matrix = []
    devices = sorted(
        [
            family
            for family in DatabaseManager().quick_info.devices.devices
            if DatabaseManager().quick_info.devices.devices.get(family) is not None
            and DatabaseManager().quick_info.devices.devices.get(family).info.use_in_doc  # type: ignore
        ]
    )

    for device in devices:
        submatrix = []
        if add_internal_links:
            submatrix.append(device)
        else:
            submatrix.append(create_internal_reference(device, use_markdown))
        info = DatabaseManager().quick_info.devices.devices.get(device).info  # type: ignore
        submatrix.append(info.purpose)
        if is_link_accessible(info.web):
            submatrix.append(get_link("Link to nxp.com", info.web, use_markdown))
        else:
            submatrix.append(device)

        submatrix.append(DatabaseManager().db.devices.get(device).latest_rev)

        value_matrix.append(submatrix)

    write_table(header, value_matrix, heading, table_file, use_markdown=use_markdown)


def get_notebook_header(notebook_path: str) -> str:
    """Extract the header from a Jupyter notebook.

    The method reads the notebook file and searches for the first markdown cell
    to extract its header. If no markdown header is found, returns the notebook filename.

    :param notebook_path: Path to the Jupyter notebook file.
    :raises FileNotFoundError: When the notebook file does not exist.
    :raises nbformat.ValidationError: When the notebook format is invalid.
    :return: The header text from the first markdown cell or notebook filename as fallback.
    """
    with open(notebook_path, "r", encoding="utf-8") as f:
        notebook = nbformat.read(f, as_version=4)
        for cell in notebook.cells:
            if cell.cell_type == "markdown":
                lines = cell.source.splitlines()
                if lines:
                    return lines[0].strip("# ").strip()
    return os.path.basename(notebook_path)


def get_jupyters_for_device(
    device: str, alternative_device_name: Optional[str] = None
) -> list[str]:
    """Get list of Jupyter notebooks for the specified device.

    Searches through the examples directory to find all Jupyter notebook files
    that contain the device name or alternative device name in their path.

    :param device: Device name to search for in notebook paths
    :param alternative_device_name: Optional alternative device name to search for
    :return: List of relative paths to Jupyter notebooks matching the device criteria
    """
    jupyters = []
    for root, _, files in os.walk(os.path.join(DOC_PATH, "examples")):
        for file in files:
            relative_path = os.path.relpath(root, DOC_PATH).replace(os.sep, "/")
            if file.endswith(".ipynb") and (
                device in relative_path.lower() or alternative_device_name in relative_path.lower()
                if alternative_device_name
                else False
            ):
                jupyters.append(os.path.join(relative_path, file).replace(os.sep, "/"))
    return jupyters


def get_jupyters_for_feature(feature: str) -> list[str]:
    """Get list of Jupyter notebooks for the specified feature.

    Searches through the examples directory to find all Jupyter notebook files
    that are located in subdirectories matching the given feature name.

    :param feature: Name of the feature to search notebooks for.
    :return: List of relative paths to Jupyter notebooks associated with the feature.
    """
    jupyters = []
    for root, _, files in os.walk(os.path.join(DOC_PATH, "examples")):
        for file in files:
            relative_path = os.path.relpath(root, DOC_PATH)
            if file.endswith(".ipynb") and feature in relative_path.split(os.sep):
                jupyters.append(os.path.join(relative_path, file))
    return jupyters


def get_filtered_features(device: Device) -> list[str]:
    """Get filtered list of supported features for the specified device.

    The method filters device features and includes AHAB only if it supports
    ahab_image sub-feature. Results are returned in sorted order.

    :param device: Device object containing revision and feature information
    :return: Sorted list of supported feature names for the device
    """
    result = []
    features: dict = device.revisions.get().features
    for feature in features:
        if feature == DatabaseManager.AHAB:
            sub_features = features[feature]["sub_features"]
            if "ahab_image" not in sub_features:
                continue
        result.append(feature)
    return sorted(result)


def generate_devices_list(output_file: str) -> None:
    """Generate markdown file containing all supported devices organized by category.

    The method retrieves all devices from the DatabaseManager that are marked for documentation use,
    sorts them by purpose/category, and generates a comprehensive markdown file with device details,
    features, and related examples.

    :param output_file: Path to the output markdown file where the device list will be written
    :raises IOError: If the output file cannot be written to
    :raises SPSDKError: If database access fails or device information is corrupted
    """
    print("Processing list of devices")

    devices = sorted(
        [
            family
            for family in DatabaseManager().quick_info.devices.devices
            if DatabaseManager().quick_info.devices.devices.get(family).info.use_in_doc  # type: ignore
        ],
        key=lambda x: DatabaseManager().quick_info.devices.devices.get(x).info.purpose,  # type: ignore
    )

    lines = [
        "============================\n",
        "List of supported devices\n",
        "============================\n",
    ]

    for category, devices in itertools.groupby(  # type: ignore
        devices, key=lambda x: DatabaseManager().quick_info.devices.devices.get(x).info.purpose  # type: ignore
    ):
        lines.append("\n")
        lines.extend(
            [
                "========================================================\n",
                f"{category}\n",
                "========================================================\n",
            ]
        )
        devices = sorted(devices)
        for device in devices:

            device_full = DatabaseManager().db.devices.get(device)
            features = get_filtered_features(device_full)

            lines.append(f"\n{device}\n")
            lines.append("--------------------------\n")
            # lines.append(f"\nDevice category: {device.info.purpose}\n")
            lines.append(f"\nLatest revision: {device_full.latest_rev}\n")
            lines.append(
                f"\nAll supported chip revisions: {', '.join(device_full.revisions.revision_names())}\n"
            )
            lines.append(f"\nWeblink: {get_link(device, device_full.info.web, False)}\n\n")
            lines.append(
                generate_feature_table(
                    device_full,
                    features,
                    "",
                    ALL_FEATURES_MAPPING,
                    use_markdown=False,
                )
            )

            # Jupyters for device
            jupyters = get_jupyters_for_device(device, device_full.info.spsdk_predecessor_name)

            if jupyters:
                lines.append("\n")
                lines.append(f"Examples for {device}\n")
                lines.append("\n")
                for jupyter in jupyters:
                    header = get_notebook_header(jupyter)
                    lines.append(f"* `{header} <{jupyter}>`__\n")
                lines.append("\n")

            # Jupyters for alias
            jupyters = []
            if device_full.device_alias:
                jupyters = get_jupyters_for_device(
                    device_full.device_alias.name,
                    device_full.device_alias.info.spsdk_predecessor_name,
                )

            if jupyters:
                lines.append("\n")
                if device_full.device_alias:
                    lines.append(f"Similar examples for {device_full.device_alias.name}\n")
                lines.append("\n")
                for jupyter in jupyters:
                    header = get_notebook_header(jupyter)
                    lines.append(f"* `{header} <{jupyter}>`__\n")
                lines.append("\n")

            # Jupyters for features
            for feature in features:
                jupyters = get_jupyters_for_feature(feature)

                if jupyters:
                    lines.append("\n")
                    lines.append(f"Similar examples for {feature}\n")
                    lines.append("\n")
                    for jupyter in jupyters:
                        header = get_notebook_header(jupyter)
                        lines.append(f"* `{header} <{jupyter}>`__\n")
                    lines.append("\n")

    with open(output_file, "w", encoding="utf-8") as f:
        f.writelines(lines)

    print(f"List of devices has been written to {output_file}")


def generate_nxpele_commands_table() -> None:
    """Generate table with nxpele commands.

    This method extracts all available commands from the nxpele main module
    and creates a documentation table containing command names and their
    descriptions. The table is written to a file for documentation purposes.

    :raises SPSDKError: If table generation or file writing fails.
    """
    commands = nxpele_main.commands.keys()
    value_matrix = [
        [command, nxpele_main.commands[command].__doc__.split("\n")[0]]  # type:ignore
        for command in commands
    ]
    write_table(
        ["Command", "Description"],
        value_matrix,
        "NXP EdgeLock Enclave - available commands",
        file_name=NXPELE_COMMANDS_TABLE,
        use_markdown=False,
    )


def generate_mboot_error_codes() -> None:
    """Generate table with mboot error codes.

    This function processes all StatusCode enumeration values and creates a formatted
    table containing error codes, names, and descriptions. The generated table is
    written to a file for documentation purposes.

    :raises SPSDKError: When table generation or file writing fails.
    """
    print("Processing Mboot error codes")
    header = ["Error code", "Name", "Description"]
    value_matrix = []
    for code in StatusCode:
        value_matrix.append([str(code.tag), code.name, str(code.description)])

    write_table(header, value_matrix, "Mboot error codes", MBOOT_ERROR_CODES, use_markdown=False)


def main() -> None:
    """Generate documentation tables for SPSDK project.

    This function generates various documentation tables including MBI table,
    devices table for different formats, supported devices list, NXP ELE
    commands table, and MBoot error codes table.
    """
    generate_mbi_table()

    # TODO: Optimize features table or delete it
    # nxpimage_features = [
    #     feature
    #     for feature in DatabaseManager().quick_info.features_data.get_all_features
    #     if is_nxpimage_subcommand(feature)
    # ]
    # generate_features_table(
    #     features=nxpimage_features,
    #     heading="NXPIMAGE Supported devices",
    #     features_mapping=NXPIMAGE_FEATURES_MAPPING,
    #     table_file=NXPIMAGE_FEATURES_TABLE_FILE,
    # )
    # generate_features_table(
    #     features=DatabaseManager().quick_info.features_data.get_all_features,
    #     heading="Other apps supported devices",
    #     features_mapping=OTHER_FEATURES_MAPPING,
    #     table_file=OTHER_FEATURES_TABLE_FILE,
    #     ignored_features=nxpimage_features,
    # )

    generate_devices_table(heading="", table_file=DEVICES_TABLE_FILE, use_markdown=True)
    generate_devices_table(
        heading="",
        table_file=DEVICES_TABLE_FILE_README,
        use_markdown=True,
        add_internal_links=True,
    )

    generate_devices_list(LIST_OF_SUPPORTED_DEVICES)
    generate_nxpele_commands_table()
    generate_mboot_error_codes()


def setup(app: Any) -> None:
    """Setup Sphinx extension for table generation.

    This function registers the table generation extension with the Sphinx application
    and executes the main table generation process.

    :param app: Sphinx application instance used for documentation building.
    """
    main()


if __name__ == "__main__":
    main()
