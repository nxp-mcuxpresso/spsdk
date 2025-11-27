#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
"""SPSDK documentation schema generation utilities.

This module provides functionality for automatically generating schema documentation
for various SPSDK components and file formats. It extracts JSON schemas from SPSDK
modules and converts them into formatted documentation tables and files.
The module supports schema generation for MBI, Secure Boot (SB21/SB31/SB40),
AHAB, HAB, OTFAD, IEE, BEE, FCB, XMCD, and bootable image configurations.
"""

# Script for the automated generation of schemas documentation for nxpimage
import copy
import json
import os
import tempfile
from typing import Any, Optional, Type

from json_schema_for_humans.generate import generate_from_schema
from json_schema_for_humans.generation_configuration import GenerationConfiguration
from pytablewriter import MarkdownTableWriter

from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.bee import Bee
from spsdk.image.bootable_image.bimg import BootableImage
from spsdk.image.hab.hab_image import HabImage
from spsdk.image.iee.iee import Iee
from spsdk.image.mbi.mbi import MasterBootImage
from spsdk.image.otfad.otfad import Otfad
from spsdk.sbfile.sb2.sb_21_helper import SB21Helper
from spsdk.sbfile.sb4.images import SecureBinary4
from spsdk.sbfile.sb31.images import SecureBinary31
from spsdk.utils.database import DatabaseManager, get_schema_file
from spsdk.utils.family import FamilyRevision, get_db, get_families
from spsdk.utils.schema_validator import CommentedConfig, SPSDKMerger

DOC_PATH = os.path.abspath(".")
DOC_DIR = os.path.join(DOC_PATH, "_prebuild")
HTML_SCHEMAS_PATH = os.path.join(DOC_PATH, "html_schemas")

MBI_SCHEMAS_FILE = os.path.join(DOC_DIR, "schemas.inc")
SB31_SCHEMAS_FILE = os.path.join(DOC_DIR, "schemas_sb31.inc")
SB40_SCHEMAS_FILE = os.path.join(DOC_DIR, "schemas_sb40.inc")
AHAB_SCHEMAS_FILE = os.path.join(DOC_DIR, "ahab_schemas.inc")
HAB_SCHEMAS_FILE = os.path.join(DOC_DIR, "hab_schemas.inc")
OTFAD_SCHEMAS_FILE = os.path.join(DOC_DIR, "otfad_schemas.inc")
IEE_SCHEMAS_FILE = os.path.join(DOC_DIR, "iee_schemas.inc")
BEE_SCHEMAS_FILE = os.path.join(DOC_DIR, "bee_schemas.inc")
# FCB_SCHEMAS_FILE = os.path.join(DOC_DIR, "fcb_schemas.inc")
# XMCD_SCHEMAS_FILE = os.path.join(DOC_DIR, "xmcd_schemas.inc")
BOOTABLE_SCHEMAS_FILE = os.path.join(DOC_DIR, "bootable_schemas.inc")
SB21_TABLE_FILE = os.path.join(DOC_DIR, "table_sb21.inc")
SB31_TABLE_FILE = os.path.join(DOC_DIR, "table_sb31.inc")
SB40_TABLE_FILE = os.path.join(DOC_DIR, "table_sb40.inc")
BOOTABLE_TABLE_FILE = os.path.join(DOC_DIR, "table_bootable.inc")

schema_files = [
    MBI_SCHEMAS_FILE,
    SB31_SCHEMAS_FILE,
    SB40_SCHEMAS_FILE,
    AHAB_SCHEMAS_FILE,
    HAB_SCHEMAS_FILE,
    OTFAD_SCHEMAS_FILE,
    IEE_SCHEMAS_FILE,
    BEE_SCHEMAS_FILE,
    # FCB_SCHEMAS_FILE,
    # XMCD_SCHEMAS_FILE,
    BOOTABLE_SCHEMAS_FILE,
    SB21_TABLE_FILE,
    SB31_TABLE_FILE,
    SB40_TABLE_FILE,
    BOOTABLE_TABLE_FILE,
]


def clean_files() -> None:
    """Clean existing schema files from the file system.

    Removes all schema files listed in the global schema_files collection if they exist
    on the file system. Prints a confirmation message after successful removal.

    :raises OSError: If file removal fails due to permission or system errors.
    """
    for file in schema_files:
        if os.path.exists(file):
            os.remove(file)
    print("Existing schemas files have been removed")


def get_docs_families(feature: str, sub_feature: Optional[str] = None) -> list[FamilyRevision]:
    """Get list of families for documentation purposes.

    Retrieves families that support the specified feature and are marked for use in documentation.
    Only families with use_in_doc flag set to True are included in the result.

    :param feature: Feature name to filter families by.
    :param sub_feature: Optional sub-feature name for additional filtering.
    :return: Sorted list of family revisions suitable for documentation.
    """
    families = get_families(feature, sub_feature=sub_feature, single_revision=True)
    families = [
        family
        for family in families
        if DatabaseManager().db.devices.get(family.name).info.use_in_doc
    ]
    return sorted(families, key=str)


def get_schema(schemas: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge partial schemas into one valid schema.

    The method uses deepmerge to combine multiple schema dictionaries into a single
    valid schema, preserving all schema definitions and validation rules.

    :param schemas: List of schema dictionaries from get_validation_schemas class method.
    :return: Dictionary containing the merged valid schema.
    """
    schemas_merger = SPSDKMerger()

    schema: dict[str, Any] = {}
    for sch in schemas:
        schemas_merger.merge(schema, copy.deepcopy(sch))

    return schema


def parse_schema(schema: dict) -> str:
    """Parse schema using json_schema_for_humans and return it as HTML.

    The method creates a temporary directory, writes the schema to a file,
    and uses json_schema_for_humans library to generate HTML documentation
    from the JSON schema.

    :param schema: Valid JSON schema dictionary from the get_schema function.
    :return: HTML string representation of the schema documentation.
    """
    config = GenerationConfiguration(with_footer=False, deprecated_from_description=True)
    with tempfile.TemporaryDirectory() as temp_dir:
        schema_file = os.path.join(temp_dir, schema["title"].replace(" ", "_"))
        with open(schema_file, "w", encoding="utf-8") as file:
            json.dump(schema, file)

        output = generate_from_schema(schema_file, config=config)

    return output


def append_schema(
    parsed: str,
    template: str,
    file: str,
    note: Optional[str] = None,
    title: str = "Title",
    subtitle: Optional[str] = None,
) -> None:
    """Append schema and template to the markdown document.

    Creates necessary directories and generates both markdown and HTML files
    for schema documentation with embedded iframe and YAML template.

    :param parsed: HTML string with parsed schema content
    :param template: YAML configuration template string to be included
    :param file: Path to the output markdown file
    :param note: Optional note to be added after the parsed schema
    :param title: Title of the schema section
    :param subtitle: Optional subtitle for the schema section
    """
    if not os.path.exists(DOC_DIR):
        os.makedirs(DOC_DIR)

    if not os.path.exists(HTML_SCHEMAS_PATH):
        os.makedirs(HTML_SCHEMAS_PATH)

    html_file = title.replace(" ", "_") + ".html"

    with open(file, "a+", encoding="utf-8") as f:
        f.write(f"## {title}\n")
        if note:
            f.write("\n")
            f.write(note)
            f.write("\n")

        if subtitle:
            f.write(f"### {subtitle}\n")
        f.write(
            f"""\n<details>
<summary>{title} JSON schema</summary>

<a href="../{html_file}" target="_blank">Open it in full page</a>

<iframe title="JSON schema" width="100%" height="1000" src="../{html_file}" frameborder="0" allowfullscreen></iframe>

</details>
"""
        )
        f.write("\n")
        f.write("\n")
        f.write(
            f"""<details>
<summary>{title} YAML configuration template</summary>

```yaml\n
{template}
\n```
\n

</details>
\n
"""
        )

    with open(os.path.join(HTML_SCHEMAS_PATH, html_file), "w", encoding="utf-8") as f:
        f.write(parsed)


def get_template(schemas: list, name: str) -> str:
    """Get template for schemas.

    Generates a YAML template from validation schemas with predefined template values
    for specific properties like family, execution target, and authentication type.

    :param schemas: List of validation schemas used for template generation.
    :param name: Display name that will be used as the template title.
    :return: YAML template string generated from the provided schemas.
    """

    def override_template_values(key: str, value: str) -> None:
        """Override template value for a specific property key across all schemas.

        Searches through all schemas for the specified property key and sets its template_value
        to the provided value. Only the first matching schema property is modified.

        :param key: The property key to search for in schema properties.
        :param value: The template value to assign to the matching property.
        """
        for schema in schemas:
            if "properties" in schema and key in schema["properties"]:
                schema["properties"][key]["template_value"] = value
                break

    hint = "CHOOSE_FROM_TABLE"

    override_template_values("family", hint)
    override_template_values("outputImageExecutionTarget", hint)
    override_template_values("outputImageAuthenticationType", hint)

    yaml_data = CommentedConfig(name, schemas).get_template()

    return yaml_data


def get_mbi_note(mbi_cls: Any) -> str:
    """Get note about MBI supported mixins.

    Generates a formatted note containing information about the MBI class and its base classes (mixins).

    :param mbi_cls: The MBI class to analyze for supported mixins.
    :return: Formatted string containing class name and list of base classes.
    """
    note = " **MBI Mixins**\n\n"
    note += f"Class name: {mbi_cls.__name__}\n"
    for mbi_base in mbi_cls.__bases__:
        note += f" - {mbi_base.__name__}\n"
    return note


def get_all_mbi_classes() -> list[tuple[Type["MasterBootImage"], FamilyRevision]]:
    """Get all Master Boot Image supported classes.

    This method retrieves all supported MBI classes across all families in the SPSDK,
    ensuring no duplicate classes are returned by using hash-based deduplication.

    :return: List of tuples containing MBI class types and their corresponding family revisions.
    """
    mbi_families = MasterBootImage.get_supported_families()
    cls_list = []
    hash_set = set()
    for family in mbi_families:
        db = get_db(family)
        mbi_classes: dict[str, Any] = db.get_dict(DatabaseManager.MBI, "mbi_classes")

        for mbi_cls_name in mbi_classes:
            cls = MasterBootImage.create_mbi_class(mbi_cls_name, family)
            if cls.hash() not in hash_set:
                hash_set.add(cls.hash())
                cls_list.append((cls, family))

    return cls_list


def get_mbi_doc() -> None:
    """Generate documentation for all MBI (Master Boot Image) classes.

    This method iterates through all available MBI classes, retrieves their validation
    schemas, processes them into documentation format, and appends the generated
    documentation to the MBI schemas file. If the schemas file already exists,
    it is removed before generating new documentation.

    :raises OSError: If there are file system issues when removing or writing to the schemas file.
    :raises SPSDKError: If there are issues retrieving MBI classes or their validation schemas.
    """
    if os.path.exists(MBI_SCHEMAS_FILE):
        os.remove(MBI_SCHEMAS_FILE)
    image_classes = get_all_mbi_classes()
    for cls, family_ambassador in image_classes:
        validation_schemas = cls.get_validation_schemas(family_ambassador)
        schema = get_schema(validation_schemas)
        schema["title"] = cls.hash()
        parsed_schema = parse_schema(schema)
        # parsed_schema[1] = parsed_schema[1].replace("Properties", f"Class name: {cls.__name__}")
        template = get_template([schema], f"YAML template {cls.__name__}")
        note = get_mbi_note(cls)
        append_schema(
            parsed_schema,
            template,
            MBI_SCHEMAS_FILE,
            note,
            title=cls.hash(),
        )


def get_sb31_table() -> None:
    """Generate table with SB3.1 supported commands.

    The method creates a comprehensive table showing which SB3.1 commands are supported
    by each device family. It loads device information and command schemas from the
    database, then generates a markdown table file with the support matrix.

    :raises OSError: If there are issues reading schema files or writing the output table.
    :raises SPSDKError: If database operations fail or device information cannot be retrieved.
    """
    if os.path.exists(SB31_TABLE_FILE):
        os.remove(SB31_TABLE_FILE)
    # Load the YAML files
    sb31_devices = get_docs_families(DatabaseManager.SB31)
    commands_yaml = get_schema_file(DatabaseManager.SB31)

    headers = ["Command", "Command Description"]
    values = []
    supported_commands = {}
    devices: list[str] = []

    # Iterate over the devices in the devices YAML data
    for device in sb31_devices:
        supported_commands[device.name] = get_db(device).get_list(
            DatabaseManager.SB31, "supported_commands"
        )
        devices.append(str(device.name))
    headers.extend(devices)
    commands = commands_yaml["sb3_commands"]["properties"]["commands"]["items"]["oneOf"]

    for command in commands:
        properties = command["properties"]
        command_name = list(properties.keys())[0]
        description = properties[command_name]["description"]
        vals = [command_name, description]

        for device_name in devices:
            if command_name in supported_commands[device_name]:
                supported = "YES"
            else:
                supported = "NO"
            vals.append(supported)
        values.append(vals)

    write_table(headers, values, "List of SB 3.1 supported commands", SB31_TABLE_FILE)


def get_sb31_doc() -> None:
    """Generate documentation for SB3.1 configurations.

    This method generates validation schemas documentation for all supported families
    in the SB3.1 (Secure Binary 3.1) format. It removes any existing schema file,
    retrieves supported families from the database, and creates comprehensive
    documentation including validation schemas and configuration templates for each family.

    :raises OSError: If there are file system permission issues when removing existing schema file.
    :raises SPSDKError: If validation schema generation or template retrieval fails for any family.
    """
    # Get validation schemas DOC
    if os.path.exists(SB31_SCHEMAS_FILE):
        os.remove(SB31_SCHEMAS_FILE)
    families = get_docs_families(DatabaseManager.SB31)
    for family in families:
        validation_schemas = SecureBinary31.get_validation_schemas(family)
        schema = get_schema(validation_schemas)
        schema["title"] = f"{SecureBinary31.__name__} for {family}"
        parsed_schema = parse_schema(schema)
        template = SecureBinary31.get_config_template(family)
        append_schema(parsed_schema, template, SB31_SCHEMAS_FILE, title=schema["title"])


def get_sb40_table() -> None:
    """Generate table with SB4.0 supported commands.

    This method creates a comprehensive table showing which SB4.0 commands are supported
    by different device families. The table is written to a file and includes command
    names, descriptions, and device-specific support status.

    :raises SPSDKError: If database access fails or schema files cannot be loaded.
    :raises OSError: If file operations fail during table generation.
    """
    if os.path.exists(SB40_TABLE_FILE):
        os.remove(SB40_TABLE_FILE)
    # Load the YAML files
    sb40_devices = get_docs_families(DatabaseManager.SB40)
    commands_yaml = get_schema_file(DatabaseManager.SB31)

    headers = ["Command", "Command Description"]
    values = []
    supported_commands = {}
    devices = []

    # Iterate over the devices in the devices YAML data
    for device in sb40_devices:
        supported_commands[device.name] = get_db(device).get_list(
            DatabaseManager.SB40, "supported_commands"
        )
        devices.append(str(device.name))
    headers.extend(devices)
    commands = commands_yaml["sb3_commands"]["properties"]["commands"]["items"]["oneOf"]

    for command in commands:
        properties = command["properties"]
        command_name = list(properties.keys())[0]
        description = properties[command_name]["description"]
        vals = [command_name, description]

        for device_name in devices:
            if command_name in supported_commands[device_name]:
                supported = "YES"
            else:
                supported = "NO"
            vals.append(supported)
        values.append(vals)

    write_table(headers, values, "List of SB 4.0 supported commands", SB40_TABLE_FILE)


def get_sb40_doc() -> None:
    """Generate documentation for SB4.0 configurations.

    This method generates validation schemas documentation for all supported families
    in the SB4.0 (Secure Binary 4.0) format. It removes any existing schema file,
    retrieves supported families from the database manager, and creates comprehensive
    documentation including validation schemas and configuration templates for each family.

    :raises OSError: If there are file system permission issues when removing existing schema file.
    :raises SPSDKError: If validation schema generation or template retrieval fails for any family.
    """
    # Get validation schemas DOC
    if os.path.exists(SB40_SCHEMAS_FILE):
        os.remove(SB40_SCHEMAS_FILE)
    families = get_docs_families(DatabaseManager.SB40)
    for family in families:
        validation_schemas = SecureBinary4.get_validation_schemas(family)
        schema = get_schema(validation_schemas)
        schema["title"] = f"{SecureBinary4.__name__} for {family}"
        parsed_schema = parse_schema(schema)
        template = SecureBinary4.get_config_template(family)
        append_schema(parsed_schema, template, SB40_SCHEMAS_FILE, title=schema["title"])


def get_ahab_doc() -> None:
    """Generate documentation for AHAB (Advanced High Assurance Boot) configurations.

    This method generates validation schemas and templates for AHAB image configurations
    across all supported device families. It removes any existing AHAB schemas file,
    retrieves supported families from the database, and creates comprehensive documentation
    including validation schemas and configuration templates for each family.

    :raises OSError: If there are file system permission issues when removing or writing files.
    :raises SPSDKError: If AHAB validation schemas cannot be retrieved for a family.
    """
    # Get validation schemas DOC
    if os.path.exists(AHAB_SCHEMAS_FILE):
        os.remove(AHAB_SCHEMAS_FILE)
    families = get_docs_families(DatabaseManager.AHAB, sub_feature="ahab_image")
    for fam in families:
        validation_schemas = AHABImage.get_validation_schemas(fam)
        schema = get_schema(validation_schemas)
        schema["title"] = f"{AHABImage.__name__} for {fam}"
        parsed_schema = parse_schema(schema)
        template = get_template([schema], f"AHAB template {AHABImage.__name__} for {fam}")
        append_schema(parsed_schema, template, AHAB_SCHEMAS_FILE, title=schema["title"])


def get_hab_doc() -> None:
    """Generate documentation for HAB (High Assurance Boot) configurations.

    This method creates schema documentation for HAB configurations by retrieving
    validation schemas, parsing them, and generating template documentation that
    is appended to the HAB schemas file.

    :raises SPSDKError: If schema generation or file operations fail.
    """
    # Get validation schemas DOC
    if os.path.exists(HAB_SCHEMAS_FILE):
        os.remove(HAB_SCHEMAS_FILE)
    validation_schemas = HabImage.get_validation_schemas(FamilyRevision("mimxrt1176"))
    schema = get_schema(validation_schemas)
    schema["title"] = f"{HabImage.__name__}"
    parsed_schema = parse_schema(schema)
    template = get_template([schema], f"HAB template {HabImage.__name__}")
    append_schema(parsed_schema, template, HAB_SCHEMAS_FILE, title=schema["title"])


def get_otfad_doc() -> None:
    """Generate documentation for OTFAD configurations.

    This method creates validation schema documentation for OTFAD (On-The-Fly AES Decryption)
    configurations across all supported device families. It removes any existing schema file,
    retrieves validation schemas for each family, processes them into documentation format,
    and appends the results to the OTFAD schemas file.

    :raises SPSDKError: When validation schema retrieval fails for a family.
    :raises OSError: When file operations (remove/write) fail on the schemas file.
    """
    # Get validation schemas DOC
    if os.path.exists(OTFAD_SCHEMAS_FILE):
        os.remove(OTFAD_SCHEMAS_FILE)
    families = get_docs_families(DatabaseManager.OTFAD)
    for fam in families:
        validation_schemas = Otfad.get_validation_schemas(fam)
        schema = get_schema(validation_schemas)
        schema["title"] = f"OTFAD for {fam}"
        parsed_schema = parse_schema(schema)
        template = get_template([schema], f"OTFAD template for {fam}")
        append_schema(parsed_schema, template, OTFAD_SCHEMAS_FILE, title=schema["title"])


def get_iee_doc() -> None:
    """Generate documentation for IEE (Inline Encryption Engine) configurations.

    This method generates validation schema documentation for IEE configurations
    across all supported device families. It removes any existing schema file,
    retrieves validation schemas for each family, processes them into a readable
    format, and appends the documentation to the IEE schemas file.

    :raises OSError: If there are file system issues when removing or writing files.
    :raises SPSDKError: If schema generation or parsing fails for any family.
    """
    # Get validation schemas DOC
    if os.path.exists(IEE_SCHEMAS_FILE):
        os.remove(IEE_SCHEMAS_FILE)
    families = get_docs_families(DatabaseManager.IEE)
    for fam in families:
        validation_schemas = Iee.get_validation_schemas(fam)
        schema = get_schema(validation_schemas)
        schema["title"] = f"IEE for {fam}"
        parsed_schema = parse_schema(schema)
        template = get_template([schema], f"IEE template for {fam}")
        append_schema(parsed_schema, template, IEE_SCHEMAS_FILE, title=schema["title"])


def get_bee_doc() -> None:
    """Generate documentation for BEE (Bus Encryption Engine) configurations.

    This method generates validation schema documentation for all supported families
    in the BEE database. It removes any existing schema file, retrieves validation
    schemas for each family, processes them into a standardized format, and appends
    the documentation to the BEE schemas file.

    :raises OSError: If there are file system issues when removing or writing files.
    :raises SPSDKError: If validation schema retrieval or processing fails.
    """
    # Get validation schemas DOC
    if os.path.exists(BEE_SCHEMAS_FILE):
        os.remove(BEE_SCHEMAS_FILE)
    families = get_docs_families(DatabaseManager.BEE)
    for fam in families:
        validation_schemas = Bee.get_validation_schemas(fam)
        schema = get_schema(validation_schemas)
        schema["title"] = f"{Bee.__name__} for {fam}"
        parsed_schema = parse_schema(schema)
        template = get_template([schema], "BEE template")
        append_schema(parsed_schema, template, BEE_SCHEMAS_FILE, title=schema["title"])


def get_bootable_image() -> None:
    """Generate bootable image schemas for all supported families and memory types.

    This method removes any existing bootable schemas file and regenerates it by iterating
    through all supported families and their memory types. For each combination, it creates
    validation schemas, parses them, generates templates, and appends the results to the
    bootable schemas file.

    :raises OSError: If file operations fail during schema file manipulation.
    :raises SPSDKError: If bootable image operations or schema generation fails.
    """
    if os.path.exists(BOOTABLE_SCHEMAS_FILE):
        os.remove(BOOTABLE_SCHEMAS_FILE)
    families = get_docs_families(DatabaseManager.BOOTABLE_IMAGE)
    for fam in families:
        memories = BootableImage.get_supported_memory_types(fam)
        for mem in memories:
            validation_schemas = BootableImage.get_validation_schemas(fam, mem)
            schema = get_schema(validation_schemas)
            schema["title"] = f"Bootable Image for {fam} and {mem}"
            parsed_schema = parse_schema(schema)
            template = get_template([schema], f"Bootable Image template for {fam} and {mem}")
            append_schema(parsed_schema, template, BOOTABLE_SCHEMAS_FILE, title=schema["title"])


def get_bootable_image_table() -> None:
    """Generate bootable image table for documentation.

    This method creates a comprehensive table of supported families, their memory types,
    and corresponding configuration offsets for bootable images. The generated table
    is written to a file for documentation purposes.

    :raises SPSDKError: If family or memory type data cannot be retrieved.
    :raises IOError: If the output table file cannot be written.
    """
    values = []
    families = get_docs_families(DatabaseManager.BOOTABLE_IMAGE)
    for fam in families:
        supported_memory = BootableImage.get_supported_memory_types(fam)
        for mem in supported_memory:
            config = BootableImage.get_memory_type_config(fam, mem)
            values.append([str(fam), str(mem), "```" + str(config) + "```"])

    write_table(
        ["Family", "Memory Type", "Offsets"],
        values,
        "List of devices and supported memory types",
        BOOTABLE_TABLE_FILE,
    )


# temporary disable due to the fact that generating takes a lot of time
#  def get_fcb_doc() -> None:
#     """Generate documentation for FCB (Firmware Configuration Block) configurations.

#     This method generates schema documentation for all supported families and memory types
#     in the FCB database. It removes any existing FCB schemas file, iterates through all
#     supported family-memory combinations, retrieves their validation schemas, and appends
#     the parsed documentation to the output file.

#     :raises OSError: If there are file system issues when removing or writing files.
#     :raises SPSDKError: If FCB validation schemas cannot be retrieved or parsed.
#     """
#     # Get validation schemas DOC
#     if os.path.exists(FCB_SCHEMAS_FILE):
#         os.remove(FCB_SCHEMAS_FILE)
#     families = get_docs_families(DatabaseManager.FCB)
#     for fam in families:
#         memories = FCB.get_supported_memory_types(fam)
#         for mem in memories:
#             validation_schemas = FCB.get_validation_schemas(fam, mem)
#             schema = get_schema(validation_schemas)
#             schema["title"] = f"FCB for {fam} and {mem.label}"
#             parsed_schema = parse_schema(schema)
#             template = get_template([schema], f"FCB for {fam} and {mem.label}")
#             append_schema(parsed_schema, template, FCB_SCHEMAS_FILE, title=schema["title"])

# temporary disable due to the fact that generating takes a lot of time
# def get_xmcd_doc() -> None:
#     """Generate documentation for XMCD configurations.

#     This method generates schema documentation for all supported XMCD (External Memory Configuration Data)
#     configurations across different families, memory types, and configuration types. It removes any existing
#     XMCD schemas file and recreates it with updated documentation for each supported combination.

#     :raises OSError: If there are file system access issues when removing or writing files.
#     :raises SPSDKError: If there are issues retrieving XMCD validation schemas or supported types.
#     """
#     # Get validation schemas DOC
#     if os.path.exists(XMCD_SCHEMAS_FILE):
#         os.remove(XMCD_SCHEMAS_FILE)
#     families = get_docs_families(DatabaseManager.XMCD)
#     for fam in families:
#         memories = XMCD.get_supported_memory_types(fam)
#         for mem in memories:
#             config_types = XMCD.get_supported_configuration_types(fam, mem)
#             for cfg_type in config_types:
#                 validation_schemas = XMCD.get_validation_schemas(
#                     fam, MemoryType.from_label(mem.name), cfg_type
#                 )
#                 schema = get_schema(validation_schemas)
#                 schema["title"] = f"XMCD for {fam} and {mem.label}_{cfg_type.label}"
#                 parsed_schema = parse_schema(schema)
#                 template = get_template(
#                     [schema], f"XMCD for {fam} and {mem.label}_{cfg_type.label}"
#                 )
#                 append_schema(parsed_schema, template, XMCD_SCHEMAS_FILE, title=schema["title"])


def write_table(
    header: list[str], values: list[list[str]], table_name: str, table_file_path: str
) -> None:
    """Write Markdown table to file using pytablewriter.

    Creates the output directory if it doesn't exist and writes the table data
    to the specified file path.

    :param header: List of column headers for the table.
    :param values: Matrix of table values where each inner list represents a row.
    :param table_name: Name/title of the table to be written.
    :param table_file_path: Absolute or relative path where the table file will be created.
    """
    writer = MarkdownTableWriter(
        table_name=table_name,
        headers=header,
        value_matrix=values,
    )

    if not os.path.exists(DOC_DIR):
        os.makedirs(DOC_DIR)

    with open(table_file_path, "w", encoding="utf-8") as f:
        writer.stream = f
        writer.write_table()


def get_sb21_doc() -> None:
    """Generate documentation table for SB2.1 commands.

    This method creates a documentation table containing all supported SB2.1 commands
    with their descriptions and examples. It removes the existing table file if present,
    extracts command documentation from SB21Helper, and writes a new formatted table.
    The programFuses command is excluded as it's not usable in YAML configuration.

    :raises AssertionError: When SB2 documentation cannot be parsed for a command.
    """
    if os.path.exists(SB21_TABLE_FILE):
        os.remove(SB21_TABLE_FILE)
    doc_lst = []
    helper = SB21Helper()
    del helper.cmds["programFuses"]  # delete program fuses command
    # special command not usable in YAML
    for key, val in helper.cmds.items():
        assert isinstance(val.__doc__, str), f"No docstring found for command {key}"
        docstring_lines_raw = val.__doc__.split("\n\n")[1:]
        assert len(docstring_lines_raw) > 0, f"No documentation found for command {key}"
        docstring_lines: list[str] = [line.strip() for line in docstring_lines_raw]
        end_line = 0
        for x, line in enumerate(docstring_lines):
            if line.startswith(":"):
                end_line = x
                break
        doc = docstring_lines[:end_line]
        assert len(doc) == 2, f"SB2 documentation cannot be parsed for {key}"
        doc_lst.append([key, doc[0], r"<code>" + doc[1].replace("\n", "<br>") + r"</code>"])
    write_table(
        ["Command", "Description", "Example"],
        doc_lst,
        "Supported commands for SB2.1",
        SB21_TABLE_FILE,
    )


def main() -> None:
    """Generate all SPSDK schema documentation files.

    This function orchestrates the generation of various schema documentation
    files for different SPSDK components including MBI, Secure Binary (SB40, SB31, SB21),
    AHAB, HAB, OTFAD, IEE, BEE, FCB, and XMCD. Each component's documentation
    is generated by calling its respective generation function.
    """
    print("Running generate schemas script")
    # clean_files() # not necessary anymore and each schema cleans its own file
    get_mbi_doc()
    get_sb40_doc()
    get_sb31_doc()
    get_sb21_doc()
    get_sb40_table()
    get_sb31_table()
    get_ahab_doc()
    get_hab_doc()
    get_otfad_doc()
    get_iee_doc()
    get_bee_doc()
    # get_bootable_image()
    # get_bootable_image_table()
    # get_fcb_doc()
    # get_xmcd_doc()
    print("Finished running")


def setup(app: Any) -> None:
    """Setup function for Sphinx extension to generate schemas.

    This function is called by Sphinx during the extension initialization process.
    It triggers the main schema generation functionality.

    :param app: The Sphinx application instance.
    """
    main()


if __name__ == "__main__":
    main()
