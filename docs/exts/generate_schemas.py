#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
# Script for the automated generation of schemas documentation for nxpimage
import copy
import json
import os
import tempfile
from typing import Any, Dict, List, Optional, Sequence

from pytablewriter import MarkdownTableWriter
from json_schema_for_humans.generation_configuration import GenerationConfiguration
from json_schema_for_humans.generate import generate_from_schema

from spsdk.image.ahab.ahab_image import AHABImage
from spsdk.image.bee import BeeNxp
from spsdk.image.bootable_image.bimg import BootableImage
from spsdk.image.fcb.fcb import FCB
from spsdk.image.hab.hab_container import HabContainer
from spsdk.image.mbi.mbi import get_all_mbi_classes
from spsdk.image.xmcd.xmcd import XMCD, ConfigurationBlockType, MemoryType
from spsdk.sbfile.sb2.sb_21_helper import SB21Helper
from spsdk.sbfile.sb31.images import SecureBinary31
from spsdk.utils.crypto.iee import IeeNxp
from spsdk.utils.crypto.otfad import OtfadNxp
from spsdk.utils.database import DatabaseManager, get_db, get_families, get_schema_file
from spsdk.utils.schema_validator import CommentedConfig, SPSDKMerger

DOC_PATH = os.path.abspath(".")
DOC_DIR = os.path.join(DOC_PATH, "_prebuild")
HTML_SCHEMAS_PATH = os.path.join(DOC_PATH, "html_schemas")

MBI_SCHEMAS_FILE = os.path.join(DOC_DIR, "schemas.inc")
SB3_SCHEMAS_FILE = os.path.join(DOC_DIR, "schemas_sb3.inc")
AHAB_SCHEMAS_FILE = os.path.join(DOC_DIR, "ahab_schemas.inc")
HAB_SCHEMAS_FILE = os.path.join(DOC_DIR, "hab_schemas.inc")
OTFAD_SCHEMAS_FILE = os.path.join(DOC_DIR, "otfad_schemas.inc")
IEE_SCHEMAS_FILE = os.path.join(DOC_DIR, "iee_schemas.inc")
BEE_SCHEMAS_FILE = os.path.join(DOC_DIR, "bee_schemas.inc")
FCB_SCHEMAS_FILE = os.path.join(DOC_DIR, "fcb_schemas.inc")
XMCD_SCHEMAS_FILE = os.path.join(DOC_DIR, "xmcd_schemas.inc")
BOOTABLE_SCHEMAS_FILE = os.path.join(DOC_DIR, "bootable_schemas.inc")
SB2_TABLE_FILE = os.path.join(DOC_DIR, "table_sb21.inc")
SB3_TABLE_FILE = os.path.join(DOC_DIR, "table_sb31.inc")
BOOTABLE_TABLE_FILE = os.path.join(DOC_DIR, "table_bootable.inc")

schema_files = [
    MBI_SCHEMAS_FILE,
    SB3_SCHEMAS_FILE,
    AHAB_SCHEMAS_FILE,
    HAB_SCHEMAS_FILE,
    OTFAD_SCHEMAS_FILE,
    IEE_SCHEMAS_FILE,
    BEE_SCHEMAS_FILE,
    FCB_SCHEMAS_FILE,
    XMCD_SCHEMAS_FILE,
    BOOTABLE_SCHEMAS_FILE,
    SB2_TABLE_FILE,
    SB3_TABLE_FILE,
    BOOTABLE_TABLE_FILE,
]


def clean_files() -> None:
    """Clean files."""
    for file in schema_files:
        if os.path.exists(file):
            os.remove(file)
    print("Existing schemas files have been removed")


def get_docs_families(feature: str) -> List[str]:
    """Get list of families."""
    families = get_families(feature)
    families = [
        family for family in families if DatabaseManager().db.devices.get(family).info.use_in_doc
    ]
    return sorted(families)


def get_schema(schemas: List[Dict[str, Any]]) -> Dict:
    """Merges partial schemas into one valid schema using deepmerge

    :param schemas: List of schemas as an output from get_validation_schemas class method
    :return: Dictionary with valid schema
    """

    schemas_merger = SPSDKMerger(
        [(list, ["set"]), (dict, ["merge"]), (set, ["union"])],
        ["override"],
        ["override"],
    )

    schema = {}
    for sch in schemas:
        schemas_merger.merge(schema, copy.deepcopy(sch))

    return schema


def parse_schema(schema: Dict) -> Sequence[str]:
    """Parse schema using json_schema_for_humans and return it as a HTML

    :param schema: Valid schema from the get_schema function
    :return: HTML string
    """
    config = GenerationConfiguration(with_footer=False, deprecated_from_description=True)
    with tempfile.TemporaryDirectory() as temp_dir:
        schema_file = os.path.join(temp_dir, schema["title"].replace(" ", "_"))
        with open(schema_file, "w") as file:
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
    """Appends schema and template to the markdown document

    :param parsed: HTML string with parsed schema
    :param template: string with YAML to be appended to the doc
    :param file: schema file
    :param note: note that will be appended after parsed
    :param title: title of the schema
    :param subtitle: subtitle of the schema
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


def get_template(schemas: List, name: str) -> str:
    """Get template for schemas

    :param schemas: List with validation schemas
    :param name: Name that will be displayed as a title
    :return: string with YAML template
    """

    def override_template_values(key: str, value: str):
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
    """Get note about MBI supported mixins"""
    note = " **MBI Mixins**\n\n"
    note += f"Class name: {mbi_cls.__name__}\n"
    for mbi_base in mbi_cls.__bases__:
        note += f" - {mbi_base.__name__}\n"
    return note


def get_mbi_doc() -> None:
    """Get doc for MBI classes."""
    if os.path.exists(MBI_SCHEMAS_FILE):
        os.remove(MBI_SCHEMAS_FILE)
    image_classes = get_all_mbi_classes()
    for cls in image_classes:
        validation_schemas = cls.get_validation_schemas("lpc55s36")
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


def get_sb3_table() -> None:
    """Generates table with SB3 supported commands"""
    # Load the YAML files
    sb31_devices = get_docs_families(DatabaseManager.SB31)
    commands_yaml = get_schema_file(DatabaseManager.SB31)

    headers = ["Command", "Command Description"]
    values = []
    supported_commands = {}
    devices = []

    # Iterate over the devices in the devices YAML data
    for device in sb31_devices:
        supported_commands[device] = get_db(device, "latest").get_list(
            DatabaseManager.SB31, "supported_commands"
        )
        devices.append(device)
    headers.extend(devices)
    commands = commands_yaml["sb3_commands"]["properties"]["commands"]["items"]["oneOf"]

    for command in commands:
        properties = command["properties"]
        command_name = list(properties.keys())[0]
        description = properties[command_name]["description"]
        vals = [command_name, description]

        for device in devices:
            if command_name in supported_commands[device]:
                supported = "YES"
            else:
                supported = "NO"
            vals.append(supported)
        values.append(vals)

    write_table(headers, values, "List of SB 3.1 supported commands", SB3_TABLE_FILE)


def get_sb3_doc() -> None:
    """Get doc for SB3 configurations."""
    # Get validation schemas DOC
    if os.path.exists(SB3_SCHEMAS_FILE):
        os.remove(SB3_SCHEMAS_FILE)
    families = get_docs_families(DatabaseManager.SB31)
    for fam in families:
        validation_schemas = SecureBinary31.get_validation_schemas(fam)
        schema = get_schema(validation_schemas)
        schema["title"] = f"{SecureBinary31.__name__} for {fam}"
        parsed_schema = parse_schema(schema)
        template = SecureBinary31.generate_config_template(fam)[f"{fam}_sb31"]
        append_schema(parsed_schema, template, SB3_SCHEMAS_FILE, title=schema["title"])


def get_ahab_doc() -> None:
    """Get doc for AHAB configurations."""
    # Get validation schemas DOC
    if os.path.exists(AHAB_SCHEMAS_FILE):
        os.remove(AHAB_SCHEMAS_FILE)
    families = get_docs_families(DatabaseManager.AHAB)
    for fam in families:
        validation_schemas = AHABImage.get_validation_schemas(fam)
        schema = get_schema(validation_schemas)
        schema["title"] = f"{AHABImage.__name__} for {fam}"
        parsed_schema = parse_schema(schema)
        template = get_template([schema], f"AHAB template {AHABImage.__name__} for {fam}")
        append_schema(parsed_schema, template, AHAB_SCHEMAS_FILE, title=schema["title"])


def get_hab_doc() -> None:
    """Get doc for HAB configurations."""
    # Get validation schemas DOC
    if os.path.exists(HAB_SCHEMAS_FILE):
        os.remove(HAB_SCHEMAS_FILE)
    validation_schemas = HabContainer.get_validation_schemas()
    schema = get_schema(validation_schemas)
    schema["title"] = f"{HabContainer.__name__}"
    parsed_schema = parse_schema(schema)
    template = get_template([schema], f"HAB template {HabContainer.__name__}")
    append_schema(parsed_schema, template, HAB_SCHEMAS_FILE, title=schema["title"])


def get_otfad_doc() -> None:
    """Get doc for OTFAD configurations."""
    # Get validation schemas DOC
    if os.path.exists(OTFAD_SCHEMAS_FILE):
        os.remove(OTFAD_SCHEMAS_FILE)
    families = get_docs_families(DatabaseManager.OTFAD)
    for fam in families:
        validation_schemas = OtfadNxp.get_validation_schemas(fam)
        schema = get_schema(validation_schemas)
        schema["title"] = f"OTFAD for {fam}"
        parsed_schema = parse_schema(schema)
        template = get_template([schema], f"OTFAD template for {fam}")
        append_schema(parsed_schema, template, OTFAD_SCHEMAS_FILE, title=schema["title"])


def get_iee_doc() -> None:
    """Get doc for AHAB configurations."""
    # Get validation schemas DOC
    if os.path.exists(IEE_SCHEMAS_FILE):
        os.remove(IEE_SCHEMAS_FILE)
    families = get_docs_families(DatabaseManager.IEE)
    for fam in families:
        validation_schemas = IeeNxp.get_validation_schemas(fam)
        schema = get_schema(validation_schemas)
        schema["title"] = f"IEE for {fam}"
        parsed_schema = parse_schema(schema)
        template = get_template([schema], f"IEE template for {fam}")
        append_schema(parsed_schema, template, IEE_SCHEMAS_FILE, title=schema["title"])


def get_bee_doc() -> None:
    """Get doc for AHAB configurations."""
    # Get validation schemas DOC
    if os.path.exists(BEE_SCHEMAS_FILE):
        os.remove(BEE_SCHEMAS_FILE)
    validation_schemas = BeeNxp.get_validation_schemas()
    schema = get_schema(validation_schemas)
    schema["title"] = f"{BeeNxp.__name__}"
    parsed_schema = parse_schema(schema)
    template = get_template([schema], "BEE template")
    append_schema(parsed_schema, template, BEE_SCHEMAS_FILE, title=schema["title"])


def get_bootable_image() -> None:
    """Get bootable image schemas."""
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
    """Get bootable image table."""
    values = []
    families = get_docs_families(DatabaseManager.BOOTABLE_IMAGE)
    for fam in families:
        supported_memory = BootableImage.get_supported_memory_types(fam)
        for mem in supported_memory:
            config = BootableImage.get_memory_type_config(fam, mem)
            values.append([fam, mem, "```" + str(config) + "```"])

    write_table(
        ["Family", "Memory Type", "Offsets"],
        values,
        "List of devices and supported memory types",
        BOOTABLE_TABLE_FILE,
    )


def get_fcb_doc() -> None:
    """Get doc for FCB configurations."""
    # Get validation schemas DOC
    if os.path.exists(FCB_SCHEMAS_FILE):
        os.remove(FCB_SCHEMAS_FILE)
    families = get_docs_families(DatabaseManager.FCB)
    for fam in families:
        memories = FCB.get_supported_memory_types(fam)
        for mem in memories:
            validation_schemas = FCB.get_validation_schemas(fam, mem)
            schema = get_schema(validation_schemas)
            schema["title"] = f"FCB for {fam} and {mem.label}"
            parsed_schema = parse_schema(schema)
            template = get_template([schema], f"FCB for {fam} and {mem.label}")
            append_schema(parsed_schema, template, FCB_SCHEMAS_FILE, title=schema["title"])


def get_xmcd_doc() -> None:
    """Get doc for XMCD configurations."""
    # Get validation schemas DOC
    if os.path.exists(XMCD_SCHEMAS_FILE):
        os.remove(XMCD_SCHEMAS_FILE)
    families = get_docs_families(DatabaseManager.XMCD)
    for fam in families:
        memories = XMCD.get_supported_memory_types(fam)
        for mem in memories:
            config_types = XMCD.get_supported_configuration_types(fam, mem)
            for cfg_type in config_types:
                validation_schemas = XMCD.get_validation_schemas(
                    fam, MemoryType.from_label(mem.name), cfg_type
                )
                schema = get_schema(validation_schemas)
                schema["title"] = f"XMCD for {fam} and {mem.label}_{cfg_type.label}"
                parsed_schema = parse_schema(schema)
                template = get_template(
                    [schema], f"XMCD for {fam} and {mem.label}_{cfg_type.label}"
                )
                append_schema(parsed_schema, template, XMCD_SCHEMAS_FILE, title=schema["title"])


def write_table(header: List[str], values: List[List[str]], table_name: str, table_file_path: str):
    """Write MD table to file using pytablewriter

    :param header: table header
    :param values: values to be written
    :param table_name: Name of the table
    :param table_file_path: Path to the file
    """
    writer = MarkdownTableWriter(
        table_name=table_name,
        headers=header,
        value_matrix=values,
    )

    if not os.path.exists(DOC_DIR):
        os.makedirs(DOC_DIR)

    with open(table_file_path, "w") as f:
        writer.stream = f
        writer.write_table()


def get_sb2_doc() -> None:
    """Get doc for SB2 commands."""
    doc_lst = []
    helper = SB21Helper()
    del helper.cmds["programFuses"]  # delete program fuses command
    # special command not usable in YAML
    for key, val in helper.cmds.items():
        doc = [
            line.strip()
            for line in val.__doc__.split("\n\n")
            if not (line.strip().startswith(":") or line.strip().startswith("Returns"))
        ]
        assert len(doc) == 2, f"SB2 documentation cannot be parsed for {key}"
        doc_lst.append([key, doc[0], r"<code>" + doc[1].replace("\n", "<br>") + r"</code>"])
    write_table(
        ["Command", "Description", "Example"],
        doc_lst,
        "Supported commands for SB2.1",
        SB2_TABLE_FILE,
    )


def main():
    print("Running generate schemas script")
    clean_files()
    get_mbi_doc()
    get_sb3_doc()
    get_sb2_doc()
    get_sb3_table()
    get_ahab_doc()
    get_hab_doc()
    get_otfad_doc()
    get_iee_doc()
    get_bee_doc()
    # get_bootable_image()
    # get_bootable_image_table()
    get_fcb_doc()
    get_xmcd_doc()
    print("Finished running")


def setup(app):
    main()


if __name__ == "__main__":
    main()
