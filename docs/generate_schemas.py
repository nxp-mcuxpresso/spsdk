#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
# Script for the automated generation of schemas documentation for elftosb
import os
from typing import List, Dict, Any, Sequence

from spsdk.utils.schema_validator import ConfigTemplate
from spsdk.sbfile.sb31.images import SecureBinary31
from spsdk.image.mbimg import (
    Mbi_PlainXip,
    Mbi_CrcXip,
    Mbi_SignedXip,
    Mbi_PlainXipRtxxx,
    Mbi_CrcXipRtxxx,
    Mbi_PlainSignedXipRtxxx,
    Mbi_PlainRamRtxxx,
    Mbi_CrcRamRtxxx,
    Mbi_PlainSignedRamRtxxx,
    Mbi_EncryptedRamRtxxx,
    Mbi_CrcXipLpc55s3x,
    Mbi_CrcExtXipLpc55s3x,
    Mbi_PlainXipSignedLpc55s3x,
    Mbi_PlainExtXipSignedLpc55s3x,
    Mbi_PlainRamLpc55s3x,
    Mbi_CrcRamLpc55s3x,
)

import deepmerge
import jsonschema2md

DOC_PATH = os.path.dirname(os.path.realpath(__file__))
SCHEMAS_DIR = os.path.join(DOC_PATH, "apps")
SCHEMAS_FILE = os.path.join(SCHEMAS_DIR, "schemas.inc")

cls_lst = [
    Mbi_PlainXip,
    Mbi_CrcXip,
    Mbi_SignedXip,
    Mbi_PlainXipRtxxx,
    Mbi_CrcXipRtxxx,
    Mbi_PlainSignedXipRtxxx,
    Mbi_PlainRamRtxxx,
    Mbi_CrcRamRtxxx,
    Mbi_PlainSignedRamRtxxx,
    Mbi_EncryptedRamRtxxx,
    Mbi_CrcXipLpc55s3x,
    Mbi_CrcExtXipLpc55s3x,
    Mbi_PlainXipSignedLpc55s3x,
    Mbi_PlainExtXipSignedLpc55s3x,
    Mbi_PlainRamLpc55s3x,
    Mbi_CrcRamLpc55s3x,
]


def get_schema(schemas: List[Dict[str, Any]]) -> Dict:
    """Merges partial schemas into one valid schema using deepmerge

    :param schemas: List of schemas as an output from get_validation_schemas class method
    :type schemas: List[Dict[str, Any]]
    :return: Dictionary with valid schema
    :rtype: Dict
    """
    schema = {}
    for sch in schemas:
        deepmerge.always_merger.merge(schema, sch)

    return schema


def parse_schema(schema: Dict) -> Sequence[str]:
    """Parse schema using jsonschema2md parser and returns MD as a string

    :param schema: Valid schema from the get_schema function
    :type schema: Dict
    :return: Sequence of strings with parsed schema as a Markdown
    :rtype: Sequence[str]
    """
    parser = jsonschema2md.Parser(
        examples_as_yaml=False,
        show_examples="all",
    )

    return parser.parse_schema(schema)


def append_schema(parsed: Sequence[str], template: str) -> None:
    """Appends schema and template to the markdown document

    :param parsed: sequence of MD strings
    :type parsed: Sequence[str]
    :param template: string with YAML to be appended to the doc
    :type template: str
    """
    if not os.path.exists(SCHEMAS_DIR):
        os.makedirs(SCHEMAS_DIR)
    with open(SCHEMAS_FILE, "a+") as f:
        del parsed[1]  # remove subtitle
        f.writelines(parsed)
        f.write("\n")
        f.write("```yaml\n")
        f.write(template)
        f.write("\n```")
        f.write("\n")


def get_template(schemas: Dict, name: str) -> str:
    """Get template for schemas

    :param schemas: dictionary with validation schemas
    :type schemas: Dict
    :param name: Name that will be displayed as a title
    :type name: str
    :return: string with YAML template
    :rtype: str
    """
    override = {}

    yaml_data = ConfigTemplate(
        name,
        schemas,
        override,
    ).export_to_yaml()

    return yaml_data


def main():
    print("Running generate schemas script")
    if os.path.exists(SCHEMAS_FILE):
        os.remove(SCHEMAS_FILE)
        print("Existing schemas file has been removed")

    for cls in cls_lst:
        schema = get_schema(cls.get_validation_schemas())
        schema["title"] = cls.__name__
        parsed_schema = parse_schema(schema)
        template = get_template(cls.get_validation_schemas(), f"YAML template {cls.__name__}")
        append_schema(parsed_schema, template)
    print("Finished running")


if __name__ == "__main__":
    main()
