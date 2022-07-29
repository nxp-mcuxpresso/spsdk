#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause
# Script for the automated generation of schemas documentation for elftosb
import os
from typing import Any, Dict, List, Sequence

import jsonschema2md
from deepmerge import Merger

from spsdk.image.mbimg import get_all_mbi_classes
from spsdk.sbfile.sb31.images import SecureBinary31
from spsdk.utils.schema_validator import ConfigTemplate, SPSDK_Merger

DOC_PATH = os.path.abspath(".")
SCHEMAS_DIR = os.path.join(DOC_PATH, "_prebuild")
SCHEMAS_FILE = os.path.join(SCHEMAS_DIR, "schemas.inc")


def get_schema(schemas: List[Dict[str, Any]]) -> Dict:
    """Merges partial schemas into one valid schema using deepmerge

    :param schemas: List of schemas as an output from get_validation_schemas class method
    :return: Dictionary with valid schema
    """

    schemas_merger = SPSDK_Merger(
        [(list, ["set"]), (dict, ["merge"]), (set, ["union"])],
        ["override"],
        ["override"],
    )

    schema = {}
    for sch in schemas:
        schemas_merger.merge(schema, sch)

    return schema


def parse_schema(schema: Dict) -> Sequence[str]:
    """Parse schema using jsonschema2md parser and returns MD as a string

    :param schema: Valid schema from the get_schema function
    :return: Sequence of strings with parsed schema as a Markdown
    """
    parser = jsonschema2md.Parser(
        examples_as_yaml=False,
        show_examples="all",
    )

    return parser.parse_schema(schema)


def append_schema(parsed: Sequence[str], template: str) -> None:
    """Appends schema and template to the markdown document

    :param parsed: sequence of MD strings
    :param template: string with YAML to be appended to the doc
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
    :param name: Name that will be displayed as a title
    :return: string with YAML template
    """
    override = {}
    hint = "CHOOSE_FROM_TABLE"
    override["family"] = hint
    override["outputImageExecutionTarget"] = hint
    override["outputImageAuthenticationType"] = hint

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

    image_classes = get_all_mbi_classes()
    image_classes.append(SecureBinary31)

    for cls in image_classes:
        validation_schemas = cls.get_validation_schemas()
        schema = get_schema(validation_schemas)
        schema["title"] = cls.__name__
        parsed_schema = parse_schema(schema)
        template = get_template([schema], f"YAML template {cls.__name__}")
        append_schema(parsed_schema, template)
    print("Finished running")


def setup(app):
    main()


if __name__ == "__main__":
    main()
