#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for schema-based configuration validation."""

import copy
import io
import os
from typing import Any, Callable, Dict, List, Optional, Union

import deepmerge
import fastjsonschema
from ruamel.yaml import YAML, YAMLError
from ruamel.yaml.comments import CommentedMap as CM
from ruamel.yaml.comments import CommentedSeq as CS

from spsdk import SPSDK_YML_INDENT, SPSDKError
from spsdk.utils.misc import value_to_int

ENABLE_DEBUG = False


def _is_number(param: Any) -> bool:
    """Checks whether the input represents a number.

    :param param: Input to analyze
    :raises SPSDKError: Input doesn't represent a number
    :return: True if input represents a number
    """
    try:
        value_to_int(param)
        return True
    except SPSDKError:
        return False


CUSTOM_FORMATERS: Dict[str, Callable[[str], bool]] = {
    "dir": lambda x: os.path.isdir(x.replace("\\", "/")),
    "file": lambda x: os.path.isfile(x.replace("\\", "/")),
    "file_name": lambda x: os.path.basename(x.replace("\\", "/")) not in ("", None),
    "optional_file": lambda x: not x or os.path.isfile(x.replace("\\", "/")),
    "number": _is_number,
}


def check_config(
    config: Dict[str, Any],
    schemas: List[Dict[str, Any]],
    extra_formaters: Dict[str, Callable[[str], bool]] = None,
) -> None:
    """Check the configuration by provided list of validation schemas.

    :param config: Configuration to check
    :param schemas: List of validation schemas
    :param extra_formaters: Additional custom formaters
    :raises SPSDKError: Invalid validation schema or configuration
    """
    schema: Dict[str, Any] = {}
    for sch in schemas:
        deepmerge.always_merger.merge(schema, sch)
    formats = deepmerge.always_merger.merge(CUSTOM_FORMATERS, extra_formaters or {})
    try:
        if ENABLE_DEBUG:
            validator_code = fastjsonschema.compile_to_code(schema, formats=formats)
            with open("validator_file.py", "w") as f:
                f.write(validator_code)
        else:
            validator = fastjsonschema.compile(schema, formats=formats)
    except (TypeError, fastjsonschema.JsonSchemaDefinitionException) as exc:
        raise SPSDKError(f"Invalid validation schema to check config: {str(exc)}") from exc
    try:
        config_to_check = copy.deepcopy(config)
        if ENABLE_DEBUG:
            # pylint: disable=import-error,import-outside-toplevel
            import validator_file  # type: ignore

            validator_file.validate(config_to_check)
        else:
            validator(config_to_check)
    except fastjsonschema.JsonSchemaValueException as exc:
        message = str(exc)
        if exc.rule == "required":
            missing = filter(lambda x: x not in exc.value.keys(), exc.rule_definition)
            message += f"; Missing field(s): {', '.join(missing)}"
        raise SPSDKError(f"Configuration validation failed: {message}") from exc


class ConfigTemplate:
    """Class for generating commented config templates."""

    def __init__(
        self, main_title: str, schemas: List[Dict[str, Any]], override_values: Dict[str, Any] = None
    ):
        """Constructor for Config templates.

        :param main_title: Main title of final template.
        :param schemas: Main decscription of final template.
        :param override_values: Additional overriding default values.
        """
        self.main_title = main_title
        self.schemas = schemas
        self.override_values = override_values

    def _get_required(self, key: str, block: Dict[str, Any]) -> str:
        """Function to determine if the config key is required or not.

        :param key: Name of config record
        :param block: Source data block
        :return: Final description.
        """

        def _find_required(d_in: Dict[str, Any]) -> Optional[List[str]]:
            if "required" in d_in:
                return d_in["required"]

            for d_v in d_in.values():
                if isinstance(d_v, dict):
                    ret = _find_required(d_v)
                    if ret:
                        return ret
            return None

        if "required" in block and key in block["required"]:
            return "Required"

        for val in block.values():
            if isinstance(val, dict):
                ret = _find_required(val)
                if ret and key in ret:
                    return "Conditionally required"

        return "Optional"

    def _insert_to_cfg(
        self, cfg: Union[CM, CS], key: str, block: Dict[str, Any], value: Any
    ) -> None:
        """Private function used to Insert configuration in final config CM/CS block.

        :param cfg: Block where the new configuration should be placed.
        :param key: Key for store
        :param block: Block where of source data
        :param value: Value
        """
        val = block["properties"][key]
        p_title = val.get("title", key)
        p_descr = val.get("description", None)
        p_required = self._get_required(key, block)

        if isinstance(cfg, CM):
            cfg[key] = value
            cfg.yaml_add_eol_comment(f"[{p_required}], {p_title}, {p_descr}", key=key)
        if isinstance(cfg, CS):
            if isinstance(value, dict):
                new_dict = CM()
                cfg.append(new_dict)
                new_dict[key] = value
                new_dict.yaml_add_eol_comment(f"[{p_required}], {p_title}, {p_descr}", key=key)
            else:
                cfg.append(value)
                cfg.yaml_add_eol_comment(
                    f"[{p_required}], {p_title}, {p_descr}", column=len(cfg) - 1
                )

    def _fill_up_block(self, cfg: Union[CM, CS], block: Dict[str, Any]) -> None:
        """Private function used to fill up configuration block with data.

        :param cfg: CM base configuration object to fill up
        :param block: Source block with data
        :raises SPSDKError: In case of invalid data pattern.
        """
        if not "properties" in block:
            return
        for key, val in block["properties"].items():
            schema_type = val.get("type")
            if schema_type is None:
                raise SPSDKError("Invalid type in JSONSCHEMA.")

            if schema_type == "array":
                arr_cfg = CS()
                self._fill_up_block(arr_cfg, val["items"])
                self._insert_to_cfg(cfg, key, block, arr_cfg)

            elif schema_type == "object":
                obj_cfg = CM()
                self._fill_up_block(obj_cfg, val)
                self._insert_to_cfg(cfg, key, block, obj_cfg)

            else:
                p_default_val = val.get("template_value", None)
                if self.override_values and key in self.override_values:
                    p_default_val = self.override_values[key]
                self._insert_to_cfg(cfg, key, block, p_default_val)

    def export(self) -> CM:
        """Export configuration template into CommentedMap.

        :raises SPSDKError: Error
        :return: Configuration template in CM.
        """
        loc_schemas = copy.deepcopy(self.schemas)
        # 1. Do pre-merge by schema titles
        pre_merged: Dict[str, Any] = {}
        for schema in loc_schemas:
            title = schema.get("title", "General Options")
            if title in pre_merged:
                deepmerge.always_merger.merge(pre_merged[title], schema)
            else:
                pre_merged[title] = schema

        cfg = CM()
        # 2. Add main title of configuration
        cfg.yaml_set_start_comment(f"===========  {self.main_title}  ===========\n")
        # 3. Go through all individual logic blocks
        for block in pre_merged.values():
            try:
                self._fill_up_block(cfg, block)
                title = block.get("title", "General Options")
                description = block.get("description", "")
                cfg.yaml_set_comment_before_after_key(
                    list(block["properties"].keys())[0], f" \n == {title} == \n {description}"
                )
            except Exception as exc:
                raise SPSDKError(f"Template generation failed: {str(exc)}") from exc

        return cfg

    def export_to_yaml(self) -> str:
        """Export Configuration template directly into YAML string format.

        :return: YAML string.
        """
        return ConfigTemplate.convert_cm_to_yaml(self.export())

    @staticmethod
    def convert_cm_to_yaml(config: CM) -> str:
        """Convert Commented Map for into final YAML string.

        :param config: Configuration in CM format.
        :return: YAML string with configuration to use to store in file.
        """
        yaml = YAML(pure=True)
        yaml.indent(sequence=SPSDK_YML_INDENT * 2, offset=SPSDK_YML_INDENT)
        stream = io.StringIO()
        yaml.dump(config, stream)
        yaml_data = stream.getvalue()

        return yaml_data


class ValidationSchemas:
    """Manager for validation schemas."""

    _instancies: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def get_schema_file(sch_file: str) -> Dict[str, Any]:
        """Return load schema file. Use SingleTon behavior.

        :param sch_file: Path to schema config file.
        :raises SPSDKError: Invalid schema config file.
        :return: Loaded schema file.
        """
        abs_path = os.path.abspath(sch_file)
        # Just workaround because PYTEST environment corrupt caching of loaded schema configs
        pytest_running = "PYTEST_CURRENT_TEST" in os.environ

        if not abs_path in ValidationSchemas._instancies or pytest_running:  # pragma: no cover
            try:
                with open(abs_path) as f:
                    schema_cfg = YAML(typ="safe").load(f)
            except (FileNotFoundError, YAMLError, UnicodeDecodeError) as exc:
                raise SPSDKError("Invalid validation scheme configuration file.") from exc
            if pytest_running:  # pragma: no cover
                return schema_cfg
            ValidationSchemas._instancies[abs_path] = schema_cfg  # pragma: no cover

        return ValidationSchemas._instancies[abs_path]  # pragma: no cover
