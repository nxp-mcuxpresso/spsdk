#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright 2021-2022 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for schema-based configuration validation."""

import copy
import io
import logging
import os
import textwrap
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import fastjsonschema
from deepmerge import Merger, always_merger
from deepmerge.strategy.dict import DictStrategies
from deepmerge.strategy.list import ListStrategies
from deepmerge.strategy.set import SetStrategies
from ruamel.yaml import YAML, YAMLError
from ruamel.yaml.comments import CommentedMap as CM
from ruamel.yaml.comments import CommentedSeq as CS

from spsdk import SPSDK_YML_INDENT, SPSDKError
from spsdk.apps.utils import load_configuration
from spsdk.utils.misc import find_file, value_to_int

ENABLE_DEBUG = False

logger = logging.getLogger(__name__)


class SPSDK_ListStrategies(ListStrategies):
    """Extended List Strategies."""

    @staticmethod
    def strategy_set(config, path, base, nxt):  # type: ignore
        """Use the set of both as a output."""
        try:
            ret = list(set(base + nxt))
            ret.sort()
        except TypeError:
            logger.warning(
                "Found unhashable object in List 'set' strategy during merge."
                " It was used 'override' method instead of 'set'."
            )
            ret = nxt
        return ret


class SPSDK_Merger(Merger):
    """Modified Merger to add new list strategy 'set'."""

    PROVIDED_TYPE_STRATEGIES = {
        list: SPSDK_ListStrategies,
        dict: DictStrategies,
        set: SetStrategies,
    }


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


def _print_validation_fail_reason(
    exc: fastjsonschema.JsonSchemaValueException,
    extra_formaters: Dict[str, Callable[[str], bool]] = None,
) -> str:
    """Print formated and easy to read reason why the  validation failed.

    :param exc: Original exception.
    :param extra_formaters: Additional custom formatters
    :return: String explaining the reason of fail.
    """
    message = str(exc)
    if exc.rule == "required":
        missing = filter(lambda x: x not in exc.value.keys(), exc.rule_definition)
        message += f"; Missing field(s): {', '.join(missing)}"
    elif exc.rule == "format":
        if exc.rule_definition == "file":
            message += f"; Non-existing file: {exc.value}"
    elif exc.rule == "oneOf":
        # re-run just the part where the rule failed and get the exact mistake to print
        for rule_def_ix, rule_def in enumerate(exc.rule_definition):
            try:
                oneof_validator = fastjsonschema.compile(rule_def, formats=extra_formaters)
                oneof_validator(exc.value)
            except fastjsonschema.JsonSchemaValueException as oneof_exc:
                message += (
                    f"\nReason of fail for OneOf rule#{rule_def_ix}: "
                    f"\n {_print_validation_fail_reason(oneof_exc, extra_formaters)}\n"
                )
    return message


def check_config(
    config: Union[str, Dict[str, Any]],
    schemas: List[Dict[str, Any]],
    extra_formaters: Dict[str, Callable[[str], bool]] = None,
    search_paths: List[str] = None,
) -> None:
    """Check the configuration by provided list of validation schemas.

    :param config: Configuration to check
    :param schemas: List of validation schemas
    :param extra_formaters: Additional custom formaters
    :param search_paths: List of paths where to search for the file, defaults to None
    :raises SPSDKError: Invalid validation schema or configuration
    """
    custom_formatters: Dict[str, Callable[[str], bool]] = {
        "dir": lambda x: os.path.isdir(x.replace("\\", "/")),
        "file": lambda x: bool(find_file(x, search_paths=search_paths, raise_exc=False)),
        "file_name": lambda x: os.path.basename(x.replace("\\", "/")) not in ("", None),
        "optional_file": lambda x: not x
        or bool(find_file(x, search_paths=search_paths, raise_exc=False)),
        "number": _is_number,
    }
    if isinstance(config, str):
        config_to_check = load_configuration(config)
        config_dir = os.path.dirname(config)
        if search_paths:
            search_paths.append(config_dir)
        else:
            search_paths = [config_dir]
    else:
        config_to_check = copy.deepcopy(config)

    schema: Dict[str, Any] = {}
    for sch in schemas:
        always_merger.merge(schema, copy.deepcopy(sch))
    formats = always_merger.merge(custom_formatters, extra_formaters or {})
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
        if ENABLE_DEBUG:
            # pylint: disable=import-error,import-outside-toplevel
            import validator_file  # type: ignore

            validator_file.validate(config_to_check, formats)
        else:
            validator(config_to_check)
    except fastjsonschema.JsonSchemaValueException as exc:
        message = _print_validation_fail_reason(exc, formats)
        raise SPSDKError(f"Configuration validation failed: {message}") from exc


class ConfigTemplate:
    """Class for generating commented config templates."""

    def __init__(
        self, main_title: str, schemas: List[Dict[str, Any]], override_values: Dict[str, Any] = None
    ):
        """Constructor for Config templates.

        :param main_title: Main title of final template.
        :param schemas: Main description of final template.
        :param override_values: Additional overriding default values.
        """
        self.main_title = main_title
        self.schemas = schemas
        self.override_values = override_values
        self.indent = 0

    @staticmethod
    def _get_title_block(title: str, description: str = None) -> str:
        """Get unified title blob.

        :param title: Simple title of block
        :param description: Description of block
        :return: ASCII art block
        """
        block_len = 100
        delimiter = "-" * block_len
        title_str = f" == {title} == "
        title_str = title_str.center(block_len)
        descr_list = (
            [text.center(block_len) + "\n" for text in textwrap.wrap(description, block_len)]
            if description
            else [""]
        )

        ret = delimiter + "\n" + title_str + "\n"
        for descr in descr_list:
            ret += descr
        ret += delimiter
        return ret

    @staticmethod
    def _get_required(key: str, block: Dict[str, Any]) -> str:
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

    def _create_object_block(
        self,
        block: Dict[str, Dict[str, Any]],
        order_list: List[str] = None,
    ) -> CM:
        """Private function used to create object block with data.

        :param block: Source block with data
        :param order_list: Optional list with right order of records.
        :return: CM base configuration object
        :raises SPSDKError: In case of invalid data pattern.
        """
        assert block.get("type") == "object"
        self.indent += 1
        cfg_m = CM()
        assert "properties" in block.keys()
        key_order = order_list or list(block["properties"].keys())
        for key in key_order:
            assert key in block["properties"].keys()
            val_p: Dict = block["properties"][key]
            value_to_add, comment, title = self._get_schema_value(val_p)

            if self.override_values and key in self.override_values:
                value_to_add = self.override_values[key]

            cfg_m[key] = value_to_add
            p_required = self._get_required(key, block)
            cfg_m.yaml_add_eol_comment(f"[{p_required}]{', ' if comment else ''}{comment}", key=key)
            if title:
                cfg_m.yaml_set_comment_before_after_key(
                    key,
                    self._get_title_block(title),
                    indent=SPSDK_YML_INDENT * (self.indent - 1),
                )
        self.indent -= 1
        return cfg_m

    def _create_array_block(self, block: Dict[str, Dict[str, Any]]) -> CS:
        """Private function used to create array block with data.

        :param block: Source block with data
        :return: CS base configuration object
        :raises SPSDKError: In case of invalid data pattern.
        """
        self.indent += 1
        assert block.get("type") == "array"
        cfg_s = CS()
        assert "items" in block.keys()
        val_i: Dict = block["items"]
        value, comment, title = self._get_schema_value(val_i)
        if isinstance(value, CS):
            self.indent -= 1
            return value
        elif isinstance(value, list):
            cfg_s.extend(value)
        else:
            cfg_s.append(value)
        if comment:
            cfg_s.yaml_add_eol_comment(comment, key=0)
        if title:
            cfg_s.yaml_set_comment_before_after_key(
                0,
                self._get_title_block(title),
                indent=SPSDK_YML_INDENT * (self.indent - 1),
            )
        self.indent -= 1
        return cfg_s

    def _create_one_of_block(self, block: Dict[str, Dict[str, Any]]) -> CS:
        """Private function used to create oneOf block with data.

        :param block: Source block with data
        :return: CS base configuration object
        """
        self.indent += 1
        ret = CS()
        one_of = block["oneOf"]
        assert isinstance(one_of, list)
        option_types = ",".join([str(x.get("type")) for x in one_of])
        title = f"List of possible {len(one_of)} options. Option types[{option_types}]"
        for i, option in enumerate(one_of):
            value, loc_comment, loc_title = self._get_schema_value(option)
            ret.append(value)
            ret.yaml_add_eol_comment(
                f"[Example of possible configuration #{i}] {loc_comment}", key=i
            )
            if loc_title:
                ret.yaml_set_comment_before_after_key(
                    key=i,
                    before=self._get_title_block(loc_title),
                    indent=SPSDK_YML_INDENT * (self.indent - 1),
                )
        ret.yaml_set_comment_before_after_key(
            key=0,
            before=self._get_title_block(title),
            indent=SPSDK_YML_INDENT * (self.indent - 1),
        )
        self.indent -= 1
        return ret

    def _get_schema_value(
        self,
        block: Dict[str, Any],
    ) -> Tuple[Optional[Union[CM, CS, str, int, float, List]], Optional[str], Optional[str]]:
        """Private function used to fill up configuration block with data.

        :param block: Source block with data
        :param order_list: Optional list with right order of records.
        :return: CM/CS base configuration object with comment
        :raises SPSDKError: In case of invalid data pattern.
        """
        schema_type = block.get("type")
        title = None
        ret: Optional[Union[CM, CS, str, int, float, List]] = None
        if "oneOf" in block.keys():
            ret = self._create_one_of_block(block)
        elif schema_type is None:
            raise SPSDKError("Type not available")
        elif schema_type == "object":
            ret = self._create_object_block(block)  # type: ignore
        elif schema_type == "array":
            ret = self._create_array_block(block)  # type: ignore
        else:
            assert "template_value" in block.keys()
            ret = block.get("template_value")

        assert isinstance(ret, (CM, CS, str, int, float, list)) or ret is None

        p_title = block.get("title", "")
        p_descr = block.get("description", "")
        p_enum = block.get("enum", None)
        if "template_title" in block.keys():
            title = block["template_title"]
        if p_enum:
            p_descr = f"{p_descr}{', 'if p_descr else ''}Possible options:{p_enum}"
        comment = f"{p_title}{', ' if p_descr else ''}{p_descr}"
        return ret, comment, title

    @staticmethod
    def _get_schema_block_keys(schema: Dict[str, Dict[str, Any]]) -> List[str]:
        """Creates list of property keys in given schema.

        :param schema: Input schema piece.
        :return: List of all property keys.
        """
        if "properties" not in schema:
            return []
        return list(schema["properties"].keys())

    def export(self) -> CM:
        """Export configuration template into CommentedMap.

        :raises SPSDKError: Error
        :return: Configuration template in CM.
        """
        loc_schemas = copy.deepcopy(self.schemas)
        # 1. Get blocks with their titles and lists of their keys
        block_list: Dict[str, Any] = {}
        for schema in loc_schemas:
            title = schema.get("title", "General Options")
            if title in block_list:
                property_list = block_list[title]["properties"]
                assert isinstance(property_list, list)
                property_list.extend(
                    [
                        x
                        for x in self._get_schema_block_keys(schema)
                        if x not in block_list[title]["properties"]
                    ]
                )
            else:
                block_list[title] = {}
                block_list[title]["properties"] = self._get_schema_block_keys(schema)
                block_list[title]["description"] = schema.get("description", "")

        # 2. Merge all schemas together to get whole single schema
        schemas_merger = SPSDK_Merger(
            [(list, ["set"]), (dict, ["merge"]), (set, ["union"])],
            ["override"],
            ["override"],
        )

        merged: Dict[str, Any] = {}
        for schema in loc_schemas:
            schemas_merger.merge(merged, copy.deepcopy(schema))

        # 3. Create order of individual settings
        order_list: List[str] = []
        for info in block_list.values():
            order_list.extend(info["properties"])

        try:
            self.indent = 0
            # 4. Go through all individual logic blocks
            cfg = self._create_object_block(merged, order_list)
            assert isinstance(cfg, CM)
            # 5. Add main title of configuration
            cfg.yaml_set_start_comment(f"===========  {self.main_title}  ===========\n")
            for title, info in block_list.items():
                description = info["description"]
                assert isinstance(description, str) or description is None
                cfg.yaml_set_comment_before_after_key(
                    info["properties"][0], self._get_title_block(title, description)
                )
            return cfg

        except Exception as exc:
            raise SPSDKError(f"Template generation failed: {str(exc)}") from exc

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
        if not abs_path in ValidationSchemas._instancies:
            try:
                with open(abs_path) as f:
                    schema_cfg = YAML(typ="safe").load(f)
            except (FileNotFoundError, YAMLError, UnicodeDecodeError) as exc:
                raise SPSDKError("Invalid validation scheme configuration file.") from exc
            ValidationSchemas._instancies[abs_path] = schema_cfg

        return ValidationSchemas._instancies[abs_path]
