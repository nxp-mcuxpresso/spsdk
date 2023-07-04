#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright 2021-2023 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Module for schema-based configuration validation."""

import copy
import io
import logging
import os
import textwrap
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import fastjsonschema
from deepmerge import Merger, always_merger
from deepmerge.strategy.dict import DictStrategies
from deepmerge.strategy.list import ListStrategies
from deepmerge.strategy.set import SetStrategies
from ruamel.yaml import YAML, YAMLError
from ruamel.yaml.comments import CommentedMap as CMap
from ruamel.yaml.comments import CommentedSeq as CSeq

from spsdk import SPSDK_YML_INDENT, SPSDKError
from spsdk.utils.misc import find_file, load_configuration, value_to_int, write_file

ENABLE_DEBUG = False

logger = logging.getLogger(__name__)


class SPSDKListStrategies(ListStrategies):
    """Extended List Strategies."""

    # pylint: disable=unused-argument   # because of the base class
    @staticmethod
    def strategy_set(_config, _path, base, nxt):  # type: ignore
        """Use the set of both as a output."""
        try:
            ret = list(set(base + nxt))
            ret.sort()
        except TypeError:
            try:
                ret = base + nxt
            except TypeError:
                logger.warning(
                    "Found unhashable object in List 'set' strategy during merge."
                    " It was used 'override' method instead of 'set'."
                )
                ret = nxt
        return ret


class SPSDKMerger(Merger):
    """Modified Merger to add new list strategy 'set'."""

    PROVIDED_TYPE_STRATEGIES = {
        list: SPSDKListStrategies,
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
    extra_formaters: Optional[Dict[str, Callable[[str], bool]]] = None,
) -> str:
    """Print formated and easy to read reason why the  validation failed.

    :param exc: Original exception.
    :param extra_formaters: Additional custom formatters
    :return: String explaining the reason of fail.
    """

    def process_nested_rule(
        exception: fastjsonschema.JsonSchemaValueException,
        extra_formaters: Optional[Dict[str, Callable[[str], bool]]],
    ) -> str:
        message = ""
        for rule_def_ix, rule_def in enumerate(exception.rule_definition):
            try:
                validator = fastjsonschema.compile(rule_def, formats=extra_formaters)
                validator(exception.value)
            except fastjsonschema.JsonSchemaValueException as _exc:
                message += (
                    f"\nReason of fail for {exception.rule} rule#{rule_def_ix}: "
                    f"\n {_print_validation_fail_reason(_exc , extra_formaters)}\n"
                )
        if all(rule_def.get("required") for rule_def in exception.rule_definition):
            message += f"\nYou need to define {exception.rule} of the following sets:"
            for rule_def in exc.rule_definition:
                message += f" {rule_def['required']}"
        return message

    message = str(exc)
    if exc.rule == "required":
        missing = filter(lambda x: x not in exc.value.keys(), exc.rule_definition)
        message += f"; Missing field(s): {', '.join(missing)}"
    elif exc.rule == "format":
        if exc.rule_definition == "file":
            message += f"; Non-existing file: {exc.value}"
            message += "; The file must exists even if the key is NOT used in configuration."
    elif exc.rule == "anyOf":
        message += process_nested_rule(exc, extra_formaters=extra_formaters)
    elif exc.rule == "oneOf":
        message += process_nested_rule(exc, extra_formaters=extra_formaters)
    return message


def check_config(
    config: Union[str, Dict[str, Any]],
    schemas: List[Dict[str, Any]],
    extra_formaters: Optional[Dict[str, Callable[[str], bool]]] = None,
    search_paths: Optional[List[str]] = None,
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
    validator = None
    formats = always_merger.merge(custom_formatters, extra_formaters or {})
    try:
        if ENABLE_DEBUG:
            validator_code = fastjsonschema.compile_to_code(schema, formats=formats)
            write_file(validator_code, "validator_file.py")
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
            assert validator is not None
            validator(config_to_check)
    except fastjsonschema.JsonSchemaValueException as exc:
        message = _print_validation_fail_reason(exc, formats)
        raise SPSDKError(f"Configuration validation failed: {message}") from exc


class CommentedConfig:
    """Class for generating commented config templates or custom configurations."""

    def __init__(
        self,
        main_title: str,
        schemas: List[Dict[str, Any]],
        values: Optional[Dict[str, Any]] = None,
        note: Optional[str] = None,
        export_template: bool = True,
    ):
        """Constructor for Config templates.

        :param main_title: Main title of final template.
        :param schemas: Main description of final template.
        :param values:
            - for configuration, this is dictionary of values to be saved
            - for schema, this is dictionary of override values (overriding default values)
        :param note: Additional Note after title test.
        :param export_template: True to export schema template; False to export custom configuration
        """
        self.main_title = main_title
        self.schemas = schemas
        self.values = values
        self.indent = 0
        self.note = note
        self.export_template = export_template
        assert export_template or values, "values must be defined for configuration export"

    @staticmethod
    def _get_title_block(title: str, description: Optional[str] = None) -> str:
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
    def get_property_optional_required(key: str, block: Dict[str, Any]) -> str:
        """Function to determine if the config property is required or not.

        :param key: Name of config record
        :param block: Source data block
        :return: Final description.
        """
        schema_kws = ["allOf", "anyOf", "oneOf", "if", "then", "else"]

        def _find_required(d_in: Dict[str, Any]) -> Optional[List[str]]:
            if "required" in d_in:
                return d_in["required"]

            for d_v in d_in.values():
                if isinstance(d_v, dict):
                    ret = _find_required(d_v)
                    if ret:
                        return ret
            return None

        def _find_required_in_schema_kws(schema_node: Union[List, Dict[str, Any]]) -> List[str]:
            """Find all required properties in structure composed of nested properties."""
            all_props: List[str] = []
            if isinstance(schema_node, dict):
                for k, v in schema_node.items():
                    if k == "required":
                        all_props.extend(v)
                    elif k in schema_kws:
                        req_props = _find_required_in_schema_kws(v)
                        all_props.extend(req_props)
            if isinstance(schema_node, list):
                for item in schema_node:
                    req_props = _find_required_in_schema_kws(item)
                    all_props.extend(req_props)
            return list(set(all_props))

        if "required" in block and key in block["required"]:
            return "Required"

        for val in block.values():
            if isinstance(val, dict):
                ret = _find_required(val)
                if ret and key in ret:
                    return "Conditionally required"

        actual_kws = {k: v for k, v in block.items() if k in schema_kws}
        ret = _find_required_in_schema_kws(actual_kws)
        if key in ret:
            return "Conditionally required"

        return "Optional"

    def _create_object_block(
        self,
        block: Dict[str, Dict[str, Any]],
        custom_value: Optional[Union[Dict[str, Any], List[Any]]] = None,
    ) -> Union[CMap, CSeq]:
        """Private function used to create object block with data.

        :param block: Source block with data
        :param custom_value:
            Optional dictionary or List of properties to be exported.
        It is recommended to pass OrderedDict to preserve the key order.
            - key is property ID to be exported
            - value is its value; or None if default value shall be used
        :return: CMap or CSeq base configuration object
        :raises SPSDKError: In case of invalid data pattern.
        """
        assert block.get("type") == "object"
        self.indent += 1

        assert "properties" in block.keys()

        if "oneOf" in block["properties"].keys():
            cfg_s = self._create_one_of_block_array(block["properties"], custom_value)  # type: ignore
            self.indent -= 1
            return cfg_s

        cfg_m = CMap()
        for key in self._get_schema_block_keys(block):
            assert (
                key in block["properties"].keys()
            ), f"Missing key ({key}, in block properties. Block title: {block.get('title', 'Unknown')})"

            # Skip the record in case that custom value key is defined,
            # but it has None value as a mark to not use this record
            value = custom_value.get(key, None) if custom_value else None  # type: ignore
            if not self.export_template and value is None:
                continue

            val_p: Dict = block["properties"][key]
            value_to_add, comment, title = self._get_schema_value(val_p, value)

            cfg_m[key] = value_to_add
            p_required = self.get_property_optional_required(key, block)
            cfg_m.yaml_add_eol_comment(f"[{p_required}]{', ' if comment else ''}{comment}", key=key)
            if title:
                cfg_m.yaml_set_comment_before_after_key(
                    key,
                    self._get_title_block(title),
                    indent=SPSDK_YML_INDENT * (self.indent - 1),
                )
        self.indent -= 1
        return cfg_m

    def _create_array_block(
        self, block: Dict[str, Dict[str, Any]], custom_value: Optional[List[Any]]
    ) -> CSeq:
        """Private function used to create array block with data.

        :param block: Source block with data
        :return: CS base configuration object
        :raises SPSDKError: In case of invalid data pattern.
        """
        assert block.get("type") == "array"
        assert "items" in block.keys()
        self.indent += 1
        val_i: Dict = block["items"]
        if "oneOf" in val_i.keys():
            cfg_s = self._create_one_of_block_array(val_i, custom_value)
        else:
            cfg_s = CSeq()
            if custom_value:
                for cust_val in custom_value:
                    value, _, _ = self._get_schema_value(val_i, cust_val)
                    if isinstance(value, list):
                        cfg_s.extend(value)
                    else:
                        cfg_s.append(value)
            elif self.export_template:
                value, _, _ = self._get_schema_value(val_i, None)
                # the template_value can be the actual list(not only one element)
                if isinstance(value, list):
                    cfg_s.extend(value)
                else:
                    cfg_s.append(value)
        self.indent -= 1
        return cfg_s

    @staticmethod
    def _find_matching_oneof_option(one_of: List[Dict[str, Any]], cust_val: Any) -> Dict[str, Any]:
        """Find matching "oneOf" schema for given custom value.

        :param one_of: list of oneOf schemas
        :param cust_val: custom value; currently must be dictionary
        :raise SPSDKError: if not found
        """
        assert (
            isinstance(cust_val, dict) and cust_val
        ), "currently the implementation supports only dictionary as custom value"
        for option in one_of:
            assert option.get("type") == "object"
            properties = option.get("properties")
            assert properties, "non-empty properties must be defined"
            if all([key in properties for key in cust_val.keys()]):
                return option
        raise SPSDKError(f"for custom value {str(cust_val)}, no corresponding `oneOf` schema found")

    def _create_one_of_block_array(
        self, block: Dict[str, Dict[str, Any]], custom_value: Optional[List[Any]]
    ) -> CSeq:
        """Private function used to create oneOf block with data, and return as an array that contains all values.

        :param block: Source block with data
        :param custom_value: custom value to fill the array
        :return: CS base configuration object
        """
        self.indent += 1
        ret = CSeq()
        one_of = block["oneOf"]
        assert isinstance(one_of, list)
        if custom_value is not None:
            for i, cust_val in enumerate(custom_value):
                option = self._find_matching_oneof_option(one_of, cust_val)
                value, loc_comment, loc_title = self._get_schema_value(option, cust_val)
                ret.append(value)
                if loc_comment:
                    ret.yaml_add_eol_comment(f"{loc_comment}", key=i)
                if loc_title:
                    ret.yaml_set_comment_before_after_key(
                        key=i,
                        before=self._get_title_block(loc_title),
                        indent=SPSDK_YML_INDENT * (self.indent - 1),
                    )
        elif self.export_template:
            option_types = ",".join([str(x.get("type")) for x in one_of])
            title = f"List of possible {len(one_of)} options. Option types[{option_types}]"
            for i, option in enumerate(one_of):
                value, loc_comment, loc_title = self._get_schema_value(option, None)
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
        self, block: Dict[str, Any], custom_value: Any
    ) -> Tuple[Optional[Union[CMap, CSeq, str, int, float, List]], Optional[str], Optional[str]]:
        """Private function used to fill up configuration block with data.

        :param block: Source block with data
        :param custom_value: value to be saved instead of default value
        :return: CM/CS base configuration object with comment
        :raises SPSDKError: In case of invalid data pattern.
        """
        title = None
        if "oneOf" in block.keys():
            ret = self._create_one_of_block_array(block, custom_value)
        else:
            schema_type = block.get("type")
            if not schema_type:
                raise SPSDKError(f"Type not available in block: {block}")
            assert schema_type, f"Type not available in block: {block}"

            if schema_type == "object":
                assert (custom_value is None) or isinstance(custom_value, dict)
                ret = self._create_object_block(block, custom_value)  # type: ignore
            elif schema_type == "array":
                assert (custom_value is None) or isinstance(custom_value, list)
                ret = self._create_array_block(block, custom_value)  # type: ignore
            else:
                assert "template_value" in block.keys()
                ret = custom_value if (custom_value is not None) else block.get("template_value")

        assert isinstance(ret, (CMap, CSeq, str, int, float, list)) or (ret is None)

        p_title = block.get("title", "")
        p_descr = block.get("description", "")
        p_enum = block.get("enum", None)
        if "template_title" in block.keys():
            title = block["template_title"]
        if p_enum:
            if p_descr.endswith("."):
                p_descr = p_descr[:-1]
            p_descr = f"{p_descr}{'; ' if p_descr else ''}Possible options:{p_enum}"
        if p_title.endswith("."):
            p_title = p_title[:-1]
        if p_descr.lower().startswith(p_title.lower()):
            comment = p_descr
        else:
            comment = f"{p_title}{'; ' if p_descr else ''}{p_descr}"
        return ret, comment, title

    @staticmethod
    def _get_schema_block_keys(schema: Dict[str, Dict[str, Any]]) -> List[str]:
        """Creates list of property keys in given schema.

        :param schema: Input schema piece.
        :return: List of all property keys.
        """
        if "properties" not in schema:
            return []
        return [
            key
            for key in schema["properties"]
            if "skip_in_template" not in schema["properties"][key]
            or schema["properties"][key]["skip_in_template"] is False
        ]

    def export(self) -> CMap:
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
        schemas_merger = SPSDKMerger(
            [(list, ["set"]), (dict, ["merge"]), (set, ["union"])],
            ["override"],
            ["override"],
        )

        merged: Dict[str, Any] = {}
        for schema in loc_schemas:
            schemas_merger.merge(merged, copy.deepcopy(schema))

        # 3. Create order of individual settings

        order_dict: Dict[str, Any] = OrderedDict()
        properties_for_template = self._get_schema_block_keys(merged)
        for block in block_list.values():
            block_properties: list = block["properties"]
            # block_properties.sort()
            for block_property in block_properties:
                if block_property in properties_for_template:
                    order_dict[block_property] = merged["properties"][block_property]
        merged["properties"] = order_dict

        try:
            self.indent = 0
            # 4. Go through all individual logic blocks
            cfg = self._create_object_block(merged, self.values)
            assert isinstance(cfg, CMap)
            # 5. Add main title of configuration
            title = f"===========  {self.main_title}  ===========\n"
            if self.note:
                title += f"\n {'-'*50} Note {'-'*50}\n{self.note}\n\n"
            cfg.yaml_set_start_comment(title)
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
        return self.convert_cm_to_yaml(self.export())

    @staticmethod
    def convert_cm_to_yaml(config: CMap) -> str:
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
        if abs_path not in ValidationSchemas._instancies:
            try:
                schema_cfg = load_configuration(abs_path)
            except (FileNotFoundError, YAMLError, UnicodeDecodeError) as exc:
                raise SPSDKError("Invalid validation scheme configuration file.") from exc
            ValidationSchemas._instancies[abs_path] = schema_cfg

        return ValidationSchemas._instancies[abs_path]


class ConfigTemplate(CommentedConfig):
    """Deprecated, kept for backward compatibility only."""
