#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK schema-based configuration validation utilities.

This module provides comprehensive functionality for validating configuration
data against JSON schemas, merging configurations with different strategies,
and handling commented YAML configurations within the SPSDK framework.
"""

import copy
import io
import logging
import os
from collections import OrderedDict
from typing import Any, Callable, Optional, Union

import fastjsonschema
from deepmerge import Merger, always_merger
from deepmerge.strategy.dict import DictStrategies
from deepmerge.strategy.list import ListStrategies
from deepmerge.strategy.set import SetStrategies
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap as CMap
from ruamel.yaml.comments import CommentedSeq as CSeq

from spsdk import SPSDK_DEBUG, SPSDK_SCHEMA_STRICT, SPSDK_YML_INDENT
from spsdk.exceptions import SPSDKError
from spsdk.utils.misc import find_dir, find_file, value_to_int, wrap_text, write_file
from spsdk.utils.spsdk_enum import SpsdkEnum

ENABLE_DEBUG = SPSDK_DEBUG

logger = logging.getLogger(__name__)


def cmap_update(cmap: CMap, updater: CMap) -> None:
    """Update CMap including comments.

    This method updates the original CMap with data from the updater CMap,
    ensuring that both the main data and comment annotations are properly merged.

    :param cmap: Original CMap to be updated.
    :param updater: CMap updater containing new data and comments to merge.
    """
    cmap.update(updater)
    cmap.ca.items.update(updater.ca.items)


class PropertyRequired(SpsdkEnum):
    """Property requirement level enumeration for schema validation.

    This enumeration defines the different requirement levels that can be applied
    to properties in SPSDK schema validation, indicating whether a property must
    be present, conditionally required, or optional.
    """

    REQUIRED = (0, "REQUIRED", "Required")
    CONDITIONALLY_REQUIRED = (1, "CONDITIONALLY_REQUIRED", "Conditionally required")
    OPTIONAL = (2, "OPTIONAL", "Optional")


class SPSDKListStrategies(ListStrategies):
    """SPSDK List Strategies for configuration merging.

    This class extends the base ListStrategies to provide custom list merging
    strategies for SPSDK configuration processing. It implements specialized
    handling for combining lists during configuration merges, including set-based
    deduplication with fallback mechanisms for unhashable objects.
    """

    # pylint: disable=unused-argument   # because of the base class
    @staticmethod
    def strategy_set(_config: Merger, _path: list, base: list, nxt: list):  # type: ignore
        """Merge two lists using set strategy to create a unique sorted output.

        This strategy combines two lists by creating a set union to remove duplicates,
        then sorts the result. Falls back to concatenation if items are unhashable,
        or override strategy if concatenation fails.

        :param base: Base list to merge from.
        :param nxt: Next list to merge with base.
        :return: Merged list with unique elements, sorted if possible.
        """
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
    """SPSDK Configuration Merger with enhanced list strategies.

    This class extends the base Merger functionality to provide additional merge strategies
    specifically for SPSDK configuration processing, including a new 'set' strategy for
    list merging operations.

    :cvar PROVIDED_TYPE_STRATEGIES: Mapping of data types to their available merge strategies.
    """

    PROVIDED_TYPE_STRATEGIES = {
        list: SPSDKListStrategies,
        dict: DictStrategies,
        set: SetStrategies,
    }

    def __init__(  # pylint: disable=dangerous-default-value
        self,
        type_strategies: list = [(list, ["set"]), (dict, ["merge"]), (set, ["union"])],
        fallback_strategies: list = ["override"],
        type_conflict_strategies: list = ["override"],
    ):
        """Initialize SPSDK Merger with configurable merge strategies.

        The merger provides flexible data merging capabilities with customizable strategies
        for different data types and conflict resolution.

        :param type_strategies: List of tuples defining merge strategies for specific types,
            each tuple contains (type, [strategy_list]).
        :param fallback_strategies: List of fallback strategies to use when no type-specific
            strategy is defined.
        :param type_conflict_strategies: List of strategies for resolving type conflicts
            during merge operations.
        """
        super().__init__(type_strategies, fallback_strategies, type_conflict_strategies)


def _is_number(param: Any) -> bool:
    """Check if the input parameter represents a number.

    The method uses value_to_int conversion to determine if the input can be
    interpreted as a numeric value.

    :param param: Input value to analyze for numeric representation.
    :return: True if input represents a number, False otherwise.
    """
    try:
        value_to_int(param)
        return True
    except SPSDKError:
        return False


def _is_hex_number(param: Any) -> bool:
    """Check if the input represents a hexadecimal number.

    The method validates whether the input parameter can be interpreted as a valid hexadecimal
    number. It handles both string inputs (with or without '0x' prefix) and other types that
    can be converted to hexadecimal format.

    :param param: Input value to analyze for hexadecimal format compatibility.
    :return: True if input represents a valid hexadecimal number, False otherwise.
    """
    try:
        if isinstance(param, str):
            if param.startswith("0x"):
                param = param[2:]
        bytes.fromhex(param)
        return True
    except (TypeError, ValueError):
        return False


def _is_config_string(param: Any) -> bool:
    """Checks whether the input represents a valid configuration string.

    :param param: Input to analyze
    :return: True if input is a valid configuration string
    """
    if not isinstance(param, str):
        return False
    return param.startswith("type=")


def _print_validation_fail_reason(
    exc: fastjsonschema.JsonSchemaValueException,
    extra_formatters: Optional[dict[str, Callable[[str], bool]]] = None,
) -> str:
    """Format JSON schema validation failure into human-readable error message.

    The method processes different types of JSON schema validation errors and provides
    detailed explanations for common failure scenarios including missing required fields,
    format violations, and complex rule failures (oneOf, anyOf).

    :param exc: The JSON schema validation exception to process.
    :param extra_formatters: Optional dictionary of custom format validators for schema validation.
    :return: Formatted error message explaining the validation failure reason.
    """

    def process_one_of_rule(
        exception: fastjsonschema.JsonSchemaValueException,
        extra_formatters: Optional[dict[str, Callable[[str], bool]]],
    ) -> str:
        """Process oneOf JSON schema validation rule and generate error message.

        This method analyzes a oneOf validation exception by testing each rule definition
        against the exception value and collecting failure reasons. It helps provide
        detailed error messages for complex schema validation failures.

        :param exception: The JSON schema validation exception containing oneOf rule data.
        :param extra_formatters: Optional dictionary of custom format validators.
        :return: Formatted error message describing why oneOf validation failed.
        """
        message = ""
        for rule_def in exception.rule_definition:
            try:
                # Validate only the rules that apply to exception.value
                required = rule_def.get("required")
                if required and required[0] in exception.value:
                    validator = fastjsonschema.compile(rule_def, formats=extra_formatters)
                    validator(exception.value)
            except fastjsonschema.JsonSchemaValueException as _exc:
                message += (
                    f"\nReason of fail for oneOf rule '{required[0]}': "
                    f"\n {_print_validation_fail_reason(_exc , extra_formatters)}\n"
                )
        if not message and all(rule_def.get("required") for rule_def in exception.rule_definition):
            message += f"\nYou need to define {exception.rule} of the following sets:"
            for rule_def in exc.rule_definition:
                message += f" {rule_def['required']}"
        return message

    def process_nested_rule(
        exception: fastjsonschema.JsonSchemaValueException,
        extra_formatters: Optional[dict[str, Callable[[str], bool]]],
    ) -> str:
        """Process nested JSON schema validation rule and generate detailed error message.

        Analyzes each rule definition within a nested validation exception to determine
        which specific rules passed or failed, providing comprehensive feedback for
        debugging schema validation issues.

        :param exception: The JSON schema validation exception containing nested rule definitions.
        :param extra_formatters: Optional dictionary of custom format validators for schema
            validation.
        :return: Formatted string containing detailed analysis of rule validation results
            and failure reasons.
        """
        message = ""
        for rule_def_ix, rule_def in enumerate(exception.rule_definition):
            try:
                validator = fastjsonschema.compile(rule_def, formats=extra_formatters)
                validator(exception.value)
                message += f"\nRule#{rule_def_ix} passed.\n"
            except fastjsonschema.JsonSchemaValueException as _exc:
                message += (
                    f"\nReason of fail for {exception.rule} rule#{rule_def_ix}: "
                    f"\n {_print_validation_fail_reason(_exc , extra_formatters)}\n"
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
        elif exc.rule_definition == "file-or-hex-value":
            message += (
                f"; Value '{exc.value}' is neither a valid hex value nor an existing file path"
                "; The value must be either a valid hex string (e.g. 0x1234ABCD) or a path to an existing file."
            )
        elif exc.rule_definition == "file-or-hex-value-or-config-string":
            message += (
                f"; Value '{exc.value}' is neither a valid hex value, an existing file path, "
                "nor a valid configuration string."
            )

    elif exc.rule == "anyOf":
        message += process_nested_rule(exc, extra_formatters=extra_formatters)
    elif exc.rule == "oneOf":
        message += process_one_of_rule(exc, extra_formatters=extra_formatters)
    return message


def check_unknown_properties(config_dict: dict, schema_dict: dict, path: str = "") -> None:
    """Recursively check for unknown properties in configuration against schema.

    This method validates that all properties in the configuration dictionary
    are defined in the corresponding schema. It handles nested objects, arrays,
    and pattern properties. When unknown properties are found, it either raises
    an exception (in strict mode) or logs a warning.

    :param config_dict: Configuration dictionary to validate
    :param schema_dict: JSON schema dictionary defining allowed properties
    :param path: Current path in the configuration for error reporting
    :raises SPSDKError: When unknown property is found and strict mode is enabled
    """

    def process_nested_schemas(schemas: dict) -> dict:
        """Process and merge nested schema structures.

        This function handles structures that contain nested schemas under keywords like 'oneOf',
        'allOf', or 'anyOf'. It merges all nested schemas into a single schema that can be used
        for property checking.

        :param schemas: Original schema dictionary that may contain nested schemas.
        :return: Merged schema if nested schemas were found, otherwise the original schema.
        """
        nested_ch_keywords = ["oneOf", "allOf", "anyOf"]
        if not any(key in schemas for key in nested_ch_keywords):
            return schemas
        merger = SPSDKMerger()
        merged_sch: dict[str, Any] = {}
        for keyword in nested_ch_keywords:
            if keyword in schemas:
                for schema in schemas[keyword]:
                    merger.merge(merged_sch, copy.deepcopy(schema))
        # Return the original schema if no nested schemas were merged
        return merged_sch

    schema_dict = process_nested_schemas(schema_dict)
    if "properties" not in schema_dict and "patternProperties" not in schema_dict:
        return

    schema_props = set(schema_dict.get("properties", {}).keys())
    pattern_props = schema_dict.get("patternProperties", {})

    for key, value in config_dict.items():
        current_path = f"{path}.{key}" if path else key

        # Skip if it's a known property
        if key in schema_props:
            # If it's an object, recurse into it
            if isinstance(value, dict) and isinstance(schema_dict["properties"].get(key, {}), dict):
                check_unknown_properties(value, schema_dict["properties"][key], current_path)
            # If it's an array with object items, check each item
            elif isinstance(value, list) and "items" in schema_dict["properties"].get(key, {}):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        check_unknown_properties(
                            item, schema_dict["properties"][key]["items"], f"{current_path}[{i}]"
                        )
            continue

        # Check if key matches any pattern in patternProperties
        matched_pattern = False
        for pattern in pattern_props:
            import re

            if re.match(pattern, key):
                matched_pattern = True
                break

        if not matched_pattern:
            # This property is unknown to the schema
            error_msg = f"Unknown property found in configuration: '{current_path}'"
            if SPSDK_SCHEMA_STRICT:
                raise SPSDKError(error_msg)
            logger.warning(error_msg)


def check_config(
    config: dict[str, Any],
    schemas: list[dict[str, Any]],
    extra_formatters: Optional[dict[str, Callable[[str], bool]]] = None,
    search_paths: Optional[list[str]] = None,
    check_unknown_props: bool = False,
) -> None:
    """Check the configuration by provided list of validation schemas.

    The method validates configuration data against multiple JSON schemas that are merged together.
    It supports custom formatters for file/directory validation and can optionally check for
    unknown properties in the configuration.

    :param config: Configuration dictionary to validate.
    :param schemas: List of JSON schema dictionaries for validation.
    :param extra_formatters: Additional custom format validators for schema validation.
    :param search_paths: List of directory paths to search for files during validation.
    :param check_unknown_props: Whether to check and warn about unknown properties in config.
    :raises SPSDKError: Invalid validation schema or configuration validation failed.
    """
    custom_formatters: dict[str, Callable[[str], bool]] = {
        "dir": lambda x: bool(find_dir(x, search_paths=search_paths, raise_exc=False)),
        "dir_name": lambda x: os.path.basename(x.replace("\\", "/")) not in ("", None),
        "file": lambda x: bool(find_file(x, search_paths=search_paths, raise_exc=False)),
        "file_name": lambda x: os.path.basename(x.replace("\\", "/")) not in ("", None),
        "optional_file": lambda x: not x
        or bool(find_file(x, search_paths=search_paths, raise_exc=False)),
        "number": _is_number,
        "hex_value": _is_hex_number,
        "file-or-hex-value": lambda x: (
            _is_hex_number(x) or bool(find_file(x, search_paths=search_paths, raise_exc=False))
        ),
        "file-or-hex-value-or-config-string": lambda x: (
            _is_hex_number(x)
            or _is_config_string(x)
            or bool(find_file(x, search_paths=search_paths, raise_exc=False))
        ),
    }

    config_to_check = copy.deepcopy(config)

    schema: dict[str, Any] = {}
    for sch in schemas:
        always_merger.merge(schema, copy.deepcopy(sch))
    validator = None
    formats = always_merger.merge(custom_formatters, extra_formatters or {})
    # Check for unknown properties before validation
    if check_unknown_props and "properties" in schema:
        check_unknown_properties(config_to_check, schema)

    try:
        if ENABLE_DEBUG:
            validator_code = fastjsonschema.compile_to_code(schema, formats=formats)
            write_file(validator_code, "validator_file.py")
            import json

            for i, part_schema in enumerate(schemas):
                write_file(json.dumps(part_schema, indent=2), f"part_schema_{i}.json")
            write_file(json.dumps(config_to_check, indent=2), "config.json")
            write_file(json.dumps(schema, indent=2), "merged_schema.json")
        else:
            validator = fastjsonschema.compile(schema, formats=formats)
    except (TypeError, fastjsonschema.JsonSchemaDefinitionException) as exc:
        raise SPSDKError(f"Invalid validation schema to check config: {str(exc)}") from exc
    try:
        if ENABLE_DEBUG:
            # pylint: disable=import-error,import-outside-toplevel
            import sys

            sys.path.insert(0, os.path.abspath(os.curdir))
            import validator_file

            validator_file.validate(config_to_check, formats)
        else:
            if validator is None:
                raise SPSDKError("Validator is not defined")
            validator(config_to_check)
    except fastjsonschema.JsonSchemaValueException as exc:
        message = _print_validation_fail_reason(exc, formats)
        raise SPSDKError(f"Configuration validation failed: {message}") from exc


class CommentedConfig:
    """SPSDK Configuration Template Generator.

    This class generates commented YAML configuration templates and custom configurations
    with proper formatting, indentation, and documentation comments for SPSDK operations.

    :cvar MAX_LINE_LENGTH: Maximum line length for generated comments and formatting.
    """

    MAX_LINE_LENGTH = 120 - 2  # Minus '# '

    def __init__(
        self,
        main_title: str,
        schemas: list[dict[str, Any]],
        note: Optional[str] = None,
    ):
        """Initialize configuration template generator.

        Creates a new instance for generating configuration templates from JSON schemas.
        The generator processes multiple schemas to create comprehensive configuration
        documentation with proper formatting and structure.

        :param main_title: Main title of the generated configuration template.
        :param schemas: List of JSON schema dictionaries to process for template generation.
        :param note: Optional additional note to display after the title section.
        """
        self.main_title = main_title
        self.schemas = schemas
        self.indent = 0
        self.note = note
        self.creating_configuration = False

    @property
    def max_line(self) -> int:
        """Get maximum line length adjusted for current indentation level.

        Calculates the maximum allowed line length by subtracting the current
        indentation space from the base maximum line length constant.

        :return: Maximum line length accounting for current indent level.
        """
        return self.MAX_LINE_LENGTH - max(SPSDK_YML_INDENT * (self.indent - 1), 0)

    def _get_title_block(self, title: str, description: Optional[str] = None) -> str:
        """Get unified title block for display formatting.

        Creates an ASCII art formatted block with centered title and optional description,
        surrounded by delimiter lines for visual separation.

        :param title: Simple title of block to be displayed.
        :param description: Optional description text to include below title.
        :return: Formatted ASCII art block as string.
        """
        delimiter = "=" * self.max_line
        title_str = f" == {title} == "
        title_str = title_str.center(self.max_line)

        ret = delimiter + "\n" + title_str + "\n"
        if description:
            wrapped_description = wrap_text(description, self.max_line)
            lines = wrapped_description.splitlines()
            ret += "\n".join([line.center(self.max_line) for line in lines])
            ret += "\n"
        ret += delimiter
        return ret

    @staticmethod
    def get_property_optional_required(key: str, block: dict[str, Any]) -> PropertyRequired:
        """Determine if a configuration property is required, optional, or conditionally required.

        The method analyzes JSON schema blocks to classify property requirements by checking
        direct required arrays, nested conditional structures, and schema keywords like
        allOf, anyOf, oneOf, if/then/else constructs.

        :param key: Name of the configuration property to check.
        :param block: JSON schema block containing property definitions and requirements.
        :return: PropertyRequired enum indicating if property is REQUIRED, OPTIONAL, or
            CONDITIONALLY_REQUIRED.
        """
        schema_kws = ["allOf", "anyOf", "oneOf", "if", "then", "else"]

        def _find_required(d_in: dict[str, Any]) -> Optional[list[str]]:
            """Find required fields in a dictionary structure.

            Recursively searches through a dictionary to locate the first occurrence of a 'required' key
            and returns its associated list of required field names.

            :param d_in: Dictionary to search for required fields
            :return: List of required field names if found, None otherwise
            """
            if "required" in d_in:
                return d_in["required"]

            for d_v in d_in.values():
                if isinstance(d_v, dict):
                    ret = _find_required(d_v)
                    if ret:
                        return ret
            return None

        def _find_required_in_schema_kws(schema_node: Union[list, dict[str, Any]]) -> list[str]:
            """Find all required properties in structure composed of nested properties.

            Recursively traverses a schema structure (dictionary or list) to extract all property names
            that are marked as required in JSON schema format.

            :param schema_node: Schema structure to search for required properties (dict or list).
            :return: List of unique required property names found in the schema structure.
            """
            all_props: list[str] = []
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
            return PropertyRequired.REQUIRED

        for val in block.values():
            if isinstance(val, dict):
                ret = _find_required(val)
                if ret and key in ret:
                    return PropertyRequired.CONDITIONALLY_REQUIRED

        actual_kws = {k: v for k, v in block.items() if k in schema_kws}
        ret = _find_required_in_schema_kws(actual_kws)
        if key in ret:
            return PropertyRequired.CONDITIONALLY_REQUIRED

        return PropertyRequired.OPTIONAL

    def _create_object_block(
        self,
        block: dict[str, dict[str, Any]],
        custom_value: Optional[Union[dict[str, Any], list[Any]]] = None,
    ) -> CMap:
        """Create object block with data from schema definition.

        This private method processes a schema block of type 'object' and creates a CMap
        configuration object with the specified properties. It handles custom values,
        validates required properties, and adds comments based on schema definitions.

        :param block: Source schema block containing object definition with properties.
        :param custom_value: Optional dictionary or list of custom property values to override
            defaults. Keys represent property IDs, values are the custom values or None to
            skip the property. OrderedDict recommended to preserve key order.
        :return: CMap configuration object containing the processed properties.
        :raises SPSDKError: If block type is not 'object', properties are missing, value
            creation fails, or required property definitions are invalid.
        """
        if block.get("type") != "object":
            raise SPSDKError(f"block type is not 'object' but {block.get('type')}")

        self.indent += 1

        if "properties" not in block:
            raise SPSDKError("Block doesn't contain properties")

        cfg_m = CMap()
        for key in self._get_schema_block_keys(block):
            # Skip the record in case that custom value key is defined,
            # but it has None value as a mark to not use this record
            value = custom_value.get(key, None) if custom_value else None  # type: ignore
            if custom_value and value is None:
                continue

            val_p: dict = block["properties"][key]
            value_to_add = self._get_schema_value(val_p, value)
            if value_to_add is None:
                raise SPSDKError(f"Cannot create the value for {key}")

            cfg_m[key] = value_to_add
            required = self.get_property_optional_required(key, block).description
            if not required:
                raise SPSDKError(f"Required property is not defined for {key}")
            if not val_p.get("no_yaml_comments", False):
                self._add_comment(
                    cfg_m,
                    val_p,
                    key,
                    value_to_add,
                    required,
                )

        self.indent -= 1
        return cfg_m

    def _create_array_block(
        self, block: dict[str, dict[str, Any]], custom_value: Optional[list[Any]]
    ) -> CSeq:
        """Create array block configuration from schema definition.

        This method processes an array-type schema block and generates a corresponding
        CSeq configuration object with the appropriate data values.

        :param block: Schema block dictionary containing array definition with 'type' and 'items' keys.
        :param custom_value: Optional list of custom values to use instead of schema defaults.
        :raises SPSDKError: If block type is not 'array' or 'items' key is missing.
        :return: CSeq configuration object containing the array elements.
        """
        if block.get("type") != "array":
            raise SPSDKError(f"block type is not 'array' but {block.get('type')}")
        if "items" not in block:
            raise SPSDKError("Block doesn't contain items")
        self.indent += 1
        val_i: dict = block["items"]

        cfg_s = CSeq()
        if custom_value is not None:
            for cust_val in custom_value:
                value = self._get_schema_value(val_i, cust_val)
                if isinstance(value, (CSeq, list)):
                    cfg_s.extend(value)
                else:
                    cfg_s.append(value)
        else:
            value = self._get_schema_value(val_i, None)
            # the template_value can be the actual list(not only one element)
            if isinstance(value, (CSeq, list)):
                cfg_s.extend(value)
            else:
                cfg_s.append(value)
        self.indent -= 1
        return cfg_s

    @staticmethod
    def _check_matching_oneof_option(one_of: dict[str, Any], cust_val: Any) -> bool:
        """Check if custom value matches oneOf schema option.

        The method validates whether a given custom value conforms to a specific oneOf schema
        option by checking type compatibility and structural requirements.

        :param one_of: Dictionary containing oneOf schema definition with type and properties.
        :param cust_val: Custom value to validate against the schema option.
        :raises SPSDKError: If properties are not defined for object type validation.
        :return: True if custom value matches the schema option, False otherwise.
        """

        def check_type(option: dict, t: str) -> bool:
            """Check if option type matches the specified type.

            Validates whether the given option's type field matches the target type string.
            Handles both single type strings and lists of multiple allowed types.

            :param option: Dictionary containing option configuration with 'type' field.
            :param t: Target type string to check against.
            :return: True if the option type matches the target type, False otherwise.
            """
            option_type = option.get("type")
            if isinstance(option_type, list):
                return t in option_type
            return t == option_type

        if cust_val:
            if isinstance(cust_val, dict) and check_type(one_of, "object"):
                properties = one_of.get("properties")
                if not properties:
                    raise SPSDKError("Properties must be defined")
                if all([key in properties for key in cust_val.keys()]):
                    return True

            if isinstance(cust_val, str) and check_type(one_of, "string"):
                return True

            if isinstance(cust_val, int) and check_type(one_of, "number"):
                return True

        return False

    def _handle_one_of_block(
        self,
        block: dict[str, Any],
        custom_value: Optional[Union[dict[str, Any], list[Any]]] = None,
    ) -> CMap:
        """Handle oneOf schema block and generate configuration map.

        Processes a oneOf schema block to create a configuration map with all possible options.
        When custom_value is provided, finds and returns the matching option. Otherwise,
        generates a template with all available options as examples.

        :param block: Source oneOf schema block containing multiple option definitions.
        :param custom_value: Optional custom configuration data to match against schema options.
        :raises SPSDKError: When custom_value doesn't match any available oneOf option.
        :return: Configuration map with schema values or template examples.
        """

        def get_help_name(schema: dict) -> str:
            """Get help name from JSON schema.

            Extracts a human-readable name from a JSON schema object. For object schemas with a single
            property, returns that property name. For object schemas with multiple properties, returns
            the list of property names. For other schema types, returns the title or type.

            :param schema: JSON schema dictionary to extract name from.
            :return: Help name as string representation.
            """
            if schema.get("type") == "object":
                options = list(schema["properties"].keys())
                if len(options) == 1:
                    return options[0]
                return str(options)
            return str(schema.get("title", schema.get("type", "Unknown")))

        ret = CMap()
        one_of = block
        assert isinstance(one_of, list)
        if custom_value is not None:
            for i, one_option in enumerate(one_of):
                if not self._check_matching_oneof_option(one_option, custom_value):
                    continue
                return self._get_schema_value(one_option, custom_value)
            raise SPSDKError(
                f"Any allowed option matching the configuration data for {custom_value}"
            )

        # Check the restriction into templates in oneOf block
        one_of_mod = []
        for x in one_of:
            skip = x.get("skip_in_template", False)
            if not skip:
                one_of_mod.append(x)

        # In case that only one oneOf option left just return simple value
        if len(one_of_mod) == 1:
            return self._get_schema_value(one_of_mod[0], custom_value)

        option_types = ", ".join([x.get("template_title", get_help_name(x)) for x in one_of_mod])
        title = f"List of possible {len(one_of_mod)} options."
        for i, option in enumerate(one_of_mod):
            if option.get("type") != "object":
                continue
            value = self._get_schema_value(option, None)
            assert isinstance(value, CMap)
            cmap_update(ret, value)

            key = list(value.keys())[0]
            comment = ""
            if i == 0:
                comment = self._get_title_block(title, f"Options [{option_types}]") + "\n"

            comment += "\n " + (
                f" [Example of possible configuration: #{i} "
                + f"{option.get('template_title', '')}, erase if not used] "
            ).center(self.max_line, "=")
            description = option.get("description")
            if description:
                comment += "\n" + description
            self._update_before_comment(cfg=ret, key=key, comment=comment)
        return ret

    def _get_schema_value(
        self, block: dict[str, Any], custom_value: Any
    ) -> Union[CMap, CSeq, str, int, float, list]:
        """Get schema value from configuration block with optional custom data.

        Processes a configuration block according to its schema type (object, array, or oneOf)
        and fills it with either custom provided values or template default values.

        :param block: Source configuration block containing schema definition and data.
        :param custom_value: Custom value to use instead of template default value.
        :return: Configuration object with comments (CMap/CSeq) or primitive value.
        :raises SPSDKError: In case of invalid data pattern or missing required values.
        """

        def get_custom_or_template() -> Any:
            """Get custom value or template value from block configuration.

            Returns the custom value if it's not None, otherwise returns the template_value
            from the block dictionary. Raises an error if neither is available.

            :raises SPSDKError: When neither custom_value nor template_value is defined in block.
            :return: The custom value if available, otherwise the template value from block.
            """
            if not (custom_value or "template_value" in block.keys()):
                raise SPSDKError("Custom value or template_value must be defined")
            return (
                custom_value
                if (custom_value is not None)
                else block.get("template_value", "Unknown")
            )

        ret: Optional[Union[CMap, CSeq, str, int, float]] = None
        if "oneOf" in block and "properties" not in block:
            ret = self._handle_one_of_block(block["oneOf"], custom_value)
            if not ret:
                ret = get_custom_or_template()
        else:
            schema_type = block.get("type")
            if not schema_type:
                raise SPSDKError(f"Type not available in block: {block}")

            if schema_type == "object":
                assert isinstance(custom_value, (dict, type(None)))
                ret = self._create_object_block(block, custom_value)
            elif schema_type == "array":
                assert isinstance(custom_value, (list, type(None)))
                ret = self._create_array_block(block, custom_value)
            else:
                ret = get_custom_or_template()

        assert isinstance(
            ret, (CMap, CSeq, str, int, float, list)
        ), f"{ret} is wrong object instance"

        return ret

    def _add_comment(
        self,
        cfg: Union[CMap, CSeq],
        schema: dict[str, Any],
        key: Union[str, int],
        value: Optional[Union[CMap, CSeq, str, int, float, list]],
        required: str,
    ) -> None:
        """Add comment block to configuration based on JSON schema.

        Creates formatted comment blocks with title, description, and possible values
        for configuration keys. Handles both single-line and multi-line comments with
        proper indentation and wrapping.

        :param cfg: Target configuration where the comment should be stored
        :param schema: Object configuration JSON SCHEMA
        :param key: Config key
        :param value: Value of config key
        :param required: Required text description
        """
        value_len = len(str(key) + ": ")
        if value and isinstance(value, (str, int)):
            value_len += len(str(value))
        template_title = schema.get("template_title")
        title = schema.get("title", "")
        descr = schema.get("description", "")
        enum_list = schema.get("enum_template", schema.get("enum", []))
        enum = ""

        if len(enum_list):
            enum = "Possible options: <" + ", ".join([str(x) for x in enum_list]) + ">"
        if title:
            # one_line_comment = (
            #     f"[{required}] {title}{'; ' if descr else ''}{descr}{';'+enum if enum else ''}"
            # )
            # TODO This feature will be disabled since the issue
            # https://sourceforge.net/p/ruamel-yaml/tickets/475/ will be solved
            # if True:  # len(one_line_comment) > self.max_line - value_len:
            # Too long comment split it into comment block
            comment = f"===== {title} [{required}] =====".center(self.max_line, "-")
            if descr:
                comment += wrap_text("\nDescription: " + descr, max_line=self.max_line)
            if enum:
                comment += wrap_text("\n" + enum, max_line=self.max_line)
            cfg.yaml_set_comment_before_after_key(
                key, comment, indent=SPSDK_YML_INDENT * (self.indent - 1)
            )
            # else:
            #     cfg.yaml_add_eol_comment(
            #         one_line_comment,
            #         key=key,
            #         column=SPSDK_YML_INDENT * (self.indent - 1),
            #     )

        if template_title:
            self._update_before_comment(cfg, key, "\n" + self._get_title_block(template_title))

    def _get_schema_block_keys(self, schema: dict[str, dict[str, Any]]) -> list[str]:
        """Get property keys from schema based on template configuration.

        Filters out properties marked with 'skip_in_template' unless creating a configuration.
        Returns all property keys when no 'properties' section exists in schema.

        :param schema: Input schema dictionary containing properties definition.
        :return: List of property keys that should be included in the template.
        """
        if "properties" not in schema:
            return []
        return [
            key
            for key in schema["properties"]
            if (
                schema["properties"][key].get("skip_in_template", False) is False
                or self.creating_configuration
            )
        ]

    def _update_before_comment(
        self, cfg: Union[CMap, CSeq], key: Union[str, int], comment: str
    ) -> None:
        """Update comment to add new comment before current one.

        The method manipulates YAML comment structure by inserting new comment lines
        before existing comments in a commented map or sequence configuration.

        :param cfg: Commented map or Commented Sequence to update.
        :param key: Key name or index for the comment location.
        :param comment: Comment text that should be placed before current one.
        """
        from ruamel.yaml.error import CommentMark
        from ruamel.yaml.tokens import CommentToken

        def comment_token(s: str, mark: CommentMark) -> CommentToken:
            """Create a comment token with the given string and comment mark.

            Handles empty lines by adding no comment prefix, while non-empty lines get
            the standard comment prefix.

            :param s: The string content to be converted into a comment token.
            :param mark: The comment mark indicating the position or type of comment.
            :return: A CommentToken object containing the formatted comment string.
            """
            # handle empty lines as having no comment
            return CommentToken(("# " if s else "") + s + "\n", mark)

        comments = cfg.ca.items.setdefault(key, [None, None, None, None])
        if not isinstance(comments[1], list):
            comments[1] = []
        new_lines = comment.splitlines()
        new_lines.reverse()
        start_mark = CommentMark(max(SPSDK_YML_INDENT * (self.indent - 1), 0))
        for c in new_lines:
            comments[1].insert(0, comment_token(c, start_mark))

    def export(self, config: Optional[dict[str, Any]] = None) -> CMap:
        """Export configuration template into CommentedMap.

        This method processes the schema configuration by merging multiple schemas,
        organizing properties into logical blocks, and generating a formatted
        configuration template with proper comments and structure.

        :param config: Optional configuration dictionary to be applied to template.
        :raises SPSDKError: Template generation failed due to processing errors.
        :return: Configuration template as CommentedMap with proper formatting.
        """
        self.indent = 0
        self.creating_configuration = bool(config)
        loc_schemas = copy.deepcopy(self.schemas)
        # 1. Get blocks with their titles and lists of their keys
        block_list: dict[str, Any] = {}
        for schema in loc_schemas:
            if schema.get("skip_in_template", False):
                continue
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
        schemas_merger = SPSDKMerger()

        merged: dict[str, Any] = {}
        for schema in loc_schemas:
            schemas_merger.merge(merged, copy.deepcopy(schema))

        # 3. Create order of individual settings

        order_dict: dict[str, Any] = OrderedDict()
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
            cfg = self._create_object_block(merged, config)
            assert isinstance(cfg, CMap)
            # 5. Add main title of configuration
            title = f"  {self.main_title}  ".center(self.MAX_LINE_LENGTH, "=") + "\n\n"
            if self.note:
                title += f"\n{' Note '.center(self.MAX_LINE_LENGTH, '-')}\n"
                title += wrap_text(self.note, self.max_line) + "\n"
            cfg.yaml_set_start_comment(title)
            for title, info in block_list.items():
                description = info["description"]
                assert isinstance(description, (str, type(None)))

                first_key = None
                for info_key in info["properties"]:
                    if info_key in cfg.keys():
                        first_key = info_key
                        break

                if first_key:
                    self._update_before_comment(
                        cfg, first_key, self._get_title_block(title, description)
                    )

            self.creating_configuration = False
            return cfg

        except Exception as exc:
            self.creating_configuration = False
            raise SPSDKError(f"Template generation failed: {str(exc)}") from exc

    def get_template(self) -> str:
        """Export configuration template directly into YAML string format.

        The method converts the exported configuration model into a YAML formatted
        string that can be used as a template for configuration files.

        :return: Configuration template as YAML formatted string.
        """
        return self.convert_cm_to_yaml(self.export())

    def get_config(self, config: dict[str, Any]) -> str:
        """Export Configuration directly into YAML string format.

        :param config: Configuration dictionary to be exported.
        :return: YAML string representation of the configuration.
        """
        return self.convert_cm_to_yaml(self.export(config))

    @staticmethod
    def convert_cm_to_yaml(config: CMap) -> str:
        """Convert Commented Map into final YAML string.

        The method converts a configuration in Commented Map format to a properly formatted YAML string
        with appropriate indentation and width settings for file storage.

        :param config: Configuration in Commented Map format.
        :raises SPSDKError: If configuration is empty.
        :return: YAML string with configuration ready for file storage.
        """
        if not config:
            raise SPSDKError("Configuration cannot be empty")
        yaml = YAML(pure=True)
        yaml.indent(sequence=SPSDK_YML_INDENT * 2, offset=SPSDK_YML_INDENT)
        # Use a reasonable width that prevents wrapping of long configuration keys
        # This should be larger than the longest expected configuration key name
        yaml.width = 200
        stream = io.StringIO()
        yaml.dump(config, stream)
        yaml_data = stream.getvalue()

        return yaml_data
