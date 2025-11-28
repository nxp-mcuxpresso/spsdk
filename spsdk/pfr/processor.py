#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK PFR processor for handling conditional rules and transformations.

This module provides functionality for processing and transforming conditional
rules in PFR (Protected Flash Region) context. It includes AST-based code
transformation capabilities and rule processing logic.
"""

import ast
import logging
import re
import sys

if sys.version_info < (3, 9):
    from astunparse import unparse
else:
    from ast import unparse

from spsdk.pfr.translator import Translator

logger = logging.getLogger(__name__)


class MyTransformer(ast.NodeTransformer):
    """AST node transformer for PFR configuration processing.

    This transformer replaces string attribute references with their corresponding
    numeric values during AST traversal, enabling dynamic value resolution in
    PFR configuration expressions.
    """

    def __init__(self, translator: Translator) -> None:
        """Initialize Transformer.

        :param translator: Translator instance for processing operations.
        """
        self.translator = translator
        self.logger = logger.getChild("transformer")

    def visit_Attribute(self, node: ast.Attribute) -> ast.Constant:  # pylint: disable=invalid-name
        """Transform AST Attribute nodes into Constant nodes with translated values.

        This method processes attribute access expressions in the AST by translating
        them using the configured translator and converting them to constant values.

        :param node: The AST Attribute node to be transformed.
        :return: A new AST Constant node containing the translated value with copied location info.
        """
        self.logger.debug("Transforming node attribute...")
        thing = unparse(node).strip()
        value = self.translator.translate(thing)
        self.logger.debug(f"Attribute '{thing}' transformed into {value:x}")
        result = ast.Constant(value=value, kind=None)
        return ast.copy_location(result, node)


class Processor:
    """SPSDK condition processor for PFR operations.

    This class processes conditional expressions by parsing condition strings,
    transforming register keys through a translator, and evaluating the results.
    It handles the conversion of condition expressions into executable code while
    maintaining proper logging and formatting of numeric values.
    """

    def __init__(self, translator: Translator) -> None:
        """Initialize processor with translator instance.

        :param translator: Translator instance used for processing operations.
        """
        self.logger = logger.getChild("processor")
        self.transformer = MyTransformer(translator)

    def process(self, condition: str) -> tuple[bool, str]:
        """Process individual condition from rules.

        The method parses and evaluates a condition string using AST transformation,
        converting it to executable code and returning both the boolean result and
        the transformed condition string with translated keys.

        :param condition: Condition string to parse and evaluate.
        :return: Tuple containing boolean evaluation result and transformed condition string.
        """
        self.logger.debug(f"Transforming condition: {condition}")
        org_node = ast.parse(condition, mode="eval")
        new_node = self.transformer.visit(org_node)
        node_str = unparse(new_node).rstrip()
        self.logger.debug(f"Transformed condition: {node_str}")
        node_str = self._replace_int_as_hex(node_str)
        # pylint: disable=eval-used
        result = eval(compile(new_node, filename="", mode="eval"))  # nosec
        return result, node_str

    @staticmethod
    def _replace_int_as_hex(string: str) -> str:
        """Convert numeric decimal values in string to hexadecimal format.

        The method processes a string and converts all decimal numeric occurrences to their
        hexadecimal representation using Python's hex() function.

        :param string: Input string containing decimal numbers to convert.
        :return: String with all decimal numbers converted to hexadecimal format.
        """
        replaced_string = ""
        for sub_string in re.split("([0-9]+)", string):
            replaced_string += hex(int(sub_string, 0)) if sub_string.isnumeric() else sub_string

        return replaced_string
