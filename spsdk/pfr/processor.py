#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2020-2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""Processor for conditions in rules."""

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
    """AST-based transformer for replacing string names with actual values."""

    def __init__(self, translator: Translator) -> None:
        """Initialize Transformer.

        :param translator: Translator instance
        """
        self.translator = translator
        self.logger = logger.getChild("transformer")

    def visit_Attribute(self, node: ast.Attribute) -> ast.Constant:  # pylint: disable=invalid-name
        """Translate Attribute Nodes."""
        self.logger.debug("Transforming node attribute...")
        thing = unparse(node).strip()
        value = self.translator.translate(thing)
        self.logger.debug(f"Attribute '{thing}' transformed into {value:x}")
        result = ast.Constant(value=value, kind=None)
        return ast.copy_location(result, node)


class Processor:
    """Class responsible for processing conditions.

    Processor is responsible for processing condition
        - parsing the condition string (lookup)
        - calling translator for individual keys (registers)

    Translator is responsible for looking up values for given keys
    """

    def __init__(self, translator: Translator) -> None:
        """Initialize processor.

        :param translator: Translator instance
        """
        self.logger = logger.getChild("processor")
        self.transformer = MyTransformer(translator)

    def process(self, condition: str) -> tuple[bool, str]:
        """Process individual condition from rules.

        :param condition: condition to quantify
        :return: Tuple with boolean result and string with translated keys
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
        """Converts all numeric occurrences in `string` in decimal form into hexadecimal form.

        :param string: string to process
        :return: returns a string, where all numbers represented as in dec form are converted to hex form
        """
        replaced_string = ""
        for sub_string in re.split("([0-9]+)", string):
            replaced_string += hex(int(sub_string, 0)) if sub_string.isnumeric() else sub_string

        return replaced_string
