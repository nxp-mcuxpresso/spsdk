#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK SB2 Boot Data file parser implementation.

This module provides a parser for Boot Descriptor (BD) command files used in SB2 format,
enabling parsing and processing of secure boot configuration commands.
"""

import logging
from numbers import Number
from typing import Any, Optional

from sly import Parser
from sly.lex import Token
from sly.yacc import YaccProduction

from spsdk.exceptions import SPSDKError
from spsdk.sbfile.sb2 import sly_bd_lexer as bd_lexer


# pylint: disable=too-many-public-methods,too-many-lines
# too-many-public-methods : every method in the parser represents a syntax rule,
#   this is necessary and thus can't be omitted. From this perspective this check
#   is disabled.
# too-many-lines : the class can't be shortened, as all the methods represent
#   rules.
class BDParser(Parser):
    """Command (BD) file parser for SB2.1 format.

    The parser is based on SLY framework (python implementation of Lex/YACC)
    and is used to parse command files that serve as input for creating
    secure binaries in SB2.1 format. It processes BD file syntax including
    variables, sources, keyblobs, and sections to generate structured
    configuration data.

    :cvar tokens: Lexer tokens imported from BDLexer for parser operation.
    :cvar log: Logger instance for parser operations.
    """

    # Import tokens from lexer. This is required by the parser!
    tokens = bd_lexer.BDLexer.tokens
    # tokens = BDLexer.tokens

    # Uncomment this line to output parser debug file
    # debugfile = "parser.out"

    log = logging.getLogger(__name__)
    log.setLevel(logging.ERROR)

    def __init__(self) -> None:
        """Initialize the SLY BD parser.

        Sets up the parser with empty collections for variables, sources, keyblobs,
        sections, and other internal state needed for parsing boot descriptor files.
        """
        super().__init__()
        self._variables: list[bd_lexer.Variable] = []
        self._sources: list[bd_lexer.Variable] = []
        self._keyblobs: list[dict] = []
        self._sections: list[bd_lexer.Variable] = []
        self._input: Any = None
        self._bd_file: dict = {}
        self._parse_error: bool = False
        self._extern: list[str] = []
        self._lexer = bd_lexer.BDLexer()

    def _cleanup(self) -> None:
        """Clean up allocated resources before next parsing.

        This method resets all internal state variables to their initial values,
        preparing the parser for a new parsing operation. It clears variables,
        keyblobs, sections, input data, and the parsed BD file structure.

        :raises SPSDKError: If lexer cleanup fails.
        """
        self._variables = []
        self._keyblobs = []
        self._sections = []
        # for some strange reason, mypy assumes this is a redefinition of _input
        self._input = None
        self._bd_file = {}
        self._parse_error = False
        self._lexer.cleanup()

    def parse(
        self, text: str, extern: Optional[list] = None
    ) -> Optional[dict]:  # pylint: disable=arguments-differ
        """Parse the BD command file and return its structured content.

        The method processes a Boot Descriptor (BD) command file text, tokenizes it using the lexer,
        and parses it into a structured dictionary format. It also handles external files
        that may be referenced in the command file.

        :param text: Command file content to be parsed in string format.
        :param extern: Additional external files defined on command line, defaults to None.
        :return: Dictionary containing the parsed command file structure, or None if parsing fails.
        """
        self._cleanup()
        self._extern = extern or []
        # for some strange reason, mypy assumes this is a redefinition of _input
        self._input: Any = text  # type: ignore

        super().parse(self._lexer.tokenize(text))

        if self._parse_error is True:
            print("BD file parsing not successful.")
            return None

        return self._bd_file

    # Operators precedence
    precedence = (
        ("left", "LOR"),
        ("left", "LAND"),
        ("left", "OR"),
        ("left", "XOR"),
        ("left", "AND"),
        ("left", "EQ", "NE"),
        ("left", "GT", "GE", "LT", "LE"),
        ("left", "LSHIFT", "RSHIFT"),
        ("left", "PLUS", "MINUS"),
        ("left", "TIMES", "DIVIDE", "MOD"),
        ("right", "SIZEOF"),
        ("right", "LNOT", "NOT"),
    )

    # ruff: noqa: F821, F811
    # pylint: disable=undefined-variable,function-redefined,no-self-use,unused-argument
    # undefined-variable : the module uses underscore decorator to define
    #   each rule, however, this causes issues to mypy and pylint.
    # function-redefined : each rule is identified by a function name and a
    #   decorator. However from code checking tools perspective, this is
    #   function redefinition. Thus we need to disable this rule as well.
    # no-self-use : all 'rules' must be class methods, although they don't use
    #   self. Thus we need to omit this rule.
    # unused-argument : not all token input arguments are always used, especially
    #   in rules which are not supported.
    @_("pre_section_block section_block")  # type: ignore
    def command_file(self, token: YaccProduction) -> None:
        """Parse command file token and update BD file structure.

        This method processes a parser token containing file command data, merges
        the pre-section and section blocks, and updates the main BD file structure
        with the combined content.

        :param token: YaccProduction object holding the parsed content from the grammar rule.
        """
        token.pre_section_block.update(token.section_block)
        self._bd_file.update(token.pre_section_block)

    @_("pre_section_block options_block")  # type: ignore
    def pre_section_block(self, token: YaccProduction) -> dict:
        """Parse pre-section block with options.

        Processes a pre-section block token by merging its existing options with
        additional options from the options block, then returns the updated
        pre-section block dictionary.

        :param token: YaccProduction object holding the pre-section block content
            and options defined in the parser decorator.
        :return: Dictionary defining the complete pre-section block with merged
            options.
        """
        options = token.pre_section_block.get("options", {})
        options.update(token.options_block["options"])
        token.pre_section_block["options"] = options
        return token.pre_section_block

    @_("pre_section_block constants_block", "pre_section_block sources_block")  # type: ignore
    def pre_section_block(self, token: YaccProduction) -> dict:
        """Parse pre-section block from SB2 file tokens.

        Updates the pre-section block dictionary with parsed token content and returns
        the complete pre-section block configuration.

        :param token: YaccProduction object holding the parsed content from grammar rule.
        :return: Dictionary defining the pre-section block configuration.
        """
        token.pre_section_block.update(token[1])
        return token.pre_section_block

    @_("pre_section_block keyblob_block")  # type: ignore
    def pre_section_block(self, token: YaccProduction) -> dict:
        """Parse pre-section block with keyblob data.

        This method processes a parser token containing pre-section block information
        and appends keyblob block data to the keyblobs list. If no keyblobs list
        exists, it creates one before appending the new keyblob block.

        :param token: YaccProduction object holding the parsed content from grammar rule.
        :return: Dictionary containing the complete pre-section block configuration.
        """
        if token.pre_section_block.get("keyblobs") is None:
            token.pre_section_block["keyblobs"] = []
        token.pre_section_block["keyblobs"].append(token.keyblob_block)
        return token.pre_section_block

    @_("empty")  # type: ignore
    def pre_section_block(self, token: YaccProduction) -> dict:
        """Parse pre-section block from SB2 file.

        This method processes a YACC production token to extract pre-section block
        information and returns an empty dictionary as the default implementation.

        :param token: YACC production object containing parsed content from the decorator.
        :return: Dictionary defining the pre-section block structure.
        """
        return token.empty

    @_("OPTIONS LBRACE option_def RBRACE")  # type: ignore
    def options_block(self, token: YaccProduction) -> dict:
        """Parse options block from boot descriptor file.

        Extracts and processes the options block definition from the parsed token,
        returning the configuration as a dictionary structure.

        :param token: YaccProduction object containing the parsed options block content.
        :return: Dictionary containing the options block configuration.
        """
        return token.option_def

    @_("option_def IDENT ASSIGN const_expr SEMI")  # type: ignore
    def option_def(self, token: YaccProduction) -> dict:
        """Parse option definition from boot descriptor file.

        Processes an option definition token and updates the parser's variables list
        and option dictionary with the identifier and its constant expression value.

        :param token: YaccProduction object containing IDENT and const_expr attributes
            from the parsed option definition.
        :return: Dictionary containing the updated option definition with the new
            identifier-value pair.
        """
        # it appears, that in the option block anything can be defined, so
        # we don't check, whether the identifiers defined there are from the
        # allowed options anymore. The code is left just as a reminder.
        # identifier = token.IDENT
        # if identifier in self.allowed_option_identifiers:
        #     self._variables.append(self.Variable(token.IDENT, "option", token.const_expr))
        #     token.option_def["options"].update({token.IDENT : token.const_expr})
        #     return token.option_def
        # else:
        #     column = BDParser._find_column(self._input, token)
        #     print(f"Unknown option in options block at {token.lineno}/{column}: {token.IDENT}")
        #     self.error(token)
        self._variables.append(bd_lexer.Variable(token.IDENT, "option", token.const_expr))
        token.option_def["options"].update({token.IDENT: token.const_expr})
        return token.option_def

    @_("empty")  # type: ignore
    def option_def(self, token: YaccProduction) -> dict:
        """Parse option definition rule for SB2 file format.

        Creates an empty options dictionary structure that can be populated
        with configuration options during the parsing process.

        :param token: YaccProduction object holding the content defined in decorator.
        :return: Dictionary containing empty options structure.
        """
        return {"options": {}}

    @_("CONSTANTS LBRACE constant_def RBRACE")  # type: ignore
    def constants_block(self, token: YaccProduction) -> dict:
        """Parse constants block from boot descriptor file.

        For now, we don't store the constants in the final bd file.

        :param token: YaccProduction object holding the content defined in decorator.
        :return: Empty dictionary as constants are not currently stored.
        """
        dictionary: dict = {}
        return dictionary

    @_("constant_def IDENT ASSIGN bool_expr SEMI")  # type: ignore
    def constant_def(self, token: YaccProduction):
        """Parse constant definition rule and add variable to collection.

        This method processes a constant definition token from the parser and creates
        a new Variable object with the constant type, storing it in the variables list.

        :param token: YaccProduction object containing IDENT and bool_expr attributes
            from the parsed constant definition rule.
        """
        self._variables.append(bd_lexer.Variable(token.IDENT, "constant", token.bool_expr))

    @_("empty")  # type: ignore
    def constant_def(self, token: YaccProduction) -> dict:
        """Parse constant definition rule.

        This parser rule handles the parsing of constant definitions in the SB2 boot image
        configuration file format.

        :param token: YaccProduction object containing the parsed content from the grammar rule.
        :return: Dictionary representing an empty constant definition structure.
        """
        return token.empty

    @_("SOURCES LBRACE source_def RBRACE")  # type: ignore
    def sources_block(self, token: YaccProduction) -> dict:
        """Parse sources block from boot descriptor file.

        Extracts source definitions from the lexer but does not store them in the final BD file.
        This method processes the sources block syntax and returns the collected source mappings.

        :param token: YaccProduction object holding the parsed content from grammar rule.
        :return: Dictionary containing sources mapping with 'sources' key and source definitions.
        """
        sources = {}
        for source in self._lexer._sources:
            sources[source.name] = source.value
        return {"sources": sources}

    @_("source_def IDENT ASSIGN source_value SEMI")  # type: ignore
    def source_def(self, token: YaccProduction) -> None:
        """Define source variable in the parser.

        This method processes a source definition token and creates a new source variable
        that is added to the lexer's source collection.

        :param token: YaccProduction object containing the source identifier and value from the parser.
        """
        new_source = bd_lexer.Variable(token.IDENT, "source", token.source_value)
        self._lexer.add_source(new_source)

    @_("source_def IDENT ASSIGN source_value LPAREN source_attr_list RPAREN SEMI")  # type: ignore
    def source_def(self, token: YaccProduction) -> None:
        """Parse source definition rule and raise error for unsupported attribute lists.

        This parser rule handles source definition syntax but currently does not support
        attribute lists, raising an error when encountered.

        :param token: YaccProduction object containing parsed tokens and line information
        :raises SPSDKError: When attribute list syntax is encountered (not supported)
        """
        # self._sources.append(self.Variable(token.IDENT, "source", token.source_value))
        error_token = Token()
        error_token.lineno = token.lineno
        error_token.index = token._slice[4].index
        self.error(error_token, ": attribute list is not supported")

    @_("empty")  # type: ignore
    def source_def(self, token: YaccProduction) -> dict:
        """Parse source definition rule for SB2 file format.

        This method handles the parsing of source definition tokens in the SB2 file
        grammar, returning empty content as defined by the parser rule.

        :param token: YaccProduction object holding the content defined in decorator.
        :return: Dictionary holding empty content.
        """
        return token.empty

    @_("STRING_LITERAL")  # type: ignore
    def source_value(self, token: YaccProduction) -> str:
        """Parse source value from string literal token.

        Extracts the actual string content from a STRING_LITERAL token by removing
        the surrounding double quotes.

        :param token: YaccProduction object containing the parsed STRING_LITERAL token.
        :return: String content with surrounding quotes removed.
        """
        # Everything we read is a string. But strings already contain double quotes,
        # from this perspective we need to remove them, this omit the first and last
        # character.
        return token.STRING_LITERAL[1:-1]

    @_("EXTERN LPAREN int_const_expr RPAREN")  # type: ignore
    def source_value(self, token: YaccProduction) -> str:
        """Get source value from external source array.

        Retrieves a string value from the external source array using the integer constant
        expression from the token as an index.

        :param token: YaccProduction object holding the content with int_const_expr attribute.
        :raises SPSDKError: When the index is out of range for the external source array.
        :return: String defining a path from the external source array.
        """
        if token.int_const_expr > len(self._extern) - 1:
            self.error(token, ": extern() out of range")
            return ""
        return self._extern[token.int_const_expr]

    @_("source_attr COMMA source_attr_list")  # type: ignore
    def source_attr_list(self, token: YaccProduction) -> dict:
        """Parse source attribute list from boot description file.

        This method processes source attribute list tokens but currently returns an empty
        dictionary as source attributes are not yet implemented in the parser.

        :param token: YaccProduction object holding the parsed content from the grammar rule.
        :return: Empty dictionary placeholder for future source attribute implementation.
        """
        dictionary = {}
        return dictionary

    @_("source_attr")  # type: ignore
    def source_attr_list(self, token: YaccProduction) -> dict:
        """Parse source attribute list from token.

        Extracts the source attribute dictionary from a YaccProduction token during
        the parsing process of SB2 boot image files.

        :param token: YaccProduction object containing parsed content from grammar rule.
        :return: Dictionary containing source attribute data.
        """
        return token.source_attr

    @_("empty")  # type: ignore
    def source_attr_list(self, token: YaccProduction) -> dict:
        """Parse source attribute list rule for empty attributes.

        This parser rule handles the case when a source definition contains
        an empty attribute list, returning an empty dictionary to represent
        no attributes being specified.

        :param token: YaccProduction object holding the parsed content from grammar rule.
        :return: Empty dictionary representing no source attributes.
        """
        return {}

    @_("IDENT ASSIGN const_expr")  # type: ignore
    def source_attr(self, token: YaccProduction) -> dict:
        """Parse source file attribute from token.

        Extracts identifier and constant expression from YaccProduction token to create
        a dictionary mapping attribute names to their values.

        :param token: YaccProduction object containing IDENT and const_expr attributes.
        :return: Dictionary with identifier as key and constant expression as value.
        """
        return {token.IDENT: token.const_expr}

    @_("KEYBLOB LPAREN int_const_expr RPAREN LBRACE keyblob_contents RBRACE")  # type: ignore
    def keyblob_block(self, token: YaccProduction) -> dict:
        """Parse keyblob block from BD file token.

        Processes a keyblob block token containing keyblob ID and content, stores it in the
        internal keyblobs list, and returns the parsed data as a dictionary.

        :param token: YaccProduction object holding the keyblob block content from parser.
        :return: Dictionary with 'keyblob_id' and 'keyblob_content' keys containing the parsed
                 keyblob data.
        """
        dictionary = {"keyblob_id": token.int_const_expr, "keyblob_content": token.keyblob_contents}
        dictionary["keyblob_id"] = token.int_const_expr
        dictionary["keyblob_content"] = token.keyblob_contents
        self._keyblobs.append(dictionary)
        return dictionary

    # The legacy tool allowed to have multiple definitions inside a keyblob.
    # It has been agreed, that this makes no sense and may be dangerous.
    # However, it may happen, that someone comes with a use cases, where legacy
    # grammar is needed, thus the code has been left untouched just in case.
    # @_("keyblob_contents LPAREN keyblob_options_list RPAREN")
    # def keyblob_contents(self, token):
    #     l = token.keyblob_contents

    #     # Append only non-empty options lists to simplify further processing
    #     if len(token.keyblob_options_list) != 0:
    #         l.append(token.keyblob_options_list)
    #     return l

    # @_("empty")
    # def keyblob_contents(self, token):
    #     return []

    # @_("keyblob_options")
    # def keyblob_options_list(self, token):
    #     return token.keyblob_options

    # @_("empty")
    # def keyblob_options_list(self, token):
    #     # After discussion internal discussion, we will ignore empty definitions in keyblob
    #     # It's not clear, whether this has some effect on the final sb file or not.
    #     # C++ elftosb implementation is able to parse the file even without empty
    #     # parenthesis
    #     return token.empty

    # @_("IDENT ASSIGN const_expr COMMA keyblob_options")
    # def keyblob_options(self, token):
    #     d = {}
    #     d[token.IDENT] = token.const_expr
    #     d.update(token.keyblob_options)
    #     return d

    # @_("IDENT ASSIGN const_expr")
    # def keyblob_options(self, token):
    #     d = {}
    #     d[token.IDENT] = token.const_expr
    #     return d

    # New keyblob grammar!
    @_("LPAREN keyblob_options RPAREN")  # type: ignore
    def keyblob_contents(self, token: YaccProduction) -> list:
        """Parse keyblob contents from token.

        Extracts and processes keyblob options from the provided parser token to create
        a list containing the keyblob configuration options.

        :param token: YaccProduction object holding the keyblob content defined in decorator.
        :return: List containing options of each keyblob.
        """
        list_ = [token.keyblob_options]

        return list_

    @_("IDENT ASSIGN const_expr COMMA keyblob_options")  # type: ignore
    def keyblob_options(self, token: YaccProduction) -> dict:
        """Parse keyblob options from grammar token.

        Processes a YaccProduction token containing keyblob configuration options and converts
        them into a dictionary format for further processing.

        :param token: YaccProduction object holding keyblob options content from parser.
        :return: Dictionary containing keyblob configuration options with identifier as key.
        """
        dictionary = {}
        dictionary[token.IDENT] = token.const_expr
        dictionary.update(token.keyblob_options)
        return dictionary

    @_("IDENT ASSIGN const_expr")  # type: ignore
    def keyblob_options(self, token: YaccProduction) -> dict:
        """Parse keyblob options from token.

        Extracts keyblob configuration options from a parser token and converts them
        into a dictionary format for further processing.

        :param token: YaccProduction object holding the parsed keyblob option content.
        :return: Dictionary containing the keyblob option with identifier as key and
                 constant expression as value.
        """
        dictionary = {}
        dictionary[token.IDENT] = token.const_expr
        return dictionary

    @_("section_block SECTION LPAREN int_const_expr section_options RPAREN section_contents")  # type: ignore
    def section_block(self, token: YaccProduction) -> dict:
        """Parse section block from boot descriptor file.

        Processes a section block token containing section ID, options, and commands,
        then adds it to the internal sections list and updates the section block dictionary.

        :param token: YaccProduction object holding the parsed section content with int_const_expr,
                      section_options, and section_contents attributes.
        :return: Updated dictionary containing all parsed sections.
        """
        self._sections.append(
            {
                "section_id": token.int_const_expr,
                "options": token.section_options,
                "commands": token.section_contents,
            }
        )
        token.section_block["sections"] += [
            {
                "section_id": token.int_const_expr,
                "options": token.section_options,
                "commands": token.section_contents,
            }
        ]
        return token.section_block

    @_("empty")  # type: ignore
    def section_block(self, token: YaccProduction) -> dict:
        """Parse section block rule to create empty section dictionary.

        This parser rule initializes an empty section structure by adding an empty
        sections list to the token's empty dictionary.

        :param token: YaccProduction object holding the content defined in decorator.
        :return: Dictionary holding content of empty section with initialized sections list.
        """
        token.empty["sections"] = []
        return token.empty

    @_("SEMI section_option_list")  # type: ignore
    def section_options(self, token: YaccProduction) -> dict:
        """Parse section options from BD command file.

        This method processes a YACC production token containing section option definitions
        and extracts them into a dictionary format for further processing.

        :param token: YACC production token containing parsed section option list from BD file.
        :return: Dictionary containing the parsed section options and their values.
        """
        return token.section_option_list

    @_("SEMI")  # type: ignore
    def section_options(self, token: YaccProduction) -> dict:
        """Parse section options from BD file token.

        This method processes a YaccProduction token to extract section options and returns
        an empty dictionary as the base implementation for section options parsing.

        :param token: YaccProduction object holding the parsed content from the BD file.
        :return: Empty dictionary representing the base section options structure.
        """
        dictionary = {}
        return dictionary

    @_("empty")  # type: ignore
    def section_options(self, token: YaccProduction) -> dict:
        """Parse section options from BD file token.

        This method processes a YaccProduction token containing section options
        and extracts the empty section options content.

        :param token: YaccProduction object holding the content defined in decorator.
        :return: Dictionary holding the content of empty section options.
        """
        return token.empty

    @_("section_option_list COMMA section_option")  # type: ignore
    def section_option_list(self, token: YaccProduction) -> dict:
        """Parse section option list from boot descriptor file.

        Processes a YACC production token containing section options and builds a dictionary
        with all section option configurations. Updates existing options and maintains the
        section option list structure.

        :param token: YACC production token containing section option definitions and list.
        :return: Updated section option list with merged configurations.
        """
        options = {}
        options.update(token.section_option)
        if token.section_option_list:
            token.section_option_list.append(options)
        return token.section_option_list

    @_("section_option")  # type: ignore
    def section_option_list(self, token: YaccProduction) -> list:
        """Parse section option list from grammar token.

        Extracts a single section option from the parser token and returns it as a list
        containing one element for further processing in the grammar rules.

        :param token: YaccProduction object holding the parsed section option content.
        :return: List containing the extracted section option dictionary.
        """
        return [token.section_option]

    @_("IDENT ASSIGN const_expr")  # type: ignore
    def section_option(self, token: YaccProduction) -> dict:
        """Parse section option from boot descriptor token.

        Extracts identifier and constant expression from a YaccProduction token to create
        a section option dictionary entry.

        :param token: YaccProduction object containing IDENT and const_expr attributes.
        :return: Dictionary with identifier as key and constant expression as value.
        """
        return {token.IDENT: token.const_expr}

    @_("LBRACE statement RBRACE")  # type: ignore
    def section_contents(self, token: YaccProduction) -> list:
        """Parse section contents from boot descriptor token.

        Extracts the statement content from a YaccProduction token representing
        a section in the boot descriptor file.

        :param token: YaccProduction object containing parsed section content.
        :return: List of statements within the section.
        """
        return token.statement

    @_("LE SOURCE_NAME SEMI")  # type: ignore
    def section_contents(self, token: YaccProduction) -> None:
        """Parse section contents rule for SB2 file format.

        Handles the section contents syntax parsing but currently raises an error
        as the ": <= <source_name>" syntax is not yet supported in the parser.

        :param token: YaccProduction object containing the parsed tokens and grammar rule content.
        :raises SPSDKError: Always raised as this syntax is not currently supported.
        """
        self.error(token, ": <= <source_name> syntax is not supported right now.")

    @_("statement basic_stmt SEMI")  # type: ignore
    def statement(self, token: YaccProduction) -> list:
        """Parse statement rule to build section statements list.

        Combines existing statements with a new basic statement to create
        a comprehensive list of section statements for SB2 file processing.

        :param token: YaccProduction object holding parsed content from grammar rule.
        :return: List of section statements including the new basic statement.
        """
        list_ = [] + token.statement
        list_.append(token.basic_stmt)
        return list_

    @_("statement from_stmt")  # type: ignore
    def statement(self, token: YaccProduction) -> dict:
        """Parse statement rule for SB2 file format.

        Currently returns empty dictionary as from_stmt is not supported in this implementation.

        :param token: YaccProduction object holding the parsed content defined in grammar rule decorator.
        :return: Empty dictionary as placeholder for future from_stmt implementation.
        """
        dictionary = {}
        return dictionary

    @_("statement if_stmt")  # type: ignore
    def statement(self, token: YaccProduction) -> None:
        """Parse a statement rule in the boot data language.

        Currently, if statements are not supported in the parser implementation.

        :param token: YaccProduction object containing the parsed content and grammar rule data.
        """
        # return token.statement + token.if_stmt

    @_("statement encrypt_block")  # type: ignore
    def statement(self, token: YaccProduction) -> list:
        """Parse statement rule for encrypt block processing.

        Processes a parser token containing statement and encrypt block information,
        combining them into a unified list structure.

        :param token: YaccProduction object holding the parsed content from grammar rule.
        :return: Combined list containing the statement and encrypt block elements.
        """
        list_ = [] + token.statement
        list_.append(token.encrypt_block)
        return list_

    @_("statement keywrap_block")  # type: ignore
    def statement(self, token: YaccProduction) -> list:
        """Parse statement rule for keywrap block processing.

        Processes a parser token containing statement and keywrap block data,
        combining them into a single list structure for further processing.

        :param token: YaccProduction object holding the parsed content from grammar rule.
        :return: List containing the combined statement and keywrap block elements.
        """
        list_ = [] + token.statement
        list_.append(token.keywrap_block)
        return list_

    @_("empty")  # type: ignore
    def statement(self, token: YaccProduction) -> list:
        """Parse an empty statement rule.

        This method handles empty statement productions in the parser grammar,
        returning an empty list to maintain parser state consistency.

        :param token: YaccProduction object holding the content defined in decorator.
        :return: Empty list representing no statements to process.
        """
        # return empty statement list
        return []

    @_("KEYWRAP LPAREN int_const_expr RPAREN LBRACE LOAD BINARY_BLOB GT int_const_expr SEMI RBRACE")  # type: ignore
    def keywrap_block(self, token: YaccProduction) -> dict:
        """Parse keywrap block from SB2 file format.

        Processes a keywrap block token containing keyblob ID, address, and binary data
        to create a structured dictionary representation for SB2 file generation.

        :param token: YaccProduction object containing parsed keywrap block data with
                      keyblob ID, load address, and binary blob content.
        :return: Dictionary with keywrap block structure containing keyblob_id,
                 address, and values fields.
        """
        dictionary = {"keywrap": {"keyblob_id": token.int_const_expr0}}
        load_cmd = {"address": token.int_const_expr1, "values": token.BINARY_BLOB}
        dictionary["keywrap"].update(load_cmd)
        return dictionary

    @_("ENCRYPT LPAREN int_const_expr RPAREN LBRACE load_stmt SEMI RBRACE")  # type: ignore
    def encrypt_block(self, token: YaccProduction) -> dict:
        """Parse encrypt block from boot descriptor file.

        Processes an encrypt block token containing keyblob ID and load statement,
        combining them into a structured dictionary format.

        :param token: YaccProduction object holding the encrypt block content from parser.
        :return: Dictionary with encrypt block configuration including keyblob_id and load data.
        """
        dictionary = {"encrypt": {"keyblob_id": token.int_const_expr}}
        dictionary["encrypt"].update(token.load_stmt.get("load"))
        return dictionary

    @_(  # type: ignore
        "load_stmt",
        "call_stmt",
        "jump_sp_stmt",
        "mode_stmt",
        "message_stmt",
        "erase_stmt",
        "enable_stmt",
        "reset_stmt",
        "keystore_stmt",
        "version_stmt",
    )
    def basic_stmt(self, token: YaccProduction) -> dict:
        """Parse basic statement from token production.

        Processes a YaccProduction token containing basic statement content and extracts
        the parsed data structure.

        :param token: YaccProduction object holding the content defined in decorator.
        :return: Dictionary holding the content of defined statements.
        """
        return token[0]

    @_("LOAD load_opt load_data load_target")  # type: ignore
    def load_stmt(self, token: YaccProduction) -> dict:
        """Parse load statement from BD file into command dictionary.

        Converts a load statement token into either a 'load' or 'fill' command dictionary
        based on the presence of pattern and load options. When pattern is specified
        without load options, it creates a 'fill' command, otherwise a 'load' command.

        :param token: YaccProduction object containing load statement components
        :return: Dictionary with command type as key and merged statement data as value
        """
        # pattern with load options means load -> program command
        if token.load_data.get("pattern") is not None and token.load_opt.get("load_opt") is None:
            cmd = "fill"
        else:
            cmd = "load"
        dictionary: dict = {cmd: {}}
        dictionary[cmd].update(token.load_opt)
        dictionary[cmd].update(token.load_data)
        dictionary[cmd].update(token.load_target)
        return dictionary

    @_("empty")  # type: ignore
    def load_opt(self, token: YaccProduction) -> dict:
        """Parse load options from token production.

        Extracts and returns the load options content from a parser token,
        typically used in SB2 file parsing to handle load operation parameters.

        :param token: YaccProduction object holding the content defined in decorator.
        :return: Dictionary holding the content of load options.
        """
        return token.empty

    @_("'@' int_const_expr")  # type: ignore
    def load_opt(self, token: YaccProduction) -> dict:
        """Parse load option from token.

        Extracts the integer constant expression from the YaccProduction token and returns it as a
        load option dictionary entry.

        :param token: YaccProduction object holding the content defined in decorator.
        :return: Dictionary containing the load option with integer constant expression value.
        """
        return {"load_opt": token.int_const_expr}

    @_("IDENT")  # type: ignore
    def load_opt(self, token: YaccProduction) -> dict:
        """Parse load option from token.

        Extracts the identifier from a YaccProduction token and returns it as a load option
        dictionary entry for SB2 file processing.

        :param token: YaccProduction object containing the parsed token content.
        :return: Dictionary with load option identifier under 'load_opt' key.
        """
        return {"load_opt": token.IDENT}

    @_("int_const_expr")  # type: ignore
    def load_data(self, token: YaccProduction) -> dict:
        """Parse load data command from SB2 file.

        Processes a load data token from the parser and extracts the pattern value.
        Validates that the integer constant expression is not a string identifier.

        :param token: YaccProduction object containing the parsed load data command content.
        :raises SPSDKError: When the integer constant expression is a string identifier.
        :return: Dictionary containing the load data pattern or error information.
        """
        if isinstance(token.int_const_expr, str):
            self.error(token, f": identifier '{token.int_const_expr}' is not a source identifier.")
            retval = {"N/A": "N/A"}
        else:
            retval = {"pattern": token.int_const_expr}

        return retval

    @_("STRING_LITERAL")  # type: ignore
    def load_data(self, token: YaccProduction) -> dict:
        """Parse load data command from SB2 file.

        Extracts the file path from a load data token by removing the surrounding quotes
        from the string literal.

        :param token: YaccProduction object containing the parsed load data command with STRING_LITERAL.
        :return: Dictionary with 'file' key containing the unquoted file path string.
        """
        return {"file": token.STRING_LITERAL[1:-1]}

    @_("SOURCE_NAME")  # type: ignore
    def load_data(self, token: YaccProduction) -> dict:
        """Parse load data rule from SB2 boot descriptor file.

        Extracts file source information from the token and matches it against
        defined sources in the lexer. Returns a dictionary containing the file
        path for the load data operation.

        :param token: YaccProduction object holding the parsed content from the
            grammar rule decorator.
        :return: Dictionary with 'file' key containing the source file path, or
            'N/A' if source is not found.
        """
        for source in self._lexer._sources:
            if token.SOURCE_NAME == source.name:
                return {"file": source.value}

        # with current implementation, this code won't be ever reached. In case
        # a not defined source file is used as `load_data`, the parser detects
        # it as a different rule:
        #
        # load_data ::= int_const_expr
        #
        # which evaluates as false... however, this fragment is left just in
        # in case something changes.
        self.error(token, ": source file not defined")
        return {"file": "N/A"}

    @_("section_list")  # type: ignore
    def load_data(self, token: YaccProduction) -> dict:
        """Parse load data section from SB2 file.

        This method handles the parsing of load data sections in SB2 files. Currently,
        section lists are not supported and will raise an error.

        :param token: YaccProduction object holding the parsed content from the grammar rule.
        :raises SPSDKError: When section list is encountered (not supported).
        :return: Empty dictionary as placeholder for load data content.
        """
        self.error(token, ": section list is not supported")
        dictionary = {}
        return dictionary

    @_("section_list FROM SOURCE_NAME")  # type: ignore
    def load_data(self, token: YaccProduction) -> dict:
        """Parse load data section from BD file token.

        This method currently raises an error as section list using 'from' syntax
        is not supported in the current implementation.

        :param token: YaccProduction object containing the parsed BD file content.
        :raises SPSDKError: Always raised as this functionality is not supported.
        :return: Empty dictionary (placeholder return value).
        """
        self.error(token, "section list using from is not supported")
        dictionary = {}
        return dictionary

    @_("BINARY_BLOB")  # type: ignore
    def load_data(self, token: YaccProduction) -> dict:
        """Parse load data command from BD file token.

        Extracts binary blob data from the parsed token and returns it in a structured format
        for further processing in the secure boot file generation.

        :param token: YaccProduction object containing the parsed load data command content.
        :return: Dictionary with 'values' key containing the binary blob data.
        """
        # no_spaces = "".join(token.BINARY_BLOB.split())

        return {"values": token.BINARY_BLOB}

    @_("GT PERIOD")  # type: ignore
    def load_target(self, token: YaccProduction) -> dict:
        """Parse load target rule from boot description file.

        This parser rule is currently not supported and will raise an error when encountered.
        The '.' as load destination syntax is not implemented in the current version.

        :param token: YaccProduction object holding the parsed content from the grammar rule.
        :raises SPSDKError: When the unsupported load target rule is encountered.
        :return: Empty dictionary as placeholder for load target configuration.
        """
        self.error(token, ": '.' as load destination is not supported right now")
        dictionary = {}
        return dictionary

    @_("GT address_or_range")  # type: ignore
    def load_target(self, token: YaccProduction) -> dict:
        """Parse load target from BD command token.

        Extracts the address or range information from a parsed BD (Boot Data) command
        token to create a load target dictionary for SB2 file processing.

        :param token: YaccProduction object containing parsed BD command content.
        :return: Dictionary containing the address or range data for the load target.
        """
        return token.address_or_range

    @_("empty")  # type: ignore
    def load_target(self, token: YaccProduction) -> dict:
        """Parse load target rule from BD file.

        This parser rule is currently not supported and will raise an error when encountered.

        :param token: YaccProduction object holding the parsed content from the grammar rule.
        :raises SPSDKError: Always raised as load target rule is not currently supported.
        :return: Empty token object.
        """
        self.error(token, ": empty load target is not supported right now.")
        return token.empty

    @_("ERASE mem_opt address_or_range")  # type: ignore
    def erase_stmt(self, token: YaccProduction) -> dict:
        """Parse erase statement from BD file token.

        Processes a YaccProduction token containing erase command information and converts
        it into a structured dictionary format with address/range and memory options.

        :param token: YaccProduction object holding the parsed erase statement content.
        :return: Dictionary containing the structured erase statement with address/range and memory options.
        """
        dictionary: dict = {token.ERASE: {}}
        dictionary[token.ERASE].update(token.address_or_range)
        dictionary[token.ERASE].update(token.mem_opt)
        return dictionary

    @_("ERASE mem_opt ALL")  # type: ignore
    def erase_stmt(self, token: YaccProduction) -> dict:
        """Parse erase statement from SB2 boot descriptor file.

        Processes an erase statement token and creates a dictionary containing the erase
        operation parameters with default address and flags values.

        :param token: YaccProduction object containing parsed erase statement content.
        :return: Dictionary with erase statement configuration including address and flags.
        """
        dictionary: dict = {token.ERASE: {"address": 0x00, "flags": 0x01}}
        dictionary[token.ERASE].update(token.mem_opt)
        return dictionary

    @_("ERASE UNSECURE ALL")  # type: ignore
    def erase_stmt(self, token: YaccProduction) -> dict:
        """Parse erase statement from boot descriptor file.

        Processes the erase statement token and creates a dictionary representation
        with default address and flags values for the erase operation.

        :param token: YaccProduction object holding the parsed erase statement content.
        :return: Dictionary containing erase operation with address and flags.
        """
        return {"erase": {"address": 0x00, "flags": 0x02}}

    @_("ENABLE mem_opt int_const_expr")  # type: ignore
    def enable_stmt(self, token: YaccProduction) -> dict:
        """Parse enable statement from SB2 boot image configuration.

        Processes the enable statement token and creates a dictionary containing
        the enable configuration with memory options and target address.

        :param token: YaccProduction object containing parsed enable statement tokens.
        :return: Dictionary with enable statement configuration including memory options and address.
        """
        dictionary: dict = {token.ENABLE: {}}
        dictionary[token.ENABLE].update(token.mem_opt)
        dictionary[token.ENABLE]["address"] = token.int_const_expr
        return dictionary

    @_("section_list COMMA section_ref")  # type: ignore
    def section_list(self, token: YaccProduction) -> dict:
        """Parse section list rule for SB2 file format.

        This parser rule is currently not implemented and returns an empty dictionary
        as a placeholder for future functionality.

        :param token: YaccProduction object holding the parsed content from the grammar rule.
        :return: Empty dictionary as placeholder for section list content.
        """
        dictionary = {}
        return dictionary

    @_("section_ref")  # type: ignore
    def section_list(self, token: YaccProduction) -> dict:
        """Parse section list from boot descriptor token.

        Extracts section reference dictionary from the YaccProduction token containing
        section list data parsed from boot descriptor file.

        :param token: YaccProduction object holding parsed section list content.
        :return: Dictionary containing section reference data.
        """
        return token.section_ref

    @_("NOT SECTION_NAME")  # type: ignore
    def section_ref(self, token: YaccProduction) -> dict:
        """Parse section reference rule in SLY BD parser.

        This method handles section reference parsing but currently raises an error
        as section references are not supported in the current implementation.

        :param token: YaccProduction object holding the parsed content from grammar rule.
        :raises SPSDKError: Always raised as section references are not supported.
        :return: Empty dictionary (placeholder return value).
        """
        self.error(token, ": section reference is not supported.")
        dictionary = {}
        return dictionary

    @_("SECTION_NAME")  # type: ignore
    def section_ref(self, token: YaccProduction) -> dict:
        """Parse section reference token and raise error for unsupported operation.

        This method handles section reference parsing but currently raises an error
        since section references are not supported in the current implementation.

        :param token: YaccProduction object holding the content defined in decorator.
        :raises SPSDKError: Section reference operation is not supported.
        :return: Dictionary holding the content of a section reference.
        """
        self.error(token, ": section reference is not supported.")
        return {token.SECTION_NAME}

    @_("int_const_expr")  # type: ignore
    def address_or_range(self, token: YaccProduction) -> dict:
        """Parse address or range token into dictionary format.

        Processes a YaccProduction token containing an integer constant expression
        and extracts the address value into a structured dictionary format.

        :param token: YaccProduction object holding the content defined in decorator.
        :return: Dictionary containing the parsed address with 'address' key.
        """
        address_start = token.int_const_expr
        return {"address": address_start}

    @_("int_const_expr RANGE int_const_expr")  # type: ignore
    def address_or_range(self, token: YaccProduction) -> dict:
        """Parse address or range expression from SB2 boot descriptor.

        Extracts start address and calculates length from two integer constant expressions,
        typically used for defining memory regions in boot descriptors.

        :param token: YaccProduction object containing parsed tokens with int_const_expr0 and int_const_expr1.
        :return: Dictionary with 'address' (start address) and 'length' (calculated range length) keys.
        """
        address_start = token.int_const_expr0
        length = token.int_const_expr1 - address_start
        return {"address": address_start, "length": length}

    @_("SOURCE_NAME QUESTIONMARK COLON IDENT")  # type: ignore
    def symbol_ref(self, token: YaccProduction) -> None:
        """Handle symbol reference parser rule.

        This parser rule is currently not supported and will raise an error when encountered.

        :param token: YaccProduction object holding the parsed content from the grammar rule.
        :raises SPSDKError: Always raised as symbol references are not supported.
        """
        self.error(token, ": symbol reference is not supported.")

    @_("call_type call_target call_arg")  # type: ignore
    def call_stmt(self, token: YaccProduction) -> dict:
        """Parse call statement from SB2 boot descriptor file.

        Processes a YaccProduction token containing call statement components and constructs
        a dictionary with the call type, target, and arguments.

        :param token: YaccProduction object holding call statement content defined in decorator.
        :return: Dictionary containing the parsed call statement with call type as key and
                 combined target and argument information as value.
        """
        dictionary: dict = {token.call_type: {}}
        dictionary[token.call_type].update(token.call_target)
        dictionary[token.call_type].update(token.call_arg)
        return dictionary

    @_("CALL", "JUMP")  # type: ignore
    def call_type(self, token: YaccProduction) -> str:
        """Parse call type token from grammar rule.

        Extracts the call type ('call' or 'jump') from the parsed token content.

        :param token: YaccProduction object holding the content defined in decorator.
        :return: String representing 'call' or 'jump'.
        """
        return token[0]

    @_("int_const_expr")  # type: ignore
    def call_target(self, token: YaccProduction) -> dict:
        """Parse call target rule from BD command file.

        Extracts the target address from a call target command token and returns
        it as a dictionary structure for further processing.

        :param token: YaccProduction object containing the parsed call target content.
        :return: Dictionary with 'address' key containing the target address value.
        """
        return {"address": token.int_const_expr}

    @_("SOURCE_NAME")  # type: ignore
    def call_target(self, token: YaccProduction) -> dict:
        """Parse call target rule from boot descriptor.

        This parser rule is currently not supported and will raise an error when encountered.

        :param token: YaccProduction object holding the content defined in decorator.
        :raises SPSDKError: Always raised as call target with source name is not supported.
        :return: Empty dictionary as placeholder return value.
        """
        self.error(token, ": source name as call target is not supported.")
        dictionary = {}
        return dictionary

    @_("symbol_ref")  # type: ignore
    def call_target(self, token: YaccProduction) -> dict:
        """Parse call target rule from boot descriptor.

        This parser rule is currently not supported and will raise an error when encountered.

        :param token: YaccProduction object holding the parsed token content.
        :raises SPSDKError: Always raised as call target symbol references are not supported.
        :return: Empty dictionary as placeholder return value.
        """
        self.error(token, ": symbol reference as call target is not supported.")
        dictionary = {}
        return dictionary

    @_("LPAREN RPAREN")  # type: ignore
    def call_arg(self, token: YaccProduction) -> dict:
        """Parse call argument token into dictionary format.

        This method processes a YaccProduction token representing a call argument
        and converts it into an empty dictionary structure for further processing.

        :param token: YaccProduction object holding the content defined in decorator.
        :return: Empty dictionary representing a call argument structure.
        """
        dictionary = {}
        return dictionary

    @_("LPAREN int_const_expr RPAREN")  # type: ignore
    def call_arg(self, token: YaccProduction) -> dict:
        """Parse call argument from token production.

        Extracts the integer constant expression from a YaccProduction token and wraps it
        in a dictionary structure for call argument representation.

        :param token: YaccProduction object containing the parsed content from grammar rule.
        :return: Dictionary with 'argument' key containing the integer constant expression.
        """
        return {"argument": token.int_const_expr}

    @_("empty")  # type: ignore
    def call_arg(self, token: YaccProduction) -> dict:
        """Parse call argument from token production.

        Extracts and returns the empty call argument content from the provided
        YaccProduction token object used in the SLY parser grammar rules.

        :param token: YaccProduction object containing parsed grammar content.
        :return: Empty call argument dictionary extracted from the token.
        """
        return token.empty

    @_("JUMP_SP int_const_expr call_target call_arg")  # type: ignore
    def jump_sp_stmt(self, token: YaccProduction) -> dict:
        """Parse jump statement with stack pointer register specification.

        Processes a jump statement that includes a stack pointer register assignment
        along with the target address and optional arguments.

        :param token: YaccProduction object containing parsed tokens with int_const_expr,
                      call_target, and call_arg attributes.
        :return: Dictionary containing the jump statement configuration with spreg,
                 target, and argument specifications.
        """
        dictionary: dict = {"jump": {}}
        dictionary["jump"]["spreg"] = token.int_const_expr
        dictionary["jump"].update(token.call_target)
        dictionary["jump"].update(token.call_arg)
        return dictionary

    @_("RESET")  # type: ignore
    def reset_stmt(self, token: YaccProduction) -> dict:
        """Parse reset statement from boot descriptor file.

        Parses a reset command that instructs the target device to perform a system reset
        during secure boot execution.

        :param token: YaccProduction object containing parsed token data from the grammar rule.
        :return: Dictionary with reset command structure for secure boot file generation.
        """
        return {"reset": {}}

    @_("FROM SOURCE_NAME LBRACE in_from_stmt RBRACE")  # type: ignore
    def from_stmt(self, token: YaccProduction) -> None:
        """Parse 'from' statement rule (currently unsupported).

        This parser rule handles 'from' statements in the build description language.
        The functionality is not implemented and will raise an error when encountered.

        :param token: YaccProduction object containing the parsed token content and context.
        :raises SPSDKError: Always raised as 'from' statements are not supported.
        """
        self.error(token, ": from statement not supported.")

    @_("basic_stmt SEMI")  # type: ignore
    def in_from_stmt(self, token: YaccProduction) -> list:
        """Parse 'from' statement in SB2 boot image configuration.

        Extracts the basic statement content from a 'from' statement token during
        the parsing of SB2 boot image configuration files.

        :param token: YaccProduction object containing the parsed statement content.
        :return: List of basic statements extracted from the token.
        """
        return token.basic_stmt

    @_("if_stmt")  # type: ignore
    def in_from_stmt(self, token: YaccProduction) -> list:
        """Parse 'from' statement in SB2 boot image configuration.

        Extracts and processes the 'from' statement content from the parser token,
        which typically specifies source locations or references in boot image scripts.

        :param token: Parser production token containing the 'from' statement content.
        :return: List of parsed statement objects from the 'from' clause.
        """
        return token.if_stmt

    @_("empty")  # type: ignore
    def in_from_stmt(self, token: YaccProduction) -> list:
        """Parse 'from' statement in boot descriptor language.

        This method handles the parsing of 'from' statements which specify source locations
        for data or commands in the secure boot file format.

        :param token: YaccProduction object containing the parsed token content from the grammar rule.
        :return: Empty list as placeholder for future implementation or to maintain parser structure.
        """
        return []

    @_("MODE int_const_expr")  # type: ignore
    def mode_stmt(self, token: YaccProduction) -> dict:
        """Parse mode statement from BD file.

        This parser rule is currently not supported and will raise an error when encountered.

        :param token: YaccProduction object holding the parsed content from the grammar rule.
        :raises SPSDKError: Always raised as mode statements are not supported.
        :return: Empty dictionary as placeholder return value.
        """
        self.error(token, ": mode statement is not supported")
        dictionary: dict = {}
        return dictionary

    @_("message_type STRING_LITERAL")  # type: ignore
    def message_stmt(self, token: YaccProduction) -> dict:
        """Parse message statement from boot descriptor file.

        This parser rule is currently not supported and returns an empty dictionary
        as a placeholder for future implementation.

        :param token: YaccProduction object containing the parsed token content.
        :return: Empty dictionary as message statements are not yet implemented.
        """
        dictionary: dict = {}
        return dictionary

    @_("INFO", "WARNING", "ERROR")  # type: ignore
    def message_type(self, token: YaccProduction) -> dict:
        """Parse message type rule from BD file.

        This parser rule is currently not supported and will raise an error when encountered.

        :param token: YaccProduction object holding the parsed content from the grammar rule.
        :raises SPSDKError: Always raised as message type rules are not supported.
        :return: Empty dictionary as placeholder return value.
        """
        self.error(token, ": info/warning/error messages are not supported.")
        dictionary: dict = {}
        return dictionary

    @_("KEYSTORE_TO_NV mem_opt address_or_range")  # type: ignore
    def keystore_stmt(self, token: YaccProduction) -> dict:
        """Parse keystore statement from BD file tokens.

        Processes a KEYSTORE_TO_NV statement token and extracts memory options
        and address/range information into a structured dictionary format.

        :param token: YaccProduction object containing parsed keystore statement tokens
        :return: Dictionary with keystore statement data including memory options and address range
        """
        dictionary = {token.KEYSTORE_TO_NV: {}}
        dictionary[token.KEYSTORE_TO_NV].update(token.mem_opt)
        dictionary[token.KEYSTORE_TO_NV].update(token.address_or_range)
        return dictionary

    @_("KEYSTORE_FROM_NV mem_opt address_or_range")  # type: ignore
    def keystore_stmt(self, token: YaccProduction) -> dict:
        """Parse keystore statement from boot descriptor file.

        Processes a keystore statement token and extracts memory options and address/range
        information into a structured dictionary format.

        :param token: YaccProduction object containing parsed keystore statement with memory
            options and address/range data.
        :return: Dictionary with keystore statement content including memory options and
            address/range configuration.
        """
        dictionary = {token.KEYSTORE_FROM_NV: {}}
        dictionary[token.KEYSTORE_FROM_NV].update(token.mem_opt)
        dictionary[token.KEYSTORE_FROM_NV].update(token.address_or_range)
        return dictionary

    @_("IDENT")  # type: ignore
    def mem_opt(self, token: YaccProduction) -> None:
        """Parse memory optimization option from boot descriptor.

        This parser rule handles memory optimization syntax in boot descriptor files.
        Currently this syntax is not fully supported and returns a dictionary with
        the memory option identifier.

        :param token: YaccProduction object containing the parsed token content with
            IDENT attribute representing the memory option identifier.
        :return: Dictionary containing the memory option identifier under 'mem_opt' key.
        """
        # search in variables for token.IDENT variable and get it's value
        return {"mem_opt": token.IDENT}

    @_("'@' int_const_expr")  # type: ignore
    def mem_opt(self, token: YaccProduction) -> dict:
        """Parse memory option token into dictionary format.

        Processes a YACC production token containing memory option data and converts
        it into a structured dictionary representation.

        :param token: YACC production token object containing memory option content.
        :return: Dictionary with 'mem_opt' key containing the integer constant expression value.
        """
        dictionary = {"mem_opt": token.int_const_expr}
        return dictionary

    @_("empty")  # type: ignore
    def mem_opt(self, token: YaccProduction) -> None:
        """Parse memory optimization directive from BD file.

        This parser rule handles memory optimization syntax which is currently
        not supported in the implementation.

        :param token: YaccProduction object containing the parsed tokens and grammar rule content.
        """
        return token.empty

    @_("VERSION_CHECK sec_or_nsec fw_version")  # type: ignore
    def version_stmt(self, token: YaccProduction) -> dict:
        """Parse version statement from SB2 boot descriptor file.

        Processes a version check statement token and converts it into a structured
        dictionary format containing security configuration and firmware version data.

        :param token: YaccProduction object containing parsed version statement data.
        :return: Dictionary with version check statement configuration including security
                 and firmware version settings.
        """
        dictionary: dict = {token.VERSION_CHECK: {}}
        dictionary[token.VERSION_CHECK].update(token.sec_or_nsec)
        dictionary[token.VERSION_CHECK].update(token.fw_version)
        return dictionary

    @_("SEC")  # type: ignore
    def sec_or_nsec(self, token: YaccProduction) -> dict:
        """Parse secure or non-secure version check type.

        This parser rule processes tokens to create a dictionary containing
        version check type information with a default secure type value.

        :param token: YaccProduction object holding the parsed content from grammar rule.
        :return: Dictionary with version check type configuration, containing 'ver_type' key set to 0.
        """
        dictionary = {"ver_type": 0}
        return dictionary

    @_("NSEC")  # type: ignore
    def sec_or_nsec(self, token: YaccProduction) -> dict:
        """Parse secure or non-secure version check rule.

        Processes a parser token to create a dictionary containing version check type
        information for secure boot file parsing.

        :param token: YaccProduction object holding the parsed content from grammar rule.
        :return: Dictionary with version check type set to secure (value 1).
        """
        dictionary = {"ver_type": 1}
        return dictionary

    @_("int_const_expr")  # type: ignore
    def fw_version(self, token: YaccProduction) -> dict:
        """Parse firmware version from SB2 file token.

        This method processes a YACC production token containing firmware version
        information and converts it into a structured dictionary format.

        :param token: YACC production token containing firmware version data
        :return: Dictionary with 'fw_version' key containing the parsed version value
        """
        dictionary = {"fw_version": token.int_const_expr}
        return dictionary

    @_("IF bool_expr LBRACE statement RBRACE else_stmt")  # type: ignore
    def if_stmt(self, token: YaccProduction) -> list:
        """Parse if statement rule in SLY parser.

        This parser rule is currently not supported and will raise an error when encountered.
        The method is a placeholder for future if/if-else statement functionality.

        :param token: YaccProduction object holding the parsed content from grammar rule.
        :raises SPSDKError: Always raised as if statements are not currently supported.
        :return: List of statements from either if block or else block (unreachable due to error).
        """
        self.error(token, ": if & if-else statement is not supported.")
        if token.bool_expr:
            return token.statement

        return token.else_stmt

    @_("ELSE LBRACE statement RBRACE")  # type: ignore
    def else_stmt(self, token: YaccProduction) -> list:
        """Parse else statement in SLY grammar rule.

        Processes the else statement token from the parser and extracts the statement content
        for further processing in the secure boot file generation.

        :param token: YaccProduction object containing the parsed else statement content.
        :return: List of else statements extracted from the token.
        """
        return token.statement

    @_("ELSE if_stmt")  # type: ignore
    def else_stmt(self, token: YaccProduction) -> list:
        """Parse else statement in SLY grammar rule.

        Processes the else statement token from the grammar parser and extracts
        the if statement content.

        :param token: YaccProduction object containing parsed grammar content.
        :return: List of else if statements extracted from the token.
        """
        return token.if_stmt

    @_("empty")  # type: ignore
    def else_stmt(self, token: YaccProduction) -> list:
        """Parse else statement in SB2 file grammar.

        Handles the 'else' clause in conditional statements within the SB2 file format.
        Returns an empty list as else statements don't contain executable commands.

        :param token: YaccProduction object containing the parsed token content.
        :return: Empty list representing no commands in else clause.
        """
        list_ = []
        return list_

    @_("STRING_LITERAL")  # type: ignore
    def const_expr(self, token: YaccProduction) -> str:
        """Parse constant expression from string literal token.

        Extracts the string content from a STRING_LITERAL token by removing the surrounding quotes.

        :param token: YaccProduction object containing the parsed token with STRING_LITERAL content.
        :return: String content with surrounding quotes removed.
        """
        return token.STRING_LITERAL[1:-1]

    @_("bool_expr")  # type: ignore
    def const_expr(self, token: YaccProduction) -> bool:
        """Parse constant expression from token.

        Evaluates a boolean expression token and returns its boolean value result.

        :param token: YaccProduction object holding the parsed content from grammar rule.
        :return: Boolean value as a result of constant expression evaluation.
        """
        return token.bool_expr

    @_("expr")  # type: ignore
    def int_const_expr(self, token: YaccProduction) -> Number:
        """Parse integer constant expression from grammar rule.

        Processes a grammar production token containing an integer constant expression
        and extracts the underlying expression value.

        :param token: Grammar production token containing the parsed expression content.
        :return: Number value extracted from the expression.
        """
        return token.expr

    @_("DEFINED LPAREN IDENT RPAREN")  # type: ignore
    def bool_expr(self, token: YaccProduction) -> bool:
        """Evaluate boolean expression for identifier existence.

        Parser rule that checks if an identifier is defined in the variables dictionary.

        :param token: YaccProduction object containing the parsed identifier token.
        :return: True if the identifier exists in variables, False otherwise.
        """
        return token.IDENT in self._variables

    @_(  # type: ignore
        "bool_expr LT bool_expr",
        "bool_expr LE bool_expr",
        "bool_expr GT bool_expr",
        "bool_expr GE bool_expr",
        "bool_expr EQ bool_expr",
        "bool_expr NE bool_expr",
        "bool_expr LAND bool_expr",
        "bool_expr LOR bool_expr",
        "LPAREN bool_expr RPAREN",
    )
    def bool_expr(self, token: YaccProduction) -> bool:
        """Parse boolean expression from SLY parser token.

        Evaluates boolean expressions including comparison operators (<, <=, >, >=, ==, !=)
        and logical operators (&&, ||). Returns the result of the boolean operation or
        the token value if no operator is present.

        :param token: YaccProduction object containing parsed expression components.
        :return: Result of the boolean expression evaluation.
        """
        operator = token[1]
        if operator == "<":
            return token.bool_expr0 < token.bool_expr1
        if operator == "<=":
            return token.bool_expr0 <= token.bool_expr1
        if operator == ">":
            return token.bool_expr0 > token.bool_expr1
        if operator == ">=":
            return token.bool_expr0 >= token.bool_expr1
        if operator == "==":
            return token.bool_expr0 == token.bool_expr1
        if operator == "!=":
            return token.bool_expr0 != token.bool_expr1
        if operator == "&&":
            return token.bool_expr0 and token.bool_expr1
        if operator == "||":
            return token.bool_expr0 or token.bool_expr1

        return token[1]

    @_("int_const_expr")  # type: ignore
    def bool_expr(self, token: YaccProduction) -> bool:
        """Parse boolean expression from token.

        Extracts and returns the boolean value from the integer constant expression
        contained within the provided parser token.

        :param token: YaccProduction object containing the parsed content from grammar rule.
        :return: Boolean value extracted from the integer constant expression.
        """
        return token.int_const_expr

    @_("LNOT bool_expr")  # type: ignore
    def bool_expr(self, token: YaccProduction) -> bool:
        """Parse boolean expression with logical NOT operator.

        This parser rule handles the negation of boolean expressions in the SB2 boot image
        configuration language, returning the inverted boolean value.

        :param token: YaccProduction object containing the parsed boolean expression to negate.
        :return: Inverted boolean value of the input expression.
        """
        return not token.bool_expr

    @_("IDENT LPAREN SOURCE_NAME RPAREN")  # type: ignore
    def bool_expr(self, token: YaccProduction) -> bool:
        """Parse boolean expression rule.

        This parser rule is currently not supported and will raise an error when encountered.
        The rule appears to handle IDENT ( SOURCE_NAME ) syntax but its exact purpose is unclear.

        :param token: YaccProduction object holding the content defined in decorator.
        :raises SPSDKError: When the boolean expression rule is encountered.
        :return: Always returns False as this rule is not supported.
        """
        # I've absolutely no clue, what this rule can mean or be for???
        self.error(token, ": IDENT ( SOURCE_NAME ) is not supported.")
        return False

    @_(  # type: ignore
        "expr PLUS expr",
        "expr MINUS expr",
        "expr TIMES expr",
        "expr DIVIDE expr",
        "expr MOD expr",
        "expr LSHIFT expr",
        "expr RSHIFT expr",
        "expr AND expr",
        "expr OR expr",
        "expr XOR expr",
        "expr PERIOD INT_SIZE",
        "LPAREN expr RPAREN",
    )
    def expr(self, token: YaccProduction) -> Number:
        """Parse arithmetic and bitwise expressions from SB2 boot image file.

        Evaluates mathematical expressions including arithmetic operations (+, -, *, /, %),
        bitwise operations (<<, >>, &, |, ^), size qualifiers (.w, .h, .b), and parentheses.

        :param token: YaccProduction object containing parsed tokens and operands from grammar rule.
        :return: Computed numerical result of the expression evaluation.
        """
        operator = token[1]
        if operator == "+":
            return token.expr0 + token.expr1
        if operator == "-":
            return token.expr0 - token.expr1
        if operator == "*":
            return token.expr0 - token.expr1
        if operator == "/":
            return token.expr0 // token.expr1
        if operator == "%":
            return token.expr0 % token.expr1
        if operator == "<<":
            return token.expr0 << token.expr1
        if operator == ">>":
            return token.expr0 >> token.expr1
        if operator == "&":
            return token.expr0 & token.expr1
        if operator == "|":
            return token.expr0 | token.expr1
        if operator == "^":
            return token.expr0 ^ token.expr1
        if operator == ".":
            char = token.INT_SIZE
            if char == "w":
                return token[0] & 0xFFFF
            if char == "h":
                return token[0] & 0xFF
            if char == "b":
                return token[0] & 0xF
        # LPAREN expr RPAREN
        return token[1]

    @_("INT_LITERAL")  # type: ignore
    def expr(self, token: YaccProduction) -> Number:
        """Parse expression rule for integer literals.

        Extracts integer literal values from parser tokens during SB2 file parsing.

        :param token: YaccProduction object containing the parsed token content.
        :return: Integer number extracted from the token.
        """
        return token.INT_LITERAL

    @_("IDENT")  # type: ignore
    def expr(self, token: YaccProduction) -> Number:
        """Parse expression token to resolve identifier value.

        Searches through variables to find the value associated with the given identifier.
        If no matching variable is found, returns the identifier itself.

        :param token: YaccProduction object containing the identifier to resolve.
        :return: Number value associated with the identifier, or the identifier if not found.
        """
        # we need to convert the IDENT into a value stored under that identifier
        # search the variables and check, whether there is a name of IDENT
        for var in self._variables:
            if var.name == token.IDENT:
                return var.value

        return token.IDENT

    @_("symbol_ref")  # type: ignore
    def expr(self, token: YaccProduction) -> None:
        """Parse expression rule (currently unsupported).

        This parser rule is not implemented and will raise an error when encountered.
        Expression symbol references are not supported in the current implementation.

        :param token: YaccProduction object containing the parsed token content.
        :raises SPSDKError: Always raised as expression parsing is not supported.
        """
        self.error(token, ": symbol reference is not supported.")

    @_("unary_expr")  # type: ignore
    def expr(self, token: YaccProduction) -> Number:
        """Parse expression rule to extract unary expression result.

        This method processes a parser token containing a unary expression and returns
        the evaluated number result from the expression.

        :param token: YaccProduction object holding the parsed content from grammar rule.
        :return: Number result from evaluating the unary expression.
        """
        return token.unary_expr

    @_("SIZEOF LPAREN symbol_ref RPAREN")  # type: ignore
    def expr(self, token: YaccProduction) -> None:
        """Handle sizeof operator expression in parser.

        This parser rule is currently not supported and will raise an error when encountered.
        The sizeof operator functionality is not implemented in the current parser version.

        :param token: YaccProduction object containing the parsed token content and context.
        :raises SPSDKError: Always raised as sizeof operator is not supported.
        """
        self.error(token, ": sizeof operator is not supported")

    @_("SIZEOF LPAREN IDENT RPAREN")  # type: ignore
    def expr(self, token: YaccProduction) -> None:
        """Handle unsupported sizeof operator expression.

        This parser rule is intentionally not implemented as the sizeof operator
        is not supported in the current SB2 file format specification.

        :param token: YaccProduction object containing the parsed expression tokens.
        :raises SPSDKError: Always raised when this unsupported expression is encountered.
        """
        self.error(token, ": sizeof operator is not supported")

    @_("PLUS expr", "MINUS expr")  # type: ignore
    def unary_expr(self, token: YaccProduction) -> Number:
        """Parse unary expression with optional sign operator.

        Processes unary expressions that may contain a sign (+ or -) followed by a number.
        Applies the sign operation to the numeric value if present.

        :param token: YaccProduction object containing the parsed unary expression tokens.
        :return: Number object representing the result of the unary expression evaluation.
        """
        sign = token[0]
        number = token.expr
        if sign == "-":
            number = -number

        return number

    @_("")  # type: ignore
    def empty(self, token: YaccProduction) -> dict:
        """Parse empty production rule.

        This method handles empty grammar productions in the SLY parser, returning
        an empty dictionary as the semantic value.

        :param token: YaccProduction object containing parser state and matched tokens.
        :return: Empty dictionary representing no parsed content.
        """
        dictionary: dict = {}
        return dictionary

    @staticmethod
    def _find_column(text: str, token: YaccProduction) -> int:
        """Find the column position of a token in the input text.

        The method calculates the column number by finding the last newline character
        before the token's position and computing the offset from that position.

        :param text: Input file content being parsed.
        :param token: YaccProduction object holding the token content and position.
        :return: Column number (1-based) of the token in the input text.
        """
        last_cr = text.rfind("\n", 0, token.index)
        if last_cr < 0:
            last_cr = 0
        else:
            last_cr += 1
        column = (token.index - last_cr) + 1
        return column

    @staticmethod
    def _find_line(text: str, line_num: int) -> str:
        """Find the line in text based on line number.

        :param text: Text to search for the specified line.
        :param line_num: Zero-based line number to retrieve.
        :return: Content of the specified line from the text.
        """
        lines = text.split("\n")

        return lines[line_num]

    def error(  # pylint: disable=redundant-returns-doc
        self, token: YaccProduction, msg: str = ""
    ) -> YaccProduction:  # pylint: disable=arguments-differ
        """Handle syntax errors during BD file parsing.

        On syntax error, sets an error flag and raises an SPSDKError with detailed
        location information including line number, column, and context.

        :param token: Token object containing parsing context and position information.
        :param msg: Additional error message to append to the standard error format.
        :raises SPSDKError: Always raised with formatted error message including file location.
        :return: Never returns as it always raises an exception.
        """
        self._parse_error = True

        if token:
            lineno = getattr(token, "lineno", -1)
            if lineno != -1:
                column = BDParser._find_column(self._input, token)
                error_line = BDParser._find_line(self._input, lineno - 1)
                raise SPSDKError(
                    f"bdcompiler:{lineno}:{column}: error{msg}\n\n{error_line}\n"
                    + (column - 1) * " "
                    + "^\n"
                )

            raise SPSDKError(f"bdcompiler: error{msg}\n")

        raise SPSDKError("bdcompiler: unspecified error.")
