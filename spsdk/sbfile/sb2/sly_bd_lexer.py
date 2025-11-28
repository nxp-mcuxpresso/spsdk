#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause


"""SPSDK SLY-based lexer for Boot Descriptor (BD) command files.

This module provides lexical analysis functionality for parsing Boot Data command files
used in secure boot processes. It defines tokens and lexical rules for BD file syntax
using the SLY lexer framework.
"""

from typing import Union

from sly import Lexer
from sly.lex import Token


# ruff: noqa: F821
# pylint: disable=undefined-variable,invalid-name,no-self-use
# undefined-variable : the lexer uses '_' as a decorator, which throws undefined
#   variable error. We can't do much with it.
# invalid-name : tokens are defined as upper case. However this violates the
#   snake cae naming style. We can't do much, as this is required by the lexer.
# no-self-use : the public methods must be defined as class methods although
#   the self is not used at all.
class Variable:
    """Command file variable representation for SB2 lexical analysis.

    This class encapsulates variable definitions found in SB2 command files,
    storing the variable name, type token, and associated value for use during
    lexical parsing and processing.
    """

    def __init__(self, name: str, token: str, value: Union[str, int, float]) -> None:
        """Initialize identifier with name, token type, and value.

        :param name: Name of the identifier (variable).
        :param token: Type of variable (option, constant etc.).
        :param value: The content of the variable.
        """
        self.name = name
        self.t = token
        self.value = value

    def __str__(self) -> str:
        """Return string representation of the variable.

        The string contains variable name, type, and value in format:
        "<var_name>, <var_type>, <var_value>"

        :return: Formatted string with variable information.
        """
        return f"{self.name}, {self.t}, {self.value}"


class BDLexer(Lexer):
    """Lexer for Boot Descriptor (BD) files used in SB2.1 format.

    This class provides tokenization and parsing capabilities for Boot Descriptor
    files, which contain commands and configuration for secure boot operations.
    It handles reserved keywords, identifiers, literals, and maintains source
    references for proper parsing context.

    :cvar reserved: Dictionary mapping BD file keywords to token types.
    """

    def __init__(self) -> None:
        """Initialize the Variables container.

        Creates an empty list to store Variable objects that will be used
        for managing variables in the SB2 file processing.
        """
        self._sources: list[Variable] = []

    def cleanup(self) -> None:
        """Reset the lexer's internal state to initial conditions.

        Clears all internal data sources and prepares the lexer for reuse or reinitialization.
        """
        self._sources.clear()

    def add_source(self, source: Variable) -> None:
        """Add source identifier to the sources list.

        Appends a source identifier that was defined in the sources block of a BD file
        to the internal sources list for later processing.

        :param source: Source identifier defined under sources block in BD file.
        """
        self._sources.append(source)

    # List of reserved keywords
    reserved = {
        "call": "CALL",
        "constants": "CONSTANTS",
        "extern": "EXTERN",
        "erase": "ERASE",
        "false": "FALSE",
        "filters": "FILTERS",
        "from": "FROM",
        "jump": "JUMP",
        "load": "LOAD",
        "mode": "MODE",
        "else": "ELSE",
        "info": "INFO",
        "error": "ERROR",
        "enable": "ENABLE",
        "keywrap": "KEYWRAP",
        "keystore_to_nv": "KEYSTORE_TO_NV",
        "keystore_from_nv": "KEYSTORE_FROM_NV",
        "all": "ALL",
        "no": "NO",
        "options": "OPTIONS",
        "raw": "RAW",
        "section": "SECTION",
        "sources": "SOURCES",
        "switch": "SWITCH",
        "true": "TRUE",
        "yes": "YES",
        "if": "IF",
        "defined": "DEFINED",
        "warning": "WARNING",
        "sizeof": "SIZEOF",
        "unsecure": "UNSECURE",
        "jump_sp": "JUMP_SP",
        "keyblob": "KEYBLOB",
        "reset": "RESET",
        "encrypt": "ENCRYPT",
        "version_check": "VERSION_CHECK",
        "sec": "SEC",
        "nsec": "NSEC",
    }

    # List of token names. This is always required
    tokens = [
        "COMMENT",
        "IDENT",
        "SOURCE_NAME",
        "BINARY_BLOB",
        "INT_LITERAL",
        "STRING_LITERAL",
        "RANGE",
        "ASSIGN",
        "INT_SIZE",
        "SECTION_NAME",
        #'SYMBOL_REF', replaced with a non-terminal symbol_ref
        # Operators (+,-,*,/,%,|,&,~,^,<<,>>, ||, &&, !, <, <=, >, >=, ==, !=)
        "PLUS",
        "MINUS",
        "TIMES",
        "DIVIDE",
        "MOD",
        "OR",
        "AND",
        "NOT",
        "XOR",
        "LSHIFT",
        "RSHIFT",
        "LOR",
        "LAND",
        "LNOT",
        "LT",
        "LE",
        "GT",
        "GE",
        "EQ",
        "NE",
        # Delimiters ( ) { } , . ; :
        "LPAREN",
        "RPAREN",
        "LBRACE",
        "RBRACE",
        "COMMA",
        "PERIOD",
        "SEMI",
        "COLON",
        # Special characters
        "QUESTIONMARK",
        "DOLLAR",
    ] + list(reserved.values())

    literals = {"@"}

    # A regular expression rules with some action code
    # The order of these functions MATTER!!! Make sure you know what you are
    # doing, when changing the order of function declarations!!!
    @_(r"(//.*)|(/\*(.|\s)*?\*/)|(\#.*)")  # type: ignore
    def COMMENT(self, token: Token) -> None:
        """Token rule to detect comments including multiline comments.

        Handles C/C++ style comments ('/* */', '//') and bash-style comments ('#').
        Updates line numbering to account for multiline comments by incrementing
        the line counter based on newlines within the comment content.

        :param token: Token object containing the matched comment text.
        """
        # Multiline comments are counted as a single line. This causes us troubles
        # in t_newline(), which treats the multiline comment as a single line causing
        # a mismatch in the final line position.
        # From this perspective we increment the linenumber here by the total
        # number of lines - 1 (the subtracted 1 gets counted byt t_newline)
        self.lineno += len(token.value.split("\n")) - 1

    # It's not possible to detect INT_SIZE token while whitespaces are present between period and
    # letter in real use case, because of regex engine limitation in positive lookbehind.
    @_(r"(?<=(\d|[0-9a-fA-F])\.)[ \t]*[whb]")  # type: ignore
    def INT_SIZE(self, token: Token) -> Token:
        """Token rule to detect numbers appended with w/h/b size specifiers.

        Example:
        my_number = 4.b
        my_number = 1.h
        my_number = 3.w
        The w/h/b defines size (Byte, Halfword, Word). This should be taken into
        account during number computation.

        :param token: Token matching int size specifier.
        :return: Token representing the size of int literal.
        """
        return token

    @_(r"[_a-zA-Z][_a-zA-Z0-9]*")  # type: ignore
    def IDENT(self, token: Token) -> Token:
        """Token rule to detect identifiers.

        A valid identifier can start either with underscore or a letter followed
        by any numbers of underscores, letters and numbers.
        If the name of an identifier is from the set of reserved keywords, the
        token type is replaced with the keyword name, otherwise the token is
        of type 'IDENT'.
        Values of type TRUE/YES, FALSE/NO are replaced by 1 or 0 respectively.

        :param token: Token matching an identifier pattern.
        :return: Token representing identifier with appropriate type and value.
        """
        # it may happen that we find an identifier, which is a keyword, in such
        # a case remap the type from IDENT to reserved word (i.e. keyword)
        token_type = self.reserved.get(token.value, "IDENT")
        if token_type in ["TRUE", "YES"]:
            token.type = "INT_LITERAL"
            token.value = 1
        elif token_type in ["FALSE", "NO"]:
            token.type = "INT_LITERAL"
            token.value = 0
        else:
            token.type = token_type
            # check, whether the identifier is under sources, in such case
            # change the type to SOURCE_NAME
            for source in self._sources:
                if source.name == token.value:
                    token.type = "SOURCE_NAME"
                    break
        return token

    @_(r"\b([0-9]+[K]?|0[xX][0-9a-fA-F]+)\b|'.*'")  # type: ignore
    def INT_LITERAL(self, token: Token) -> Token:
        """Process integer literal tokens and convert them to numeric values.

        Supports decimal numbers, hexadecimal numbers, string literals in single quotes,
        and decimal numbers with 'K' suffix (multiplied by 1024).
        Supported formats:
        - Decimal: 1024, -256
        - Hexadecimal: 0x25
        - With K suffix: 1K (equals 1024)
        - String literals: 'text' (converted to hex representation)

        :param token: Token object containing the matched integer literal pattern.
        :return: Token object with numeric value assigned to the value attribute.
        """
        number = token.value
        if number[0] == "'" and number[-1] == "'":
            # transform 'dude' into '0x64756465'
            number = "0x" + bytearray(number[1:-1], "utf-8").hex()
            number = int(number, 0)
        elif number[-1] == "K":
            number = int(number[:-1], 0) * 1024
        else:
            number = int(number, 0)

        token.value = number
        return token

    @_(r"\$[\w\.\*\?\-\^\[\]]+")  # type: ignore
    def SECTION_NAME(self, token: Token) -> Token:
        """Token rule to detect section names.

        Section names start with a dollar sign ($) followed by a glob-type expression that
        can match any number of ELF sections.

        Examples:
            $section_[ab]
            $math*

        :param token: Token matching section name pattern.
        :return: Token representing section name.
        """
        return token

    @_(r"\{\{([0-9a-fA-F]{2}| )+\}\}")  # type: ignore
    def BINARY_BLOB(self, token: Token) -> Token:
        """Process binary blob token from lexer input.

        A binary blob is a sequence of hexadecimal bytes enclosed in double curly braces.
        The method extracts the hexadecimal content and removes whitespace formatting.

        Example:
        {{aa bb cc 1F 3C}} becomes "aabbcc1F3C"

        :param token: Token object matching binary blob pattern from lexer.
        :return: Modified token with cleaned hexadecimal string value.
        """
        # return just the content between braces
        value = token.value[2:-2]

        token.value = "".join(value.split())
        return token

    # A string containing ignored characters (spaces and tabs)
    ignore = " \t"

    @_(r"\n")  # type: ignore
    def newline(self, token: Token) -> None:
        """Process new line token and increment line counter.

        Updates the internal line number counter based on the number of newline
        characters found in the token value.

        :param token: Token containing newline character(s) to process.
        """
        self.lineno += len(token.value)

    # Operators regular expressions
    PLUS = r"\+"
    MINUS = r"-"
    TIMES = r"\*"
    DIVIDE = r"/"
    MOD = r"%"
    NOT = r"~"
    XOR = r"\^"
    LSHIFT = r"<<"
    RSHIFT = r">>"
    LOR = r"\|\|"
    OR = r"\|"
    LAND = r"&&"
    AND = r"&"
    LE = r"<="
    LT = r"<"
    GE = r">="
    GT = r">"
    EQ = r"=="
    NE = r"!="
    LNOT = r"!"

    # Tokens regular expressions
    STRING_LITERAL = r"\".*\""
    RANGE = r"\.\."

    # Assignment operator regular expressions
    ASSIGN = r"="

    # Delimiters regular expressions
    LPAREN = r"\("
    RPAREN = r"\)"
    LBRACE = r"\{"
    RBRACE = r"\}"
    COMMA = r","
    PERIOD = r"\."
    SEMI = r";"
    COLON = r":"

    # Special characters
    QUESTIONMARK = r"\?"
    DOLLAR = r"\$"

    # Error handling rule
    def error(self, t: Token) -> Token:
        """Handle token error during lexical analysis.

        The lexing index is incremented so lexing can continue, however, an
        error token is returned. The token contains the whole text starting
        with the detected error.

        :param t: Invalid token that caused the error.
        :return: The invalid token with updated value.
        """
        self.index += 1
        t.value = t.value[0]
        return t
