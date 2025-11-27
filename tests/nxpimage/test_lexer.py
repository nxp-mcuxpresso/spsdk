#!/usr/bin/env python
# -*- coding: UTF-8 -*-
#
# Copyright 2021-2023,2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK BD lexer unit tests.

This module contains comprehensive unit tests for the BD (Boot Data) lexer
functionality used in SB2 (Secure Binary 2) file processing within SPSDK.
Tests validate lexical analysis of boot data commands, tokenization,
and variable handling.
"""

from typing import Any

import pytest

from spsdk.sbfile.sb2.sly_bd_lexer import BDLexer, Variable


class myToken:
    """Token representation for lexical analysis.

    This class provides a simple token structure that stores type and value
    information in a dictionary-like interface, commonly used in parsing
    and lexical analysis operations within SPSDK image processing.
    """

    def __init__(self, t: str, value: Any) -> None:
        """Initialize a new instance with type and value.

        Creates a new object with internal storage for type and value information
        that can be accessed through the _values dictionary.

        :param t: The type identifier for this instance.
        :param value: The value to be stored, can be of any type.
        """
        self._values = {"type": t, "value": value}

    def __getitem__(self, item: str) -> Any:
        """Get item value by key.

        Retrieves a value from the internal values dictionary using the provided key.

        :param item: The key to look up in the values dictionary.
        :raises KeyError: If the specified key does not exist in the values dictionary.
        :return: The value associated with the given key.
        """
        return self._values[item]


def test_lexer() -> None:
    """Test BDLexer tokenization functionality.

    This test verifies that the BDLexer correctly tokenizes a comprehensive test string
    containing various token types including literals, identifiers, operators, comments,
    and special constructs. The test compares actual tokenization output against expected
    token types and values to ensure lexer accuracy.

    :raises AssertionError: When tokenized output doesn't match expected tokens.
    """
    test_string = r"""
    false no true yes
    // some comment
    /* multiline
    comment
    */
    # bash style comment
    1.h 2.w 3.b
    _identifier identifier2 id3nt1f13r id_En_t1_f13R
    @9 @0x008
    10K 0x80 0X1122 'abc'
    $section.section_name $section.[abc] $section* $section[^abc]?
    {{00 aa bb 11}} {{22Af1C}}
    +-*/%|&~^<<>>||&&!<><=>===!=
    "string literal"
    ..
    =
    ,.;:
    {}()
    ?
    $
    1_invalid
    """

    expected_tokens = [
        myToken("INT_LITERAL", 0),
        myToken("INT_LITERAL", 0),
        myToken("INT_LITERAL", 1),
        myToken("INT_LITERAL", 1),
        myToken("INT_LITERAL", 1),
        myToken("PERIOD", "."),
        myToken("INT_SIZE", "h"),
        myToken("INT_LITERAL", 2),
        myToken("PERIOD", "."),
        myToken("INT_SIZE", "w"),
        myToken("INT_LITERAL", 3),
        myToken("PERIOD", "."),
        myToken("INT_SIZE", "b"),
        myToken("IDENT", "_identifier"),
        myToken("IDENT", "identifier2"),
        myToken("IDENT", "id3nt1f13r"),
        myToken("IDENT", "id_En_t1_f13R"),
        myToken("@", "@"),
        myToken("INT_LITERAL", 9),
        myToken("@", "@"),
        myToken("INT_LITERAL", 8),
        myToken("INT_LITERAL", 10240),
        myToken("INT_LITERAL", 128),
        myToken("INT_LITERAL", 4386),
        myToken("INT_LITERAL", 6382179),
        myToken("SECTION_NAME", "$section.section_name"),
        myToken("SECTION_NAME", "$section.[abc]"),
        myToken("SECTION_NAME", "$section*"),
        myToken("SECTION_NAME", "$section[^abc]?"),
        myToken("BINARY_BLOB", "00aabb11"),
        myToken("BINARY_BLOB", "22Af1C"),
        myToken("PLUS", "+"),
        myToken("MINUS", "-"),
        myToken("TIMES", "*"),
        myToken("DIVIDE", "/"),
        myToken("MOD", "%"),
        myToken("OR", "|"),
        myToken("AND", "&"),
        myToken("NOT", "~"),
        myToken("XOR", "^"),
        myToken("LSHIFT", "<<"),
        myToken("RSHIFT", ">>"),
        myToken("LOR", "||"),
        myToken("LAND", "&&"),
        myToken("LNOT", "!"),
        myToken("LT", "<"),
        myToken("GT", ">"),
        myToken("LE", "<="),
        myToken("GE", ">="),
        myToken("EQ", "=="),
        myToken("NE", "!="),
        myToken("STRING_LITERAL", '"string literal"'),
        myToken("RANGE", ".."),
        myToken("ASSIGN", "="),
        myToken("COMMA", ","),
        myToken("PERIOD", "."),
        myToken("SEMI", ";"),
        myToken("COLON", ":"),
        myToken("LBRACE", "{"),
        myToken("RBRACE", "}"),
        myToken("LPAREN", "("),
        myToken("RPAREN", ")"),
        myToken("QUESTIONMARK", "?"),
        myToken("DOLLAR", "$"),
        myToken("ERROR", "1"),
        myToken("IDENT", "_invalid"),
    ]

    lexer = BDLexer()

    for index, token in enumerate(lexer.tokenize(test_string)):
        print(
            token.type, expected_tokens[index]["type"], token.value, expected_tokens[index]["value"]
        )
        assert (
            token.type == expected_tokens[index]["type"]
            and token.value == expected_tokens[index]["value"]
        )


@pytest.mark.parametrize(
    "input_text, expected_result",
    [
        (r"""source_name""", myToken("SOURCE_NAME", "source_name")),
    ],
)
def test_source_name(input_text: str, expected_result: myToken) -> None:
    """Test source name tokenization in BDLexer.

    This test verifies that the BDLexer correctly tokenizes input text when a source
    variable is present in the lexer's sources list. It checks that the generated
    token has the expected type and value.

    :param input_text: The text to be tokenized by the lexer.
    :param expected_result: Dictionary containing expected token type and value for validation.
    """
    lexer = BDLexer()
    lexer._sources.append(Variable("source_name", "source", ""))

    tokgen = lexer.tokenize(text=input_text)

    t = next(tokgen)
    assert t.type == expected_result["type"]
    assert t.value == expected_result["value"]
